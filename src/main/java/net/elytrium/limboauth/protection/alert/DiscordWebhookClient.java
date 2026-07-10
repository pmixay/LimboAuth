/*
 * Copyright (C) 2021 - 2025 Elytrium
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package net.elytrium.limboauth.protection.alert;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import net.elytrium.limboauth.Settings;
import net.elytrium.limboauth.protection.Severity;
import org.slf4j.Logger;

/**
 * Small Discord webhook sender: batches up to 10 embeds per message, honors 429
 * rate limits, retries transient server errors and drops on overflow instead of
 * ever blocking the detection pipeline.
 */
public class DiscordWebhookClient {

  private static final int MAX_EMBEDS_PER_MESSAGE = 10;
  private static final int MAX_QUEUE_SIZE = 100;
  private static final int MAX_SEND_ATTEMPTS = 3;

  private final Logger logger;
  private final HttpClient httpClient = HttpClient.newHttpClient();
  private final Queue<PendingAlert> queue = new ConcurrentLinkedQueue<>();
  private final AtomicInteger queueSize = new AtomicInteger();
  private final AtomicBoolean inFlight = new AtomicBoolean();
  private final AtomicLong sentAlerts = new AtomicLong();
  private final AtomicLong droppedAlerts = new AtomicLong();

  private volatile long blockedUntil;

  public DiscordWebhookClient(Logger logger) {
    this.logger = logger;
  }

  public void enqueue(PendingAlert alert) {
    if (this.queueSize.incrementAndGet() > MAX_QUEUE_SIZE) {
      this.queueSize.decrementAndGet();
      this.droppedAlerts.incrementAndGet();
      return;
    }

    this.queue.add(alert);
  }

  public void drain() {
    Settings.PROTECTION.WEBHOOK config = Settings.IMP.PROTECTION.WEBHOOK;
    if (!config.ENABLED || config.URL.isEmpty() || System.currentTimeMillis() < this.blockedUntil) {
      return;
    }

    if (!this.inFlight.compareAndSet(false, true)) {
      return;
    }

    List<PendingAlert> batch = new ArrayList<>(MAX_EMBEDS_PER_MESSAGE);
    PendingAlert alert;
    while (batch.size() < MAX_EMBEDS_PER_MESSAGE && (alert = this.queue.poll()) != null) {
      this.queueSize.decrementAndGet();
      batch.add(alert);
    }

    if (batch.isEmpty()) {
      this.inFlight.set(false);
      return;
    }

    HttpRequest request;
    try {
      request = HttpRequest.newBuilder()
          .uri(URI.create(config.URL))
          .header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(this.buildPayload(batch, config), StandardCharsets.UTF_8))
          .build();
    } catch (IllegalArgumentException e) {
      this.logger.warn("Invalid protection webhook URL: {}", e.getMessage());
      this.droppedAlerts.addAndGet(batch.size());
      this.inFlight.set(false);
      return;
    }

    this.httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString()).whenComplete((response, throwable) -> {
      try {
        if (throwable != null) {
          this.retryOrDrop(batch, "request failed: " + throwable.getMessage());
        } else if (response.statusCode() == 429) {
          long retryAfterMillis = this.parseRetryAfterMillis(response);
          this.blockedUntil = System.currentTimeMillis() + retryAfterMillis;
          batch.forEach(this::enqueue);
        } else if (response.statusCode() >= 500) {
          this.retryOrDrop(batch, "server error " + response.statusCode());
        } else if (response.statusCode() >= 400) {
          this.logger.warn("Protection webhook rejected with status {}", response.statusCode());
          this.droppedAlerts.addAndGet(batch.size());
        } else {
          this.sentAlerts.addAndGet(batch.size());
        }
      } finally {
        this.inFlight.set(false);
      }
    });
  }

  public long getSentAlerts() {
    return this.sentAlerts.get();
  }

  public long getDroppedAlerts() {
    return this.droppedAlerts.get();
  }

  public int getQueueSize() {
    return this.queueSize.get();
  }

  private void retryOrDrop(List<PendingAlert> batch, String reason) {
    for (PendingAlert failed : batch) {
      if (++failed.sendAttempts < MAX_SEND_ATTEMPTS) {
        this.enqueue(failed);
      } else {
        this.droppedAlerts.incrementAndGet();
      }
    }

    this.logger.warn("Protection webhook delivery failed ({}), will retry", reason);
  }

  private long parseRetryAfterMillis(HttpResponse<String> response) {
    return response.headers().firstValue("Retry-After")
        .map(value -> {
          try {
            return (long) (Double.parseDouble(value) * 1000);
          } catch (NumberFormatException e) {
            return 5000L;
          }
        })
        .orElse(5000L);
  }

  private String buildPayload(List<PendingAlert> batch, Settings.PROTECTION.WEBHOOK config) {
    JsonObject payload = new JsonObject();
    if (!config.USERNAME.isEmpty()) {
      payload.addProperty("username", config.USERNAME);
    }

    boolean critical = batch.stream().anyMatch(entry -> entry.severity == Severity.CRITICAL);
    if (critical && !config.MENTION_ROLE_CRITICAL.isEmpty()) {
      payload.addProperty("content", "<@&" + config.MENTION_ROLE_CRITICAL + ">");
    }

    JsonArray embeds = new JsonArray();
    for (PendingAlert entry : batch) {
      embeds.add(this.buildEmbed(entry));
    }

    payload.add("embeds", embeds);
    return payload.toString();
  }

  private JsonObject buildEmbed(PendingAlert alert) {
    JsonObject embed = new JsonObject();
    embed.addProperty("title", this.titleFor(alert));
    embed.addProperty("color", this.colorFor(alert.severity));
    embed.addProperty("timestamp", Instant.ofEpochMilli(alert.timestamp).toString());

    JsonArray fields = new JsonArray();
    this.addField(fields, "Account", "`" + alert.nickname + "`", true);
    this.addField(fields, "Source", "`" + alert.ip + "` (" + alert.subnet + ")", true);
    this.addField(fields, "Attempt", alert.outcome + ", score " + alert.score, true);
    if (alert.clientBrand != null) {
      this.addField(fields, "Client brand", "`" + alert.clientBrand + "`", true);
    }

    if (alert.country != null || alert.asn != null) {
      this.addField(fields, "Geo", (alert.country == null ? "?" : alert.country) + (alert.asn == null ? "" : ", AS" + alert.asn), true);
    }

    if (!alert.factorLines.isEmpty()) {
      this.addField(fields, "Factors", String.join("\n", alert.factorLines), false);
    }

    if (alert.suppressedCount > 0) {
      this.addField(fields, "Suppressed", "+" + alert.suppressedCount + " similar alerts since the last message", false);
    }

    embed.add("fields", fields);
    return embed;
  }

  private void addField(JsonArray fields, String name, String value, boolean inline) {
    JsonObject field = new JsonObject();
    field.addProperty("name", name);
    // Discord caps embed field values at 1024 characters.
    field.addProperty("value", value.length() > 1024 ? value.substring(0, 1021) + "..." : value);
    field.addProperty("inline", inline);
    fields.add(field);
  }

  private String titleFor(PendingAlert alert) {
    switch (alert.severity) {
      case CRITICAL: {
        return "🚨 CRITICAL - probable compromised account";
      }
      case HIGH: {
        return "⚠ HIGH - credential-stuffing suspected";
      }
      case SUSPICIOUS: {
        return "🔍 SUSPICIOUS activity";
      }
      default: {
        return "ℹ Protection notice";
      }
    }
  }

  private int colorFor(Severity severity) {
    switch (severity) {
      case CRITICAL: {
        return 0xE74C3C;
      }
      case HIGH: {
        return 0xE67E22;
      }
      case SUSPICIOUS: {
        return 0xF1C40F;
      }
      default: {
        return 0x95A5A6;
      }
    }
  }

  public static class PendingAlert {

    private final Severity severity;
    private final int score;
    private final String nickname;
    private final String ip;
    private final String subnet;
    private final String outcome;
    private final String clientBrand;
    private final String country;
    private final Long asn;
    private final List<String> factorLines;
    private final int suppressedCount;
    private final long timestamp;

    private int sendAttempts;

    public PendingAlert(Severity severity, int score, String nickname, String ip, String subnet, String outcome,
                        String clientBrand, String country, Long asn, List<String> factorLines, int suppressedCount, long timestamp) {
      this.severity = severity;
      this.score = score;
      this.nickname = nickname;
      this.ip = ip;
      this.subnet = subnet;
      this.outcome = outcome;
      this.clientBrand = clientBrand;
      this.country = country;
      this.asn = asn;
      this.factorLines = List.copyOf(factorLines);
      this.suppressedCount = suppressedCount;
      this.timestamp = timestamp;
    }
  }
}
