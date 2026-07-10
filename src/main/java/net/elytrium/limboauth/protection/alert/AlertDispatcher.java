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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import net.elytrium.limboauth.Settings;
import net.elytrium.limboauth.event.ProtectionAlertEvent;
import net.elytrium.limboauth.protection.AttemptObservation;
import net.elytrium.limboauth.protection.Severity;
import net.elytrium.limboauth.protection.geoip.GeoIpResult;
import net.elytrium.limboauth.protection.scoring.FactorContribution;
import net.elytrium.limboauth.protection.scoring.RiskAssessment;
import net.elytrium.limboauth.protection.storage.ProtectionEvent;
import net.elytrium.limboauth.protection.storage.ProtectionEventStorage;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.slf4j.Logger;

/**
 * Routes scored attempts to the log, the PROTECTION_EVENTS table, the Velocity event bus
 * and the Discord webhook. The webhook path is deduplicated per attack cluster: repeats at
 * the same or lower severity within the cooldown are counted and folded into the next alert.
 */
public class AlertDispatcher {

  private final Logger logger;
  private final ProtectionEventStorage storage;
  private final DiscordWebhookClient webhookClient;
  private final Consumer<ProtectionAlertEvent> eventSink;
  private final LongSupplier clock;
  private final Map<String, ClusterState> clusters = new ConcurrentHashMap<>();
  private final AtomicLong webhookAlerts = new AtomicLong();
  private final AtomicLong suppressedAlerts = new AtomicLong();
  private final AtomicLong storedEvents = new AtomicLong();

  public AlertDispatcher(Logger logger, ProtectionEventStorage storage, DiscordWebhookClient webhookClient,
                         Consumer<ProtectionAlertEvent> eventSink, LongSupplier clock) {
    this.logger = logger;
    this.storage = storage;
    this.webhookClient = webhookClient;
    this.eventSink = eventSink;
    this.clock = clock;
  }

  public void dispatch(AttemptObservation observation, RiskAssessment assessment, @Nullable GeoIpResult geo) {
    Severity severity = assessment.severity();
    if (severity == Severity.NONE) {
      return;
    }

    String factorSummary = this.factorSummary(assessment.contributions());
    String logLine = "[PROTECTION] severity=" + severity + " score=" + assessment.score()
        + " outcome=" + observation.getOutcome() + " nick=" + observation.getLowercaseNickname()
        + " ip=" + observation.getIpString() + " subnet=" + observation.getSubnetKey()
        + " cluster=" + assessment.clusterKey()
        + (observation.getClientBrand() == null ? "" : " brand=\"" + observation.getClientBrand() + "\"")
        + " factors=[" + factorSummary + "]";
    if (severity.atLeast(Severity.SUSPICIOUS)) {
      this.logger.warn(logLine);
    } else {
      this.logger.info(logLine);
    }

    if (severity.atLeast(Severity.parse(Settings.IMP.PROTECTION.STORAGE.STORE_MIN_SEVERITY, Severity.INFO))) {
      this.storage.store(new ProtectionEvent(
          observation.getTimestamp(),
          severity.name(),
          assessment.score(),
          observation.getLowercaseNickname(),
          observation.getIpString(),
          observation.getSubnetKey(),
          observation.getOutcome().name(),
          this.factorsJson(assessment.contributions()),
          observation.getClientBrand(),
          geo == null ? null : geo.countryIso(),
          geo == null ? null : geo.asn()
      ));
      this.storedEvents.incrementAndGet();
    }

    if (severity.atLeast(Severity.SUSPICIOUS)) {
      this.eventSink.accept(new ProtectionAlertEvent(
          observation.getLowercaseNickname(),
          observation.getIpString(),
          observation.getSubnetKey(),
          observation.getOutcome(),
          assessment.score(),
          severity,
          assessment.contributions(),
          assessment.clusterKey(),
          observation.getTimestamp()
      ));
    }

    Settings.PROTECTION.WEBHOOK webhookConfig = Settings.IMP.PROTECTION.WEBHOOK;
    if (webhookConfig.ENABLED && !webhookConfig.URL.isEmpty()
        && severity.atLeast(Severity.parse(webhookConfig.MIN_SEVERITY, Severity.HIGH))) {
      this.dispatchWebhook(observation, assessment, geo, webhookConfig.COOLDOWN_MILLIS);
    }
  }

  public void purge(long now) {
    // Forget clusters that have been quiet for a while so the map stays bounded.
    long horizon = Math.max(Settings.IMP.PROTECTION.WEBHOOK.COOLDOWN_MILLIS * 2, 3600000);
    this.clusters.values().removeIf(state -> now - state.lastSent > horizon);
  }

  public long getWebhookAlerts() {
    return this.webhookAlerts.get();
  }

  public long getSuppressedAlerts() {
    return this.suppressedAlerts.get();
  }

  public long getStoredEvents() {
    return this.storedEvents.get();
  }

  private void dispatchWebhook(AttemptObservation observation, RiskAssessment assessment, @Nullable GeoIpResult geo, long cooldownMillis) {
    long now = this.clock.getAsLong();
    ClusterState state = this.clusters.computeIfAbsent(assessment.clusterKey(), key -> new ClusterState());

    int suppressedCount;
    synchronized (state) {
      boolean escalated = assessment.severity().ordinal() > state.lastSeverity.ordinal();
      if (!escalated && state.lastSent != 0 && now - state.lastSent < cooldownMillis) {
        ++state.suppressed;
        this.suppressedAlerts.incrementAndGet();
        return;
      }

      suppressedCount = state.suppressed;
      state.suppressed = 0;
      state.lastSent = now;
      state.lastSeverity = assessment.severity();
    }

    List<String> factorLines = new ArrayList<>();
    for (FactorContribution contribution : assessment.contributions()) {
      factorLines.add("`" + contribution.factor() + "` +" + contribution.points() + " - " + contribution.detail());
    }

    this.webhookClient.enqueue(new DiscordWebhookClient.PendingAlert(
        assessment.severity(),
        assessment.score(),
        observation.getLowercaseNickname(),
        observation.getIpString(),
        observation.getSubnetKey(),
        observation.getOutcome().name(),
        observation.getClientBrand(),
        geo == null ? null : geo.countryIso(),
        geo == null ? null : geo.asn(),
        factorLines,
        suppressedCount,
        observation.getTimestamp()
    ));
    this.webhookAlerts.incrementAndGet();
  }

  private String factorSummary(List<FactorContribution> contributions) {
    StringBuilder builder = new StringBuilder();
    for (FactorContribution contribution : contributions) {
      if (builder.length() > 0) {
        builder.append(", ");
      }

      builder.append(contribution.factor()).append(":+").append(contribution.points()).append("(").append(contribution.detail()).append(")");
    }

    return builder.toString();
  }

  private String factorsJson(List<FactorContribution> contributions) {
    JsonArray array = new JsonArray();
    for (FactorContribution contribution : contributions) {
      JsonObject entry = new JsonObject();
      entry.addProperty("f", contribution.factor().name());
      entry.addProperty("p", contribution.points());
      entry.addProperty("d", contribution.detail());
      array.add(entry);
    }

    return array.toString();
  }

  private static class ClusterState {

    private long lastSent;
    private Severity lastSeverity = Severity.NONE;
    private int suppressed;
  }
}
