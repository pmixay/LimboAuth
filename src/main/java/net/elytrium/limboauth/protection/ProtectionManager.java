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

package net.elytrium.limboauth.protection;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.scheduler.ScheduledTask;
import java.net.InetAddress;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import net.elytrium.limboauth.LimboAuth;
import net.elytrium.limboauth.Settings;
import net.elytrium.limboauth.model.SQLRuntimeException;
import net.elytrium.limboauth.protection.action.ActionPolicy;
import net.elytrium.limboauth.protection.action.MonitorActionPolicy;
import net.elytrium.limboauth.protection.aggregate.AggregateSnapshot;
import net.elytrium.limboauth.protection.aggregate.ProtectionAggregator;
import net.elytrium.limboauth.protection.alert.AlertDispatcher;
import net.elytrium.limboauth.protection.alert.DiscordWebhookClient;
import net.elytrium.limboauth.protection.geoip.GeoIpProvider;
import net.elytrium.limboauth.protection.geoip.GeoIpResult;
import net.elytrium.limboauth.protection.scoring.RiskAssessment;
import net.elytrium.limboauth.protection.scoring.RiskScorer;
import net.elytrium.limboauth.protection.social.SocialLinkResolver;
import net.elytrium.limboauth.protection.storage.ProtectionEvent;
import net.elytrium.limboauth.protection.storage.ProtectionEventStorage;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.slf4j.Logger;

/**
 * Coordinates the account protection pipeline. Constructed once (survives config reloads,
 * so in-flight attack state is not forgotten); {@link #reload()} rebinds the DB-backed
 * parts to the current connection source and reschedules the maintenance tasks.
 *
 * <p>Pipeline (on a dedicated single thread, never the connection threads):
 * social exemption -&gt; window aggregation -&gt; multi-factor scoring -&gt; monitor-only
 * dispatch (log, PROTECTION_EVENTS, Velocity event, Discord webhook).
 */
public class ProtectionManager {

  private static final int QUEUE_CAPACITY = 8192;
  private static final long PURGE_INTERVAL_MILLIS = 60000;
  private static final long RETENTION_INTERVAL_MILLIS = 3600000;
  private static final long GEO_REFRESH_INTERVAL_MILLIS = 86400000;
  private static final int RECENT_ASSESSMENTS_LIMIT = 512;

  private final LimboAuth plugin;
  private final Logger logger;
  private final PasswordFingerprinter fingerprinter = new PasswordFingerprinter();
  private final ProtectionAggregator aggregator = new ProtectionAggregator();
  private final RiskScorer scorer = new RiskScorer();
  private final ActionPolicy actionPolicy = new MonitorActionPolicy();
  private final ProtectionEventStorage storage;
  private final SocialLinkResolver socialResolver;
  private final GeoIpProvider geoIpProvider;
  private final DiscordWebhookClient webhookClient;
  private final AlertDispatcher alertDispatcher;
  private final ThreadPoolExecutor executor;
  private final AtomicLong droppedObservations = new AtomicLong();
  private final Map<String, RecentAssessment> recentAssessments;

  private volatile boolean enabled;
  private ScheduledTask purgeTask;
  private ScheduledTask retentionTask;
  private ScheduledTask webhookTask;
  private ScheduledTask geoRefreshTask;

  public ProtectionManager(LimboAuth plugin, Logger logger) {
    this.plugin = plugin;
    this.logger = logger;
    this.storage = new ProtectionEventStorage(logger);
    this.socialResolver = new SocialLinkResolver(logger);
    this.geoIpProvider = new GeoIpProvider(logger);
    this.webhookClient = new DiscordWebhookClient(logger);
    this.alertDispatcher = new AlertDispatcher(logger, this.storage, this.webhookClient,
        event -> plugin.getServer().getEventManager().fireAndForget(event), System::currentTimeMillis);
    this.executor = new ThreadPoolExecutor(1, 1, 30, TimeUnit.SECONDS, new LinkedBlockingQueue<>(QUEUE_CAPACITY), runnable -> {
      Thread thread = new Thread(runnable, "limboauth-protection");
      thread.setDaemon(true);
      return thread;
    }, (runnable, executor) -> this.droppedObservations.incrementAndGet());
    this.executor.allowCoreThreadTimeOut(true);
    this.recentAssessments = new LinkedHashMap<>(64, 0.75F, true) {
      @Override
      protected boolean removeEldestEntry(Map.Entry<String, RecentAssessment> eldest) {
        return this.size() > RECENT_ASSESSMENTS_LIMIT;
      }
    };
  }

  public void reload() {
    this.enabled = Settings.IMP.PROTECTION.ENABLED;

    if (this.enabled) {
      try {
        this.storage.init(this.plugin.getConnectionSource(), this.plugin::migrateDb);
      } catch (Exception e) {
        throw new SQLRuntimeException("Failed to initialize the PROTECTION_EVENTS table.", e);
      }

      this.socialResolver.reload(this.plugin.getPlayerDao());
      this.geoIpProvider.reload(this.getGeoIpDirectory());
      this.logger.info("Account protection is active in MONITOR mode: it detects and reports, but never kicks or locks anyone.");
      if (!"MONITOR".equalsIgnoreCase(Settings.IMP.PROTECTION.MODE)) {
        this.logger.warn("protection.mode \"{}\" is not implemented yet, running in MONITOR mode.", Settings.IMP.PROTECTION.MODE);
      }

      if (Settings.IMP.PROTECTION.ENFORCEMENT.ENABLED
          || !"NONE".equalsIgnoreCase(Settings.IMP.PROTECTION.ENFORCEMENT.ACTION_HIGH)
          || !"NONE".equalsIgnoreCase(Settings.IMP.PROTECTION.ENFORCEMENT.ACTION_CRITICAL)) {
        this.logger.warn("protection.enforcement is reserved for a future release and is ignored in this version.");
      }

      if (Settings.IMP.MAIN.MOD.ENABLED && Settings.IMP.MAIN.MOD.LOGIN_ONLY_BY_MOD) {
        this.logger.warn("login-only-by-mod is enabled: password attempts are not visible to the protection system.");
      }
    } else {
      this.geoIpProvider.close();
    }

    this.rescheduleTasks();
  }

  public void shutdown() {
    this.cancelTasks();
    this.executor.shutdown();
    try {
      if (!this.executor.awaitTermination(2, TimeUnit.SECONDS)) {
        this.executor.shutdownNow();
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      this.executor.shutdownNow();
    }

    this.webhookClient.drain();
    this.geoIpProvider.close();
  }

  public boolean isEnabled() {
    return this.enabled;
  }

  public long fingerprint(String password) {
    return this.fingerprinter.fingerprint(password);
  }

  public void recordAttempt(AttemptObservation observation) {
    if (!this.enabled) {
      return;
    }

    this.executor.execute(() -> this.process(observation));
  }

  public void recordSessionEnd(Player proxyPlayer, boolean accountExists, int attemptsMade, long joinTime) {
    if (!this.enabled || attemptsMade == 0) {
      return;
    }

    long now = System.currentTimeMillis();
    InetAddress address = proxyPlayer.getRemoteAddress().getAddress();
    this.recordAttempt(AttemptObservation.builder(proxyPlayer.getUsername().toLowerCase(Locale.ROOT), address, AttemptOutcome.SESSION_END)
        .accountExists(accountExists)
        .timestamp(now)
        .millisSinceJoin(now - joinTime)
        .sessionAttempts(attemptsMade)
        .build());
  }

  private void process(AttemptObservation observation) {
    try {
      if (observation.getOutcome() == AttemptOutcome.SESSION_END) {
        this.aggregator.update(observation);
        return;
      }

      // Players with a linked social account are fully exempt: not aggregated, not scored,
      // and their attempts never push shared-IP counters towards a threshold.
      if (observation.isAccountExists() && this.socialResolver.isLinked(observation.getLowercaseNickname())) {
        return;
      }

      this.aggregator.update(observation);
      AggregateSnapshot snapshot = this.aggregator.snapshot(observation);

      GeoIpResult geo = this.geoIpProvider.lookup(observation.getIp());
      String storedCountry = observation.isAccountExists() ? this.geoIpProvider.lookupCountryIso(observation.getStoredLoginIp()) : null;

      RiskAssessment assessment = this.scorer.score(observation, snapshot, geo, storedCountry);

      if (assessment.severity().atLeast(Severity.HIGH)) {
        // Flag the source so a later successful login from it is treated as a probable hit.
        this.aggregator.markFlagged(observation.getIpString(),
            observation.getTimestamp() + Settings.IMP.PROTECTION.WINDOWS.DISTRIBUTION_WINDOW_MILLIS);
      }

      if (assessment.severity() != Severity.NONE) {
        synchronized (this.recentAssessments) {
          this.recentAssessments.put(observation.getIpString(), new RecentAssessment(
              observation.getIpString(), observation.getLowercaseNickname(), assessment.score(), assessment.severity(), observation.getTimestamp()));
        }
      }

      this.actionPolicy.apply(observation, assessment);
      this.alertDispatcher.dispatch(observation, assessment, geo);
    } catch (Throwable t) {
      this.logger.warn("Protection pipeline failure (attempt ignored)", t);
    }
  }

  private void purge() {
    long now = System.currentTimeMillis();
    this.aggregator.purge(now);
    this.socialResolver.purgeCache(now);
    this.alertDispatcher.purge(now);
  }

  private Path getGeoIpDirectory() {
    return this.plugin.getDataDirectory().resolve("geoip");
  }

  private void rescheduleTasks() {
    this.cancelTasks();
    if (!this.enabled) {
      return;
    }

    this.purgeTask = this.plugin.getServer().getScheduler()
        .buildTask(this.plugin, () -> this.executor.execute(this::purge))
        .delay(PURGE_INTERVAL_MILLIS, TimeUnit.MILLISECONDS)
        .repeat(PURGE_INTERVAL_MILLIS, TimeUnit.MILLISECONDS)
        .schedule();

    this.retentionTask = this.plugin.getServer().getScheduler()
        .buildTask(this.plugin, () -> this.storage.purgeOlderThan(
            System.currentTimeMillis() - TimeUnit.DAYS.toMillis(Math.max(1, Settings.IMP.PROTECTION.STORAGE.RETENTION_DAYS))))
        .delay(RETENTION_INTERVAL_MILLIS, TimeUnit.MILLISECONDS)
        .repeat(RETENTION_INTERVAL_MILLIS, TimeUnit.MILLISECONDS)
        .schedule();

    long batchMillis = Math.max(1000, Settings.IMP.PROTECTION.WEBHOOK.BATCH_MILLIS);
    this.webhookTask = this.plugin.getServer().getScheduler()
        .buildTask(this.plugin, this.webhookClient::drain)
        .delay(batchMillis, TimeUnit.MILLISECONDS)
        .repeat(batchMillis, TimeUnit.MILLISECONDS)
        .schedule();

    this.geoRefreshTask = this.plugin.getServer().getScheduler()
        .buildTask(this.plugin, () -> this.geoIpProvider.refresh(this.getGeoIpDirectory()))
        .delay(GEO_REFRESH_INTERVAL_MILLIS, TimeUnit.MILLISECONDS)
        .repeat(GEO_REFRESH_INTERVAL_MILLIS, TimeUnit.MILLISECONDS)
        .schedule();
  }

  private void cancelTasks() {
    if (this.purgeTask != null) {
      this.purgeTask.cancel();
    }

    if (this.retentionTask != null) {
      this.retentionTask.cancel();
    }

    if (this.webhookTask != null) {
      this.webhookTask.cancel();
    }

    if (this.geoRefreshTask != null) {
      this.geoRefreshTask.cancel();
    }
  }

  public void handleCommand(CommandSource source, String[] args) {
    String subcommand = args.length > 1 ? args[1].toLowerCase(Locale.ROOT) : "status";
    switch (subcommand) {
      case "status": {
        this.sendStatus(source);
        break;
      }
      case "stats": {
        this.sendStats(source);
        break;
      }
      case "recent": {
        int limit = 10;
        if (args.length > 2) {
          try {
            limit = Math.max(1, Math.min(25, Integer.parseInt(args[2])));
          } catch (NumberFormatException e) {
            // Keep the default.
          }
        }

        this.sendRecent(source, limit);
        break;
      }
      case "test-webhook": {
        this.testWebhook(source);
        break;
      }
      default: {
        source.sendMessage(Component.text("Usage: /limboauth protection <status|stats|recent [n]|test-webhook>", NamedTextColor.YELLOW));
        break;
      }
    }
  }

  private void sendStatus(CommandSource source) {
    source.sendMessage(Component.text("Account protection: " + (this.enabled ? "ENABLED (monitor mode)" : "DISABLED"),
        this.enabled ? NamedTextColor.GREEN : NamedTextColor.RED));
    if (!this.enabled) {
      return;
    }

    source.sendMessage(Component.text("Queue: " + this.executor.getQueue().size() + " pending, "
        + this.droppedObservations.get() + " dropped", NamedTextColor.WHITE));
    source.sendMessage(Component.text("Tracked: " + this.aggregator.getTrackedIps() + " IPs, "
        + this.aggregator.getTrackedSubnets() + " subnets, " + this.aggregator.getTrackedAccounts() + " accounts, "
        + this.aggregator.getTrackedFingerprints() + " password patterns, " + this.aggregator.getFlaggedSources()
        + " flagged sources", NamedTextColor.WHITE));
    source.sendMessage(Component.text("Social exemption: " + this.socialResolver.getStatusSummary()
        + " (" + this.socialResolver.getCacheSize() + " cached)", NamedTextColor.WHITE));
    source.sendMessage(Component.text("GeoIP: " + this.geoIpProvider.getStatus(), NamedTextColor.WHITE));
    source.sendMessage(Component.text("Events stored: " + this.alertDispatcher.getStoredEvents()
        + ", webhook: " + this.alertDispatcher.getWebhookAlerts() + " sent to queue, "
        + this.alertDispatcher.getSuppressedAlerts() + " suppressed, " + this.webhookClient.getSentAlerts() + " delivered, "
        + this.webhookClient.getDroppedAlerts() + " dropped, " + this.webhookClient.getQueueSize() + " queued", NamedTextColor.WHITE));
    if (Settings.IMP.MAIN.MOD.ENABLED && Settings.IMP.MAIN.MOD.LOGIN_ONLY_BY_MOD) {
      source.sendMessage(Component.text("Warning: login-only-by-mod is enabled, password attempts are invisible to detection.",
          NamedTextColor.YELLOW));
    }
  }

  private void sendStats(CommandSource source) {
    List<RecentAssessment> top;
    long horizon = System.currentTimeMillis() - Settings.IMP.PROTECTION.WINDOWS.DISTRIBUTION_WINDOW_MILLIS;
    synchronized (this.recentAssessments) {
      top = new ArrayList<>(this.recentAssessments.values());
    }

    top.removeIf(assessment -> assessment.time() < horizon);
    top.sort(Comparator.comparingInt(RecentAssessment::score).reversed());

    source.sendMessage(Component.text("Top suspicious sources (distribution window):", NamedTextColor.WHITE));
    if (top.isEmpty()) {
      source.sendMessage(Component.text("  none", NamedTextColor.GREEN));
    } else {
      for (RecentAssessment assessment : top.subList(0, Math.min(5, top.size()))) {
        source.sendMessage(Component.text("  " + assessment.ip() + " -> " + assessment.nickname()
            + " score " + assessment.score() + " (" + assessment.severity() + ", " + this.formatAgo(assessment.time()) + ")",
            NamedTextColor.YELLOW));
      }
    }

    try {
      Map<String, Long> counts = this.storage.severityCountsSince(System.currentTimeMillis() - TimeUnit.HOURS.toMillis(24));
      StringBuilder builder = new StringBuilder("Events in the last 24h: ");
      if (counts.isEmpty()) {
        builder.append("none");
      } else {
        boolean first = true;
        for (Map.Entry<String, Long> entry : counts.entrySet()) {
          if (!first) {
            builder.append(", ");
          }

          builder.append(entry.getKey()).append(": ").append(entry.getValue());
          first = false;
        }
      }

      source.sendMessage(Component.text(builder.toString(), NamedTextColor.WHITE));
    } catch (Exception e) {
      source.sendMessage(Component.text("Failed to query stored events: " + e.getMessage(), NamedTextColor.RED));
    }
  }

  private void sendRecent(CommandSource source, int limit) {
    try {
      List<ProtectionEvent> events = this.storage.recent(limit);
      source.sendMessage(Component.text("Last " + events.size() + " protection events:", NamedTextColor.WHITE));
      for (ProtectionEvent event : events) {
        source.sendMessage(Component.text("  [" + this.formatAgo(event.getEventTime()) + "] " + event.getSeverity()
            + " score " + event.getScore() + " " + event.getNickname() + " from " + event.getIp()
            + " (" + event.getOutcome() + ")", NamedTextColor.YELLOW));
      }
    } catch (Exception e) {
      source.sendMessage(Component.text("Failed to query stored events: " + e.getMessage(), NamedTextColor.RED));
    }
  }

  private void testWebhook(CommandSource source) {
    Settings.PROTECTION.WEBHOOK config = Settings.IMP.PROTECTION.WEBHOOK;
    if (!config.ENABLED || config.URL.isEmpty()) {
      source.sendMessage(Component.text("Configure protection.webhook.enabled and protection.webhook.url first.", NamedTextColor.RED));
      return;
    }

    this.webhookClient.enqueue(new DiscordWebhookClient.PendingAlert(
        Severity.INFO, 0, "test-player", "127.0.0.1", "127.0.0.0/24", "TEST",
        "vanilla", null, null, List.of("`TEST` +0 - webhook connectivity test"), 0, System.currentTimeMillis()));
    this.webhookClient.drain();
    source.sendMessage(Component.text("Test alert queued - check your Discord channel.", NamedTextColor.GREEN));
  }

  private String formatAgo(long time) {
    long seconds = Math.max(0, (System.currentTimeMillis() - time) / 1000);
    if (seconds < 60) {
      return seconds + "s ago";
    } else if (seconds < 3600) {
      return (seconds / 60) + "m ago";
    } else if (seconds < 86400) {
      return (seconds / 3600) + "h ago";
    } else {
      return (seconds / 86400) + "d ago";
    }
  }

  private record RecentAssessment(String ip, String nickname, int score, Severity severity, long time) {
  }
}
