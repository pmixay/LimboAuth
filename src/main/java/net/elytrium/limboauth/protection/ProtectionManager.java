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
import net.elytrium.limboauth.protection.action.EnforceActionPolicy;
import net.elytrium.limboauth.protection.action.EnforcementState;
import net.elytrium.limboauth.protection.action.MonitorActionPolicy;
import net.elytrium.limboauth.protection.aggregate.ActivityWindow;
import net.elytrium.limboauth.protection.aggregate.AggregateSnapshot;
import net.elytrium.limboauth.protection.aggregate.ProtectionAggregator;
import net.elytrium.limboauth.protection.alert.AlertDispatcher;
import net.elytrium.limboauth.protection.alert.DiscordWebhookClient;
import net.elytrium.limboauth.protection.geoip.GeoIpProvider;
import net.elytrium.limboauth.protection.geoip.GeoIpResult;
import net.elytrium.limboauth.protection.scoring.FactorContribution;
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
 * social exemption -&gt; window aggregation -&gt; multi-factor scoring -&gt; dispatch
 * (log, PROTECTION_EVENTS, Velocity event, Discord webhook) plus, in ENFORCE mode,
 * the enforcement actions (kick, source block, account shield).
 *
 * <p>The connection threads additionally consult two synchronous, lock-free gates:
 * {@link #shouldBlockJoin} at session start and {@link #isLoginShielded} on login.
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
  private final RetroactiveElevation retroactiveElevation = new RetroactiveElevation(this.aggregator, this.scorer);
  private final EnforcementState enforcementState = new EnforcementState(System::currentTimeMillis);
  private final ActionPolicy monitorPolicy = new MonitorActionPolicy();
  private final ActionPolicy enforcePolicy;
  private final ProtectionEventStorage storage;
  private final SocialLinkResolver socialResolver;
  private final GeoIpProvider geoIpProvider;
  private final DiscordWebhookClient webhookClient;
  private final AlertDispatcher alertDispatcher;
  private final ThreadPoolExecutor executor;
  private final AtomicLong droppedObservations = new AtomicLong();
  private final Map<String, RecentAssessment> recentAssessments;

  private volatile boolean enabled;
  private volatile boolean enforcementActive;
  private volatile Component protectionKick = Component.empty();
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
    this.enforcePolicy = new EnforceActionPolicy(this.enforcementState, this::kickSession, logger);
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
    String mode = Settings.IMP.PROTECTION.MODE;
    this.enforcementActive = this.enabled
        && (Settings.IMP.PROTECTION.ENFORCEMENT.ENABLED || "ENFORCE".equalsIgnoreCase(mode));
    this.protectionKick = LimboAuth.getSerializer().deserialize(Settings.IMP.MAIN.STRINGS.PROTECTION_KICK);

    if (this.enabled) {
      try {
        // Events live in a plugin-local H2 store; rows an older version left in the
        // auth database are migrated over once and the old table is dropped there.
        // The storage runs its own H2 column migration - LimboAuth#migrateDb keys its
        // column discovery to the MAIN database engine and must not touch this store.
        this.storage.init(ProtectionEventStorage.openLocal(this.plugin.getDataDirectory()), this.plugin.getConnectionSource());
      } catch (Exception e) {
        throw new SQLRuntimeException("Failed to initialize the local protection events database.", e);
      }

      this.socialResolver.reload(this.plugin.getPlayerDao());
      this.geoIpProvider.reload(this.getGeoIpDirectory());
      if (this.enforcementActive) {
        Settings.PROTECTION.ENFORCEMENT enforcement = Settings.IMP.PROTECTION.ENFORCEMENT;
        this.logger.info("Account protection is active in ENFORCE mode: kick >= {}, source block >= {} ({} min), "
                + "account shield on successful logins >= {} ({} min).",
            enforcement.KICK_ON, enforcement.BLOCK_SOURCE_ON, enforcement.SOURCE_BLOCK_MINUTES,
            enforcement.SHIELD_ACCOUNT_ON, enforcement.SHIELD_MINUTES);
      } else {
        this.logger.info("Account protection is active in MONITOR mode: it detects and reports, but never kicks or locks anyone.");
        if (!"MONITOR".equalsIgnoreCase(mode)) {
          this.logger.warn("Unknown protection.mode \"{}\" - use MONITOR or ENFORCE. Running in MONITOR mode.", mode);
        }
      }

      if (Settings.IMP.MAIN.MOD.ENABLED && Settings.IMP.MAIN.MOD.LOGIN_ONLY_BY_MOD) {
        this.logger.warn("login-only-by-mod is enabled: password attempts are not visible to the protection system.");
      }
    } else {
      this.geoIpProvider.close();
      this.storage.close();
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
    this.storage.close();
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

      // Sampled ahead of the fold-in so the retroactive pass can detect a tier crossing.
      final int foreignFailedBefore = this.aggregator.foreignFailedTargets(observation);
      ActivityWindow.AttemptEvent windowEvent = this.aggregator.update(observation);
      AggregateSnapshot snapshot = this.aggregator.snapshot(observation);

      GeoIpResult geo = this.geoIpProvider.lookup(observation.getIp());
      String storedCountry = observation.isAccountExists() ? this.geoIpProvider.lookupCountryIso(observation.getStoredLoginIp()) : null;

      RiskAssessment assessment = this.scorer.score(observation, snapshot, geo, storedCountry);

      if (assessment.severity().atLeast(Severity.HIGH)) {
        // Flag the source so a later successful login from it is treated as a probable hit.
        this.aggregator.markFlagged(observation.getIpString(),
            observation.getTimestamp() + Settings.IMP.PROTECTION.WINDOWS.DISTRIBUTION_WINDOW_MILLIS);

        if (observation.getOutcome() == AttemptOutcome.LOGIN_SUCCESS && assessment.hasConfirmationFactor()) {
          // Reported as a probable hit right now - the retroactive pass must not repeat
          // it. A HIGH that carried no confirmation factor (volume/geo/behavior only)
          // stays eligible: the multi-target linkage would still be new information.
          windowEvent.markConfirmationAlerted();
        }
      }

      if (assessment.severity() != Severity.NONE) {
        synchronized (this.recentAssessments) {
          this.recentAssessments.put(observation.getIpString(), new RecentAssessment(
              observation.getIpString(), observation.getLowercaseNickname(), assessment.score(), assessment.severity(), observation.getTimestamp()));
        }
      }

      (this.enforcementActive ? this.enforcePolicy : this.monitorPolicy).apply(observation, assessment);
      this.alertDispatcher.dispatch(observation, assessment, geo);

      // Success-first hits: if this attempt pushed the source across a multi-target tier,
      // earlier quiet successes from it get their confirmation alert now. Deliberately
      // dispatch-only (log, event row, webhook) - enforcement stays tied to live attempts,
      // and the geo of the current attempt applies because the source IP is the same.
      // The source itself gets the same flagged/stats treatment as any live >= HIGH
      // assessment: a retro-confirmed checker must not look cleaner than a live one.
      for (RetroactiveElevation.ElevatedSuccess elevated
          : this.retroactiveElevation.onAttempt(observation, foreignFailedBefore, snapshot.foreignFailedTargets())) {
        this.aggregator.markFlagged(observation.getIpString(),
            observation.getTimestamp() + Settings.IMP.PROTECTION.WINDOWS.DISTRIBUTION_WINDOW_MILLIS);
        synchronized (this.recentAssessments) {
          this.recentAssessments.put(observation.getIpString(), new RecentAssessment(
              observation.getIpString(), elevated.observation().getLowercaseNickname(),
              elevated.assessment().score(), elevated.assessment().severity(), elevated.observation().getTimestamp()));
        }

        this.alertDispatcher.dispatch(elevated.observation(), elevated.assessment(), geo);
      }
    } catch (Throwable t) {
      this.logger.warn("Protection pipeline failure (attempt ignored)", t);
    }
  }

  private void purge() {
    long now = System.currentTimeMillis();
    this.aggregator.purge(now);
    this.socialResolver.purgeCache(now);
    this.alertDispatcher.purge(now);
    this.enforcementState.purge(now);
  }

  /**
   * Synchronous connection-thread gate: should this join be refused outright because the
   * source IP is under an enforcement block? The map read is free; the social lookup (a
   * TTL-cached query, matching the blocking DAO calls the join path already makes) only
   * runs for registered accounts on an actually-blocked IP, so linked-social players
   * behind a blocked shared IP keep their promised exemption from enforcement.
   */
  public boolean shouldBlockJoin(Player proxyPlayer, boolean accountExists) {
    if (!this.enabled || !this.enforcementActive
        || !this.enforcementState.isSourceBlocked(proxyPlayer.getRemoteAddress().getAddress().getHostAddress())) {
      return false;
    }

    if (proxyPlayer.hasPermission("limboauth.protection.bypass")) {
      return false;
    }

    return !(accountExists && this.socialResolver.isLinked(proxyPlayer.getUsername().toLowerCase(Locale.ROOT)));
  }

  /**
   * Synchronous connection-thread gate: is this account currently shielded? While shielded,
   * the login flow treats every password as wrong, so a checker can never confirm a hit.
   * No social-exemption check is needed (or wanted - it would block the login thread on a
   * database query): linked players are exempt from the pipeline upstream, so a shield can
   * only ever have been placed on an unlinked account.
   */
  public boolean isLoginShielded(String lowercaseNickname) {
    return this.enabled && this.enforcementActive && this.enforcementState.isAccountShielded(lowercaseNickname);
  }

  public Component getProtectionKick() {
    return this.protectionKick;
  }

  private void kickSession(String lowercaseNickname, String expectedIp) {
    this.plugin.getServer().getPlayer(lowercaseNickname).ifPresent(player -> {
      // The attacker may have disconnected and the real owner reconnected in the meantime;
      // only kick the session that actually produced the flagged attempt.
      if (expectedIp.equals(player.getRemoteAddress().getAddress().getHostAddress())
          && !player.hasPermission("limboauth.protection.bypass")) {
        this.logger.warn("enforcement action=kick player={} ip={}", lowercaseNickname, expectedIp);
        player.disconnect(this.protectionKick);
      }
    });
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
      case "inspect": {
        if (args.length < 3) {
          source.sendMessage(Component.text("Usage: /limboauth protection inspect <nickname>", NamedTextColor.YELLOW));
        } else {
          this.sendInspect(source, args[2].toLowerCase(Locale.ROOT));
        }

        break;
      }
      case "test-webhook": {
        this.testWebhook(source);
        break;
      }
      case "blocks": {
        this.sendBlocks(source);
        break;
      }
      case "unblock": {
        if (args.length < 3) {
          source.sendMessage(Component.text("Usage: /limboauth protection unblock <ip|nickname>", NamedTextColor.YELLOW));
        } else {
          String removed = this.enforcementState.unblock(args[2]);
          if (removed == null) {
            source.sendMessage(Component.text("No active block or shield matches \"" + args[2] + "\".", NamedTextColor.RED));
          } else {
            this.logger.info("enforcement action=unblock target={} by={}", args[2], source);
            source.sendMessage(Component.text("Removed: " + removed, NamedTextColor.GREEN));
          }
        }

        break;
      }
      default: {
        source.sendMessage(Component.text(
            "Usage: /limboauth protection <status|stats|recent [n]|inspect <nickname>|blocks|unblock <target>|test-webhook>",
            NamedTextColor.YELLOW));
        break;
      }
    }
  }

  private void sendStatus(CommandSource source) {
    String state = !this.enabled ? "DISABLED" : this.enforcementActive ? "ENABLED (ENFORCE mode)" : "ENABLED (monitor mode)";
    source.sendMessage(Component.text("Account protection: " + state, this.enabled ? NamedTextColor.GREEN : NamedTextColor.RED));
    if (!this.enabled) {
      return;
    }

    if (this.enforcementActive) {
      Settings.PROTECTION.ENFORCEMENT enforcement = Settings.IMP.PROTECTION.ENFORCEMENT;
      source.sendMessage(Component.text("Enforcement: kick >= " + enforcement.KICK_ON
          + ", block source >= " + enforcement.BLOCK_SOURCE_ON + " (" + enforcement.SOURCE_BLOCK_MINUTES + "m)"
          + ", shield account >= " + enforcement.SHIELD_ACCOUNT_ON + " (" + enforcement.SHIELD_MINUTES + "m); "
          + this.enforcementState.getBlockedSourceCount() + " blocked sources, "
          + this.enforcementState.getShieldedAccountCount() + " shielded accounts", NamedTextColor.WHITE));
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

  /**
   * Triage view for one account: its recent events WITH the factor breakdown that
   * produced each score, so an admin can judge a report without grepping the log.
   */
  private void sendInspect(CommandSource source, String lowercaseNickname) {
    try {
      List<ProtectionEvent> events = this.storage.recentForNickname(lowercaseNickname, 5);
      if (events.isEmpty()) {
        source.sendMessage(Component.text("No stored protection events for \"" + lowercaseNickname + "\".", NamedTextColor.GREEN));
        return;
      }

      source.sendMessage(Component.text("Last " + events.size() + " protection events for " + lowercaseNickname + ":", NamedTextColor.WHITE));
      for (ProtectionEvent event : events) {
        source.sendMessage(Component.text("  [" + this.formatAgo(event.getEventTime()) + "] " + event.getSeverity()
            + " score " + event.getScore() + " from " + event.getIp() + " (" + event.getOutcome() + ")"
            + (event.getClientBrand() == null ? "" : " brand \"" + event.getClientBrand() + "\""), NamedTextColor.YELLOW));
        for (String line : FactorContribution.describeJson(event.getFactors())) {
          source.sendMessage(Component.text("    " + line, NamedTextColor.GRAY));
        }
      }
    } catch (Exception e) {
      source.sendMessage(Component.text("Failed to query stored events: " + e.getMessage(), NamedTextColor.RED));
    }
  }

  private void sendBlocks(CommandSource source) {
    if (!this.enforcementActive) {
      source.sendMessage(Component.text("Enforcement is not active (monitor mode) - there are no blocks or shields.", NamedTextColor.YELLOW));
      return;
    }

    long now = System.currentTimeMillis();
    Map<String, Long> sources = this.enforcementState.snapshotBlockedSources();
    Map<String, Long> shields = this.enforcementState.snapshotShieldedAccounts();

    source.sendMessage(Component.text("Blocked sources (" + sources.size() + "):", NamedTextColor.WHITE));
    sources.forEach((ip, until) -> source.sendMessage(
        Component.text("  " + ip + " - " + this.formatRemaining(until, now) + " left", NamedTextColor.YELLOW)));
    source.sendMessage(Component.text("Shielded accounts (" + shields.size() + "):", NamedTextColor.WHITE));
    shields.forEach((nickname, until) -> source.sendMessage(
        Component.text("  " + nickname + " - " + this.formatRemaining(until, now) + " left", NamedTextColor.YELLOW)));
    if (!sources.isEmpty() || !shields.isEmpty()) {
      source.sendMessage(Component.text("Remove one early with /limboauth protection unblock <ip|nickname>", NamedTextColor.GRAY));
    }
  }

  private String formatRemaining(long until, long now) {
    long seconds = Math.max(0, (until - now) / 1000);
    return seconds < 60 ? seconds + "s" : (seconds / 60) + "m";
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
