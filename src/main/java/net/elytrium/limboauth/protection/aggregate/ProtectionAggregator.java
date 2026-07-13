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

package net.elytrium.limboauth.protection.aggregate;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import net.elytrium.limboauth.Settings;
import net.elytrium.limboauth.protection.AttemptObservation;
import net.elytrium.limboauth.protection.AttemptOutcome;
import net.elytrium.limboauth.protection.SubnetKey;

/**
 * Sliding-window aggregates keyed by IP, subnet, account and password fingerprint.
 * All mutation happens on the single protection executor thread; the maps are concurrent
 * only so that admin commands can read sizes from other threads.
 */
public class ProtectionAggregator {

  private final Map<String, ActivityWindow> ipWindows = new ConcurrentHashMap<>();
  private final Map<String, ActivityWindow> subnetWindows = new ConcurrentHashMap<>();
  private final Map<String, ActivityWindow> accountWindows = new ConcurrentHashMap<>();
  private final Map<Long, ActivityWindow> fingerprintWindows = new ConcurrentHashMap<>();
  private final Map<String, Long> flaggedSources = new ConcurrentHashMap<>();

  /**
   * Folds the observation into every window it belongs to and returns the shared event,
   * so the caller can mark it once its assessment is known (see
   * {@link ActivityWindow.AttemptEvent#markConfirmationAlerted()}).
   */
  public ActivityWindow.AttemptEvent update(AttemptObservation observation) {
    Settings.PROTECTION.WINDOWS windows = Settings.IMP.PROTECTION.WINDOWS;
    int maxEvents = windows.MAX_EVENTS_PER_WINDOW;

    boolean churn = observation.getOutcome() == AttemptOutcome.SESSION_END
        && observation.getMillisSinceJoin() < windows.CHURN_SESSION_MILLIS
        && observation.getSessionAttempts() >= 1
        && observation.getSessionAttempts() <= windows.CHURN_MAX_ATTEMPTS;

    String storedLoginIp = observation.getStoredLoginIp();
    boolean newSource = observation.getOutcome() == AttemptOutcome.LOGIN_SUCCESS
        && storedLoginIp != null
        && !storedLoginIp.isEmpty()
        && !storedLoginIp.equals(observation.getIpString());

    String storedSubnet = SubnetKey.ofLiteral(storedLoginIp);
    boolean foreignTarget = observation.isAccountExists()
        && SubnetKey.isForeignSubnet(storedSubnet, observation.getSubnetKey());

    ActivityWindow.AttemptEvent event = new ActivityWindow.AttemptEvent(
        observation.getTimestamp(),
        observation.getLowercaseNickname(),
        observation.isAccountExists(),
        observation.getIpString(),
        observation.getOutcome(),
        churn,
        newSource,
        foreignTarget,
        storedSubnet
    );

    this.windowFor(this.ipWindows, observation.getIpString(), windows.MAX_TRACKED_IPS).add(event, maxEvents);
    this.windowFor(this.subnetWindows, observation.getSubnetKey(), windows.MAX_TRACKED_SUBNETS).add(event, maxEvents);

    if (observation.getOutcome() != AttemptOutcome.SESSION_END) {
      if (observation.isAccountExists()) {
        this.windowFor(this.accountWindows, observation.getLowercaseNickname(), windows.MAX_TRACKED_ACCOUNTS).add(event, maxEvents);
      }

      if (observation.hasFingerprint()) {
        this.windowFor(this.fingerprintWindows, observation.getPasswordFingerprint(), windows.MAX_TRACKED_FINGERPRINTS).add(event, maxEvents);
      }
    }

    return event;
  }

  public AggregateSnapshot snapshot(AttemptObservation observation) {
    long now = observation.getTimestamp();
    long volumeSince = now - Settings.IMP.PROTECTION.WINDOWS.VOLUME_WINDOW_MILLIS;
    long distributionSince = distributionSince(now);

    ActivityWindow ipWindow = this.ipWindows.get(observation.getIpString());
    ActivityWindow subnetWindow = this.subnetWindows.get(observation.getSubnetKey());
    ActivityWindow accountWindow = observation.isAccountExists() ? this.accountWindows.get(observation.getLowercaseNickname()) : null;
    ActivityWindow fingerprintWindow = observation.hasFingerprint() ? this.fingerprintWindows.get(observation.getPasswordFingerprint()) : null;

    // Only the raw fail rate is a "fast source" signal bound to the short volume window.
    // Everything target- or session-shaped is measured over the distribution window: a human
    // working through leaked credentials spreads a handful of attempts across an hour.
    return new AggregateSnapshot(
        ipWindow == null ? 0 : ipWindow.countFails(volumeSince),
        ipWindow == null ? 0 : ipWindow.distinctFailedExistingTargets(distributionSince),
        ipWindow == null ? 0 : ipWindow.countChurnSessions(distributionSince),
        ipWindow == null ? 0 : ipWindow.distinctNewSourceSuccesses(distributionSince),
        subnetWindow == null ? 0 : subnetWindow.distinctFailedExistingTargets(distributionSince),
        subnetWindow == null ? 0 : subnetWindow.distinctIps(distributionSince),
        subnetWindow == null ? 0 : subnetWindow.countChurnSessions(distributionSince),
        accountWindow == null ? 0 : accountWindow.distinctFailIps(distributionSince),
        accountWindow == null ? 0 : accountWindow.countFailsFromOtherIps(distributionSince, observation.getIpString()),
        fingerprintWindow == null ? 0 : fingerprintWindow.distinctFingerprintTargets(distributionSince),
        this.isFlagged(observation.getIpString(), now),
        fingerprintWindow == null ? 0 : fingerprintWindow.distinctForeignFingerprintTargets(distributionSince, observation.getLowercaseNickname()),
        ipWindow == null ? 0 : ipWindow.distinctForeignFailedTargets(distributionSince),
        fingerprintWindow == null ? 0 : fingerprintWindow.distinctForeignFingerprintTargetSubnets(distributionSince, observation.getLowercaseNickname())
    );
  }

  /**
   * The source's current foreign-failed-target count, read WITHOUT folding anything in.
   * The manager samples it before and after {@link #update} to detect the moment a
   * source crosses a multi-target tier and owes its earlier successes a second look.
   */
  public int foreignFailedTargets(AttemptObservation observation) {
    ActivityWindow ipWindow = this.ipWindows.get(observation.getIpString());
    return ipWindow == null ? 0 : ipWindow.distinctForeignFailedTargets(distributionSince(observation.getTimestamp()));
  }

  /**
   * Recent successes from this observation's source on foreign targets that were never
   * reported at confirmation severity - the candidates for retroactive elevation.
   */
  public List<ActivityWindow.AttemptEvent> unalertedForeignSuccesses(AttemptObservation observation) {
    ActivityWindow ipWindow = this.ipWindows.get(observation.getIpString());
    return ipWindow == null ? List.of() : ipWindow.unalertedForeignSuccesses(distributionSince(observation.getTimestamp()));
  }

  /**
   * One horizon for the snapshot, the pre-update sample and the retroactive scan: the
   * tier-crossing comparison is only sound while all three share it exactly.
   */
  private static long distributionSince(long now) {
    return now - Settings.IMP.PROTECTION.WINDOWS.DISTRIBUTION_WINDOW_MILLIS;
  }

  public void markFlagged(String ip, long untilTime) {
    this.flaggedSources.merge(ip, untilTime, Math::max);
  }

  public boolean isFlagged(String ip, long now) {
    Long until = this.flaggedSources.get(ip);
    return until != null && until > now;
  }

  public void purge(long now) {
    long horizon = now - Math.max(Settings.IMP.PROTECTION.WINDOWS.VOLUME_WINDOW_MILLIS, Settings.IMP.PROTECTION.WINDOWS.DISTRIBUTION_WINDOW_MILLIS);
    this.purgeWindows(this.ipWindows, horizon);
    this.purgeWindows(this.subnetWindows, horizon);
    this.purgeWindows(this.accountWindows, horizon);
    this.purgeWindows(this.fingerprintWindows, horizon);
    this.flaggedSources.values().removeIf(until -> until <= now);
  }

  public int getTrackedIps() {
    return this.ipWindows.size();
  }

  public int getTrackedSubnets() {
    return this.subnetWindows.size();
  }

  public int getTrackedAccounts() {
    return this.accountWindows.size();
  }

  public int getTrackedFingerprints() {
    return this.fingerprintWindows.size();
  }

  public int getFlaggedSources() {
    return this.flaggedSources.size();
  }

  private <K> ActivityWindow windowFor(Map<K, ActivityWindow> windows, K key, int maxTracked) {
    ActivityWindow window = windows.get(key);
    if (window == null) {
      // Flood backstop: evict an arbitrary entry above the cap so memory stays bounded.
      while (windows.size() >= maxTracked) {
        Iterator<K> iterator = windows.keySet().iterator();
        if (iterator.hasNext()) {
          iterator.next();
          iterator.remove();
        } else {
          break;
        }
      }

      window = new ActivityWindow();
      windows.put(key, window);
    }

    return window;
  }

  private <K> void purgeWindows(Map<K, ActivityWindow> windows, long horizon) {
    windows.values().forEach(window -> window.trim(horizon));
    windows.values().removeIf(window -> window.isEmpty() && window.getLastTouched() < horizon);
  }
}
