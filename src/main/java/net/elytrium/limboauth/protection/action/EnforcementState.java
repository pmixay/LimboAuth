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

package net.elytrium.limboauth.protection.action;

import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import net.elytrium.limboauth.Settings;

/**
 * Active enforcement decisions: temporarily blocked source IPs and shielded accounts.
 * Written by the protection executor, read synchronously from connection threads, so
 * everything is lock-free and a lookup is a single map read plus a timestamp compare.
 * Deliberately in-memory only - a proxy restart clears all blocks, matching the
 * temporary nature of the actions.
 */
public class EnforcementState {

  private final Map<String, Long> blockedSources = new ConcurrentHashMap<>();
  private final Map<String, Long> shieldedAccounts = new ConcurrentHashMap<>();
  private final LongSupplier clock;

  public EnforcementState(LongSupplier clock) {
    this.clock = clock;
  }

  public void blockSource(String ip, long untilTime) {
    this.bound(this.blockedSources, Settings.IMP.PROTECTION.ENFORCEMENT.MAX_BLOCKED_SOURCES);
    this.blockedSources.merge(ip, untilTime, Math::max);
  }

  public void shieldAccount(String lowercaseNickname, long untilTime) {
    this.bound(this.shieldedAccounts, Settings.IMP.PROTECTION.ENFORCEMENT.MAX_SHIELDED_ACCOUNTS);
    this.shieldedAccounts.merge(lowercaseNickname, untilTime, Math::max);
  }

  public boolean isSourceBlocked(String ip) {
    return this.isActive(this.blockedSources.get(ip));
  }

  public boolean isAccountShielded(String lowercaseNickname) {
    return this.isActive(this.shieldedAccounts.get(lowercaseNickname));
  }

  /**
   * Removes any block or shield matching the target (an IP or a nickname).
   *
   * @return a human-readable list of what was removed, or {@code null} if nothing matched.
   */
  public String unblock(String target) {
    StringBuilder removed = new StringBuilder();
    if (this.blockedSources.remove(target) != null) {
      removed.append("source block ").append(target);
    }

    String lowercase = target.toLowerCase(Locale.ROOT);
    if (this.shieldedAccounts.remove(lowercase) != null) {
      if (removed.length() > 0) {
        removed.append(", ");
      }

      removed.append("account shield ").append(lowercase);
    }

    return removed.length() == 0 ? null : removed.toString();
  }

  public void purge(long now) {
    this.blockedSources.values().removeIf(until -> until <= now);
    this.shieldedAccounts.values().removeIf(until -> until <= now);
  }

  public int getBlockedSourceCount() {
    return this.blockedSources.size();
  }

  public int getShieldedAccountCount() {
    return this.shieldedAccounts.size();
  }

  /**
   * Sorted copies for admin display; expired entries are excluded.
   */
  public Map<String, Long> snapshotBlockedSources() {
    return this.snapshot(this.blockedSources);
  }

  public Map<String, Long> snapshotShieldedAccounts() {
    return this.snapshot(this.shieldedAccounts);
  }

  private Map<String, Long> snapshot(Map<String, Long> source) {
    long now = this.clock.getAsLong();
    Map<String, Long> copy = new TreeMap<>();
    source.forEach((key, until) -> {
      if (until > now) {
        copy.put(key, until);
      }
    });

    return copy;
  }

  private boolean isActive(Long until) {
    return until != null && until > this.clock.getAsLong();
  }

  private void bound(Map<String, Long> map, int maxEntries) {
    // Flood backstop, mirroring the aggregator windows: evict an arbitrary entry above the cap.
    while (map.size() >= Math.max(1, maxEntries)) {
      Iterator<String> iterator = map.keySet().iterator();
      if (iterator.hasNext()) {
        iterator.next();
        iterator.remove();
      } else {
        break;
      }
    }
  }
}
