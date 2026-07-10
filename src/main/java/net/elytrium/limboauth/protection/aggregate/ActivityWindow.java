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

import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import net.elytrium.limboauth.protection.AttemptOutcome;

/**
 * Bounded sliding window of attempt events for one tracked key (IP, subnet, account or
 * password fingerprint). Only the single-threaded protection executor mutates instances,
 * so no synchronization is needed.
 */
public class ActivityWindow {

  private final ArrayDeque<AttemptEvent> events = new ArrayDeque<>();
  private long lastTouched;

  public void add(AttemptEvent event, int maxEvents) {
    this.events.addLast(event);
    while (this.events.size() > maxEvents) {
      this.events.removeFirst();
    }

    this.lastTouched = Math.max(this.lastTouched, event.time());
  }

  public void trim(long minTime) {
    while (!this.events.isEmpty() && this.events.peekFirst().time() < minTime) {
      this.events.removeFirst();
    }
  }

  public boolean isEmpty() {
    return this.events.isEmpty();
  }

  public long getLastTouched() {
    return this.lastTouched;
  }

  public int countFails(long since) {
    int count = 0;
    for (AttemptEvent event : this.events) {
      if (event.time() >= since && event.outcome() == AttemptOutcome.LOGIN_FAIL) {
        ++count;
      }
    }

    return count;
  }

  /**
   * Distinct existing accounts that had a failed login in this window. Nonexistent
   * usernames (typos, name scans) are deliberately excluded from this heavier signal.
   */
  public int distinctFailedExistingTargets(long since) {
    return this.distinctCount(since,
        event -> event.outcome() == AttemptOutcome.LOGIN_FAIL && event.accountExists(), AttemptEvent::nickname);
  }

  public int distinctIps(long since) {
    return this.distinctCount(since, event -> true, AttemptEvent::ip);
  }

  public int distinctFailIps(long since) {
    return this.distinctCount(since, event -> event.outcome() == AttemptOutcome.LOGIN_FAIL, AttemptEvent::ip);
  }

  public int countFailsFromOtherIps(long since, String currentIp) {
    int count = 0;
    for (AttemptEvent event : this.events) {
      if (event.time() >= since && event.outcome() == AttemptOutcome.LOGIN_FAIL && !event.ip().equals(currentIp)) {
        ++count;
      }
    }

    return count;
  }

  /**
   * Distinct existing accounts this password fingerprint was tried against.
   */
  public int distinctFingerprintTargets(long since) {
    return this.distinctCount(since, event -> event.accountExists()
        && (event.outcome() == AttemptOutcome.LOGIN_FAIL || event.outcome() == AttemptOutcome.LOGIN_SUCCESS), AttemptEvent::nickname);
  }

  public int countChurnSessions(long since) {
    int count = 0;
    for (AttemptEvent event : this.events) {
      if (event.time() >= since && event.churn()) {
        ++count;
      }
    }

    return count;
  }

  /**
   * Distinct accounts successfully logged into from this source while the account's stored
   * LOGINIP pointed elsewhere. Alts relogged by their owner keep their stored IP and are
   * excluded, so this only counts takeover-shaped successes.
   */
  public int distinctNewSourceSuccesses(long since) {
    return this.distinctCount(since, AttemptEvent::newSource, AttemptEvent::nickname);
  }

  private int distinctCount(long since, Predicate<AttemptEvent> filter, Function<AttemptEvent, String> key) {
    Set<String> values = new HashSet<>();
    for (AttemptEvent event : this.events) {
      if (event.time() >= since && filter.test(event)) {
        values.add(key.apply(event));
      }
    }

    return values.size();
  }

  public record AttemptEvent(long time, String nickname, boolean accountExists, String ip, AttemptOutcome outcome, boolean churn,
                             boolean newSource) {
  }
}
