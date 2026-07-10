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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
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

  /**
   * Distinct FOREIGN accounts this password fingerprint was tried against. One owner
   * reusing a password across their own alts stays at zero here, so the spray
   * confirmation can tell an alt family from a genuine spray.
   */
  public int distinctForeignFingerprintTargets(long since) {
    return this.distinctCount(since, event -> event.foreignTarget()
        && (event.outcome() == AttemptOutcome.LOGIN_FAIL || event.outcome() == AttemptOutcome.LOGIN_SUCCESS), AttemptEvent::nickname);
  }

  /**
   * Distinct FOREIGN existing accounts that had a failed login in this window: the
   * "this source keeps failing against accounts that are not its own" signal of a
   * credential-stuffing run, which shared-IP households cannot produce.
   */
  public int distinctForeignFailedTargets(long since) {
    return this.distinctCount(since, event -> event.outcome() == AttemptOutcome.LOGIN_FAIL && event.foreignTarget(), AttemptEvent::nickname);
  }

  /**
   * Successful logins on foreign targets that were never surfaced at confirmation
   * severity, for the retroactive pass over a source that only later revealed itself
   * as multi-target.
   */
  public List<AttemptEvent> unalertedForeignSuccesses(long since) {
    List<AttemptEvent> successes = new ArrayList<>();
    for (AttemptEvent event : this.events) {
      if (event.time() >= since && event.outcome() == AttemptOutcome.LOGIN_SUCCESS
          && event.foreignTarget() && !event.isConfirmationAlerted()) {
        successes.add(event);
      }
    }

    return successes;
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

  /**
   * One observed attempt, shared by the ip/subnet/account/fingerprint windows it fell
   * into. {@code foreignTarget} means the targeted account exists and its stored LOGINIP
   * sits on a different subnet than the attempt's source - the subnet-level, any-outcome
   * generalization of the success-only, exact-IP {@code newSource} flag (kept separate on
   * purpose: {@code newSource} is spec-blessed for MULTI_ACCOUNT_NEW_SOURCE_SUCCESS, so
   * do not invent a third variant). Not a record only because of the single mutable
   * {@code confirmationAlerted} marker, which - like all window state - is touched
   * exclusively by the protection executor thread.
   */
  public static final class AttemptEvent {

    private final long time;
    private final String nickname;
    private final boolean accountExists;
    private final String ip;
    private final AttemptOutcome outcome;
    private final boolean churn;
    private final boolean newSource;
    private final boolean foreignTarget;
    private boolean confirmationAlerted;

    public AttemptEvent(long time, String nickname, boolean accountExists, String ip, AttemptOutcome outcome, boolean churn,
                        boolean newSource, boolean foreignTarget) {
      this.time = time;
      this.nickname = nickname;
      this.accountExists = accountExists;
      this.ip = ip;
      this.outcome = outcome;
      this.churn = churn;
      this.newSource = newSource;
      this.foreignTarget = foreignTarget;
    }

    public long time() {
      return this.time;
    }

    public String nickname() {
      return this.nickname;
    }

    public boolean accountExists() {
      return this.accountExists;
    }

    public String ip() {
      return this.ip;
    }

    public AttemptOutcome outcome() {
      return this.outcome;
    }

    public boolean churn() {
      return this.churn;
    }

    public boolean newSource() {
      return this.newSource;
    }

    public boolean foreignTarget() {
      return this.foreignTarget;
    }

    /**
     * Whether this success has already been reported at confirmation severity, either
     * live or by an earlier retroactive pass. Prevents the retroactive elevation from
     * re-alerting the same hit every time the source crosses a tier again.
     */
    public boolean isConfirmationAlerted() {
      return this.confirmationAlerted;
    }

    public void markConfirmationAlerted() {
      this.confirmationAlerted = true;
    }
  }
}
