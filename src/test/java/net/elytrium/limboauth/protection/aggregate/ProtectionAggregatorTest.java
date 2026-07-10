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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.util.List;
import net.elytrium.limboauth.protection.AttemptObservation;
import net.elytrium.limboauth.protection.AttemptOutcome;
import net.elytrium.limboauth.protection.TestSettings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class ProtectionAggregatorTest {

  @BeforeAll
  static void loadSettings() {
    TestSettings.load();
  }

  @Test
  void tracksDistinctTargetsPerIpAndSpraysPerFingerprint() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    long now = 1_000_000_000L;

    // One attacker IP fails against three different existing accounts with the same password.
    for (int i = 0; i < 3; ++i) {
      aggregator.update(this.attempt("victim" + i, "203.0.113.7", now + i * 1000, AttemptOutcome.LOGIN_FAIL, 777L));
    }

    AttemptObservation last = this.attempt("victim2", "203.0.113.7", now + 5000, AttemptOutcome.LOGIN_FAIL, 777L);
    aggregator.update(last);
    AggregateSnapshot snapshot = aggregator.snapshot(last);

    assertEquals(4, snapshot.ipFailures());
    assertEquals(3, snapshot.ipDistinctFailedTargets());
    assertEquals(3, snapshot.fingerprintDistinctTargets());
  }

  @Test
  void humanPacedTargetsCountAcrossDistributionWindow() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    long now = 1_000_000_000L;

    // Two failed accounts 30 minutes apart: far outside the 10-minute volume window,
    // but a human working through leaked credentials must still be seen as one campaign.
    aggregator.update(this.attempt("victim0", "203.0.113.7", now, AttemptOutcome.LOGIN_FAIL, 1L));
    AttemptObservation last = this.attempt("victim1", "203.0.113.7", now + 30L * 60000, AttemptOutcome.LOGIN_FAIL, 2L);
    aggregator.update(last);

    AggregateSnapshot snapshot = aggregator.snapshot(last);
    assertEquals(1, snapshot.ipFailures());
    assertEquals(2, snapshot.ipDistinctFailedTargets());
  }

  @Test
  void newSourceSuccessesCountDistinctAccountsFromElsewhere() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    long now = 1_000_000_000L;
    String ip = "203.0.113.7";

    aggregator.update(this.success("stolen1", ip, now, "198.51.100.1"));
    aggregator.update(this.success("stolen2", ip, now + 60000, "198.51.100.2"));
    // Own alt: its stored login IP is the current address, so it is not a "new source".
    aggregator.update(this.success("ownalt", ip, now + 120000, ip));
    // Failures never count, whatever their stored IP says.
    AttemptObservation fail = this.attempt("other", ip, now + 180000, AttemptOutcome.LOGIN_FAIL, 9L);
    aggregator.update(fail);

    assertEquals(2, aggregator.snapshot(fail).ipDistinctNewSourceSuccesses());
  }

  /**
   * The foreign-target counts only see existing accounts whose stored LOGINIP sits on a
   * different subnet than the source: the owner's own accounts (stored on the source's
   * subnet), never-logged-in rows and nonexistent names all stay invisible to them.
   */
  @Test
  void foreignCountsExcludeOwnSubnetUnknownAndNonexistentAccounts() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    long now = 1_000_000_000L;
    String ip = "203.0.113.7";

    // Foreign: exists, stored on another subnet.
    aggregator.update(this.storedFail("victim1", ip, now, "198.51.100.4", true));
    // The source's own subnet: an alt or the player's own account after a router reboot.
    aggregator.update(this.storedFail("ownalt", ip, now + 1000, "203.0.113.200", true));
    // No stored login IP at all (registered but never logged in, or a legacy row).
    aggregator.update(this.storedFail("fresh", ip, now + 2000, null, true));
    // Nonexistent username.
    aggregator.update(this.storedFail("ghost", ip, now + 3000, "198.51.100.9", false));

    AttemptObservation last = this.storedFail("victim2", ip, now + 4000, "198.51.100.5", true);
    aggregator.update(last);
    AggregateSnapshot snapshot = aggregator.snapshot(last);

    // The raw counts still see every existing account; the foreign fail count only the
    // two victims, and the fingerprint count additionally excludes the current target
    // (victim2) - it answers "how many OTHER foreign accounts got this password".
    assertEquals(4, snapshot.ipDistinctFailedTargets());
    assertEquals(4, snapshot.fingerprintDistinctTargets());
    assertEquals(2, snapshot.foreignFailedTargets());
    assertEquals(1, snapshot.foreignFingerprintTargets());
  }

  @Test
  void foreignFailedTargetsCanBeReadWithoutFoldingTheAttemptIn() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    long now = 1_000_000_000L;
    String ip = "203.0.113.7";

    AttemptObservation attempt = this.storedFail("victim1", ip, now, "198.51.100.4", true);
    assertEquals(0, aggregator.foreignFailedTargets(attempt));
    aggregator.update(attempt);
    assertEquals(1, aggregator.foreignFailedTargets(this.storedFail("victim2", ip, now + 1000, "198.51.100.5", true)));
  }

  @Test
  void unalertedForeignSuccessesSkipMarkedAndOwnSubnetEvents() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    long now = 1_000_000_000L;
    String ip = "203.0.113.7";

    final ActivityWindow.AttemptEvent foreignHit = aggregator.update(this.success("stolen", ip, now, "198.51.100.4"));
    aggregator.update(this.success("ownalt", ip, now + 1000, ip));
    AttemptObservation probe = this.storedFail("victim", ip, now + 2000, "198.51.100.9", true);
    aggregator.update(probe);

    List<ActivityWindow.AttemptEvent> candidates = aggregator.unalertedForeignSuccesses(probe);
    assertEquals(1, candidates.size());
    assertEquals("stolen", candidates.get(0).nickname());

    foreignHit.markConfirmationAlerted();
    assertTrue(aggregator.unalertedForeignSuccesses(probe).isEmpty());
  }

  @Test
  void accountUnderDistributedAttackCountsOtherIpsOnly() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    long now = 1_000_000_000L;

    aggregator.update(this.attempt("victim", "198.51.100.1", now, AttemptOutcome.LOGIN_FAIL, 1L));
    aggregator.update(this.attempt("victim", "198.51.100.2", now + 1000, AttemptOutcome.LOGIN_FAIL, 2L));
    AttemptObservation ownIp = this.attempt("victim", "203.0.113.7", now + 2000, AttemptOutcome.LOGIN_SUCCESS, 3L);
    aggregator.update(ownIp);

    AggregateSnapshot snapshot = aggregator.snapshot(ownIp);
    assertEquals(2, snapshot.accountDistinctFailIps());
    assertEquals(2, snapshot.accountFailsFromOtherIps());

    // Same story but the failures came from the success IP itself: not "other IPs".
    ProtectionAggregator sameIp = new ProtectionAggregator();
    sameIp.update(this.attempt("victim", "203.0.113.7", now, AttemptOutcome.LOGIN_FAIL, 1L));
    sameIp.update(this.attempt("victim", "203.0.113.7", now + 1000, AttemptOutcome.LOGIN_FAIL, 2L));
    AttemptObservation success = this.attempt("victim", "203.0.113.7", now + 2000, AttemptOutcome.LOGIN_SUCCESS, 3L);
    sameIp.update(success);
    assertEquals(0, sameIp.snapshot(success).accountFailsFromOtherIps());
  }

  @Test
  void churnSessionsAreCounted() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    long now = 1_000_000_000L;

    for (int i = 0; i < 3; ++i) {
      AttemptObservation end = AttemptObservation
          .builder("bot" + i, InetAddress.getByName("203.0.113.7"), AttemptOutcome.SESSION_END)
          .timestamp(now + i * 1000)
          .millisSinceJoin(5000)
          .sessionAttempts(1)
          .build();
      aggregator.update(end);
    }

    AttemptObservation attempt = this.attempt("victim", "203.0.113.7", now + 10000, AttemptOutcome.LOGIN_FAIL, 1L);
    aggregator.update(attempt);
    assertEquals(3, aggregator.snapshot(attempt).ipChurnSessions());
  }

  @Test
  void longSessionsDoNotCountAsChurn() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    long now = 1_000_000_000L;

    AttemptObservation end = AttemptObservation
        .builder("player", InetAddress.getByName("203.0.113.7"), AttemptOutcome.SESSION_END)
        .timestamp(now)
        .millisSinceJoin(120000)
        .sessionAttempts(1)
        .build();
    aggregator.update(end);

    AttemptObservation attempt = this.attempt("victim", "203.0.113.7", now + 1000, AttemptOutcome.LOGIN_FAIL, 1L);
    aggregator.update(attempt);
    assertEquals(0, aggregator.snapshot(attempt).ipChurnSessions());
  }

  @Test
  void flaggedSourcesExpire() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    aggregator.markFlagged("203.0.113.7", 2000);
    assertTrue(aggregator.isFlagged("203.0.113.7", 1000));
    assertFalse(aggregator.isFlagged("203.0.113.7", 3000));
    aggregator.purge(3000);
    assertEquals(0, aggregator.getFlaggedSources());
  }

  @Test
  void purgeEvictsIdleWindows() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    long now = 1_000_000_000L;
    aggregator.update(this.attempt("victim", "203.0.113.7", now, AttemptOutcome.LOGIN_FAIL, 1L));
    assertEquals(1, aggregator.getTrackedIps());
    aggregator.purge(now + 24L * 3600 * 1000);
    assertEquals(0, aggregator.getTrackedIps());
  }

  private AttemptObservation attempt(String nickname, String ip, long time, AttemptOutcome outcome, long fingerprint) throws Exception {
    return AttemptObservation.builder(nickname, InetAddress.getByName(ip), outcome)
        .accountExists(true)
        .timestamp(time)
        .millisSinceJoin(5000)
        .fingerprint(fingerprint)
        .build();
  }

  private AttemptObservation success(String nickname, String ip, long time, String storedLoginIp) throws Exception {
    return AttemptObservation.builder(nickname, InetAddress.getByName(ip), AttemptOutcome.LOGIN_SUCCESS)
        .accountExists(true)
        .timestamp(time)
        .millisSinceJoin(5000)
        .storedLoginIp(storedLoginIp)
        .fingerprint(7L)
        .build();
  }

  private AttemptObservation storedFail(String nickname, String ip, long time, String storedLoginIp, boolean accountExists) throws Exception {
    return AttemptObservation.builder(nickname, InetAddress.getByName(ip), AttemptOutcome.LOGIN_FAIL)
        .accountExists(accountExists)
        .timestamp(time)
        .millisSinceJoin(5000)
        .storedLoginIp(storedLoginIp)
        .fingerprint(777L)
        .build();
  }
}
