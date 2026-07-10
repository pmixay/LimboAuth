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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import net.elytrium.limboauth.protection.action.EnforceActionPolicy;
import net.elytrium.limboauth.protection.action.EnforcementState;
import net.elytrium.limboauth.protection.aggregate.ProtectionAggregator;
import net.elytrium.limboauth.protection.scoring.RiskAssessment;
import net.elytrium.limboauth.protection.scoring.RiskScorer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/**
 * End-to-end enforcement scenarios: attempts flow through the real aggregator and scorer,
 * and every assessment is fed to the real {@link EnforceActionPolicy} with the shipped
 * default thresholds - exactly what {@code ProtectionManager#process} does in ENFORCE
 * mode. The attacker patterns must end kicked/blocked/shielded; the legitimate-player
 * patterns must end with zero actions taken.
 */
class EnforcementScenarioTest {

  private static final long NOW = 1_700_000_000_000L;

  @BeforeAll
  static void loadSettings() {
    TestSettings.load();
  }

  /**
   * The real checking behavior this feature targets: a person works through leaked
   * credentials from one IP at human pace - five accounts fail across 40 minutes (wrong or
   * rotated passwords, quitting between accounts), then the sixth, a dormant account, hits
   * first-try. The moment of harm - the takeover-shaped success - must be kicked, the
   * source blocked and the account shielded, all without GeoIP being configured.
   */
  @Test
  void humanCheckerRunEndsKickedBlockedAndShielded() throws Exception {
    Harness harness = new Harness();
    String checkerIp = "203.0.113.99";

    for (int i = 0; i < 5; ++i) {
      long joinTime = NOW + i * 8L * 60000;
      RiskAssessment assessment = harness.observe(AttemptObservation
          .builder("leaked" + i, InetAddress.getByName(checkerIp), AttemptOutcome.LOGIN_FAIL)
          .accountExists(true)
          .timestamp(joinTime)
          .millisSinceJoin(7000)
          .firstAttemptOfSession(true)
          .clientBrand("vanilla")
          .fingerprint(6000L + i)
          .build());
      assertFalse(assessment.severity().atLeast(Severity.HIGH),
          "failures alone must not be enforced against yet, got " + assessment.severity() + " at account " + i);

      harness.observe(AttemptObservation
          .builder("leaked" + i, InetAddress.getByName(checkerIp), AttemptOutcome.SESSION_END)
          .accountExists(true)
          .timestamp(joinTime + 9000)
          .millisSinceJoin(16000)
          .sessionAttempts(1)
          .build());
    }

    assertTrue(harness.kicked.isEmpty(), "no enforcement before the confident moment");

    long hitTime = NOW + 41L * 60000;
    harness.clock.set(hitTime);
    RiskAssessment hit = harness.observe(AttemptObservation
        .builder("victim", InetAddress.getByName(checkerIp), AttemptOutcome.LOGIN_SUCCESS)
        .accountExists(true)
        .timestamp(hitTime)
        .millisSinceJoin(6000)
        .firstAttemptOfSession(true)
        .clientBrand("vanilla")
        .storedLoginIp("198.51.100.44")
        .storedLoginDate(hitTime - 45L * 86400000)
        .fingerprint(31337L)
        .build());

    assertTrue(hit.severity().atLeast(Severity.HIGH), "the takeover-shaped success must be HIGH, got " + hit.severity());
    assertEquals(List.of("victim@" + checkerIp), harness.kicked);
    assertTrue(harness.state.isSourceBlocked(checkerIp));
    assertTrue(harness.state.isAccountShielded("victim"));
  }

  /**
   * FPR guard: the forgotten-password player - failures and the eventual success all from
   * their own IP - must never be kicked, blocked or shielded.
   */
  @Test
  void forgottenPasswordIsNeverEnforcedAgainst() throws Exception {
    Harness harness = new Harness();
    String ownIp = "192.0.2.10";

    for (int i = 0; i < 8; ++i) {
      harness.observe(AttemptObservation
          .builder("me", InetAddress.getByName(ownIp), AttemptOutcome.LOGIN_FAIL)
          .accountExists(true)
          .timestamp(NOW + i * 20000L)
          .millisSinceJoin(6000 + i * 1000L)
          .clientBrand("vanilla")
          .fingerprint(2000L + i)
          .build());
    }

    harness.observe(AttemptObservation
        .builder("me", InetAddress.getByName(ownIp), AttemptOutcome.LOGIN_SUCCESS)
        .accountExists(true)
        .timestamp(NOW + 200000L)
        .millisSinceJoin(9000)
        .clientBrand("vanilla")
        .storedLoginIp(ownIp)
        .storedLoginDate(NOW - 86400000L)
        .fingerprint(3000L)
        .build());

    assertTrue(harness.kicked.isEmpty());
    assertEquals(0, harness.state.getBlockedSourceCount());
    assertEquals(0, harness.state.getShieldedAccountCount());
  }

  /**
   * FPR guard: hour-spread mistypes from a shared IP stay entirely unenforced.
   */
  @Test
  void sharedIpMistypesAreNeverEnforcedAgainst() throws Exception {
    Harness harness = new Harness();

    for (int player = 0; player < 3; ++player) {
      for (int attempt = 0; attempt < 2; ++attempt) {
        harness.observe(AttemptObservation
            .builder("classmate" + player, InetAddress.getByName("192.0.2.50"), AttemptOutcome.LOGIN_FAIL)
            .accountExists(true)
            .timestamp(NOW + (player * 2L + attempt) * 11L * 60000)
            .millisSinceJoin(5000)
            .clientBrand("fabric")
            .fingerprint(4000L + player * 10L + attempt)
            .build());
      }
    }

    assertTrue(harness.kicked.isEmpty());
    assertEquals(0, harness.state.getBlockedSourceCount());
    assertEquals(0, harness.state.getShieldedAccountCount());
  }

  private static final class Harness {

    private final ProtectionAggregator aggregator = new ProtectionAggregator();
    private final RiskScorer scorer = new RiskScorer();
    private final AtomicLong clock = new AtomicLong(NOW);
    private final EnforcementState state = new EnforcementState(this.clock::get);
    private final List<String> kicked = new ArrayList<>();
    private final EnforceActionPolicy policy =
        new EnforceActionPolicy(this.state, (nickname, ip) -> this.kicked.add(nickname + "@" + ip), LoggerFactory.getLogger("test"));

    RiskAssessment observe(AttemptObservation observation) {
      this.clock.set(observation.getTimestamp());
      this.aggregator.update(observation);
      if (observation.getOutcome() == AttemptOutcome.SESSION_END) {
        return null;
      }

      RiskAssessment assessment = this.scorer.score(observation, this.aggregator.snapshot(observation), null, null);
      this.policy.apply(observation, assessment);
      return assessment;
    }
  }
}
