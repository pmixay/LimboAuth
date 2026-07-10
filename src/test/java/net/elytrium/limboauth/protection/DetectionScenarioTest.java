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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import net.elytrium.limboauth.protection.aggregate.ProtectionAggregator;
import net.elytrium.limboauth.protection.scoring.RiskAssessment;
import net.elytrium.limboauth.protection.scoring.RiskScorer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Scenario tests that replay whole attacks through aggregator + scorer, mirroring what
 * {@code ProtectionManager#process} does per attempt. These pin the emergent behavior:
 * checker patterns must escalate, legitimate-player patterns must not.
 */
class DetectionScenarioTest {

  @BeforeAll
  static void loadSettings() {
    TestSettings.load();
  }

  /**
   * A password checker replays a combo list from one IP: for each of 10 existing accounts
   * it connects, tries one password and disconnects (the join-try-quit churn pattern).
   */
  @Test
  void singleIpComboListReachesHigh() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    RiskScorer scorer = new RiskScorer();
    long now = 1_000_000_000L;

    Severity worst = Severity.NONE;
    for (int i = 0; i < 10; ++i) {
      AttemptObservation attempt = AttemptObservation
          .builder("victim" + i, InetAddress.getByName("203.0.113.66"), AttemptOutcome.LOGIN_FAIL)
          .accountExists(true)
          .timestamp(now + i * 15000L)
          .millisSinceJoin(400)
          .firstAttemptOfSession(true)
          .fingerprint(1000L + i)
          .build();
      aggregator.update(attempt);
      RiskAssessment assessment = scorer.score(attempt, aggregator.snapshot(attempt), null, null);
      if (assessment.severity().atLeast(worst)) {
        worst = assessment.severity();
      }

      // The checker disconnects right after the attempt - a churn session.
      aggregator.update(AttemptObservation
          .builder("victim" + i, InetAddress.getByName("203.0.113.66"), AttemptOutcome.SESSION_END)
          .accountExists(true)
          .timestamp(now + i * 15000L + 1000)
          .millisSinceJoin(1400)
          .sessionAttempts(1)
          .build());
    }

    assertTrue(worst.atLeast(Severity.HIGH), "combo-list run should reach HIGH, got " + worst);
  }

  /**
   * The critical case: the checker finds a working password. Fails from two source IPs,
   * then the success comes from a third one.
   */
  @Test
  void distributedHitOnOneAccountIsCritical() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    RiskScorer scorer = new RiskScorer();
    long now = 1_000_000_000L;

    String[] failIps = {"198.51.100.1", "198.51.100.2"};
    for (int i = 0; i < failIps.length; ++i) {
      AttemptObservation fail = AttemptObservation
          .builder("victim", InetAddress.getByName(failIps[i]), AttemptOutcome.LOGIN_FAIL)
          .accountExists(true)
          .timestamp(now + i * 60000L)
          .millisSinceJoin(500)
          .firstAttemptOfSession(true)
          .fingerprint(500L + i)
          .build();
      aggregator.update(fail);
      scorer.score(fail, aggregator.snapshot(fail), null, null);
    }

    AttemptObservation hit = AttemptObservation
        .builder("victim", InetAddress.getByName("198.51.100.99"), AttemptOutcome.LOGIN_SUCCESS)
        .accountExists(true)
        .timestamp(now + 300000L)
        .millisSinceJoin(700)
        .firstAttemptOfSession(true)
        .fingerprint(999L)
        .build();
    aggregator.update(hit);
    RiskAssessment assessment = scorer.score(hit, aggregator.snapshot(hit), null, null);

    assertTrue(assessment.severity().atLeast(Severity.CRITICAL),
        "a success after distributed failures must be CRITICAL, got " + assessment.severity());
  }

  /**
   * FPR guard: a legitimate player who forgot their password. Several failures and then
   * a success, all from their own IP, with a normal client. Must never reach HIGH.
   */
  @Test
  void forgottenPasswordNeverReachesHigh() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    RiskScorer scorer = new RiskScorer();
    long now = 1_000_000_000L;

    Severity worst = Severity.NONE;
    for (int i = 0; i < 8; ++i) {
      AttemptObservation fail = AttemptObservation
          .builder("me", InetAddress.getByName("192.0.2.10"), AttemptOutcome.LOGIN_FAIL)
          .accountExists(true)
          .timestamp(now + i * 20000L)
          .millisSinceJoin(6000 + i * 1000L)
          .firstAttemptOfSession(i % 3 == 0)
          .clientBrand("vanilla")
          .fingerprint(2000L + i)
          .build();
      aggregator.update(fail);
      RiskAssessment assessment = scorer.score(fail, aggregator.snapshot(fail), null, null);
      if (assessment.severity().atLeast(worst)) {
        worst = assessment.severity();
      }
    }

    AttemptObservation success = AttemptObservation
        .builder("me", InetAddress.getByName("192.0.2.10"), AttemptOutcome.LOGIN_SUCCESS)
        .accountExists(true)
        .timestamp(now + 200000L)
        .millisSinceJoin(9000)
        .clientBrand("vanilla")
        .fingerprint(3000L)
        .build();
    aggregator.update(success);
    RiskAssessment finalAssessment = scorer.score(success, aggregator.snapshot(success), null, null);

    assertFalse(worst.atLeast(Severity.HIGH), "forgotten password must stay below HIGH, got " + worst);
    assertFalse(finalAssessment.severity().atLeast(Severity.HIGH),
        "the eventual own-IP success must stay below HIGH, got " + finalAssessment.severity());
  }

  /**
   * FPR guard: three players behind one shared IP (school/CGNAT) each mistyping once or
   * twice must never reach HIGH.
   */
  @Test
  void sharedIpMistypesStayBelowHigh() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    RiskScorer scorer = new RiskScorer();
    long now = 1_000_000_000L;

    Severity worst = Severity.NONE;
    for (int player = 0; player < 3; ++player) {
      for (int attempt = 0; attempt < 2; ++attempt) {
        AttemptObservation fail = AttemptObservation
            .builder("classmate" + player, InetAddress.getByName("192.0.2.50"), AttemptOutcome.LOGIN_FAIL)
            .accountExists(true)
            .timestamp(now + (player * 2L + attempt) * 30000L)
            .millisSinceJoin(5000)
            .clientBrand("fabric")
            .fingerprint(4000L + player * 10L + attempt)
            .build();
        aggregator.update(fail);
        RiskAssessment assessment = scorer.score(fail, aggregator.snapshot(fail), null, null);
        if (assessment.severity().atLeast(worst)) {
          worst = assessment.severity();
        }
      }
    }

    assertFalse(worst.atLeast(Severity.HIGH), "shared-IP mistypes must stay below HIGH, got " + worst);
  }

  /**
   * Password spraying: the same password tried against many accounts, low-and-slow,
   * and the moment it works it must be CRITICAL.
   */
  @Test
  void passwordSprayEscalatesAndHitIsCritical() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    RiskScorer scorer = new RiskScorer();
    long now = 1_000_000_000L;
    long sprayedPassword = 31337L;

    for (int i = 0; i < 4; ++i) {
      AttemptObservation fail = AttemptObservation
          .builder("target" + i, InetAddress.getByName("198.51.100." + (10 + i)), AttemptOutcome.LOGIN_FAIL)
          .accountExists(true)
          .timestamp(now + i * 600000L)
          .millisSinceJoin(800)
          .firstAttemptOfSession(true)
          .fingerprint(sprayedPassword)
          .build();
      aggregator.update(fail);
      scorer.score(fail, aggregator.snapshot(fail), null, null);
    }

    AttemptObservation hit = AttemptObservation
        .builder("target9", InetAddress.getByName("198.51.100.20"), AttemptOutcome.LOGIN_SUCCESS)
        .accountExists(true)
        .timestamp(now + 5 * 600000L)
        .millisSinceJoin(900)
        .firstAttemptOfSession(true)
        .fingerprint(sprayedPassword)
        .build();
    aggregator.update(hit);
    RiskAssessment assessment = scorer.score(hit, aggregator.snapshot(hit), null, null);

    assertTrue(assessment.severity().atLeast(Severity.CRITICAL),
        "a sprayed password that works must be CRITICAL, got " + assessment.severity());
  }
}
