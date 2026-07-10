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

package net.elytrium.limboauth.protection.scoring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import net.elytrium.limboauth.protection.AttemptObservation;
import net.elytrium.limboauth.protection.AttemptOutcome;
import net.elytrium.limboauth.protection.Severity;
import net.elytrium.limboauth.protection.TestSettings;
import net.elytrium.limboauth.protection.aggregate.AggregateSnapshot;
import net.elytrium.limboauth.protection.geoip.GeoIpResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class RiskScorerTest {

  private final RiskScorer scorer = new RiskScorer();

  @BeforeAll
  static void loadSettings() {
    TestSettings.load();
  }

  @Test
  void behaviorAloneNeverReachesSuspicious() throws Exception {
    // Instant first command from a brand-less client, but no volume/distribution signals at all.
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 100, true, null);
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, false), null, null);
    assertTrue(assessment.hasFactor(RiskFactor.INSTANT_FIRST_COMMAND));
    assertTrue(assessment.hasFactor(RiskFactor.MISSING_BRAND));
    assertFalse(assessment.severity().atLeast(Severity.SUSPICIOUS));
  }

  @Test
  void volumeTiersApply() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 5000, false, "vanilla");
    assertEquals(10, this.scorer.score(observation, this.snapshot(6, 0, 0, 0, 0, 0, 0, 0, 0, false), null, null).score());
    assertEquals(15, this.scorer.score(observation, this.snapshot(10, 0, 0, 0, 0, 0, 0, 0, 0, false), null, null).score());
    assertEquals(20, this.scorer.score(observation, this.snapshot(20, 0, 0, 0, 0, 0, 0, 0, 0, false), null, null).score());
  }

  @Test
  void singleVolumeCategoryIsCappedBelowHigh() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 5000, false, "vanilla");
    // Raw volume: 20 (fails) + 30 (10 targets) + 20 (subnet) = 70, capped at 35.
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(20, 10, 0, 10, 3, 0, 0, 0, 0, false), null, null);
    assertEquals(35, assessment.score());
    assertEquals(Severity.SUSPICIOUS, assessment.severity());
    assertFalse(assessment.severity().atLeast(Severity.HIGH));
  }

  @Test
  void subnetFactorRequiresMultipleSourceIps() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 5000, false, "vanilla");
    RiskAssessment single = this.scorer.score(observation, this.snapshot(0, 0, 0, 10, 1, 0, 0, 0, 0, false), null, null);
    assertFalse(single.hasFactor(RiskFactor.SUBNET_DISTINCT_TARGETS));
    RiskAssessment multiple = this.scorer.score(observation, this.snapshot(0, 0, 0, 10, 2, 0, 0, 0, 0, false), null, null);
    assertTrue(multiple.hasFactor(RiskFactor.SUBNET_DISTINCT_TARGETS));
  }

  @Test
  void successAfterOwnFailuresFromSameIpIsNotConfirmed() throws Exception {
    // The classic forgotten-password case: failures exist, but all from the player's own IP.
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_SUCCESS, true, 8000, false, "vanilla");
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(8, 1, 0, 0, 0, 0, 1, 0, 0, false), null, null);
    assertFalse(assessment.hasFactor(RiskFactor.CONFIRM_SUCCESS_AFTER_DISTRIBUTED_FAILURES));
    assertFalse(assessment.hasFactor(RiskFactor.CONFIRM_SUCCESS_FROM_FLAGGED_SOURCE));
    assertFalse(assessment.hasFactor(RiskFactor.CONFIRM_SPRAYED_PASSWORD_SUCCESS));
    assertFalse(assessment.severity().atLeast(Severity.HIGH));
  }

  @Test
  void successAfterDistributedFailuresIsCritical() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_SUCCESS, true, 8000, false, "vanilla");
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(0, 0, 0, 0, 0, 0, 2, 2, 0, false), null, null);
    assertTrue(assessment.hasFactor(RiskFactor.CONFIRM_SUCCESS_AFTER_DISTRIBUTED_FAILURES));
    assertEquals(Severity.CRITICAL, assessment.severity());
    assertEquals("account:target", assessment.clusterKey());
  }

  @Test
  void sprayedPasswordSuccessIsCritical() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_SUCCESS, true, 8000, false, "vanilla");
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 3, false), null, null);
    assertTrue(assessment.hasFactor(RiskFactor.CONFIRM_SPRAYED_PASSWORD_SUCCESS));
    assertTrue(assessment.severity().atLeast(Severity.CRITICAL));
  }

  @Test
  void failedSprayIsNotConfirmation() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 8000, false, "vanilla");
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 5, false), null, null);
    assertTrue(assessment.hasFactor(RiskFactor.PASSWORD_SPRAY));
    assertFalse(assessment.hasFactor(RiskFactor.CONFIRM_SPRAYED_PASSWORD_SUCCESS));
    assertFalse(assessment.severity().atLeast(Severity.HIGH));
  }

  @Test
  void geoIsCappedAndCountryMismatchIsStrong() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 8000, false, "vanilla");
    GeoIpResult geo = new GeoIpResult("DE", 12345L, "Example Hosting GmbH");
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, false), geo, "RU");
    assertTrue(assessment.hasFactor(RiskFactor.GEO_COUNTRY_MISMATCH));
    assertTrue(assessment.hasFactor(RiskFactor.GEO_HOSTING_ASN));
    // Raw 20 + 10 = 30, equal to the GEO cap: alone it can reach SUSPICIOUS but never HIGH.
    assertEquals(30, assessment.score());
    assertEquals(Severity.SUSPICIOUS, assessment.severity());
  }

  @Test
  void churnRequiresThreeSessions() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 8000, false, "vanilla");
    assertFalse(this.scorer.score(observation, this.snapshot(0, 0, 2, 0, 0, 0, 0, 0, 0, false), null, null)
        .hasFactor(RiskFactor.CHURN_SESSIONS));
    assertTrue(this.scorer.score(observation, this.snapshot(0, 0, 3, 0, 0, 0, 0, 0, 0, false), null, null)
        .hasFactor(RiskFactor.CHURN_SESSIONS));
  }

  @Test
  void clusterKeyPrefersSprayOverIp() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 8000, false, "vanilla");
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 5, false), null, null);
    assertTrue(assessment.clusterKey().startsWith("spray:"));
    RiskAssessment plain = this.scorer.score(observation, this.snapshot(20, 0, 0, 0, 0, 0, 0, 0, 0, false), null, null);
    assertTrue(plain.clusterKey().startsWith("ip:"));
  }

  private AggregateSnapshot snapshot(int ipFailures, int ipDistinctFailedTargets, int ipChurnSessions,
                                     int subnetDistinctFailedTargets, int subnetDistinctIps, int subnetChurnSessions,
                                     int accountDistinctFailIps, int accountFailsFromOtherIps,
                                     int fingerprintDistinctTargets, boolean sourceFlagged) {
    return new AggregateSnapshot(ipFailures, ipDistinctFailedTargets, ipChurnSessions, subnetDistinctFailedTargets,
        subnetDistinctIps, subnetChurnSessions, accountDistinctFailIps, accountFailsFromOtherIps,
        fingerprintDistinctTargets, sourceFlagged);
  }

  private AttemptObservation observation(AttemptOutcome outcome, boolean accountExists, long millisSinceJoin,
                                         boolean firstAttempt, String brand) throws Exception {
    AttemptObservation.Builder builder = AttemptObservation.builder("target", InetAddress.getByName("203.0.113.7"), outcome)
        .accountExists(accountExists)
        .millisSinceJoin(millisSinceJoin)
        .firstAttemptOfSession(firstAttempt)
        .clientBrand(brand)
        .fingerprint(42L);
    return builder.build();
  }
}
