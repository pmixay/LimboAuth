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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.util.concurrent.TimeUnit;
import net.elytrium.limboauth.protection.AttemptObservation;
import net.elytrium.limboauth.protection.AttemptOutcome;
import net.elytrium.limboauth.protection.Severity;
import net.elytrium.limboauth.protection.TestSettings;
import net.elytrium.limboauth.protection.aggregate.AggregateSnapshot;
import net.elytrium.limboauth.protection.geoip.GeoIpResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class RiskScorerTest {

  private static final long NOW = 1_700_000_000_000L;

  private final RiskScorer scorer = new RiskScorer();

  @BeforeAll
  static void loadSettings() {
    TestSettings.load();
  }

  @Test
  void behaviorAloneNeverReachesSuspicious() throws Exception {
    // Instant first command from a brand-less client, but no volume/distribution signals at all.
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 100, true, null);
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false), null, null);
    assertTrue(assessment.hasFactor(RiskFactor.INSTANT_FIRST_COMMAND));
    assertTrue(assessment.hasFactor(RiskFactor.MISSING_BRAND));
    assertFalse(assessment.severity().atLeast(Severity.SUSPICIOUS));
  }

  @Test
  void volumeTiersApply() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 5000, false, "vanilla");
    assertEquals(10, this.scorer.score(observation, this.snapshot(6, 0, 0, 0, 0, 0, 0, 0, 0, 0, false), null, null).score());
    assertEquals(15, this.scorer.score(observation, this.snapshot(10, 0, 0, 0, 0, 0, 0, 0, 0, 0, false), null, null).score());
    assertEquals(20, this.scorer.score(observation, this.snapshot(20, 0, 0, 0, 0, 0, 0, 0, 0, 0, false), null, null).score());
  }

  @Test
  void distinctTargetTiersCoverHumanPace() throws Exception {
    // 3 targets is still explainable by shared-IP mistypes (10); 4 leans checker (15).
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 5000, false, "vanilla");
    assertEquals(10, this.scorer.score(observation, this.snapshot(0, 3, 0, 0, 0, 0, 0, 0, 0, 0, false), null, null).score());
    assertEquals(15, this.scorer.score(observation, this.snapshot(0, 4, 0, 0, 0, 0, 0, 0, 0, 0, false), null, null).score());
    assertEquals(20, this.scorer.score(observation, this.snapshot(0, 5, 0, 0, 0, 0, 0, 0, 0, 0, false), null, null).score());
  }

  @Test
  void singleVolumeCategoryIsCappedBelowHigh() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 5000, false, "vanilla");
    // Raw volume: 20 (fails) + 30 (10 targets) + 20 (subnet) = 70, capped at 35.
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(20, 10, 0, 0, 10, 3, 0, 0, 0, 0, false), null, null);
    assertEquals(35, assessment.score());
    assertEquals(Severity.SUSPICIOUS, assessment.severity());
    assertFalse(assessment.severity().atLeast(Severity.HIGH));
  }

  @Test
  void subnetFactorRequiresMultipleSourceIps() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 5000, false, "vanilla");
    RiskAssessment single = this.scorer.score(observation, this.snapshot(0, 0, 0, 0, 10, 1, 0, 0, 0, 0, false), null, null);
    assertFalse(single.hasFactor(RiskFactor.SUBNET_DISTINCT_TARGETS));
    RiskAssessment multiple = this.scorer.score(observation, this.snapshot(0, 0, 0, 0, 10, 2, 0, 0, 0, 0, false), null, null);
    assertTrue(multiple.hasFactor(RiskFactor.SUBNET_DISTINCT_TARGETS));
  }

  @Test
  void successAfterOwnFailuresFromSameIpIsNotConfirmed() throws Exception {
    // The classic forgotten-password case: failures exist, but all from the player's own IP.
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_SUCCESS, true, 8000, false, "vanilla");
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(8, 1, 0, 0, 0, 0, 0, 1, 0, 0, false), null, null);
    assertFalse(assessment.hasFactor(RiskFactor.CONFIRM_SUCCESS_AFTER_DISTRIBUTED_FAILURES));
    assertFalse(assessment.hasFactor(RiskFactor.CONFIRM_SUCCESS_FROM_FLAGGED_SOURCE));
    assertFalse(assessment.hasFactor(RiskFactor.CONFIRM_SPRAYED_PASSWORD_SUCCESS));
    assertFalse(assessment.severity().atLeast(Severity.HIGH));
  }

  @Test
  void successAfterDistributedFailuresIsCritical() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_SUCCESS, true, 8000, false, "vanilla");
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(0, 0, 0, 0, 0, 0, 0, 2, 2, 0, false), null, null);
    assertTrue(assessment.hasFactor(RiskFactor.CONFIRM_SUCCESS_AFTER_DISTRIBUTED_FAILURES));
    assertEquals(Severity.CRITICAL, assessment.severity());
    assertEquals("account:target", assessment.clusterKey());
  }

  @Test
  void sprayedPasswordSuccessIsCritical() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_SUCCESS, true, 8000, false, "vanilla");
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 4, false, 3, 0), null, null);
    assertTrue(assessment.hasFactor(RiskFactor.CONFIRM_SPRAYED_PASSWORD_SUCCESS));
    assertTrue(assessment.severity().atLeast(Severity.CRITICAL));
  }

  @Test
  void sprayConfirmationNeedsThreeOtherForeignTargets() throws Exception {
    // Production-fitted default: a three-alt family relogged from a new subnet produces
    // exactly 2 other foreign targets and must stay unconfirmed; the third OTHER
    // account is what separates a campaign from a family.
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_SUCCESS, true, 8000, false, "vanilla");
    RiskAssessment family = this.scorer.score(observation, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 3, false, 2, 0), null, null);
    assertFalse(family.hasFactor(RiskFactor.CONFIRM_SPRAYED_PASSWORD_SUCCESS));
    assertFalse(family.severity().atLeast(Severity.HIGH));
  }

  @Test
  void sprayConfirmationIgnoresOwnAltFamilies() throws Exception {
    // The dnecek shape: the password hit 3 distinct accounts, but every one of them is
    // stored on the source's own subnet - zero foreign targets, so no confirmation.
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_SUCCESS, true, 8000, false, "vanilla");
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 3, false, 0, 0), null, null);
    assertTrue(assessment.hasFactor(RiskFactor.PASSWORD_SPRAY));
    assertFalse(assessment.hasFactor(RiskFactor.CONFIRM_SPRAYED_PASSWORD_SUCCESS));
    assertFalse(assessment.severity().atLeast(Severity.HIGH));
  }

  @Test
  void failedSprayIsNotConfirmation() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 8000, false, "vanilla");
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 5, false, 5, 0), null, null);
    assertTrue(assessment.hasFactor(RiskFactor.PASSWORD_SPRAY));
    assertFalse(assessment.hasFactor(RiskFactor.CONFIRM_SPRAYED_PASSWORD_SUCCESS));
    assertFalse(assessment.severity().atLeast(Severity.HIGH));
  }

  @Test
  void multiTargetSourceConfirmationTiersApply() throws Exception {
    // The success itself is on a foreign account (stored login IP on another subnet).
    AttemptObservation success = this.foreignSuccess();

    RiskAssessment below = this.scorer.score(success, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, 0, 2), null, null);
    assertFalse(below.hasFactor(RiskFactor.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE));

    RiskAssessment high = this.scorer.score(success, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, 0, 3), null, null);
    assertTrue(high.hasFactor(RiskFactor.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE));
    assertEquals(50, high.score());
    assertEquals(Severity.HIGH, high.severity());
    assertEquals("account:target", high.clusterKey());

    RiskAssessment critical = this.scorer.score(success, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, 0, 6), null, null);
    assertEquals(80, critical.score());
    assertEquals(Severity.CRITICAL, critical.severity());
  }

  @Test
  void multiTargetSourceConfirmationRequiresForeignSuccess() throws Exception {
    // A neighbor logging into their OWN account (stored on the source's subnet) must not
    // be confirmed by foreign failures somebody else produced behind the same source.
    AttemptObservation ownAccount = this.observation(AttemptOutcome.LOGIN_SUCCESS, true, 8000, false, "vanilla", "203.0.113.200");
    RiskAssessment own = this.scorer.score(ownAccount, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, 0, 6), null, null);
    assertFalse(own.hasFactor(RiskFactor.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE));

    // No stored login IP at all (never logged in): unknown is not foreign either.
    AttemptObservation unknown = this.observation(AttemptOutcome.LOGIN_SUCCESS, true, 8000, false, "vanilla");
    RiskAssessment noStored = this.scorer.score(unknown, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, 0, 6), null, null);
    assertFalse(noStored.hasFactor(RiskFactor.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE));
  }

  @Test
  void multiTargetSourceConfirmationIsSuccessOnly() throws Exception {
    // The failures themselves must stay on the volume/distribution path; only the
    // moment of harm - a success from the multi-target source - confirms.
    AttemptObservation fail = this.observation(AttemptOutcome.LOGIN_FAIL, true, 8000, false, "vanilla", "198.51.100.44");
    RiskAssessment assessment = this.scorer.score(fail, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, 0, 6), null, null);
    assertFalse(assessment.hasFactor(RiskFactor.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE));
  }

  @Test
  void retroactiveAssessmentMirrorsLiveTiersAndClusters() {
    assertNull(this.scorer.scoreRetroactiveMultiTargetSuccess("finsterry", 2, 600000L));

    RiskAssessment high = this.scorer.scoreRetroactiveMultiTargetSuccess("finsterry", 3, 600000L);
    assertNotNull(high);
    assertTrue(high.hasFactor(RiskFactor.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE));
    assertEquals(50, high.score());
    assertEquals(Severity.HIGH, high.severity());
    assertEquals("account:finsterry", high.clusterKey());

    RiskAssessment critical = this.scorer.scoreRetroactiveMultiTargetSuccess("finsterry", 6, 600000L);
    assertNotNull(critical);
    assertEquals(80, critical.score());
    assertEquals(Severity.CRITICAL, critical.severity());
  }

  @Test
  void multiTargetTierCrossingsFireExactlyOnTierBoundaries() {
    assertFalse(RiskScorer.crossedMultiTargetTier(0, 2));
    assertTrue(RiskScorer.crossedMultiTargetTier(2, 3));
    assertFalse(RiskScorer.crossedMultiTargetTier(3, 5));
    assertTrue(RiskScorer.crossedMultiTargetTier(5, 6));
    assertTrue(RiskScorer.crossedMultiTargetTier(0, 6));
    assertFalse(RiskScorer.crossedMultiTargetTier(6, 9));
  }

  @Test
  void geoIsCappedAndCountryMismatchIsStrong() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 8000, false, "vanilla");
    GeoIpResult geo = new GeoIpResult("DE", 12345L, "Example Hosting GmbH");
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false), geo, "RU");
    assertTrue(assessment.hasFactor(RiskFactor.GEO_COUNTRY_MISMATCH));
    assertTrue(assessment.hasFactor(RiskFactor.GEO_HOSTING_ASN));
    // Raw 20 + 10 = 30, equal to the GEO cap: alone it can reach SUSPICIOUS but never HIGH.
    assertEquals(30, assessment.score());
    assertEquals(Severity.SUSPICIOUS, assessment.severity());
  }

  @Test
  void churnRequiresThreeSessions() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 8000, false, "vanilla");
    assertFalse(this.scorer.score(observation, this.snapshot(0, 0, 2, 0, 0, 0, 0, 0, 0, 0, false), null, null)
        .hasFactor(RiskFactor.CHURN_SESSIONS));
    assertTrue(this.scorer.score(observation, this.snapshot(0, 0, 3, 0, 0, 0, 0, 0, 0, 0, false), null, null)
        .hasFactor(RiskFactor.CHURN_SESSIONS));
  }

  @Test
  void multiAccountNewSourceRequiresTwoAccounts() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_SUCCESS, true, 8000, false, "vanilla");
    RiskAssessment single = this.scorer.score(observation, this.snapshot(0, 0, 0, 1, 0, 0, 0, 0, 0, 0, false), null, null);
    assertFalse(single.hasFactor(RiskFactor.MULTI_ACCOUNT_NEW_SOURCE_SUCCESS));
    RiskAssessment multiple = this.scorer.score(observation, this.snapshot(0, 0, 0, 2, 0, 0, 0, 0, 0, 0, false), null, null);
    assertTrue(multiple.hasFactor(RiskFactor.MULTI_ACCOUNT_NEW_SOURCE_SUCCESS));
    // 15 points: on its own this stays an INFO breadcrumb, never an alert-worthy severity.
    assertEquals(15, multiple.score());
    assertFalse(multiple.severity().atLeast(Severity.SUSPICIOUS));
  }

  @Test
  void dormantTakeoverRequiresSuccessDormancyAndNewSubnet() throws Exception {
    AggregateSnapshot quiet = this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false);

    RiskAssessment takeover = this.scorer.score(this.dormant(AttemptOutcome.LOGIN_SUCCESS, "198.51.100.44", 45), quiet, null, null);
    assertTrue(takeover.hasFactor(RiskFactor.DORMANT_ACCOUNT_TAKEOVER));
    assertEquals(15, takeover.score());

    RiskAssessment failed = this.scorer.score(this.dormant(AttemptOutcome.LOGIN_FAIL, "198.51.100.44", 45), quiet, null, null);
    assertFalse(failed.hasFactor(RiskFactor.DORMANT_ACCOUNT_TAKEOVER));

    // Same /24 as the stored login: the regular comeback of a regular player.
    RiskAssessment sameSubnet = this.scorer.score(this.dormant(AttemptOutcome.LOGIN_SUCCESS, "203.0.113.200", 45), quiet, null, null);
    assertFalse(sameSubnet.hasFactor(RiskFactor.DORMANT_ACCOUNT_TAKEOVER));

    RiskAssessment recent = this.scorer.score(this.dormant(AttemptOutcome.LOGIN_SUCCESS, "198.51.100.44", 5), quiet, null, null);
    assertFalse(recent.hasFactor(RiskFactor.DORMANT_ACCOUNT_TAKEOVER));

    RiskAssessment noDate = this.scorer.score(this.dormant(AttemptOutcome.LOGIN_SUCCESS, "198.51.100.44", 0), quiet, null, null);
    assertFalse(noDate.hasFactor(RiskFactor.DORMANT_ACCOUNT_TAKEOVER));
  }

  @Test
  void dormantTakeoverWithGeoMismatchReachesSuspicious() throws Exception {
    AggregateSnapshot quiet = this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false);
    GeoIpResult geo = new GeoIpResult("DE", null, null);
    RiskAssessment assessment = this.scorer.score(this.dormant(AttemptOutcome.LOGIN_SUCCESS, "198.51.100.44", 45), quiet, geo, "FR");
    // 15 (dormant takeover) + 20 (country mismatch) = 35.
    assertTrue(assessment.severity().atLeast(Severity.SUSPICIOUS));
    assertFalse(assessment.severity().atLeast(Severity.HIGH));
  }

  @Test
  void clusterKeyPrefersSprayOverIp() throws Exception {
    AttemptObservation observation = this.observation(AttemptOutcome.LOGIN_FAIL, true, 8000, false, "vanilla");
    RiskAssessment assessment = this.scorer.score(observation, this.snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 5, false), null, null);
    assertTrue(assessment.clusterKey().startsWith("spray:"));
    RiskAssessment plain = this.scorer.score(observation, this.snapshot(20, 0, 0, 0, 0, 0, 0, 0, 0, 0, false), null, null);
    assertTrue(plain.clusterKey().startsWith("ip:"));
  }

  private AggregateSnapshot snapshot(int ipFailures, int ipDistinctFailedTargets, int ipChurnSessions, int ipDistinctNewSourceSuccesses,
                                     int subnetDistinctFailedTargets, int subnetDistinctIps, int subnetChurnSessions,
                                     int accountDistinctFailIps, int accountFailsFromOtherIps,
                                     int fingerprintDistinctTargets, boolean sourceFlagged) {
    return this.snapshot(ipFailures, ipDistinctFailedTargets, ipChurnSessions, ipDistinctNewSourceSuccesses,
        subnetDistinctFailedTargets, subnetDistinctIps, subnetChurnSessions, accountDistinctFailIps, accountFailsFromOtherIps,
        fingerprintDistinctTargets, sourceFlagged, 0, 0);
  }

  private AggregateSnapshot snapshot(int ipFailures, int ipDistinctFailedTargets, int ipChurnSessions, int ipDistinctNewSourceSuccesses,
                                     int subnetDistinctFailedTargets, int subnetDistinctIps, int subnetChurnSessions,
                                     int accountDistinctFailIps, int accountFailsFromOtherIps,
                                     int fingerprintDistinctTargets, boolean sourceFlagged,
                                     int foreignFingerprintTargets, int foreignFailedTargets) {
    return new AggregateSnapshot(ipFailures, ipDistinctFailedTargets, ipChurnSessions, ipDistinctNewSourceSuccesses,
        subnetDistinctFailedTargets, subnetDistinctIps, subnetChurnSessions, accountDistinctFailIps, accountFailsFromOtherIps,
        fingerprintDistinctTargets, sourceFlagged, foreignFingerprintTargets, foreignFailedTargets);
  }

  private AttemptObservation observation(AttemptOutcome outcome, boolean accountExists, long millisSinceJoin,
                                         boolean firstAttempt, String brand) throws Exception {
    return this.observation(outcome, accountExists, millisSinceJoin, firstAttempt, brand, null);
  }

  private AttemptObservation observation(AttemptOutcome outcome, boolean accountExists, long millisSinceJoin,
                                         boolean firstAttempt, String brand, String storedLoginIp) throws Exception {
    return AttemptObservation.builder("target", InetAddress.getByName("203.0.113.7"), outcome)
        .accountExists(accountExists)
        .millisSinceJoin(millisSinceJoin)
        .firstAttemptOfSession(firstAttempt)
        .clientBrand(brand)
        .storedLoginIp(storedLoginIp)
        .fingerprint(42L)
        .build();
  }

  private AttemptObservation foreignSuccess() throws Exception {
    return this.observation(AttemptOutcome.LOGIN_SUCCESS, true, 8000, false, "vanilla", "198.51.100.44");
  }

  private AttemptObservation dormant(AttemptOutcome outcome, String storedIp, int storedDaysAgo) throws Exception {
    return AttemptObservation.builder("veteran", InetAddress.getByName("203.0.113.7"), outcome)
        .accountExists(true)
        .timestamp(NOW)
        .millisSinceJoin(8000)
        .clientBrand("vanilla")
        .storedLoginIp(storedIp)
        .storedLoginDate(storedDaysAgo == 0 ? 0 : NOW - TimeUnit.DAYS.toMillis(storedDaysAgo))
        .fingerprint(42L)
        .build();
  }
}
