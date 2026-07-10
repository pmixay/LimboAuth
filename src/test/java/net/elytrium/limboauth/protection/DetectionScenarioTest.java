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
import net.elytrium.limboauth.protection.geoip.GeoIpResult;
import net.elytrium.limboauth.protection.scoring.RiskAssessment;
import net.elytrium.limboauth.protection.scoring.RiskFactor;
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
   * FPR anchor for the widened 60-minute counting: three players behind one shared IP,
   * each mistyping twice, spread across nearly an hour. All six failures now land in the
   * same distribution window, and the total must still stay below SUSPICIOUS.
   */
  @Test
  void sharedIpMistypesSpreadOverAnHourStayBelowSuspicious() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    RiskScorer scorer = new RiskScorer();
    long now = 1_700_000_000_000L;

    Severity worst = Severity.NONE;
    for (int player = 0; player < 3; ++player) {
      for (int attempt = 0; attempt < 2; ++attempt) {
        AttemptObservation fail = AttemptObservation
            .builder("classmate" + player, InetAddress.getByName("192.0.2.50"), AttemptOutcome.LOGIN_FAIL)
            .accountExists(true)
            .timestamp(now + (player * 2L + attempt) * 11L * 60000)
            .millisSinceJoin(5000)
            .clientBrand("fabric")
            .fingerprint(5000L + player * 10L + attempt)
            .build();
        aggregator.update(fail);
        RiskAssessment assessment = scorer.score(fail, aggregator.snapshot(fail), null, null);
        if (assessment.severity().atLeast(worst)) {
          worst = assessment.severity();
        }
      }
    }

    assertFalse(worst.atLeast(Severity.SUSPICIOUS), "hour-spread shared-IP mistypes must stay below SUSPICIOUS, got " + worst);
  }

  /**
   * The v1.1 threat model: a person looks up leaked passwords on a website and manually
   * checks four existing accounts from one IP over 40 minutes, with a normal client,
   * disconnecting between accounts. Far too slow for the volume window, but the
   * distribution-window signals must still add up to SUSPICIOUS.
   */
  @Test
  void humanPacedLeakedAccountCheckingReachesSuspicious() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    RiskScorer scorer = new RiskScorer();
    long now = 1_700_000_000_000L;

    Severity worst = Severity.NONE;
    for (int i = 0; i < 4; ++i) {
      long joinTime = now + i * 13L * 60000;
      AttemptObservation fail = AttemptObservation
          .builder("leaked" + i, InetAddress.getByName("203.0.113.99"), AttemptOutcome.LOGIN_FAIL)
          .accountExists(true)
          .timestamp(joinTime)
          .millisSinceJoin(7000)
          .firstAttemptOfSession(true)
          .clientBrand("vanilla")
          .fingerprint(6000L + i)
          .build();
      aggregator.update(fail);
      RiskAssessment assessment = scorer.score(fail, aggregator.snapshot(fail), null, null);
      if (assessment.severity().atLeast(worst)) {
        worst = assessment.severity();
      }

      // Quits a few seconds later to rejoin under the next leaked username.
      aggregator.update(AttemptObservation
          .builder("leaked" + i, InetAddress.getByName("203.0.113.99"), AttemptOutcome.SESSION_END)
          .accountExists(true)
          .timestamp(joinTime + 9000)
          .millisSinceJoin(16000)
          .sessionAttempts(1)
          .build());
    }

    assertTrue(worst.atLeast(Severity.SUSPICIOUS), "human-paced account checking should reach SUSPICIOUS, got " + worst);
    assertFalse(worst.atLeast(Severity.HIGH), "failures alone (no confirmed hit) must stay below HIGH, got " + worst);
  }

  /**
   * FPR guard for the new-source factor: a player whose ISP handed them a new address
   * relogs two of their own alts. Both stored login IPs differ from the current one, so
   * the factor fires - but on its own it must stay an INFO-level breadcrumb.
   */
  @Test
  void ownAltsAfterIspAddressChangeStayBelowSuspicious() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    RiskScorer scorer = new RiskScorer();
    long now = 1_700_000_000_000L;
    String oldIspIp = "198.51.100.44";

    AttemptObservation first = this.altLogin(aggregator, "alt1", now, oldIspIp, now - 2L * 86400000);
    RiskAssessment firstAssessment = scorer.score(first, aggregator.snapshot(first), null, null);
    assertFalse(firstAssessment.hasFactor(RiskFactor.MULTI_ACCOUNT_NEW_SOURCE_SUCCESS));

    // Plays for five minutes (no churn), then switches to the second alt.
    aggregator.update(AttemptObservation
        .builder("alt1", InetAddress.getByName("203.0.113.7"), AttemptOutcome.SESSION_END)
        .accountExists(true)
        .timestamp(now + 300000)
        .millisSinceJoin(300000)
        .sessionAttempts(1)
        .build());

    AttemptObservation second = this.altLogin(aggregator, "alt2", now + 320000, oldIspIp, now - 3L * 86400000);
    RiskAssessment secondAssessment = scorer.score(second, aggregator.snapshot(second), null, null);

    assertTrue(secondAssessment.hasFactor(RiskFactor.MULTI_ACCOUNT_NEW_SOURCE_SUCCESS));
    assertFalse(secondAssessment.severity().atLeast(Severity.SUSPICIOUS),
        "own alts after an IP change must stay below SUSPICIOUS, got " + secondAssessment.severity());
  }

  /**
   * First-try takeover of a dormant account, the pattern password-website attackers
   * produce: no failed attempts anywhere, just one clean success on an account whose
   * last login is 45 days old, from another subnet and (GeoIP active) another country.
   */
  @Test
  void firstTryDormantTakeoverWithGeoMismatchIsSuspicious() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    RiskScorer scorer = new RiskScorer();
    long now = 1_700_000_000_000L;

    AttemptObservation hit = AttemptObservation
        .builder("veteran", InetAddress.getByName("203.0.113.7"), AttemptOutcome.LOGIN_SUCCESS)
        .accountExists(true)
        .timestamp(now)
        .millisSinceJoin(6000)
        .firstAttemptOfSession(true)
        .clientBrand("vanilla")
        .storedLoginIp("198.51.100.44")
        .storedLoginDate(now - 45L * 86400000)
        .fingerprint(777L)
        .build();
    aggregator.update(hit);
    RiskAssessment assessment = scorer.score(hit, aggregator.snapshot(hit), new GeoIpResult("DE", null, null), "FR");

    assertTrue(assessment.hasFactor(RiskFactor.DORMANT_ACCOUNT_TAKEOVER));
    assertTrue(assessment.severity().atLeast(Severity.SUSPICIOUS),
        "a first-try dormant takeover with a geo mismatch must be SUSPICIOUS, got " + assessment.severity());
    assertFalse(assessment.severity().atLeast(Severity.HIGH),
        "without volume or confirmation signals it must stay below HIGH, got " + assessment.severity());
  }

  /**
   * Password spraying: the same password tried against many accounts stored on OTHER
   * networks, low-and-slow, and the moment it works it must be CRITICAL. The stored
   * login IPs are what makes the targets foreign - see the alt-family scenario below
   * for the same shape without them.
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
          .storedLoginIp("192.0.2." + (10 + i))
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
        .storedLoginIp("192.0.2.30")
        .fingerprint(sprayedPassword)
        .build();
    aggregator.update(hit);
    RiskAssessment assessment = scorer.score(hit, aggregator.snapshot(hit), null, null);

    assertTrue(assessment.hasFactor(RiskFactor.CONFIRM_SPRAYED_PASSWORD_SUCCESS));
    assertTrue(assessment.severity().atLeast(Severity.CRITICAL),
        "a sprayed password that works must be CRITICAL, got " + assessment.severity());
  }

  /**
   * FP regression (production finding A, the dnecek family): one person reuses one
   * password across their own typo-alts and relogs them all from the family's usual IP.
   * The raw spray count sees 3 distinct accounts, but every stored login IP is the
   * source itself - zero foreign targets - so the old CRITICAL 100 must collapse to
   * INFO-level noise.
   */
  @Test
  void ownAltFamilySharedPasswordStaysBelowSuspicious() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    RiskScorer scorer = new RiskScorer();
    long now = 1_700_000_000_000L;
    String familyIp = "217.114.146.6";
    long sharedPassword = 424242L;
    String[] alts = {"danecek2014", "dnecek2014", "danecek14"};

    Severity worst = Severity.NONE;
    RiskAssessment last = null;
    for (int i = 0; i < alts.length; ++i) {
      AttemptObservation relog = AttemptObservation
          .builder(alts[i], InetAddress.getByName(familyIp), AttemptOutcome.LOGIN_SUCCESS)
          .accountExists(true)
          .timestamp(now + i * 240000L)
          .millisSinceJoin(4000)
          .firstAttemptOfSession(true)
          .clientBrand("optifine")
          .storedLoginIp(familyIp)
          .storedLoginDate(now - 3L * 86400000)
          .fingerprint(sharedPassword)
          .build();
      aggregator.update(relog);
      last = scorer.score(relog, aggregator.snapshot(relog), null, null);
      if (last.severity().atLeast(worst)) {
        worst = last.severity();
      }
    }

    assertTrue(last.hasFactor(RiskFactor.PASSWORD_SPRAY), "the breadcrumb factor may fire");
    assertFalse(last.hasFactor(RiskFactor.CONFIRM_SPRAYED_PASSWORD_SUCCESS),
        "an alt family must never trip the spray confirmation");
    assertFalse(worst.atLeast(Severity.SUSPICIOUS),
        "own alts sharing one password must stay below SUSPICIOUS, got " + worst);
  }

  /**
   * FP guard for the spray confirmation away from home: two own alts sharing one
   * password, both stored at the family's home subnet, relogged from a hotel network.
   * Both targets are foreign now, but the hit itself may not count as its own spray
   * evidence - one other foreign account is not a campaign.
   */
  @Test
  void travelingAltFamilySharedPasswordStaysBelowHigh() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    RiskScorer scorer = new RiskScorer();
    long now = 1_700_000_000_000L;
    String homeIp = "198.51.100.44";
    long sharedPassword = 434343L;

    Severity worst = Severity.NONE;
    RiskAssessment last = null;
    for (String alt : new String[] {"alt1", "alt2"}) {
      AttemptObservation relog = AttemptObservation
          .builder(alt, InetAddress.getByName("203.0.113.77"), AttemptOutcome.LOGIN_SUCCESS)
          .accountExists(true)
          .timestamp(now)
          .millisSinceJoin(5000)
          .firstAttemptOfSession(true)
          .clientBrand("vanilla")
          .storedLoginIp(homeIp)
          .storedLoginDate(now - 2L * 86400000)
          .fingerprint(sharedPassword)
          .build();
      aggregator.update(relog);
      last = scorer.score(relog, aggregator.snapshot(relog), null, null);
      if (last.severity().atLeast(worst)) {
        worst = last.severity();
      }

      now += 240000;
    }

    assertFalse(last.hasFactor(RiskFactor.CONFIRM_SPRAYED_PASSWORD_SUCCESS),
        "one other foreign alt must not confirm a spray");
    assertFalse(worst.atLeast(Severity.HIGH),
        "a traveling two-alt family must stay below HIGH, got " + worst);
  }

  /**
   * FN regression (production finding B, failures-first shape): a checker IP fails
   * against four other players' accounts and then logs into a fifth. Before the
   * multi-target-source confirmation the hit logged INFO 20 and cost the account;
   * now it must be HIGH.
   */
  @Test
  void checkerSuccessAfterForeignFailuresReachesHigh() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    RiskScorer scorer = new RiskScorer();
    long now = 1_700_000_000_000L;
    String checkerIp = "185.159.162.53";

    for (int i = 0; i < 4; ++i) {
      AttemptObservation fail = AttemptObservation
          .builder("cracked" + i, InetAddress.getByName(checkerIp), AttemptOutcome.LOGIN_FAIL)
          .accountExists(true)
          .timestamp(now + i * 7L * 60000)
          .millisSinceJoin(3000)
          .firstAttemptOfSession(true)
          .clientBrand("vanilla")
          .storedLoginIp("192.0.2." + (10 + i))
          .fingerprint(7000L + i)
          .build();
      aggregator.update(fail);
      scorer.score(fail, aggregator.snapshot(fail), null, null);
    }

    AttemptObservation hit = AttemptObservation
        .builder("finsterry", InetAddress.getByName(checkerIp), AttemptOutcome.LOGIN_SUCCESS)
        .accountExists(true)
        .timestamp(now + 30L * 60000)
        .millisSinceJoin(3000)
        .firstAttemptOfSession(true)
        .clientBrand("vanilla")
        .storedLoginIp("192.0.2.99")
        .fingerprint(7100L)
        .build();
    aggregator.update(hit);
    RiskAssessment assessment = scorer.score(hit, aggregator.snapshot(hit), null, null);

    assertTrue(assessment.hasFactor(RiskFactor.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE));
    assertTrue(assessment.severity().atLeast(Severity.HIGH),
        "a success from a multi-target source must be HIGH, got " + assessment.severity());
  }

  /**
   * FPR guard for the multi-target confirmation: a shared IP (school/CGNAT) where three
   * players mistype their OWN passwords - stored login IPs on the shared subnet - and a
   * fourth then logs in cleanly. Non-foreign failures must not confirm the success.
   */
  @Test
  void sharedIpOwnAccountFailuresDoNotConfirmANeighborsSuccess() throws Exception {
    ProtectionAggregator aggregator = new ProtectionAggregator();
    RiskScorer scorer = new RiskScorer();
    long now = 1_700_000_000_000L;
    String sharedIp = "192.0.2.50";

    for (int player = 0; player < 3; ++player) {
      AttemptObservation fail = AttemptObservation
          .builder("classmate" + player, InetAddress.getByName(sharedIp), AttemptOutcome.LOGIN_FAIL)
          .accountExists(true)
          .timestamp(now + player * 60000L)
          .millisSinceJoin(5000)
          .clientBrand("fabric")
          .storedLoginIp(sharedIp)
          .fingerprint(4000L + player)
          .build();
      aggregator.update(fail);
      scorer.score(fail, aggregator.snapshot(fail), null, null);
    }

    AttemptObservation success = AttemptObservation
        .builder("classmate3", InetAddress.getByName(sharedIp), AttemptOutcome.LOGIN_SUCCESS)
        .accountExists(true)
        .timestamp(now + 240000L)
        .millisSinceJoin(5000)
        .clientBrand("fabric")
        .storedLoginIp(sharedIp)
        .fingerprint(4100L)
        .build();
    aggregator.update(success);
    RiskAssessment assessment = scorer.score(success, aggregator.snapshot(success), null, null);

    assertFalse(assessment.hasFactor(RiskFactor.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE));
    assertFalse(assessment.severity().atLeast(Severity.HIGH),
        "a neighbor's clean login behind a shared IP must stay below HIGH, got " + assessment.severity());
  }

  private AttemptObservation altLogin(ProtectionAggregator aggregator, String nickname, long time,
                                      String storedLoginIp, long storedLoginDate) throws Exception {
    AttemptObservation observation = AttemptObservation
        .builder(nickname, InetAddress.getByName("203.0.113.7"), AttemptOutcome.LOGIN_SUCCESS)
        .accountExists(true)
        .timestamp(time)
        .millisSinceJoin(6000)
        .firstAttemptOfSession(true)
        .clientBrand("vanilla")
        .storedLoginIp(storedLoginIp)
        .storedLoginDate(storedLoginDate)
        .fingerprint(nickname.hashCode())
        .build();
    aggregator.update(observation);
    return observation;
  }
}
