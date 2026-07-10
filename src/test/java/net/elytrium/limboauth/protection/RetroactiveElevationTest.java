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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import net.elytrium.limboauth.protection.aggregate.ActivityWindow;
import net.elytrium.limboauth.protection.aggregate.AggregateSnapshot;
import net.elytrium.limboauth.protection.aggregate.ProtectionAggregator;
import net.elytrium.limboauth.protection.scoring.RiskAssessment;
import net.elytrium.limboauth.protection.scoring.RiskFactor;
import net.elytrium.limboauth.protection.scoring.RiskScorer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Scenario tests for the retroactive elevation of "success-first" hits, replaying
 * attacks through aggregator + scorer + {@link RetroactiveElevation} exactly the way
 * {@code ProtectionManager#process} chains them (including marking live-confirmed
 * successes so they are never reported twice).
 */
class RetroactiveElevationTest {

  private static final long NOW = 1_700_000_000_000L;

  @BeforeAll
  static void loadSettings() {
    TestSettings.load();
  }

  /**
   * The finsterry timeline from production: the checker's very first try SUCCEEDS,
   * then the same IP grinds on and fails other players' accounts. At the success there
   * was nothing to score - the alert must arrive retroactively, exactly once, when the
   * source crosses the multi-target tier.
   */
  @Test
  void successFirstHitIsElevatedWhenSourceCrossesTheTier() throws Exception {
    Harness harness = new Harness();
    String checkerIp = "185.159.162.53";
    long hitTime = NOW;

    harness.observe(this.success("finsterry", checkerIp, hitTime, "192.0.2.99"));
    assertTrue(harness.elevated.isEmpty(), "nothing to elevate at the quiet success");

    harness.observe(this.foreignFail("fl0paaaaaaaaa", checkerIp, NOW + 5L * 60000, "192.0.2.10"));
    harness.observe(this.foreignFail("pipka2282282", checkerIp, NOW + 10L * 60000, "192.0.2.11"));
    assertTrue(harness.elevated.isEmpty(), "two foreign failures are below the tier");

    harness.observe(this.foreignFail("loool_000", checkerIp, NOW + 15L * 60000, "192.0.2.12"));
    assertEquals(1, harness.elevated.size(), "crossing the >=3 tier must surface the earlier hit");

    RetroactiveElevation.ElevatedSuccess elevated = harness.elevated.get(0);
    assertEquals("finsterry", elevated.observation().getLowercaseNickname());
    assertEquals(checkerIp, elevated.observation().getIpString());
    assertEquals(hitTime, elevated.observation().getTimestamp(), "the alert carries the original success time");
    assertEquals(AttemptOutcome.LOGIN_SUCCESS, elevated.observation().getOutcome());
    assertTrue(elevated.assessment().hasFactor(RiskFactor.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE));
    assertTrue(elevated.assessment().severity().atLeast(Severity.HIGH),
        "the retroactive confirmation must be HIGH, got " + elevated.assessment().severity());
    assertEquals("account:finsterry", elevated.assessment().clusterKey());

    // More failures do not re-report the same hit: no boundary between the tiers...
    harness.observe(this.foreignFail("stray0", checkerIp, NOW + 20L * 60000, "192.0.2.13"));
    harness.observe(this.foreignFail("stray1", checkerIp, NOW + 25L * 60000, "192.0.2.14"));
    assertEquals(1, harness.elevated.size());

    // ...and even the next tier crossing skips it, because it is marked as reported.
    harness.observe(this.foreignFail("stray2", checkerIp, NOW + 30L * 60000, "192.0.2.15"));
    assertEquals(1, harness.elevated.size(), "the >=6 crossing must not re-report an already-alerted success");
  }

  /**
   * FPR guard: a shared-IP household. The successes on the source's own subnet are not
   * foreign, so even when the same IP later accumulates foreign failures (one flatmate
   * checking leaked lists, say), the neighbors' ordinary logins are never re-reported.
   */
  @Test
  void ownSubnetSuccessesAreNeverElevated() throws Exception {
    Harness harness = new Harness();
    String sharedIp = "192.0.2.50";

    harness.observe(this.success("flatmate1", sharedIp, NOW, sharedIp));
    harness.observe(this.success("flatmate2", sharedIp, NOW + 60000, sharedIp));

    for (int i = 0; i < 3; ++i) {
      harness.observe(this.foreignFail("victim" + i, sharedIp, NOW + 120000 + i * 60000L, "198.51.100." + (10 + i)));
    }

    assertTrue(harness.elevated.isEmpty(), "own-subnet successes must never be retroactively elevated");
  }

  /**
   * A success that was already confirmed LIVE (the failures came first) is marked at
   * dispatch time and must not be reported a second time by a later tier crossing.
   */
  @Test
  void liveConfirmedSuccessIsNotReElevated() throws Exception {
    Harness harness = new Harness();
    String checkerIp = "203.0.113.66";

    for (int i = 0; i < 3; ++i) {
      harness.observe(this.foreignFail("cracked" + i, checkerIp, NOW + i * 60000L, "192.0.2." + (10 + i)));
    }

    assertTrue(harness.elevated.isEmpty(), "no successes existed at the >=3 crossing");

    RiskAssessment live = harness.observe(this.success("victim", checkerIp, NOW + 240000, "192.0.2.99"));
    assertTrue(live.hasFactor(RiskFactor.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE));
    assertTrue(live.severity().atLeast(Severity.HIGH));

    // Push the source across the >=6 tier: the scan runs again, but the hit is marked.
    for (int i = 3; i < 6; ++i) {
      harness.observe(this.foreignFail("cracked" + i, checkerIp, NOW + 300000 + i * 60000L, "192.0.2." + (10 + i)));
    }

    assertTrue(harness.elevated.isEmpty(), "a live-confirmed success must not be re-reported retroactively");
  }

  private AttemptObservation foreignFail(String nickname, String ip, long time, String storedLoginIp) throws Exception {
    return AttemptObservation.builder(nickname, InetAddress.getByName(ip), AttemptOutcome.LOGIN_FAIL)
        .accountExists(true)
        .timestamp(time)
        .millisSinceJoin(4000)
        .firstAttemptOfSession(true)
        .clientBrand("vanilla")
        .storedLoginIp(storedLoginIp)
        .fingerprint(nickname.hashCode())
        .build();
  }

  private AttemptObservation success(String nickname, String ip, long time, String storedLoginIp) throws Exception {
    return AttemptObservation.builder(nickname, InetAddress.getByName(ip), AttemptOutcome.LOGIN_SUCCESS)
        .accountExists(true)
        .timestamp(time)
        .millisSinceJoin(4000)
        .firstAttemptOfSession(true)
        .clientBrand("vanilla")
        .storedLoginIp(storedLoginIp)
        .fingerprint(nickname.hashCode())
        .build();
  }

  private static final class Harness {

    private final ProtectionAggregator aggregator = new ProtectionAggregator();
    private final RiskScorer scorer = new RiskScorer();
    private final RetroactiveElevation elevation = new RetroactiveElevation(this.aggregator, this.scorer);
    private final List<RetroactiveElevation.ElevatedSuccess> elevated = new ArrayList<>();

    RiskAssessment observe(AttemptObservation observation) {
      int foreignFailedBefore = this.aggregator.foreignFailedTargets(observation);
      ActivityWindow.AttemptEvent windowEvent = this.aggregator.update(observation);
      AggregateSnapshot snapshot = this.aggregator.snapshot(observation);
      RiskAssessment assessment = this.scorer.score(observation, snapshot, null, null);
      if (observation.getOutcome() == AttemptOutcome.LOGIN_SUCCESS && assessment.severity().atLeast(Severity.HIGH)) {
        windowEvent.markConfirmationAlerted();
      }

      this.elevated.addAll(this.elevation.onAttempt(observation, foreignFailedBefore, snapshot.foreignFailedTargets()));
      return assessment;
    }
  }
}
