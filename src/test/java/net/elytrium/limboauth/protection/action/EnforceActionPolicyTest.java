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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import net.elytrium.limboauth.Settings;
import net.elytrium.limboauth.protection.AttemptObservation;
import net.elytrium.limboauth.protection.AttemptOutcome;
import net.elytrium.limboauth.protection.Severity;
import net.elytrium.limboauth.protection.TestSettings;
import net.elytrium.limboauth.protection.scoring.RiskAssessment;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class EnforceActionPolicyTest {

  private static final long NOW = 1_700_000_000_000L;

  @BeforeAll
  static void loadSettings() {
    TestSettings.load();
  }

  @Test
  void severityGateHandlesNoneAndGarbageAsDisabled() {
    assertTrue(EnforceActionPolicy.meets(Severity.HIGH, "HIGH"));
    assertTrue(EnforceActionPolicy.meets(Severity.CRITICAL, "HIGH"));
    assertFalse(EnforceActionPolicy.meets(Severity.SUSPICIOUS, "HIGH"));
    // NONE (or an unparsable value) must disable the action, never match everything.
    assertFalse(EnforceActionPolicy.meets(Severity.CRITICAL, "NONE"));
    assertFalse(EnforceActionPolicy.meets(Severity.CRITICAL, "garbage"));
  }

  @Test
  void highSeverityKicksAndBlocksButOnlySuccessShields() throws Exception {
    EnforcementState state = new EnforcementState(() -> NOW);
    List<String> kicked = new ArrayList<>();
    EnforceActionPolicy policy = new EnforceActionPolicy(state, (nickname, ip) -> kicked.add(nickname + "@" + ip),
        LoggerFactory.getLogger("test"));

    policy.apply(this.observation("victim", AttemptOutcome.LOGIN_FAIL), this.assessment(55, Severity.HIGH));
    assertEquals(List.of("victim@203.0.113.7"), kicked);
    assertTrue(state.isSourceBlocked("203.0.113.7"));
    assertFalse(state.isAccountShielded("victim"), "a failed attempt must never shield the account");

    policy.apply(this.observation("victim", AttemptOutcome.LOGIN_SUCCESS), this.assessment(80, Severity.CRITICAL));
    assertTrue(state.isAccountShielded("victim"));
  }

  @Test
  void suspiciousSeverityTakesNoAction() throws Exception {
    EnforcementState state = new EnforcementState(() -> NOW);
    List<String> kicked = new ArrayList<>();
    EnforceActionPolicy policy = new EnforceActionPolicy(state, (nickname, ip) -> kicked.add(nickname),
        LoggerFactory.getLogger("test"));

    policy.apply(this.observation("player", AttemptOutcome.LOGIN_SUCCESS), this.assessment(35, Severity.SUSPICIOUS));
    assertTrue(kicked.isEmpty());
    assertEquals(0, state.getBlockedSourceCount());
    assertEquals(0, state.getShieldedAccountCount());
  }

  @Test
  void noneConfigurationDisablesEachActionIndependently() throws Exception {
    Settings.PROTECTION.ENFORCEMENT config = Settings.IMP.PROTECTION.ENFORCEMENT;
    String kickOn = config.KICK_ON;
    String blockOn = config.BLOCK_SOURCE_ON;
    try {
      config.KICK_ON = "NONE";
      config.BLOCK_SOURCE_ON = "NONE";

      EnforcementState state = new EnforcementState(() -> NOW);
      List<String> kicked = new ArrayList<>();
      EnforceActionPolicy policy = new EnforceActionPolicy(state, (nickname, ip) -> kicked.add(nickname),
          LoggerFactory.getLogger("test"));

      policy.apply(this.observation("victim", AttemptOutcome.LOGIN_SUCCESS), this.assessment(80, Severity.CRITICAL));
      assertTrue(kicked.isEmpty());
      assertEquals(0, state.getBlockedSourceCount());
      assertTrue(state.isAccountShielded("victim"), "the shield stays governed by its own key");
    } finally {
      config.KICK_ON = kickOn;
      config.BLOCK_SOURCE_ON = blockOn;
    }
  }

  private AttemptObservation observation(String nickname, AttemptOutcome outcome) throws Exception {
    return AttemptObservation.builder(nickname, InetAddress.getByName("203.0.113.7"), outcome)
        .accountExists(true)
        .timestamp(NOW)
        .millisSinceJoin(5000)
        .build();
  }

  private RiskAssessment assessment(int score, Severity severity) {
    return new RiskAssessment(score, severity, List.of(), "ip:203.0.113.7");
  }
}
