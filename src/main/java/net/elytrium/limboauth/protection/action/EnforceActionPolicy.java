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

import java.util.concurrent.TimeUnit;
import net.elytrium.limboauth.Settings;
import net.elytrium.limboauth.protection.AttemptObservation;
import net.elytrium.limboauth.protection.AttemptOutcome;
import net.elytrium.limboauth.protection.Severity;
import net.elytrium.limboauth.protection.scoring.RiskAssessment;
import org.slf4j.Logger;

/**
 * Enforcing reaction for attempts the system is confident about. Three independent,
 * severity-gated actions:
 *
 * <ul>
 * <li><b>kick</b> - disconnect the offending session with the generic protection kick;</li>
 * <li><b>source block</b> - temporarily refuse all joins from the source IP;</li>
 * <li><b>account shield</b> - after a suspicious SUCCESSFUL login, make the account
 *     answer every password with the ordinary wrong-password reply for a while, so a
 *     checker can never confirm a working credential.</li>
 * </ul>
 *
 * <p>Runs on the protection executor; the synchronous connection-thread gates read the
 * shared {@link EnforcementState}.
 */
public class EnforceActionPolicy implements ActionPolicy {

  private final EnforcementState state;
  private final SessionKicker kicker;
  private final Logger logger;

  public EnforceActionPolicy(EnforcementState state, SessionKicker kicker, Logger logger) {
    this.state = state;
    this.kicker = kicker;
    this.logger = logger;
  }

  @Override
  public void apply(AttemptObservation observation, RiskAssessment assessment) {
    Settings.PROTECTION.ENFORCEMENT config = Settings.IMP.PROTECTION.ENFORCEMENT;
    Severity severity = assessment.severity();

    // The shield is deliberately success-only: shielding an account somebody merely FAILED
    // against would let an attacker lock arbitrary players out, and the moment of harm that
    // needs containing is a takeover-shaped success.
    if (observation.getOutcome() == AttemptOutcome.LOGIN_SUCCESS && observation.isAccountExists()
        && meets(severity, config.SHIELD_ACCOUNT_ON)) {
      long until = observation.getTimestamp() + TimeUnit.MINUTES.toMillis(Math.max(1, config.SHIELD_MINUTES));
      this.state.shieldAccount(observation.getLowercaseNickname(), until);
      this.logger.warn("enforcement action=shield account={} minutes={} severity={} score={}",
          observation.getLowercaseNickname(), config.SHIELD_MINUTES, severity, assessment.score());
    }

    if (meets(severity, config.BLOCK_SOURCE_ON)) {
      long until = observation.getTimestamp() + TimeUnit.MINUTES.toMillis(Math.max(1, config.SOURCE_BLOCK_MINUTES));
      this.state.blockSource(observation.getIpString(), until);
      this.logger.warn("enforcement action=block-source ip={} minutes={} severity={} score={}",
          observation.getIpString(), config.SOURCE_BLOCK_MINUTES, severity, assessment.score());
    }

    if (meets(severity, config.KICK_ON)) {
      this.kicker.kick(observation.getLowercaseNickname(), observation.getIpString());
    }
  }

  /**
   * A configured value of NONE (or garbage) disables the action entirely - it must never
   * mean "act on everything", which a naive {@code atLeast(NONE)} comparison would.
   */
  static boolean meets(Severity severity, String configuredMinimum) {
    Severity minimum = Severity.parse(configuredMinimum, Severity.NONE);
    return minimum != Severity.NONE && severity.atLeast(minimum);
  }

  /**
   * Disconnects a live session, if one matching both the nickname and the source IP still
   * exists. Implemented by the manager so this policy stays free of proxy API calls.
   */
  @FunctionalInterface
  public interface SessionKicker {

    void kick(String lowercaseNickname, String expectedIp);
  }
}
