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

package net.elytrium.limboauth.event;

import java.util.List;
import net.elytrium.limboauth.protection.AttemptOutcome;
import net.elytrium.limboauth.protection.Severity;
import net.elytrium.limboauth.protection.scoring.FactorContribution;

/**
 * Fired when the account protection system scores an attempt at SUSPICIOUS severity
 * or above. Monitor-only: cancelling or mutating has no effect on the player.
 */
public class ProtectionAlertEvent {

  private final String lowercaseNickname;
  private final String ip;
  private final String subnet;
  private final AttemptOutcome outcome;
  private final int score;
  private final Severity severity;
  private final List<FactorContribution> contributions;
  private final String clusterKey;
  private final long timestamp;

  public ProtectionAlertEvent(String lowercaseNickname, String ip, String subnet, AttemptOutcome outcome, int score,
                              Severity severity, List<FactorContribution> contributions, String clusterKey, long timestamp) {
    this.lowercaseNickname = lowercaseNickname;
    this.ip = ip;
    this.subnet = subnet;
    this.outcome = outcome;
    this.score = score;
    this.severity = severity;
    this.contributions = List.copyOf(contributions);
    this.clusterKey = clusterKey;
    this.timestamp = timestamp;
  }

  public String getLowercaseNickname() {
    return this.lowercaseNickname;
  }

  public String getIp() {
    return this.ip;
  }

  public String getSubnet() {
    return this.subnet;
  }

  public AttemptOutcome getOutcome() {
    return this.outcome;
  }

  public int getScore() {
    return this.score;
  }

  public Severity getSeverity() {
    return this.severity;
  }

  public List<FactorContribution> getContributions() {
    return this.contributions;
  }

  public String getClusterKey() {
    return this.clusterKey;
  }

  public long getTimestamp() {
    return this.timestamp;
  }
}
