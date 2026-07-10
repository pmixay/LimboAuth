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

import java.net.InetAddress;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Immutable snapshot of a single auth attempt, built on the connection thread
 * and consumed by the protection pipeline on its own executor.
 */
public class AttemptObservation {

  private final String lowercaseNickname;
  private final boolean accountExists;
  private final InetAddress ip;
  private final String ipString;
  private final String subnetKey;
  private final long timestamp;
  private final AttemptOutcome outcome;
  private final long millisSinceJoin;
  private final boolean firstAttemptOfSession;
  private final int sessionAttempts;
  @Nullable
  private final String clientBrand;
  private final int protocolVersion;
  private final boolean hasFingerprint;
  private final long passwordFingerprint;
  @Nullable
  private final String storedLoginIp;
  private final long storedLoginDate;
  private final boolean floodgate;

  private AttemptObservation(Builder builder) {
    this.lowercaseNickname = builder.lowercaseNickname;
    this.accountExists = builder.accountExists;
    this.ip = builder.ip;
    this.ipString = builder.ip.getHostAddress();
    this.subnetKey = SubnetKey.of(builder.ip);
    this.timestamp = builder.timestamp;
    this.outcome = builder.outcome;
    this.millisSinceJoin = builder.millisSinceJoin;
    this.firstAttemptOfSession = builder.firstAttemptOfSession;
    this.sessionAttempts = builder.sessionAttempts;
    this.clientBrand = builder.clientBrand;
    this.protocolVersion = builder.protocolVersion;
    this.hasFingerprint = builder.hasFingerprint;
    this.passwordFingerprint = builder.passwordFingerprint;
    this.storedLoginIp = builder.storedLoginIp;
    this.storedLoginDate = builder.storedLoginDate;
    this.floodgate = builder.floodgate;
  }

  public String getLowercaseNickname() {
    return this.lowercaseNickname;
  }

  public boolean isAccountExists() {
    return this.accountExists;
  }

  public InetAddress getIp() {
    return this.ip;
  }

  public String getIpString() {
    return this.ipString;
  }

  public String getSubnetKey() {
    return this.subnetKey;
  }

  public long getTimestamp() {
    return this.timestamp;
  }

  public AttemptOutcome getOutcome() {
    return this.outcome;
  }

  public long getMillisSinceJoin() {
    return this.millisSinceJoin;
  }

  public boolean isFirstAttemptOfSession() {
    return this.firstAttemptOfSession;
  }

  public int getSessionAttempts() {
    return this.sessionAttempts;
  }

  @Nullable
  public String getClientBrand() {
    return this.clientBrand;
  }

  public int getProtocolVersion() {
    return this.protocolVersion;
  }

  public boolean hasFingerprint() {
    return this.hasFingerprint;
  }

  public long getPasswordFingerprint() {
    return this.passwordFingerprint;
  }

  @Nullable
  public String getStoredLoginIp() {
    return this.storedLoginIp;
  }

  /**
   * Timestamp of the account's last successful login before this attempt, or {@code 0}
   * when unknown (unregistered account or a legacy row without a login date).
   */
  public long getStoredLoginDate() {
    return this.storedLoginDate;
  }

  public boolean isFloodgate() {
    return this.floodgate;
  }

  public static Builder builder(String lowercaseNickname, InetAddress ip, AttemptOutcome outcome) {
    return new Builder(lowercaseNickname, ip, outcome);
  }

  public static class Builder {

    private final String lowercaseNickname;
    private final InetAddress ip;
    private final AttemptOutcome outcome;

    private boolean accountExists;
    private long timestamp = System.currentTimeMillis();
    private long millisSinceJoin;
    private boolean firstAttemptOfSession;
    private int sessionAttempts;
    @Nullable
    private String clientBrand;
    private int protocolVersion;
    private boolean hasFingerprint;
    private long passwordFingerprint;
    @Nullable
    private String storedLoginIp;
    private long storedLoginDate;
    private boolean floodgate;

    private Builder(String lowercaseNickname, InetAddress ip, AttemptOutcome outcome) {
      this.lowercaseNickname = lowercaseNickname;
      this.ip = ip;
      this.outcome = outcome;
    }

    public Builder accountExists(boolean accountExists) {
      this.accountExists = accountExists;
      return this;
    }

    public Builder timestamp(long timestamp) {
      this.timestamp = timestamp;
      return this;
    }

    public Builder millisSinceJoin(long millisSinceJoin) {
      this.millisSinceJoin = millisSinceJoin;
      return this;
    }

    public Builder firstAttemptOfSession(boolean firstAttemptOfSession) {
      this.firstAttemptOfSession = firstAttemptOfSession;
      return this;
    }

    public Builder sessionAttempts(int sessionAttempts) {
      this.sessionAttempts = sessionAttempts;
      return this;
    }

    public Builder clientBrand(@Nullable String clientBrand) {
      this.clientBrand = clientBrand;
      return this;
    }

    public Builder protocolVersion(int protocolVersion) {
      this.protocolVersion = protocolVersion;
      return this;
    }

    public Builder fingerprint(long passwordFingerprint) {
      this.hasFingerprint = true;
      this.passwordFingerprint = passwordFingerprint;
      return this;
    }

    public Builder storedLoginIp(@Nullable String storedLoginIp) {
      this.storedLoginIp = storedLoginIp;
      return this;
    }

    public Builder storedLoginDate(long storedLoginDate) {
      // RegisteredPlayer#getLoginDate() reports Long.MIN_VALUE for legacy rows; collapse
      // every "unknown" flavor to 0 so consumers only need one absence check.
      this.storedLoginDate = Math.max(0, storedLoginDate);
      return this;
    }

    public Builder floodgate(boolean floodgate) {
      this.floodgate = floodgate;
      return this;
    }

    public AttemptObservation build() {
      return new AttemptObservation(this);
    }
  }
}
