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

package net.elytrium.limboauth.protection.storage;

import com.j256.ormlite.field.DataType;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

@DatabaseTable(tableName = "PROTECTION_EVENTS")
public class ProtectionEvent {

  public static final String ID_FIELD = "ID";
  public static final String EVENT_TIME_FIELD = "EVENTTIME";
  public static final String SEVERITY_FIELD = "SEVERITY";
  public static final String SCORE_FIELD = "SCORE";
  public static final String NICKNAME_FIELD = "NICKNAME";
  public static final String IP_FIELD = "IP";
  public static final String SUBNET_FIELD = "SUBNET";
  public static final String OUTCOME_FIELD = "OUTCOME";
  public static final String FACTORS_FIELD = "FACTORS";
  public static final String CLIENT_BRAND_FIELD = "CLIENTBRAND";
  public static final String COUNTRY_FIELD = "COUNTRY";
  public static final String ASN_FIELD = "ASN";

  @DatabaseField(generatedId = true, columnName = ID_FIELD)
  private long id;

  @DatabaseField(index = true, columnName = EVENT_TIME_FIELD)
  private long eventTime;

  @DatabaseField(canBeNull = false, columnName = SEVERITY_FIELD)
  private String severity;

  @DatabaseField(columnName = SCORE_FIELD)
  private int score;

  @DatabaseField(index = true, columnName = NICKNAME_FIELD)
  private String nickname;

  @DatabaseField(index = true, columnName = IP_FIELD)
  private String ip;

  @DatabaseField(columnName = SUBNET_FIELD)
  private String subnet;

  @DatabaseField(columnName = OUTCOME_FIELD)
  private String outcome;

  @DatabaseField(dataType = DataType.LONG_STRING, columnName = FACTORS_FIELD)
  private String factors;

  @DatabaseField(columnName = CLIENT_BRAND_FIELD)
  private String clientBrand;

  @DatabaseField(columnName = COUNTRY_FIELD)
  private String country;

  @DatabaseField(columnName = ASN_FIELD)
  private Long asn;

  public ProtectionEvent() {
    // ORMLite requires an empty constructor.
  }

  public ProtectionEvent(long eventTime, String severity, int score, String nickname, String ip, String subnet,
                         String outcome, String factors, String clientBrand, String country, Long asn) {
    this.eventTime = eventTime;
    this.severity = severity;
    this.score = score;
    this.nickname = nickname;
    this.ip = ip;
    this.subnet = subnet;
    this.outcome = outcome;
    this.factors = factors;
    this.clientBrand = clientBrand;
    this.country = country;
    this.asn = asn;
  }

  public long getId() {
    return this.id;
  }

  public long getEventTime() {
    return this.eventTime;
  }

  public String getSeverity() {
    return this.severity;
  }

  public int getScore() {
    return this.score;
  }

  public String getNickname() {
    return this.nickname;
  }

  public String getIp() {
    return this.ip;
  }

  public String getSubnet() {
    return this.subnet;
  }

  public String getOutcome() {
    return this.outcome;
  }

  public String getFactors() {
    return this.factors;
  }

  public String getClientBrand() {
    return this.clientBrand;
  }

  public String getCountry() {
    return this.country;
  }

  public Long getAsn() {
    return this.asn;
  }
}
