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

public enum RiskFactor {

  IP_FAIL_RATE(FactorCategory.VOLUME),
  IP_DISTINCT_TARGETS(FactorCategory.VOLUME),
  SUBNET_DISTINCT_TARGETS(FactorCategory.VOLUME),
  ACCOUNT_DISTINCT_IPS(FactorCategory.DISTRIBUTION),
  PASSWORD_SPRAY(FactorCategory.DISTRIBUTION),
  CHURN_SESSIONS(FactorCategory.DISTRIBUTION),
  INSTANT_FIRST_COMMAND(FactorCategory.BEHAVIOR),
  MISSING_BRAND(FactorCategory.BEHAVIOR),
  SUSPICIOUS_BRAND(FactorCategory.BEHAVIOR),
  GEO_COUNTRY_MISMATCH(FactorCategory.GEO),
  GEO_HOSTING_ASN(FactorCategory.GEO),
  CONFIRM_SUCCESS_AFTER_DISTRIBUTED_FAILURES(FactorCategory.CONFIRMATION),
  CONFIRM_SUCCESS_FROM_FLAGGED_SOURCE(FactorCategory.CONFIRMATION),
  CONFIRM_SPRAYED_PASSWORD_SUCCESS(FactorCategory.CONFIRMATION);

  private final FactorCategory category;

  RiskFactor(FactorCategory category) {
    this.category = category;
  }

  public FactorCategory getCategory() {
    return this.category;
  }
}
