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

import java.util.List;
import net.elytrium.limboauth.protection.Severity;

public record RiskAssessment(int score, Severity severity, List<FactorContribution> contributions, String clusterKey) {

  public boolean hasFactor(RiskFactor factor) {
    return this.contributions.stream().anyMatch(contribution -> contribution.factor() == factor);
  }
}
