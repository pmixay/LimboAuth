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

import net.elytrium.limboauth.protection.AttemptObservation;
import net.elytrium.limboauth.protection.scoring.RiskAssessment;

/**
 * Reaction to a scored attempt. The only implementation shipped in this version is
 * {@link MonitorActionPolicy}; an enforcing policy can be added later without
 * touching the detection pipeline.
 */
public interface ActionPolicy {

  void apply(AttemptObservation observation, RiskAssessment assessment);
}
