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

package net.elytrium.limboauth.protection.aggregate;

/**
 * Immutable numbers the risk scorer consumes, computed for one attempt after
 * that attempt was folded into the sliding windows.
 */
public record AggregateSnapshot(
    int ipFailures,
    int ipDistinctFailedTargets,
    int ipChurnSessions,
    int subnetDistinctFailedTargets,
    int subnetDistinctIps,
    int subnetChurnSessions,
    int accountDistinctFailIps,
    int accountFailsFromOtherIps,
    int fingerprintDistinctTargets,
    boolean sourceFlagged) {
}
