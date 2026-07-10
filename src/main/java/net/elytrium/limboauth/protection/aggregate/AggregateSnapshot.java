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
 * that attempt was folded into the sliding windows. New components are appended
 * at the end - the constructor is positional and tests wire it by position.
 *
 * <p>The two "foreign" counts only include targets whose stored LOGINIP sits on a
 * different subnet than the source of the attempt, so same-owner alt families
 * contribute nothing to them. {@code foreignFingerprintTargets} additionally excludes
 * the current attempt's own target: it answers "how many OTHER foreign accounts was
 * this password tried against", which is what a spray confirmation may count.
 */
public record AggregateSnapshot(
    int ipFailures,
    int ipDistinctFailedTargets,
    int ipChurnSessions,
    int ipDistinctNewSourceSuccesses,
    int subnetDistinctFailedTargets,
    int subnetDistinctIps,
    int subnetChurnSessions,
    int accountDistinctFailIps,
    int accountFailsFromOtherIps,
    int fingerprintDistinctTargets,
    boolean sourceFlagged,
    int foreignFingerprintTargets,
    int foreignFailedTargets) {
}
