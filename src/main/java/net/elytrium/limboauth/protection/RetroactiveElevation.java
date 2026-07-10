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

import java.util.ArrayList;
import java.util.List;
import net.elytrium.limboauth.protection.aggregate.ActivityWindow;
import net.elytrium.limboauth.protection.aggregate.ProtectionAggregator;
import net.elytrium.limboauth.protection.scoring.RiskAssessment;
import net.elytrium.limboauth.protection.scoring.RiskScorer;

/**
 * Retroactive elevation of "success-first" hits: a checker that finds a working
 * credential EARLY and only then grinds down the rest of its list leaves a clean
 * LOGIN_SUCCESS in its source window - at that moment no multi-target signal existed
 * yet, so no real-time check can score it. When the source's foreign-failed-target
 * count later crosses a multi-target tier, this pass re-reads the same bounded window
 * and emits, for each still-unreported foreign success, the confirmation alert it
 * would have received had the order been reversed.
 *
 * <p>No new persistence: the candidates come from the ip window the aggregator already
 * keeps, and each elevated event is marked on the shared {@code AttemptEvent} so it is
 * reported at most once. Runs on the single protection executor thread, like the rest
 * of the pipeline.
 */
public class RetroactiveElevation {

  private final ProtectionAggregator aggregator;
  private final RiskScorer scorer;

  public RetroactiveElevation(ProtectionAggregator aggregator, RiskScorer scorer) {
    this.aggregator = aggregator;
    this.scorer = scorer;
  }

  /**
   * Called once per processed attempt with the source's foreign-failed-target count
   * sampled before and after the attempt was folded into the windows. Returns the
   * successes to report - empty on the overwhelming majority of attempts, where no
   * tier boundary was crossed.
   */
  public List<ElevatedSuccess> onAttempt(AttemptObservation observation, int foreignFailedBefore, int foreignFailedNow) {
    if (!RiskScorer.crossedMultiTargetTier(foreignFailedBefore, foreignFailedNow)) {
      return List.of();
    }

    List<ElevatedSuccess> elevated = new ArrayList<>();
    for (ActivityWindow.AttemptEvent event : this.aggregator.unalertedForeignSuccesses(observation)) {
      RiskAssessment assessment = this.scorer.scoreRetroactiveMultiTargetSuccess(event.nickname(), foreignFailedNow);
      if (assessment == null) {
        // The reached tier is disabled by config; leave the events unmarked so a later
        // reload that re-enables the factor can still pick them up.
        break;
      }

      event.markConfirmationAlerted();
      // The candidate came from the source's own ip window, so its address IS the
      // current observation's address - no parsing, no DNS.
      elevated.add(new ElevatedSuccess(
          AttemptObservation.builder(event.nickname(), observation.getIp(), AttemptOutcome.LOGIN_SUCCESS)
              .accountExists(true)
              .timestamp(event.time())
              .build(),
          assessment));
    }

    return elevated;
  }

  /**
   * A past success re-scored at confirmation severity: a synthetic observation carrying
   * the original nickname, source address and timestamp, ready for the ordinary
   * dispatch path (log, PROTECTION_EVENTS row, Velocity event, webhook with the
   * {@code account:<nick>} cluster cooldown).
   */
  public record ElevatedSuccess(AttemptObservation observation, RiskAssessment assessment) {
  }
}
