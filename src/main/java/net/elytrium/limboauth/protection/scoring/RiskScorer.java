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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import net.elytrium.limboauth.Settings;
import net.elytrium.limboauth.protection.AttemptObservation;
import net.elytrium.limboauth.protection.AttemptOutcome;
import net.elytrium.limboauth.protection.Severity;
import net.elytrium.limboauth.protection.SubnetKey;
import net.elytrium.limboauth.protection.aggregate.AggregateSnapshot;
import net.elytrium.limboauth.protection.geoip.GeoIpResult;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Weighted additive risk scoring with per-category caps.
 *
 * <p>Low-FPR properties: BEHAVIOR and GEO are capped so they can never reach the HIGH
 * threshold alone, HIGH structurally requires at least two independent categories,
 * and the CRITICAL-tier confirmation factors only fire on signals a legitimate player
 * cannot produce alone (e.g. failures from OTHER IPs preceding a success).
 */
public class RiskScorer {

  /**
   * Foreign-failed-target counts at which the multi-target-source confirmation escalates,
   * descending as {@link #tiered} expects. Shared with the retroactive pass through
   * {@link #crossedMultiTargetTier} so both react at exactly the same boundaries.
   */
  private static final int[] MULTI_TARGET_SOURCE_TIERS = {6, 3};

  private volatile List<String> brandRegexSource;
  private volatile List<Pattern> brandPatterns = List.of();
  private volatile List<String> hostingAsnSource;
  private volatile Set<Long> hostingAsns = Set.of();

  public RiskAssessment score(AttemptObservation observation, AggregateSnapshot snapshot,
                              @Nullable GeoIpResult currentGeo, @Nullable String storedCountryIso) {
    Settings.PROTECTION.SCORING scoring = Settings.IMP.PROTECTION.SCORING;
    Settings.PROTECTION.SCORING.WEIGHTS weights = scoring.WEIGHTS;
    List<FactorContribution> contributions = new ArrayList<>();

    int volume = 0;
    volume += this.tiered(contributions, RiskFactor.IP_FAIL_RATE, snapshot.ipFailures(),
        new int[] {20, 10, 6}, new int[] {weights.IP_FAIL_RATE_20, weights.IP_FAIL_RATE_10, weights.IP_FAIL_RATE_6},
        snapshot.ipFailures() + " failed logins from this IP in the volume window");
    volume += this.tiered(contributions, RiskFactor.IP_DISTINCT_TARGETS, snapshot.ipDistinctFailedTargets(),
        new int[] {10, 5, 4, 3},
        new int[] {weights.IP_DISTINCT_TARGETS_10, weights.IP_DISTINCT_TARGETS_5, weights.IP_DISTINCT_TARGETS_4, weights.IP_DISTINCT_TARGETS_3},
        snapshot.ipDistinctFailedTargets() + " distinct accounts failed from this IP in the distribution window");
    if (snapshot.subnetDistinctIps() >= 2) {
      volume += this.tiered(contributions, RiskFactor.SUBNET_DISTINCT_TARGETS, snapshot.subnetDistinctFailedTargets(),
          new int[] {10, 5}, new int[] {weights.SUBNET_DISTINCT_TARGETS_10, weights.SUBNET_DISTINCT_TARGETS_5},
          snapshot.subnetDistinctFailedTargets() + " distinct accounts failed from this subnet ("
              + snapshot.subnetDistinctIps() + " source IPs) in the distribution window");
    }

    int distribution = 0;
    distribution += this.tiered(contributions, RiskFactor.ACCOUNT_DISTINCT_IPS, snapshot.accountDistinctFailIps(),
        new int[] {4, 2}, new int[] {weights.ACCOUNT_DISTINCT_IPS_4, weights.ACCOUNT_DISTINCT_IPS_2},
        "this account failed from " + snapshot.accountDistinctFailIps() + " distinct IPs in the distribution window");
    // Foreign refinement of the raw distinct-target volume factor: failures against other
    // players' accounts, which a shared-IP household cannot produce. Lifts a grinding
    // checker to HIGH (and thus a flagged source) BEFORE it scores a hit, so the eventual
    // success is confirmed by the flagged-source factor even when the hit lands on an
    // account the foreign gates cannot vouch for (e.g. no stored login IP yet).
    distribution += this.tiered(contributions, RiskFactor.IP_FOREIGN_TARGET_SPREAD, snapshot.foreignFailedTargets(),
        new int[] {5, 3}, new int[] {weights.IP_FOREIGN_TARGET_SPREAD_5, weights.IP_FOREIGN_TARGET_SPREAD_3},
        "failed logins against " + snapshot.foreignFailedTargets() + " other players' accounts from this source in the distribution window");
    distribution += this.tiered(contributions, RiskFactor.PASSWORD_SPRAY, snapshot.fingerprintDistinctTargets(),
        new int[] {8, 3}, new int[] {weights.PASSWORD_SPRAY_8, weights.PASSWORD_SPRAY_3},
        "the same password was tried against " + snapshot.fingerprintDistinctTargets() + " distinct accounts");
    int churnSessions = Math.max(snapshot.ipChurnSessions(), snapshot.subnetChurnSessions());
    distribution += this.tiered(contributions, RiskFactor.CHURN_SESSIONS, churnSessions,
        new int[] {3}, new int[] {weights.CHURN_SESSIONS_3},
        churnSessions + " short join-attempt-quit sessions from this source in the distribution window");
    distribution += this.tiered(contributions, RiskFactor.MULTI_ACCOUNT_NEW_SOURCE_SUCCESS, snapshot.ipDistinctNewSourceSuccesses(),
        new int[] {4, 2}, new int[] {weights.MULTI_ACCOUNT_NEW_SOURCE_4, weights.MULTI_ACCOUNT_NEW_SOURCE_2},
        snapshot.ipDistinctNewSourceSuccesses() + " accounts whose last login came from elsewhere were logged into from this IP");
    distribution += this.dormantTakeover(contributions, observation, weights, scoring);

    int behavior = 0;
    if (!(observation.isFloodgate() && scoring.SKIP_BEHAVIOR_FOR_FLOODGATE)) {
      if (observation.isFirstAttemptOfSession() && observation.getMillisSinceJoin() < scoring.FAST_FIRST_COMMAND_MILLIS) {
        behavior += this.add(contributions, RiskFactor.INSTANT_FIRST_COMMAND, weights.INSTANT_FIRST_COMMAND,
            "first command " + observation.getMillisSinceJoin() + "ms after spawn");
      }

      String brand = observation.getClientBrand();
      if (brand == null) {
        behavior += this.add(contributions, RiskFactor.MISSING_BRAND, weights.MISSING_BRAND, "client sent no brand");
      } else {
        for (Pattern pattern : this.getBrandPatterns(scoring.SUSPICIOUS_BRANDS)) {
          if (pattern.matcher(brand).matches()) {
            behavior += this.add(contributions, RiskFactor.SUSPICIOUS_BRAND, weights.SUSPICIOUS_BRAND, "client brand \"" + brand + "\"");
            break;
          }
        }
      }
    }

    int geo = 0;
    if (currentGeo != null) {
      String currentCountry = currentGeo.countryIso();
      if (currentCountry != null && storedCountryIso != null && !currentCountry.equalsIgnoreCase(storedCountryIso)) {
        geo += this.add(contributions, RiskFactor.GEO_COUNTRY_MISMATCH, weights.GEO_COUNTRY_MISMATCH,
            "login country " + currentCountry + " differs from last login country " + storedCountryIso);
      }

      if (this.isHostingAsn(currentGeo)) {
        geo += this.add(contributions, RiskFactor.GEO_HOSTING_ASN, weights.GEO_HOSTING_ASN,
            "hosting ASN " + currentGeo.asn() + " (" + currentGeo.asnOrganization() + ")");
      }
    }

    int confirmation = 0;
    if (observation.getOutcome() == AttemptOutcome.LOGIN_SUCCESS) {
      if (snapshot.accountFailsFromOtherIps() >= 2) {
        confirmation += this.add(contributions, RiskFactor.CONFIRM_SUCCESS_AFTER_DISTRIBUTED_FAILURES,
            weights.CONFIRM_SUCCESS_AFTER_DISTRIBUTED_FAILURES,
            "successful login after " + snapshot.accountFailsFromOtherIps() + " recent failures from OTHER IPs");
      }

      if (snapshot.sourceFlagged()) {
        confirmation += this.add(contributions, RiskFactor.CONFIRM_SUCCESS_FROM_FLAGGED_SOURCE,
            weights.CONFIRM_SUCCESS_FROM_FLAGGED_SOURCE, "successful login from a source flagged HIGH before this attempt");
      }

      // Foreign OTHER targets only: one person reusing one password across their own
      // alts (stored LOGINIP on the source's subnet) satisfies the raw distinct-target
      // count but is not a spray, and the hit itself is never evidence of the spray -
      // the count that confirms covers other players' accounts. Two triggers, each 0 to
      // disable: enough other foreign targets outright, or fewer targets whose stored
      // subnets are SCATTERED - a family's alts live on their owner's network(s), a real
      // spray's victims are strangers spread across unrelated ones.
      int sprayForeignMin = scoring.SPRAY_FOREIGN_TARGET_MIN;
      int sprayScatterMin = scoring.SPRAY_SCATTER_SUBNET_MIN;
      boolean sprayByCount = sprayForeignMin > 0 && snapshot.foreignFingerprintTargets() >= sprayForeignMin;
      boolean sprayByScatter = sprayScatterMin > 0 && snapshot.foreignFingerprintSubnets() >= sprayScatterMin;
      if (sprayByCount || sprayByScatter) {
        confirmation += this.add(contributions, RiskFactor.CONFIRM_SPRAYED_PASSWORD_SUCCESS,
            weights.CONFIRM_SPRAYED_PASSWORD_SUCCESS,
            "the successful password was sprayed against " + snapshot.foreignFingerprintTargets()
                + " other accounts stored on " + snapshot.foreignFingerprintSubnets() + " other networks");
      }

      // The success must itself be on a foreign account, mirroring the retroactive pass:
      // a checker's hit lands on somebody ELSE's account, while an innocent neighbor
      // logging into their own account behind the same source must never be confirmed
      // by failures they did not produce.
      if (observation.isAccountExists() && SubnetKey.isForeign(observation.getStoredLoginIp(), observation.getSubnetKey())) {
        confirmation += this.multiTargetSourceContribution(contributions, snapshot.foreignFailedTargets(),
            "successful login from a source that recently failed against " + snapshot.foreignFailedTargets() + " other players' accounts");
      }
    }

    int score = Math.min(volume, scoring.CAP_VOLUME)
        + Math.min(distribution, scoring.CAP_DISTRIBUTION)
        + Math.min(behavior, scoring.CAP_BEHAVIOR)
        + Math.min(geo, scoring.CAP_GEO)
        + confirmation;

    return new RiskAssessment(score, this.severityOf(score, scoring), List.copyOf(contributions),
        this.clusterKey(observation, contributions, confirmation > 0));
  }

  /**
   * Assessment for a success that predates its source crossing a multi-target tier: the
   * same factor, weights and thresholds as the live path, evaluated against the source's
   * current foreign-failure spread. Returns {@code null} when the reached tier is
   * disabled (weight 0), so a config that switches the factor off also silences the
   * retroactive pass.
   */
  @Nullable
  public RiskAssessment scoreRetroactiveMultiTargetSuccess(String lowercaseNickname, int foreignFailedTargets, long millisSinceSuccess) {
    Settings.PROTECTION.SCORING scoring = Settings.IMP.PROTECTION.SCORING;

    List<FactorContribution> contributions = new ArrayList<>();
    int score = this.multiTargetSourceContribution(contributions, foreignFailedTargets,
        "successful login " + TimeUnit.MILLISECONDS.toMinutes(millisSinceSuccess) + " min earlier from a source that has since failed against "
            + foreignFailedTargets + " other players' accounts (retroactive confirmation)");
    if (score == 0) {
      return null;
    }

    return new RiskAssessment(score, this.severityOf(score, scoring), List.copyOf(contributions), "account:" + lowercaseNickname);
  }

  /**
   * The one place the multi-target tiers are paired with their weights, so the live
   * confirmation and the retroactive pass can never drift apart.
   */
  private int multiTargetSourceContribution(List<FactorContribution> contributions, int foreignFailedTargets, String detail) {
    Settings.PROTECTION.SCORING.WEIGHTS weights = Settings.IMP.PROTECTION.SCORING.WEIGHTS;
    return this.tiered(contributions, RiskFactor.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE, foreignFailedTargets,
        MULTI_TARGET_SOURCE_TIERS,
        new int[] {weights.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE_6, weights.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE_3},
        detail);
  }

  /**
   * Did the foreign-failed-target count cross into a higher multi-target tier with this
   * attempt? The retroactive pass triggers exactly on these transitions - once per tier
   * per window-epoch - instead of rescanning on every attempt from a hot source.
   */
  public static boolean crossedMultiTargetTier(int before, int now) {
    for (int tier : MULTI_TARGET_SOURCE_TIERS) {
      if (before < tier && now >= tier) {
        return true;
      }
    }

    return false;
  }

  private Severity severityOf(int score, Settings.PROTECTION.SCORING scoring) {
    if (score >= scoring.THRESHOLD_CRITICAL) {
      return Severity.CRITICAL;
    } else if (score >= scoring.THRESHOLD_HIGH) {
      return Severity.HIGH;
    } else if (score >= scoring.THRESHOLD_SUSPICIOUS) {
      return Severity.SUSPICIOUS;
    } else if (score >= scoring.THRESHOLD_INFO) {
      return Severity.INFO;
    } else {
      return Severity.NONE;
    }
  }

  /**
   * A successful login on a long-dormant account from a different subnet than its stored
   * LOGINIP. Requires both conditions at once so a returning player scores nothing when
   * they come back from their usual network, and a merely traveling player is caught by
   * the GEO factor alone (INFO) rather than this one.
   */
  private int dormantTakeover(List<FactorContribution> contributions, AttemptObservation observation,
                              Settings.PROTECTION.SCORING.WEIGHTS weights, Settings.PROTECTION.SCORING scoring) {
    if (observation.getOutcome() != AttemptOutcome.LOGIN_SUCCESS || observation.getStoredLoginDate() <= 0) {
      return 0;
    }

    long dormantMillis = observation.getTimestamp() - observation.getStoredLoginDate();
    if (dormantMillis < TimeUnit.DAYS.toMillis(Math.max(1, scoring.DORMANT_DAYS))) {
      return 0;
    }

    if (!SubnetKey.isForeign(observation.getStoredLoginIp(), observation.getSubnetKey())) {
      return 0;
    }

    return this.add(contributions, RiskFactor.DORMANT_ACCOUNT_TAKEOVER, weights.DORMANT_ACCOUNT_TAKEOVER,
        "successful login on an account dormant for " + TimeUnit.MILLISECONDS.toDays(dormantMillis) + " days from a new subnet");
  }

  private String clusterKey(AttemptObservation observation, List<FactorContribution> contributions, boolean confirmed) {
    boolean accountDistributed = contributions.stream().anyMatch(contribution -> contribution.factor() == RiskFactor.ACCOUNT_DISTINCT_IPS);
    if (confirmed || accountDistributed) {
      return "account:" + observation.getLowercaseNickname();
    }

    boolean spray = contributions.stream().anyMatch(contribution -> contribution.factor() == RiskFactor.PASSWORD_SPRAY);
    if (spray && observation.hasFingerprint()) {
      return "spray:" + Long.toHexString(observation.getPasswordFingerprint());
    }

    boolean subnetOnly = contributions.stream().allMatch(contribution -> contribution.factor() == RiskFactor.SUBNET_DISTINCT_TARGETS);
    if (subnetOnly && !contributions.isEmpty()) {
      return "subnet:" + observation.getSubnetKey();
    }

    return "ip:" + observation.getIpString();
  }

  private int tiered(List<FactorContribution> contributions, RiskFactor factor, int value, int[] thresholds, int[] weights, String detail) {
    for (int i = 0; i < thresholds.length; ++i) {
      if (value >= thresholds[i] && weights[i] > 0) {
        contributions.add(new FactorContribution(factor, weights[i], detail));
        return weights[i];
      }
    }

    return 0;
  }

  private int add(List<FactorContribution> contributions, RiskFactor factor, int weight, String detail) {
    if (weight <= 0) {
      return 0;
    }

    contributions.add(new FactorContribution(factor, weight, detail));
    return weight;
  }

  private boolean isHostingAsn(GeoIpResult geo) {
    if (geo.asn() != null && this.getHostingAsns(Settings.IMP.PROTECTION.GEOIP.HOSTING_ASNS).contains(geo.asn())) {
      return true;
    }

    String organization = geo.asnOrganization();
    if (organization != null) {
      String lowercase = organization.toLowerCase(Locale.ROOT);
      for (String keyword : Settings.IMP.PROTECTION.GEOIP.HOSTING_ORG_KEYWORDS) {
        if (lowercase.contains(keyword.toLowerCase(Locale.ROOT))) {
          return true;
        }
      }
    }

    return false;
  }

  private List<Pattern> getBrandPatterns(List<String> source) {
    if (source != this.brandRegexSource) {
      List<Pattern> compiled = new ArrayList<>();
      for (String regex : source) {
        try {
          compiled.add(Pattern.compile(regex));
        } catch (PatternSyntaxException e) {
          // Ignore invalid patterns instead of breaking the whole pipeline; the config is user-supplied.
        }
      }

      this.brandPatterns = List.copyOf(compiled);
      this.brandRegexSource = source;
    }

    return this.brandPatterns;
  }

  private Set<Long> getHostingAsns(List<String> source) {
    if (source != this.hostingAsnSource) {
      Set<Long> parsed = new HashSet<>();
      for (String asn : source) {
        try {
          parsed.add(Long.parseLong(asn.trim()));
        } catch (NumberFormatException e) {
          // Ignore unparsable entries; the config is user-supplied.
        }
      }

      this.hostingAsns = Set.copyOf(parsed);
      this.hostingAsnSource = source;
    }

    return this.hostingAsns;
  }
}
