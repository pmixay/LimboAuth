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

package net.elytrium.limboauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SettingsUpgradeTest {

  /**
   * Simulates upgrading from a stock LimboAuth install: a config.yml written by an older
   * version has no protection section, and the new keys must appear with their defaults
   * after the reload - no manual migration.
   */
  @Test
  void protectionSectionIsAddedToOldConfigs(@TempDir Path directory) throws Exception {
    Path configFile = directory.resolve("config.yml");
    Files.writeString(configFile, "prefix: \"LimboAuth &6>>&f\"\n", StandardCharsets.UTF_8);

    Settings.IMP.reload(configFile.toFile(), Settings.IMP.PREFIX);

    assertNotNull(Settings.IMP.PROTECTION);
    assertNotNull(Settings.IMP.PROTECTION.SCORING);
    assertNotNull(Settings.IMP.PROTECTION.SCORING.WEIGHTS);
    assertTrue(Settings.IMP.PROTECTION.ENABLED);
    assertEquals("MONITOR", Settings.IMP.PROTECTION.MODE);
    assertEquals(20, Settings.IMP.PROTECTION.SCORING.WEIGHTS.GEO_COUNTRY_MISMATCH);
    assertEquals("SOCIAL", Settings.IMP.PROTECTION.SOCIAL.TABLE_NAME);
    assertEquals(50, Settings.IMP.PROTECTION.SCORING.THRESHOLD_HIGH);

    // v1.1 human-attacker tuning keys must appear on upgrade as well.
    assertEquals(30, Settings.IMP.PROTECTION.SCORING.DORMANT_DAYS);
    assertEquals(15, Settings.IMP.PROTECTION.SCORING.WEIGHTS.IP_DISTINCT_TARGETS_4);
    assertEquals(15, Settings.IMP.PROTECTION.SCORING.WEIGHTS.MULTI_ACCOUNT_NEW_SOURCE_2);
    assertEquals(15, Settings.IMP.PROTECTION.SCORING.WEIGHTS.DORMANT_ACCOUNT_TAKEOVER);

    // v2.1 foreign-target tuning keys (spray FP fix + multi-target-source confirmation).
    assertEquals(3, Settings.IMP.PROTECTION.SCORING.SPRAY_FOREIGN_TARGET_MIN);
    assertEquals(50, Settings.IMP.PROTECTION.SCORING.WEIGHTS.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE_3);
    assertEquals(80, Settings.IMP.PROTECTION.SCORING.WEIGHTS.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE_6);

    // v2.2 balancing keys (scatter shortcut, foreign-fail spread, new-source cash-out tier).
    assertEquals(2, Settings.IMP.PROTECTION.SCORING.SPRAY_SCATTER_SUBNET_MIN);
    assertEquals(15, Settings.IMP.PROTECTION.SCORING.WEIGHTS.IP_FOREIGN_TARGET_SPREAD_3);
    assertEquals(25, Settings.IMP.PROTECTION.SCORING.WEIGHTS.IP_FOREIGN_TARGET_SPREAD_5);
    assertEquals(25, Settings.IMP.PROTECTION.SCORING.WEIGHTS.MULTI_ACCOUNT_NEW_SOURCE_4);

    // v2 enforcement ships present-but-off: one switch away, safe thresholds preconfigured.
    assertFalse(Settings.IMP.PROTECTION.ENFORCEMENT.ENABLED);
    assertEquals("HIGH", Settings.IMP.PROTECTION.ENFORCEMENT.KICK_ON);
    assertEquals("HIGH", Settings.IMP.PROTECTION.ENFORCEMENT.BLOCK_SOURCE_ON);
    assertEquals("HIGH", Settings.IMP.PROTECTION.ENFORCEMENT.SHIELD_ACCOUNT_ON);
    assertEquals(30, Settings.IMP.PROTECTION.ENFORCEMENT.SOURCE_BLOCK_MINUTES);
    assertEquals(60, Settings.IMP.PROTECTION.ENFORCEMENT.SHIELD_MINUTES);

    String written = Files.readString(configFile, StandardCharsets.UTF_8);
    assertTrue(written.contains("protection:"), "the protection section must be written back to disk");
    assertTrue(written.contains("geo-country-mismatch:"), "weights must be written back to disk");
    assertTrue(written.contains("dormant-days:"), "v1.1 keys must be written back to disk");
    assertTrue(written.contains("multi-account-new-source-2:"), "v1.1 weights must be written back to disk");
    assertTrue(written.contains("spray-foreign-target-min:"), "v2.1 keys must be written back to disk");
    assertTrue(written.contains("confirm-success-from-multi-target-source-3:"), "v2.1 weights must be written back to disk");
    assertTrue(written.contains("confirm-success-from-multi-target-source-6:"), "v2.1 weights must be written back to disk");
    assertTrue(written.contains("spray-scatter-subnet-min:"), "v2.2 keys must be written back to disk");
    assertTrue(written.contains("ip-foreign-target-spread-3:"), "v2.2 weights must be written back to disk");
    assertTrue(written.contains("multi-account-new-source-4:"), "v2.2 weights must be written back to disk");
    assertTrue(written.contains("kick-on:"), "enforcement keys must be written back to disk");
    assertTrue(written.contains("shield-account-on:"), "enforcement keys must be written back to disk");
    assertTrue(written.contains("protection-kick:"), "the protection kick message must be written back to disk");
  }

  /**
   * Simulates upgrading from the v2 protection release (detection + enforcement, the
   * version running in production before the foreign-target work): the config carries a
   * complete v2 protection section with values the admin customized - including live
   * enforcement - and none of the v2.1 keys. The reload must keep every customization,
   * leave untouched keys alone, and append the v2.1 keys with their defaults, so the
   * upgrade needs no manual config edit and cannot silently disarm enforcement.
   */
  @Test
  void v2ProtectionConfigMigratesToV21(@TempDir Path directory) throws Exception {
    Path configFile = directory.resolve("config.yml");
    Files.writeString(configFile, String.join("\n",
        "prefix: \"LimboAuth &6>>&f\"",
        "protection:",
        "  enabled: true",
        "  mode: MONITOR",
        "  windows:",
        "    volume-window-millis: 600000",
        "    distribution-window-millis: 3600000",
        "    max-events-per-window: 256",
        "  scoring:",
        "    threshold-high: 55",
        "    dormant-days: 30",
        "    weights:",
        "      password-spray-3: 20",
        "      confirm-sprayed-password-success: 90",
        "      confirm-success-after-distributed-failures: 80",
        "  enforcement:",
        "    enabled: true",
        "    kick-on: CRITICAL",
        "    block-source-on: HIGH",
        "    source-block-minutes: 30",
        ""), StandardCharsets.UTF_8);

    // Bootstrap once so the @Create sections exist regardless of test order, then
    // capture the shipped defaults the finally block must restore (YamlConfig keeps
    // current field values as the defaults it writes - see the v1 test).
    Settings.IMP.reload(directory.resolve("bootstrap.yml").toFile(), Settings.IMP.PREFIX);
    int defaultThresholdHigh = Settings.IMP.PROTECTION.SCORING.THRESHOLD_HIGH;
    int defaultSprayedWeight = Settings.IMP.PROTECTION.SCORING.WEIGHTS.CONFIRM_SPRAYED_PASSWORD_SUCCESS;
    boolean defaultEnforcementEnabled = Settings.IMP.PROTECTION.ENFORCEMENT.ENABLED;
    String defaultKickOn = Settings.IMP.PROTECTION.ENFORCEMENT.KICK_ON;
    try {
      Settings.IMP.reload(configFile.toFile(), Settings.IMP.PREFIX);

      // Every customized v2 value survives the upgrade, enforcement stays armed.
      assertEquals(55, Settings.IMP.PROTECTION.SCORING.THRESHOLD_HIGH);
      assertEquals(90, Settings.IMP.PROTECTION.SCORING.WEIGHTS.CONFIRM_SPRAYED_PASSWORD_SUCCESS);
      assertTrue(Settings.IMP.PROTECTION.ENFORCEMENT.ENABLED);
      assertEquals("CRITICAL", Settings.IMP.PROTECTION.ENFORCEMENT.KICK_ON);
      // Untouched v2 keys keep the values the file pinned.
      assertEquals(20, Settings.IMP.PROTECTION.SCORING.WEIGHTS.PASSWORD_SPRAY_3);
      assertEquals(80, Settings.IMP.PROTECTION.SCORING.WEIGHTS.CONFIRM_SUCCESS_AFTER_DISTRIBUTED_FAILURES);
      assertEquals(30, Settings.IMP.PROTECTION.ENFORCEMENT.SOURCE_BLOCK_MINUTES);
      // The v2.1/v2.2 foreign-target keys appear with their defaults.
      assertEquals(3, Settings.IMP.PROTECTION.SCORING.SPRAY_FOREIGN_TARGET_MIN);
      assertEquals(50, Settings.IMP.PROTECTION.SCORING.WEIGHTS.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE_3);
      assertEquals(80, Settings.IMP.PROTECTION.SCORING.WEIGHTS.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE_6);
      assertEquals(2, Settings.IMP.PROTECTION.SCORING.SPRAY_SCATTER_SUBNET_MIN);
      assertEquals(15, Settings.IMP.PROTECTION.SCORING.WEIGHTS.IP_FOREIGN_TARGET_SPREAD_3);
      assertEquals(25, Settings.IMP.PROTECTION.SCORING.WEIGHTS.MULTI_ACCOUNT_NEW_SOURCE_4);

      String written = Files.readString(configFile, StandardCharsets.UTF_8);
      assertTrue(written.contains("spray-foreign-target-min: 3"), "the v2.1 scoring key must be appended with its default");
      assertTrue(written.contains("confirm-success-from-multi-target-source-3: 50"), "the v2.1 weights must be appended with their defaults");
      assertTrue(written.contains("confirm-success-from-multi-target-source-6: 80"), "the v2.1 weights must be appended with their defaults");
      assertTrue(written.contains("confirm-sprayed-password-success: 90"), "customized weights must be preserved on disk");
      assertTrue(written.contains("kick-on: \"CRITICAL\""), "customized enforcement must be preserved on disk");
    } finally {
      Settings.IMP.PROTECTION.SCORING.THRESHOLD_HIGH = defaultThresholdHigh;
      Settings.IMP.PROTECTION.SCORING.WEIGHTS.CONFIRM_SPRAYED_PASSWORD_SUCCESS = defaultSprayedWeight;
      Settings.IMP.PROTECTION.ENFORCEMENT.ENABLED = defaultEnforcementEnabled;
      Settings.IMP.PROTECTION.ENFORCEMENT.KICK_ON = defaultKickOn;
    }
  }

  /**
   * Simulates upgrading from the v1 protection release: the config already has a protection
   * section with the retired action-high/action-critical enforcement placeholders and a
   * value the admin customized. The reload must keep the customization, append every new
   * key with its default, and drop the retired keys - without any manual edit.
   */
  @Test
  void v1ProtectionConfigMigratesToV2(@TempDir Path directory) throws Exception {
    Path configFile = directory.resolve("config.yml");
    Files.writeString(configFile, String.join("\n",
        "prefix: \"LimboAuth &6>>&f\"",
        "protection:",
        "  enabled: true",
        "  mode: MONITOR",
        "  scoring:",
        "    weights:",
        "      geo-country-mismatch: 25",
        "  enforcement:",
        "    enabled: false",
        "    action-high: NONE",
        "    action-critical: NONE",
        ""), StandardCharsets.UTF_8);

    // Bootstrap once with a pristine config so the @Create sections exist regardless of
    // which test in this JVM runs first, then capture the shipped default to restore.
    Settings.IMP.reload(directory.resolve("bootstrap.yml").toFile(), Settings.IMP.PREFIX);
    int defaultGeoWeight = Settings.IMP.PROTECTION.SCORING.WEIGHTS.GEO_COUNTRY_MISMATCH;
    try {
      Settings.IMP.reload(configFile.toFile(), Settings.IMP.PREFIX);

      // The admin's customized weight survives the upgrade.
      assertEquals(25, Settings.IMP.PROTECTION.SCORING.WEIGHTS.GEO_COUNTRY_MISMATCH);
      // Untouched keys keep the values the v1 file pinned.
      assertTrue(Settings.IMP.PROTECTION.ENABLED);
      assertFalse(Settings.IMP.PROTECTION.ENFORCEMENT.ENABLED);
      // Every key that did not exist in v1 appears with its v2 default.
      assertEquals(15, Settings.IMP.PROTECTION.SCORING.WEIGHTS.IP_DISTINCT_TARGETS_4);
      assertEquals(30, Settings.IMP.PROTECTION.SCORING.DORMANT_DAYS);
      assertEquals("HIGH", Settings.IMP.PROTECTION.ENFORCEMENT.KICK_ON);
      assertEquals("HIGH", Settings.IMP.PROTECTION.ENFORCEMENT.SHIELD_ACCOUNT_ON);
      assertEquals(60, Settings.IMP.PROTECTION.ENFORCEMENT.SHIELD_MINUTES);
      assertEquals(3, Settings.IMP.PROTECTION.SCORING.SPRAY_FOREIGN_TARGET_MIN);
      assertEquals(50, Settings.IMP.PROTECTION.SCORING.WEIGHTS.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE_3);
      assertEquals(80, Settings.IMP.PROTECTION.SCORING.WEIGHTS.CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE_6);

      String written = Files.readString(configFile, StandardCharsets.UTF_8);
      assertTrue(written.contains("geo-country-mismatch: 25"), "customized values must be preserved on disk");
      assertTrue(written.contains("kick-on:"), "new enforcement keys must be appended");
      assertFalse(written.contains("action-high:"), "retired v1 keys must be dropped from the rewritten config");
      assertFalse(written.contains("action-critical:"), "retired v1 keys must be dropped from the rewritten config");
    } finally {
      // Settings is JVM-global and YamlConfig keeps current field values as the defaults
      // it writes, so the customized weight must be restored by hand for the other tests.
      Settings.IMP.PROTECTION.SCORING.WEIGHTS.GEO_COUNTRY_MISMATCH = defaultGeoWeight;
    }
  }
}
