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

    String written = Files.readString(configFile, StandardCharsets.UTF_8);
    assertTrue(written.contains("protection:"), "the protection section must be written back to disk");
    assertTrue(written.contains("geo-country-mismatch:"), "weights must be written back to disk");
  }
}
