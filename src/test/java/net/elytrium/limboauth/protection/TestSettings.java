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

import java.nio.file.Files;
import java.nio.file.Path;
import net.elytrium.limboauth.Settings;

/**
 * Loads the real Settings defaults once per JVM (through the same YamlConfig path the
 * plugin uses in production), so tests exercise the shipped default weights/thresholds.
 */
public final class TestSettings {

  private static final Object LOCK = new Object();

  private static boolean loaded;

  private TestSettings() {
  }

  public static void load() {
    synchronized (LOCK) {
      if (!loaded) {
        try {
          Path directory = Files.createTempDirectory("limboauth-test");
          Settings.IMP.reload(directory.resolve("config.yml").toFile(), Settings.IMP.PREFIX);
          loaded = true;
        } catch (Exception e) {
          throw new IllegalStateException("Failed to load test settings", e);
        }
      }
    }
  }
}
