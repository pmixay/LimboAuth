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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

class PasswordFingerprinterTest {

  @Test
  void stableWithinInstance() {
    PasswordFingerprinter fingerprinter = new PasswordFingerprinter();
    assertEquals(fingerprinter.fingerprint("hunter2"), fingerprinter.fingerprint("hunter2"));
    assertNotEquals(fingerprinter.fingerprint("hunter2"), fingerprinter.fingerprint("hunter3"));
  }

  @Test
  void keyedPerBoot() {
    // Different instances (= different boots) must not produce comparable fingerprints,
    // otherwise stored values could be brute-forced offline.
    PasswordFingerprinter first = new PasswordFingerprinter();
    PasswordFingerprinter second = new PasswordFingerprinter();
    assertNotEquals(first.fingerprint("hunter2"), second.fingerprint("hunter2"));
  }
}
