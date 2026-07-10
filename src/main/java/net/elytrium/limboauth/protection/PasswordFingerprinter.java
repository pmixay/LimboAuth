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

import io.whitfin.siphash.SipHash;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * Keyed 64-bit fingerprint of attempted passwords, used only to correlate the same password
 * being tried against multiple accounts (password spraying). The key is generated per boot
 * and never persisted, so stored fingerprints cannot be brute-forced back to passwords offline.
 */
public class PasswordFingerprinter {

  private static final SecureRandom RANDOM = new SecureRandom();

  private final byte[] key = new byte[16];

  public PasswordFingerprinter() {
    RANDOM.nextBytes(this.key);
  }

  public long fingerprint(String password) {
    return SipHash.init(this.key).update(password.getBytes(StandardCharsets.UTF_8)).digest();
  }
}
