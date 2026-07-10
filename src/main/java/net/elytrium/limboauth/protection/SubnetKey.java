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

import com.google.common.net.InetAddresses;
import java.net.InetAddress;
import org.checkerframework.checker.nullness.qual.Nullable;

public final class SubnetKey {

  private SubnetKey() {
  }

  /**
   * Subnet key of a stored IP string, or {@code null} when the value is absent or not a
   * plain IP literal. Uses Guava's literal-only parser so a corrupted LOGINIP value can
   * never trigger a DNS lookup from the scoring path.
   */
  @Nullable
  public static String ofLiteral(@Nullable String address) {
    if (address == null || address.isEmpty() || !InetAddresses.isInetAddress(address)) {
      return null;
    }

    return of(InetAddresses.forString(address));
  }

  /**
   * The single definition of a "foreign" stored address: present, parseable and on a
   * different subnet than the given key. Subnet-level (not exact-IP) so a returning
   * player on a rotated dynamic address inside their usual ISP block is not foreign.
   * Used by the DORMANT_ACCOUNT_TAKEOVER comparison and every foreign-target count -
   * keep them agreeing by changing it only here. An absent or unparsable stored address
   * is NOT foreign: unknown must never score against a player.
   */
  public static boolean isForeign(@Nullable String storedAddress, String subnetKey) {
    String storedSubnet = ofLiteral(storedAddress);
    return storedSubnet != null && !storedSubnet.equals(subnetKey);
  }

  /**
   * Canonical subnet key: /24 for IPv4, /64 for IPv6.
   */
  public static String of(InetAddress address) {
    byte[] bytes = address.getAddress();
    if (bytes.length == 4) {
      return (bytes[0] & 0xFF) + "." + (bytes[1] & 0xFF) + "." + (bytes[2] & 0xFF) + ".0/24";
    } else {
      StringBuilder builder = new StringBuilder();
      for (int i = 0; i < 8 && i < bytes.length - 1; i += 2) {
        if (i > 0) {
          builder.append(':');
        }

        builder.append(Integer.toHexString(((bytes[i] & 0xFF) << 8) | (bytes[i + 1] & 0xFF)));
      }

      return builder.append("::/64").toString();
    }
  }
}
