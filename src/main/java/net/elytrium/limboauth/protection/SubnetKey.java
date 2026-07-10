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

import java.net.InetAddress;

public final class SubnetKey {

  private SubnetKey() {
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
