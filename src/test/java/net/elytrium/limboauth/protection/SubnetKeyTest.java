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

import java.net.InetAddress;
import org.junit.jupiter.api.Test;

class SubnetKeyTest {

  @Test
  void ipv4UsesSlash24() throws Exception {
    assertEquals("203.0.113.0/24", SubnetKey.of(InetAddress.getByName("203.0.113.77")));
    assertEquals(SubnetKey.of(InetAddress.getByName("203.0.113.1")), SubnetKey.of(InetAddress.getByName("203.0.113.254")));
  }

  @Test
  void ipv6UsesSlash64() throws Exception {
    assertEquals(SubnetKey.of(InetAddress.getByName("2001:db8:1:2:aaaa::1")), SubnetKey.of(InetAddress.getByName("2001:db8:1:2:bbbb::2")));
    assertEquals("2001:db8:1:2::/64", SubnetKey.of(InetAddress.getByName("2001:db8:1:2::1")));
  }

  @Test
  void differentSubnetsDiffer() throws Exception {
    assertEquals(false, SubnetKey.of(InetAddress.getByName("203.0.113.1")).equals(SubnetKey.of(InetAddress.getByName("203.0.114.1"))));
  }
}
