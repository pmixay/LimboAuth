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

package net.elytrium.limboauth.protection.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicLong;
import net.elytrium.limboauth.protection.TestSettings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class EnforcementStateTest {

  @BeforeAll
  static void loadSettings() {
    TestSettings.load();
  }

  @Test
  void blocksAndShieldsExpire() {
    AtomicLong clock = new AtomicLong(1000);
    EnforcementState state = new EnforcementState(clock::get);

    state.blockSource("203.0.113.7", 5000);
    state.shieldAccount("victim", 4000);
    assertTrue(state.isSourceBlocked("203.0.113.7"));
    assertTrue(state.isAccountShielded("victim"));
    assertFalse(state.isSourceBlocked("203.0.113.8"));

    clock.set(4500);
    assertTrue(state.isSourceBlocked("203.0.113.7"));
    assertFalse(state.isAccountShielded("victim"));

    clock.set(6000);
    assertFalse(state.isSourceBlocked("203.0.113.7"));

    state.purge(6000);
    assertEquals(0, state.getBlockedSourceCount());
    assertEquals(0, state.getShieldedAccountCount());
  }

  @Test
  void extensionsKeepTheLongerDeadline() {
    AtomicLong clock = new AtomicLong(1000);
    EnforcementState state = new EnforcementState(clock::get);

    state.blockSource("203.0.113.7", 9000);
    state.blockSource("203.0.113.7", 5000);
    clock.set(8000);
    assertTrue(state.isSourceBlocked("203.0.113.7"), "a shorter re-block must not shrink an existing one");
  }

  @Test
  void unblockClearsBothKinds() {
    EnforcementState state = new EnforcementState(() -> 1000);
    state.blockSource("203.0.113.7", 9000);
    state.shieldAccount("victim", 9000);

    assertNull(state.unblock("unrelated"));
    assertNotNull(state.unblock("203.0.113.7"));
    assertFalse(state.isSourceBlocked("203.0.113.7"));

    // Nickname matching is case-insensitive, like the rest of the auth flow.
    assertNotNull(state.unblock("Victim"));
    assertFalse(state.isAccountShielded("victim"));
  }

  @Test
  void snapshotsExcludeExpiredEntries() {
    AtomicLong clock = new AtomicLong(1000);
    EnforcementState state = new EnforcementState(clock::get);
    state.blockSource("203.0.113.7", 2000);
    state.blockSource("203.0.113.8", 9000);

    clock.set(3000);
    assertEquals(1, state.snapshotBlockedSources().size());
    assertTrue(state.snapshotBlockedSources().containsKey("203.0.113.8"));
  }
}
