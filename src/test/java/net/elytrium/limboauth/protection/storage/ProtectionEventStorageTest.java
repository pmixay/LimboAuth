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

package net.elytrium.limboauth.protection.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.jdbc.JdbcPooledConnectionSource;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/**
 * The local event store and the one-way migration out of the auth database, exercised
 * against real (in-memory H2) databases: a "local" store and a separate "auth" database
 * that may still carry a PROTECTION_EVENTS table from an older version.
 */
class ProtectionEventStorageTest {

  private static final AtomicInteger DB_COUNTER = new AtomicInteger();

  private final ProtectionEventStorage storage = new ProtectionEventStorage(LoggerFactory.getLogger("test"));
  private final int dbId = DB_COUNTER.incrementAndGet();

  @AfterEach
  void closeStorage() {
    this.storage.close();
  }

  @Test
  void storesAndQueriesInTheLocalStore() throws Exception {
    this.storage.init(this.memorySource("local"), null);

    this.storage.store(this.event(1000, "finsterry", "HIGH"));
    this.storage.store(this.event(2000, "microsoft", "CRITICAL"));
    this.storage.store(this.event(3000, "finsterry", "INFO"));

    List<ProtectionEvent> recent = this.storage.recent(10);
    assertEquals(3, recent.size());
    assertEquals(3000, recent.get(0).getEventTime());

    List<ProtectionEvent> inspected = this.storage.recentForNickname("finsterry", 10);
    assertEquals(2, inspected.size());
    assertEquals("finsterry", inspected.get(0).getNickname());

    assertEquals(2, this.storage.purgeOlderThan(3000));
    assertEquals(1, this.storage.recent(10).size());
  }

  @Test
  void legacyRowsAreMovedAndTheAuthTableIsDropped() throws Exception {
    ConnectionSource authSource = this.memorySource("auth");
    Dao<ProtectionEvent, Long> authDao = this.createLegacyTable(authSource);
    authDao.create(this.event(1000, "finsterry", "HIGH"));
    authDao.create(this.event(2000, "microsoft", "CRITICAL"));

    this.storage.init(this.memorySource("local"), authSource);

    List<ProtectionEvent> recent = this.storage.recent(10);
    assertEquals(2, recent.size());
    assertEquals("microsoft", recent.get(0).getNickname());
    assertFalse(authDao.isTableExists(), "the PROTECTION_EVENTS table must be dropped from the auth database");
  }

  @Test
  void migrationSkipsRowsAlreadyPresentAndMissingTable() throws Exception {
    // First bind: no legacy table at all - nothing to migrate, nothing to fail on.
    ConnectionSource local = this.memorySource("local");
    ConnectionSource authSource = this.memorySource("auth");
    this.storage.init(local, authSource);
    this.storage.store(this.event(1000, "finsterry", "HIGH"));

    // A crash-between-copy-and-drop shape: the auth database still has one row that
    // already made it into the local store, plus one that did not.
    Dao<ProtectionEvent, Long> authDao = this.createLegacyTable(authSource);
    authDao.create(this.event(1000, "finsterry", "HIGH"));
    authDao.create(this.event(2000, "microsoft", "CRITICAL"));

    // Rebind (same in-memory local database through a fresh source, like a reload).
    this.storage.init(this.memorySource("local"), authSource);

    List<ProtectionEvent> recent = this.storage.recent(10);
    assertEquals(2, recent.size(), "the duplicate row must not be copied twice");
    assertTrue(recent.stream().anyMatch(event -> event.getNickname().equals("microsoft")));
    assertFalse(authDao.isTableExists());
  }

  /**
   * The production boot crash: binding to a local database whose table already has
   * every column must be a no-op, not an attempt to re-add existing columns. (The old
   * wiring borrowed LimboAuth#migrateDb, whose column discovery is keyed to the MAIN
   * database engine and finds nothing on H2 when the main engine is MySQL.)
   */
  @Test
  void rebindingToAnExistingCompleteTableDoesNotReAddColumns() throws Exception {
    this.storage.init(this.memorySource("local"), null);
    this.storage.store(this.event(1000, "finsterry", "HIGH"));

    this.storage.init(this.memorySource("local"), null);

    assertEquals(1, this.storage.recent(10).size(), "the rebind must reuse the intact table");
  }

  @Test
  void missingColumnIsAddedOnUpgrade() throws Exception {
    // An older-schema table: a future version added the ASN column.
    ConnectionSource local = this.memorySource("local");
    Dao<ProtectionEvent, Long> dao = DaoManager.createDao(local, ProtectionEvent.class);
    TableUtils.createTableIfNotExists(local, ProtectionEvent.class);
    dao.executeRawNoArgs("ALTER TABLE PROTECTION_EVENTS DROP COLUMN " + ProtectionEvent.ASN_FIELD);

    this.storage.init(this.memorySource("local"), null);
    this.storage.store(this.event(1000, "finsterry", "HIGH"));

    assertEquals(1, this.storage.recent(10).size(), "the store must work after the column was re-added");
  }

  /**
   * An in-memory H2 database that survives pooled connections closing. The name is
   * unique per test (fresh instance per method), while calling this twice with the same
   * name inside one test re-opens the same database - modelling a reload rebind.
   */
  private ConnectionSource memorySource(String name) throws Exception {
    return new JdbcPooledConnectionSource("jdbc:h2:mem:protection-" + name + "-" + this.dbId + ";DB_CLOSE_DELAY=-1");
  }

  private Dao<ProtectionEvent, Long> createLegacyTable(ConnectionSource authSource) throws Exception {
    TableUtils.createTableIfNotExists(authSource, ProtectionEvent.class);
    return DaoManager.createDao(authSource, ProtectionEvent.class);
  }

  private ProtectionEvent event(long time, String nickname, String severity) {
    return new ProtectionEvent(time, severity, 50, nickname, "203.0.113.7", "203.0.113.0/24",
        "LOGIN_SUCCESS", "[]", "vanilla", null, null);
  }
}
