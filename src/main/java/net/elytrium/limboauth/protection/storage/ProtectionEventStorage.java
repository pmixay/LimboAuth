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

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.dao.GenericRawResults;
import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.stmt.DeleteBuilder;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.elytrium.limboauth.dependencies.DatabaseLibrary;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.slf4j.Logger;

/**
 * PROTECTION_EVENTS storage in a plugin-local H2 database, deliberately separate from
 * the auth database: detection telemetry stays out of the (possibly shared, possibly
 * remote) main DB, and its writes never compete with auth queries. Rows an older
 * version stored in the auth database are migrated over once and the old table is
 * dropped there.
 */
public class ProtectionEventStorage {

  private final Logger logger;

  private volatile ConnectionSource localSource;
  private volatile Dao<ProtectionEvent, Long> dao;

  public ProtectionEventStorage(Logger logger) {
    this.logger = logger;
  }

  /**
   * Local connection source for the event store: an H2 file next to the plugin config
   * ({@code protection-events-v2.mv.db}), whatever engine the auth database uses.
   */
  public static ConnectionSource openLocal(Path dataDirectory) throws Exception {
    return DatabaseLibrary.H2.connectToORM("jdbc:h2:" + dataDirectory.toAbsolutePath().resolve("protection-events-v2"), null, null);
  }

  /**
   * (Re)binds the storage to a local connection source (closing the previous one) and,
   * when the auth database still holds a PROTECTION_EVENTS table from an older version,
   * migrates its rows into the local store and drops the old table. Table creation
   * follows the same pattern as the AUTH table, including the CREATE INDEX guard and
   * an automatic column migration for future upgrades - a local, H2-specific one:
   * LimboAuth#migrateDb discovers existing columns with SQL chosen by the MAIN
   * database's engine and therefore must never be pointed at this store (doing so is
   * what once made a MySQL-main server re-add every column on boot).
   */
  public void init(ConnectionSource local, @Nullable ConnectionSource legacySource) throws Exception {
    this.close();

    try {
      TableUtils.createTableIfNotExists(local, ProtectionEvent.class);
    } catch (Exception e) {
      if (e.getMessage() == null || !e.getMessage().contains("CREATE INDEX")) {
        throw e;
      }
    }

    Dao<ProtectionEvent, Long> createdDao = DaoManager.createDao(local, ProtectionEvent.class);
    this.migrateColumns(createdDao);
    this.localSource = local;
    this.dao = createdDao;

    if (legacySource != null) {
      this.migrateLegacyRows(createdDao, legacySource);
    }
  }

  /**
   * Adds columns a future version introduces to an existing local table. The discovery
   * query is H2's - the local store is H2 by construction, whatever engine the auth
   * database runs on.
   */
  private void migrateColumns(Dao<ProtectionEvent, Long> localDao) throws Exception {
    Set<FieldType> missing = new HashSet<>();
    Collections.addAll(missing, localDao.getTableInfo().getFieldTypes());
    try (GenericRawResults<String[]> columns = localDao.queryRaw(
        "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'PROTECTION_EVENTS'")) {
      columns.forEach(row -> missing.removeIf(field -> field.getColumnName().equalsIgnoreCase(row[0])));
    }

    for (FieldType field : missing) {
      StringBuilder builder = new StringBuilder("ALTER TABLE PROTECTION_EVENTS ADD ");
      List<String> dummy = new ArrayList<>();
      localDao.getConnectionSource().getDatabaseType().appendColumnArg(field.getTableName(), builder, field, dummy, dummy, dummy, dummy);
      localDao.executeRawNoArgs(builder.toString());
      this.logger.info("Added the {} column to the local protection events store.", field.getColumnName());
    }
  }

  public void close() {
    ConnectionSource current = this.localSource;
    this.localSource = null;
    this.dao = null;
    if (current != null) {
      current.closeQuietly();
    }
  }

  /**
   * One-way move of rows an older version stored in the auth database. Idempotent:
   * rows already present locally (same event time + nickname, e.g. after a crash
   * between copy and drop) are not duplicated, and the old table is only dropped after
   * the copy completed. A failure leaves the auth database untouched and is retried on
   * the next start.
   */
  private void migrateLegacyRows(Dao<ProtectionEvent, Long> localDao, ConnectionSource legacySource) {
    try {
      Dao<ProtectionEvent, Long> legacyDao = DaoManager.createDao(legacySource, ProtectionEvent.class);
      if (!legacyDao.isTableExists()) {
        return;
      }

      Set<String> present = new HashSet<>();
      for (ProtectionEvent event : localDao.queryBuilder()
          .selectColumns(ProtectionEvent.EVENT_TIME_FIELD, ProtectionEvent.NICKNAME_FIELD).query()) {
        present.add(event.getEventTime() + ":" + event.getNickname());
      }

      long copied = 0;
      long skipped = 0;
      for (ProtectionEvent event : legacyDao.queryForAll()) {
        if (present.contains(event.getEventTime() + ":" + event.getNickname())) {
          ++skipped;
          continue;
        }

        // Rebuilt without the generated ID so the local store assigns its own.
        localDao.create(new ProtectionEvent(event.getEventTime(), event.getSeverity(), event.getScore(), event.getNickname(),
            event.getIp(), event.getSubnet(), event.getOutcome(), event.getFactors(), event.getClientBrand(),
            event.getCountry(), event.getAsn()));
        ++copied;
      }

      // Not TableUtils.dropTable: it first emits bare "DROP INDEX <name>" statements,
      // which MySQL/MariaDB reject (they need "... ON <table>"). A plain DROP TABLE
      // removes the indexes together with the table on every supported engine.
      StringBuilder dropTable = new StringBuilder("DROP TABLE ");
      legacySource.getDatabaseType().appendEscapedEntityName(dropTable, legacyDao.getTableInfo().getTableName());
      legacyDao.executeRawNoArgs(dropTable.toString());
      this.logger.info("Moved {} protection events from the auth database into the local store"
          + "{} and dropped the old PROTECTION_EVENTS table.", copied, skipped == 0 ? "" : " (" + skipped + " already present)");
    } catch (Exception e) {
      this.logger.warn("Failed to migrate protection events out of the auth database; "
          + "the old table is left in place and the migration will be retried on the next start.", e);
    }
  }

  public void store(ProtectionEvent event) {
    Dao<ProtectionEvent, Long> currentDao = this.dao;
    if (currentDao == null) {
      return;
    }

    try {
      currentDao.create(event);
    } catch (Exception e) {
      this.logger.warn("Failed to store protection event", e);
    }
  }

  public List<ProtectionEvent> recent(int limit) throws Exception {
    Dao<ProtectionEvent, Long> currentDao = this.dao;
    if (currentDao == null) {
      return List.of();
    }

    return currentDao.queryBuilder()
        .orderBy(ProtectionEvent.EVENT_TIME_FIELD, false)
        .limit((long) limit)
        .query();
  }

  /**
   * Newest-first events for one nickname, so an admin can see WHY an account was scored
   * without grepping the server log. The nickname column is indexed.
   */
  public List<ProtectionEvent> recentForNickname(String lowercaseNickname, int limit) throws Exception {
    Dao<ProtectionEvent, Long> currentDao = this.dao;
    if (currentDao == null) {
      return List.of();
    }

    return currentDao.queryBuilder()
        .orderBy(ProtectionEvent.EVENT_TIME_FIELD, false)
        .limit((long) limit)
        .where().eq(ProtectionEvent.NICKNAME_FIELD, lowercaseNickname)
        .query();
  }

  public Map<String, Long> severityCountsSince(long sinceTime) throws Exception {
    Dao<ProtectionEvent, Long> currentDao = this.dao;
    Map<String, Long> counts = new LinkedHashMap<>();
    if (currentDao == null) {
      return counts;
    }

    try (GenericRawResults<String[]> results = currentDao.queryRaw(
        "SELECT " + ProtectionEvent.SEVERITY_FIELD + ", COUNT(*) FROM PROTECTION_EVENTS WHERE "
            + ProtectionEvent.EVENT_TIME_FIELD + " >= " + sinceTime + " GROUP BY " + ProtectionEvent.SEVERITY_FIELD)) {
      for (String[] row : results) {
        counts.put(row[0], Long.parseLong(row[1]));
      }
    }

    return counts;
  }

  public long purgeOlderThan(long minTime) {
    Dao<ProtectionEvent, Long> currentDao = this.dao;
    if (currentDao == null) {
      return 0;
    }

    try {
      DeleteBuilder<ProtectionEvent, Long> deleteBuilder = currentDao.deleteBuilder();
      deleteBuilder.where().lt(ProtectionEvent.EVENT_TIME_FIELD, minTime);
      return deleteBuilder.delete();
    } catch (Exception e) {
      this.logger.warn("Failed to purge old protection events", e);
      return 0;
    }
  }
}
