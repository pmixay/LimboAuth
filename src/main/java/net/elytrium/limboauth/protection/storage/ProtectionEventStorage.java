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
import com.j256.ormlite.stmt.DeleteBuilder;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.slf4j.Logger;

public class ProtectionEventStorage {

  private final Logger logger;

  private volatile Dao<ProtectionEvent, Long> dao;

  public ProtectionEventStorage(Logger logger) {
    this.logger = logger;
  }

  /**
   * (Re)binds the storage to the current connection source. Follows the same
   * table-creation pattern as the AUTH table, including the CREATE INDEX guard
   * and the automatic column migration for future upgrades.
   */
  public void init(ConnectionSource connectionSource, Consumer<Dao<?, ?>> migrator) throws Exception {
    try {
      TableUtils.createTableIfNotExists(connectionSource, ProtectionEvent.class);
    } catch (Exception e) {
      if (e.getMessage() == null || !e.getMessage().contains("CREATE INDEX")) {
        throw e;
      }
    }

    Dao<ProtectionEvent, Long> createdDao = DaoManager.createDao(connectionSource, ProtectionEvent.class);
    migrator.accept(createdDao);
    this.dao = createdDao;
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
