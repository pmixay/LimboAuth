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

package net.elytrium.limboauth.protection.social;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.GenericRawResults;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import net.elytrium.limboauth.Settings;
import net.elytrium.limboauth.dependencies.DatabaseLibrary;
import org.slf4j.Logger;

/**
 * Resolves whether a player has a linked social account via the LimboAuth-SocialAddon
 * table living in the same database. The table and its columns are auto-detected at
 * startup; when absent, every player is treated as unlinked (and therefore watched).
 */
public class SocialLinkResolver {

  private static final Pattern SAFE_IDENTIFIER = Pattern.compile("^[A-Za-z0-9_]+$");
  private static final long ERROR_LOG_INTERVAL_MILLIS = 60000;

  private final Logger logger;
  private final Map<String, CachedLink> cache = new ConcurrentHashMap<>();

  private volatile Dao<?, ?> queryDao;
  private volatile String querySql;
  private volatile String statusSummary = "not initialized";
  private volatile long lastErrorLog;

  public SocialLinkResolver(Logger logger) {
    this.logger = logger;
  }

  public void reload(Dao<?, ?> dao) {
    this.cache.clear();
    this.queryDao = dao;
    this.querySql = null;

    Settings.PROTECTION.SOCIAL config = Settings.IMP.PROTECTION.SOCIAL;
    if (!config.ENABLED) {
      this.statusSummary = "disabled in config";
      return;
    }

    if (!SAFE_IDENTIFIER.matcher(config.TABLE_NAME).matches() || !SAFE_IDENTIFIER.matcher(config.NICKNAME_COLUMN).matches()
        || config.LINK_COLUMNS.stream().anyMatch(column -> !SAFE_IDENTIFIER.matcher(column).matches())) {
      this.statusSummary = "invalid table/column names in config";
      this.logger.warn("Social exemption disabled: table/column names may only contain letters, digits and underscores.");
      return;
    }

    try {
      DetectedTable detected = this.detectTable(dao, config.TABLE_NAME);
      if (detected == null) {
        this.statusSummary = "table '" + config.TABLE_NAME + "' not found - all players treated as unlinked";
        this.logger.info("Social table '{}' not found - all players are treated as unlinked and protected by detection.", config.TABLE_NAME);
        return;
      }

      String nicknameColumn = detected.columns().get(config.NICKNAME_COLUMN.toUpperCase(Locale.ROOT));
      List<String> linkColumns = new ArrayList<>();
      for (String configured : config.LINK_COLUMNS) {
        String actual = detected.columns().get(configured.toUpperCase(Locale.ROOT));
        if (actual != null) {
          linkColumns.add(actual);
        }
      }

      if (nicknameColumn == null || linkColumns.isEmpty()) {
        this.statusSummary = "table found but expected columns are missing - all players treated as unlinked";
        this.logger.warn("Social table '{}' found, but the nickname column or all link columns are missing - social exemption inactive.",
            config.TABLE_NAME);
        return;
      }

      boolean quote = Settings.IMP.DATABASE.STORAGE_TYPE == DatabaseLibrary.POSTGRESQL;
      StringBuilder builder = new StringBuilder("SELECT ");
      for (int i = 0; i < linkColumns.size(); ++i) {
        if (i > 0) {
          builder.append(", ");
        }

        this.appendIdentifier(builder, linkColumns.get(i), quote);
      }

      builder.append(" FROM ");
      this.appendIdentifier(builder, detected.tableName(), quote);
      builder.append(" WHERE ");
      this.appendIdentifier(builder, nicknameColumn, quote);
      builder.append(" = ?");

      this.querySql = builder.toString();
      this.statusSummary = "active (table '" + config.TABLE_NAME + "', link columns: " + String.join(", ", linkColumns) + ")";
      this.logger.info("Social table '{}' found (link columns: {}) - players with a linked social account are exempt from detection.",
          config.TABLE_NAME, String.join(", ", linkColumns));
    } catch (Exception e) {
      this.statusSummary = "detection failed: " + e.getMessage();
      this.logger.warn("Failed to detect the social addon table - all players are treated as unlinked.", e);
    }
  }

  public boolean isLinked(String lowercaseNickname) {
    String sql = this.querySql;
    Dao<?, ?> dao = this.queryDao;
    if (sql == null || dao == null) {
      return false;
    }

    long now = System.currentTimeMillis();
    CachedLink cached = this.cache.get(lowercaseNickname);
    if (cached != null && cached.checkTime() + Settings.IMP.PROTECTION.SOCIAL.CACHE_TTL_MILLIS > now) {
      return cached.linked();
    }

    boolean linked = false;
    try (GenericRawResults<String[]> results = dao.queryRaw(sql, lowercaseNickname)) {
      String[] row = results.getFirstResult();
      if (row != null) {
        for (String value : row) {
          if (value != null && !value.isEmpty()) {
            linked = true;
            break;
          }
        }
      }
    } catch (Exception e) {
      // Fail open for detection: treat the player as unlinked so monitoring continues.
      if (now - this.lastErrorLog > ERROR_LOG_INTERVAL_MILLIS) {
        this.lastErrorLog = now;
        this.logger.warn("Social link lookup failed, treating players as unlinked", e);
      }

      return false;
    }

    this.cache.put(lowercaseNickname, new CachedLink(now, linked));
    return linked;
  }

  public void purgeCache(long now) {
    long ttl = Settings.IMP.PROTECTION.SOCIAL.CACHE_TTL_MILLIS;
    this.cache.values().removeIf(cached -> cached.checkTime() + ttl <= now);
  }

  public String getStatusSummary() {
    return this.statusSummary;
  }

  public int getCacheSize() {
    return this.cache.size();
  }

  /**
   * Detects the social table (matched case-insensitively) and returns its actual stored
   * name plus a map of UPPERCASE column name to the column name as stored by the database,
   * using the same per-backend introspection as {@code LimboAuth#migrateDb}.
   */
  private DetectedTable detectTable(Dao<?, ?> dao, String tableName) throws Exception {
    String database = Settings.IMP.DATABASE.DATABASE;
    String findSql;
    boolean includesTableName = true;
    switch (Settings.IMP.DATABASE.STORAGE_TYPE) {
      case SQLITE: {
        // SQLite identifiers are case-insensitive, so the configured name can be used as-is.
        findSql = "SELECT name FROM PRAGMA_TABLE_INFO('" + tableName + "')";
        includesTableName = false;
        break;
      }
      case H2: {
        findSql = "SELECT COLUMN_NAME, TABLE_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE UPPER(TABLE_NAME) = UPPER('" + tableName + "')";
        break;
      }
      case POSTGRESQL: {
        findSql = "SELECT COLUMN_NAME, TABLE_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_CATALOG = '" + database
            + "' AND UPPER(TABLE_NAME) = UPPER('" + tableName + "')";
        break;
      }
      case MARIADB:
      case MYSQL: {
        findSql = "SELECT COLUMN_NAME, TABLE_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = '" + database
            + "' AND UPPER(TABLE_NAME) = UPPER('" + tableName + "')";
        break;
      }
      default: {
        return null;
      }
    }

    Map<String, String> columns = new LinkedHashMap<>();
    String actualTableName = tableName;
    try (GenericRawResults<String[]> results = dao.queryRaw(findSql)) {
      for (String[] row : results) {
        columns.put(row[0].toUpperCase(Locale.ROOT), row[0]);
        if (includesTableName) {
          actualTableName = row[1];
        }
      }
    }

    return columns.isEmpty() ? null : new DetectedTable(actualTableName, columns);
  }

  private record DetectedTable(String tableName, Map<String, String> columns) {
  }

  private void appendIdentifier(StringBuilder builder, String identifier, boolean quote) {
    if (quote) {
      builder.append('"').append(identifier).append('"');
    } else {
      builder.append(identifier);
    }
  }

  private record CachedLink(long checkTime, boolean linked) {
  }
}
