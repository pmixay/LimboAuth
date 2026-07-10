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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.jdbc.JdbcConnectionSource;
import net.elytrium.limboauth.model.RegisteredPlayer;
import net.elytrium.limboauth.protection.TestSettings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class SocialLinkResolverTest {

  @BeforeAll
  static void loadSettings() {
    TestSettings.load();
  }

  @Test
  void detectsStockSocialAddonTable() throws Exception {
    try (JdbcConnectionSource connectionSource = new JdbcConnectionSource("jdbc:h2:mem:social-present")) {
      Dao<RegisteredPlayer, String> dao = DaoManager.createDao(connectionSource, RegisteredPlayer.class);
      dao.executeRawNoArgs("CREATE TABLE SOCIAL (LOWERCASENICKNAME VARCHAR(255) PRIMARY KEY, "
          + "VK_ID BIGINT, TELEGRAM_ID BIGINT, DISCORD_ID BIGINT, BLOCKED BOOLEAN, TOTP_ENABLED BOOLEAN, NOTIFY_ENABLED BOOLEAN)");
      dao.executeRawNoArgs("INSERT INTO SOCIAL VALUES ('linked_tg', NULL, 123456789, NULL, FALSE, FALSE, TRUE)");
      dao.executeRawNoArgs("INSERT INTO SOCIAL VALUES ('linked_ds', NULL, NULL, 987654321, FALSE, FALSE, TRUE)");
      dao.executeRawNoArgs("INSERT INTO SOCIAL VALUES ('row_no_links', NULL, NULL, NULL, FALSE, FALSE, TRUE)");

      SocialLinkResolver resolver = new SocialLinkResolver(LoggerFactory.getLogger("test"));
      resolver.reload(dao);

      assertTrue(resolver.getStatusSummary().startsWith("active"), resolver.getStatusSummary());
      assertTrue(resolver.isLinked("linked_tg"));
      assertTrue(resolver.isLinked("linked_ds"));
      assertFalse(resolver.isLinked("row_no_links"));
      assertFalse(resolver.isLinked("never_seen"));

      // Second lookup hits the cache.
      assertTrue(resolver.isLinked("linked_tg"));
      assertTrue(resolver.getCacheSize() > 0);
    }
  }

  @Test
  void missingTableTreatsEveryoneAsUnlinked() throws Exception {
    try (JdbcConnectionSource connectionSource = new JdbcConnectionSource("jdbc:h2:mem:social-absent")) {
      Dao<RegisteredPlayer, String> dao = DaoManager.createDao(connectionSource, RegisteredPlayer.class);

      SocialLinkResolver resolver = new SocialLinkResolver(LoggerFactory.getLogger("test"));
      resolver.reload(dao);

      assertTrue(resolver.getStatusSummary().contains("not found"), resolver.getStatusSummary());
      assertFalse(resolver.isLinked("anyone"));
    }
  }

  @Test
  void partialColumnsStillWork() throws Exception {
    try (JdbcConnectionSource connectionSource = new JdbcConnectionSource("jdbc:h2:mem:social-partial")) {
      Dao<RegisteredPlayer, String> dao = DaoManager.createDao(connectionSource, RegisteredPlayer.class);
      // Only one of the configured link columns exists.
      dao.executeRawNoArgs("CREATE TABLE SOCIAL (LOWERCASENICKNAME VARCHAR(255) PRIMARY KEY, DISCORD_ID BIGINT)");
      dao.executeRawNoArgs("INSERT INTO SOCIAL VALUES ('linked_ds', 42)");

      SocialLinkResolver resolver = new SocialLinkResolver(LoggerFactory.getLogger("test"));
      resolver.reload(dao);

      assertTrue(resolver.isLinked("linked_ds"));
      assertFalse(resolver.isLinked("someone_else"));
    }
  }
}
