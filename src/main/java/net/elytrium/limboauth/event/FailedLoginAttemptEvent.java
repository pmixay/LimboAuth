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

package net.elytrium.limboauth.event;

import com.velocitypowered.api.proxy.Player;
import net.elytrium.limboauth.model.RegisteredPlayer;

/**
 * Fired whenever a registered player enters a wrong password in the auth limbo.
 */
public class FailedLoginAttemptEvent {

  private final Player player;
  private final RegisteredPlayer playerInfo;
  private final int attemptsLeft;

  public FailedLoginAttemptEvent(Player player, RegisteredPlayer playerInfo, int attemptsLeft) {
    this.player = player;
    this.playerInfo = playerInfo;
    this.attemptsLeft = attemptsLeft;
  }

  public Player getPlayer() {
    return this.player;
  }

  public RegisteredPlayer getPlayerInfo() {
    return this.playerInfo;
  }

  public int getAttemptsLeft() {
    return this.attemptsLeft;
  }
}
