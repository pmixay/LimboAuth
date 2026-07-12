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

package net.elytrium.limboauth;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import net.elytrium.commons.config.ConfigSerializer;
import net.elytrium.commons.config.YamlConfig;
import net.elytrium.commons.kyori.serialization.Serializers;
import net.elytrium.limboapi.api.chunk.Dimension;
import net.elytrium.limboapi.api.file.BuiltInWorldFileType;
import net.elytrium.limboapi.api.player.GameMode;
import net.elytrium.limboauth.command.CommandPermissionState;
import net.elytrium.limboauth.dependencies.DatabaseLibrary;
import net.elytrium.limboauth.migration.MigrationHash;
import net.kyori.adventure.bossbar.BossBar;
import net.kyori.adventure.title.Title;
import net.kyori.adventure.util.Ticks;

public class Settings extends YamlConfig {

  @Ignore
  public static final Settings IMP = new Settings();

  @Final
  public String VERSION = BuildConstants.AUTH_VERSION;

  @Comment({
      "Available serializers:",
      "LEGACY_AMPERSAND - \"&c&lExample &c&9Text\".",
      "LEGACY_SECTION - \"§c§lExample §c§9Text\".",
      "MINIMESSAGE - \"<bold><red>Example</red> <blue>Text</blue></bold>\". (https://webui.adventure.kyori.net/)",
      "GSON - \"[{\"text\":\"Example\",\"bold\":true,\"color\":\"red\"},{\"text\":\" \",\"bold\":true},{\"text\":\"Text\",\"bold\":true,\"color\":\"blue\"}]\". (https://minecraft.tools/en/json_text.php/)",
      "GSON_COLOR_DOWNSAMPLING - Same as GSON, but uses downsampling."
  })
  public Serializers SERIALIZER = Serializers.LEGACY_AMPERSAND;
  public String PREFIX = "LimboAuth &6>>&f";

  @Create
  public MAIN MAIN;

  @Comment("Don't use \\n, use {NL} for new line, and {PRFX} for prefix.")
  public static class MAIN {

    @Comment("Maximum time for player to authenticate in milliseconds. If the player stays on the auth limbo for longer than this time, then the player will be kicked.")
    public int AUTH_TIME = 60000;
    public boolean ENABLE_BOSSBAR = true;
    @Comment("Available colors: PINK, BLUE, RED, GREEN, YELLOW, PURPLE, WHITE")
    public BossBar.Color BOSSBAR_COLOR = BossBar.Color.RED;
    @Comment("Available overlays: PROGRESS, NOTCHED_6, NOTCHED_10, NOTCHED_12, NOTCHED_20")
    public BossBar.Overlay BOSSBAR_OVERLAY = BossBar.Overlay.NOTCHED_20;
    public int MIN_PASSWORD_LENGTH = 4;
    @Comment("Max password length for the BCrypt hashing algorithm, which is used in this plugin, can't be higher than 71. You can set a lower value than 71.")
    public int MAX_PASSWORD_LENGTH = 71;
    public boolean CHECK_PASSWORD_STRENGTH = true;
    public String UNSAFE_PASSWORDS_FILE = "unsafe_passwords.txt";
    @Comment({
        "Players with premium nicknames should register/auth if this option is enabled",
        "Players with premium nicknames must login with a premium Minecraft account if this option is disabled",
    })
    public boolean ONLINE_MODE_NEED_AUTH = true;
    @Comment({
        "WARNING: its experimental feature, so disable only if you really know what you are doing",
        "When enabled, this option will keep default 'online-mode-need-auth' behavior",
        "When disabled, this option will disable premium authentication for unregistered players if they fail it once,",
        "allowing offline-mode players to use online-mode usernames",
        "Does nothing when enabled, but when disabled require 'save-premium-accounts: true', 'online-mode-need-auth: false' and 'purge_premium_cache_millis > 100000'"
    })
    public boolean ONLINE_MODE_NEED_AUTH_STRICT = true;
    @Comment("Needs floodgate plugin if disabled.")
    public boolean FLOODGATE_NEED_AUTH = true;
    @Comment("TOTALLY disables hybrid auth feature")
    public boolean FORCE_OFFLINE_MODE = false;
    @Comment("Forces all players to get offline uuid")
    public boolean FORCE_OFFLINE_UUID = false;
    @Comment("If enabled, the plugin will firstly check whether the player is premium through the local database, and secondly through Mojang API.")
    public boolean CHECK_PREMIUM_PRIORITY_INTERNAL = true;
    @Comment("Delay in milliseconds before sending auth-confirming titles and messages to the player. (login-premium-title, login-floodgate, etc.)")
    public int PREMIUM_AND_FLOODGATE_MESSAGES_DELAY = 1250;
    @Comment({
        "Forcibly set player's UUID to the value from the database",
        "If the player had the cracked account, and switched to the premium account, the cracked UUID will be used."
    })
    public boolean SAVE_UUID = true;
    @Comment({
        "Saves in the database the accounts of premium users whose login is via online-mode-need-auth: false",
        "Can be disabled to reduce the size of stored data in the database"
    })
    public boolean SAVE_PREMIUM_ACCOUNTS = true;
    public boolean ENABLE_TOTP = true;
    public boolean TOTP_NEED_PASSWORD = true;
    public boolean REGISTER_NEED_REPEAT_PASSWORD = true;
    public boolean CHANGE_PASSWORD_NEED_OLD_PASSWORD = true;
    @Comment("Used in unregister and premium commands.")
    public String CONFIRM_KEYWORD = "confirm";
    @Comment("This prefix will be added to offline mode players nickname")
    public String OFFLINE_MODE_PREFIX = "";
    @Comment("This prefix will be added to online mode players nickname")
    public String ONLINE_MODE_PREFIX = "";
    @Comment({
        "If you want to migrate your database from another plugin, which is not using BCrypt.",
        "You can set an old hash algorithm to migrate from.",
        "AUTHME - AuthMe SHA256(SHA256(password) + salt) that looks like $SHA$salt$hash (AuthMe, MoonVKAuth, DSKAuth, DBA)",
        "AUTHME_NP - AuthMe SHA256(SHA256(password) + salt) that looks like SHA$salt$hash (JPremium)",
        "SHA256_NP - SHA256(password) that looks like SHA$salt$hash",
        "SHA256_P - SHA256(password) that looks like $SHA$salt$hash",
        "SHA512_NP - SHA512(password) that looks like SHA$salt$hash",
        "SHA512_P - SHA512(password) that looks like $SHA$salt$hash",
        "SHA512_DBA - DBA plugin SHA512(SHA512(password) + salt) that looks like SHA$salt$hash (DBA, JPremium)",
        "MD5 - Basic md5 hash",
        "ARGON2 - Argon2 hash that looks like $argon2i$v=1234$m=1234,t=1234,p=1234$hash",
        "MOON_SHA256 - Moon SHA256(SHA256(password)) that looks like $SHA$hash (no salt)",
        "SHA256_NO_SALT - SHA256(password) that looks like $SHA$hash (NexAuth)",
        "SHA512_NO_SALT - SHA512(password) that looks like $SHA$hash (NexAuth)",
        "SHA512_P_REVERSED_HASH - SHA512(password) that looks like $SHA$hash$salt (nLogin)",
        "SHA512_NLOGIN - SHA512(SHA512(password) + salt) that looks like $SHA$hash$salt (nLogin)",
        "CRC32C - Basic CRC32C hash",
        "PLAINTEXT - Plain text",
    })
    public MigrationHash MIGRATION_HASH = MigrationHash.AUTHME;
    @Comment("Available dimensions: OVERWORLD, NETHER, THE_END")
    public Dimension DIMENSION = Dimension.THE_END;
    public long PURGE_CACHE_MILLIS = 3600000;
    public long PURGE_PREMIUM_CACHE_MILLIS = 28800000;
    public long PURGE_BRUTEFORCE_CACHE_MILLIS = 28800000;
    @Comment("Used to ban IPs when a possible attacker incorrectly enters the password")
    public int BRUTEFORCE_MAX_ATTEMPTS = 10;
    @Comment("QR Generator URL, set {data} placeholder")
    public String QR_GENERATOR_URL = "https://api.qrserver.com/v1/create-qr-code/?data={data}&size=200x200&ecc=M&margin=30";
    public String TOTP_ISSUER = "LimboAuth by Elytrium";
    public int BCRYPT_COST = 10;
    public int LOGIN_ATTEMPTS = 3;
    public int IP_LIMIT_REGISTRATIONS = 3;
    public int TOTP_RECOVERY_CODES_AMOUNT = 16;
    @Comment("Time in milliseconds, when ip limit works, set to 0 for disable.")
    public long IP_LIMIT_VALID_TIME = 21600000;
    @Comment({
        "Regex of allowed nicknames",
        "^ means the start of the line, $ means the end of the line",
        "[A-Za-z0-9_] is a character set of A-Z, a-z, 0-9 and _",
        "{3,16} means that allowed length is from 3 to 16 chars"
    })
    public String ALLOWED_NICKNAME_REGEX = "^[A-Za-z0-9_]{3,16}$";

    public boolean LOAD_WORLD = false;
    @Comment({
        "World file type:",
        " SCHEMATIC (MCEdit .schematic, 1.12.2 and lower, not recommended)",
        " STRUCTURE (structure block .nbt, any Minecraft version is supported, but the latest one is recommended).",
        " WORLDEDIT_SCHEM (WorldEdit .schem, any Minecraft version is supported, but the latest one is recommended)."
    })
    public BuiltInWorldFileType WORLD_FILE_TYPE = BuiltInWorldFileType.STRUCTURE;
    public String WORLD_FILE_PATH = "world.nbt";
    public boolean DISABLE_FALLING = true;

    @Comment("World time in ticks (24000 ticks == 1 in-game day)")
    public long WORLD_TICKS = 1000L;

    @Comment("World light level (from 0 to 15)")
    public int WORLD_LIGHT_LEVEL = 15;

    @Comment("Available: ADVENTURE, CREATIVE, SURVIVAL, SPECTATOR")
    public GameMode GAME_MODE = GameMode.ADVENTURE;

    @Comment({
        "Custom isPremium URL",
        "You can use Mojang one's API (set by default)",
        "Or CloudFlare one's: https://api.ashcon.app/mojang/v2/user/%s",
        "Or use this code to make your own API: https://blog.cloudflare.com/minecraft-api-with-workers-coffeescript/",
        "Or implement your own API, it should just respond with HTTP code 200 (see parameters below) only if the player is premium"
    })
    public String ISPREMIUM_AUTH_URL = "https://api.mojang.com/users/profiles/minecraft/%s";

    @Comment({
        "Status codes (see the comment above)",
        "Responses with unlisted status codes will be identified as responses with a server error",
        "Set 200 if you use using Mojang or CloudFlare API"
    })
    public List<Integer> STATUS_CODE_USER_EXISTS = List.of(200);
    @Comment("Set 204 and 404 if you use Mojang API, 404 if you use CloudFlare API")
    public List<Integer> STATUS_CODE_USER_NOT_EXISTS = List.of(204, 404);
    @Comment("Set 429 if you use Mojang or CloudFlare API")
    public List<Integer> STATUS_CODE_RATE_LIMIT = List.of(429);

    @Comment({
        "Sample Mojang API exists response: {\"name\":\"hevav\",\"id\":\"9c7024b2a48746b3b3934f397ae5d70f\"}",
        "Sample CloudFlare API exists response: {\"uuid\":\"9c7024b2a48746b3b3934f397ae5d70f\",\"username\":\"hevav\", ...}",
        "",
        "Sample Mojang API not exists response (sometimes can be empty): {\"path\":\"/users/profiles/minecraft/someletters1234566\",\"errorMessage\":\"Couldn't find any profile with that name\"}",
        "Sample CloudFlare API not exists response: {\"code\":404,\"error\":\"Not Found\",\"reason\":\"No user with the name 'someletters123456' was found\"}",
        "",
        "Responses with an invalid scheme will be identified as responses with a server error",
        "Set this parameter to [], to disable JSON scheme validation"
    })
    public List<String> USER_EXISTS_JSON_VALIDATOR_FIELDS = List.of("name", "id");
    public String JSON_UUID_FIELD = "id";
    public List<String> USER_NOT_EXISTS_JSON_VALIDATOR_FIELDS = List.of();

    @Comment({
        "If Mojang rate-limits your server, we cannot determine if the player is premium or not",
        "This option allows you to choose whether every player will be defined as premium or as cracked while Mojang is rate-limiting the server",
        "True - as premium; False - as cracked"
    })
    public boolean ON_RATE_LIMIT_PREMIUM = true;

    @Comment({
        "If Mojang API is down, we cannot determine if the player is premium or not",
        "This option allows you to choose whether every player will be defined as premium or as cracked while Mojang API is unavailable",
        "True - as premium; False - as cracked"
    })
    public boolean ON_SERVER_ERROR_PREMIUM = true;

    public List<String> REGISTER_COMMAND = List.of("/r", "/reg", "/register");
    public List<String> LOGIN_COMMAND = List.of("/l", "/log", "/login");
    public List<String> TOTP_COMMAND = List.of("/2fa", "/totp");

    @Comment("New players will be kicked with registrations-disabled-kick message")
    public boolean DISABLE_REGISTRATIONS = false;

    @Create
    public Settings.MAIN.MOD MOD;

    @Comment({
        "Implement the automatic login using the plugin, the LimboAuth client mod and optionally using a custom launcher",
        "See https://github.com/Elytrium/LimboAuth-ClientMod"
    })
    public static class MOD {

      public boolean ENABLED = true;

      @Comment("Should the plugin forbid logging in without a mod")
      public boolean LOGIN_ONLY_BY_MOD = false;

      @Comment("The key must be the same in the plugin config and in the server hash issuer, if you use it")
      @CustomSerializer(serializerClass = MD5KeySerializer.class)
      public byte[] VERIFY_KEY = null;

    }

    @Create
    public Settings.MAIN.WORLD_COORDS WORLD_COORDS;

    public static class WORLD_COORDS {

      public int X = 0;
      public int Y = 0;
      public int Z = 0;
    }

    @Create
    public MAIN.AUTH_COORDS AUTH_COORDS;

    public static class AUTH_COORDS {

      public double X = 0;
      public double Y = 0;
      public double Z = 0;
      public double YAW = 0;
      public double PITCH = 0;
    }

    @Create
    public Settings.MAIN.CRACKED_TITLE_SETTINGS CRACKED_TITLE_SETTINGS;

    public static class CRACKED_TITLE_SETTINGS {

      public int FADE_IN = 10;
      public int STAY = 70;
      public int FADE_OUT = 20;
      public boolean CLEAR_AFTER_LOGIN = false;

      public Title.Times toTimes() {
        return Title.Times.times(Ticks.duration(this.FADE_IN), Ticks.duration(this.STAY), Ticks.duration(this.FADE_OUT));
      }
    }

    @Create
    public Settings.MAIN.PREMIUM_TITLE_SETTINGS PREMIUM_TITLE_SETTINGS;

    public static class PREMIUM_TITLE_SETTINGS {

      public int FADE_IN = 10;
      public int STAY = 70;
      public int FADE_OUT = 20;

      public Title.Times toTimes() {
        return Title.Times.times(Ticks.duration(this.FADE_IN), Ticks.duration(this.STAY), Ticks.duration(this.FADE_OUT));
      }
    }

    @Create
    public Settings.MAIN.BACKEND_API BACKEND_API;

    public static class BACKEND_API {

      @Comment({
          "Should backend API be enabled?",
          "Required for PlaceholderAPI expansion to work (https://github.com/UserNugget/LimboAuth-Expansion)"
      })
      public boolean ENABLED = false;

      @Comment("Backend API token")
      // Generated with a CSPRNG (~130 bits): this token authenticates the plugin's responses to backend servers.
      public String TOKEN = new BigInteger(130, new SecureRandom()).toString(36);

      @Comment({
          "Available endpoints:",
          " premium_state, hash, totp_token, login_date, reg_date, token_issued_at,",
          " uuid, premium_uuid, ip, login_ip, token_issued_at"
      })
      public List<String> ENABLED_ENDPOINTS = List.of(
          "premium_state", "login_date", "reg_date", "uuid", "premium_uuid", "token_issued_at"
      );
    }

    @Create
    public MAIN.COMMAND_PERMISSION_STATE COMMAND_PERMISSION_STATE;

    @Comment({
        "Available values: FALSE, TRUE, PERMISSION",
        " FALSE - the command will be disallowed",
        " TRUE - the command will be allowed if player has false permission state",
        " PERMISSION - the command will be allowed if player has true permission state"
    })
    public static class COMMAND_PERMISSION_STATE {
      @Comment("Permission: limboauth.commands.changepassword")
      public CommandPermissionState CHANGE_PASSWORD = CommandPermissionState.PERMISSION;
      @Comment("Permission: limboauth.commands.destroysession")
      public CommandPermissionState DESTROY_SESSION = CommandPermissionState.PERMISSION;
      @Comment("Permission: limboauth.commands.premium")
      public CommandPermissionState PREMIUM = CommandPermissionState.PERMISSION;
      @Comment("Permission: limboauth.commands.totp")
      public CommandPermissionState TOTP = CommandPermissionState.PERMISSION;
      @Comment("Permission: limboauth.commands.unregister")
      public CommandPermissionState UNREGISTER = CommandPermissionState.PERMISSION;

      @Comment("Permission: limboauth.admin.forcechangepassword")
      public CommandPermissionState FORCE_CHANGE_PASSWORD = CommandPermissionState.PERMISSION;
      @Comment("Permission: limboauth.admin.forceregister")
      public CommandPermissionState FORCE_REGISTER = CommandPermissionState.PERMISSION;
      @Comment("Permission: limboauth.admin.forcelogin")
      public CommandPermissionState FORCE_LOGIN = CommandPermissionState.PERMISSION;
      @Comment("Permission: limboauth.admin.forceunregister")
      public CommandPermissionState FORCE_UNREGISTER = CommandPermissionState.PERMISSION;
      @Comment("Permission: limboauth.admin.reload")
      public CommandPermissionState RELOAD = CommandPermissionState.PERMISSION;
      @Comment("Permission: limboauth.admin.protection")
      public CommandPermissionState PROTECTION = CommandPermissionState.PERMISSION;
      @Comment("Permission: limboauth.admin.help")
      public CommandPermissionState HELP = CommandPermissionState.TRUE;
    }

    /*
    @Create
    public Settings.MAIN.EVENTS_PRIORITIES EVENTS_PRIORITIES;

    @Comment("Available priorities: FIRST, EARLY, NORMAL, LATE, LAST")
    public static class EVENTS_PRIORITIES {

      public String PRE_LOGIN = "NORMAL";
      public String LOGIN_LIMBO_REGISTER = "NORMAL";
      public String SAFE_GAME_PROFILE_REQUEST = "NORMAL";
    }
    */

    @Create
    public MAIN.STRINGS STRINGS;

    public static class STRINGS {

      public String RELOAD = "{PRFX} &aReloaded successfully!";
      public String ERROR_OCCURRED = "{PRFX} &cAn internal error has occurred!";
      public String RATELIMITED = "{PRFX} &cPlease wait before next usage!";
      public String DATABASE_ERROR_KICK = "{PRFX} &cA database error has occurred!";

      public String NOT_PLAYER = "{PRFX} &cСonsole is not allowed to execute this command!";
      public String NOT_REGISTERED = "{PRFX} &cYou are not registered or your account is &6PREMIUM!";
      public String CRACKED_COMMAND = "{PRFX}{NL}&aYou can not use this command since your account is &6PREMIUM&a!";
      public String WRONG_PASSWORD = "{PRFX} &cPassword is wrong!";

      public String NICKNAME_INVALID_KICK = "{PRFX}{NL}&cYour nickname contains forbidden characters. Please, change your nickname!";
      public String RECONNECT_KICK = "{PRFX}{NL}&cReconnect to the server to verify your account!";

      @Comment("6 hours by default in ip-limit-valid-time")
      public String IP_LIMIT_KICK = "{PRFX}{NL}{NL}&cYour IP has reached max registered accounts. If this is an error, restart your router, or wait about 6 hours.";
      public String WRONG_NICKNAME_CASE_KICK = "{PRFX}{NL}&cYou should join using username &6{0}&c, not &6{1}&c.";

      public String BOSSBAR = "{PRFX} You have &6{0} &fseconds left to log in.";
      public String TIMES_UP = "{PRFX}{NL}&cAuthorization time is up.";

      @Comment(value = "Can be empty.", at = Comment.At.SAME_LINE)
      public String LOGIN_PREMIUM = "{PRFX} You've been logged in automatically using the premium account!";
      @Comment(value = "Can be empty.", at = Comment.At.SAME_LINE)
      public String LOGIN_PREMIUM_TITLE = "{PRFX} Welcome!";
      @Comment(value = "Can be empty.", at = Comment.At.SAME_LINE)
      public String LOGIN_PREMIUM_SUBTITLE = "&aYou have been logged in as premium player!";
      @Comment(value = "Can be empty.", at = Comment.At.SAME_LINE)
      public String LOGIN_FLOODGATE = "{PRFX} You've been logged in automatically using the bedrock account!";
      @Comment(value = "Can be empty.", at = Comment.At.SAME_LINE)
      public String LOGIN_FLOODGATE_TITLE = "{PRFX} Welcome!";
      @Comment(value = "Can be empty.", at = Comment.At.SAME_LINE)
      public String LOGIN_FLOODGATE_SUBTITLE = "&aYou have been logged in as bedrock player!";

      public String LOGIN = "{PRFX} &aPlease, login using &6/login <password>&a, you have &6{0} &aattempts.";
      public String LOGIN_WRONG_PASSWORD = "{PRFX} &cYou''ve entered the wrong password, you have &6{0} &cattempts left.";
      public String LOGIN_WRONG_PASSWORD_KICK = "{PRFX}{NL}&cYou've entered the wrong password numerous times!";
      @Comment({
          "Kick screen used by the account protection enforcement (blocked source / kicked session).",
          "Deliberately identical to the wrong-password kick by default, so password checkers",
          "cannot tell that they were detected rather than simply wrong."
      })
      public String PROTECTION_KICK = "{PRFX}{NL}&cYou've entered the wrong password numerous times!";
      public String LOGIN_SUCCESSFUL = "{PRFX} &aSuccessfully logged in!";
      @Comment(value = "Can be empty.", at = Comment.At.SAME_LINE)
      public String LOGIN_TITLE = "&fPlease, login using &6/login <password>&a.";
      @Comment(value = "Can be empty.", at = Comment.At.SAME_LINE)
      public String LOGIN_SUBTITLE = "&aYou have &6{0} &aattempts.";
      @Comment(value = "Can be empty.", at = Comment.At.SAME_LINE)
      public String LOGIN_SUCCESSFUL_TITLE = "{PRFX}";
      @Comment(value = "Can be empty.", at = Comment.At.SAME_LINE)
      public String LOGIN_SUCCESSFUL_SUBTITLE = "&aSuccessfully logged in!";

      @Comment("Or if register-need-repeat-password set to false remove the \"<repeat password>\" part.")
      public String REGISTER = "{PRFX} Please, register using &6/register <password> <repeat password>";
      public String REGISTER_DIFFERENT_PASSWORDS = "{PRFX} &cThe entered passwords differ from each other!";
      public String REGISTER_PASSWORD_TOO_SHORT = "{PRFX} &cYou entered a too short password, use a different one!";
      public String REGISTER_PASSWORD_TOO_LONG = "{PRFX} &cYou entered a too long password, use a different one!";
      public String REGISTER_PASSWORD_UNSAFE = "{PRFX} &cYour password is unsafe, use a different one!";
      public String REGISTER_SUCCESSFUL = "{PRFX} &aSuccessfully registered!";
      @Comment(value = "Can be empty.", at = Comment.At.SAME_LINE)
      public String REGISTER_TITLE = "{PRFX}";
      @Comment(value = "Can be empty.", at = Comment.At.SAME_LINE)
      public String REGISTER_SUBTITLE = "&aPlease, register using &6/register <password> <repeat password>";
      @Comment(value = "Can be empty.", at = Comment.At.SAME_LINE)
      public String REGISTER_SUCCESSFUL_TITLE = "{PRFX}";
      @Comment(value = "Can be empty.", at = Comment.At.SAME_LINE)
      public String REGISTER_SUCCESSFUL_SUBTITLE = "&aSuccessfully registered!";

      public String UNREGISTER_SUCCESSFUL = "{PRFX}{NL}&aSuccessfully unregistered!";
      public String UNREGISTER_USAGE = "{PRFX} Usage: &6/unregister <current password> confirm";

      public String PREMIUM_SUCCESSFUL = "{PRFX}{NL}&aSuccessfully changed account state to &6PREMIUM&a!";
      public String ALREADY_PREMIUM = "{PRFX} &cYour account is already &6PREMIUM&c!";
      public String NOT_PREMIUM = "{PRFX} &cYour account is not &6PREMIUM&c!";
      public String PREMIUM_USAGE = "{PRFX} Usage: &6/premium <current password> confirm";

      public String EVENT_CANCELLED = "{PRFX} Authorization event was cancelled";

      public String FORCE_UNREGISTER_SUCCESSFUL = "{PRFX} &6{0} &asuccessfully unregistered!";
      public String FORCE_UNREGISTER_KICK = "{PRFX}{NL}&aYou have been unregistered by an administrator!";
      public String FORCE_UNREGISTER_NOT_SUCCESSFUL = "{PRFX} &cUnable to unregister &6{0}&c. Most likely this player has never been on this server.";
      public String FORCE_UNREGISTER_USAGE = "{PRFX} Usage: &6/forceunregister <nickname>";

      public String REGISTRATIONS_DISABLED_KICK = "{PRFX} Registrations are currently disabled.";

      public String CHANGE_PASSWORD_SUCCESSFUL = "{PRFX} &aSuccessfully changed password!";
      @Comment("Or if change-password-need-old-pass set to false remove the \"<old password>\" part.")
      public String CHANGE_PASSWORD_USAGE = "{PRFX} Usage: &6/changepassword <old password> <new password>";

      public String FORCE_CHANGE_PASSWORD_SUCCESSFUL = "{PRFX} &aSuccessfully changed password for player &6{0}&a!";
      public String FORCE_CHANGE_PASSWORD_MESSAGE = "{PRFX} &aYour password has been changed to &6{0} &aby an administator!";
      public String FORCE_CHANGE_PASSWORD_NOT_SUCCESSFUL = "{PRFX} &cUnable to change password for &6{0}&c. Most likely this player has never been on this server.";
      public String FORCE_CHANGE_PASSWORD_NOT_REGISTERED = "{PRFX} &cPlayer &6{0}&c is not registered.";
      public String FORCE_CHANGE_PASSWORD_USAGE = "{PRFX} Usage: &6/forcechangepassword <nickname> <new password>";

      public String FORCE_REGISTER_USAGE = "{PRFX} Usage: &6/forceregister <nickname> <password>";
      public String FORCE_REGISTER_INCORRECT_NICKNAME = "{PRFX} &cNickname contains forbidden characters.";
      public String FORCE_REGISTER_TAKEN_NICKNAME = "{PRFX} &cThis nickname is already taken.";
      public String FORCE_REGISTER_SUCCESSFUL = "{PRFX} &aSuccessfully registered player &6{0}&a!";
      public String FORCE_REGISTER_NOT_SUCCESSFUL = "{PRFX} &cUnable to register player &6{0}&c.";

      public String FORCE_LOGIN_USAGE = "{PRFX} Usage: &6/forcelogin <nickname>";
      public String FORCE_LOGIN_SUCCESSFUL = "{PRFX} &aSuccessfully authenticated &6{0}&a!";
      public String FORCE_LOGIN_UNKNOWN_PLAYER = "{PRFX} &cUnable to find authenticating player with username &6{0}&a!";

      public String TOTP = "{PRFX} Please, enter your 2FA key using &6/2fa <key>";
      @Comment(value = "Can be empty.", at = Comment.At.SAME_LINE)
      public String TOTP_TITLE = "{PRFX}";
      @Comment(value = "Can be empty.", at = Comment.At.SAME_LINE)
      public String TOTP_SUBTITLE = "&aEnter your 2FA key using &6/2fa <key>";
      public String TOTP_SUCCESSFUL = "{PRFX} &aSuccessfully enabled 2FA!";
      public String TOTP_DISABLED = "{PRFX} &aSuccessfully disabled 2FA!";
      @Comment("Or if totp-need-pass set to false remove the \"<current password>\" part.")
      public String TOTP_USAGE = "{PRFX} Usage: &6/2fa enable <current password>&f or &6/2fa disable <totp key>&f.";
      public String TOTP_WRONG = "{PRFX} &cWrong 2FA key!";
      public String TOTP_ALREADY_ENABLED = "{PRFX} &c2FA is already enabled. Disable it using &6/2fa disable <key>&c.";
      public String TOTP_QR = "{PRFX} Click here to open 2FA QR code in browser.";
      public String TOTP_TOKEN = "{PRFX} &aYour 2FA token &7(Click to copy)&a: &6{0}";
      public String TOTP_RECOVERY = "{PRFX} &aYour recovery codes &7(Click to copy)&a: &6{0}";

      public String DESTROY_SESSION_SUCCESSFUL = "{PRFX} &eYour session is now destroyed, you'll need to log in again after reconnecting.";

      public String MOD_SESSION_EXPIRED = "{PRFX} Your session has expired, log in again.";
    }
  }

  @Create
  public DATABASE DATABASE;

  @Comment("Database settings")
  public static class DATABASE {

    @Comment("Database type: mariadb, mysql, postgresql, sqlite or h2.")
    public DatabaseLibrary STORAGE_TYPE = DatabaseLibrary.H2;

    @Comment("Settings for Network-based database (like MySQL, PostgreSQL): ")
    public String HOSTNAME = "127.0.0.1:3306";
    public String USER = "user";
    public String PASSWORD = "password";
    public String DATABASE = "limboauth";
    public String CONNECTION_PARAMETERS = "?autoReconnect=true&initialTimeout=1&useSSL=false";
  }

  @Create
  public PROTECTION PROTECTION;

  @Comment({
      "Credential-stuffing / password-checker detection.",
      "MONITOR mode scores every login attempt, logs, stores and alerts, but never kicks or",
      "locks anyone. ENFORCE mode additionally applies the actions from the enforcement",
      "section when the score is high enough. Players with a linked social account",
      "(LimboAuth-SocialAddon) are fully exempt from detection and enforcement."
  })
  public static class PROTECTION {

    public boolean ENABLED = true;

    @Comment("MONITOR: detect and report only. ENFORCE: also apply the actions from the enforcement section.")
    public String MODE = "MONITOR";

    @Create
    public WINDOWS WINDOWS;

    public static class WINDOWS {

      @Comment("Short window for fast-source signals (raw fail rate), milliseconds (10 minutes)")
      public long VOLUME_WINDOW_MILLIS = 600000;
      @Comment({
          "Long window for distributed, low-and-slow and human-paced signals, milliseconds (60 minutes).",
          "Distinct-target and churn counts use this window: a human checking leaked credentials",
          "spreads a handful of attempts across an hour."
      })
      public long DISTRIBUTION_WINDOW_MILLIS = 3600000;
      @Comment("Sessions shorter than this count as \"churn\" (join -> few attempts -> quit), milliseconds")
      public long CHURN_SESSION_MILLIS = 20000;
      @Comment("Sessions with at most this many password attempts can count as churn")
      public int CHURN_MAX_ATTEMPTS = 3;
      @Comment({
          "Hard caps on tracked keys to bound memory under botnet-scale floods.",
          "When a cap is reached, an arbitrary old entry is evicted to make room."
      })
      public int MAX_TRACKED_IPS = 50000;
      public int MAX_TRACKED_SUBNETS = 20000;
      public int MAX_TRACKED_ACCOUNTS = 50000;
      public int MAX_TRACKED_FINGERPRINTS = 20000;
      @Comment("Maximum events kept per tracked IP/subnet/account/password-fingerprint")
      public int MAX_EVENTS_PER_WINDOW = 256;
    }

    @Create
    public SCORING SCORING;

    public static class SCORING {

      @Comment("Severity thresholds on the additive risk score")
      public int THRESHOLD_INFO = 15;
      public int THRESHOLD_SUSPICIOUS = 30;
      public int THRESHOLD_HIGH = 50;
      public int THRESHOLD_CRITICAL = 75;

      @Comment({
          "Per-category score caps. No single non-confirmation category can reach the HIGH threshold",
          "on its own, so a HIGH alert always requires at least two independent signal categories."
      })
      public int CAP_VOLUME = 35;
      public int CAP_DISTRIBUTION = 35;
      public int CAP_BEHAVIOR = 15;
      public int CAP_GEO = 30;

      @Comment("First login command sent within this time after spawning counts as \"instant\" (milliseconds)")
      public long FAST_FIRST_COMMAND_MILLIS = 1000;

      @Comment("An account is \"dormant\" when its last successful login is older than this many days")
      public int DORMANT_DAYS = 30;

      @Comment({
          "Distinct OTHER foreign accounts (existing accounts, not the one that succeeded, whose",
          "stored last-login IP is on another subnet than the source) a password must have been",
          "tried against before a successful login with it counts as a confirmed spray hit.",
          "Same-owner alt families relogged from their usual network have zero foreign targets",
          "and can never trip the confirmation; accounts that never logged in (no stored IP)",
          "are never counted as foreign. 0 disables the confirmation.",
          "Default 3: monitor data showed real three-alt families relogged from a rotated or",
          "new subnet (all stored login IPs elsewhere), which a threshold of 2 flags CRITICAL.",
          "At 3 such a family peaks at SUSPICIOUS while a spray that reached three or more",
          "OTHER players' accounts still confirms."
      })
      public int SPRAY_FOREIGN_TARGET_MIN = 3;

      @Comment({
          "Java regexes matched against the client brand. Empty by default to avoid false positives.",
          "Example: [\"(?i).*console.*\", \"(?i)wurst.*\"]"
      })
      public List<String> SUSPICIOUS_BRANDS = List.of();

      @Comment("Behavioral factors (brand, timing) are skipped for floodgate/bedrock players")
      public boolean SKIP_BEHAVIOR_FOR_FLOODGATE = true;

      @Create
      public WEIGHTS WEIGHTS;

      @Comment({
          "Points each factor adds to the risk score. The numeric suffix is the trigger threshold",
          "within the corresponding window (see the windows section). Set a weight to 0 to disable a factor."
      })
      public static class WEIGHTS {

        @Comment("Failed logins from one IP in the volume window")
        public int IP_FAIL_RATE_6 = 10;
        public int IP_FAIL_RATE_10 = 15;
        public int IP_FAIL_RATE_20 = 20;
        @Comment("Distinct existing accounts with failed logins from one IP in the distribution window")
        public int IP_DISTINCT_TARGETS_3 = 10;
        public int IP_DISTINCT_TARGETS_4 = 15;
        public int IP_DISTINCT_TARGETS_5 = 20;
        public int IP_DISTINCT_TARGETS_10 = 30;
        @Comment("Distinct existing accounts with failed logins from one subnet (needs >= 2 source IPs)")
        public int SUBNET_DISTINCT_TARGETS_5 = 10;
        public int SUBNET_DISTINCT_TARGETS_10 = 20;
        @Comment("One account with failed logins from multiple IPs in the distribution window")
        public int ACCOUNT_DISTINCT_IPS_2 = 15;
        public int ACCOUNT_DISTINCT_IPS_4 = 25;
        @Comment("The same password tried against multiple existing accounts in the distribution window")
        public int PASSWORD_SPRAY_3 = 20;
        public int PASSWORD_SPRAY_8 = 35;
        @Comment("Short join -> few attempts -> quit sessions from one IP or subnet in the distribution window")
        public int CHURN_SESSIONS_3 = 15;
        @Comment({
            "One IP successfully logging into multiple accounts whose stored last-login IP was a different",
            "address. Own alts keep their stored IP, so relogging your own accounts never triggers this."
        })
        public int MULTI_ACCOUNT_NEW_SOURCE_2 = 15;
        @Comment("Successful login on a dormant account (see dormant-days) from a different subnet than its last login")
        public int DORMANT_ACCOUNT_TAKEOVER = 15;
        @Comment("First login command sent almost instantly after spawn")
        public int INSTANT_FIRST_COMMAND = 5;
        @Comment("Client never sent a brand plugin message before the attempt")
        public int MISSING_BRAND = 5;
        @Comment("Client brand matched one of the suspicious-brands regexes")
        public int SUSPICIOUS_BRAND = 10;
        @Comment("Login country differs from the country of the account's last successful login IP")
        public int GEO_COUNTRY_MISMATCH = 20;
        @Comment("Login IP belongs to a hosting/datacenter ASN")
        public int GEO_HOSTING_ASN = 10;
        @Comment("Successful login on an account that recently failed from OTHER IPs (probable confirmed hit)")
        public int CONFIRM_SUCCESS_AFTER_DISTRIBUTED_FAILURES = 80;
        @Comment("Successful login from a source that was already flagged HIGH before this attempt")
        public int CONFIRM_SUCCESS_FROM_FLAGGED_SOURCE = 65;
        @Comment("Successful login with a password that was part of a spray against multiple foreign accounts (see spray-foreign-target-min)")
        public int CONFIRM_SPRAYED_PASSWORD_SUCCESS = 80;
        @Comment({
            "Successful login on a FOREIGN account (stored last-login IP on another subnet) from",
            "a source that recently FAILED against several other players' foreign accounts - the",
            "checker-with-a-hit pattern. A neighbor logging into their OWN account behind the same",
            "source is never confirmed by failures they did not produce. Also used retroactively:",
            "a success that happened BEFORE the source crossed a tier is re-reported once it does."
        })
        public int CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE_3 = 50;
        public int CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE_6 = 80;
      }
    }

    @Create
    public SOCIAL SOCIAL;

    @Comment({
        "Players with any linked social account (LimboAuth-SocialAddon) are fully exempt from detection.",
        "The addon's table lives in the same database as LimboAuth. The table is auto-detected at startup;",
        "if it is not found, all players are treated as unlinked (and therefore protected by detection)."
    })
    public static class SOCIAL {

      public boolean ENABLED = true;
      @Comment("Defaults match the stock LimboAuth-SocialAddon schema")
      public String TABLE_NAME = "SOCIAL";
      public String NICKNAME_COLUMN = "LOWERCASENICKNAME";
      @Comment("A player is considered linked when ANY of these columns is non-empty")
      public List<String> LINK_COLUMNS = List.of("VK_ID", "TELEGRAM_ID", "DISCORD_ID");
      public long CACHE_TTL_MILLIS = 300000;
    }

    @Create
    public STORAGE STORAGE;

    @Comment("Detection events are stored in the PROTECTION_EVENTS table for threshold tuning")
    public static class STORAGE {

      @Comment("Minimum severity persisted to the database: INFO, SUSPICIOUS, HIGH or CRITICAL")
      public String STORE_MIN_SEVERITY = "INFO";
      public int RETENTION_DAYS = 14;
    }

    @Create
    public WEBHOOK WEBHOOK;

    @Comment("Discord webhook alerts")
    public static class WEBHOOK {

      public boolean ENABLED = false;
      public String URL = "";
      @Comment("Minimum severity that triggers a Discord message: INFO, SUSPICIOUS, HIGH or CRITICAL")
      public String MIN_SEVERITY = "HIGH";
      @Comment("Suppress repeat alerts for the same attack cluster unless severity escalates, milliseconds")
      public long COOLDOWN_MILLIS = 300000;
      @Comment("Alerts arriving within this interval are combined into one message, milliseconds")
      public long BATCH_MILLIS = 10000;
      @Comment("Optional role id to mention on CRITICAL alerts, e.g. \"123456789012345678\"")
      public String MENTION_ROLE_CRITICAL = "";
      public String USERNAME = "LimboAuth Protection";
    }

    @Create
    public GEOIP GEOIP;

    @Comment({
        "Optional MaxMind GeoLite2 factors. Requires a free license key",
        "(https://www.maxmind.com/en/geolite2/signup). Inactive while the key is empty.",
        "The databases are downloaded into the plugin folder and refreshed automatically."
    })
    public static class GEOIP {

      public boolean ENABLED = false;
      public String LICENSE_KEY = "";
      @Comment("COUNTRY is enough for the mismatch factor and is much smaller than CITY")
      public String EDITION = "COUNTRY";
      public boolean ENABLE_ASN = true;
      public int REFRESH_DAYS = 7;
      @Comment("ASNs always treated as hosting providers (AS numbers as strings)")
      public List<String> HOSTING_ASNS = List.of();
      @Comment("ASN organization name keywords treated as hosting providers (case-insensitive)")
      public List<String> HOSTING_ORG_KEYWORDS = List.of("hosting", "datacenter", "data center", "vps", "cloud", "colo", "server");
    }

    @Create
    public ENFORCEMENT ENFORCEMENT;

    @Comment({
        "Automatic enforcement, applied only when detection is confident. Active when this",
        "section is enabled OR protection.mode is ENFORCE. All actions are temporary and",
        "in-memory (cleared by a proxy restart); admins unlock early with",
        "\"/limboauth protection unblock <ip|nickname>\". Players with the",
        "\"limboauth.protection.bypass\" permission are never kicked or blocked."
    })
    public static class ENFORCEMENT {

      @Comment("Master switch, equivalent to setting protection.mode: ENFORCE")
      public boolean ENABLED = false;
      @Comment({
          "Kick the offending session when an attempt scores this severity or above.",
          "HIGH, CRITICAL or NONE (never). The kick screen is the generic protection-kick",
          "message, indistinguishable from an ordinary wrong-password kick."
      })
      public String KICK_ON = "HIGH";
      @Comment("Temporarily refuse all joins from the source IP at this severity or above: HIGH, CRITICAL or NONE")
      public String BLOCK_SOURCE_ON = "HIGH";
      public int SOURCE_BLOCK_MINUTES = 30;
      @Comment({
          "Shield the targeted account when a SUCCESSFUL login scores this severity or above:",
          "HIGH, CRITICAL or NONE. While shielded, every password - even the correct one -",
          "gets the ordinary wrong-password reply, so a checker can never confirm a hit.",
          "The shield also applies to mod session-token logins. Linked-social accounts are",
          "never shielded (they are exempt from the whole system)."
      })
      public String SHIELD_ACCOUNT_ON = "HIGH";
      public int SHIELD_MINUTES = 60;
      @Comment("Memory bounds; oldest entries are evicted above these caps")
      public int MAX_BLOCKED_SOURCES = 10000;
      public int MAX_SHIELDED_ACCOUNTS = 5000;
    }
  }

  public static class MD5KeySerializer extends ConfigSerializer<byte[], String> {

    private final MessageDigest md5;
    private final SecureRandom random;
    private String originalValue;

    @SuppressFBWarnings("CT_CONSTRUCTOR_THROW")
    public MD5KeySerializer() throws NoSuchAlgorithmException {
      super(byte[].class, String.class);
      this.md5 = MessageDigest.getInstance("MD5");
      this.random = new SecureRandom();
    }

    @Override
    public String serialize(byte[] from) {
      if (this.originalValue == null || this.originalValue.isEmpty()) {
        this.originalValue = generateRandomString(24);
      }

      return this.originalValue;
    }

    @Override
    public byte[] deserialize(String from) {
      // An empty key would make the mod session-token digest MD5("") — a publicly known constant —
      // which, with mod auto-login enabled, would let anyone forge auto-login tokens. Generate one instead.
      if (from == null || from.isEmpty()) {
        from = generateRandomString(24);
      }

      this.originalValue = from;
      return this.md5.digest(from.getBytes(StandardCharsets.UTF_8));
    }

    private String generateRandomString(int length) {
      String chars = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890";
      StringBuilder builder = new StringBuilder();
      for (int i = 0; i < length; i++) {
        builder.append(chars.charAt(this.random.nextInt(chars.length())));
      }
      return builder.toString();
    }
  }
}
