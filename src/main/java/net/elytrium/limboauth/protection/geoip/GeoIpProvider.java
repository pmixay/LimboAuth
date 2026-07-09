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

package net.elytrium.limboauth.protection.geoip;

import com.maxmind.db.CHMCache;
import com.maxmind.db.MaxMindDbConstructor;
import com.maxmind.db.MaxMindDbParameter;
import com.maxmind.db.Reader;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import net.elytrium.limboauth.Settings;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.slf4j.Logger;

/**
 * Optional GeoLite2 country/ASN lookups. Databases are downloaded asynchronously with the
 * owner's license key and memory-mapped, so lookups are microseconds and heap impact is
 * negligible. While inactive (no key, disabled, or download pending) every lookup returns
 * null and the GEO factors simply contribute nothing.
 */
public class GeoIpProvider {

  private final Logger logger;
  private final AtomicBoolean refreshing = new AtomicBoolean();

  @Nullable
  private volatile Reader countryReader;
  @Nullable
  private volatile Reader asnReader;
  private volatile String status = "inactive";

  public GeoIpProvider(Logger logger) {
    this.logger = logger;
  }

  public void reload(Path geoIpDirectory) {
    Settings.PROTECTION.GEOIP config = Settings.IMP.PROTECTION.GEOIP;
    if (!config.ENABLED || config.LICENSE_KEY.isEmpty()) {
      this.close();
      this.status = config.ENABLED ? "waiting for a license key" : "disabled";
      return;
    }

    this.refresh(geoIpDirectory);
  }

  /**
   * Downloads missing/stale databases and (re)opens the readers. Runs asynchronously;
   * safe to call repeatedly (e.g. from the daily refresh task).
   */
  public void refresh(Path geoIpDirectory) {
    Settings.PROTECTION.GEOIP config = Settings.IMP.PROTECTION.GEOIP;
    if (!config.ENABLED || config.LICENSE_KEY.isEmpty() || !this.refreshing.compareAndSet(false, true)) {
      return;
    }

    CompletableFuture.runAsync(() -> {
      try {
        String countryEdition = "CITY".equalsIgnoreCase(config.EDITION) ? "GeoLite2-City" : "GeoLite2-Country";
        Reader newCountryReader = this.openFresh(geoIpDirectory, countryEdition, config);
        if (newCountryReader != null) {
          this.swapCountryReader(newCountryReader);
        }

        if (config.ENABLE_ASN) {
          Reader newAsnReader = this.openFresh(geoIpDirectory, "GeoLite2-ASN", config);
          if (newAsnReader != null) {
            this.swapAsnReader(newAsnReader);
          }
        }

        if (this.countryReader != null) {
          this.status = "active (" + countryEdition + (this.asnReader != null ? " + GeoLite2-ASN" : "") + ")";
        }
      } catch (GeoLite2Downloader.InvalidLicenseKeyException e) {
        this.status = "invalid license key";
        this.logger.error("GeoIP disabled: {}", e.getMessage());
      } catch (Exception e) {
        this.status = "download failed: " + e.getMessage();
        this.logger.warn("Failed to refresh the GeoLite2 databases", e);
      } finally {
        this.refreshing.set(false);
      }
    });
  }

  public boolean isActive() {
    return this.countryReader != null;
  }

  public String getStatus() {
    return this.status;
  }

  @Nullable
  public GeoIpResult lookup(InetAddress address) {
    Reader country = this.countryReader;
    if (country == null) {
      return null;
    }

    String iso = null;
    Long asn = null;
    String organization = null;
    try {
      CountryResponse response = country.get(address, CountryResponse.class);
      if (response != null && response.country != null) {
        iso = response.country.isoCode;
      }
    } catch (Exception e) {
      // A single failed lookup must never break the pipeline.
      this.logger.debug("GeoIP country lookup failed", e);
    }

    Reader asnDb = this.asnReader;
    if (asnDb != null) {
      try {
        AsnResponse response = asnDb.get(address, AsnResponse.class);
        if (response != null) {
          asn = response.number;
          organization = response.organization;
        }
      } catch (Exception e) {
        this.logger.debug("GeoIP ASN lookup failed", e);
      }
    }

    return new GeoIpResult(iso, asn, organization);
  }

  @Nullable
  public String lookupCountryIso(@Nullable String ipString) {
    if (ipString == null || ipString.isEmpty() || !this.isActive()) {
      return null;
    }

    try {
      // The stored login IP is always a literal address, so this never does a DNS lookup.
      GeoIpResult result = this.lookup(InetAddress.getByName(ipString));
      return result == null ? null : result.countryIso();
    } catch (Exception e) {
      return null;
    }
  }

  public void close() {
    this.swapCountryReader(null);
    this.swapAsnReader(null);
  }

  private Reader openFresh(Path geoIpDirectory, String editionId, Settings.PROTECTION.GEOIP config) throws IOException, InterruptedException {
    Path file = geoIpDirectory.resolve(editionId.toLowerCase(Locale.ROOT) + ".mmdb");
    boolean stale = !Files.exists(file)
        || Files.getLastModifiedTime(file).toInstant().isBefore(Instant.now().minusSeconds(TimeUnit.DAYS.toSeconds(Math.max(1, config.REFRESH_DAYS))));
    if (stale) {
      this.logger.info("Downloading {} (this happens once every {} days)...", editionId, config.REFRESH_DAYS);
      GeoLite2Downloader.download(editionId, config.LICENSE_KEY, file);
      this.logger.info("{} downloaded ({} KiB)", editionId, Files.size(file) / 1024);
    } else if (("GeoLite2-ASN".equals(editionId) ? this.asnReader : this.countryReader) != null) {
      // Fresh file already open - nothing to do.
      return null;
    }

    return new Reader(file.toFile(), new CHMCache());
  }

  private synchronized void swapCountryReader(@Nullable Reader reader) {
    Reader old = this.countryReader;
    this.countryReader = reader;
    this.closeQuietly(old);
  }

  private synchronized void swapAsnReader(@Nullable Reader reader) {
    Reader old = this.asnReader;
    this.asnReader = reader;
    this.closeQuietly(old);
  }

  private void closeQuietly(@Nullable Reader reader) {
    if (reader != null) {
      try {
        reader.close();
      } catch (IOException e) {
        this.logger.debug("Failed to close a GeoIP reader", e);
      }
    }
  }

  public static class CountryResponse {

    private final CountryRecord country;

    @MaxMindDbConstructor
    public CountryResponse(@MaxMindDbParameter(name = "country") CountryRecord country) {
      this.country = country;
    }
  }

  public static class CountryRecord {

    private final String isoCode;

    @MaxMindDbConstructor
    public CountryRecord(@MaxMindDbParameter(name = "iso_code") String isoCode) {
      this.isoCode = isoCode;
    }
  }

  public static class AsnResponse {

    private final Long number;
    private final String organization;

    @MaxMindDbConstructor
    public AsnResponse(@MaxMindDbParameter(name = "autonomous_system_number") Long number,
                       @MaxMindDbParameter(name = "autonomous_system_organization") String organization) {
      this.number = number;
      this.organization = organization;
    }
  }
}
