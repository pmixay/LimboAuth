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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;

class GeoLite2DownloaderTest {

  @Test
  void extractsMmdbEntry() throws IOException {
    byte[] mmdb = "fake mmdb content".getBytes(StandardCharsets.US_ASCII);
    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("GeoLite2-Country_20260101/COPYRIGHT.txt", "copyright".getBytes(StandardCharsets.US_ASCII));
    entries.put("GeoLite2-Country_20260101/GeoLite2-Country.mmdb", mmdb);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertTrue(GeoLite2Downloader.extractMmdb(new ByteArrayInputStream(this.tarGz(entries)), out));
    assertArrayEquals(mmdb, out.toByteArray());
  }

  @Test
  void returnsFalseWithoutMmdbEntry() throws IOException {
    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("README.txt", "nothing here".getBytes(StandardCharsets.US_ASCII));

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertFalse(GeoLite2Downloader.extractMmdb(new ByteArrayInputStream(this.tarGz(entries)), out));
  }

  private byte[] tarGz(Map<String, byte[]> entries) throws IOException {
    ByteArrayOutputStream tar = new ByteArrayOutputStream();
    for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
      byte[] header = new byte[512];
      byte[] name = entry.getKey().getBytes(StandardCharsets.US_ASCII);
      System.arraycopy(name, 0, header, 0, name.length);
      byte[] size = String.format("%011o", entry.getValue().length).getBytes(StandardCharsets.US_ASCII);
      System.arraycopy(size, 0, header, 124, size.length);
      header[156] = '0';
      tar.write(header);
      tar.write(entry.getValue());
      int padding = (512 - (entry.getValue().length % 512)) % 512;
      tar.write(new byte[padding]);
    }

    tar.write(new byte[1024]);

    ByteArrayOutputStream compressed = new ByteArrayOutputStream();
    try (GZIPOutputStream gzip = new GZIPOutputStream(compressed)) {
      gzip.write(tar.toByteArray());
    }

    return compressed.toByteArray();
  }
}
