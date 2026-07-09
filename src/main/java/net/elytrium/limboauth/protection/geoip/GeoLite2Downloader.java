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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.zip.GZIPInputStream;

/**
 * Downloads a GeoLite2 database with the owner's license key and extracts the single
 * .mmdb entry from the tar.gz archive (MaxMind only ships mmdb files inside tar.gz).
 * The tar entry name is never used as a filesystem path, so hostile archives cannot
 * escape the target file.
 */
public final class GeoLite2Downloader {

  private static final String DOWNLOAD_URL = "https://download.maxmind.com/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz";
  private static final int TAR_BLOCK_SIZE = 512;

  private GeoLite2Downloader() {
  }

  public static void download(String editionId, String licenseKey, Path targetFile) throws IOException, InterruptedException {
    HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();
    URI uri = URI.create(String.format(DOWNLOAD_URL, editionId, URLEncoder.encode(licenseKey, StandardCharsets.UTF_8)));
    HttpResponse<InputStream> response = client.send(HttpRequest.newBuilder(uri).build(), HttpResponse.BodyHandlers.ofInputStream());
    if (response.statusCode() == 401 || response.statusCode() == 403) {
      try (InputStream body = response.body()) {
        body.readAllBytes();
      }

      throw new InvalidLicenseKeyException("MaxMind rejected the license key (HTTP " + response.statusCode() + ")");
    }

    if (response.statusCode() != 200) {
      try (InputStream body = response.body()) {
        body.readAllBytes();
      }

      throw new IOException("Unexpected HTTP status " + response.statusCode() + " while downloading " + editionId);
    }

    Path parent = targetFile.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }

    Path temp = targetFile.resolveSibling(targetFile.getFileName() + ".tmp");
    try {
      try (InputStream in = response.body(); OutputStream out = Files.newOutputStream(temp)) {
        if (!extractMmdb(in, out)) {
          throw new IOException("No .mmdb entry found in the " + editionId + " archive");
        }
      }

      try {
        Files.move(temp, targetFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
      } catch (IOException e) {
        Files.move(temp, targetFile, StandardCopyOption.REPLACE_EXISTING);
      }
    } finally {
      Files.deleteIfExists(temp);
    }
  }

  /**
   * Streams the first .mmdb entry of a tar.gz archive into {@code out}.
   * Minimal ustar reader: 512-byte headers, octal sizes, block padding.
   */
  public static boolean extractMmdb(InputStream rawInput, OutputStream out) throws IOException {
    GZIPInputStream in = new GZIPInputStream(rawInput);
    byte[] header = new byte[TAR_BLOCK_SIZE];
    byte[] buffer = new byte[8192];
    while (readBlock(in, header)) {
      if (isZeroBlock(header)) {
        return false;
      }

      String name = readName(header);
      long size = readOctal(header, 124, 12);
      byte typeFlag = header[156];
      boolean regularFile = typeFlag == 0 || typeFlag == '0';
      long padding = (TAR_BLOCK_SIZE - (size % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;

      if (regularFile && name.endsWith(".mmdb")) {
        long remaining = size;
        while (remaining > 0) {
          int read = in.read(buffer, 0, (int) Math.min(buffer.length, remaining));
          if (read < 0) {
            throw new IOException("Truncated tar entry: " + name);
          }

          out.write(buffer, 0, read);
          remaining -= read;
        }

        return true;
      }

      skipFully(in, size + padding);
    }

    return false;
  }

  private static boolean readBlock(InputStream in, byte[] block) throws IOException {
    int offset = 0;
    while (offset < block.length) {
      int read = in.read(block, offset, block.length - offset);
      if (read < 0) {
        return false;
      }

      offset += read;
    }

    return true;
  }

  private static boolean isZeroBlock(byte[] block) {
    for (byte value : block) {
      if (value != 0) {
        return false;
      }
    }

    return true;
  }

  private static String readName(byte[] header) {
    String name = readString(header, 0, 100);
    String prefix = readString(header, 345, 155);
    return prefix.isEmpty() ? name : prefix + "/" + name;
  }

  private static String readString(byte[] header, int offset, int length) {
    int end = offset;
    int limit = Math.min(offset + length, header.length);
    while (end < limit && header[end] != 0) {
      ++end;
    }

    return new String(header, offset, end - offset, StandardCharsets.US_ASCII).trim();
  }

  private static long readOctal(byte[] header, int offset, int length) throws IOException {
    String value = readString(header, offset, length).trim();
    if (value.isEmpty()) {
      return 0;
    }

    try {
      return Long.parseLong(value, 8);
    } catch (NumberFormatException e) {
      throw new IOException("Invalid octal field in tar header: \"" + value + "\"");
    }
  }

  private static void skipFully(InputStream in, long count) throws IOException {
    long remaining = count;
    while (remaining > 0) {
      long skipped = in.skip(remaining);
      if (skipped <= 0) {
        if (in.read() < 0) {
          throw new IOException("Truncated tar archive");
        }

        --remaining;
      } else {
        remaining -= skipped;
      }
    }
  }

  public static class InvalidLicenseKeyException extends IOException {

    public InvalidLicenseKeyException(String message) {
      super(message);
    }
  }
}
