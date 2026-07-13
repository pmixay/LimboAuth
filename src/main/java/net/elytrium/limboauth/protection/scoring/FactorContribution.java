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

package net.elytrium.limboauth.protection.scoring;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.util.ArrayList;
import java.util.List;

public record FactorContribution(RiskFactor factor, int points, String detail) {

  /**
   * The persisted FACTORS-column format ({@code [{"f","p","d"},...]}). Writer and reader
   * live together here so the schema has a single point of change; PROTECTION_EVENTS
   * rows written by one version stay readable by the other side.
   */
  public static String toJson(List<FactorContribution> contributions) {
    JsonArray array = new JsonArray();
    for (FactorContribution contribution : contributions) {
      JsonObject entry = new JsonObject();
      entry.addProperty("f", contribution.factor().name());
      entry.addProperty("p", contribution.points());
      entry.addProperty("d", contribution.detail());
      array.add(entry);
    }

    return array.toString();
  }

  /**
   * Human-readable lines ("FACTOR +points - detail") from a persisted FACTORS value.
   * A row that does not parse (written by another version) is returned raw rather
   * than dropped, so triage never loses information.
   */
  public static List<String> describeJson(String factorsJson) {
    if (factorsJson == null || factorsJson.isEmpty()) {
      return List.of();
    }

    try {
      List<String> lines = new ArrayList<>();
      for (JsonElement element : JsonParser.parseString(factorsJson).getAsJsonArray()) {
        JsonObject entry = element.getAsJsonObject();
        lines.add(entry.get("f").getAsString() + " +" + entry.get("p").getAsInt() + " - " + entry.get("d").getAsString());
      }

      return lines;
    } catch (RuntimeException e) {
      return List.of(factorsJson);
    }
  }
}
