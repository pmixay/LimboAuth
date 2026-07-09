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

package net.elytrium.limboauth.protection.alert;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import net.elytrium.limboauth.Settings;
import net.elytrium.limboauth.event.ProtectionAlertEvent;
import net.elytrium.limboauth.protection.AttemptObservation;
import net.elytrium.limboauth.protection.AttemptOutcome;
import net.elytrium.limboauth.protection.Severity;
import net.elytrium.limboauth.protection.TestSettings;
import net.elytrium.limboauth.protection.scoring.FactorContribution;
import net.elytrium.limboauth.protection.scoring.RiskAssessment;
import net.elytrium.limboauth.protection.scoring.RiskFactor;
import net.elytrium.limboauth.protection.storage.ProtectionEventStorage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class AlertDispatcherTest {

  private final AtomicLong clock = new AtomicLong(1_000_000_000L);
  private final List<ProtectionAlertEvent> firedEvents = new ArrayList<>();
  private AlertDispatcher dispatcher;
  private DiscordWebhookClient webhookClient;

  @BeforeAll
  static void loadSettings() {
    TestSettings.load();
  }

  @BeforeEach
  void setUp() {
    Settings.IMP.PROTECTION.WEBHOOK.ENABLED = true;
    Settings.IMP.PROTECTION.WEBHOOK.URL = "https://example.invalid/webhook";
    Settings.IMP.PROTECTION.WEBHOOK.MIN_SEVERITY = "HIGH";
    Settings.IMP.PROTECTION.WEBHOOK.COOLDOWN_MILLIS = 300000;

    this.firedEvents.clear();
    this.webhookClient = new DiscordWebhookClient(LoggerFactory.getLogger("test"));
    // The webhook drain task never runs in tests, so nothing ever leaves the queue.
    this.dispatcher = new AlertDispatcher(LoggerFactory.getLogger("test"),
        new ProtectionEventStorage(LoggerFactory.getLogger("test")), this.webhookClient, this.firedEvents::add, this.clock::get);
  }

  @Test
  void suppressesRepeatsWithinCooldownAndEscalates() throws Exception {
    AttemptObservation observation = this.observation();

    this.dispatcher.dispatch(observation, this.assessment(55, Severity.HIGH), null);
    assertEquals(1, this.dispatcher.getWebhookAlerts());

    // Same cluster, same severity, within cooldown: suppressed.
    this.clock.addAndGet(1000);
    this.dispatcher.dispatch(observation, this.assessment(60, Severity.HIGH), null);
    assertEquals(1, this.dispatcher.getWebhookAlerts());
    assertEquals(1, this.dispatcher.getSuppressedAlerts());

    // Escalation bypasses the cooldown immediately.
    this.clock.addAndGet(1000);
    this.dispatcher.dispatch(observation, this.assessment(80, Severity.CRITICAL), null);
    assertEquals(2, this.dispatcher.getWebhookAlerts());

    // After the cooldown expires the next alert goes out again.
    this.clock.addAndGet(300001);
    this.dispatcher.dispatch(observation, this.assessment(80, Severity.CRITICAL), null);
    assertEquals(3, this.dispatcher.getWebhookAlerts());
  }

  @Test
  void firesVelocityEventFromSuspiciousUpwards() throws Exception {
    AttemptObservation observation = this.observation();
    this.dispatcher.dispatch(observation, this.assessment(20, Severity.INFO), null);
    assertEquals(0, this.firedEvents.size());
    this.dispatcher.dispatch(observation, this.assessment(35, Severity.SUSPICIOUS), null);
    assertEquals(1, this.firedEvents.size());
    assertEquals(Severity.SUSPICIOUS, this.firedEvents.get(0).getSeverity());
  }

  @Test
  void webhookRespectsMinSeverity() throws Exception {
    AttemptObservation observation = this.observation();
    this.dispatcher.dispatch(observation, this.assessment(35, Severity.SUSPICIOUS), null);
    assertEquals(0, this.dispatcher.getWebhookAlerts());
    this.dispatcher.dispatch(observation, this.assessment(55, Severity.HIGH), null);
    assertEquals(1, this.dispatcher.getWebhookAlerts());
  }

  private RiskAssessment assessment(int score, Severity severity) {
    return new RiskAssessment(score, severity,
        List.of(new FactorContribution(RiskFactor.IP_FAIL_RATE, score, "test detail")), "ip:203.0.113.7");
  }

  private AttemptObservation observation() throws Exception {
    return AttemptObservation.builder("target", InetAddress.getByName("203.0.113.7"), AttemptOutcome.LOGIN_FAIL)
        .accountExists(true)
        .timestamp(this.clock.get())
        .build();
  }
}
