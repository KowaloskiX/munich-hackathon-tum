#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>

#include <algorithm>
#include <cstdio>

#include "anomaly_detector.h"
#include "app_config.h"
#include "blink_pattern.h"
#include "mac_address.h"
#include "reporter.h"
#include "sniffer_radio.h"

namespace {

defense_sniffer::DetectorConfig detectorConfig() {
  defense_sniffer::DetectorConfig config;
  config.windowMs = app_config::kDetectionWindowMs;
  config.cooldownMs = app_config::kDetectionCooldownMs;
  config.deauthThreshold = app_config::kDeauthThreshold;
  config.disassocThreshold = app_config::kDisassocThreshold;
  config.authThreshold = app_config::kAuthThreshold;
  config.associationThreshold = app_config::kAssociationThreshold;
  return config;
}

defense_sniffer::SnifferRadio radio;
defense_sniffer::MgmtFloodDetector detector(detectorConfig());
defense_sniffer::Reporter reporter(radio);
defense_sniffer::BlinkPattern lampPattern(app_config::kLampDurationMs,
                                           app_config::kLampToggleIntervalMs);
bool lampOutputOn = false;
uint32_t lastSerialStatsAtMs = 0;
defense_sniffer::PacketTypeCounters lastPacketCounters;
WiFiUDP testUdp;

void writeLamp(bool on);

const char* subtypeName(uint8_t subtype) {
  switch (subtype) {
    case 0:
      return "association";
    case 10:
      return "disassoc";
    case 11:
      return "auth";
    case 12:
      return "deauth";
    default:
      return "other";
  }
}

void formatMac(const uint8_t* mac, char* output, size_t outputSize) {
  std::snprintf(output, outputSize, "%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void traceCapturedFrame(const defense_sniffer::CapturedFrame& frame) {
  if constexpr (!app_config::kSerialTrace) {
    return;
  }

  char bssid[18];
  char sender[18];
  formatMac(frame.bssid, bssid, sizeof(bssid));
  formatMac(frame.sender, sender, sizeof(sender));

  const size_t hexLength = std::min(
      static_cast<size_t>(frame.length), app_config::kSerialTraceHexBytes);
  char hex[app_config::kSerialTraceHexBytes * 2 + 1];
  static constexpr char kHexDigits[] = "0123456789abcdef";
  for (size_t index = 0; index < hexLength; ++index) {
    hex[index * 2] = kHexDigits[(frame.bytes[index] >> 4U) & 0x0FU];
    hex[index * 2 + 1] = kHexDigits[frame.bytes[index] & 0x0FU];
  }
  hex[hexLength * 2] = '\0';

  Serial.printf(
      "[frame] t=%lums type=%s subtype=%u ch=%u rssi=%d "
      "bssid=%s sender=%s len=%u/%u hex=%s%s\n",
      static_cast<unsigned long>(frame.observedAtMs),
      subtypeName(frame.subtype), frame.subtype, frame.channel, frame.rssi,
      bssid, sender, frame.length, frame.originalLength, hex,
      hexLength < frame.length ? "..." : "");
}

void traceStats(uint32_t nowMs) {
  if constexpr (!app_config::kSerialTrace) {
    return;
  }
  if (nowMs - lastSerialStatsAtMs < app_config::kSerialStatsIntervalMs) {
    return;
  }
  lastSerialStatsAtMs = nowMs;
  const defense_sniffer::PacketTypeCounters packets = radio.packetTypeCounters();
  Serial.printf(
      "[traffic/s] ch=%u mgmt=%lu ctrl=%lu data=%lu misc=%lu "
      "target_mgmt=%lu drops=%lu lamp=%s\n",
      radio.targetChannel(),
      static_cast<unsigned long>(packets.management -
                                 lastPacketCounters.management),
      static_cast<unsigned long>(packets.control - lastPacketCounters.control),
      static_cast<unsigned long>(packets.data - lastPacketCounters.data),
      static_cast<unsigned long>(packets.misc - lastPacketCounters.misc),
      static_cast<unsigned long>(radio.managementFramesSeen()),
      static_cast<unsigned long>(radio.captureFramesDropped()),
      lampPattern.active() ? "ON" : "OFF");
  lastPacketCounters = packets;
}

void handleAcceptedReport(const defense_sniffer::AnomalyReport& report,
                          uint32_t nowMs) {
  lampPattern.trigger(nowMs);
  writeLamp(true);
  reporter.queueAlert(report, nowMs);
  Serial.printf(
      "[alert] potential %s: subtype=%u, count=%lu/%lums, channel=%u\n",
      defense_sniffer::attackKindName(report.kind), report.subtype,
      static_cast<unsigned long>(report.countInWindow),
      static_cast<unsigned long>(report.windowMs), report.channel);
}

void sendSimulatedMarker(uint16_t count, uint8_t channel, const char* bssid,
                         const char* senderMac, uint8_t subtype,
                         const char* attackClass) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println(
        "[test-net] marker not sent: ESP is not connected to Wi-Fi yet");
    return;
  }

  char payload[256];
  const int length =
      subtype == 12
          ? std::snprintf(
                payload, sizeof(payload),
                "{\"schema_version\":1,\"type\":\"SIMULATED_DEAUTH\","
                "\"node_id\":\"%s\",\"uptime_ms\":%lu,\"count\":%u,"
                "\"channel\":%u,\"bssid\":\"%s\",\"sender_mac\":\"%s\"}",
                app_config::kNodeId, static_cast<unsigned long>(millis()),
                count, channel, bssid, senderMac)
          : std::snprintf(
                payload, sizeof(payload),
                "{\"schema_version\":1,\"type\":\"SIMULATED_MGMT_FLOOD\","
                "\"node_id\":\"%s\",\"uptime_ms\":%lu,\"count\":%u,"
                "\"channel\":%u,\"bssid\":\"%s\",\"sender_mac\":\"%s\","
                "\"subtype\":%u,"
                "\"attack_class\":\"%s\"}",
                app_config::kNodeId, static_cast<unsigned long>(millis()),
                count, channel, bssid, senderMac, subtype, attackClass);
  if (length <= 0 || static_cast<size_t>(length) >= sizeof(payload)) {
    Serial.println("[test-net] marker JSON did not fit in the buffer");
    return;
  }

  const IPAddress destination(app_config::kTestMulticastAddress[0],
                              app_config::kTestMulticastAddress[1],
                              app_config::kTestMulticastAddress[2],
                              app_config::kTestMulticastAddress[3]);
  static constexpr uint8_t kMarkerCopies = 5;
  uint8_t sent = 0;
  for (uint8_t copy = 0; copy < kMarkerCopies; ++copy) {
    if (testUdp.beginPacket(destination, app_config::kTestMulticastPort) != 1) {
      continue;
    }
    testUdp.write(reinterpret_cast<const uint8_t*>(payload),
                  static_cast<size_t>(length));
    if (testUdp.endPacket() == 1) {
      ++sent;
    }
    delay(20);
  }
  if (sent > 0) {
    Serial.printf(
        "[test-net] sent %u copies of %s to %s:%u (%d bytes)\n", sent,
        attackClass, destination.toString().c_str(),
        app_config::kTestMulticastPort, length);
  } else {
    Serial.println("[test-net] multicast marker send failed");
  }
}

void runSyntheticMgmtSelfTest(uint8_t subtype, uint16_t threshold) {
  if constexpr (!app_config::kSerialSelfTest) {
    return;
  }

  uint8_t bssid[6];
  radio.copyTargetBssid(bssid);
  char formattedBssid[18];
  formatMac(bssid, formattedBssid, sizeof(formattedBssid));

  static constexpr uint8_t kSyntheticSender[6] = {0x02, 0x00, 0x00,
                                                   0x00, 0x00, 0x01};
  char formattedSender[18];
  formatMac(kSyntheticSender, formattedSender, sizeof(formattedSender));
  uint8_t frameBytes[26]{};
  frameBytes[0] = static_cast<uint8_t>(subtype << 4U);
  std::copy(bssid, bssid + 6, frameBytes + 4);
  std::copy(kSyntheticSender, kSyntheticSender + 6, frameBytes + 10);
  std::copy(bssid, bssid + 6, frameBytes + 16);

  detector.reset();
  const uint32_t nowMs = millis();
  const uint32_t nowUs = micros();
  bool triggered = false;
  const char* detectedKind = "unknown_mgmt_flood";
  for (uint16_t index = 0; index < threshold; ++index) {
    defense_sniffer::FrameObservation observation;
    observation.observedAtMs = nowMs;
    observation.observedAtUs = nowUs + index;
    observation.rssi = -42;
    observation.channel = radio.targetChannel();
    observation.subtype = subtype;
    observation.bssid = bssid;
    observation.sender = kSyntheticSender;
    observation.bytes = frameBytes;
    observation.length = sizeof(frameBytes);
    observation.originalLength = sizeof(frameBytes);

    defense_sniffer::AnomalyReport report;
    if (detector.observe(observation, report)) {
      handleAcceptedReport(report, millis());
      detectedKind = defense_sniffer::attackKindName(report.kind);
      triggered = true;
    }
  }

  Serial.printf(
      "[self-test] injected %u synthetic %s frames; attack RF "
      "transmitted: no; result=%s\n",
      threshold, subtypeName(subtype), triggered ? "ALERT" : "FAILED");
  sendSimulatedMarker(threshold, radio.targetChannel(), formattedBssid,
                      formattedSender, subtype, detectedKind);
}

void synchronizeRadioTarget() {
  if (WiFi.status() != WL_CONNECTED) {
    return;
  }
  radio.followAssociatedAccessPoint(static_cast<uint8_t>(WiFi.channel()),
                                    WiFi.BSSID());
}

void serviceSerialCommands() {
  if constexpr (!app_config::kSerialSelfTest) {
    return;
  }
  while (Serial.available() > 0) {
    const char command = static_cast<char>(Serial.read());
    if (command == 't' || command == 'T' || command == 'd' ||
        command == 'D') {
      runSyntheticMgmtSelfTest(12, app_config::kDeauthThreshold);
    } else if (command == 'y' || command == 'Y') {
      runSyntheticMgmtSelfTest(11, app_config::kAuthThreshold);
    } else if (command == 'u' || command == 'U') {
      runSyntheticMgmtSelfTest(0, app_config::kAssociationThreshold);
    }
  }
}

void writeLamp(bool on) {
  if (app_config::kLampPin < 0 || on == lampOutputOn) {
    return;
  }
  digitalWrite(app_config::kLampPin,
               on == app_config::kLampActiveHigh ? HIGH : LOW);
  lampOutputOn = on;
}

void serviceLamp(uint32_t nowMs) { writeLamp(lampPattern.update(nowMs)); }

void processCapturedFrame(const defense_sniffer::CapturedFrame& frame) {
  // The fixed target remains valid while the STA is temporarily disconnected,
  // so a deauth cannot disable local detection merely by breaking reporting.
  if (!radio.matchesTarget(frame)) {
    return;
  }
  traceCapturedFrame(frame);

  defense_sniffer::FrameObservation observation;
  observation.observedAtMs = frame.observedAtMs;
  observation.observedAtUs = frame.observedAtUs;
  observation.rssi = frame.rssi;
  observation.channel = frame.channel;
  observation.subtype = frame.subtype;
  observation.bssid = frame.bssid;
  observation.sender = frame.sender;
  observation.bytes = frame.bytes;
  observation.length = frame.length;
  observation.originalLength = frame.originalLength;

  defense_sniffer::AnomalyReport report;
  if (!detector.observe(observation, report)) {
    return;
  }

  handleAcceptedReport(report, millis());
}

}  // namespace

void setup() {
  Serial.begin(115200);
  delay(100);
  Serial.printf("\nPassive defense sniffer %s, firmware %s\n",
                app_config::kNodeId, app_config::kFirmwareVersion);

  if (app_config::kLampPin >= 0) {
    pinMode(app_config::kLampPin, OUTPUT);
    digitalWrite(app_config::kLampPin,
                 app_config::kLampActiveHigh ? LOW : HIGH);
  }

  if (!radio.begin()) {
    Serial.println("[fatal] radio sniffer did not start");
  }
  if (!reporter.begin()) {
    Serial.println("[warning] backend reporter did not start");
  }
  if constexpr (app_config::kSerialSelfTest) {
    Serial.println(
        "[self-test] staged demo keys: t=deauth, y=auth, u=association flood");
  }
}

void loop() {
  synchronizeRadioTarget();
  serviceSerialCommands();
  defense_sniffer::CapturedFrame frame;
  size_t processed = 0;
  while (processed < app_config::kMaximumFramesProcessedPerLoop &&
         radio.receive(frame)) {
    processCapturedFrame(frame);
    ++processed;
  }

  serviceLamp(millis());
  traceStats(millis());
  delay(2);
}
