#include "backend_client.h"

#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <esp_system.h>

#include <cstdio>
#include <cstring>

#include "app_config.h"
#include "mac_address.h"

namespace defense_sniffer {
namespace {

void encodeHex(const uint8_t* bytes, size_t length, char* output) {
  static constexpr char kHex[] = "0123456789abcdef";
  for (size_t index = 0; index < length; ++index) {
    output[index * 2] = kHex[(bytes[index] >> 4U) & 0x0FU];
    output[index * 2 + 1] = kHex[bytes[index] & 0x0FU];
  }
  output[length * 2] = '\0';
}

void formatMac(const uint8_t* mac, char* output, size_t outputSize) {
  std::snprintf(output, outputSize, "%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

PostResult classifyHttpStatus(int statusCode) {
  if (statusCode >= 200 && statusCode < 300) {
    return PostResult::Success;
  }
  if (statusCode < 0 || statusCode == 408 || statusCode == 425 ||
      statusCode == 429 || statusCode >= 500) {
    return PostResult::RetryableFailure;
  }
  return PostResult::PermanentFailure;
}

}  // namespace

void BackendClient::begin() {
  initializeIdentity();
  if (!app_config::kHasLocalConfig) {
    Serial.println(
        "[backend] missing include/secrets.h; capture remains active locally");
    return;
  }
  targetConfigValid_ =
      app_config::kMonitoredChannel >= 1 &&
      app_config::kMonitoredChannel <= 14 &&
      parseMacAddress(app_config::kMonitoredBssid, targetBssid_);
  if (!targetConfigValid_) {
    Serial.println("[backend] invalid monitored channel/BSSID configuration");
    return;
  }

  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.setAutoReconnect(true);
  connectWifi(millis());
}

void BackendClient::initializeIdentity() {
  const uint64_t chipId = ESP.getEfuseMac();
  bootNonce_ = esp_random();
  std::snprintf(bootId_, sizeof(bootId_), "boot-%08lx%08lx-%08lx",
                static_cast<unsigned long>(chipId >> 32U),
                static_cast<unsigned long>(chipId & 0xffffffffULL),
                static_cast<unsigned long>(bootNonce_));
}

void BackendClient::connectWifi(uint32_t nowMs) {
  lastWifiAttemptMs_ = nowMs;
  announcedConnection_ = false;
  Serial.printf("[wifi] connecting to %s (%s, channel %u)\n",
                app_config::kWifiSsid, app_config::kMonitoredBssid,
                app_config::kMonitoredChannel);
  WiFi.begin(app_config::kWifiSsid, app_config::kWifiPassword,
             app_config::kMonitoredChannel, targetBssid_, true);
}

void BackendClient::loop(uint32_t nowMs) {
  if (!app_config::kHasLocalConfig || !targetConfigValid_) {
    return;
  }

  if (!wifiConnected()) {
    announcedConnection_ = false;
    if (nowMs - lastWifiAttemptMs_ >= app_config::kWifiRetryIntervalMs) {
      WiFi.disconnect(false, false);
      connectWifi(nowMs);
    }
    return;
  }

  if (!announcedConnection_) {
    Serial.printf("[wifi] connected, IP=%s, channel=%u, RSSI=%d dBm\n",
                  WiFi.localIP().toString().c_str(), WiFi.channel(),
                  WiFi.RSSI());
    announcedConnection_ = true;
  }

}

bool BackendClient::wifiConnected() const {
  return WiFi.status() == WL_CONNECTED;
}

uint64_t BackendClient::nextSequence() { return ++sequence_; }

void BackendClient::makeEventId(uint64_t sequence, char* output,
                                size_t outputSize) const {
  std::snprintf(output, outputSize, "evt-%08lx-%llu",
                static_cast<unsigned long>(bootNonce_),
                static_cast<unsigned long long>(sequence));
}

const char* BackendClient::bootId() const { return bootId_; }

PostResult BackendClient::postAnomaly(const AnomalyReport& report,
                                      const AnomalyEnvelope& envelope) {
  JsonDocument document;
  document["node_id"] = app_config::kNodeId;
  document["timestamp"] = envelope.uptimeMs / 1000.0;

  JsonArray frames = document["frame_hex"].to<JsonArray>();
  char encoded[kMaximumCapturedFrameBytes * 2 + 1];
  for (size_t index = 0; index < report.sampleCount; ++index) {
    const FrameSample& sample = report.samples[index];
    encodeHex(sample.bytes, sample.length, encoded);
    frames.add(String(encoded));
  }
  if (report.sampleCount > 0) {
    document["rssi"] = report.samples[0].rssi;
  }
  char bssid[18];
  char senderMac[18];
  formatMac(report.bssid, bssid, sizeof(bssid));
  formatMac(report.sender, senderMac, sizeof(senderMac));
  document["bssid"] = bssid;
  document["sender_mac"] = senderMac;

  JsonObject anomaly = document["anomaly_stats"].to<JsonObject>();
  anomaly["frame_type"] = "mgmt";
  anomaly["subtype"] = report.subtype;
  anomaly["channel"] = report.channel;
  anomaly["count_in_window"] = report.countInWindow;
  anomaly["window_ms"] = report.windowMs;
  document["guessed_type"] = attackKindName(report.kind);

  String payload;
  payload.reserve(app_config::kMaximumJsonBytes);
  serializeJson(document, payload);
  if (payload.length() > app_config::kMaximumJsonBytes) {
    Serial.println("[backend] anomaly JSON exceeded configured limit");
    return PostResult::PermanentFailure;
  }
  return postJson(app_config::kIngestPath, payload);
}

PostResult BackendClient::postHeartbeat(const HeartbeatSnapshot& snapshot) {
  JsonDocument document;
  document["node_id"] = app_config::kNodeId;
  document["timestamp"] = snapshot.uptimeMs / 1000.0;
  document["state"] =
      std::strcmp(snapshot.threatLevel, "ALERT") == 0 ? "ALERT" : "NORMAL";

  JsonObject stats = document["stats"].to<JsonObject>();
  stats["frames_seen"] = snapshot.framesSeen;
  stats["blocked"] = 0;
  stats["fw_version"] = app_config::kFirmwareVersion;

  String payload;
  payload.reserve(512);
  serializeJson(document, payload);
  const bool multicastSent = sendHeartbeatMulticast(snapshot);
  const PostResult httpResult = postJson(app_config::kHeartbeatPath, payload);
  return multicastSent ? PostResult::Success : httpResult;
}

bool BackendClient::sendHeartbeatMulticast(
    const HeartbeatSnapshot& snapshot) {
  JsonDocument document;
  document["schema_version"] = 1;
  document["type"] = "HEARTBEAT";
  document["node_id"] = app_config::kNodeId;
  document["uptime_ms"] = snapshot.uptimeMs;
  document["frames_seen"] = snapshot.framesSeen;
  document["fw_version"] = app_config::kFirmwareVersion;

  char payload[256];
  const size_t length = serializeJson(document, payload, sizeof(payload));
  if (length == 0 || length >= sizeof(payload)) {
    return false;
  }

  const IPAddress destination(app_config::kTestMulticastAddress[0],
                              app_config::kTestMulticastAddress[1],
                              app_config::kTestMulticastAddress[2],
                              app_config::kTestMulticastAddress[3]);
  if (multicast_.beginPacket(destination, app_config::kTestMulticastPort) != 1) {
    return false;
  }
  multicast_.write(reinterpret_cast<const uint8_t*>(payload), length);
  return multicast_.endPacket() == 1;
}

PostResult BackendClient::postJson(const char* path, const String& payload) {
  if (!wifiConnected()) {
    return PostResult::RetryableFailure;
  }

  WiFiClient client;
  HTTPClient http;
  const String url = String("http://") + app_config::kBackendHost + ":" +
                     app_config::kBackendPort + path;
  http.setConnectTimeout(app_config::kHttpTimeoutMs);
  http.setTimeout(app_config::kHttpTimeoutMs);
  if (!http.begin(client, url)) {
    Serial.printf("[backend] cannot open %s\n", path);
    return PostResult::RetryableFailure;
  }

  http.addHeader("Content-Type", "application/json");
  http.addHeader("Accept", "application/json");
  if (std::strlen(app_config::kApiToken) > 0) {
    http.addHeader("Authorization",
                   String("Bearer ") + app_config::kApiToken);
  }

  const int statusCode = http.POST(payload);
  const PostResult result = classifyHttpStatus(statusCode);
  if (result == PostResult::Success) {
    failureLogLimiter_.reset();
  } else {
    const FailureLogDecision decision = failureLogLimiter_.observe(
        statusCode, millis(), app_config::kHttpFailureLogIntervalMs);
    if (decision.shouldLog) {
      Serial.printf("[backend] POST %s failed: HTTP %d", path, statusCode);
      if (decision.suppressed > 0) {
        Serial.printf(" (%lu repeated failures suppressed)",
                      static_cast<unsigned long>(decision.suppressed));
      }
      Serial.println();
    }
  }
  http.end();
  return result;
}

}  // namespace defense_sniffer
