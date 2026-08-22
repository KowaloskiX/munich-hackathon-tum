#include "backend_client.h"

#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <WiFi.h>

#include <algorithm>
#include <cstring>

#include "app_config.h"

namespace defense_hmi {
namespace {

bool parseSecurityLevel(const char* value, SecurityLevel& result) {
  if (value == nullptr) {
    return false;
  }
  if (strcmp(value, "SAFE") == 0) {
    result = SecurityLevel::Safe;
    return true;
  }
  if (strcmp(value, "ATTACK") == 0) {
    result = SecurityLevel::Attack;
    return true;
  }
  if (strcmp(value, "UNKNOWN") == 0) {
    result = SecurityLevel::Unknown;
    return true;
  }
  return false;
}

std::string jsonString(JsonVariantConst value) {
  const char* parsed = value.is<const char*>() ? value.as<const char*>() : "";
  return parsed == nullptr ? std::string() : std::string(parsed);
}

}  // namespace

BackendClient::BackendClient(SecurityState& state) : state_(state) {}

void BackendClient::begin() {
  if (!app_config::kHasLocalConfig) {
    lastError_ = "missing include/secrets.h";
    return;
  }

  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  connectWifi(millis());
}

bool BackendClient::wifiConnected() const {
  return WiFi.status() == WL_CONNECTED;
}

bool BackendClient::websocketConnected() const {
  return websocketConnected_;
}

const String& BackendClient::lastError() const { return lastError_; }

void BackendClient::connectWifi(uint32_t nowMs) {
  lastWifiAttemptMs_ = nowMs;
  websocketConnected_ = false;
  Serial.printf("[wifi] connecting to %s\n", app_config::kWifiSsid);
  WiFi.disconnect(false, false);
  WiFi.begin(app_config::kWifiSsid, app_config::kWifiPassword);
}

void BackendClient::startWebSocket() {
  websocketPath_ = String(app_config::kWebSocketPath) + "?node_id=" +
                   app_config::kNodeId;

  if (strlen(app_config::kApiToken) > 0) {
    authorizationHeader_ =
        String("Authorization: Bearer ") + app_config::kApiToken + "\r\n";
    websocket_.setExtraHeaders(authorizationHeader_.c_str());
  }

  websocket_.begin(app_config::kBackendHost, app_config::kBackendPort,
                   websocketPath_.c_str());
  websocket_.setReconnectInterval(3000);
  websocket_.enableHeartbeat(15000, 3000, 2);
  websocket_.onEvent([this](WStype_t type, uint8_t* payload, size_t length) {
    handleWebSocketEvent(type, payload, length);
  });
  websocketStarted_ = true;
  Serial.printf("[ws] ws://%s:%u%s\n", app_config::kBackendHost,
                app_config::kBackendPort, websocketPath_.c_str());
}

void BackendClient::loop(uint32_t nowMs) {
  if (!app_config::kHasLocalConfig) {
    return;
  }

  if (!wifiConnected()) {
    wifiWasConnected_ = false;
    if (websocketStarted_) {
      websocket_.disconnect();
      websocketStarted_ = false;
      websocketConnected_ = false;
    }
    if (nowMs - lastWifiAttemptMs_ >= app_config::kWifiRetryIntervalMs) {
      connectWifi(nowMs);
    }
    return;
  }

  if (!wifiWasConnected_) {
    wifiWasConnected_ = true;
    Serial.printf("[wifi] connected, IP=%s, RSSI=%d dBm\n",
                  WiFi.localIP().toString().c_str(), WiFi.RSSI());
    // Force a snapshot immediately after every Wi-Fi reconnect.
    lastPollMs_ = nowMs - app_config::kStatusPollIntervalMs;
  }

  if (app_config::kWebSocketEnabled && !websocketStarted_) {
    startWebSocket();
  }

  if (websocketStarted_) {
    websocket_.loop();
  }

  if (nowMs - lastPollMs_ >= app_config::kStatusPollIntervalMs) {
    pollStatus(nowMs);
  }
}

void BackendClient::pollStatus(uint32_t nowMs) {
  lastPollMs_ = nowMs;
  HTTPClient http;
  const String url = String("http://") + app_config::kBackendHost + ":" +
                     app_config::kBackendPort + app_config::kStatusPath +
                     "?node_id=" + app_config::kNodeId;

  http.setConnectTimeout(app_config::kHttpTimeoutMs);
  http.setTimeout(app_config::kHttpTimeoutMs);
  if (!http.begin(url)) {
    lastError_ = "HTTP begin failed";
    return;
  }
  http.addHeader("Accept", "application/json");
  if (strlen(app_config::kApiToken) > 0) {
    http.addHeader("Authorization",
                   String("Bearer ") + app_config::kApiToken);
  }

  const int statusCode = http.GET();
  if (statusCode != HTTP_CODE_OK) {
    lastError_ = "HTTP " + String(statusCode);
    Serial.printf("[http] status poll failed: %s\n", lastError_.c_str());
    http.end();
    return;
  }

  const int contentLength = http.getSize();
  if (contentLength <= 0 ||
      contentLength > static_cast<int>(app_config::kMaximumJsonBytes)) {
    lastError_ = contentLength < 0 ? "status missing Content-Length"
                                   : "status JSON size invalid";
    http.end();
    return;
  }

  const String body = http.getString();
  http.end();
  if (body.length() > app_config::kMaximumJsonBytes) {
    lastError_ = "status JSON too large";
    return;
  }

  JsonDocument document;
  const DeserializationError error =
      deserializeJson(document, body, DeserializationOption::NestingLimit(8));
  if (error) {
    lastError_ = "invalid status JSON";
    Serial.printf("[http] JSON error: %s\n", error.c_str());
    return;
  }

  if (applyStatusJson(document.as<JsonVariantConst>(), millis(), true)) {
    lastError_ = "";
  }
}

bool BackendClient::applyStatusJson(const JsonVariantConst& root,
                                    uint32_t nowMs,
                                    bool allowEqualSequence) {
  if (!root.is<JsonObjectConst>() || (root["schema_version"] | 0) != 1) {
    lastError_ = "unsupported HMI schema";
    return false;
  }

  const char* streamId = root["stream_id"] | "";
  if (streamId[0] == '\0' || !root["stream_generation"].is<uint64_t>() ||
      !root["seq"].is<uint64_t>() ||
      !root["valid_for_ms"].is<uint32_t>() ||
      !root["active_alerts"].is<uint32_t>() ||
      !root["sensors"].is<JsonObjectConst>() ||
      !root["sensors"]["online"].is<uint32_t>() ||
      !root["sensors"]["expected"].is<uint32_t>()) {
    lastError_ = "incomplete HMI status";
    return false;
  }

  SecuritySnapshot snapshot;
  if (!parseSecurityLevel(root["status"].as<const char*>(), snapshot.level)) {
    lastError_ = "invalid HMI status";
    return false;
  }
  snapshot.activeAlerts = root["active_alerts"].as<uint32_t>();
  snapshot.sensorsOnline = root["sensors"]["online"].as<uint32_t>();
  snapshot.sensorsExpected = root["sensors"]["expected"].as<uint32_t>();
  snapshot.attackFramesDetected =
      root["metrics"]["attack_frames_detected"] | 0U;
  snapshot.incidentId = jsonString(root["incident"]["id"]);
  snapshot.nodeId = jsonString(root["incident"]["node_id"]);
  snapshot.attackClass = jsonString(root["incident"]["attack_class"]);

  uint32_t validForMs = root["valid_for_ms"].as<uint32_t>();
  if (validForMs < app_config::kMinimumAcceptedTtlMs) {
    lastError_ = "HMI status TTL too short";
    return false;
  }
  validForMs = std::min(validForMs, app_config::kMaximumAcceptedTtlMs);

  const OrderingResult orderingResult = ordering_.accept(
      root["stream_generation"].as<uint64_t>(), streamId,
      root["seq"].as<uint64_t>(), snapshot, validForMs,
      allowEqualSequence);
  if (orderingResult == OrderingResult::Rejected) {
    lastError_ = "stale or conflicting HMI status";
    return false;
  }

  state_.applySnapshot(snapshot, nowMs, validForMs);
  return true;
}

void BackendClient::applyEventJson(const JsonVariantConst& root,
                                   uint32_t nowMs) {
  if (!root.is<JsonObjectConst>() || (root["schema_version"] | 0) != 1) {
    return;
  }

  const char* type = root["type"] | "";
  const JsonVariantConst payload = root["payload"];
  if (strcmp(type, "SYSTEM_STATUS") == 0) {
    const char* eventId = root["event_id"] | "";
    const char* outerStream = root["stream_id"] | "";
    const char* payloadStream = payload["stream_id"] | "";
    if (eventId[0] == '\0' || outerStream[0] == '\0' ||
        !root["stream_generation"].is<uint64_t>() ||
        !root["seq"].is<uint64_t>() ||
        root["stream_generation"].as<uint64_t>() !=
            (payload["stream_generation"] | 0ULL) ||
        root["seq"].as<uint64_t>() != (payload["seq"] | 0ULL) ||
        strcmp(outerStream, payloadStream) != 0) {
      lastError_ = "inconsistent SYSTEM_STATUS envelope";
      return;
    }
    applyStatusJson(payload, nowMs, false);
    return;
  }

  // Pipeline events are deliberately not reduced to a security state. Only a
  // fully ordered aggregate status can set or clear the terminal alarm.
}

void BackendClient::handleWebSocketEvent(WStype_t type, uint8_t* payload,
                                         size_t length) {
  switch (type) {
    case WStype_CONNECTED:
      websocketConnected_ = true;
      Serial.println("[ws] connected");
      break;
    case WStype_DISCONNECTED:
      websocketConnected_ = false;
      Serial.println("[ws] disconnected");
      break;
    case WStype_TEXT: {
      if (length == 0 || length > app_config::kMaximumJsonBytes) {
        lastError_ = "WebSocket JSON too large";
        return;
      }
      JsonDocument document;
      const DeserializationError error = deserializeJson(
          document, payload, length, DeserializationOption::NestingLimit(8));
      if (error) {
        lastError_ = "invalid WebSocket JSON";
        return;
      }
      applyEventJson(document.as<JsonVariantConst>(), millis());
      break;
    }
    default:
      break;
  }
}

}  // namespace defense_hmi
