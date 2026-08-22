#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>
#include <WebSocketsClient.h>

#include "security_state.h"
#include "status_ordering.h"

namespace defense_hmi {

class BackendClient {
 public:
  explicit BackendClient(SecurityState& state);

  void begin();
  void loop(uint32_t nowMs);
  bool wifiConnected() const;
  bool websocketConnected() const;
  const String& lastError() const;

 private:
  void connectWifi(uint32_t nowMs);
  void startWebSocket();
  void pollStatus(uint32_t nowMs);
  void handleWebSocketEvent(WStype_t type, uint8_t* payload, size_t length);
  bool applyStatusJson(const JsonVariantConst& root, uint32_t nowMs,
                       bool allowEqualSequence);
  void applyEventJson(const JsonVariantConst& root, uint32_t nowMs);

  SecurityState& state_;
  StatusOrdering ordering_;
  WebSocketsClient websocket_;
  bool wifiWasConnected_{false};
  bool websocketStarted_{false};
  bool websocketConnected_{false};
  uint32_t lastWifiAttemptMs_{0};
  uint32_t lastPollMs_{0};
  String websocketPath_;
  String authorizationHeader_;
  String lastError_;
};

}  // namespace defense_hmi
