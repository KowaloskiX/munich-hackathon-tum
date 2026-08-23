#pragma once

#include <Arduino.h>
#include <WiFiUdp.h>

#include "anomaly_detector.h"
#include "diagnostic_helpers.h"

namespace defense_sniffer {

enum class PostResult : uint8_t {
  Success = 0,
  RetryableFailure,
  PermanentFailure,
};

struct AnomalyEnvelope {
  char eventId[80]{};
  uint64_t sequence{0};
  uint32_t uptimeMs{0};
  uint32_t queueDrops{0};
};

struct HeartbeatSnapshot {
  uint64_t sequence{0};
  uint32_t uptimeMs{0};
  const char* threatLevel{"UNKNOWN"};
  uint16_t activeAlerts{0};
  uint32_t attackFramesDetected{0};
  const char* policyState{"MISSING"};
  uint32_t framesSeen{0};
  uint32_t queueDrops{0};
};

class BackendClient {
 public:
  void begin();
  void loop(uint32_t nowMs);

  bool wifiConnected() const;
  uint64_t nextSequence();
  void makeEventId(uint64_t sequence, char* output, size_t outputSize) const;
  const char* bootId() const;
  PostResult postAnomaly(const AnomalyReport& report,
                         const AnomalyEnvelope& envelope);
  PostResult postHeartbeat(const HeartbeatSnapshot& snapshot);

 private:
  void connectWifi(uint32_t nowMs);
  PostResult postJson(const char* path, const String& payload);
  bool sendHeartbeatMulticast(const HeartbeatSnapshot& snapshot);
  void initializeIdentity();

  uint32_t lastWifiAttemptMs_{0};
  bool announcedConnection_{false};
  uint32_t bootNonce_{0};
  uint64_t sequence_{0};
  char bootId_[64]{};
  bool targetConfigValid_{false};
  uint8_t targetBssid_[6]{};
  FailureLogLimiter failureLogLimiter_;
  WiFiUDP multicast_;
};

}  // namespace defense_sniffer
