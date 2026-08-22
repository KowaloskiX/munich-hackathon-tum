#pragma once

#include <cstdint>

namespace defense_sniffer {

enum class PacketClass : uint8_t {
  Management = 0,
  Control,
  Data,
  Misc,
};

constexpr PacketClass classifyPacketType(uint8_t rawType) {
  switch (rawType) {
    case 0:
      return PacketClass::Management;
    case 1:
      return PacketClass::Control;
    case 2:
      return PacketClass::Data;
    default:
      return PacketClass::Misc;
  }
}

constexpr bool sameAccessPoint(uint8_t leftChannel, const uint8_t* leftBssid,
                               uint8_t rightChannel,
                               const uint8_t* rightBssid) {
  if (leftChannel != rightChannel || leftBssid == nullptr ||
      rightBssid == nullptr) {
    return false;
  }
  for (uint8_t index = 0; index < 6; ++index) {
    if (leftBssid[index] != rightBssid[index]) {
      return false;
    }
  }
  return true;
}

struct FailureLogDecision {
  bool shouldLog{false};
  uint32_t suppressed{0};
};

class FailureLogLimiter {
 public:
  FailureLogDecision observe(int signature, uint32_t nowMs,
                             uint32_t intervalMs) {
    if (!hasFailure_ || signature != lastSignature_ ||
        nowMs - lastLogAtMs_ >= intervalMs) {
      const uint32_t suppressed =
          hasFailure_ && signature == lastSignature_ ? suppressed_ : 0;
      hasFailure_ = true;
      lastSignature_ = signature;
      lastLogAtMs_ = nowMs;
      suppressed_ = 0;
      FailureLogDecision decision;
      decision.shouldLog = true;
      decision.suppressed = suppressed;
      return decision;
    }
    ++suppressed_;
    return {};
  }

  void reset() {
    hasFailure_ = false;
    suppressed_ = 0;
  }

 private:
  bool hasFailure_{false};
  int lastSignature_{0};
  uint32_t lastLogAtMs_{0};
  uint32_t suppressed_{0};
};

}  // namespace defense_sniffer
