#pragma once

#include <cstdint>
#include <string>

namespace defense_hmi {

enum class SecurityLevel : uint8_t {
  Unknown = 0,
  Safe,
  Attack,
};

struct SecuritySnapshot {
  SecurityLevel level{SecurityLevel::Unknown};
  uint32_t activeAlerts{0};
  uint32_t sensorsOnline{0};
  uint32_t sensorsExpected{0};
  uint32_t attackFramesDetected{0};
  std::string incidentId;
  std::string nodeId;
  std::string attackClass;
};

// Stores the last backend view using only monotonic device time. In particular,
// SAFE expires to UNKNOWN if fresh backend data stops arriving.
class SecurityState {
 public:
  void applySnapshot(const SecuritySnapshot& snapshot, uint32_t nowMs,
                     uint32_t validForMs);
  void tick(uint32_t nowMs);

  bool hasBackendData() const;
  bool isFresh() const;
  uint32_t dataAgeMs(uint32_t nowMs) const;
  uint32_t attackDurationMs(uint32_t nowMs) const;
  uint32_t revision() const;
  const SecuritySnapshot& snapshot() const;

 private:
  static uint32_t sanitizeTtl(uint32_t validForMs);

  SecuritySnapshot snapshot_{};
  bool hasBackendData_{false};
  bool fresh_{false};
  uint32_t receivedAtMs_{0};
  uint32_t validForMs_{0};
  uint32_t attackStartedAtMs_{0};
  uint32_t revision_{0};
};

}  // namespace defense_hmi
