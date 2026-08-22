#pragma once

#include <cstddef>
#include <cstdint>

namespace defense_sniffer {

inline constexpr size_t kMaximumFrameSamples = 6;
inline constexpr size_t kMaximumCapturedFrameBytes = 192;
inline constexpr size_t kMaximumTrackedFramesPerWindow = 256;

enum class AttackKind : uint8_t {
  DeauthFlood = 0,
  DisassocFlood,
  AuthFlood,
};

const char* attackKindName(AttackKind kind);

struct DetectorConfig {
  uint32_t windowMs{1000};
  uint32_t cooldownMs{5000};
  uint16_t deauthThreshold{20};
  uint16_t disassocThreshold{20};
  uint16_t authThreshold{50};
};

struct FrameObservation {
  uint32_t observedAtMs{0};
  uint32_t observedAtUs{0};
  int8_t rssi{0};
  uint8_t channel{0};
  uint8_t subtype{0};
  const uint8_t* bssid{nullptr};
  const uint8_t* sender{nullptr};
  const uint8_t* bytes{nullptr};
  size_t length{0};
  size_t originalLength{0};
};

struct FrameSample {
  uint32_t observedAtUs{0};
  int8_t rssi{0};
  uint16_t originalLength{0};
  uint16_t length{0};
  uint8_t bytes[kMaximumCapturedFrameBytes]{};
};

struct AnomalyReport {
  AttackKind kind{AttackKind::DeauthFlood};
  uint32_t detectedAtMs{0};
  uint32_t countInWindow{0};
  uint32_t windowMs{0};
  uint8_t channel{0};
  uint8_t subtype{0};
  uint8_t bssid[6]{};
  uint8_t sender[6]{};
  uint8_t sampleCount{0};
  FrameSample samples[kMaximumFrameSamples]{};
};

class MgmtFloodDetector {
 public:
  explicit MgmtFloodDetector(const DetectorConfig& config = DetectorConfig{});

  // Returns true once for an accepted detection and copies a self-contained
  // report into output. The class performs no allocation.
  bool observe(const FrameObservation& observation, AnomalyReport& output);
  void reset();

 private:
  static constexpr size_t kRuleCount = 3;
  static constexpr size_t kBucketsPerRule = 4;

  struct RuleState {
    bool keySet{false};
    bool hasPreviousAlert{false};
    uint32_t lastAlertAtMs{0};
    uint32_t lastSeenAtMs{0};
    uint8_t channel{0};
    uint8_t bssid[6]{};
    uint8_t sender[6]{};
    uint16_t timestampStart{0};
    uint16_t timestampCount{0};
    uint32_t timestampsMs[kMaximumTrackedFramesPerWindow]{};
    uint8_t sampleCount{0};
    uint8_t sampleWriteIndex{0};
    FrameSample samples[kMaximumFrameSamples]{};
  };

  int ruleIndexForSubtype(uint8_t subtype) const;
  uint16_t thresholdForRule(size_t index) const;
  AttackKind kindForRule(size_t index) const;
  RuleState& stateForObservation(size_t ruleIndex,
                                 const FrameObservation& observation);
  bool sameKey(const RuleState& state,
               const FrameObservation& observation) const;
  void assignKey(RuleState& state, const FrameObservation& observation);
  void evictExpiredTimestamps(RuleState& state, uint32_t nowMs);
  void appendTimestamp(RuleState& state, uint32_t nowMs);
  void appendSample(RuleState& state, const FrameObservation& observation);

  DetectorConfig config_;
  RuleState states_[kRuleCount][kBucketsPerRule]{};
};

}  // namespace defense_sniffer
