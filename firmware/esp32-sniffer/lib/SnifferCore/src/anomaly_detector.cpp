#include "anomaly_detector.h"

#include <algorithm>
#include <cstring>

namespace defense_sniffer {
namespace {

constexpr uint8_t kDisassocSubtype = 10;
constexpr uint8_t kAuthSubtype = 11;
constexpr uint8_t kDeauthSubtype = 12;

}  // namespace

const char* attackKindName(AttackKind kind) {
  switch (kind) {
    case AttackKind::DeauthFlood:
      return "deauth_flood";
    case AttackKind::DisassocFlood:
      return "disassoc_flood";
    case AttackKind::AuthFlood:
      return "auth_flood";
    default:
      return "unknown_mgmt_flood";
  }
}

MgmtFloodDetector::MgmtFloodDetector(const DetectorConfig& config)
    : config_(config) {}

void MgmtFloodDetector::reset() {
  for (auto& ruleStates : states_) {
    for (RuleState& state : ruleStates) {
      state = RuleState{};
    }
  }
}

int MgmtFloodDetector::ruleIndexForSubtype(uint8_t subtype) const {
  switch (subtype) {
    case kDeauthSubtype:
      return 0;
    case kDisassocSubtype:
      return 1;
    case kAuthSubtype:
      return 2;
    default:
      return -1;
  }
}

uint16_t MgmtFloodDetector::thresholdForRule(size_t index) const {
  switch (index) {
    case 0:
      return config_.deauthThreshold;
    case 1:
      return config_.disassocThreshold;
    case 2:
      return config_.authThreshold;
    default:
      return 0;
  }
}

AttackKind MgmtFloodDetector::kindForRule(size_t index) const {
  switch (index) {
    case 0:
      return AttackKind::DeauthFlood;
    case 1:
      return AttackKind::DisassocFlood;
    case 2:
      return AttackKind::AuthFlood;
    default:
      return AttackKind::DeauthFlood;
  }
}

bool MgmtFloodDetector::sameKey(
    const RuleState& state, const FrameObservation& observation) const {
  return state.keySet && state.channel == observation.channel &&
         std::memcmp(state.bssid, observation.bssid, sizeof(state.bssid)) == 0;
}

void MgmtFloodDetector::assignKey(
    RuleState& state, const FrameObservation& observation) {
  state = RuleState{};
  state.keySet = true;
  state.channel = observation.channel;
  std::memcpy(state.bssid, observation.bssid, sizeof(state.bssid));
  std::memcpy(state.sender, observation.sender, sizeof(state.sender));
}

MgmtFloodDetector::RuleState& MgmtFloodDetector::stateForObservation(
    size_t ruleIndex, const FrameObservation& observation) {
  RuleState* unused = nullptr;
  RuleState* oldest = &states_[ruleIndex][0];
  uint32_t oldestAgeMs = observation.observedAtMs - oldest->lastSeenAtMs;

  for (RuleState& state : states_[ruleIndex]) {
    if (sameKey(state, observation)) {
      return state;
    }
    if (!state.keySet && unused == nullptr) {
      unused = &state;
    }
    const uint32_t ageMs = observation.observedAtMs - state.lastSeenAtMs;
    if (ageMs > oldestAgeMs) {
      oldest = &state;
      oldestAgeMs = ageMs;
    }
  }

  RuleState& selected = unused != nullptr ? *unused : *oldest;
  assignKey(selected, observation);
  return selected;
}

void MgmtFloodDetector::evictExpiredTimestamps(RuleState& state,
                                                uint32_t nowMs) {
  while (state.timestampCount > 0) {
    const uint32_t oldest = state.timestampsMs[state.timestampStart];
    if (nowMs - oldest < config_.windowMs) {
      break;
    }
    state.timestampStart = static_cast<uint16_t>(
        (state.timestampStart + 1U) % kMaximumTrackedFramesPerWindow);
    --state.timestampCount;
  }
}

void MgmtFloodDetector::appendTimestamp(RuleState& state, uint32_t nowMs) {
  if (state.timestampCount == kMaximumTrackedFramesPerWindow) {
    state.timestampStart = static_cast<uint16_t>(
        (state.timestampStart + 1U) % kMaximumTrackedFramesPerWindow);
    --state.timestampCount;
  }
  const size_t writeIndex =
      (state.timestampStart + state.timestampCount) %
      kMaximumTrackedFramesPerWindow;
  state.timestampsMs[writeIndex] = nowMs;
  ++state.timestampCount;
}

void MgmtFloodDetector::appendSample(
    RuleState& state, const FrameObservation& observation) {
  FrameSample& sample = state.samples[state.sampleWriteIndex];
  sample = FrameSample{};
  sample.observedAtUs = observation.observedAtUs;
  sample.rssi = observation.rssi;
  sample.originalLength = static_cast<uint16_t>(std::min(
      observation.originalLength, static_cast<size_t>(UINT16_MAX)));
  sample.length = static_cast<uint16_t>(std::min(
      observation.length, static_cast<size_t>(kMaximumCapturedFrameBytes)));
  std::memcpy(sample.bytes, observation.bytes, sample.length);

  state.sampleWriteIndex = static_cast<uint8_t>(
      (state.sampleWriteIndex + 1U) % kMaximumFrameSamples);
  state.sampleCount = static_cast<uint8_t>(
      std::min<size_t>(state.sampleCount + 1U, kMaximumFrameSamples));
}

bool MgmtFloodDetector::observe(const FrameObservation& observation,
                                AnomalyReport& output) {
  const int ruleIndex = ruleIndexForSubtype(observation.subtype);
  if (ruleIndex < 0 || observation.bytes == nullptr ||
      observation.bssid == nullptr || observation.sender == nullptr ||
      observation.length < 24 || config_.windowMs == 0) {
    return false;
  }

  const size_t index = static_cast<size_t>(ruleIndex);
  const uint16_t threshold = thresholdForRule(index);
  if (threshold == 0) {
    return false;
  }

  RuleState& state = stateForObservation(index, observation);
  evictExpiredTimestamps(state, observation.observedAtMs);
  appendTimestamp(state, observation.observedAtMs);
  state.lastSeenAtMs = observation.observedAtMs;
  appendSample(state, observation);

  const bool cooldownElapsed =
      !state.hasPreviousAlert ||
      observation.observedAtMs - state.lastAlertAtMs >= config_.cooldownMs;
  if (state.timestampCount < threshold || !cooldownElapsed) {
    return false;
  }

  state.hasPreviousAlert = true;
  state.lastAlertAtMs = observation.observedAtMs;

  output = AnomalyReport{};
  output.kind = kindForRule(index);
  output.detectedAtMs = observation.observedAtMs;
  output.countInWindow = state.timestampCount;
  output.windowMs = config_.windowMs;
  output.channel = state.channel;
  output.subtype = observation.subtype;
  std::memcpy(output.bssid, state.bssid, sizeof(output.bssid));
  std::memcpy(output.sender, state.sender, sizeof(output.sender));
  output.sampleCount = state.sampleCount;
  const size_t firstSample =
      state.sampleCount < kMaximumFrameSamples ? 0 : state.sampleWriteIndex;
  for (size_t sampleIndex = 0; sampleIndex < state.sampleCount; ++sampleIndex) {
    const size_t sourceIndex =
        (firstSample + sampleIndex) % kMaximumFrameSamples;
    output.samples[sampleIndex] = state.samples[sourceIndex];
  }
  return true;
}

}  // namespace defense_sniffer
