#pragma once

#include <cstdint>

namespace defense_sniffer {

// Calculates a deterministic, rollover-safe blink pattern. Hardware writes are
// intentionally left to main.cpp so this class can be tested on the host.
class BlinkPattern {
 public:
  BlinkPattern(uint32_t durationMs, uint32_t toggleIntervalMs)
      : durationMs_(durationMs), toggleIntervalMs_(toggleIntervalMs) {}

  void trigger(uint32_t nowMs) {
    startedAtMs_ = nowMs;
    active_ = true;
  }

  bool update(uint32_t nowMs) {
    if (!active_) {
      return false;
    }

    const uint32_t elapsedMs = nowMs - startedAtMs_;
    if (elapsedMs >= durationMs_) {
      active_ = false;
      return false;
    }
    return ((elapsedMs / toggleIntervalMs_) % 2U) == 0U;
  }

  bool active() const { return active_; }

 private:
  uint32_t durationMs_{0};
  uint32_t toggleIntervalMs_{1};
  uint32_t startedAtMs_{0};
  bool active_{false};
};

}  // namespace defense_sniffer
