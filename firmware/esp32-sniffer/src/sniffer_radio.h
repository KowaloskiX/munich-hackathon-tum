#pragma once

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#include "anomaly_detector.h"

namespace defense_sniffer {

struct CapturedFrame {
  uint32_t observedAtMs{0};
  uint32_t observedAtUs{0};
  int8_t rssi{0};
  uint8_t channel{0};
  uint8_t subtype{0};
  uint8_t bssid[6]{};
  uint8_t sender[6]{};
  uint16_t originalLength{0};
  uint16_t length{0};
  uint8_t bytes[kMaximumCapturedFrameBytes]{};
};

struct PacketTypeCounters {
  uint32_t management{0};
  uint32_t control{0};
  uint32_t data{0};
  uint32_t misc{0};
};

class SnifferRadio {
 public:
  bool begin();
  bool followAssociatedAccessPoint(uint8_t channel, const uint8_t* bssid);
  bool receive(CapturedFrame& frame);
  uint32_t managementFramesSeen() const;
  PacketTypeCounters packetTypeCounters() const;
  uint32_t captureFramesDropped() const;
  bool captureHealthy(uint32_t nowMs, uint32_t maximumAgeMs) const;
  bool matchesTarget(const CapturedFrame& frame) const;
  uint8_t targetChannel() const;
  void copyTargetBssid(uint8_t* output) const;
  bool running() const;

 private:
  bool running_{false};
  uint8_t targetChannel_{0};
  uint8_t targetBssid_[6]{};
};

}  // namespace defense_sniffer
