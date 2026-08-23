#pragma once

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>

#include "anomaly_detector.h"
#include "backend_client.h"
#include "sniffer_radio.h"

namespace defense_sniffer {

class Reporter {
 public:
  explicit Reporter(const SnifferRadio& radio);

  bool begin();
  bool queueAlert(const AnomalyReport& report, uint32_t nowMs);
  uint32_t reportsDropped() const;

 private:
  struct QueuedAlert {
    AnomalyReport report;
    uint32_t queueDrops{0};
  };

  static void taskEntry(void* context);
  void run();
  bool localAlertActive(uint32_t nowMs);
  bool takeHeartbeatUrgent();
  uint32_t attackFramesDetected() const;
  uint32_t totalQueueDrops() const;
  void recordDroppedReport();
  uint32_t retryDelayMs(uint8_t attempt) const;

  const SnifferRadio& radio_;
  BackendClient backend_;
  QueueHandle_t alertQueue_{nullptr};
  TaskHandle_t task_{nullptr};

  mutable portMUX_TYPE stateMux_ = portMUX_INITIALIZER_UNLOCKED;
  volatile bool alertStateSet_{false};
  volatile bool heartbeatUrgent_{false};
  volatile uint32_t alertStartedAtMs_{0};
  volatile uint32_t attackFramesDetected_{0};
  volatile uint32_t reportsDropped_{0};
};

}  // namespace defense_sniffer
