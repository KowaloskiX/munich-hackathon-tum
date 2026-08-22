#include "reporter.h"

#include <algorithm>
#include <limits>

#include <esp_system.h>

#include "app_config.h"

namespace defense_sniffer {
namespace {

bool deadlineReached(uint32_t nowMs, uint32_t deadlineMs) {
  return static_cast<int32_t>(nowMs - deadlineMs) >= 0;
}

uint32_t saturatedAdd(uint32_t left, uint32_t right) {
  const uint64_t sum = static_cast<uint64_t>(left) + right;
  return static_cast<uint32_t>(std::min<uint64_t>(
      sum, std::numeric_limits<uint32_t>::max()));
}

}  // namespace

Reporter::Reporter(const SnifferRadio& radio) : radio_(radio) {}

bool Reporter::begin() {
  if constexpr (app_config::kTelemetryEnabled) {
    alertQueue_ =
        xQueueCreate(app_config::kReportQueueDepth, sizeof(QueuedAlert));
    if (alertQueue_ == nullptr) {
      Serial.println("[reporter] cannot allocate alert queue");
      return false;
    }
  }

  const BaseType_t created =
      xTaskCreate(taskEntry, "backend-reporter", 12288, this, 1, &task_);
  if (created != pdPASS) {
    Serial.println("[reporter] cannot create network task");
    vQueueDelete(alertQueue_);
    alertQueue_ = nullptr;
    return false;
  }
  return true;
}

bool Reporter::queueAlert(const AnomalyReport& report, uint32_t nowMs) {
  portENTER_CRITICAL(&stateMux_);
  alertStateSet_ = true;
  alertStartedAtMs_ = nowMs;
  heartbeatUrgent_ = true;
  attackFramesDetected_ =
      saturatedAdd(attackFramesDetected_, report.countInWindow);
  portEXIT_CRITICAL(&stateMux_);

  if constexpr (!app_config::kTelemetryEnabled) {
    return true;
  }

  if (alertQueue_ == nullptr) {
    return false;
  }

  QueuedAlert queued;
  queued.report = report;
  queued.queueDrops = totalQueueDrops();
  if (xQueueSend(alertQueue_, &queued, 0) == pdTRUE) {
    return true;
  }

  recordDroppedReport();
  Serial.println("[reporter] alert queue full; report dropped");
  return false;
}

uint32_t Reporter::reportsDropped() const {
  portENTER_CRITICAL(&stateMux_);
  const uint32_t value = reportsDropped_;
  portEXIT_CRITICAL(&stateMux_);
  return value;
}

bool Reporter::localAlertActive(uint32_t nowMs) {
  portENTER_CRITICAL(&stateMux_);
  bool active = alertStateSet_ &&
                nowMs - alertStartedAtMs_ < app_config::kAlertStateHoldMs;
  if (!active) {
    alertStateSet_ = false;
  }
  portEXIT_CRITICAL(&stateMux_);
  return active;
}

bool Reporter::takeHeartbeatUrgent() {
  portENTER_CRITICAL(&stateMux_);
  const bool value = heartbeatUrgent_;
  heartbeatUrgent_ = false;
  portEXIT_CRITICAL(&stateMux_);
  return value;
}

uint32_t Reporter::attackFramesDetected() const {
  portENTER_CRITICAL(&stateMux_);
  const uint32_t value = attackFramesDetected_;
  portEXIT_CRITICAL(&stateMux_);
  return value;
}

uint32_t Reporter::totalQueueDrops() const {
  return saturatedAdd(radio_.captureFramesDropped(), reportsDropped());
}

void Reporter::recordDroppedReport() {
  portENTER_CRITICAL(&stateMux_);
  if (reportsDropped_ < std::numeric_limits<uint32_t>::max()) {
    ++reportsDropped_;
  }
  portEXIT_CRITICAL(&stateMux_);
}

uint32_t Reporter::retryDelayMs(uint8_t attempt) const {
  const uint8_t shift = std::min<uint8_t>(attempt, 4);
  const uint32_t delay = app_config::kReportRetryBaseMs << shift;
  const uint32_t bounded =
      std::min(delay, app_config::kReportRetryMaximumMs);
  return bounded + (esp_random() % 251U);
}

void Reporter::taskEntry(void* context) {
  static_cast<Reporter*>(context)->run();
}

void Reporter::run() {
  backend_.begin();

  QueuedAlert pending;
  bool hasPending = false;
  uint8_t retryAttempt = 0;
  uint32_t retryAtMs = 0;
  AnomalyEnvelope pendingEnvelope;
  uint32_t nextHeartbeatAtMs = 0;
  uint32_t connectedAtMs = 0;
  bool wasConnected = false;

  while (true) {
    const uint32_t nowMs = millis();
    backend_.loop(nowMs);
    const bool connected = backend_.wifiConnected();
    if (connected && !wasConnected) {
      connectedAtMs = nowMs;
      nextHeartbeatAtMs = nowMs + app_config::kHeartbeatPhaseMs;
    }
    wasConnected = connected;

    if (app_config::kTelemetryEnabled && !hasPending && alertQueue_ != nullptr &&
        xQueueReceive(alertQueue_, &pending, 0) == pdTRUE) {
      hasPending = true;
      retryAttempt = 0;
      retryAtMs = nowMs;
      pendingEnvelope = AnomalyEnvelope{};
      pendingEnvelope.sequence = backend_.nextSequence();
      pendingEnvelope.uptimeMs = pending.report.detectedAtMs;
      pendingEnvelope.queueDrops = pending.queueDrops;
      backend_.makeEventId(pendingEnvelope.sequence, pendingEnvelope.eventId,
                           sizeof(pendingEnvelope.eventId));
    }

    if (hasPending && connected &&
        deadlineReached(nowMs, retryAtMs)) {
      const PostResult result =
          backend_.postAnomaly(pending.report, pendingEnvelope);
      ++retryAttempt;
      if (result == PostResult::Success) {
        Serial.printf("[reporter] sent %s (%lu frames)\n",
                      attackKindName(pending.report.kind),
                      static_cast<unsigned long>(
                          pending.report.countInWindow));
        hasPending = false;
        retryAttempt = 0;
      } else if (result == PostResult::PermanentFailure ||
                 retryAttempt >= app_config::kReportMaximumAttempts) {
        Serial.printf("[reporter] discarded event %s after %u attempt(s)\n",
                      pendingEnvelope.eventId, retryAttempt);
        recordDroppedReport();
        hasPending = false;
        retryAttempt = 0;
      } else {
        retryAtMs = millis() + retryDelayMs(retryAttempt - 1U);
      }
    }

    const uint32_t afterReportMs = millis();
    const bool urgent = connected && !hasPending ? takeHeartbeatUrgent() : false;
    if (app_config::kTelemetryEnabled && connected && !hasPending &&
        (urgent || deadlineReached(afterReportMs, nextHeartbeatAtMs))) {
      const bool alertActive = localAlertActive(afterReportMs);
      const bool baselineReady =
          radio_.running() &&
          radio_.captureHealthy(afterReportMs,
                                app_config::kCaptureFreshnessMs) &&
          afterReportMs - connectedAtMs >= app_config::kDetectionWindowMs;
      HeartbeatSnapshot snapshot;
      snapshot.sequence = backend_.nextSequence();
      snapshot.uptimeMs = afterReportMs;
      snapshot.threatLevel =
          alertActive ? "ALERT" : (baselineReady ? "NORMAL" : "UNKNOWN");
      snapshot.activeAlerts = alertActive ? 1 : 0;
      snapshot.attackFramesDetected = attackFramesDetected();
      snapshot.policyState = radio_.running() ? "APPLIED" : "ERROR";
      snapshot.framesSeen = radio_.managementFramesSeen();
      snapshot.queueDrops = totalQueueDrops();
      const PostResult result = backend_.postHeartbeat(snapshot);
      if constexpr (app_config::kSerialTrace) {
        Serial.printf(
            "[heartbeat] seq=%llu threat=%s frames=%lu drops=%lu result=%s\n",
            static_cast<unsigned long long>(snapshot.sequence),
            snapshot.threatLevel,
            static_cast<unsigned long>(snapshot.framesSeen),
            static_cast<unsigned long>(snapshot.queueDrops),
            result == PostResult::Success
                ? "ok"
                : (result == PostResult::RetryableFailure ? "retry" : "drop"));
      }
      const uint32_t nextDelay =
          result == PostResult::RetryableFailure
              ? 1000U
              : app_config::kHeartbeatIntervalMs;
      nextHeartbeatAtMs = millis() + nextDelay;
    }

    vTaskDelay(pdMS_TO_TICKS(20));
  }
}

}  // namespace defense_sniffer
