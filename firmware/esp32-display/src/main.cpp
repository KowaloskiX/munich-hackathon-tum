#include <Arduino.h>

#include "app_config.h"
#include "backend_client.h"
#include "display_ui.h"
#include "security_state.h"
#include "touch_input.h"

namespace {

defense_hmi::SecurityState securityState;
defense_hmi::BackendClient backend(securityState);
defense_hmi::DisplayUi display;
defense_hmi::TouchInput touch;
defense_hmi::UiMode previousMode = defense_hmi::UiMode::ConfigRequired;
uint32_t buzzerOffAtMs = 0;
uint8_t demoPhase = UINT8_MAX;

void serviceDemo(uint32_t nowMs) {
  if (!app_config::kDemoMode) {
    return;
  }
  const uint8_t nextPhase = (nowMs / 8000U) % 2U;
  if (nextPhase == demoPhase) {
    return;
  }
  demoPhase = nextPhase;

  defense_hmi::SecuritySnapshot snapshot;
  snapshot.sensorsOnline = 3;
  snapshot.sensorsExpected = 3;
  snapshot.attackFramesDetected = nextPhase == 0 ? 0 : 247;
  if (nextPhase == 0) {
    snapshot.level = defense_hmi::SecurityLevel::Safe;
  } else {
    snapshot.level = defense_hmi::SecurityLevel::Attack;
    snapshot.activeAlerts = 1;
    snapshot.incidentId = "demo-incident";
    snapshot.nodeId = "esp-03";
    snapshot.attackClass = "deauth_flood";
  }
  securityState.applySnapshot(snapshot, nowMs, 30000);
}

defense_hmi::UiMode selectUiMode(uint32_t nowMs) {
  if (app_config::kDemoMode) {
    return securityState.snapshot().level == defense_hmi::SecurityLevel::Attack
               ? defense_hmi::UiMode::Attack
               : defense_hmi::UiMode::Safe;
  }
  if (!app_config::kHasLocalConfig) {
    return defense_hmi::UiMode::ConfigRequired;
  }
  // A known attack remains visible even if its telemetry TTL expires or Wi-Fi
  // disappears. Only a fresh, fleet-healthy SAFE snapshot clears this latch.
  if (securityState.hasBackendData() &&
      securityState.snapshot().level == defense_hmi::SecurityLevel::Attack) {
    return defense_hmi::UiMode::Attack;
  }
  if (!backend.wifiConnected()) {
    return defense_hmi::UiMode::Connecting;
  }
  if (!securityState.isFresh()) {
    return defense_hmi::UiMode::NoData;
  }

  switch (securityState.snapshot().level) {
    case defense_hmi::SecurityLevel::Safe:
      return defense_hmi::UiMode::Safe;
    case defense_hmi::SecurityLevel::Attack:
      return defense_hmi::UiMode::Attack;
    case defense_hmi::SecurityLevel::Unknown:
    default:
      return defense_hmi::UiMode::NoData;
  }
}

void startBuzzerPulse(uint32_t nowMs) {
  if (HMI_BUZZER_PIN < 0) {
    return;
  }
  digitalWrite(HMI_BUZZER_PIN, HMI_BUZZER_ACTIVE_HIGH ? HIGH : LOW);
  buzzerOffAtMs = nowMs + app_config::kBuzzerPulseMs;
}

void serviceBuzzer(uint32_t nowMs) {
  if (HMI_BUZZER_PIN < 0 || buzzerOffAtMs == 0) {
    return;
  }
  if (static_cast<int32_t>(nowMs - buzzerOffAtMs) >= 0) {
    digitalWrite(HMI_BUZZER_PIN, HMI_BUZZER_ACTIVE_HIGH ? LOW : HIGH);
    buzzerOffAtMs = 0;
  }
}

}  // namespace

void setup() {
  Serial.begin(115200);
  delay(100);
  Serial.printf("\nDefense HMI firmware %s\n", app_config::kFirmwareVersion);
  Serial.printf("[system] free heap: %u B, PSRAM: %u B\n", ESP.getFreeHeap(),
                ESP.getPsramSize());

  if (HMI_BUZZER_PIN >= 0) {
    pinMode(HMI_BUZZER_PIN, OUTPUT);
    digitalWrite(HMI_BUZZER_PIN, HMI_BUZZER_ACTIVE_HIGH ? LOW : HIGH);
  }

  display.begin();
  touch.begin();
  if (!app_config::kDemoMode) {
    backend.begin();
  }
  const uint32_t nowMs = millis();
  serviceDemo(nowMs);
  securityState.tick(nowMs);
  display.render(selectUiMode(nowMs), securityState, false, false, nowMs, true);
}

void loop() {
  const uint32_t loopStartedAtMs = millis();
  if (app_config::kDemoMode) {
    serviceDemo(loopStartedAtMs);
  } else {
    backend.loop(loopStartedAtMs);
  }

  // Network calls can consume most of the HTTP timeout, so freshness uses a
  // timestamp sampled after BackendClient::loop(), not before it.
  const uint32_t nowMs = millis();
  securityState.tick(nowMs);
  const defense_hmi::UiMode mode = selectUiMode(nowMs);
  bool forceRender = false;
  if (touch.consumeTap(nowMs)) {
    display.toggleDetails();
    forceRender = true;
  }
  if (mode == defense_hmi::UiMode::Attack &&
      previousMode != defense_hmi::UiMode::Attack) {
    startBuzzerPulse(nowMs);
  }
  previousMode = mode;

  display.render(mode, securityState,
                 !app_config::kDemoMode && backend.wifiConnected(),
                 !app_config::kDemoMode && backend.websocketConnected(),
                 nowMs, forceRender);
  serviceBuzzer(nowMs);
  delay(5);
}
