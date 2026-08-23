#pragma once

#include <Arduino.h>

#if __has_include("secrets.h")
#include "secrets.h"
#define SNIFFER_HAS_LOCAL_CONFIG 1
#else
#include "secrets.example.h"
#define SNIFFER_HAS_LOCAL_CONFIG 0
#endif

#ifndef SNIFFER_NODE_ID
#define SNIFFER_NODE_ID "esp-sniffer-dev"
#endif

#ifndef SNIFFER_FIRMWARE_VERSION
#define SNIFFER_FIRMWARE_VERSION "dev"
#endif

#ifndef SNIFFER_INGEST_PATH
#define SNIFFER_INGEST_PATH "/ingest"
#endif

#ifndef SNIFFER_HEARTBEAT_PATH
#define SNIFFER_HEARTBEAT_PATH "/heartbeat"
#endif

#ifndef SNIFFER_LAMP_PIN
#define SNIFFER_LAMP_PIN 2
#endif

#ifndef SNIFFER_LAMP_ACTIVE_HIGH
#define SNIFFER_LAMP_ACTIVE_HIGH 1
#endif

#ifndef SNIFFER_HEARTBEAT_PHASE_MS
#define SNIFFER_HEARTBEAT_PHASE_MS 0
#endif

#ifndef SNIFFER_SERIAL_TRACE
#define SNIFFER_SERIAL_TRACE 0
#endif

#ifndef SNIFFER_SERIAL_TRACE_HEX_BYTES
#define SNIFFER_SERIAL_TRACE_HEX_BYTES 32
#endif

#ifndef SNIFFER_TELEMETRY_ENABLED
#define SNIFFER_TELEMETRY_ENABLED 1
#endif

#ifndef SNIFFER_SERIAL_SELF_TEST
#define SNIFFER_SERIAL_SELF_TEST 0
#endif

#ifndef SNIFFER_API_TOKEN
#define SNIFFER_API_TOKEN ""
#endif

#ifndef SNIFFER_MONITORED_CHANNEL
#define SNIFFER_MONITORED_CHANNEL 0
#endif

#ifndef SNIFFER_MONITORED_BSSID
#define SNIFFER_MONITORED_BSSID ""
#endif

namespace app_config {

inline constexpr bool kHasLocalConfig = SNIFFER_HAS_LOCAL_CONFIG == 1;
inline constexpr char kWifiSsid[] = SNIFFER_WIFI_SSID;
inline constexpr char kWifiPassword[] = SNIFFER_WIFI_PASSWORD;
inline constexpr uint8_t kMonitoredChannel = SNIFFER_MONITORED_CHANNEL;
inline constexpr char kMonitoredBssid[] = SNIFFER_MONITORED_BSSID;
inline constexpr char kBackendHost[] = SNIFFER_BACKEND_HOST;
inline constexpr uint16_t kBackendPort = SNIFFER_BACKEND_PORT;
inline constexpr char kApiToken[] = SNIFFER_API_TOKEN;
inline constexpr char kIngestPath[] = SNIFFER_INGEST_PATH;
inline constexpr char kHeartbeatPath[] = SNIFFER_HEARTBEAT_PATH;
inline constexpr char kNodeId[] = SNIFFER_NODE_ID;
inline constexpr char kFirmwareVersion[] = SNIFFER_FIRMWARE_VERSION;

inline constexpr int kLampPin = SNIFFER_LAMP_PIN;
inline constexpr bool kLampActiveHigh = SNIFFER_LAMP_ACTIVE_HIGH == 1;
inline constexpr uint32_t kLampDurationMs = 4000;
inline constexpr uint32_t kLampToggleIntervalMs = 250;

inline constexpr uint32_t kDetectionWindowMs = 1000;
inline constexpr uint32_t kDetectionCooldownMs = 5000;
inline constexpr uint16_t kDeauthThreshold = 20;
inline constexpr uint16_t kDisassocThreshold = 20;
inline constexpr uint16_t kAuthThreshold = 50;
inline constexpr uint16_t kAssociationThreshold = 20;
inline constexpr char kPolicyId[] = "builtin-baseline-v1";
inline constexpr uint32_t kPolicyVersion = 1;

inline constexpr uint32_t kHeartbeatIntervalMs = 3000;
inline constexpr uint32_t kHeartbeatPhaseMs = SNIFFER_HEARTBEAT_PHASE_MS;
inline constexpr bool kSerialTrace = SNIFFER_SERIAL_TRACE == 1;
inline constexpr bool kTelemetryEnabled = SNIFFER_TELEMETRY_ENABLED == 1;
inline constexpr bool kSerialSelfTest = SNIFFER_SERIAL_SELF_TEST == 1;
inline constexpr size_t kSerialTraceHexBytes = SNIFFER_SERIAL_TRACE_HEX_BYTES;
inline constexpr uint32_t kSerialStatsIntervalMs = 1000;
inline constexpr uint8_t kTestMulticastAddress[4] = {239, 255, 77, 77};
inline constexpr uint16_t kTestMulticastPort = 37777;
inline constexpr uint32_t kAlertStateHoldMs = 10000;
inline constexpr uint32_t kCaptureFreshnessMs = 3000;
inline constexpr uint32_t kWifiRetryIntervalMs = 10000;
inline constexpr uint32_t kHttpTimeoutMs = 1000;
inline constexpr uint32_t kHttpFailureLogIntervalMs = 10000;
inline constexpr uint32_t kReportRetryBaseMs = 1000;
inline constexpr uint32_t kReportRetryMaximumMs = 15000;
// One retry keeps the worst-case report budget below the 10 s liveness window.
inline constexpr uint8_t kReportMaximumAttempts = 2;
inline constexpr size_t kMaximumJsonBytes = 4096;
inline constexpr size_t kDeauthQueueDepth = 32;
inline constexpr size_t kDisassocQueueDepth = 32;
inline constexpr size_t kAuthQueueDepth = 64;
inline constexpr size_t kMaximumFramesProcessedPerLoop =
    kDeauthQueueDepth + kDisassocQueueDepth + kAuthQueueDepth;
inline constexpr size_t kReportQueueDepth = 6;

static_assert(kHeartbeatIntervalMs < 10000,
              "heartbeat must arrive before the backend liveness timeout");
static_assert(kLampToggleIntervalMs > 0,
              "lamp toggle interval must be positive");

}  // namespace app_config
