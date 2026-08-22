#pragma once

#include <Arduino.h>

#if __has_include("secrets.h")
#include "secrets.h"
#define HMI_HAS_LOCAL_CONFIG 1
#else
#include "secrets.example.h"
#define HMI_HAS_LOCAL_CONFIG 0
#endif

#ifndef HMI_FIRMWARE_VERSION
#define HMI_FIRMWARE_VERSION "dev"
#endif

#ifndef HMI_DISPLAY_KIND
#define HMI_DISPLAY_KIND 1
#endif

#ifndef HMI_ROUND_DISPLAY
#define HMI_ROUND_DISPLAY 0
#endif

#ifndef HMI_TOUCH_ENABLED
#define HMI_TOUCH_ENABLED 0
#endif

#ifndef HMI_DEMO_MODE
#define HMI_DEMO_MODE 0
#endif

#ifndef HMI_STATUS_PATH
#define HMI_STATUS_PATH "/v1/hmi/status"
#endif

#ifndef HMI_WEBSOCKET_PATH
#define HMI_WEBSOCKET_PATH "/live"
#endif

#ifndef HMI_NODE_ID
#define HMI_NODE_ID "hmi-01"
#endif

#ifndef HMI_ENABLE_WEBSOCKET
#define HMI_ENABLE_WEBSOCKET 0
#endif

#ifndef HMI_BUZZER_PIN
#define HMI_BUZZER_PIN -1
#endif

#ifndef HMI_BUZZER_ACTIVE_HIGH
#define HMI_BUZZER_ACTIVE_HIGH 1
#endif

namespace app_config {

inline constexpr bool kHasLocalConfig = HMI_HAS_LOCAL_CONFIG == 1;
inline constexpr bool kDemoMode = HMI_DEMO_MODE == 1;
inline constexpr bool kWebSocketEnabled = HMI_ENABLE_WEBSOCKET == 1;
inline constexpr char kWifiSsid[] = HMI_WIFI_SSID;
inline constexpr char kWifiPassword[] = HMI_WIFI_PASSWORD;
inline constexpr char kBackendHost[] = HMI_BACKEND_HOST;
inline constexpr uint16_t kBackendPort = HMI_BACKEND_PORT;
inline constexpr char kApiToken[] = HMI_API_TOKEN;
inline constexpr char kStatusPath[] = HMI_STATUS_PATH;
inline constexpr char kWebSocketPath[] = HMI_WEBSOCKET_PATH;
inline constexpr char kNodeId[] = HMI_NODE_ID;
inline constexpr char kFirmwareVersion[] = HMI_FIRMWARE_VERSION;

inline constexpr uint32_t kStatusPollIntervalMs = 3000;
inline constexpr uint32_t kDefaultStatusTtlMs = 10000;
inline constexpr uint32_t kMinimumAcceptedTtlMs = 500;
inline constexpr uint32_t kMaximumAcceptedTtlMs = 30000;
inline constexpr uint32_t kHttpTimeoutMs = 800;
inline constexpr uint32_t kWifiRetryIntervalMs = 10000;
inline constexpr uint32_t kBuzzerPulseMs = 180;
inline constexpr size_t kMaximumJsonBytes = 4096;

}  // namespace app_config
