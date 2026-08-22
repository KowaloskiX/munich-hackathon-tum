#pragma once

// Local credentials and the target allowlist live in lab_secrets.h, which is
// deliberately ignored by git. The fallback keeps a fresh checkout buildable
// but LAB_ SSID validation prevents the traffic generator from starting.
#if __has_include("lab_secrets.h")
#include "lab_secrets.h"
#else
#define LAB_WIFI_SSID "UNCONFIGURED"
#define LAB_WIFI_PASSWORD ""
#define LAB_CONTROL_PASSWORD "change-me-now"
#endif

#ifndef LAB_WIFI_SSID
#error "LAB_WIFI_SSID must be defined"
#endif

#ifndef LAB_WIFI_PASSWORD
#error "LAB_WIFI_PASSWORD must be defined"
#endif

#ifndef LAB_CONTROL_PASSWORD
#error "LAB_CONTROL_PASSWORD must be defined"
#endif

constexpr unsigned long kArmWindowMs = 30000UL;
constexpr unsigned long kArmHoldMs = 1500UL;
constexpr uint8_t kArmButtonPin = 0U;  // BOOT button on a common ESP32 DevKit.
constexpr uint8_t kStatusLedPin = 2U;
