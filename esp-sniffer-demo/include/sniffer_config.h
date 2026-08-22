#pragma once

#if __has_include("lab_secrets.h")
#include "lab_secrets.h"
#else
#define LAB_WIFI_SSID "UNCONFIGURED"
#define LAB_WIFI_PASSWORD ""
#define BACKEND_BASE_URL "http://192.168.1.2:8000"
#endif

#ifndef LAB_WIFI_SSID
#error "LAB_WIFI_SSID must be defined"
#endif

#ifndef LAB_WIFI_PASSWORD
#error "LAB_WIFI_PASSWORD must be defined"
#endif

#ifndef BACKEND_BASE_URL
#error "BACKEND_BASE_URL must be defined"
#endif

constexpr unsigned long kCaptureWindowMs = 1000UL;
constexpr unsigned long kHeartbeatIntervalMs = 3000UL;
constexpr unsigned long kAlertHoldMs = 5000UL;
constexpr unsigned long kReconnectIntervalMs = 10000UL;
constexpr unsigned kCapturedFramesPerWindow = 8U;
