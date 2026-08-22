#pragma once

#if __has_include("lab_secrets.h")
#include "lab_secrets.h"
#else
#define LAB_WIFI_SSID "UNCONFIGURED"
#define LAB_WIFI_PASSWORD ""
#endif

#ifndef LAB_WIFI_SSID
#error "LAB_WIFI_SSID must be defined"
#endif

#ifndef LAB_WIFI_PASSWORD
#error "LAB_WIFI_PASSWORD must be defined"
#endif

constexpr int kOledWidth = 128;
constexpr int kOledHeight = 64;
constexpr int kOledResetPin = -1;
constexpr std::uint8_t kOledAddress = 0x3CU;
constexpr int kOledSdaPin = 21;
constexpr int kOledSclPin = 22;
constexpr unsigned long kAlertHoldMs = 5000UL;
constexpr unsigned long kReconnectIntervalMs = 10000UL;
