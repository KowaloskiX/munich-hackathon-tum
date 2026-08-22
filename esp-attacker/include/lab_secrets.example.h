#pragma once

// The firmware refuses to run scenarios unless the SSID starts with LAB_.
#define LAB_WIFI_SSID "LAB_TUM_DEMO"
#define LAB_WIFI_PASSWORD "replace-with-lab-password"

// Used both for the Red ESP access point and HTTP Basic authentication.
// Use at least 12 characters and do not reuse the lab Wi-Fi password.
#define LAB_CONTROL_PASSWORD "replace-control-password"

// No victim IP or MAC addresses are needed. Synthetic demo frames are sent as
// a marked ESP-NOW broadcast on the channel selected by this hotspot.
