#pragma once

// Use the same phone hotspot as the Red ESP. All devices must therefore be on
// the same Wi-Fi/ESP-NOW radio channel.
#define LAB_WIFI_SSID "LAB_TUM_DEMO"
#define LAB_WIFI_PASSWORD "replace-with-hotspot-password"

// Only the backend needs an address. No attacker/victim/sniffer IP allowlist
// is required. Start FastAPI with --host 0.0.0.0 on this computer.
//
// To route through the sentinel-edge enforcement gateway (real inline frame
// dropping — see EDGE_DEMO.md), point this at the edge's host:8100 instead of
// the backend's :8000. The edge filters /ingest and passes /heartbeat through.
//   e.g. #define BACKEND_BASE_URL "http://192.168.43.100:8100"
#define BACKEND_BASE_URL "http://192.168.43.100:8000"
