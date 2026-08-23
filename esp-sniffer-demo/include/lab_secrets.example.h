#pragma once

// Use the same phone hotspot as the Red ESP. All devices must therefore be on
// the same Wi-Fi/ESP-NOW radio channel.
#define LAB_WIFI_SSID "LAB_TUM_DEMO"
#define LAB_WIFI_PASSWORD "replace-with-hotspot-password"

// Route through the sentinel-edge enforcement gateway (:8100) so frames flow
// ESP -> edge -> backend and the edge can really drop enforced frames on
// /ingest (it passes /heartbeat straight through). See EDGE_DEMO.md.
// Run the edge with --host 0.0.0.0 on this computer, backend behind it.
// For a direct, no-enforcement run, point this at the backend's :8000 instead.
#define BACKEND_BASE_URL "http://192.168.43.100:8100"
