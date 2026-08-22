#pragma once

// Copy this file to include/secrets.h and edit the values. The local file is
// ignored by Git, so credentials are not committed accidentally.
#define SNIFFER_WIFI_SSID "CHANGE_ME"
#define SNIFFER_WIFI_PASSWORD "CHANGE_ME"

// The authorized AP being monitored. Pinning both values lets capture continue
// on the intended network even while the STA is temporarily disconnected.
#define SNIFFER_MONITORED_CHANNEL 6
#define SNIFFER_MONITORED_BSSID "aa:bb:cc:dd:ee:ff"

// Host name or IPv4 address only (without http:// and without a path).
#define SNIFFER_BACKEND_HOST "192.168.1.100"
#define SNIFFER_BACKEND_PORT 8000

// Leave empty only on an isolated demo network. Each build selects its own
// token and sends it as Authorization: Bearer <token>.
#define SNIFFER_API_TOKEN_01 ""
#define SNIFFER_API_TOKEN_02 ""
