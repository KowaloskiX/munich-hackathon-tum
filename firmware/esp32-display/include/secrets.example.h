#pragma once

// Copy this file to include/secrets.h and edit the values. secrets.h is ignored
// by Git, so Wi-Fi credentials do not accidentally end up in the repository.
#define HMI_WIFI_SSID "CHANGE_ME"
#define HMI_WIFI_PASSWORD "CHANGE_ME"

// Host name or IPv4 address only (without http:// and without a path).
#define HMI_BACKEND_HOST "192.168.1.100"
#define HMI_BACKEND_PORT 8000

// The bundled mock is HTTP-only, so leave this at 0 for the first bench test.
// Set to 1 only when the backend implements the documented SYSTEM_STATUS feed.
#define HMI_ENABLE_WEBSOCKET 0

// Leave empty for the local demo backend. Use a unique device token outside an
// isolated demo network.
#define HMI_API_TOKEN ""
