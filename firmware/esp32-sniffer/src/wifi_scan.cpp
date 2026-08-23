#include <Arduino.h>
#include <WiFi.h>

#include "app_config.h"

namespace {

void scanTarget() {
  Serial.printf("[scan] looking for SSID %s\n", app_config::kWifiSsid);
  const int count = WiFi.scanNetworks(false, true);
  bool found = false;
  for (int index = 0; index < count; ++index) {
    if (WiFi.SSID(index) != app_config::kWifiSsid) {
      continue;
    }
    found = true;
    Serial.printf("[target] ssid=%s bssid=%s channel=%d rssi=%d\n",
                  app_config::kWifiSsid, WiFi.BSSIDstr(index).c_str(),
                  WiFi.channel(index), WiFi.RSSI(index));
  }
  if (!found) {
    Serial.println("[scan] target not found; retrying in 5 seconds");
  }
  WiFi.scanDelete();
}

}  // namespace

void setup() {
  Serial.begin(115200);
  delay(500);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(false, false);
}

void loop() {
  scanTarget();
  delay(5000);
}
