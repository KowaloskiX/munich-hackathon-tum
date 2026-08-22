#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Arduino.h>
#include <WiFi.h>
#include <Wire.h>
#include <esp_now.h>

#include <cstdint>
#include <cstring>

#include "demo_protocol.h"
#include "oled_config.h"

namespace {

struct ReceivedPacket {
    std::uint16_t length;
    std::uint8_t data[demo_protocol::kMaxPacketSize];
};

Adafruit_SSD1306 display(kOledWidth, kOledHeight, &Wire, kOledResetPin);
QueueHandle_t receive_queue = nullptr;
bool display_ready = false;
bool esp_now_ready = false;
demo_protocol::Scenario last_scenario = demo_protocol::Scenario::deauth_flood;
std::uint32_t last_attack_ms = 0U;
std::uint32_t rate_window_started_ms = 0U;
std::uint32_t rate_window_count = 0U;
std::uint32_t displayed_rate = 0U;
std::uint32_t last_reconnect_ms = 0U;
std::uint32_t last_render_ms = 0U;

void on_esp_now_receive(const std::uint8_t*, const std::uint8_t* data, int data_length) {
    if (receive_queue == nullptr || data == nullptr || data_length <= 0 ||
        static_cast<std::size_t>(data_length) > demo_protocol::kMaxPacketSize) {
        return;
    }
    ReceivedPacket packet{};
    packet.length = static_cast<std::uint16_t>(data_length);
    std::memcpy(packet.data, data, static_cast<std::size_t>(data_length));
    xQueueSend(receive_queue, &packet, 0U);
}

bool ensure_esp_now() {
    if (esp_now_ready) {
        return true;
    }
    if (WiFi.status() != WL_CONNECTED || esp_now_init() != ESP_OK ||
        esp_now_register_recv_cb(on_esp_now_receive) != ESP_OK) {
        return false;
    }
    esp_now_ready = true;
    Serial.println("OLED ESP-NOW receiver ready");
    return true;
}

void tick_wifi() {
    if (WiFi.status() == WL_CONNECTED) {
        ensure_esp_now();
        return;
    }
    if (millis() - last_reconnect_ms < kReconnectIntervalMs) {
        return;
    }
    last_reconnect_ms = millis();
    WiFi.begin(LAB_WIFI_SSID, LAB_WIFI_PASSWORD);
}

void process_packets() {
    ReceivedPacket packet{};
    while (receive_queue != nullptr && xQueueReceive(receive_queue, &packet, 0U) == pdTRUE) {
        demo_protocol::DecodedFrame decoded{};
        if (!demo_protocol::decode(packet.data, packet.length, decoded)) {
            continue;
        }
        last_scenario = decoded.scenario;
        last_attack_ms = millis();
        rate_window_count += decoded.logical_count;
    }
    if (millis() - rate_window_started_ms >= 1000U) {
        displayed_rate = rate_window_count;
        rate_window_count = 0U;
        rate_window_started_ms = millis();
    }
}

const char* short_scenario_name(demo_protocol::Scenario scenario) {
    if (scenario == demo_protocol::Scenario::deauth_flood) {
        return "DEAUTH FLOOD";
    }
    if (scenario == demo_protocol::Scenario::traffic_spike) {
        return "TRAFFIC SPIKE";
    }
    if (scenario == demo_protocol::Scenario::sequence_replay) {
        return "SEQ REPLAY";
    }
    if (scenario == demo_protocol::Scenario::sequence_jump) {
        return "SEQ JUMP";
    }
    if (scenario == demo_protocol::Scenario::identity_churn) {
        return "ID CHURN";
    }
    return "BAD PAYLOAD";
}

void render() {
    if (!display_ready || millis() - last_render_ms < 200U) {
        return;
    }
    last_render_ms = millis();
    const bool alert = last_attack_ms != 0U && millis() - last_attack_ms < kAlertHoldMs;
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setTextSize(1);
    display.setCursor(0, 0);
    display.println("TUM DEFENSE / DEMO");
    display.drawLine(0, 10, 127, 10, SSD1306_WHITE);
    if (alert) {
        display.setTextSize(2);
        display.setCursor(0, 15);
        display.println("ATAK!");
        display.setTextSize(1);
        display.setCursor(0, 36);
        display.println(short_scenario_name(last_scenario));
        display.setCursor(0, 48);
        display.printf("~%lu ramek/s SIM\n", static_cast<unsigned long>(displayed_rate));
    } else {
        display.setTextSize(2);
        display.setCursor(0, 20);
        display.println("BRAK");
        display.println("ATAKU");
    }
    display.setTextSize(1);
    display.setCursor(96, 56);
    display.print(WiFi.status() == WL_CONNECTED ? "WIFI" : "OFF");
    display.display();
}

}  // namespace

void setup() {
    Serial.begin(115200);
    receive_queue = xQueueCreate(16U, sizeof(ReceivedPacket));
    Wire.begin(kOledSdaPin, kOledSclPin);
    display_ready = display.begin(SSD1306_SWITCHCAPVCC, kOledAddress);
    if (!display_ready) {
        Serial.println("SSD1306 not found at 0x3C");
    }
    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    last_reconnect_ms = millis() - kReconnectIntervalMs;
    rate_window_started_ms = millis();
    tick_wifi();
}

void loop() {
    tick_wifi();
    process_packets();
    render();
    delay(2);
}
