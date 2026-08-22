#include <Arduino.h>
#include <HTTPClient.h>
#include <WiFi.h>
#include <esp_now.h>

#include <cstdint>
#include <cstring>
#include <ctime>

#include "demo_protocol.h"
#include "sniffer_config.h"

namespace {

struct ReceivedPacket {
    std::uint16_t length;
    std::uint8_t data[demo_protocol::kMaxPacketSize];
};

struct CaptureWindow {
    bool active;
    demo_protocol::Scenario scenario;
    std::uint32_t run_id;
    std::uint32_t logical_count;
    std::uint32_t started_ms;
    std::uint8_t frame_count;
    std::uint8_t frame_lengths[kCapturedFramesPerWindow];
    std::uint8_t frames[kCapturedFramesPerWindow][demo_protocol::kMaxEmbeddedFrameSize];
};

QueueHandle_t receive_queue = nullptr;
CaptureWindow capture{};
String node_id;
bool esp_now_ready = false;
std::uint32_t total_frames_seen = 0U;
std::uint32_t dropped_demo_packets = 0U;
std::uint32_t last_attack_ms = 0U;
std::uint32_t last_heartbeat_ms = 0U;
std::uint32_t last_reconnect_ms = 0U;

void on_esp_now_receive(const std::uint8_t*, const std::uint8_t* data, int data_length) {
    if (receive_queue == nullptr || data == nullptr || data_length <= 0 ||
        static_cast<std::size_t>(data_length) > demo_protocol::kMaxPacketSize) {
        return;
    }
    ReceivedPacket packet{};
    packet.length = static_cast<std::uint16_t>(data_length);
    std::memcpy(packet.data, data, static_cast<std::size_t>(data_length));
    if (xQueueSend(receive_queue, &packet, 0U) != pdTRUE) {
        ++dropped_demo_packets;
    }
}

bool clock_is_ready() {
    return std::time(nullptr) > 1700000000;
}

String frame_to_hex(const std::uint8_t* frame, std::uint8_t length) {
    constexpr char digits[] = "0123456789abcdef";
    String hex;
    hex.reserve(static_cast<unsigned>(length) * 2U);
    for (std::uint8_t index = 0U; index < length; ++index) {
        hex += digits[frame[index] >> 4U];
        hex += digits[frame[index] & 0x0FU];
    }
    return hex;
}

bool post_json(const char* path, const String& body) {
    if (WiFi.status() != WL_CONNECTED) {
        return false;
    }
    HTTPClient http;
    const String url = String(BACKEND_BASE_URL) + path;
    if (!http.begin(url)) {
        return false;
    }
    http.addHeader("Content-Type", "application/json");
    const int status = http.POST(body);
    http.end();
    return status >= 200 && status < 300;
}

void clear_capture() {
    capture = CaptureWindow{};
}

void flush_capture() {
    if (!capture.active || capture.frame_count == 0U || !clock_is_ready()) {
        return;
    }
    const bool is_deauth = capture.scenario == demo_protocol::Scenario::deauth_flood;
    const std::uint32_t window_ms = millis() - capture.started_ms;
    String body;
    body.reserve(1400U);
    body = "{\"node_id\":\"" + node_id + "\",\"timestamp\":";
    body += String(static_cast<unsigned long>(std::time(nullptr)));
    body += ",\"frame_hex\":[";
    for (std::uint8_t index = 0U; index < capture.frame_count; ++index) {
        if (index > 0U) {
            body += ',';
        }
        body += "\"" + frame_to_hex(capture.frames[index], capture.frame_lengths[index]) + "\"";
    }
    body += "],\"rssi\":" + String(WiFi.RSSI());
    body += ",\"anomaly_stats\":{\"frame_type\":\"";
    body += is_deauth ? "mgmt" : "data";
    body += "\",\"subtype\":";
    body += is_deauth ? "12" : "null";
    body += ",\"count_in_window\":" + String(capture.logical_count);
    body += ",\"window_ms\":" + String(window_ms) + "}";
    body += ",\"guessed_type\":\"";
    body += demo_protocol::scenario_name(capture.scenario);
    body += "\"}";

    if (post_json("/ingest", body)) {
        Serial.printf(
            "Reported %s: logical=%lu samples=%u\n",
            demo_protocol::scenario_name(capture.scenario),
            static_cast<unsigned long>(capture.logical_count),
            capture.frame_count
        );
        clear_capture();
    }
}

void add_to_capture(const demo_protocol::DecodedFrame& frame) {
    if (capture.active &&
        (capture.run_id != frame.run_id || capture.scenario != frame.scenario)) {
        flush_capture();
        if (capture.active) {
            return;
        }
    }
    if (!capture.active) {
        capture.active = true;
        capture.scenario = frame.scenario;
        capture.run_id = frame.run_id;
        capture.started_ms = millis();
    }
    capture.logical_count += frame.logical_count;
    total_frames_seen += frame.logical_count;
    last_attack_ms = millis();
    if (capture.frame_count < kCapturedFramesPerWindow) {
        const std::uint8_t index = capture.frame_count++;
        capture.frame_lengths[index] = frame.frame_length;
        std::memcpy(capture.frames[index], frame.frame, frame.frame_length);
    }
}

void process_received_packets() {
    ReceivedPacket packet{};
    while (receive_queue != nullptr && xQueueReceive(receive_queue, &packet, 0U) == pdTRUE) {
        demo_protocol::DecodedFrame decoded{};
        if (demo_protocol::decode(packet.data, packet.length, decoded)) {
            add_to_capture(decoded);
        }
    }
    if (capture.active && millis() - capture.started_ms >= kCaptureWindowMs) {
        flush_capture();
    }
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
    Serial.println("ESP-NOW demo receiver ready");
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

void send_heartbeat() {
    if (!clock_is_ready() || millis() - last_heartbeat_ms < kHeartbeatIntervalMs) {
        return;
    }
    last_heartbeat_ms = millis();
    const bool alert = last_attack_ms != 0U && millis() - last_attack_ms < kAlertHoldMs;
    String body;
    body.reserve(300U);
    body = "{\"node_id\":\"" + node_id + "\",\"timestamp\":";
    body += String(static_cast<unsigned long>(std::time(nullptr)));
    body += ",\"state\":\"" + String(alert ? "ALERT" : "NORMAL") + "\"";
    body += ",\"stats\":{\"frames_seen\":" + String(total_frames_seen);
    body += ",\"blocked\":0,\"fw_version\":\"sniffer-demo-v1\"}}";
    post_json("/heartbeat", body);
}

}  // namespace

void setup() {
    Serial.begin(115200);
    receive_queue = xQueueCreate(16U, sizeof(ReceivedPacket));
    const std::uint64_t chip = ESP.getEfuseMac();
    node_id = "esp-sniffer-" + String(static_cast<std::uint32_t>(chip), HEX);
    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    configTime(0L, 0L, "pool.ntp.org", "time.google.com");
    last_reconnect_ms = millis() - kReconnectIntervalMs;
    tick_wifi();
    Serial.printf("Node: %s, backend: %s\n", node_id.c_str(), BACKEND_BASE_URL);
}

void loop() {
    tick_wifi();
    process_received_packets();
    send_heartbeat();
    delay(2);
}
