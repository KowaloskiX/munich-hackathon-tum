#include <Arduino.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_system.h>
#include <esp_wifi.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "attack_core.h"
#include "demo_protocol.h"
#include "lab_config.h"

namespace {

using red_esp::AttackConfig;
using red_esp::AttackMode;

static_assert(
    sizeof(LAB_CONTROL_PASSWORD) - 1U >= 8U,
    "LAB_CONTROL_PASSWORD must contain at least 8 characters"
);

constexpr std::uint8_t kEspNowBroadcast[6] = {
    0xFFU,
    0xFFU,
    0xFFU,
    0xFFU,
    0xFFU,
    0xFFU,
};
constexpr std::uint16_t kDeauthLogicalFramesPerPacket = 80U;
constexpr std::uint16_t kTrafficLogicalFramesPerPacket = 40U;

WebServer server(80);

AttackConfig attack_config{
    AttackMode::deauth_simulation,
    10U,
    5U,
};

bool running = false;
bool esp_now_ready = false;
bool mdns_ready = false;
bool station_announced = false;
std::uint8_t sender_mac[6]{};
std::uint32_t run_id = 0U;
std::uint32_t base_sender_id = 0U;
std::uint32_t sent_packets = 0U;
std::uint32_t failed_packets = 0U;
std::uint32_t attack_started_ms = 0U;
std::uint32_t next_send_us = 0U;
std::uint32_t armed_until_ms = 0U;
std::uint32_t last_station_attempt_ms = 0U;

constexpr char kIndexHtml[] PROGMEM = R"HTML(
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Red ESP — safe demo</title><style>
body{font:16px system-ui;background:#0b1020;color:#eef2ff;max-width:720px;margin:32px auto;padding:0 18px}
.card{background:#151c32;border:1px solid #334066;border-radius:14px;padding:18px;margin:14px 0}
label{display:block;margin:12px 0 5px}select,input,button{font:inherit;border-radius:8px;padding:10px;border:1px solid #5a668f}
select,input{width:100%;box-sizing:border-box;background:#0f1629;color:#fff}button{cursor:pointer;margin:6px;background:#3446a8;color:#fff}
button.danger{background:#a52b3b}.ok{color:#63e6a6}.warn{color:#ffc857}code{color:#8bd5ff}
</style></head><body><h1>Red ESP <small>synthetic attack</small></h1>
<div class="card"><div id="status">Loading…</div></div>
<div class="card"><h2>Scenario</h2><form id="config">
<label for="mode">Profile</label><select id="mode" name="mode">
<option value="synthetic_deauth_flood">Deauthentication flood (SIMULATED)</option>
<option value="traffic_spike">Traffic spike</option>
<option value="sequence_replay">Sequence replay</option>
<option value="sequence_jump">Sequence jump</option>
<option value="identity_churn">Application identity churn</option>
<option value="malformed_payload">Malformed payload</option></select>
<label for="pps">Physical demo packets/s (1–50)</label><input id="pps" name="pps" type="number" min="1" max="50" value="10">
<label for="duration">Duration (1–10 s)</label><input id="duration" name="duration" type="number" min="1" max="10" value="5">
<p><button type="submit">Save</button><button id="start" type="button">START</button><button class="danger" id="stop" type="button">STOP</button></p>
</form><p class="warn">Hold BOOT for 1.5 s to arm for 30 s. Only a marked ESP-NOW broadcast is on the air — the embedded deauth frame is never transmitted as a management frame.</p></div>
<script>
async function call(path,options={}){const r=await fetch(path,options);const t=await r.text();if(!r.ok)throw Error(t);return t}
async function refresh(){try{const s=JSON.parse(await call('/api/status'));document.querySelector('#status').innerHTML=
`State: <b class="${s.running?'warn':'ok'}">${s.running?'RUNNING':'IDLE'}</b><br>Hotspot: <code>${s.station}</code><br>`+
`Transport: <code>${s.transport}</code>, profile: <code>${s.mode}</code><br>`+
`Logical rate: ~${s.logical_rate} frames/s, sent: ${s.sent}, errors: ${s.failed}<br>`+
`Armed: ${s.armed?'YES':'no'}`;}catch(e){document.querySelector('#status').textContent=e}}
document.querySelector('#config').onsubmit=async e=>{e.preventDefault();try{await call('/api/config',{method:'POST',body:new URLSearchParams(new FormData(e.target))});await refresh()}catch(e){alert(e)}};
document.querySelector('#start').onclick=async()=>{try{await call('/api/start',{method:'POST'});await refresh()}catch(e){alert(e)}};
document.querySelector('#stop').onclick=async()=>{await call('/api/stop',{method:'POST'});await refresh()};
setInterval(refresh,1000);refresh();</script></body></html>
)HTML";

bool deadline_active(std::uint32_t deadline_ms) {
    return deadline_ms != 0U && static_cast<std::int32_t>(deadline_ms - millis()) > 0;
}

bool lab_ssid_is_locked() {
    return std::strncmp(LAB_WIFI_SSID, "LAB_", 4U) == 0;
}

std::uint16_t logical_frames_per_packet(AttackMode mode) {
    if (mode == AttackMode::deauth_simulation) {
        return kDeauthLogicalFramesPerPacket;
    }
    if (mode == AttackMode::traffic_spike) {
        return kTrafficLogicalFramesPerPacket;
    }
    return 1U;
}

bool ensure_esp_now() {
    if (esp_now_ready) {
        return true;
    }
    if (WiFi.status() != WL_CONNECTED || esp_now_init() != ESP_OK) {
        return false;
    }
    esp_now_peer_info_t peer{};
    std::memcpy(peer.peer_addr, kEspNowBroadcast, sizeof(kEspNowBroadcast));
    peer.channel = 0U;
    peer.ifidx = WIFI_IF_STA;
    peer.encrypt = false;
    const esp_err_t result = esp_now_add_peer(&peer);
    if (result != ESP_OK && result != ESP_ERR_ESPNOW_EXIST) {
        esp_now_deinit();
        return false;
    }
    esp_now_ready = true;
    Serial.println("ESP-NOW synthetic broadcast ready");
    return true;
}

bool authorize() {
    if (server.authenticate("redesp", LAB_CONTROL_PASSWORD)) {
        return true;
    }
    server.requestAuthentication();
    return false;
}

void send_text(int status, const String& body) {
    server.send(status, "text/plain; charset=utf-8", body);
}

void stop_attack(const char* reason) {
    if (!running) {
        return;
    }
    running = false;
    armed_until_ms = 0U;
    Serial.printf(
        "Scenario stopped (%s): sent=%lu failed=%lu\n",
        reason,
        static_cast<unsigned long>(sent_packets),
        static_cast<unsigned long>(failed_packets)
    );
}

void handle_root() {
    if (authorize()) {
        server.send_P(200, "text/html; charset=utf-8", kIndexHtml);
    }
}

void handle_status() {
    if (!authorize()) {
        return;
    }
    const std::uint32_t logical_rate =
        static_cast<std::uint32_t>(attack_config.packets_per_second) *
        logical_frames_per_packet(attack_config.mode);
    String json = "{";
    json += "\"running\":" + String(running ? "true" : "false");
    json += ",\"armed\":" + String(deadline_active(armed_until_ms) ? "true" : "false");
    json += ",\"station\":\"";
    json += WiFi.status() == WL_CONNECTED ? WiFi.localIP().toString() : "disconnected";
    json += "\",\"transport\":\"";
    json += esp_now_ready ? "ESP-NOW ready" : "waiting";
    json += "\",\"mode\":\"" + String(red_esp::mode_name(attack_config.mode)) + "\"";
    json += ",\"logical_rate\":" + String(logical_rate);
    json += ",\"sent\":" + String(sent_packets);
    json += ",\"failed\":" + String(failed_packets) + "}";
    server.send(200, "application/json", json);
}

bool parse_bounded_number(
    const String& input,
    long minimum,
    long maximum,
    std::uint16_t& output
) {
    if (input.isEmpty()) {
        return false;
    }
    char* end = nullptr;
    const long value = std::strtol(input.c_str(), &end, 10);
    if (end == input.c_str() || *end != '\0' || value < minimum || value > maximum) {
        return false;
    }
    output = static_cast<std::uint16_t>(value);
    return true;
}

void handle_config() {
    if (!authorize()) {
        return;
    }
    if (running) {
        send_text(409, "Stop the active scenario first.");
        return;
    }
    AttackMode requested_mode = attack_config.mode;
    std::uint16_t requested_pps = 0U;
    std::uint16_t requested_duration = 0U;
    if (!red_esp::parse_mode(server.arg("mode").c_str(), requested_mode) ||
        !parse_bounded_number(server.arg("pps"), 1L, 50L, requested_pps) ||
        !parse_bounded_number(server.arg("duration"), 1L, 10L, requested_duration)) {
        send_text(400, "Invalid profile, pps or duration.");
        return;
    }
    const AttackConfig candidate{requested_mode, requested_pps, requested_duration};
    const auto validation = red_esp::validate_config(candidate);
    if (!validation.ok) {
        send_text(400, validation.message);
        return;
    }
    attack_config = candidate;
    send_text(200, "ok");
}

void handle_start() {
    if (!authorize()) {
        return;
    }
    if (running) {
        send_text(409, "Scenario already running.");
        return;
    }
    if (!lab_ssid_is_locked()) {
        send_text(423, "LAB lock: hotspot name must start with LAB_.");
        return;
    }
    if (WiFi.status() != WL_CONNECTED || !ensure_esp_now()) {
        send_text(503, "No hotspot connection or ESP-NOW not ready.");
        return;
    }
    if (!deadline_active(armed_until_ms)) {
        send_text(423, "Hold BOOT for 1.5 s to arm the device.");
        return;
    }
    const auto validation = red_esp::validate_config(attack_config);
    if (!validation.ok) {
        send_text(400, validation.message);
        return;
    }
    armed_until_ms = 0U;
    running = true;
    run_id = esp_random();
    sent_packets = 0U;
    failed_packets = 0U;
    attack_started_ms = millis();
    next_send_us = micros();
    Serial.printf(
        "Scenario started: %s, %u physical pps, %lu logical fps, %u s\n",
        red_esp::mode_name(attack_config.mode),
        attack_config.packets_per_second,
        static_cast<unsigned long>(
            static_cast<std::uint32_t>(attack_config.packets_per_second) *
            logical_frames_per_packet(attack_config.mode)
        ),
        attack_config.duration_seconds
    );
    send_text(202, "started");
}

void handle_stop() {
    if (!authorize()) {
        return;
    }
    stop_attack("web stop");
    send_text(200, "stopped");
}

void setup_web_server() {
    server.on("/", HTTP_GET, handle_root);
    server.on("/api/status", HTTP_GET, handle_status);
    server.on("/api/config", HTTP_POST, handle_config);
    server.on("/api/start", HTTP_POST, handle_start);
    server.on("/api/stop", HTTP_POST, handle_stop);
    server.onNotFound([]() { send_text(404, "not found"); });
    server.begin();
}

void send_one_packet() {
    const auto plan = red_esp::make_packet_plan(
        attack_config.mode,
        sent_packets,
        base_sender_id
    );
    std::uint8_t embedded[demo_protocol::kMaxEmbeddedFrameSize]{};
    std::size_t embedded_size = 0U;
    if (attack_config.mode == AttackMode::deauth_simulation) {
        embedded_size = demo_protocol::make_synthetic_deauth_frame(
            sender_mac,
            static_cast<std::uint16_t>(sent_packets),
            embedded,
            sizeof(embedded)
        );
    } else {
        embedded_size = red_esp::encode_packet(
            attack_config.mode,
            run_id,
            plan,
            millis(),
            embedded,
            sizeof(embedded)
        );
    }

    std::uint8_t envelope[demo_protocol::kMaxPacketSize]{};
    const auto scenario = static_cast<demo_protocol::Scenario>(
        static_cast<std::uint8_t>(attack_config.mode)
    );
    const std::size_t envelope_size = demo_protocol::encode(
        scenario,
        logical_frames_per_packet(attack_config.mode),
        run_id,
        sent_packets,
        plan.sender_id,
        millis(),
        embedded,
        static_cast<std::uint8_t>(embedded_size),
        envelope,
        sizeof(envelope)
    );
    const esp_err_t result = envelope_size == 0U
                                 ? ESP_FAIL
                                 : esp_now_send(
                                       kEspNowBroadcast,
                                       envelope,
                                       static_cast<std::uint8_t>(envelope_size)
                                   );
    if (result != ESP_OK) {
        ++failed_packets;
    }
    ++sent_packets;
}

void tick_attack() {
    if (!running) {
        return;
    }
    if (WiFi.status() != WL_CONNECTED) {
        stop_attack("hotspot disconnected");
        return;
    }
    const std::uint32_t elapsed_ms = millis() - attack_started_ms;
    const std::uint32_t budget =
        static_cast<std::uint32_t>(attack_config.packets_per_second) *
        static_cast<std::uint32_t>(attack_config.duration_seconds);
    if (elapsed_ms >= static_cast<std::uint32_t>(attack_config.duration_seconds) * 1000U ||
        sent_packets >= budget) {
        stop_attack("limit reached");
        return;
    }

    const std::uint32_t interval_us = 1000000U / attack_config.packets_per_second;
    unsigned burst_guard = 0U;
    while (static_cast<std::int32_t>(micros() - next_send_us) >= 0 && burst_guard < 4U) {
        send_one_packet();
        next_send_us += interval_us;
        ++burst_guard;
        if (sent_packets >= budget) {
            break;
        }
    }
}

void tick_button() {
    static bool was_pressed = false;
    static bool armed_this_press = false;
    static std::uint32_t pressed_at_ms = 0U;
    const bool pressed = digitalRead(kArmButtonPin) == LOW;
    if (pressed && !was_pressed) {
        pressed_at_ms = millis();
        armed_this_press = false;
        if (running) {
            stop_attack("physical emergency stop");
        }
    }
    if (pressed && !running && !armed_this_press && millis() - pressed_at_ms >= kArmHoldMs) {
        armed_until_ms = millis() + kArmWindowMs;
        armed_this_press = true;
        Serial.println("Armed for 30 seconds");
    }
    if (!pressed) {
        armed_this_press = false;
    }
    was_pressed = pressed;
}

void tick_led() {
    if (running) {
        digitalWrite(kStatusLedPin, ((millis() / 100U) % 2U) == 0U ? HIGH : LOW);
    } else if (deadline_active(armed_until_ms)) {
        digitalWrite(kStatusLedPin, HIGH);
    } else {
        digitalWrite(kStatusLedPin, ((millis() / 1000U) % 2U) == 0U ? HIGH : LOW);
    }
}

void tick_station() {
    if (WiFi.status() == WL_CONNECTED) {
        if (!station_announced) {
            Serial.printf(
                "Hotspot connected: %s, panel: http://red-esp.local\n",
                WiFi.localIP().toString().c_str()
            );
            station_announced = true;
        }
        if (!mdns_ready && MDNS.begin("red-esp")) {
            MDNS.addService("http", "tcp", 80U);
            mdns_ready = true;
        }
        ensure_esp_now();
        return;
    }
    station_announced = false;
    if (!lab_ssid_is_locked() || millis() - last_station_attempt_ms < 10000U) {
        return;
    }
    last_station_attempt_ms = millis();
    WiFi.begin(LAB_WIFI_SSID, LAB_WIFI_PASSWORD);
}

}  // namespace

void setup() {
    Serial.begin(115200);
    pinMode(kArmButtonPin, INPUT_PULLUP);
    pinMode(kStatusLedPin, OUTPUT);
    base_sender_id = static_cast<std::uint32_t>(ESP.getEfuseMac());

    WiFi.mode(WIFI_AP_STA);
    WiFi.setSleep(false);
    esp_wifi_get_mac(WIFI_IF_STA, sender_mac);
    const String control_ssid =
        "RED-ESP-" + String(static_cast<std::uint16_t>(base_sender_id), HEX);
    WiFi.softAP(control_ssid.c_str(), LAB_CONTROL_PASSWORD);
    Serial.printf(
        "Control AP: %s, panel: http://%s\n",
        control_ssid.c_str(),
        WiFi.softAPIP().toString().c_str()
    );
    if (!lab_ssid_is_locked()) {
        Serial.println("LAB LOCKED: set the phone hotspot name to LAB_*");
    } else {
        last_station_attempt_ms = millis() - 10000U;
        tick_station();
    }
    setup_web_server();
}

void loop() {
    server.handleClient();
    tick_button();
    tick_station();
    tick_attack();
    tick_led();
    delay(1);
}
