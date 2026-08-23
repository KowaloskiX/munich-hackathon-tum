# ESP32 passive sniffers

One Arduino/PlatformIO firmware is built as two fleet nodes:

| Environment | `node_id` | Heartbeat phase |
|---|---|---:|
| `sniffer-01` | `esp-sniffer-01` | 0 ms |
| `sniffer-02` | `esp-sniffer-02` | 1500 ms |

Both nodes passively inspect 802.11 management frames on the channel of the
Wi-Fi access point used to reach the backend. They detect deauthentication,
disassociation and authentication floods, POST evidence to `/ingest`, and POST
liveness to `/heartbeat` every three seconds. A local LED/lamp starts
immediately and blinks every 250 ms for exactly four seconds after detection.
Network reporting runs in a separate task, so an HTTP timeout cannot freeze the
lamp or the capture loop.

After association, the capture target follows the AP and channel actually
reported by the Wi-Fi driver. This handles venue networks that move a BSSID to
a different channel or steer the ESP despite a stale configured channel; while
disconnected, the sniffer keeps monitoring the last associated AP.

## Hardware assumption and lamp wiring

The default PlatformIO board is `esp32dev`, suitable for the common ESP-32S /
ESP32 DevKit module. GPIO 2 is the default active-high output. For a small LED,
connect `GPIO 2 -> 220-330 ohm resistor -> LED -> GND`.

Do not power a larger lamp directly from an ESP32 pin. Use a transistor/MOSFET
driver and a suitable external supply with a common ground. Override
`SNIFFER_LAMP_PIN` and `SNIFFER_LAMP_ACTIVE_HIGH` in `platformio.ini` when the
board or driver differs. For an ESP32-S3 DevKit, also change `board` to
`esp32-s3-devkitc-1`; many S3 boards use an addressable RGB LED rather than a
plain GPIO LED, so an external indicator is the predictable option.

## Configuration and flashing

```bash
cd firmware/esp32-sniffer
cp include/secrets.example.h include/secrets.h
# Edit SSID, password, backend, both tokens, monitored channel and BSSID.
# SNIFFER_BACKEND_PORT defaults to 8100 (the sentinel-edge gateway) so `/ingest`
# reports flow through in-path enforcement; use 8000 for a direct backend run.

pio test -e native
pio run -e sniffer-01
pio run -e sniffer-01 -t upload --upload-port /dev/ttyUSB0
pio run -e sniffer-02
pio run -e sniffer-02 -t upload --upload-port /dev/ttyUSB1
```

`include/secrets.h` is ignored by Git. It contains the shared Wi-Fi/backend
settings plus separate `SNIFFER_API_TOKEN_01` and `SNIFFER_API_TOKEN_02` values.
Each build selects its own token and stable `node_id` from its PlatformIO
environment.

## Live serial console

Use the diagnostic environments when you want a continuous console trace. They
print a one-second `[traffic/s]` summary for every promiscuous packet class on
the monitored channel (`mgmt`, `ctrl`, `data`, `misc`). Captured deauth,
disassoc and auth frames additionally include timestamp, channel, RSSI, BSSID,
sender, lengths and the first 32 bytes as hex. Backend failures are rate-limited
to one message per ten seconds so they do not hide capture diagnostics.

```bash
# List ports first.
pio device list

# Flash sniffer 1, then keep this terminal attached at 115200 baud.
pio run -e sniffer-01-debug -t upload --upload-port /dev/cu.usbmodem5B910447981
pio device monitor --port /dev/cu.usbmodem5B910447981 --baud 115200
```

For the second ESP, open another terminal and replace the environment with
`sniffer-02-debug` and the port with that board's `/dev/cu.*` or `/dev/ttyUSB*`
path. Exit the monitor with `Ctrl+C`.

For the end-to-end bench demo, use `sniffer-01-demo`. It keeps telemetry
enabled and accepts `t` in the serial console to inject a synthetic deauth
burst into the local detector without transmitting any RF:

```bash
pio run -e sniffer-01-demo -t upload --upload-port /dev/cu.usbserial-0001
pio device monitor --port /dev/cu.usbserial-0001 -b 115200
```

On client-isolated demo WLANs the command also sends five copies of one marker
to `239.255.77.77:37777`; the backend deduplicates them by node and uptime, so
packet loss does not hide the demo and one keypress still creates one incident.

If no ingest backend is running, use `sniffer-01-console`. It still joins the
configured AP to pin the capture channel, but suppresses `/ingest` and
`/heartbeat` attempts so the terminal contains only local capture, statistics
and alert output. Type `t` in its serial monitor to inject exactly the configured
deauthentication threshold into the detector. This exercises detection and the
four-second lamp locally and does not transmit a disruptive Wi-Fi management
frame. It also sends a harmless JSON multicast marker to
`239.255.77.77:37777`; inspect it in Wireshark with the display filter
`udp.port == 37777`.

The trace deliberately summarizes common traffic instead of printing every
beacon, data and control frame: doing that at 115200 baud can block the consumer
and create artificial packet loss. `target_mgmt` in `[traffic/s]` is the
cumulative count of valid management frames from the configured BSSID. Use a
dedicated monitor-mode Wi-Fi adapter and Wireshark when a lossless view of every
802.11 frame is required.

## Detection defaults

The defaults are deliberately simple and explicit for an isolated demo:

- deauthentication subtype 12: at least 20 frames in 1000 ms;
- disassociation subtype 10: at least 20 frames in 1000 ms;
- authentication subtype 11: at least 50 frames in 1000 ms;
- an exact sliding one-second window keyed by channel and BSSID;
- five-second per-key/type cooldown between reports;
- at most six samples of 192 bytes in each report.

Beacon frames are not classified by rate alone because a busy venue can have
many legitimate access points. A reliable beacon-flood detector should also
track unique BSSIDs/SSIDs before it is enabled.

The detector tracks up to four concurrent BSSID keys per subtype and up to 256
timestamps per key/window. Aggregating the built-in baseline by BSSID prevents
rotating/spoofed sender addresses from evading an authentication flood counter.
The promiscuous callback rejects frames with a
receive error, removes the four-byte FCS, then only increments a counter and
copies relevant MPDU evidence into a bounded FreeRTOS queue. JSON creation and
HTTP never run in the Wi-Fi driver callback. Queue drops are visible in both
telemetry contracts.

Deauth, disassoc and auth use separate queues (32/32/64 entries) drained in
round-robin order. Each queue is larger than its rule threshold, so an auth
burst cannot occupy the evidence capacity reserved for a later deauth alert.
Recent queue loss makes heartbeat threat `UNKNOWN` rather than a false
`NORMAL`.

## Backend contracts

The FastAPI backend implements `/ingest` and `/heartbeat`, then turns accepted
anomalies into the ordered `SYSTEM_STATUS` stream consumed by the HMI. The
sniffers intentionally do not write directly to the display.

An anomaly is sent to `POST /ingest`:

```json
{
  "node_id": "esp-sniffer-01",
  "timestamp": 913.245,
  "frame_hex": ["c000..."],
  "rssi": -52,
  "anomaly_stats": {
    "frame_type": "mgmt",
    "subtype": 12,
    "count_in_window": 20,
    "window_ms": 1000
  },
  "guessed_type": "deauth_flood"
}
```

Liveness is sent to `POST /heartbeat`. On client-isolated Wi-Fi the same
heartbeat is also sent as a small validated multicast marker, so the backend
can keep the display's sensor count fresh even when device-to-laptop TCP is
blocked:

```json
{
  "node_id": "esp-sniffer-01",
  "timestamp": 918.245,
  "state": "ALERT",
  "stats": {"frames_seen": 10432, "blocked": 0, "fw_version": "1.0.0"}
}
```

`frames_seen` counts valid management frames. The heartbeat remains `ALERT` for
ten seconds after a detection so the backend sees it in multiple heartbeats;
the physical lamp still stops after exactly four seconds. This passive firmware
does not claim to block traffic. The backend stamps hardware heartbeats with
its receipt time, so an ESP monotonic uptime is never mistaken for Unix time.

Any HTTP 2xx response is accepted. Failed anomaly reports remain in a bounded
queue across retries. Transient failures use bounded exponential backoff with
jitter; permanent 4xx responses
and reports that fail two attempts are discarded instead of blocking every
later alert. The current HTTP + per-device bearer-token transport is intended
for an isolated demo LAN. Production use needs TLS, certificate validation and
replay protection.

Pulling, signature-verifying and acknowledging a dynamic policy manifest is a
separate integration layer from passive sniffing, alert reporting and lamp
behavior.

## Radio limitation and safe testing

An ESP32 has one 2.4 GHz radio. The firmware pins association and capture to the
configured authorized BSSID/channel and filters every other network before it
enters a queue. This also lets local detection and the four-second lamp continue
while a deauthentication temporarily breaks the reporting association; queued
alerts are sent after reconnection. Put the isolated test network and backend on
that monitored AP. Channel hopping would interrupt reporting.

This project only detects and contains no attack generator. Test with saved
captures where possible. Never transmit deauthentication/disassociation attacks
on venue or third-party Wi-Fi; any live radio test must use your own isolated
access point and devices.
