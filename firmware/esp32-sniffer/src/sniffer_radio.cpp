#include "sniffer_radio.h"

#include <WiFi.h>
#include <esp_err.h>
#include <esp_wifi.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "app_config.h"
#include "diagnostic_helpers.h"
#include "mac_address.h"

namespace defense_sniffer {
namespace {

constexpr size_t kTrackedSubtypeCount = 3;
QueueHandle_t gCaptureQueues[kTrackedSubtypeCount]{};
uint8_t gNextReceiveQueue = 0;
portMUX_TYPE gStatsMux = portMUX_INITIALIZER_UNLOCKED;
volatile uint32_t gManagementFramesSeen = 0;
volatile uint32_t gManagementPacketsSeen = 0;
volatile uint32_t gControlPacketsSeen = 0;
volatile uint32_t gDataPacketsSeen = 0;
volatile uint32_t gMiscPacketsSeen = 0;
volatile uint32_t gCaptureFramesDropped = 0;
volatile uint32_t gLastManagementFrameAtMs = 0;
volatile uint32_t gLastCaptureDropAtMs = 0;
volatile bool gHasManagementFrame = false;
volatile bool gHasCaptureDrop = false;
uint8_t gTargetChannel = 0;
uint8_t gTargetBssid[6]{};

bool trackedSubtype(uint8_t subtype) {
  return subtype == 10 || subtype == 11 || subtype == 12;
}

int queueIndexForSubtype(uint8_t subtype) {
  switch (subtype) {
    case 12:
      return 0;
    case 10:
      return 1;
    case 11:
      return 2;
    default:
      return -1;
  }
}

uint16_t minimumMpduLength(uint8_t subtype) {
  // 24-byte management header plus fixed body fields.
  return subtype == 11 ? 30 : 26;
}

void promiscuousReceiveCallback(void* buffer,
                                wifi_promiscuous_pkt_type_t packetType) {
  if (buffer == nullptr) {
    return;
  }

  const auto* packet = static_cast<const wifi_promiscuous_pkt_t*>(buffer);
  if (packet->rx_ctrl.rx_state != 0) {
    return;
  }

  portENTER_CRITICAL(&gStatsMux);
  const bool targetChannel = packet->rx_ctrl.channel == gTargetChannel;
  uint8_t targetBssid[6];
  std::memcpy(targetBssid, gTargetBssid, sizeof(targetBssid));
  if (!targetChannel) {
    portEXIT_CRITICAL(&gStatsMux);
    return;
  }
  switch (classifyPacketType(static_cast<uint8_t>(packetType))) {
    case PacketClass::Management:
      ++gManagementPacketsSeen;
      break;
    case PacketClass::Control:
      ++gControlPacketsSeen;
      break;
    case PacketClass::Data:
      ++gDataPacketsSeen;
      break;
    case PacketClass::Misc:
      ++gMiscPacketsSeen;
      break;
  }
  portEXIT_CRITICAL(&gStatsMux);

  if (packetType != WIFI_PKT_MGMT) {
    return;
  }

  const uint16_t receivedLength = packet->rx_ctrl.sig_len;

  // rx_state==0 is the only successful receive state. sig_len includes the
  // four-byte FCS; the wire contract carries MPDU bytes without it.
  if (receivedLength <= 4) {
    return;
  }
  const uint16_t mpduLength = receivedLength - 4;

  if (mpduLength < 24) {
    return;
  }

  const uint8_t frameControl = packet->payload[0];
  const uint8_t protocolVersion = frameControl & 0x03U;
  const uint8_t frameType = (frameControl >> 2U) & 0x03U;
  const uint8_t subtype = (frameControl >> 4U) & 0x0FU;
  if (protocolVersion != 0 || frameType != 0 ||
      std::memcmp(packet->payload + 16, targetBssid,
                  sizeof(targetBssid)) != 0) {
    return;
  }

  portENTER_CRITICAL(&gStatsMux);
  ++gManagementFramesSeen;
  gLastManagementFrameAtMs = millis();
  gHasManagementFrame = true;
  portEXIT_CRITICAL(&gStatsMux);

  if (!trackedSubtype(subtype)) {
    return;
  }
  if (mpduLength < minimumMpduLength(subtype)) {
    return;
  }

  CapturedFrame frame;
  frame.observedAtMs = millis();
  frame.observedAtUs = packet->rx_ctrl.timestamp;
  frame.rssi = packet->rx_ctrl.rssi;
  frame.channel = packet->rx_ctrl.channel;
  frame.subtype = subtype;
  std::memcpy(frame.sender, packet->payload + 10, sizeof(frame.sender));
  std::memcpy(frame.bssid, packet->payload + 16, sizeof(frame.bssid));
  frame.originalLength = mpduLength;
  frame.length = static_cast<uint16_t>(std::min(
      static_cast<size_t>(mpduLength), kMaximumCapturedFrameBytes));
  std::memcpy(frame.bytes, packet->payload, frame.length);

  const int queueIndex = queueIndexForSubtype(subtype);
  if (queueIndex < 0 || gCaptureQueues[queueIndex] == nullptr ||
      xQueueSend(gCaptureQueues[queueIndex], &frame, 0) != pdTRUE) {
    portENTER_CRITICAL(&gStatsMux);
    ++gCaptureFramesDropped;
    gLastCaptureDropAtMs = millis();
    gHasCaptureDrop = true;
    portEXIT_CRITICAL(&gStatsMux);
  }
}

bool checkEsp(const char* operation, esp_err_t result) {
  if (result == ESP_OK) {
    return true;
  }
  Serial.printf("[sniffer] %s failed: %s\n", operation,
                esp_err_to_name(result));
  return false;
}

}  // namespace

bool SnifferRadio::begin() {
  if (running_) {
    return true;
  }

  if (app_config::kMonitoredChannel < 1 ||
      app_config::kMonitoredChannel > 14 ||
      !parseMacAddress(app_config::kMonitoredBssid, targetBssid_)) {
    Serial.println("[sniffer] invalid monitored channel/BSSID configuration");
    return false;
  }
  targetChannel_ = app_config::kMonitoredChannel;
  gTargetChannel = targetChannel_;
  std::memcpy(gTargetBssid, targetBssid_, sizeof(gTargetBssid));

  const size_t queueDepths[kTrackedSubtypeCount] = {
      app_config::kDeauthQueueDepth, app_config::kDisassocQueueDepth,
      app_config::kAuthQueueDepth};
  for (size_t index = 0; index < kTrackedSubtypeCount; ++index) {
    gCaptureQueues[index] =
        xQueueCreate(queueDepths[index], sizeof(CapturedFrame));
    if (gCaptureQueues[index] == nullptr) {
      Serial.println("[sniffer] cannot allocate capture queues");
      for (size_t cleanup = 0; cleanup < index; ++cleanup) {
        vQueueDelete(gCaptureQueues[cleanup]);
        gCaptureQueues[cleanup] = nullptr;
      }
      return false;
    }
  }

  // STA mode lets the same radio report to the backend. Promiscuous capture is
  // therefore intentionally limited to the AP's current channel.
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);

  wifi_promiscuous_filter_t filter{};
  filter.filter_mask = app_config::kSerialTrace
                           ? WIFI_PROMIS_FILTER_MASK_ALL
                           : WIFI_PROMIS_FILTER_MASK_MGMT;

  const bool callbackSet = checkEsp(
      "set callback", esp_wifi_set_promiscuous_rx_cb(promiscuousReceiveCallback));
  const bool filterSet = checkEsp(
      "set management filter", esp_wifi_set_promiscuous_filter(&filter));
  const bool enabled =
      checkEsp("enable promiscuous mode", esp_wifi_set_promiscuous(true));
  running_ = callbackSet && filterSet && enabled;
  if (running_) {
    Serial.printf(
        "[sniffer] passive capture enabled for %s on channel %u (%s trace)\n",
        app_config::kMonitoredBssid, targetChannel_,
        app_config::kSerialTrace ? "all-packet" : "management-only");
  } else {
    esp_wifi_set_promiscuous(false);
    for (QueueHandle_t& queue : gCaptureQueues) {
      if (queue != nullptr) {
        vQueueDelete(queue);
        queue = nullptr;
      }
    }
  }
  return running_;
}

bool SnifferRadio::followAssociatedAccessPoint(uint8_t channel,
                                               const uint8_t* bssid) {
  if (!running_ || channel < 1 || channel > 14 || bssid == nullptr ||
      sameAccessPoint(targetChannel_, targetBssid_, channel, bssid)) {
    return false;
  }

  targetChannel_ = channel;
  std::memcpy(targetBssid_, bssid, sizeof(targetBssid_));
  portENTER_CRITICAL(&gStatsMux);
  gTargetChannel = channel;
  std::memcpy(gTargetBssid, bssid, sizeof(gTargetBssid));
  gManagementFramesSeen = 0;
  gHasManagementFrame = false;
  portEXIT_CRITICAL(&gStatsMux);
  for (QueueHandle_t queue : gCaptureQueues) {
    if (queue != nullptr) {
      xQueueReset(queue);
    }
  }

  char formatted[18];
  std::snprintf(formatted, sizeof(formatted),
                "%02x:%02x:%02x:%02x:%02x:%02x", bssid[0], bssid[1],
                bssid[2], bssid[3], bssid[4], bssid[5]);
  Serial.printf("[sniffer] following associated AP %s on channel %u\n",
                formatted, channel);
  return true;
}

bool SnifferRadio::receive(CapturedFrame& frame) {
  for (size_t offset = 0; offset < kTrackedSubtypeCount; ++offset) {
    const uint8_t index =
        (gNextReceiveQueue + offset) % kTrackedSubtypeCount;
    if (gCaptureQueues[index] != nullptr &&
        xQueueReceive(gCaptureQueues[index], &frame, 0) == pdTRUE) {
      gNextReceiveQueue = (index + 1U) % kTrackedSubtypeCount;
      return true;
    }
  }
  return false;
}

uint32_t SnifferRadio::managementFramesSeen() const {
  portENTER_CRITICAL(&gStatsMux);
  const uint32_t value = gManagementFramesSeen;
  portEXIT_CRITICAL(&gStatsMux);
  return value;
}

PacketTypeCounters SnifferRadio::packetTypeCounters() const {
  portENTER_CRITICAL(&gStatsMux);
  PacketTypeCounters value;
  value.management = gManagementPacketsSeen;
  value.control = gControlPacketsSeen;
  value.data = gDataPacketsSeen;
  value.misc = gMiscPacketsSeen;
  portEXIT_CRITICAL(&gStatsMux);
  return value;
}

uint32_t SnifferRadio::captureFramesDropped() const {
  portENTER_CRITICAL(&gStatsMux);
  const uint32_t value = gCaptureFramesDropped;
  portEXIT_CRITICAL(&gStatsMux);
  return value;
}

bool SnifferRadio::captureHealthy(uint32_t nowMs,
                                  uint32_t maximumAgeMs) const {
  portENTER_CRITICAL(&gStatsMux);
  const bool fresh =
      gHasManagementFrame && nowMs - gLastManagementFrameAtMs <= maximumAgeMs;
  const bool recentlyDropped =
      gHasCaptureDrop && nowMs - gLastCaptureDropAtMs <= maximumAgeMs;
  portEXIT_CRITICAL(&gStatsMux);
  return running_ && fresh && !recentlyDropped;
}

bool SnifferRadio::matchesTarget(const CapturedFrame& frame) const {
  return running_ && frame.channel == targetChannel_ &&
         std::memcmp(frame.bssid, targetBssid_, sizeof(targetBssid_)) == 0;
}

uint8_t SnifferRadio::targetChannel() const { return targetChannel_; }

void SnifferRadio::copyTargetBssid(uint8_t* output) const {
  if (output != nullptr) {
    std::memcpy(output, targetBssid_, sizeof(targetBssid_));
  }
}

bool SnifferRadio::running() const { return running_; }

}  // namespace defense_sniffer
