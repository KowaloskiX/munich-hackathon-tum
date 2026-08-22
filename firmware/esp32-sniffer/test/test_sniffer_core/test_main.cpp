#include <unity.h>

#include <cstdint>
#include <limits>

#include "anomaly_detector.h"
#include "blink_pattern.h"
#include "diagnostic_helpers.h"
#include "mac_address.h"

namespace {

uint8_t frameBytes[32] = {0xc0, 0x00};
uint8_t bssidA[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
uint8_t bssidB[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02};
uint8_t senderA[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x01};
uint8_t rotatingSenders[5][6] = {
    {0x10, 0x20, 0x30, 0x40, 0x50, 0x01},
    {0x10, 0x20, 0x30, 0x40, 0x50, 0x02},
    {0x10, 0x20, 0x30, 0x40, 0x50, 0x03},
    {0x10, 0x20, 0x30, 0x40, 0x50, 0x04},
    {0x10, 0x20, 0x30, 0x40, 0x50, 0x05},
};

defense_sniffer::FrameObservation observation(uint8_t subtype,
                                              uint32_t observedAtMs) {
  defense_sniffer::FrameObservation value;
  value.observedAtMs = observedAtMs;
  value.observedAtUs = observedAtMs * 1000U;
  value.rssi = -50;
  value.channel = 6;
  value.subtype = subtype;
  value.bssid = bssidA;
  value.sender = senderA;
  value.bytes = frameBytes;
  value.length = sizeof(frameBytes);
  value.originalLength = sizeof(frameBytes);
  return value;
}

defense_sniffer::DetectorConfig testConfig() {
  defense_sniffer::DetectorConfig config;
  config.windowMs = 1000;
  config.cooldownMs = 5000;
  config.deauthThreshold = 20;
  config.disassocThreshold = 20;
  config.authThreshold = 50;
  return config;
}

void test_deauth_threshold_and_samples() {
  defense_sniffer::MgmtFloodDetector detector(testConfig());
  defense_sniffer::AnomalyReport report;

  for (uint32_t index = 0; index < 19; ++index) {
    TEST_ASSERT_FALSE(detector.observe(observation(12, 100 + index), report));
  }
  TEST_ASSERT_TRUE(detector.observe(observation(12, 119), report));
  TEST_ASSERT_EQUAL_UINT8(12, report.subtype);
  TEST_ASSERT_EQUAL_UINT32(20, report.countInWindow);
  TEST_ASSERT_EQUAL_STRING("deauth_flood",
                           defense_sniffer::attackKindName(report.kind));
  TEST_ASSERT_EQUAL_UINT8(defense_sniffer::kMaximumFrameSamples,
                          report.sampleCount);
  TEST_ASSERT_EQUAL_INT8(-50, report.samples[0].rssi);
  TEST_ASSERT_EQUAL_UINT16(sizeof(frameBytes),
                           report.samples[0].originalLength);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(bssidA, report.bssid, sizeof(bssidA));
}

void test_auth_threshold_is_independent() {
  defense_sniffer::MgmtFloodDetector detector(testConfig());
  defense_sniffer::AnomalyReport report;
  for (uint32_t index = 0; index < 49; ++index) {
    TEST_ASSERT_FALSE(detector.observe(observation(11, index), report));
  }
  TEST_ASSERT_TRUE(detector.observe(observation(11, 49), report));
  TEST_ASSERT_EQUAL_STRING("auth_flood",
                           defense_sniffer::attackKindName(report.kind));
}

void test_untracked_beacons_do_not_alert() {
  defense_sniffer::MgmtFloodDetector detector(testConfig());
  defense_sniffer::AnomalyReport report;
  for (uint32_t index = 0; index < 500; ++index) {
    TEST_ASSERT_FALSE(detector.observe(observation(8, index), report));
  }
}

void test_cooldown_suppresses_duplicate_windows() {
  defense_sniffer::MgmtFloodDetector detector(testConfig());
  defense_sniffer::AnomalyReport report;

  for (uint32_t index = 0; index < 20; ++index) {
    detector.observe(observation(10, 100 + index), report);
  }

  for (uint32_t index = 0; index < 20; ++index) {
    TEST_ASSERT_FALSE(
        detector.observe(observation(10, 1200 + index), report));
  }

  bool detectedAfterCooldown = false;
  for (uint32_t index = 0; index < 20; ++index) {
    detectedAfterCooldown =
        detector.observe(observation(10, 5200 + index), report) ||
        detectedAfterCooldown;
  }
  TEST_ASSERT_TRUE(detectedAfterCooldown);
  TEST_ASSERT_EQUAL_STRING("disassoc_flood",
                           defense_sniffer::attackKindName(report.kind));
}

void test_frames_outside_window_do_not_accumulate() {
  defense_sniffer::MgmtFloodDetector detector(testConfig());
  defense_sniffer::AnomalyReport report;
  for (uint32_t index = 0; index < 10; ++index) {
    TEST_ASSERT_FALSE(detector.observe(observation(12, index), report));
  }
  for (uint32_t index = 0; index < 10; ++index) {
    TEST_ASSERT_FALSE(
        detector.observe(observation(12, 1000 + index), report));
  }
}

void test_sliding_window_detects_burst_across_old_boundary() {
  defense_sniffer::MgmtFloodDetector detector(testConfig());
  defense_sniffer::AnomalyReport report;
  TEST_ASSERT_FALSE(detector.observe(observation(12, 0), report));
  for (uint32_t index = 0; index < 10; ++index) {
    TEST_ASSERT_FALSE(detector.observe(observation(12, 900 + index), report));
  }
  bool detected = false;
  for (uint32_t index = 0; index < 10; ++index) {
    detected = detector.observe(observation(12, 1001 + index), report) ||
               detected;
  }
  TEST_ASSERT_TRUE(detected);
}

void test_different_bssids_do_not_share_a_counter() {
  defense_sniffer::MgmtFloodDetector detector(testConfig());
  defense_sniffer::AnomalyReport report;
  for (uint32_t index = 0; index < 10; ++index) {
    TEST_ASSERT_FALSE(detector.observe(observation(12, index), report));
    defense_sniffer::FrameObservation other = observation(12, index);
    other.bssid = bssidB;
    TEST_ASSERT_FALSE(detector.observe(other, report));
  }

  bool detectedA = false;
  for (uint32_t index = 10; index < 20; ++index) {
    detectedA = detector.observe(observation(12, index), report) || detectedA;
  }
  TEST_ASSERT_TRUE(detectedA);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(bssidA, report.bssid, sizeof(bssidA));
}

void test_rotating_senders_cannot_evade_bssid_counter() {
  defense_sniffer::MgmtFloodDetector detector(testConfig());
  defense_sniffer::AnomalyReport report;
  bool detected = false;
  for (uint32_t index = 0; index < 20; ++index) {
    defense_sniffer::FrameObservation value = observation(12, index);
    value.sender = rotatingSenders[index % 5];
    detected = detector.observe(value, report) || detected;
  }
  TEST_ASSERT_TRUE(detected);
  TEST_ASSERT_EQUAL_UINT32(20, report.countInWindow);
}

void test_mac_parser_requires_exact_unicast_address() {
  uint8_t parsed[6]{};
  TEST_ASSERT_TRUE(
      defense_sniffer::parseMacAddress("aa:bb:cc:dd:ee:ff", parsed));
  TEST_ASSERT_EQUAL_UINT8_ARRAY(bssidA, parsed, 5);
  TEST_ASSERT_EQUAL_HEX8(0xff, parsed[5]);
  TEST_ASSERT_FALSE(
      defense_sniffer::parseMacAddress("aa:bb:cc:dd:ee", parsed));
  TEST_ASSERT_FALSE(
      defense_sniffer::parseMacAddress("ab:bb:cc:dd:ee:ff", parsed));
}

void test_sample_preserves_original_length_when_truncated() {
  uint8_t largeFrame[256]{};
  defense_sniffer::DetectorConfig config = testConfig();
  config.deauthThreshold = 1;
  defense_sniffer::MgmtFloodDetector detector(config);
  defense_sniffer::AnomalyReport report;
  defense_sniffer::FrameObservation value = observation(12, 10);
  value.bytes = largeFrame;
  value.length = sizeof(largeFrame);
  value.originalLength = 300;
  TEST_ASSERT_TRUE(detector.observe(value, report));
  TEST_ASSERT_EQUAL_UINT16(300, report.samples[0].originalLength);
  TEST_ASSERT_EQUAL_UINT16(defense_sniffer::kMaximumCapturedFrameBytes,
                           report.samples[0].length);
}

void test_lamp_blinks_and_stops_at_exactly_four_seconds() {
  defense_sniffer::BlinkPattern pattern(4000, 250);
  pattern.trigger(100);
  TEST_ASSERT_TRUE(pattern.update(100));
  TEST_ASSERT_TRUE(pattern.update(349));
  TEST_ASSERT_FALSE(pattern.update(350));
  TEST_ASSERT_TRUE(pattern.update(600));
  TEST_ASSERT_TRUE(pattern.active());
  TEST_ASSERT_FALSE(pattern.update(4100));
  TEST_ASSERT_FALSE(pattern.active());
}

void test_lamp_pattern_survives_millis_rollover() {
  defense_sniffer::BlinkPattern pattern(4000, 250);
  const uint32_t start = std::numeric_limits<uint32_t>::max() - 99U;
  pattern.trigger(start);
  TEST_ASSERT_TRUE(pattern.update(start));
  TEST_ASSERT_FALSE(pattern.update(start + 250U));
  TEST_ASSERT_FALSE(pattern.update(start + 4000U));
  TEST_ASSERT_FALSE(pattern.active());
}

void test_promiscuous_packet_types_are_classified_for_console_stats() {
  using defense_sniffer::PacketClass;
  TEST_ASSERT_EQUAL_UINT8(
      static_cast<uint8_t>(PacketClass::Management),
      static_cast<uint8_t>(defense_sniffer::classifyPacketType(0)));
  TEST_ASSERT_EQUAL_UINT8(
      static_cast<uint8_t>(PacketClass::Control),
      static_cast<uint8_t>(defense_sniffer::classifyPacketType(1)));
  TEST_ASSERT_EQUAL_UINT8(
      static_cast<uint8_t>(PacketClass::Data),
      static_cast<uint8_t>(defense_sniffer::classifyPacketType(2)));
  TEST_ASSERT_EQUAL_UINT8(
      static_cast<uint8_t>(PacketClass::Misc),
      static_cast<uint8_t>(defense_sniffer::classifyPacketType(3)));
  TEST_ASSERT_EQUAL_UINT8(
      static_cast<uint8_t>(PacketClass::Misc),
      static_cast<uint8_t>(defense_sniffer::classifyPacketType(99)));
}

void test_repeated_backend_failures_are_rate_limited() {
  defense_sniffer::FailureLogLimiter limiter;
  auto decision = limiter.observe(-1, 100, 10000);
  TEST_ASSERT_TRUE(decision.shouldLog);
  TEST_ASSERT_EQUAL_UINT32(0, decision.suppressed);

  decision = limiter.observe(-1, 200, 10000);
  TEST_ASSERT_FALSE(decision.shouldLog);
  decision = limiter.observe(-1, 10100, 10000);
  TEST_ASSERT_TRUE(decision.shouldLog);
  TEST_ASSERT_EQUAL_UINT32(1, decision.suppressed);

  decision = limiter.observe(503, 10200, 10000);
  TEST_ASSERT_TRUE(decision.shouldLog);
  TEST_ASSERT_EQUAL_UINT32(0, decision.suppressed);

  limiter.reset();
  decision = limiter.observe(-1, 10300, 10000);
  TEST_ASSERT_TRUE(decision.shouldLog);
}

void test_access_point_identity_includes_channel_and_bssid() {
  uint8_t first[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
  uint8_t second[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02};
  TEST_ASSERT_TRUE(defense_sniffer::sameAccessPoint(11, first, 11, first));
  TEST_ASSERT_FALSE(defense_sniffer::sameAccessPoint(11, first, 1, first));
  TEST_ASSERT_FALSE(defense_sniffer::sameAccessPoint(11, first, 11, second));
  TEST_ASSERT_FALSE(defense_sniffer::sameAccessPoint(11, nullptr, 11, first));
}

}  // namespace

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_deauth_threshold_and_samples);
  RUN_TEST(test_auth_threshold_is_independent);
  RUN_TEST(test_untracked_beacons_do_not_alert);
  RUN_TEST(test_cooldown_suppresses_duplicate_windows);
  RUN_TEST(test_frames_outside_window_do_not_accumulate);
  RUN_TEST(test_sliding_window_detects_burst_across_old_boundary);
  RUN_TEST(test_different_bssids_do_not_share_a_counter);
  RUN_TEST(test_rotating_senders_cannot_evade_bssid_counter);
  RUN_TEST(test_mac_parser_requires_exact_unicast_address);
  RUN_TEST(test_sample_preserves_original_length_when_truncated);
  RUN_TEST(test_lamp_blinks_and_stops_at_exactly_four_seconds);
  RUN_TEST(test_lamp_pattern_survives_millis_rollover);
  RUN_TEST(test_promiscuous_packet_types_are_classified_for_console_stats);
  RUN_TEST(test_repeated_backend_failures_are_rate_limited);
  RUN_TEST(test_access_point_identity_includes_channel_and_bssid);
  return UNITY_END();
}
