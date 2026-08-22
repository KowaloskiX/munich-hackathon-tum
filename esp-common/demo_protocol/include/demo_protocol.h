#pragma once

#include <cstddef>
#include <cstdint>

namespace demo_protocol {

enum class Scenario : std::uint8_t {
    traffic_spike = 1,
    sequence_replay = 2,
    sequence_jump = 3,
    identity_churn = 4,
    malformed_payload = 5,
    deauth_flood = 6,
};

struct DecodedFrame {
    Scenario scenario;
    std::uint16_t logical_count;
    std::uint32_t run_id;
    std::uint32_t sequence;
    std::uint32_t sender_id;
    std::uint32_t sent_ms;
    std::uint8_t frame_length;
    std::uint8_t frame[128];
};

constexpr std::size_t kHeaderSize = 28U;
constexpr std::size_t kChecksumSize = 4U;
constexpr std::size_t kMaxEmbeddedFrameSize = 128U;
constexpr std::size_t kMaxPacketSize =
    kHeaderSize + kMaxEmbeddedFrameSize + kChecksumSize;

const char* scenario_name(Scenario scenario);

std::size_t encode(
    Scenario scenario,
    std::uint16_t logical_count,
    std::uint32_t run_id,
    std::uint32_t sequence,
    std::uint32_t sender_id,
    std::uint32_t sent_ms,
    const std::uint8_t* embedded_frame,
    std::uint8_t embedded_frame_length,
    std::uint8_t* output,
    std::size_t capacity
);

bool decode(const std::uint8_t* packet, std::size_t packet_length, DecodedFrame& output);

std::size_t make_synthetic_deauth_frame(
    const std::uint8_t sender_mac[6],
    std::uint16_t sequence,
    std::uint8_t* output,
    std::size_t capacity
);

}  // namespace demo_protocol
