#include "demo_protocol.h"

#include <cstring>

namespace demo_protocol {
namespace {

constexpr std::uint8_t kMagic[4] = {'T', 'U', 'M', 'D'};
constexpr std::uint8_t kVersion = 1U;
constexpr std::uint8_t kSimulatedFlag = 1U;

void write_u16_be(std::uint8_t* output, std::uint16_t value) {
    output[0] = static_cast<std::uint8_t>(value >> 8U);
    output[1] = static_cast<std::uint8_t>(value);
}

void write_u32_be(std::uint8_t* output, std::uint32_t value) {
    output[0] = static_cast<std::uint8_t>(value >> 24U);
    output[1] = static_cast<std::uint8_t>(value >> 16U);
    output[2] = static_cast<std::uint8_t>(value >> 8U);
    output[3] = static_cast<std::uint8_t>(value);
}

std::uint16_t read_u16_be(const std::uint8_t* input) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(input[0]) << 8U) |
        static_cast<std::uint16_t>(input[1])
    );
}

std::uint32_t read_u32_be(const std::uint8_t* input) {
    return (static_cast<std::uint32_t>(input[0]) << 24U) |
           (static_cast<std::uint32_t>(input[1]) << 16U) |
           (static_cast<std::uint32_t>(input[2]) << 8U) |
           static_cast<std::uint32_t>(input[3]);
}

std::uint32_t fnv1a(const std::uint8_t* data, std::size_t size) {
    std::uint32_t hash = 2166136261U;
    for (std::size_t index = 0U; index < size; ++index) {
        hash ^= data[index];
        hash *= 16777619U;
    }
    return hash;
}

bool valid_scenario(std::uint8_t value) {
    return value >= static_cast<std::uint8_t>(Scenario::traffic_spike) &&
           value <= static_cast<std::uint8_t>(Scenario::deauth_flood);
}

}  // namespace

const char* scenario_name(Scenario scenario) {
    switch (scenario) {
        case Scenario::traffic_spike:
            return "traffic_spike";
        case Scenario::sequence_replay:
            return "sequence_replay";
        case Scenario::sequence_jump:
            return "sequence_jump";
        case Scenario::identity_churn:
            return "identity_churn";
        case Scenario::malformed_payload:
            return "malformed_payload";
        case Scenario::deauth_flood:
            return "synthetic_deauth_flood";
    }
    return "unknown";
}

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
) {
    const std::size_t required =
        kHeaderSize + static_cast<std::size_t>(embedded_frame_length) + kChecksumSize;
    if (output == nullptr || embedded_frame == nullptr || logical_count == 0U ||
        embedded_frame_length == 0U ||
        embedded_frame_length > kMaxEmbeddedFrameSize || capacity < required) {
        return 0U;
    }

    std::memset(output, 0, required);
    std::memcpy(output, kMagic, sizeof(kMagic));
    output[4] = kVersion;
    output[5] = static_cast<std::uint8_t>(scenario);
    output[6] = kSimulatedFlag;
    output[7] = embedded_frame_length;
    write_u16_be(output + 8U, logical_count);
    write_u32_be(output + 12U, run_id);
    write_u32_be(output + 16U, sequence);
    write_u32_be(output + 20U, sender_id);
    write_u32_be(output + 24U, sent_ms);
    std::memcpy(output + kHeaderSize, embedded_frame, embedded_frame_length);
    write_u32_be(output + required - kChecksumSize, fnv1a(output, required - kChecksumSize));
    return required;
}

bool decode(const std::uint8_t* packet, std::size_t packet_length, DecodedFrame& output) {
    if (packet == nullptr || packet_length < kHeaderSize + 1U + kChecksumSize ||
        std::memcmp(packet, kMagic, sizeof(kMagic)) != 0 || packet[4] != kVersion ||
        packet[6] != kSimulatedFlag || !valid_scenario(packet[5])) {
        return false;
    }
    const std::uint8_t frame_length = packet[7];
    const std::size_t expected =
        kHeaderSize + static_cast<std::size_t>(frame_length) + kChecksumSize;
    if (frame_length == 0U || frame_length > kMaxEmbeddedFrameSize ||
        packet_length != expected || read_u16_be(packet + 8U) == 0U ||
        read_u32_be(packet + expected - kChecksumSize) !=
            fnv1a(packet, expected - kChecksumSize)) {
        return false;
    }

    output.scenario = static_cast<Scenario>(packet[5]);
    output.logical_count = read_u16_be(packet + 8U);
    output.run_id = read_u32_be(packet + 12U);
    output.sequence = read_u32_be(packet + 16U);
    output.sender_id = read_u32_be(packet + 20U);
    output.sent_ms = read_u32_be(packet + 24U);
    output.frame_length = frame_length;
    std::memcpy(output.frame, packet + kHeaderSize, frame_length);
    return true;
}

std::size_t make_synthetic_deauth_frame(
    const std::uint8_t sender_mac[6],
    std::uint16_t sequence,
    std::uint8_t* output,
    std::size_t capacity
) {
    constexpr std::size_t frame_size = 26U;
    if (sender_mac == nullptr || output == nullptr || capacity < frame_size) {
        return 0U;
    }
    std::memset(output, 0, frame_size);
    output[0] = 0xC0U;  // Type=management, subtype=deauthentication.
    output[1] = 0x00U;
    std::memset(output + 4U, 0xFF, 6U);  // Embedded demo destination only.
    std::memcpy(output + 10U, sender_mac, 6U);
    std::memcpy(output + 16U, sender_mac, 6U);
    const std::uint16_t sequence_control =
        static_cast<std::uint16_t>((sequence & 0x0FFFU) << 4U);
    output[22] = static_cast<std::uint8_t>(sequence_control);
    output[23] = static_cast<std::uint8_t>(sequence_control >> 8U);
    output[24] = 0x07U;  // Reason: class 3 frame from non-associated station.
    output[25] = 0x00U;
    return frame_size;
}

}  // namespace demo_protocol
