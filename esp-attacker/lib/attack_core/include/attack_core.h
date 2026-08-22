#pragma once

#include <cstddef>
#include <cstdint>

namespace red_esp {

enum class AttackMode : std::uint8_t {
    traffic_spike = 1,
    sequence_replay = 2,
    sequence_jump = 3,
    identity_churn = 4,
    malformed_payload = 5,
    deauth_simulation = 6,
};

struct AttackConfig {
    AttackMode mode;
    std::uint16_t packets_per_second;
    std::uint16_t duration_seconds;
};

struct ValidationResult {
    bool ok;
    const char* message;
};

struct PacketPlan {
    std::uint32_t sequence;
    std::uint32_t sender_id;
    bool corrupt_magic;
    bool corrupt_checksum;
};

constexpr std::size_t kPacketSize = 28U;
constexpr std::uint16_t kMaxPacketsPerSecond = 50U;
constexpr std::uint16_t kMaxDurationSeconds = 10U;
constexpr std::uint32_t kMaxPacketBudget = 500U;

const char* mode_name(AttackMode mode);
bool parse_mode(const char* text, AttackMode& output);
ValidationResult validate_config(const AttackConfig& config);
PacketPlan make_packet_plan(
    AttackMode mode,
    std::uint32_t ordinal,
    std::uint32_t base_sender_id
);
std::size_t encode_packet(
    AttackMode mode,
    std::uint32_t run_id,
    const PacketPlan& plan,
    std::uint32_t uptime_ms,
    std::uint8_t* output,
    std::size_t capacity
);
std::uint32_t read_u32_be(const std::uint8_t* input);

}  // namespace red_esp
