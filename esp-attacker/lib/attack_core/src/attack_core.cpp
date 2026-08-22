#include "attack_core.h"

#include <cstring>

namespace red_esp {
namespace {

constexpr std::uint8_t kMagic[4] = {'T', 'U', 'M', '1'};

void write_u32_be(std::uint8_t* output, std::uint32_t value) {
    output[0] = static_cast<std::uint8_t>(value >> 24U);
    output[1] = static_cast<std::uint8_t>(value >> 16U);
    output[2] = static_cast<std::uint8_t>(value >> 8U);
    output[3] = static_cast<std::uint8_t>(value);
}

std::uint32_t fnv1a(const std::uint8_t* data, std::size_t size) {
    std::uint32_t hash = 2166136261U;
    for (std::size_t index = 0; index < size; ++index) {
        hash ^= data[index];
        hash *= 16777619U;
    }
    return hash;
}

}  // namespace

const char* mode_name(AttackMode mode) {
    switch (mode) {
        case AttackMode::traffic_spike:
            return "traffic_spike";
        case AttackMode::sequence_replay:
            return "sequence_replay";
        case AttackMode::sequence_jump:
            return "sequence_jump";
        case AttackMode::identity_churn:
            return "identity_churn";
        case AttackMode::malformed_payload:
            return "malformed_payload";
        case AttackMode::deauth_simulation:
            return "synthetic_deauth_flood";
    }
    return "unknown";
}

bool parse_mode(const char* text, AttackMode& output) {
    if (text == nullptr) {
        return false;
    }
    constexpr AttackMode modes[] = {
        AttackMode::traffic_spike,
        AttackMode::sequence_replay,
        AttackMode::sequence_jump,
        AttackMode::identity_churn,
        AttackMode::malformed_payload,
        AttackMode::deauth_simulation,
    };
    for (AttackMode mode : modes) {
        if (std::strcmp(text, mode_name(mode)) == 0) {
            output = mode;
            return true;
        }
    }
    return false;
}

ValidationResult validate_config(const AttackConfig& config) {
    if (config.packets_per_second == 0U ||
        config.packets_per_second > kMaxPacketsPerSecond) {
        return {false, "packets_per_second must be in range 1..50"};
    }
    if (config.duration_seconds == 0U ||
        config.duration_seconds > kMaxDurationSeconds) {
        return {false, "duration_seconds must be in range 1..10"};
    }
    const auto budget = static_cast<std::uint32_t>(config.packets_per_second) *
                        static_cast<std::uint32_t>(config.duration_seconds);
    if (budget > kMaxPacketBudget) {
        return {false, "physical packet budget exceeds 500"};
    }
    return {true, "ok"};
}

PacketPlan make_packet_plan(
    AttackMode mode,
    std::uint32_t ordinal,
    std::uint32_t base_sender_id
) {
    PacketPlan plan{ordinal, base_sender_id, false, false};
    switch (mode) {
        case AttackMode::traffic_spike:
            break;
        case AttackMode::sequence_replay:
            plan.sequence = ordinal / 8U;
            break;
        case AttackMode::sequence_jump:
            plan.sequence = ordinal * 1000U;
            break;
        case AttackMode::identity_churn:
            plan.sender_id = base_sender_id ^ ((ordinal / 8U) * 2654435761U);
            break;
        case AttackMode::malformed_payload:
            plan.corrupt_magic = (ordinal % 2U) == 0U;
            plan.corrupt_checksum = !plan.corrupt_magic;
            break;
        case AttackMode::deauth_simulation:
            break;
    }
    return plan;
}

std::size_t encode_packet(
    AttackMode mode,
    std::uint32_t run_id,
    const PacketPlan& plan,
    std::uint32_t uptime_ms,
    std::uint8_t* output,
    std::size_t capacity
) {
    if (output == nullptr || capacity < kPacketSize) {
        return 0U;
    }
    std::memset(output, 0, kPacketSize);
    std::memcpy(output, kMagic, sizeof(kMagic));
    output[4] = 1U;  // Protocol version.
    output[5] = static_cast<std::uint8_t>(mode);
    output[6] = plan.corrupt_magic || plan.corrupt_checksum ? 1U : 0U;
    output[7] = static_cast<std::uint8_t>(kPacketSize);
    write_u32_be(output + 8U, run_id);
    write_u32_be(output + 12U, plan.sender_id);
    write_u32_be(output + 16U, plan.sequence);
    write_u32_be(output + 20U, uptime_ms);
    write_u32_be(output + 24U, fnv1a(output, 24U));

    if (plan.corrupt_magic) {
        output[0] = 'X';
    }
    if (plan.corrupt_checksum) {
        output[27] ^= 0xFFU;
    }
    return kPacketSize;
}

std::uint32_t read_u32_be(const std::uint8_t* input) {
    return (static_cast<std::uint32_t>(input[0]) << 24U) |
           (static_cast<std::uint32_t>(input[1]) << 16U) |
           (static_cast<std::uint32_t>(input[2]) << 8U) |
           static_cast<std::uint32_t>(input[3]);
}

}  // namespace red_esp
