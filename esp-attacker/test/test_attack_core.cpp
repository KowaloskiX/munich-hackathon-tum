#include "attack_core.h"
#include "demo_protocol.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>

using red_esp::AttackConfig;
using red_esp::AttackMode;

int main() {
    AttackMode parsed = AttackMode::traffic_spike;
    assert(red_esp::parse_mode("sequence_replay", parsed));
    assert(parsed == AttackMode::sequence_replay);
    assert(!red_esp::parse_mode("deauth", parsed));

    const AttackConfig valid{AttackMode::traffic_spike, 50U, 10U};
    assert(red_esp::validate_config(valid).ok);
    const AttackConfig too_fast{AttackMode::traffic_spike, 51U, 1U};
    assert(!red_esp::validate_config(too_fast).ok);
    const AttackConfig too_long{AttackMode::traffic_spike, 10U, 11U};
    assert(!red_esp::validate_config(too_long).ok);

    const auto replay0 = red_esp::make_packet_plan(AttackMode::sequence_replay, 7U, 42U);
    const auto replay1 = red_esp::make_packet_plan(AttackMode::sequence_replay, 8U, 42U);
    assert(replay0.sequence == 0U);
    assert(replay1.sequence == 1U);

    const auto jump = red_esp::make_packet_plan(AttackMode::sequence_jump, 3U, 42U);
    assert(jump.sequence == 3000U);
    const auto identity0 = red_esp::make_packet_plan(AttackMode::identity_churn, 7U, 42U);
    const auto identity1 = red_esp::make_packet_plan(AttackMode::identity_churn, 8U, 42U);
    assert(identity0.sender_id != identity1.sender_id);

    std::uint8_t packet[red_esp::kPacketSize]{};
    const auto normal = red_esp::make_packet_plan(AttackMode::traffic_spike, 9U, 42U);
    assert(
        red_esp::encode_packet(
            AttackMode::traffic_spike, 123U, normal, 456U, packet, sizeof(packet)
        ) == red_esp::kPacketSize
    );
    assert(std::memcmp(packet, "TUM1", 4U) == 0);
    assert(red_esp::read_u32_be(packet + 8U) == 123U);
    assert(red_esp::read_u32_be(packet + 12U) == 42U);
    assert(red_esp::read_u32_be(packet + 16U) == 9U);
    assert(red_esp::read_u32_be(packet + 20U) == 456U);

    const auto malformed =
        red_esp::make_packet_plan(AttackMode::malformed_payload, 2U, 42U);
    assert(
        red_esp::encode_packet(
            AttackMode::malformed_payload,
            123U,
            malformed,
            456U,
            packet,
            sizeof(packet)
        ) == red_esp::kPacketSize
    );
    assert(packet[0] == 'X');
    assert(red_esp::encode_packet(
               AttackMode::traffic_spike, 1U, normal, 1U, packet, 4U
           ) == 0U);

    const std::uint8_t sender_mac[6] = {0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U};
    std::uint8_t deauth[32]{};
    const auto deauth_size = demo_protocol::make_synthetic_deauth_frame(
        sender_mac, 17U, deauth, sizeof(deauth)
    );
    assert(deauth_size == 26U);
    assert(deauth[0] == 0xC0U);
    assert(deauth[1] == 0x00U);
    assert(std::memcmp(deauth + 10U, sender_mac, sizeof(sender_mac)) == 0);
    assert(deauth[24] == 0x07U);

    std::uint8_t envelope[demo_protocol::kMaxPacketSize]{};
    const auto envelope_size = demo_protocol::encode(
        demo_protocol::Scenario::deauth_flood,
        80U,
        123U,
        17U,
        42U,
        456U,
        deauth,
        static_cast<std::uint8_t>(deauth_size),
        envelope,
        sizeof(envelope)
    );
    assert(envelope_size > deauth_size);
    demo_protocol::DecodedFrame decoded{};
    assert(demo_protocol::decode(envelope, envelope_size, decoded));
    assert(decoded.scenario == demo_protocol::Scenario::deauth_flood);
    assert(decoded.logical_count == 80U);
    assert(decoded.run_id == 123U);
    assert(decoded.sequence == 17U);
    assert(decoded.frame_length == deauth_size);
    assert(std::memcmp(decoded.frame, deauth, deauth_size) == 0);
    envelope[envelope_size - 1U] ^= 0x01U;
    assert(!demo_protocol::decode(envelope, envelope_size, decoded));

    std::cout << "red ESP attack core: all tests passed\n";
    return 0;
}
