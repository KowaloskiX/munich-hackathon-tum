#include <unity.h>

#include "security_state.h"
#include "status_ordering.h"

using defense_hmi::OrderingResult;
using defense_hmi::SecurityLevel;
using defense_hmi::SecuritySnapshot;
using defense_hmi::SecurityState;
using defense_hmi::StatusOrdering;

void test_initial_state_has_no_fresh_data() {
  SecurityState state;
  TEST_ASSERT_FALSE(state.hasBackendData());
  state.tick(100);
  TEST_ASSERT_FALSE(state.isFresh());
  TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(SecurityLevel::Unknown),
                          static_cast<uint8_t>(state.snapshot().level));
}

void test_safe_snapshot_expires_instead_of_staying_green() {
  SecurityState state;
  SecuritySnapshot snapshot;
  snapshot.level = SecurityLevel::Safe;
  snapshot.sensorsOnline = 3;
  snapshot.sensorsExpected = 3;
  state.applySnapshot(snapshot, 1000, 5000);

  state.tick(6000);
  TEST_ASSERT_TRUE(state.isFresh());
  state.tick(6001);
  TEST_ASSERT_FALSE(state.isFresh());
}

void test_active_alert_count_overrides_inconsistent_safe_label() {
  SecurityState state;
  SecuritySnapshot snapshot;
  snapshot.level = SecurityLevel::Safe;
  snapshot.activeAlerts = 2;
  state.applySnapshot(snapshot, 1000, 5000);

  TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(SecurityLevel::Attack),
                          static_cast<uint8_t>(state.snapshot().level));
  TEST_ASSERT_EQUAL_UINT32(2, state.snapshot().activeAlerts);
}

void test_attack_snapshot_stays_latched_until_authoritative_clear() {
  SecurityState state;
  SecuritySnapshot safe;
  safe.level = SecurityLevel::Safe;
  safe.sensorsOnline = 3;
  safe.sensorsExpected = 3;
  state.applySnapshot(safe, 1000, 5000);

  SecuritySnapshot attack;
  attack.level = SecurityLevel::Attack;
  attack.activeAlerts = 1;
  attack.nodeId = "esp-03";
  attack.attackClass = "deauth_flood";
  state.applySnapshot(attack, 2000, 5000);

  TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(SecurityLevel::Attack),
                          static_cast<uint8_t>(state.snapshot().level));
  TEST_ASSERT_EQUAL_STRING("esp-03", state.snapshot().nodeId.c_str());

  state.applySnapshot(safe, 3000, 5000);
  TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(SecurityLevel::Safe),
                          static_cast<uint8_t>(state.snapshot().level));
  TEST_ASSERT_EQUAL_STRING("", state.snapshot().nodeId.c_str());
}

void test_monotonic_math_survives_millis_wraparound() {
  SecurityState state;
  SecuritySnapshot snapshot;
  snapshot.level = SecurityLevel::Safe;
  snapshot.sensorsOnline = 3;
  snapshot.sensorsExpected = 3;
  state.applySnapshot(snapshot, UINT32_MAX - 100, 1000);

  state.tick(50);
  TEST_ASSERT_TRUE(state.isFresh());
  TEST_ASSERT_EQUAL_UINT32(151, state.dataAgeMs(50));
}

void test_expired_safe_does_not_revive_after_full_millis_wrap() {
  SecurityState state;
  SecuritySnapshot snapshot;
  snapshot.level = SecurityLevel::Safe;
  snapshot.sensorsOnline = 1;
  snapshot.sensorsExpected = 1;
  state.applySnapshot(snapshot, 1000, 500);

  state.tick(2000);
  TEST_ASSERT_FALSE(state.isFresh());

  // The same low millis value appears again after a complete 2^32-ms cycle.
  state.tick(1001);
  TEST_ASSERT_FALSE(state.isFresh());
}

void test_degraded_fleet_cannot_produce_safe_screen() {
  SecurityState state;
  SecuritySnapshot snapshot;
  snapshot.level = SecurityLevel::Safe;
  snapshot.sensorsOnline = 2;
  snapshot.sensorsExpected = 3;
  state.applySnapshot(snapshot, 1000, 5000);

  TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(SecurityLevel::Unknown),
                          static_cast<uint8_t>(state.snapshot().level));
}

void test_large_sensor_counts_do_not_wrap_into_false_safe() {
  SecurityState state;
  SecuritySnapshot snapshot;
  snapshot.level = SecurityLevel::Safe;
  snapshot.sensorsOnline = 65535;
  snapshot.sensorsExpected = 65536;
  state.applySnapshot(snapshot, 1000, 5000);

  TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(SecurityLevel::Unknown),
                          static_cast<uint8_t>(state.snapshot().level));
}

void test_unknown_snapshot_does_not_clear_latched_attack() {
  SecurityState state;
  SecuritySnapshot attack;
  attack.level = SecurityLevel::Attack;
  attack.activeAlerts = 1;
  attack.nodeId = "esp-03";
  attack.attackClass = "deauth_flood";
  state.applySnapshot(attack, 1000, 5000);

  SecuritySnapshot unknown;
  unknown.level = SecurityLevel::Unknown;
  unknown.sensorsOnline = 2;
  unknown.sensorsExpected = 3;
  state.applySnapshot(unknown, 2000, 5000);

  TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(SecurityLevel::Attack),
                          static_cast<uint8_t>(state.snapshot().level));
  TEST_ASSERT_EQUAL_STRING("deauth_flood",
                           state.snapshot().attackClass.c_str());
}

void test_ordering_rejects_missing_generation_or_stream() {
  StatusOrdering ordering;
  SecuritySnapshot safe;
  safe.level = SecurityLevel::Safe;

  TEST_ASSERT_EQUAL_UINT8(
      static_cast<uint8_t>(OrderingResult::Rejected),
      static_cast<uint8_t>(ordering.accept(0, "boot-a", 1, safe, 10000,
                                           true)));
  TEST_ASSERT_EQUAL_UINT8(
      static_cast<uint8_t>(OrderingResult::Rejected),
      static_cast<uint8_t>(ordering.accept(1, "", 1, safe, 10000, true)));
}

void test_ordering_allows_only_identical_equal_sequence_refresh() {
  StatusOrdering ordering;
  SecuritySnapshot attack;
  attack.level = SecurityLevel::Attack;
  attack.activeAlerts = 1;
  SecuritySnapshot safe;
  safe.level = SecurityLevel::Safe;

  TEST_ASSERT_EQUAL_UINT8(
      static_cast<uint8_t>(OrderingResult::AcceptedNew),
      static_cast<uint8_t>(ordering.accept(7, "boot-a", 42, attack, 10000,
                                           true)));
  TEST_ASSERT_EQUAL_UINT8(
      static_cast<uint8_t>(OrderingResult::AcceptedRefresh),
      static_cast<uint8_t>(ordering.accept(7, "boot-a", 42, attack, 10000,
                                           true)));
  TEST_ASSERT_EQUAL_UINT8(
      static_cast<uint8_t>(OrderingResult::Rejected),
      static_cast<uint8_t>(ordering.accept(7, "boot-a", 42, safe, 10000,
                                           true)));
}

void test_ordering_rejects_old_generation_and_conflicting_stream() {
  StatusOrdering ordering;
  SecuritySnapshot snapshot;
  snapshot.level = SecurityLevel::Attack;
  TEST_ASSERT_EQUAL_UINT8(
      static_cast<uint8_t>(OrderingResult::AcceptedNew),
      static_cast<uint8_t>(ordering.accept(8, "boot-b", 2, snapshot, 10000,
                                           false)));
  TEST_ASSERT_EQUAL_UINT8(
      static_cast<uint8_t>(OrderingResult::Rejected),
      static_cast<uint8_t>(ordering.accept(7, "boot-a", 99, snapshot, 10000,
                                           false)));
  TEST_ASSERT_EQUAL_UINT8(
      static_cast<uint8_t>(OrderingResult::Rejected),
      static_cast<uint8_t>(ordering.accept(8, "boot-other", 3, snapshot,
                                           10000, false)));
}

void test_ordering_accepts_newer_generation_and_sequence() {
  StatusOrdering ordering;
  SecuritySnapshot attack;
  attack.level = SecurityLevel::Attack;
  SecuritySnapshot safe;
  safe.level = SecurityLevel::Safe;

  TEST_ASSERT_EQUAL_UINT8(
      static_cast<uint8_t>(OrderingResult::AcceptedNew),
      static_cast<uint8_t>(ordering.accept(4, "boot-a", 10, attack, 10000,
                                           false)));
  TEST_ASSERT_EQUAL_UINT8(
      static_cast<uint8_t>(OrderingResult::AcceptedNew),
      static_cast<uint8_t>(ordering.accept(4, "boot-a", 11, safe, 10000,
                                           false)));
  TEST_ASSERT_EQUAL_UINT8(
      static_cast<uint8_t>(OrderingResult::AcceptedNew),
      static_cast<uint8_t>(ordering.accept(5, "boot-b", 1, attack, 10000,
                                           false)));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_initial_state_has_no_fresh_data);
  RUN_TEST(test_safe_snapshot_expires_instead_of_staying_green);
  RUN_TEST(test_active_alert_count_overrides_inconsistent_safe_label);
  RUN_TEST(test_attack_snapshot_stays_latched_until_authoritative_clear);
  RUN_TEST(test_monotonic_math_survives_millis_wraparound);
  RUN_TEST(test_expired_safe_does_not_revive_after_full_millis_wrap);
  RUN_TEST(test_degraded_fleet_cannot_produce_safe_screen);
  RUN_TEST(test_large_sensor_counts_do_not_wrap_into_false_safe);
  RUN_TEST(test_unknown_snapshot_does_not_clear_latched_attack);
  RUN_TEST(test_ordering_rejects_missing_generation_or_stream);
  RUN_TEST(test_ordering_allows_only_identical_equal_sequence_refresh);
  RUN_TEST(test_ordering_rejects_old_generation_and_conflicting_stream);
  RUN_TEST(test_ordering_accepts_newer_generation_and_sequence);
  return UNITY_END();
}
