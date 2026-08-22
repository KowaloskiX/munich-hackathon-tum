#include "security_state.h"

#include <algorithm>

namespace defense_hmi {
namespace {

constexpr uint32_t kMinimumTtlMs = 500;
constexpr uint32_t kMaximumTtlMs = 30000;

}  // namespace

uint32_t SecurityState::sanitizeTtl(uint32_t validForMs) {
  return std::max(kMinimumTtlMs, std::min(validForMs, kMaximumTtlMs));
}

void SecurityState::applySnapshot(const SecuritySnapshot& snapshot,
                                  uint32_t nowMs, uint32_t validForMs) {
  const bool wasAttack = snapshot_.level == SecurityLevel::Attack;
  SecuritySnapshot next = snapshot;

  // active_alerts wins over an inconsistent SAFE label. This makes a malformed
  // payload fail toward ATTACK, never toward a false green screen.
  if (next.activeAlerts > 0) {
    next.level = SecurityLevel::Attack;
  }

  // A green screen requires at least one expected sensor and a healthy fleet.
  // The backend can still explicitly report ATTACK while some sensors are down.
  if (next.level == SecurityLevel::Safe &&
      (next.sensorsExpected == 0 || next.sensorsOnline < next.sensorsExpected)) {
    next.level = SecurityLevel::Unknown;
  }

  // Once observed, an attack is latched until an authoritative, fleet-healthy
  // SAFE snapshot arrives. UNKNOWN or stale connectivity must not clear it.
  if (wasAttack && next.level != SecurityLevel::Safe) {
    next.level = SecurityLevel::Attack;
    next.activeAlerts = std::max<uint32_t>(next.activeAlerts, 1);
    if (next.incidentId.empty()) {
      next.incidentId = snapshot_.incidentId;
    }
    if (next.nodeId.empty()) {
      next.nodeId = snapshot_.nodeId;
    }
    if (next.attackClass.empty()) {
      next.attackClass = snapshot_.attackClass;
    }
  }

  snapshot_ = next;

  if (snapshot_.level == SecurityLevel::Attack) {
    if (!wasAttack) {
      attackStartedAtMs_ = nowMs;
    }
    if (snapshot_.activeAlerts == 0) {
      snapshot_.activeAlerts = 1;
    }
  } else {
    attackStartedAtMs_ = 0;
    if (snapshot_.level == SecurityLevel::Safe) {
      snapshot_.incidentId.clear();
      snapshot_.nodeId.clear();
      snapshot_.attackClass.clear();
    }
  }

  hasBackendData_ = true;
  fresh_ = true;
  receivedAtMs_ = nowMs;
  validForMs_ = sanitizeTtl(validForMs);
  ++revision_;
}

bool SecurityState::hasBackendData() const { return hasBackendData_; }

void SecurityState::tick(uint32_t nowMs) {
  // Unsigned subtraction handles one millis() wrap. More importantly, expiry
  // is latched: after data becomes stale it cannot appear fresh again on the
  // next full 32-bit wrap without a newly accepted snapshot.
  if (fresh_ && nowMs - receivedAtMs_ > validForMs_) {
    fresh_ = false;
  }
}

bool SecurityState::isFresh() const { return hasBackendData_ && fresh_; }

uint32_t SecurityState::dataAgeMs(uint32_t nowMs) const {
  if (!hasBackendData_) {
    return 0;
  }
  const uint32_t measuredAge = nowMs - receivedAtMs_;
  return fresh_ ? measuredAge : std::max(measuredAge, validForMs_ + 1);
}

uint32_t SecurityState::attackDurationMs(uint32_t nowMs) const {
  if (snapshot_.level != SecurityLevel::Attack) {
    return 0;
  }
  return nowMs - attackStartedAtMs_;
}

uint32_t SecurityState::revision() const { return revision_; }

const SecuritySnapshot& SecurityState::snapshot() const { return snapshot_; }

}  // namespace defense_hmi
