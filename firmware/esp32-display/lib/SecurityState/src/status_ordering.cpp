#include "status_ordering.h"

namespace defense_hmi {

bool StatusOrdering::sameSnapshot(const SecuritySnapshot& left,
                                  const SecuritySnapshot& right) {
  return left.level == right.level &&
         left.activeAlerts == right.activeAlerts &&
         left.sensorsOnline == right.sensorsOnline &&
         left.sensorsExpected == right.sensorsExpected &&
         left.attackFramesDetected == right.attackFramesDetected &&
         left.incidentId == right.incidentId && left.nodeId == right.nodeId &&
         left.attackClass == right.attackClass;
}

OrderingResult StatusOrdering::accept(uint64_t streamGeneration,
                                      const std::string& streamId,
                                      uint64_t sequence,
                                      const SecuritySnapshot& snapshot,
                                      uint32_t validForMs,
                                      bool allowEqualRefresh) {
  if (streamGeneration == 0 || streamId.empty()) {
    return OrderingResult::Rejected;
  }

  if (!initialized_ || streamGeneration > streamGeneration_) {
    initialized_ = true;
    streamGeneration_ = streamGeneration;
    streamId_ = streamId;
    sequence_ = sequence;
    snapshot_ = snapshot;
    validForMs_ = validForMs;
    return OrderingResult::AcceptedNew;
  }

  if (streamGeneration < streamGeneration_ || streamId != streamId_ ||
      sequence < sequence_) {
    return OrderingResult::Rejected;
  }

  if (sequence == sequence_) {
    if (!allowEqualRefresh || validForMs != validForMs_ ||
        !sameSnapshot(snapshot, snapshot_)) {
      return OrderingResult::Rejected;
    }
    return OrderingResult::AcceptedRefresh;
  }

  sequence_ = sequence;
  snapshot_ = snapshot;
  validForMs_ = validForMs;
  return OrderingResult::AcceptedNew;
}

}  // namespace defense_hmi
