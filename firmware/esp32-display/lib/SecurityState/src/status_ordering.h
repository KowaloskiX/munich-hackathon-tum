#pragma once

#include <cstdint>
#include <string>

#include "security_state.h"

namespace defense_hmi {

enum class OrderingResult : uint8_t {
  Rejected = 0,
  AcceptedNew,
  AcceptedRefresh,
};

// Orders authoritative aggregate snapshots. streamGeneration must be a
// backend-persisted, monotonically increasing value; streamId identifies the
// corresponding backend process and seq orders changes within that process.
class StatusOrdering {
 public:
  OrderingResult accept(uint64_t streamGeneration,
                        const std::string& streamId, uint64_t sequence,
                        const SecuritySnapshot& snapshot,
                        uint32_t validForMs, bool allowEqualRefresh);

 private:
  static bool sameSnapshot(const SecuritySnapshot& left,
                           const SecuritySnapshot& right);

  bool initialized_{false};
  uint64_t streamGeneration_{0};
  std::string streamId_;
  uint64_t sequence_{0};
  SecuritySnapshot snapshot_{};
  uint32_t validForMs_{0};
};

}  // namespace defense_hmi
