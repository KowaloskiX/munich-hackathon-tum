#pragma once

#include <Arduino.h>

#include "app_config.h"

#if HMI_TOUCH_ENABLED == 1
#include <CST816S.h>
#endif

namespace defense_hmi {

class TouchInput {
 public:
  TouchInput();
  void begin();
  bool consumeTap(uint32_t nowMs);

 private:
#if HMI_TOUCH_ENABLED == 1
  CST816S touch_;
  bool ready_{false};
#endif
  uint32_t lastTapMs_{0};
};

}  // namespace defense_hmi
