#include "touch_input.h"

#if HMI_TOUCH_ENABLED == 1
#include <Wire.h>
#endif

namespace defense_hmi {

#if HMI_TOUCH_ENABLED == 1
TouchInput::TouchInput()
    : touch_(HMI_TOUCH_SDA, HMI_TOUCH_SCL, HMI_TOUCH_RST, HMI_TOUCH_IRQ) {}
#else
TouchInput::TouchInput() = default;
#endif

void TouchInput::begin() {
#if HMI_TOUCH_ENABLED == 1
  touch_.begin(RISING);
  Wire.beginTransmission(0x15);
  ready_ = Wire.endTransmission() == 0;
  if (ready_) {
    touch_.disable_auto_sleep();
    Serial.println("[touch] CST816S ready at 0x15");
  } else {
    Serial.println("[touch] CST816S not detected at 0x15");
  }
#endif
}

bool TouchInput::consumeTap(uint32_t nowMs) {
#if HMI_TOUCH_ENABLED == 1
  if (!ready_ || !touch_.available()) {
    return false;
  }
  // One physical touch can produce several controller events. The debounce is
  // deliberately UI-only: touch never acknowledges or clears an incident.
  if (nowMs - lastTapMs_ < 350) {
    return false;
  }
  lastTapMs_ = nowMs;
  return true;
#else
  (void)nowMs;
  return false;
#endif
}

}  // namespace defense_hmi
