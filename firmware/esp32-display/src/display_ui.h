#pragma once

#include <Arduino.h>

#include "app_config.h"
#include "security_state.h"

#if HMI_DISPLAY_KIND == 1
#include <TFT_eSPI.h>
#elif HMI_DISPLAY_KIND == 2
#include <U8g2lib.h>
#else
#error "Unsupported HMI_DISPLAY_KIND (use 1 for ILI9341 or 2 for SSD1306)"
#endif

namespace defense_hmi {

enum class UiMode : uint8_t {
  ConfigRequired = 0,
  Connecting,
  NoData,
  Safe,
  Attack,
};

class DisplayUi {
 public:
  DisplayUi();

  void begin();
  void toggleDetails();
  void render(UiMode mode, const SecurityState& state, bool wifiConnected,
              bool websocketConnected, uint32_t nowMs, bool force = false);

 private:
  bool shouldRender(UiMode mode, const SecurityState& state, uint32_t nowMs,
                    bool force);
  static String humanize(const std::string& value, size_t maximumLength);
  static String elapsedLabel(uint32_t elapsedMs);

#if HMI_DISPLAY_KIND == 1
  void renderTft(UiMode mode, const SecurityState& state, bool wifiConnected,
                 bool websocketConnected, uint32_t nowMs);
  void renderRoundTft(UiMode mode, const SecurityState& state,
                      bool wifiConnected, bool websocketConnected,
                      uint32_t nowMs);
  void drawTftHeader(const char* label, uint16_t accent, bool connected);
  void drawTftCheck(int16_t x, int16_t y, uint16_t color);
  void drawTftWarning(int16_t x, int16_t y, uint16_t color,
                      bool highlighted);

  TFT_eSPI tft_;
  TFT_eSprite canvas_;
#else
  void renderOled(UiMode mode, const SecurityState& state, bool wifiConnected,
                  bool websocketConnected, uint32_t nowMs);
  U8G2_SSD1306_128X64_NONAME_F_HW_I2C oled_;
#endif

  UiMode previousMode_{UiMode::ConfigRequired};
  uint32_t previousRevision_{UINT32_MAX};
  uint32_t lastRenderMs_{0};
  bool showDetails_{false};
  bool initialized_{false};
};

}  // namespace defense_hmi
