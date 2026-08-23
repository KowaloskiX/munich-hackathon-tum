#include "display_ui.h"

#include <algorithm>

#if HMI_DISPLAY_KIND == 2
#include <Wire.h>
#endif

namespace defense_hmi {
namespace {

#if HMI_DISPLAY_KIND == 1
constexpr uint16_t kBackground = 0x0861;
constexpr uint16_t kPanel = 0x10E3;
constexpr uint16_t kMuted = 0x9CF3;
constexpr uint16_t kWhite = 0xFFFF;
constexpr uint16_t kGreen = 0x4FE9;
constexpr uint16_t kGreenDark = 0x0A87;
constexpr uint16_t kRed = 0xF986;
constexpr uint16_t kRedDark = 0x5004;
constexpr uint16_t kAmber = 0xFE44;
constexpr uint16_t kBlue = 0x4D7F;
#endif

}  // namespace

#if HMI_DISPLAY_KIND == 1
DisplayUi::DisplayUi() : canvas_(&tft_) {}
#else
DisplayUi::DisplayUi() : oled_(U8G2_R0, U8X8_PIN_NONE) {}
#endif

void DisplayUi::begin() {
#if HMI_DISPLAY_KIND == 1
  Serial.printf("[display] initializing TFT %dx%d, SPI=%u Hz\n", TFT_WIDTH,
                TFT_HEIGHT, SPI_FREQUENCY);
#if TFT_BL >= 0
  pinMode(TFT_BL, OUTPUT);
  digitalWrite(TFT_BL, TFT_BACKLIGHT_ON == HIGH ? LOW : HIGH);
#endif
  tft_.init();
#if HMI_ROUND_DISPLAY == 1
  tft_.setRotation(0);
#else
  tft_.setRotation(1);
#endif
  canvas_.setColorDepth(16);
  const void* sprite = canvas_.createSprite(tft_.width(), tft_.height());
#if TFT_BL >= 0
  digitalWrite(TFT_BL, TFT_BACKLIGHT_ON);
#endif
  if (sprite == nullptr) {
    Serial.println("[display] unable to allocate the frame buffer");
    tft_.fillScreen(TFT_BLACK);
    tft_.setTextColor(TFT_RED, TFT_BLACK);
    tft_.setTextDatum(MC_DATUM);
    tft_.drawString("DISPLAY ERROR", tft_.width() / 2, tft_.height() / 2, 2);
    return;
  }
  Serial.println("[display] GC9A01A ready; backlight enabled");
#else
  Serial.printf("[display] initializing SSD1306 at 0x%02X\n",
                HMI_OLED_ADDRESS);
  Wire.begin(HMI_OLED_SDA, HMI_OLED_SCL);
  oled_.setI2CAddress(HMI_OLED_ADDRESS << 1);
  oled_.begin();
  Serial.println("[display] SSD1306 ready");
#endif
  initialized_ = true;
}

void DisplayUi::toggleDetails() { showDetails_ = !showDetails_; }

bool DisplayUi::shouldRender(UiMode mode, const SecurityState& state,
                             uint32_t nowMs, bool force) {
  const uint32_t interval = mode == UiMode::Attack ? 250 : 1000;
  if (force || mode != previousMode_ ||
      state.revision() != previousRevision_ ||
      nowMs - lastRenderMs_ >= interval) {
    previousMode_ = mode;
    previousRevision_ = state.revision();
    lastRenderMs_ = nowMs;
    return true;
  }
  return false;
}

String DisplayUi::humanize(const std::string& value, size_t maximumLength) {
  String result(value.c_str());
  result.replace("_", " ");
  result.toUpperCase();
  if (result.length() > maximumLength) {
    result = result.substring(0, maximumLength - 1) + "~";
  }
  return result;
}

String DisplayUi::elapsedLabel(uint32_t elapsedMs) {
  const uint32_t totalSeconds = elapsedMs / 1000;
  if (totalSeconds < 60) {
    return String(totalSeconds) + " s";
  }
  const uint32_t minutes = totalSeconds / 60;
  const uint32_t seconds = totalSeconds % 60;
  return String(minutes) + " min " + String(seconds) + " s";
}

void DisplayUi::render(UiMode mode, const SecurityState& state,
                       bool wifiConnected, bool websocketConnected,
                       uint32_t nowMs, bool force) {
  if (!initialized_ || !shouldRender(mode, state, nowMs, force)) {
    return;
  }

#if HMI_DISPLAY_KIND == 1
  renderTft(mode, state, wifiConnected, websocketConnected, nowMs);
#else
  renderOled(mode, state, wifiConnected, websocketConnected, nowMs);
#endif
}

#if HMI_DISPLAY_KIND == 1
void DisplayUi::drawTftHeader(const char* label, uint16_t accent,
                              bool connected) {
  canvas_.fillRect(0, 0, canvas_.width(), 38, kPanel);
  canvas_.fillRoundRect(12, 11, 14, 14, 7, accent);
  canvas_.setTextDatum(ML_DATUM);
  canvas_.setTextColor(kWhite, kPanel);
  canvas_.drawString("AUTONOMOUS DEFENSE", 34, 18, 2);

  const int16_t pillWidth = 70;
  const int16_t pillX = canvas_.width() - pillWidth - 10;
  canvas_.fillRoundRect(pillX, 9, pillWidth, 20, 10,
                        connected ? kGreenDark : 0x3186);
  canvas_.setTextDatum(MC_DATUM);
  canvas_.setTextColor(connected ? kGreen : kMuted,
                       connected ? kGreenDark : 0x3186);
  canvas_.drawString(label, pillX + pillWidth / 2, 19, 2);
}

void DisplayUi::drawTftCheck(int16_t x, int16_t y, uint16_t color) {
  canvas_.fillCircle(x, y, 49, kGreenDark);
  canvas_.drawCircle(x, y, 48, color);
  canvas_.fillCircle(x, y, 40, color);

  // Two broad anti-aliased strokes produce a clean checkmark at 240x240.
  canvas_.drawWideLine(x - 22, y, x - 5, y + 17, 9, kWhite, color);
  canvas_.drawWideLine(x - 5, y + 17, x + 25, y - 19, 9, kWhite, color);
  canvas_.fillCircle(x - 5, y + 17, 4, kWhite);
}

void DisplayUi::drawTftWarning(int16_t x, int16_t y, uint16_t color,
                               bool highlighted) {
  canvas_.fillCircle(x, y, 48, highlighted ? kRed : kRedDark);
  canvas_.fillTriangle(x, y - 38, x - 38, y + 31, x + 38, y + 31, color);
  canvas_.fillTriangle(x, y - 26, x - 28, y + 24, x + 28, y + 24,
                       kRedDark);
  canvas_.fillRoundRect(x - 4, y - 13, 8, 25, 4, kWhite);
  canvas_.fillCircle(x, y + 20, 4, kWhite);
}

void DisplayUi::renderTft(UiMode mode, const SecurityState& state,
                          bool wifiConnected, bool websocketConnected,
                          uint32_t nowMs) {
#if HMI_ROUND_DISPLAY == 1
  renderRoundTft(mode, state, wifiConnected, websocketConnected, nowMs);
  return;
#endif
  canvas_.fillSprite(kBackground);
  const bool backendConnected = wifiConnected && state.isFresh();
  drawTftHeader(app_config::kDemoMode
                    ? "DEMO"
                    : (websocketConnected ? "LIVE"
                                          : (wifiConnected ? "SYNC" : "OFFLINE")),
                app_config::kDemoMode ? kAmber
                                      : (websocketConnected ? kGreen : kAmber),
                app_config::kDemoMode ? false : backendConnected);

  const SecuritySnapshot& snapshot = state.snapshot();
  canvas_.setTextDatum(MC_DATUM);

  if (mode == UiMode::Safe) {
    drawTftCheck(68, 111, kGreen);
    canvas_.setTextColor(kGreen, kBackground);
    canvas_.drawString("BEZPIECZNIE", 211, 83, 4);
    canvas_.setTextColor(kWhite, kBackground);
    canvas_.drawString("Siec jest monitorowana", 211, 117, 2);
    canvas_.setTextColor(kMuted, kBackground);
    canvas_.drawString(String(snapshot.sensorsOnline) + "/" +
                           String(snapshot.sensorsExpected) + " sensory online",
                       211, 142, 2);
  } else if (mode == UiMode::Attack) {
    const bool flash = ((nowMs / 250) % 2) == 0;
    canvas_.drawRect(2, 2, canvas_.width() - 4, canvas_.height() - 4,
                     flash ? kRed : kAmber);
    canvas_.drawRect(5, 5, canvas_.width() - 10, canvas_.height() - 10,
                     kRedDark);
    drawTftWarning(68, 111, flash ? kRed : kAmber, flash);
    canvas_.setTextColor(kRed, kBackground);
    canvas_.drawString("ATAK WYKRYTY", 211, 72, 4);
    canvas_.setTextColor(kWhite, kBackground);
    String attackClass = humanize(snapshot.attackClass, 22);
    canvas_.drawString(attackClass.length() ? attackClass : "NIEZNANY ATAK",
                       211, 106, 2);
    canvas_.setTextColor(kMuted, kBackground);
    String node = snapshot.nodeId.empty()
                      ? "WEZEL: --"
                      : "WEZEL: " + humanize(snapshot.nodeId, 16);
    canvas_.drawString(node, 211, 130, 2);
    canvas_.drawString("CZAS: " + elapsedLabel(state.attackDurationMs(nowMs)),
                       211, 151, 2);
  } else {
    const uint16_t accent = mode == UiMode::Connecting ? kBlue : kAmber;
    canvas_.drawCircle(68, 111, 44, accent);
    canvas_.drawCircle(68, 111, 43, accent);
    canvas_.setTextColor(accent, kBackground);
    canvas_.drawString(mode == UiMode::Connecting ? "..." : "?", 68, 108,
                       mode == UiMode::Connecting ? 7 : 4);
    canvas_.setTextColor(kWhite, kBackground);
    const char* title = mode == UiMode::ConfigRequired
                            ? "BRAK KONFIGURACJI"
                            : (mode == UiMode::Connecting ? "LACZENIE"
                                                          : "BRAK DANYCH");
    canvas_.drawString(title, 211, 88, 4);
    canvas_.setTextColor(kMuted, kBackground);
    const char* subtitle =
        mode == UiMode::ConfigRequired
            ? "Utworz include/secrets.h"
            : (mode == UiMode::Connecting ? "Czekam na Wi-Fi / backend"
                                          : "Nie zakladamy, ze jest bezpiecznie");
    canvas_.drawString(subtitle, 211, 125, 2);
  }

  canvas_.fillRoundRect(12, 177, canvas_.width() - 24, 48, 10, kPanel);
  canvas_.setTextDatum(ML_DATUM);
  canvas_.setTextColor(kWhite, kPanel);
  canvas_.drawString("STATUS", 24, 192, 2);
  canvas_.setTextColor(kMuted, kPanel);
  String detail;
  if (mode == UiMode::Safe) {
    detail = "dane sprzed " + elapsedLabel(state.dataAgeMs(nowMs));
  } else if (mode == UiMode::Attack) {
    detail = state.isFresh()
                 ? String(snapshot.activeAlerts) + " aktywne alarmy"
                 : "ALARM + TELEMETRIA OFFLINE";
  } else if (mode == UiMode::NoData && state.hasBackendData()) {
    detail = "status wygasl - ponawiam";
  } else {
    detail = String("firmware ") + app_config::kFirmwareVersion;
  }
  canvas_.drawString(detail, 24, 211, 2);

  canvas_.pushSprite(0, 0);
}

void DisplayUi::renderRoundTft(UiMode mode, const SecurityState& state,
                               bool wifiConnected, bool websocketConnected,
                               uint32_t nowMs) {
  const SecuritySnapshot& snapshot = state.snapshot();
  const bool flash = mode == UiMode::Attack && ((nowMs / 250) % 2) == 0;
  const uint16_t accent =
      mode == UiMode::Safe
          ? kGreen
          : (mode == UiMode::Attack
                 ? (flash ? kRed : kAmber)
                 : (mode == UiMode::Connecting ? kBlue : kAmber));

  canvas_.fillSprite(kBackground);
  canvas_.drawCircle(120, 120, 118, accent);
  canvas_.drawCircle(120, 120, 116, mode == UiMode::Attack ? kRedDark : kPanel);

  canvas_.setTextDatum(MC_DATUM);
  if (app_config::kDemoMode) {
    canvas_.fillRoundRect(81, 7, 78, 24, 12, kAmber);
    canvas_.setTextColor(kBackground, kAmber);
    canvas_.drawString("DEMO", 120, 19, 2);
  } else {
    canvas_.setTextColor(kMuted, kBackground);
    canvas_.drawString("DEFENSE HMI", 105, 19, 2);
    const uint16_t linkColor = websocketConnected
                                   ? kGreen
                                   : (wifiConnected && state.isFresh() ? kBlue
                                                                        : kAmber);
    canvas_.fillCircle(170, 19, 4, linkColor);
  }

  if (showDetails_ && (mode == UiMode::Safe || mode == UiMode::Attack)) {
    canvas_.setTextColor(accent, kBackground);
    canvas_.drawString(mode == UiMode::Attack ? "INCYDENT" : "SYSTEM OK", 120,
                       55, 4);

    canvas_.setTextColor(kWhite, kBackground);
    if (mode == UiMode::Attack) {
      const String kind = snapshot.attackClass.empty()
                              ? "NIEZNANY ATAK"
                              : humanize(snapshot.attackClass, 20);
      canvas_.drawString(kind, 120, 91, 2);
      canvas_.setTextColor(kMuted, kBackground);
      canvas_.drawString(snapshot.nodeId.empty()
                             ? "WEZEL --"
                             : "WEZEL " + humanize(snapshot.nodeId, 14),
                         120, 115, 2);
      canvas_.drawString(String(snapshot.activeAlerts) + " AKTYWNE ALARMY", 120,
                         139, 2);
      canvas_.drawString(String(snapshot.attackFramesDetected) +
                             " RAMEK WYKRYTYCH",
                         120, 163, 2);
      canvas_.setTextColor(kWhite, kBackground);
      canvas_.drawString(elapsedLabel(state.attackDurationMs(nowMs)), 120, 190,
                         4);
    } else {
      canvas_.drawString(String(snapshot.sensorsOnline) + " / " +
                             String(snapshot.sensorsExpected),
                         120, 99, 4);
      canvas_.setTextColor(kMuted, kBackground);
      canvas_.drawString("SENSORY ONLINE", 120, 127, 2);
      canvas_.drawString(String(snapshot.attackFramesDetected) +
                             " RAMEK ATAKU",
                         120, 153, 2);
      canvas_.drawString("DANE: " + elapsedLabel(state.dataAgeMs(nowMs)), 120,
                         180, 2);
    }
    canvas_.setTextColor(app_config::kDemoMode || !state.isFresh()
                             ? kAmber
                             : kMuted,
                         kBackground);
    canvas_.drawString(app_config::kDemoMode
                           ? "DEMO - DANE TESTOWE"
                           : (state.isFresh() ? "DOTKNIJ, ABY WROCIC"
                                                   : "ALARM - DANE WYGASLY"),
                       120, 218, 1);
    canvas_.pushSprite(0, 0);
    return;
  }

  if (mode == UiMode::Safe) {
    drawTftCheck(120, 84, kGreen);
    canvas_.setTextColor(kGreen, kBackground);
    canvas_.drawString("BEZPIECZNIE", 120, 145, 4);
    canvas_.setTextColor(kWhite, kBackground);
    canvas_.drawString("SIEC MONITOROWANA", 120, 171, 2);
    canvas_.setTextColor(kMuted, kBackground);
    canvas_.drawString(String(snapshot.sensorsOnline) + "/" +
                           String(snapshot.sensorsExpected) + " SENSORY ONLINE",
                       120, 194, 2);
  } else if (mode == UiMode::Attack) {
    drawTftWarning(120, 82, accent, flash);
    canvas_.setTextColor(kRed, kBackground);
    canvas_.drawString("ATAK", 120, 139, 4);
    canvas_.setTextColor(kWhite, kBackground);
    canvas_.drawString(snapshot.attackClass.empty()
                           ? "NIEZNANY TYP"
                           : humanize(snapshot.attackClass, 20),
                       120, 169, 2);
    canvas_.setTextColor(kMuted, kBackground);
    canvas_.drawString(snapshot.nodeId.empty()
                           ? "WEZEL --"
                           : "WEZEL " + humanize(snapshot.nodeId, 14),
                       120, 191, 2);
  } else {
    canvas_.drawCircle(120, 91, 39, accent);
    canvas_.drawCircle(120, 91, 37, accent);
    canvas_.setTextColor(accent, kBackground);
    canvas_.drawString(mode == UiMode::Connecting ? "..." : "?", 120, 88,
                       mode == UiMode::Connecting ? 7 : 4);
    canvas_.setTextColor(kWhite, kBackground);
    const char* title = mode == UiMode::ConfigRequired
                            ? "KONFIGURACJA"
                            : (mode == UiMode::Connecting ? "LACZENIE"
                                                          : "BRAK DANYCH");
    canvas_.drawString(title, 120, 147, 4);
    canvas_.setTextColor(kMuted, kBackground);
    const char* line1 = mode == UiMode::ConfigRequired
                            ? "UTWORZ secrets.h"
                            : (mode == UiMode::Connecting ? "WIFI / BACKEND"
                                                          : "STATUS WYGASL");
    canvas_.drawString(line1, 120, 176, 2);
    canvas_.drawString(mode == UiMode::NoData ? "SAFE NIEPOTWIERDZONE" :
                                               app_config::kFirmwareVersion,
                       120, 198, 2);
  }

  if (mode == UiMode::Safe || mode == UiMode::Attack) {
    canvas_.setTextColor(app_config::kDemoMode || !state.isFresh()
                             ? kAmber
                             : kMuted,
                         kBackground);
    canvas_.drawString(app_config::kDemoMode
                           ? "DEMO - DANE TESTOWE"
                           : (mode == UiMode::Attack && !state.isFresh()
                                  ? "ALARM - DANE WYGASLY"
                                  : "DOTKNIJ: SZCZEGOLY"),
                       120, 218, 1);
  } else {
    canvas_.fillCircle(120, 218, 3, wifiConnected ? kGreen : kAmber);
  }
  canvas_.pushSprite(0, 0);
}

#else

void DisplayUi::renderOled(UiMode mode, const SecurityState& state,
                           bool wifiConnected, bool websocketConnected,
                           uint32_t nowMs) {
  (void)wifiConnected;
  const SecuritySnapshot& snapshot = state.snapshot();
  const bool flash = mode == UiMode::Attack && ((nowMs / 250) % 2) == 0;

  oled_.clearBuffer();
  oled_.setDrawColor(1);
  if (flash) {
    oled_.drawFrame(0, 0, 128, 64);
    oled_.drawFrame(2, 2, 124, 60);
  }

  oled_.setFont(u8g2_font_6x10_tf);
  oled_.drawStr(4, 9, "DEFENSE HMI");
  oled_.drawStr(101, 9, websocketConnected ? "LIVE" : "SYNC");

  if (mode == UiMode::Safe) {
    oled_.drawCircle(18, 33, 13);
    oled_.drawLine(10, 33, 16, 39);
    oled_.drawLine(16, 39, 27, 25);
    oled_.setFont(u8g2_font_logisoso20_tf);
    oled_.drawStr(38, 39, "SAFE");
    oled_.setFont(u8g2_font_5x8_tf);
    String footer = String(snapshot.sensorsOnline) + "/" +
                    String(snapshot.sensorsExpected) + " NODES  " +
                    elapsedLabel(state.dataAgeMs(nowMs));
    oled_.drawStr(4, 60, footer.c_str());
  } else if (mode == UiMode::Attack) {
    oled_.drawTriangle(18, 18, 5, 43, 31, 43);
    oled_.setFont(u8g2_font_7x14B_tf);
    oled_.drawStr(15, 39, "!");
    oled_.setFont(u8g2_font_logisoso18_tf);
    oled_.drawStr(37, 38, "ATTACK");
    oled_.setFont(u8g2_font_5x8_tf);
    String detail = snapshot.nodeId.empty() ? "UNKNOWN NODE" :
                    humanize(snapshot.nodeId, 12);
    String kind = humanize(snapshot.attackClass, 11);
    if (kind.length()) {
      detail += "  " + kind;
    }
    oled_.drawStr(4, 59,
                  state.isFresh() ? detail.c_str() : "ATTACK - DATA STALE");
  } else {
    oled_.drawCircle(18, 33, 13);
    oled_.setFont(u8g2_font_7x14B_tf);
    oled_.drawStr(15, 38, "?");
    oled_.setFont(u8g2_font_7x14B_tf);
    const char* title = mode == UiMode::ConfigRequired
                            ? "CONFIG"
                            : (mode == UiMode::Connecting ? "CONNECT"
                                                          : "NO DATA");
    oled_.drawStr(38, 37, title);
    oled_.setFont(u8g2_font_5x8_tf);
    const char* footer = mode == UiMode::ConfigRequired
                             ? "CREATE secrets.h"
                             : "SAFE NOT ASSUMED";
    oled_.drawStr(4, 59, footer);
  }

  oled_.sendBuffer();
}
#endif

}  // namespace defense_hmi
