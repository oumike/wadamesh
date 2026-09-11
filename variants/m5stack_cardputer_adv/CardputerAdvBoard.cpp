#include "CardputerAdvBoard.h"
#include "CardputerAdvKeyboard.h"

#include <Arduino.h>
#include <M5Cardputer.h>

void CardputerAdvBoard::begin() {
  ESP32Board::begin();

  auto cfg = M5.config();
  cfg.clear_display = true;
  cfg.output_power = true;
  cfg.internal_imu = false;
  cfg.internal_rtc = false;
  cfg.internal_mic = false;
  cfg.internal_spk = false;
  cfg.fallback_board = m5::board_t::board_M5CardputerADV;
  M5Cardputer.begin(cfg, true);
  cardputerKeyboardBegin();

  pinMode(P_LORA_NSS, OUTPUT);
  digitalWrite(P_LORA_NSS, HIGH);
  pinMode(PIN_SD_CS, OUTPUT);
  digitalWrite(PIN_SD_CS, HIGH);
}

uint16_t CardputerAdvBoard::getBattMilliVolts() {
  const int32_t millivolts = M5.Power.getBatteryVoltage();
  return millivolts > 0 && millivolts <= UINT16_MAX
      ? static_cast<uint16_t>(millivolts)
      : 0;
}
