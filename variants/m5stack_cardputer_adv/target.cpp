#include "target.h"

#include <Arduino.h>
#include <M5Cardputer.h>
#include <utility/PI4IOE5V6408_Class.hpp>

CardputerAdvBoard board;

RADIO_CLASS radio =
    new Module(P_LORA_NSS, P_LORA_DIO_1, P_LORA_RESET, P_LORA_BUSY, SPI);
WRAPPER_CLASS radio_driver(radio, board);

ESP32RTCClock fallback_clock;
ClockFloorRTC rtc_clock(fallback_clock);
EnvironmentSensorManager sensors;
DISPLAY_CLASS display;

namespace {
bool enableLoRaCap() {
  m5::PI4IOE5V6408_Class io_expander(0x43, 400000, &m5::In_I2C);
  if (!io_expander.begin()) {
    Serial.println("[cardputer] LoRa-1262 Cap expander not found at 0x43");
    return false;
  }
  io_expander.setDirection(0, true);
  io_expander.setHighImpedance(0, false);
  io_expander.digitalWrite(0, true);
  delay(12);
  return true;
}
}

bool radio_init() {
  fallback_clock.begin();
  if (!enableLoRaCap()) return false;
  return radio.std_init(&SPI);
}

mesh::LocalIdentity radio_new_identity() {
  RadioNoiseListener rng(radio);
  return mesh::LocalIdentity(&rng);
}

SPIClass* cardputerSharedSPI() { return &SPI; }
