#pragma once

#include <helpers/ESP32Board.h>

class CardputerAdvBoard : public ESP32Board {
public:
  void begin();
  uint16_t getBattMilliVolts() override;

  const char* getManufacturerName() const override {
    return "M5Stack Cardputer ADV";
  }
};
