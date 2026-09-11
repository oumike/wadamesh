#pragma once

#include <helpers/ui/DisplayDriver.h>

class CardputerAdvDisplay : public DisplayDriver {
public:
  CardputerAdvDisplay();

  bool begin();
  bool isOn() override { return _is_on; }
  void turnOn() override;
  void turnOff() override;
  void clear() override;
  void startFrame(ColorVal bkg = UIColor::window_bkg) override;
  void setTextSize(int size) override;
  void setColor(ColorVal color) override;
  void setCursor(int x, int y) override;
  void print(const char* text) override;
  void fillRect(int x, int y, int width, int height) override;
  void drawRect(int x, int y, int width, int height) override;
  void drawXbm(int x, int y, const uint8_t* bits, int width, int height) override;
  uint16_t getTextWidth(const char* text) override;
  void endFrame() override;

  void writePixelsRGB565(int x, int y, int width, int height, const uint16_t* pixels);
  void setDisplayRotation(uint8_t rotation);
  void setBrightness(uint8_t brightness);

private:
  bool _is_on = false;
  uint8_t _brightness = 160;
  uint16_t _color = 0xFFFF;
};
