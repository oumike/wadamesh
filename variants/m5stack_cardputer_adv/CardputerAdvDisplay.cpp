#include "CardputerAdvDisplay.h"

#include <M5Cardputer.h>

CardputerAdvDisplay::CardputerAdvDisplay() : DisplayDriver(240, 135) {}

bool CardputerAdvDisplay::begin() {
  auto& lcd = M5Cardputer.Display;
  lcd.setRotation(1);
  lcd.setColorDepth(16);
  lcd.setBrightness(_brightness);
  lcd.fillScreen(0);
  setLogicalSize(lcd.width(), lcd.height());
  _is_on = true;
  Serial.printf("[cardputer] display %dx%d\n", width(), height());
  return width() == 240 && height() == 135;
}

void CardputerAdvDisplay::turnOn() {
  if (_is_on) return;
  M5Cardputer.Display.wakeup();
  M5Cardputer.Display.setBrightness(_brightness);
  _is_on = true;
}

void CardputerAdvDisplay::turnOff() {
  if (!_is_on) return;
  M5Cardputer.Display.setBrightness(0);
  M5Cardputer.Display.sleep();
  _is_on = false;
}

void CardputerAdvDisplay::clear() { M5Cardputer.Display.fillScreen(0); }
void CardputerAdvDisplay::startFrame(ColorVal bkg) { M5Cardputer.Display.fillScreen(bkg); }
void CardputerAdvDisplay::setTextSize(int size) { M5Cardputer.Display.setTextSize(size); }
void CardputerAdvDisplay::setColor(ColorVal color) {
  _color = color;
  M5Cardputer.Display.setTextColor(color);
}
void CardputerAdvDisplay::setCursor(int x, int y) { M5Cardputer.Display.setCursor(x, y); }
void CardputerAdvDisplay::print(const char* text) { M5Cardputer.Display.print(text); }
void CardputerAdvDisplay::fillRect(int x, int y, int width, int height) {
  M5Cardputer.Display.fillRect(x, y, width, height, _color);
}
void CardputerAdvDisplay::drawRect(int x, int y, int width, int height) {
  M5Cardputer.Display.drawRect(x, y, width, height, _color);
}
void CardputerAdvDisplay::drawXbm(int x, int y, const uint8_t* bits, int width, int height) {
  M5Cardputer.Display.drawXBitmap(x, y, bits, width, height, _color);
}
uint16_t CardputerAdvDisplay::getTextWidth(const char* text) {
  return static_cast<uint16_t>(M5Cardputer.Display.textWidth(text ? text : ""));
}
void CardputerAdvDisplay::endFrame() {}

void CardputerAdvDisplay::writePixelsRGB565(
    int x, int y, int width, int height, const uint16_t* pixels) {
  if (!_is_on || !pixels || width <= 0 || height <= 0) return;
  auto& lcd = M5Cardputer.Display;
  lcd.startWrite();
  lcd.pushImage(x, y, width, height,
                reinterpret_cast<const lgfx::rgb565_t*>(pixels));
  lcd.endWrite();
}

void CardputerAdvDisplay::setDisplayRotation(uint8_t) {
  M5Cardputer.Display.setRotation(1);
  setLogicalSize(M5Cardputer.Display.width(), M5Cardputer.Display.height());
}

void CardputerAdvDisplay::setBrightness(uint8_t brightness) {
  _brightness = brightness;
  if (_is_on) M5Cardputer.Display.setBrightness(brightness);
}
