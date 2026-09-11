#include "CardputerAdvKeyboard.h"

#include <Arduino.h>
#include <M5Cardputer.h>

namespace {
constexpr uint8_t kQueueSize = 32;
uint8_t s_queue[kQueueSize] = {};
uint8_t s_head = 0;
uint8_t s_tail = 0;
uint32_t s_last_signature = 0;
bool s_button_down = false;
bool s_started = false;

void enqueue(uint8_t key) {
  if (key == 0) return;
  const uint8_t next = static_cast<uint8_t>((s_head + 1) % kQueueSize);
  if (next == s_tail) s_tail = static_cast<uint8_t>((s_tail + 1) % kQueueSize);
  s_queue[s_head] = key;
  s_head = next;
}

uint32_t keySignature(const Keyboard_Class::KeysState& state) {
  uint32_t hash = 2166136261u;
  auto mix = [&](uint8_t value) {
    hash ^= value;
    hash *= 16777619u;
  };
  mix(state.fn); mix(state.shift); mix(state.ctrl); mix(state.opt); mix(state.alt);
  mix(state.tab); mix(state.enter); mix(state.backspace); mix(state.del); mix(state.esc);
  mix(state.up); mix(state.down); mix(state.left); mix(state.right);
  for (char key : state.word) mix(static_cast<uint8_t>(key));
  for (uint8_t key : state.hid_keys) mix(key);
  return hash;
}
}

void cardputerKeyboardBegin() {
  s_started = true;
  s_head = s_tail = 0;
  s_last_signature = 0;
  s_button_down = false;
}

void cardputerKeyboardPoll() {
  if (!s_started) return;
  static uint32_t s_next_poll_ms = 0;
  const uint32_t now = millis();
  if (static_cast<int32_t>(now - s_next_poll_ms) < 0) return;
  s_next_poll_ms = now + 10;

  M5Cardputer.update();
  const bool button_down = M5Cardputer.BtnA.isPressed();
  if (button_down && !s_button_down) {
    s_button_down = true;
    enqueue(CARDPUTER_KEY_ENTER);
    return;
  }
  s_button_down = button_down;

  auto& state = M5Cardputer.Keyboard.keysState();
  if (!M5Cardputer.Keyboard.isPressed()) {
    s_last_signature = 0;
    return;
  }

  const uint32_t signature = keySignature(state);
  if (signature == s_last_signature) return;
  s_last_signature = signature;

  if (state.esc)        { enqueue(CARDPUTER_KEY_ESCAPE); return; }
  if (state.up)         { enqueue(CARDPUTER_KEY_UP); return; }
  if (state.down)       { enqueue(CARDPUTER_KEY_DOWN); return; }
  if (state.left)       { enqueue(CARDPUTER_KEY_LEFT); return; }
  if (state.right)      { enqueue(CARDPUTER_KEY_RIGHT); return; }
  if (state.enter) {
    enqueue(CARDPUTER_KEY_ENTER);
    return;
  }
  if (state.backspace || state.del) {
    enqueue(CARDPUTER_KEY_BACKSPACE);
    return;
  }
  if (state.f1) { enqueue(CARDPUTER_KEY_HOME); return; }
  if (state.f2) { enqueue(CARDPUTER_KEY_CHATS); return; }
  if (state.f3) { enqueue(CARDPUTER_KEY_CONTACTS); return; }
  if (state.f4) { enqueue(CARDPUTER_KEY_MAP); return; }
  if (state.f5) { enqueue(CARDPUTER_KEY_SETTINGS); return; }
  if (state.tab) enqueue('\t');
  for (char key : state.word) {
    const uint8_t value = static_cast<uint8_t>(key);
    if (value == '\r' || value == '\n') continue;
    if (value >= 0x20) enqueue(value);
  }
}

int cardputerKeyboardReadKey() {
  if (s_tail == s_head) return 0;
  const uint8_t key = s_queue[s_tail];
  s_tail = static_cast<uint8_t>((s_tail + 1) % kQueueSize);
  return key;
}
