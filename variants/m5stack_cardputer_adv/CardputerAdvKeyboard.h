#pragma once

#include <stdint.h>

#define CARDPUTER_KEY_LEFT       0xB4
#define CARDPUTER_KEY_UP         0xB5
#define CARDPUTER_KEY_DOWN       0xB6
#define CARDPUTER_KEY_RIGHT      0xB7
#define CARDPUTER_KEY_ENTER      0x0D
#define CARDPUTER_KEY_BACKSPACE  0x08
#define CARDPUTER_KEY_ESCAPE     0x1B
#define CARDPUTER_KEY_HOME       0xC0
#define CARDPUTER_KEY_CHATS      0xC1
#define CARDPUTER_KEY_CONTACTS   0xC2
#define CARDPUTER_KEY_MAP        0xC3
#define CARDPUTER_KEY_SETTINGS   0xC4

void cardputerKeyboardBegin();
void cardputerKeyboardPoll();
int cardputerKeyboardReadKey();
