#pragma once

#define RADIOLIB_STATIC_ONLY 1
#include <RadioLib.h>
#include <helpers/AutoDiscoverRTCClock.h>
#include <helpers/radiolib/CustomSX1262Wrapper.h>
#include <helpers/radiolib/RadioLibWrappers.h>
#include "../../src/helpers/ClockFloorRTC.h"
#include "CardputerAdvBoard.h"
#include "CardputerAdvDisplay.h"
#include "CardputerAdvKeyboard.h"
#include "helpers/sensors/EnvironmentSensorManager.h"

extern CardputerAdvBoard board;
extern WRAPPER_CLASS radio_driver;
extern RADIO_CLASS radio;
extern ClockFloorRTC rtc_clock;
extern EnvironmentSensorManager sensors;
extern DISPLAY_CLASS display;

bool radio_init();
mesh::LocalIdentity radio_new_identity();
SPIClass* cardputerSharedSPI();
