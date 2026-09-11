#pragma once

// Cardputer ADV uses the shared LVGL feature set but has no pointer input and
// no PSRAM. Keep keypad navigation responsive and avoid touch-scroll overrides.
#ifndef LV_CONF_H
#define LV_CONF_H
#endif

#include "lv_conf.h"

#ifdef LV_INDEV_DEF_SCROLL_LIMIT
#undef LV_INDEV_DEF_SCROLL_LIMIT
#endif

#ifdef LV_INDEV_DEF_SCROLL_THROW
#undef LV_INDEV_DEF_SCROLL_THROW
#endif
