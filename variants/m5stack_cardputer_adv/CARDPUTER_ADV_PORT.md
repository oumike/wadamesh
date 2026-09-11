# M5Stack Cardputer ADV port

Target environment: `m5stack_cardputer_adv_companion_radio`

This target is for the M5Stack Cardputer ADV fitted with the LoRa-1262 Cap. It does not support a bare Cardputer without the radio attachment.

## Hardware basis

- M5Stack Cardputer ADV: ESP32-S3FN8, 8 MB flash, no PSRAM, ST7789V2 240x135 display, TCA8418 keyboard, microSD, and 1750 mAh battery.
- LoRa-1262 Cap: SX1262 connected to the Cardputer ADV EXT bus.
- Display, keyboard, battery, and power handling use the official `M5Cardputer`/`M5Unified` libraries.
- The LoRa pin map and cap-expander enable sequence follow `oumike/camillia-mt`.

## LoRa-1262 Cap wiring

| Signal | GPIO |
| --- | ---: |
| SCK | 40 |
| MISO | 39 |
| MOSI | 14 |
| NSS | 5 |
| DIO1 | 4 |
| RESET | 3 |
| BUSY | 6 |

The cap's PI4IOE5V6408-compatible expander is at I2C address `0x43`. Port 0 is driven high before RadioLib initializes the SX1262.

## Cardputer controls

- `Fn` + `;`, `.`, `,`, `/`: Up, Down, Left, Right
- `Fn` + `1`...`5`: Home, Chats, Contacts, Map status, Settings
- Enter: activate the focused control or send from the composer
- Side button: activate the focused control
- `Fn` + backtick: Back/Escape
- Backspace: delete while editing

The Map tab remains in the navigation layout but reports that maps are unavailable
on this no-PSRAM build; no map worker or tile buffers are allocated.

## Storage

A FAT32 microSD card is required. Identity, MeshCore preferences, contacts,
channels, blobs, and chat history live under `/meshcomod` on the card. Backups
and crash exports are written to the card root. UI settings and Wi-Fi credentials
remain in native NVS. This target has no SPIFFS partition or SPIFFS fallback. If
the card cannot be mounted and verified writable at boot, the firmware shows an
error and waits for the user to insert or repair the card and restart.

## Bring-up checklist

1. Connect an antenna before transmitting.
2. Insert a FAT32 microSD card, then build and upload `m5stack_cardputer_adv_companion_radio`.
3. Verify the display reports `240x135` and the keyboard can complete first-run setup.
4. Verify the boot log reports the LoRa cap expander at `0x43` and radio initialization succeeds.
5. Verify receive, transmit, battery voltage, and persistent identity after a restart.

## No-PSRAM feature budget

The OTA-enabled firmware currently links at 2,719,413 bytes, or 86.4% of each
3 MiB application slot, leaving 426,315 bytes (about 416 KiB) per slot. Static
RAM is 91,580 bytes of 327,680 bytes (27.9%). Flash fits; runtime internal heap
is the limiting resource.

Features disabled or capped in this initial target:

| Component | Reason |
| --- | --- |
| Screen mirror / Remote UI | A 240x135 mirror needs a 384 KB ring, a 64.8 KB RGB565 framebuffer, and two 33 KB work buffers: about 515 KB before socket buffers. The app tiles and mirror initialization are disabled, so none of these buffers allocate. The mirror HTML itself is only about 7.9 KB of flash. |
| Browser terminal/control UI | The Remote page is disabled with the mirror. Enabling only its terminal path would add 16 KB and 24 KB rings plus roughly 16 KB of JSON scratch. |
| Lua apps and Store | Each app has a 256 KB PSRAM heap cap. There is no safe internal-RAM fallback budget. |
| Console mode | Its scrollback is about 16 KB and its command backend currently shares Lua-host APIs. It can return after that dependency is split. |
| On-device Web reader | Parsed text alone reserves 60 KB, with link and HTTP buffers on top. |
| Online/offline map rendering | The 8 KB worker stack is only the floor; decoded RGB565 tiles cost 128 KB each and network/decode buffers add transient pressure. The tab is a status placeholder and no worker is created. |
| Deep SD chat history | The normal SD ring is 5,000 messages (about 1.46 MB). Cardputer uses 64 messages and 24 threads, about 20.8 KB total. |
| Large contact table | Each contact is 184 bytes plus indexes. Cardputer starts at 50 contacts, matching Camillia-MT's no-PSRAM profile. |

Candidates to cut next only if hardware testing shows runtime pressure:

1. Spectrum waterfall: 160 x 48 RGB565, about 15 KB when opened.
2. MQTT bridge, then Wi-Fi/WebSocket companion transport. An USB-only build
   recovers the most remaining internal heap but loses useful connectivity.
3. Web file transfer: three 2,052-byte inbound slots and one 2,053-byte outbound
   slot, about 8.2 KiB allocated when the feature is enabled.
4. Emoji and extended fallback fonts. These primarily cost flash, so they are a
   poor early cut while the application still has about 416 KiB free per slot.

Sources:

- https://docs.m5stack.com/en/core/Cardputer-Adv
- https://github.com/m5stack/M5Cardputer
- https://github.com/oumike/camillia-mt
