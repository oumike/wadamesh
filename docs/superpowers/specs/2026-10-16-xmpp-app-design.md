# XMPP chat app + relay — design

Issue: [#678](https://github.com/ALLFATHER-BV/wadamesh/issues/678) (Internet messaging).
Status: design approved in conversation (parts 1–2); parts 3–5 under review.

## Goal

A Store app that lets a WADAMESH device use the owner's own XMPP account over
Wi-Fi: 1:1 chats with ordinary XMPP contacts and group chats (MUC rooms). It is
for anyone, each user hosting their own relay; the first real deployment is
`xmpp.sumat.org`.

**Success:** from a T-Deck you can see your contacts and bookmarked rooms, read
what arrived while the app was closed, and send replies that show up in a
normal client (Conversations, Gajim).

## Why a relay

A Lua app has only plain-HTTP `wada.net.http_get/http_post` (one request in
flight, 32 KB reply cap), no TLS and no sockets. Every XMPP server worth using
requires TLS (`xmpp.sumat.org` advertises `<starttls><required/>`, and
`c2s_require_encryption = true`), and XMPP needs a persistent connection. So:

```
device (Lua app) --plain HTTP, sealed--> relay (Python) --XMPP over TLS--> XMPP server
```

Lua apps also only run while open, so the relay keeps the XMPP session and the
history while the device is away.

## Non-goals (v1)

Account registration, room creation, file transfer and images, OMEMO/OTR,
typing indicators, read receipts sent to contacts, roster editing, several
accounts per relay, background notifications on the device.

## 1. Components

### Relay — `scripts/xmpp-relay/xmpp_relay.py`

Not under `deploy/apps/` (that tree is published to the Store and versions are
immutable). One file, one dependency (`slixmpp`), plus a `Dockerfile`,
`relay.ini.example` and `README.md` in the same directory.

- **XMPP side.** Logs in and stays logged in, reconnecting with backoff
  (5 s doubling to 5 min). Loads the roster and tracks contact presence. Joins
  the rooms in the account's bookmarks that are marked autojoin (XEP-0402,
  falling back to XEP-0048 private storage), so a room joined in Conversations
  appears on the device. Enables carbons (XEP-0280), so messages sent from the
  user's other clients appear too.
- **Backfill.** On every (re)connect, queries MAM (XEP-0313) for the account and
  for each joined room since the newest stored message, so an outage does not
  lose history the server kept.
- **History.** SQLite: `conversations(id, jid, kind, name, unread)` and
  `messages(seq, conv_id, stanza_id, time, sender, text)`; `seq` is a global
  autoincrement. The last 50 messages per conversation are kept (configurable).
  Deduplicated by stanza ID so MAM backfill and live delivery cannot double up.
- **Device side.** `POST /w`, sealed body in, sealed body out (section 2). Any
  request that fails the seal check gets `200` with the plain body `DENIED`
  and is not parsed. (Not `403`: `wada.net` reports every non-2xx status as
  `-1`, so the app could not tell a rejection from an unreachable relay.)
  Python's built-in `asyncio` HTTP handling on the same event loop as slixmpp;
  no web framework.
- **Config** (`relay.ini`): `jid`, `password`, `passphrase`, `listen`
  (default `0.0.0.0:8765`), `history` (default 50). Read once at start.

### App — `deploy/apps/xmpp/1.0/xmpp.lua` + `xmpp.json`

Manifest: `{"id":"xmpp","name":"XMPP Chat","ver":"1.0","desc":"Chat with your XMPP contacts and rooms through a relay you host.","icon":"message"}`.
Catalog row has `"seed": false` (needs Wi-Fi and a relay, so not worth flash on
boards without the Store).

Four parts inside the one file:

- **seal** — key derivation, seal/open (section 2).
- **sync** — the 5 s poll loop and the line codec.
- **screens** — setup, conversation list, chat view (section 3).
- **sdlog** — optional on-card history (section 3).

The wire format is tab-separated lines, not JSON: the SDK has no JSON parser and
one written in Lua would burn instruction budget.

## 2. Protocol

### Seal

```
keys      = PBKDF2-HMAC-SHA256(passphrase, salt = "wada-xmpp-v1", 2000 rounds, 64 bytes)
            enc_key = bytes 1..32, mac_key = bytes 33..64
message   = nonce(16) | ciphertext | tag(16)
keystream = HMAC(enc_key, nonce | u32be(block)) for block = 0, 1, 2, ...
ciphertext = plaintext XOR keystream
tag       = first 16 bytes of HMAC(mac_key, dir | nonce | ciphertext)
dir       = "Q" for requests, "P" for replies
```

- Encrypt-then-MAC; the tag is checked before anything is decrypted, compared in
  constant time on the relay.
- Nonces are random on both ends: `wada.sys.random()` is `esp_random()` (the
  hardware RNG, 32 bits per call, four calls per nonce); the relay uses
  `os.urandom`.
- PBKDF2 runs once at setup. Only `enc_key` and `mac_key` (hex) are kept in
  `wada.store`, never the passphrase. 2000 rounds is about 4000 native HMAC
  calls; it is split across timer callbacks so no single callback approaches
  the 100k-instruction budget.
- **Replay protection.** Setup generates a random 64-bit session ID `sid`
  (stored). Every request carries `sid` and a sequence number `q` that must be
  greater than the last `q` the relay accepted for that `sid`; the relay
  persists the highest `q` per `sid`, so a Reset or reinstall (new `sid`)
  starts cleanly while old captured requests stay dead. The app does not write
  `wada.store` per request (flash wear): it reserves blocks of 1000, writing
  `qb` once when the app opens and once per 1000 requests. Numbers skipped by a
  reservation are never used.
- **Reply binding.** Every reply starts with `P <q>` echoing the request's `q`;
  the app drops a reply whose `q` does not match, so an old reply cannot be
  replayed at the device.

### Sync request (plaintext)

```
S <sid> <q> <cursor>
M <conv-id> <client-msg-id> <text>     zero or more: outgoing messages
R <conv-id> <seq>                      zero or more: read up to <seq>
```

### Sync reply (plaintext)

```
P <q>                                                     always first
E xmpp-offline                                            only while the relay is not logged in
C <conv-id> <chat|room> <jid> <name> <presence> <unread>   changed conversations only
G <conv-id> <seq> <unix-time> <sender> <text>              new messages, ascending seq
A <client-msg-id> <ok|err> [reason]                         result of each M line
N <cursor> <more:0|1>
```

- Fields are tab-separated; in text, `\t`, `\n` and `\\` are escaped as `\\t`,
  `\\n`, `\\\\`.
- `sender` is the contact's bare JID in chats, the occupant nick in rooms, and
  empty for the user's own messages (sent from this device or, via carbons and
  room reflection, from another client).
- `presence` is one of `on`, `away`, `off` (rooms: `on` when joined).
- Conversation IDs are small integers the relay assigns; the JID travels only on
  the `C` line.
- `cursor` is the highest `seq` (or conversation revision) the device has.
  Messages and conversation changes share one revision counter, so "changed
  since cursor" covers both. The app keeps the cursor in RAM only and starts
  every open at `0`: with no device-side history it needs a fresh window
  anyway, and it avoids a flash write per sync.
- **Initial sync (`cursor = 0`)** returns every conversation and the newest
  messages of each, up to 10 per conversation, picked round-robin from newest
  down until the reply budget is full. It is never paged: `N` carries the
  relay's current revision and `more = 0`.
- A reply stays under ~6 KB of plaintext so it can be opened in one callback
  (decrypting costs roughly 3–5 VM instructions per byte). When `more = 1` the
  app syncs again immediately instead of waiting 5 s.
- Sending is idempotent: the relay remembers the last 200 `client-msg-id`s, so a
  send retried after a timeout is acknowledged, not posted twice.
- Outgoing text is capped at 1000 bytes (the input dialog's practical limit is
  lower anyway).

## 3. Screens and storage

- **Setup** (first run, or Settings): relay URL (`http://host:port`) and
  passphrase, each via `wada.ui.input`. "Test" runs one sync and reports
  "Connected as <jid>" or the error. Settings also holds "Keep history on SD
  card" (shown only when `caps.sd` and `caps.sdk_ext`) and "Reset" (forget keys
  and cursor).
- **Conversation list** — `wada.ui.list`, one row per conversation: presence dot
  (rooms get a group marker), name, unread count. Unread first, then by latest
  message. Header line shows relay state: "Online", "Relay unreachable",
  "Relay offline from XMPP".
- **Chat view** — `wada.ui.list` of messages. In rooms each row starts with
  the sender's nick; own messages are prefixed `> ` and coloured with the theme
  accent (the list has no right alignment). A "Write" button that opens `wada.ui.input`. Pending
  messages show `…` until their `A` line arrives, then nothing (`ok`) or `!` and
  the reason (`err`). Opening a chat sends `R` for its newest message.
- **Memory bound:** the app keeps at most 50 messages per conversation and 40
  conversations in RAM; older ones are dropped from the view (they stay on the
  relay and, if enabled, on the card).
- **SD history** (optional): one append-only file per conversation in `wada.fs`,
  `c<conv-id>.log`, one escaped line per message. Rotated at 30 KB to
  `c<conv-id>.old` (one generation kept), below the 32 KB file cap. Writes are
  batched and flushed at most once every 2 s, under the ~1 write/s limit; a
  `"too fast"` answer just leaves the batch for the next flush. The card copy
  is not encrypted; the setting's description says so. Opening a chat with SD
  history on loads the tail of its log so scroll-back goes past 50 messages.
  **History is never written to internal flash.** `caps.sd` only means the
  board has a slot, and several boards keep `wada.fs` on internal flash when no
  card was present at boot. The app offers and writes history only when the
  host reports `caps().fs_sd == true` (the app filesystem is the SD card right
  now); a missing `fs_sd` (older firmware) means off. Any write error stops
  logging for the session; nothing falls back to flash.

## 4. Errors

| Condition | Behaviour |
|---|---|
| No Wi-Fi / relay unreachable / timeout | Header shows "Relay unreachable"; retry every 5 s, backing off to 30 s after 6 failures; queued sends kept and resent |
| Body `DENIED` (wrong passphrase, or `q` replayed) | "Passphrase rejected — check Settings"; polling stops until settings change |
| Reply fails the tag check | Dropped, counted, treated like a timeout; three in a row shows "Relay reply corrupted" |
| Relay up but not logged in to XMPP | Relay answers `N` plus an `E xmpp-offline` line; header shows "Relay offline from XMPP"; sends return `err offline` |
| Send rejected by server (e.g. room kicked) | `A ... err <reason>`; message marked `!` |
| Net worker busy (`http_post` refuses) | Skip this tick |
| App closed before a send is acknowledged | Unacknowledged sends are saved in `wada.store` when written (a user action, so no wear concern) and resent on next open; the relay's `client-msg-id` memory stops a duplicate |

## 5. Testing and deployment

- **Relay unit tests** (`scripts/xmpp-relay/test_relay.py`, stdlib `unittest`):
  seal/open round trip, tag tamper, `q` replay, line escaping, reply paging at
  the 6 KB bound, idempotent sends, history trim.
- **Shared test vectors:** a fixed passphrase/nonce/plaintext → expected bytes
  file used by both the Python tests and a Lua test in `scripts/lua-harness`,
  so the two seal implementations cannot drift.
- **Lua harness:** run the app against a stub `wada.net` that replays recorded
  relay replies; check instruction counts stay under budget for a 6 KB reply
  and for key derivation.
- **Live:** relay as a second service in `/home/mike/Projects/xmpp` on donut,
  logged in as a test account on `xmpp.sumat.org`; a second account in
  Conversations to send/receive 1:1 and in a test room on
  `conference.xmpp.sumat.org`. Device test on T-Deck first, then a small screen
  (M9 or Wio Tracker L2) and Heltec V4 for the memory floor.
- **Exposure:** for development, an nginx-proxy-manager proxy host on donut
  forwards plain HTTP to the relay container. This hosting is temporary, so
  nothing is tied to it: the relay's `listen` address and every account and
  passphrase setting live in `relay.ini`, the app takes the relay URL from its
  Setup screen, and neither side hard-codes `sumat.org` or donut. Moving the
  relay is a config change, not a code change.

## Open items

- Test accounts `wadatest1@xmpp.sumat.org` and `wadatest2@xmpp.sumat.org`
  exist; passwords are in `~/Projects/xmpp/wada-test-accounts.txt` on donut
  (mode 600), not in this repo.
- The NPM proxy host name and port are chosen when the relay is first deployed.
