# XMPP relay

Lets the wadamesh **XMPP Chat** Store app use your own XMPP account. A Lua app
can only make plain-HTTP requests and only runs while it is open, while XMPP
needs TLS and a connection that stays up. The relay sits in between:

```
device (Lua app) --plain HTTP, sealed--> relay --XMPP over TLS--> your XMPP server
```

It stays logged in, keeps the last messages of every contact and bookmarked
room in SQLite, and answers the app's sync requests on `POST /w`. Each user
hosts their own relay for their own account. Design and wire protocol:
`docs/superpowers/specs/2026-10-16-xmpp-app-design.md` (issue #678).

## What it does

- Logs in, loads the roster and tracks contact presence; reconnects on its own
  (5 s, doubling up to 5 min).
- Joins the rooms in your bookmarks that are marked **autojoin** (XEP-0402,
  falling back to XEP-0048), so a room joined in Conversations or Gajim shows
  up on the device. The relay's nick in a room is the local part of its JID.
- Enables carbons (XEP-0280), so messages you send from other clients appear.
- On every (re)connect, fetches what it missed from the server archive
  (XEP-0313 MAM) for the account and each joined room.
- Deduplicates by stanza ID: device sends carry XEP-0359 `origin-id` = the
  app's message ID, so room reflections, carbons and archive copies of the
  same message are stored once.

Not supported (v1): account registration, room creation, files and images,
OMEMO/OTR, private messages inside rooms, more than one account per relay.

## Setup

1. Copy `relay.ini.example` to `relay.ini` and fill it in:

   | key | meaning |
   |---|---|
   | `jid`, `password` | the XMPP account the relay logs in as |
   | `passphrase` | shared secret you also type into the app's Setup screen |
   | `listen` | plain-HTTP address, default `0.0.0.0:8765` |
   | `history` | messages kept per conversation, default `50` |
   | `db` | SQLite file, default `relay.db` next to `relay.ini` |

   `relay.ini` holds your XMPP password: keep it private (`chmod 600`). It is
   git-ignored and never copied into the Docker image.

2. Run it, either directly (Python 3.10+):

   ```sh
   pip install -r requirements.txt
   python3 xmpp_relay.py relay.ini
   ```

   or with Docker, keeping `relay.ini` and the database in a host directory
   mounted at `/data` (the container runs as uid 10001, which must be able to
   write there):

   ```sh
   docker build -t wada-xmpp-relay scripts/xmpp-relay
   mkdir -p data && cp relay.ini data/ && sudo chown -R 10001 data
   docker run -d --name wada-xmpp-relay --restart unless-stopped \
       -v "$PWD/data:/data" -p 8765:8765 wada-xmpp-relay
   ```

   Logs go to stderr at INFO level. A good start looks like
   `session started as ...`, `roster has N contacts`, `joined N rooms`.
   The password and passphrase are never logged.

3. In the app's Setup screen, enter the relay URL (`http://host:port`, the
   app adds `/w` itself; at most 157 characters) and the same passphrase.

## Exposing it to the device

The device speaks plain HTTP only (no TLS on the board), so the relay listens
on plain HTTP. Behind a reverse proxy such as **nginx-proxy-manager**, create
a proxy host that forwards plain HTTP to the relay's `listen` port, and do not
force HTTPS on it (the device cannot follow a redirect to `https://`). Request
bodies are at most 16 KB.

The traffic is still protected: every request and reply is sealed with keys
derived from the passphrase (encrypt-then-MAC, HMAC-SHA256, replay counter per
device session). Anything that fails the check gets `200` with the body
`DENIED` and is not processed. **The passphrase is the only secret the device
holds** (it stores the derived keys, not the text); the XMPP password never
leaves the relay. Choose a long random passphrase; changing it means entering
the new one on the device.

## Tests

```sh
python3 -m unittest discover -s scripts/xmpp-relay -v
```

The unit tests need neither network nor slixmpp; slixmpp is only imported when
the relay starts. `python3 xmpp_relay.py --gen-vectors` regenerates
`seal_vectors.txt`, shared with the Lua implementation's tests.
