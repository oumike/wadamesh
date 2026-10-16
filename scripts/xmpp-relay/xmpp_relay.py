#!/usr/bin/env python3
"""wadamesh XMPP relay.

Sections: seal (crypto), codec, history, sync handler, HTTP endpoint, inbound
routing, config, XMPP session, main.
slixmpp must only be imported lazily, never at module top level.

Usage: python3 xmpp_relay.py relay.ini
       python3 xmpp_relay.py --gen-vectors > seal_vectors.txt
       python3 xmpp_relay.py --gen-reply-fixture > reply_fixture.txt
"""
import asyncio
import configparser
import hashlib
import hmac
import inspect
import logging
import os
import signal
import sqlite3
import sys
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

# ---------------------------------------------------------------- seal

SALT = b"wada-xmpp-v1"
ROUNDS = 2000
NONCE_LEN = 16
TAG_LEN = 16


def derive_keys(passphrase: str):
    k = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), SALT, ROUNDS, 64)
    return k[:32], k[32:]


def _keystream(enc: bytes, nonce: bytes, n: int) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hmac.new(enc, nonce + i.to_bytes(4, "big"), hashlib.sha256).digest()
        i += 1
    return bytes(out[:n])


def _tag(mac: bytes, direction: bytes, nonce: bytes, ct: bytes) -> bytes:
    return hmac.new(mac, direction + nonce + ct, hashlib.sha256).digest()[:TAG_LEN]


def seal(enc, mac, direction, plaintext, nonce=None):
    if nonce is None:
        nonce = os.urandom(NONCE_LEN)
    ks = _keystream(enc, nonce, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    return nonce + ct + _tag(mac, direction, nonce, ct)


def open_sealed(enc, mac, direction, msg):
    if len(msg) < NONCE_LEN + TAG_LEN:
        return None
    nonce, ct, tag = msg[:NONCE_LEN], msg[NONCE_LEN:-TAG_LEN], msg[-TAG_LEN:]
    if not hmac.compare_digest(tag, _tag(mac, direction, nonce, ct)):
        return None
    ks = _keystream(enc, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


def gen_vectors(out):
    pw = "correct horse battery staple"
    pw2 = "pässwörd ☃"
    lens = [0, 1, 31, 32, 33, 100, 6000]
    cases = []
    for idx, n in enumerate(lens):
        pt = bytes((i * 7 + idx) % 256 for i in range(n))
        cases.append((pw, b"Q" if idx % 2 == 0 else b"P", pt))
    cases.append((pw2, b"Q", "héllo wörld ☃ \U0001f600".encode("utf-8")))
    cases.append((pw2, b"P", "你好，世界".encode("utf-8")))
    seen = set()
    for p, _, _ in cases:
        if p not in seen:
            seen.add(p)
            e, m = derive_keys(p)
            out.write("K\t%s\t%s\t%s\n" % (p, e.hex(), m.hex()))
    for n, (p, d, pt) in enumerate(cases):
        e, m = derive_keys(p)
        nonce = bytes((n * 16 + i) % 256 for i in range(NONCE_LEN))
        s = seal(e, m, d, pt, nonce=nonce)
        out.write("V\t%s\t%s\t%s\t%s\t%s\n" % (p, d.decode(), nonce.hex(), pt.hex(), s.hex()))


# ---------------------------------------------------------------- codec

MAX_SEND_BYTES = 1000
MAX_G_TEXT_BYTES = 1000


def esc(s: str) -> str:
    return (s.replace("\\", "\\\\").replace("\t", "\\t")
            .replace("\r", "").replace("\n", "\\n"))


def unesc(s: str) -> str:
    out = []
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "\\" and i + 1 < n:
            nx = s[i + 1]
            if nx == "t":
                out.append("\t")
            elif nx == "n":
                out.append("\n")
            elif nx == "\\":
                out.append("\\")
            else:
                out.append(nx)
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def cut_utf8(s: str, max_bytes: int) -> str:
    b = s.encode("utf-8")
    if len(b) <= max_bytes:
        return s
    return b[:max_bytes].decode("utf-8", errors="ignore")


@dataclass
class Request:
    sid: str
    q: int
    cursor: int
    sends: list = field(default_factory=list)   # (conv, cmid, text)
    reads: list = field(default_factory=list)   # (conv, seq)


def parse_request(text: str) -> Request:
    lines = [l for l in text.split("\n") if l != ""]
    if not lines:
        raise ValueError("empty request")
    p = lines[0].split("\t")
    if p[0] != "S" or len(p) != 4 or not p[1]:
        raise ValueError("missing S line")
    try:
        req = Request(p[1], int(p[2]), int(p[3]))
    except ValueError:
        raise ValueError("bad S line")
    for line in lines[1:]:
        f = line.split("\t", 3)
        try:
            if f[0] == "M" and len(f) == 4:
                req.sends.append((int(f[1]), f[2], unesc(f[3])))
            elif f[0] == "R" and len(f) == 3:
                req.reads.append((int(f[1]), int(f[2])))
        except ValueError:
            continue
    return req


# ---------------------------------------------------------------- history


class SendError(Exception):
    def __init__(self, reason="error"):
        super().__init__(reason)
        self.reason = reason


class History:
    def __init__(self, path: str, keep: int = 50):
        self.keep = keep
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v INTEGER);
            CREATE TABLE IF NOT EXISTS conversations(
                id INTEGER PRIMARY KEY, jid TEXT UNIQUE, kind TEXT, name TEXT,
                presence TEXT, last_read INTEGER, rev INTEGER);
            CREATE TABLE IF NOT EXISTS messages(
                seq INTEGER PRIMARY KEY, conv INTEGER, stanza_id TEXT UNIQUE,
                ts INTEGER, sender TEXT, text TEXT);
            CREATE INDEX IF NOT EXISTS messages_conv ON messages(conv, seq);
            CREATE TABLE IF NOT EXISTS sessions(sid TEXT PRIMARY KEY, q INTEGER);
            CREATE TABLE IF NOT EXISTS aliases(id TEXT PRIMARY KEY, seq INTEGER);
            INSERT OR IGNORE INTO meta(k, v) VALUES('rev', 0);
        """)
        self.db.commit()

    def _bump(self) -> int:
        self.db.execute("UPDATE meta SET v = v + 1 WHERE k = 'rev'")
        return self.db.execute("SELECT v FROM meta WHERE k = 'rev'").fetchone()[0]

    def rev(self) -> int:
        with self.lock:
            return self.db.execute("SELECT v FROM meta WHERE k = 'rev'").fetchone()[0]

    def conv_for(self, jid: str, kind: str, name: str) -> int:
        with self.lock:
            row = self.db.execute(
                "SELECT id, kind, name FROM conversations WHERE jid = ?", (jid,)).fetchone()
            if row:
                if (row[1], row[2]) != (kind, name):
                    rv = self._bump()
                    self.db.execute(
                        "UPDATE conversations SET kind=?, name=?, rev=? WHERE id=?",
                        (kind, name, rv, row[0]))
                    self.db.commit()
                return row[0]
            rv = self._bump()
            cur = self.db.execute(
                "INSERT INTO conversations(jid, kind, name, presence, last_read, rev) "
                "VALUES(?,?,?,?,0,?)", (jid, kind, name, "off", rv))
            self.db.commit()
            return cur.lastrowid

    def set_presence(self, conv: int, presence: str) -> None:
        with self.lock:
            row = self.db.execute(
                "SELECT presence FROM conversations WHERE id = ?", (conv,)).fetchone()
            if row is None or row[0] == presence:
                return
            rv = self._bump()
            self.db.execute("UPDATE conversations SET presence=?, rev=? WHERE id=?",
                            (presence, rv, conv))
            self.db.commit()

    def add_message(self, conv, stanza_id, ts, sender, text):
        with self.lock:
            if stanza_id is not None and self.db.execute(
                    "SELECT 1 FROM messages WHERE stanza_id = ?", (stanza_id,)).fetchone():
                return None
            rv = self._bump()
            self.db.execute(
                "INSERT INTO messages(seq, conv, stanza_id, ts, sender, text) "
                "VALUES(?,?,?,?,?,?)", (rv, conv, stanza_id, int(ts), sender, text))
            self.db.execute("UPDATE conversations SET rev=? WHERE id=?", (rv, conv))
            self.db.execute(
                "DELETE FROM messages WHERE conv=? AND seq NOT IN "
                "(SELECT seq FROM messages WHERE conv=? ORDER BY seq DESC LIMIT ?)",
                (conv, conv, self.keep))
            self.db.commit()
            return rv

    def mark_read(self, conv: int, seq: int) -> None:
        with self.lock:
            row = self.db.execute(
                "SELECT last_read FROM conversations WHERE id = ?", (conv,)).fetchone()
            if row is None or seq <= row[0]:
                return
            rv = self._bump()
            self.db.execute("UPDATE conversations SET last_read=?, rev=? WHERE id=?",
                            (seq, rv, conv))
            self.db.commit()

    def accept_q(self, sid: str, q: int) -> bool:
        with self.lock:
            row = self.db.execute("SELECT q FROM sessions WHERE sid = ?", (sid,)).fetchone()
            if row is not None and q <= row[0]:
                return False
            self.db.execute("INSERT OR REPLACE INTO sessions(sid, q) VALUES(?,?)", (sid, q))
            self.db.commit()
            return True

    def newest_ts(self, conv: int):
        with self.lock:
            row = self.db.execute(
                "SELECT MAX(ts) FROM messages WHERE conv = ?", (conv,)).fetchone()
            return row[0]


# ---------------------------------------------------------------- sync handler

OFFLINE_REASON = "offline"
N_RESERVE = 32          # bytes held back for the closing N line
INITIAL_PER_CONV = 10
CMID_MEMORY = 200


class SyncHandler:
    def __init__(self, history: History, xmpp, budget: int = 6000):
        self.h = history
        self.xmpp = xmpp
        self.budget = budget
        self.acks = OrderedDict()   # cmid -> "ok" | "err\treason"
        self.lock = threading.RLock()

    @staticmethod
    def _line(*fields) -> str:
        return "\t".join(str(f) for f in fields) + "\n"

    def _send(self, conv, cmid, text) -> str:
        if cmid in self.acks:
            return self.acks[cmid]
        if not self.xmpp.online:
            return "err\t" + OFFLINE_REASON       # not remembered: retry later
        text = cut_utf8(text, MAX_SEND_BYTES)
        try:
            self.xmpp.send(conv, text, cmid)
            self.h.add_message(conv, cmid, int(time.time()), "", text)
            res = "ok"
        except SendError as e:
            res = "err\t" + esc(e.reason)
        self.acks[cmid] = res
        while len(self.acks) > CMID_MEMORY:
            self.acks.popitem(last=False)
        return res

    def handle(self, text: str) -> str:
        with self.lock:
            return self._handle(parse_request(text))

    def _handle(self, req: Request) -> str:
        h = self.h
        acks = []
        for conv, cmid, body in req.sends:
            acks.append(self._line("A", cmid, *self._send(conv, cmid, body).split("\t")))
        for conv, seq in req.reads:
            h.mark_read(conv, seq)

        head = self._line("P", req.q)
        if not self.xmpp.online:
            head += self._line("E", "xmpp-offline")
        with h.lock:
            for cid, kind, jid, name, pres, rev in h.db.execute(
                    "SELECT id, kind, jid, name, presence, rev FROM conversations "
                    "WHERE rev > ? ORDER BY id", (req.cursor,)).fetchall():
                unread = h.db.execute(
                    "SELECT COUNT(*) FROM messages WHERE conv=? AND sender != '' "
                    "AND seq > (SELECT last_read FROM conversations WHERE id=?)",
                    (cid, cid)).fetchone()[0]
                head += self._line("C", cid, kind, esc(jid), esc(name), pres, unread)
            head += "".join(acks)
            room = self.budget - len(head.encode("utf-8")) - N_RESERVE
            if req.cursor == 0:
                gl, more, last = self._initial(room)
            else:
                gl, more, last = self._incremental(req.cursor, room)
            ncur = last if more else h.rev()
        return head + "".join(l for _, l in gl) + self._line("N", ncur, 1 if more else 0)

    def _gline(self, row):
        seq, conv, ts, sender, text = row
        return self._line("G", conv, seq, ts, esc(sender),
                          esc(cut_utf8(text, MAX_G_TEXT_BYTES)))

    def _initial(self, room):
        db = self.h.db
        convs = [r[0] for r in db.execute(
            "SELECT c.id FROM conversations c LEFT JOIN "
            "(SELECT conv, MAX(seq) m FROM messages GROUP BY conv) x ON x.conv = c.id "
            "ORDER BY COALESCE(x.m, 0) DESC, c.id")]
        per = {}
        for c in convs:
            per[c] = db.execute(
                "SELECT seq, conv, ts, sender, text FROM messages WHERE conv=? "
                "ORDER BY seq DESC LIMIT ?", (c, INITIAL_PER_CONV)).fetchall()
        chosen = []
        used = 0
        full = False
        for rnd in range(INITIAL_PER_CONV):
            for c in convs:
                if rnd < len(per[c]):
                    line = self._gline(per[c][rnd])
                    n = len(line.encode("utf-8"))
                    if used + n > room:
                        full = True
                        break
                    used += n
                    chosen.append((per[c][rnd][0], line))
            if full:
                break
        chosen.sort()
        return chosen, False, 0

    def _incremental(self, cursor, room):
        rows = self.h.db.execute(
            "SELECT seq, conv, ts, sender, text FROM messages WHERE seq > ? "
            "ORDER BY seq", (cursor,)).fetchall()
        out = []
        used = 0
        more = False
        for i, row in enumerate(rows):
            line = self._gline(row)
            n = len(line.encode("utf-8"))
            if out and used + n > room:
                more = True
                break
            used += n
            out.append((row[0], line))
        return out, more, (out[-1][0] if out else 0)


def gen_reply_fixture(out):
    """A full (~6000-byte) initial-sync reply, for the Lua app's codec tests.

    Deterministic: in-memory history, fixed timestamps, no clock reads.
    """
    class _Port:
        online = True

        def send(self, conv, text, cmid):
            raise SendError("not-acceptable: room\tclosed")

    h = History(":memory:")
    convs = [
        h.conv_for("alice@example.net", "chat", "Alice Liddell"),
        h.conv_for("bob@example.org", "chat", "Bob \U0001f6b2"),
        h.conv_for("lounge@conference.example.net", "room", "The\tLounge"),
        h.conv_for("carol@example.com", "chat", "Carol Ångström"),
        h.conv_for("dev@conference.example.org", "room", "Dev \\ team"),
        h.conv_for("dave@example.net", "chat", "Dave"),
        h.conv_for("erin@example.net", "chat", "Erin O'Brien"),
        h.conv_for("radio@conference.example.net", "room", "Radio ☎ club"),
    ]
    h.set_presence(convs[0], "on")
    h.set_presence(convs[1], "away")
    h.set_presence(convs[2], "on")
    h.set_presence(convs[4], "on")
    texts = [
        "Hi! Are you around later today?",
        "line one\nline two\nline three",
        "tab\tseparated\tvalues and a back\\slash",
        "emoji time \U0001f600\U0001f44d\U0001f389 and more \u2603",
        "héllo wörld, ça va? 你好，世界",
        "C:\\Users\\nobody\\notes.txt is where I left it",
        "Meeting moved to 15:30, room 4B. Bring the radio and the spare battery pack.",
        "ok",
        "trailing newline\n",
        "Long-ish message: the quick brown fox jumps over the lazy dog, twice. " * 2,
    ]
    senders = {
        convs[0]: "alice@example.net", convs[1]: "bob@example.org",
        convs[2]: "rabbit", convs[3]: "carol@example.com",
        convs[4]: "hacker\twith tab", convs[5]: "dave@example.net",
        convs[6]: "erin@example.net", convs[7]: "KD9XYZ",
    }
    ts = 1760000000
    n = 0
    for rnd in range(12):
        for c in convs:
            own = (n % 4 == 3)
            h.add_message(c, "id-%d" % n, ts + 37 * n, "" if own else senders[c],
                          texts[(n * 7 + rnd) % len(texts)])
            n += 1
    h.mark_read(convs[0], 5)
    handler = SyncHandler(h, _Port())
    handler.acks["cm-ok"] = "ok"
    out.write(handler.handle(
        "S\tfixture\t7\t0\nM\t%d\tcm-ok\thi\nM\t%d\tcm-err\tyo\nR\t%d\t3\n"
        % (convs[0], convs[2], convs[1])))


# ---------------------------------------------------------------- device endpoint

log = logging.getLogger("xmpp-relay")

DENIED = b"DENIED"
MAX_BODY = 16384
HTTP_READ_TIMEOUT = 20


def _fallback_reply(req: Request) -> str:
    # Keeps the device's view unchanged (N = its own cursor); unacked sends are
    # retried by the device and the cmid memory stops duplicates.
    return "P\t%d\nN\t%d\t0\n" % (req.q, req.cursor)


def handle_body(body: bytes, keys, handler, history) -> bytes:
    """Sealed request in, sealed reply (or DENIED) out. Never raises."""
    enc, mac = keys
    try:
        pt = open_sealed(enc, mac, b"Q", body)
        if pt is None:
            return DENIED
        text = pt.decode("utf-8", errors="replace")
        req = parse_request(text)
    except Exception:
        return DENIED
    try:
        if not history.accept_q(req.sid, req.q):
            return DENIED
    except Exception:
        log.exception("replay check failed")
        return seal(enc, mac, b"P", _fallback_reply(req).encode("utf-8"))
    try:
        reply = handler.handle(text)
    except Exception:
        log.exception("sync failed")
        reply = _fallback_reply(req)
    return seal(enc, mac, b"P", reply.encode("utf-8"))


_REASONS = {200: "OK", 400: "Bad Request", 404: "Not Found", 408: "Request Timeout",
            411: "Length Required", 413: "Payload Too Large",
            500: "Internal Server Error"}


async def _read_request(reader):
    """Returns (status, body); body is set only for an acceptable POST /w."""
    line = await reader.readline()
    parts = line.decode("latin-1").split()
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        return 400, None
    method, target = parts[0], parts[1]
    headers = {}
    for _ in range(100):
        h = await reader.readline()
        if h in (b"\r\n", b"\n", b""):
            break
        k, sep, v = h.decode("latin-1").partition(":")
        if not sep:
            return 400, None
        headers[k.strip().lower()] = v.strip()
    else:
        return 400, None
    if method != "POST" or target.split("?", 1)[0] != "/w":
        return 404, None
    if "transfer-encoding" in headers or "content-length" not in headers:
        return 411, None
    try:
        n = int(headers["content-length"])
    except ValueError:
        return 400, None
    if n < 0:
        return 400, None
    if n > MAX_BODY:
        return 413, None
    return 200, await reader.readexactly(n)


async def serve_http(host: str, port: int, on_body):
    """Minimal HTTP/1.1: POST /w with a body of at most MAX_BODY bytes."""
    async def client(reader, writer):
        try:
            try:
                status, body = await asyncio.wait_for(_read_request(reader),
                                                      HTTP_READ_TIMEOUT)
            except asyncio.TimeoutError:
                status, body = 408, None
            except (ValueError, asyncio.IncompleteReadError, ConnectionError):
                status, body = 400, None
            out = b""
            if status == 200:
                try:
                    out = on_body(body)
                    if inspect.isawaitable(out):
                        out = await out
                except Exception:
                    log.exception("request handler failed")
                    status, out = 500, b""
            head = ("HTTP/1.1 %d %s\r\nContent-Type: application/octet-stream\r\n"
                    "Content-Length: %d\r\nConnection: close\r\n\r\n"
                    % (status, _REASONS.get(status, "Error"), len(out)))
            writer.write(head.encode("latin-1") + out)
            await writer.drain()
        except Exception as e:
            log.debug("http client error: %r", e)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    return await asyncio.start_server(client, host, port, limit=8192)


# ---------------------------------------------------------------- inbound routing

def ingest(history, conv, ids, ts, sender, text):
    """Store a message unless any of its ids (MAM archive id, stanza-id,
    origin-id) is already known. The first id becomes messages.stanza_id, the
    rest are kept as aliases for as long as the message is. -> seq | None."""
    ids = list(dict.fromkeys(i for i in ids if i))
    db = history.db
    with history.lock:
        for i in ids:
            if db.execute("SELECT 1 FROM messages WHERE stanza_id = ?", (i,)).fetchone() \
                    or db.execute("SELECT 1 FROM aliases WHERE id = ?", (i,)).fetchone():
                return None
        seq = history.add_message(conv, ids[0] if ids else None, ts, sender, text)
        if seq is not None and len(ids) > 1:
            db.executemany("INSERT OR IGNORE INTO aliases(id, seq) VALUES(?,?)",
                           [(i, seq) for i in ids[1:]])
            db.execute("DELETE FROM aliases WHERE seq NOT IN (SELECT seq FROM messages)")
            db.commit()
        return seq


def route(own_bare, rooms, mtype, frm_bare, frm_res, to_bare, self_occupant=False):
    """Where an inbound message belongs: (peer_jid, kind, sender) or None.
    rooms maps joined room JID -> our nick there. sender "" means "us"."""
    if mtype == "groupchat":
        if frm_bare not in rooms or not frm_res:
            return None
        own = self_occupant or frm_res == rooms[frm_bare]
        return frm_bare, "room", "" if own else frm_res
    if mtype not in ("chat", "normal", ""):
        return None
    if frm_bare == own_bare:
        if not to_bare or to_bare == own_bare or to_bare in rooms:
            return None
        return to_bare, "chat", ""
    if frm_bare in rooms:          # MUC private message: not supported in v1
        return None
    return frm_bare, "chat", frm_bare


def presence_of(shows) -> str:
    """Presence for the C line from the show values of the online resources."""
    shows = list(shows)
    if not shows:
        return "off"
    if any(s in ("", "chat") for s in shows):
        return "on"
    return "away"


def deliver(history, rooms, conv, text, cmid, emit):
    """Resolve conv and hand it to emit(jid, mtype, text, cmid). Raises only
    SendError; anything else emit raises becomes SendError("internal")."""
    try:
        with history.lock:
            row = history.db.execute(
                "SELECT jid, kind FROM conversations WHERE id = ?", (conv,)).fetchone()
        if row is None:
            raise SendError("unknown-conversation")
        jid, kind = row
        if kind == "room":
            if jid not in rooms:
                raise SendError("not-joined")
            mtype = "groupchat"
        else:
            mtype = "chat"
        emit(jid, mtype, text, cmid)
    except SendError:
        raise
    except Exception:
        log.exception("send to conversation %s failed", conv)
        raise SendError("internal")


# ---------------------------------------------------------------- config

@dataclass
class Config:
    jid: str
    password: str = field(repr=False)
    passphrase: str = field(repr=False)
    host: str = "0.0.0.0"
    port: int = 8765
    history: int = 50
    db: str = "relay.db"


def load_config(path: str) -> Config:
    cp = configparser.ConfigParser(interpolation=None)
    if not cp.read(path, encoding="utf-8"):
        raise ValueError("cannot read %s" % path)
    if not cp.has_section("relay"):
        raise ValueError("%s: missing [relay] section" % path)
    sec = cp["relay"]
    vals = {}
    for k in ("jid", "password", "passphrase"):
        v = sec.get(k, "").strip()
        if not v:
            raise ValueError("%s: [relay] %s is required" % (path, k))
        vals[k] = v
    host, _, port = sec.get("listen", "0.0.0.0:8765").strip().rpartition(":")
    try:
        port = int(port)
        keep = int(sec.get("history", "50"))
    except ValueError:
        raise ValueError("%s: bad listen or history value" % path)
    if keep < 1:
        raise ValueError("%s: history must be >= 1" % path)
    db = sec.get("db", "relay.db").strip()
    if not os.path.isabs(db):
        db = os.path.join(os.path.dirname(os.path.abspath(path)), db)
    return Config(vals["jid"], vals["password"], vals["passphrase"],
                  host.strip("[]") or "0.0.0.0", port, keep, db)


# ---------------------------------------------------------------- session helpers

CONTACT_SUBSCRIPTIONS = ("to", "from", "both")
LIVE_HOLD_MAX = 2000


def is_contact(subscription, pending_out=False) -> bool:
    """A real roster contact. slixmpp's client_roster also holds every JID that
    ever sent us presence (room occupants, strangers) with subscription none."""
    return subscription in CONTACT_SUBSCRIPTIONS or bool(pending_out)


def chat_conv(history, rooms, jid, name):
    """Conversation id for a 1:1 chat with jid, or None when jid is a room
    (joined now, or already stored as kind 'room'): a room is never
    downgraded to 'chat'."""
    if jid in rooms:
        return None
    with history.lock:
        row = history.db.execute(
            "SELECT kind FROM conversations WHERE jid = ?", (jid,)).fetchone()
    if row is not None and row[0] == "room":
        return None
    return history.conv_for(jid, "chat", name)


def apply_subscription_policy(client):
    """Never answer subscription requests on the user's account: pending
    requests are left for the user's normal client. In slixmpp these settings
    live on the roster (client.roster), which passes them to every node."""
    client.roster.auto_authorize = None
    client.roster.auto_subscribe = False


class LiveGate:
    """Holds live inbound work while MAM backfill runs, so older backfilled
    messages get lower seqs than live ones arriving meanwhile (pruning is by
    seq). Past LIVE_HOLD_MAX held items new work runs at once rather than
    being dropped."""

    def __init__(self, cap=LIVE_HOLD_MAX):
        self.cap = cap
        self.held = None

    def hold(self):
        if self.held is None:
            self.held = []

    def submit(self, fn):
        if self.held is None or len(self.held) >= self.cap:
            fn()
        else:
            self.held.append(fn)

    def release(self):
        held, self.held = self.held or [], None
        for fn in held:
            try:
                fn()
            except Exception:
                log.exception("held message handling failed")


def apply_backfill(newest_first, ingest_one) -> int:
    """MAM results arrive newest first (reverse query); store oldest first so
    seq follows time. -> number stored."""
    added = 0
    for res in reversed(list(newest_first)):
        try:
            if ingest_one(res):
                added += 1
        except Exception:
            log.exception("MAM result handling failed")
    return added


# ---------------------------------------------------------------- XMPP session

PLUGINS = ("xep_0030", "xep_0045", "xep_0048", "xep_0402", "xep_0280",
           "xep_0313", "xep_0359", "xep_0199")
RECONNECT_MIN = 5
RECONNECT_MAX = 300
MAM_PAGE = 50
MAM_SLACK = 60          # seconds re-queried before newest stored message
NS_BOOKMARKS2 = "urn:xmpp:bookmarks:1"
NS_SID = "{urn:xmpp:sid:0}"
NS_DELAY = "{urn:xmpp:delay}delay"
NS_CARBONS_RECEIVED = "{urn:xmpp:carbons:2}received"

_session_cls = None


def XmppSession(jid, password, history):
    """slixmpp.ClientXMPP subclass, built on first use so the module imports
    without slixmpp. Exposes .online and .send_text(conv, text, cmid); it cannot
    be called .send because slixmpp's own XMLStream.send carries every stanza.
    Wrap it in DevicePort for SyncHandler."""
    return _session_class()(jid, password, history)


class DevicePort:
    """The .online / .send(conv, text, cmid) view SyncHandler expects."""

    def __init__(self, session):
        self.session = session

    @property
    def online(self):
        return self.session.online

    def send(self, conv, text, cmid):
        self.session.send_text(conv, text, cmid)


def _session_class():
    global _session_cls
    if _session_cls is not None:
        return _session_cls
    from datetime import datetime, timezone

    import slixmpp
    from slixmpp import JID
    from slixmpp.stanza import Message

    # slixmpp 1.8.5 builds the <message/> nested in a carbon or a MAM result
    # with recv=False and no stream, and Message.__init__ then deletes its
    # <origin-id/> from the parsed XML (and would invent an id when it has
    # none). That loses exactly the id that recognises our own sends coming
    # back. Parsed XML is never a new outgoing stanza, so treat it as received.
    if not getattr(Message, "_wada_keep_ids", False):
        _orig_init = Message.__init__

        def _init(self, *args, recv=False, **kwargs):
            xml = kwargs.get("xml", args[1] if len(args) > 1 else None)
            _orig_init(self, *args, recv=recv or xml is not None, **kwargs)

        Message.__init__ = _init
        Message._wada_keep_ids = True

    def stamp(el, default=None):
        """Unix time from a <delay/> under el (message or forwarded), else default."""
        d = el.xml.find(NS_DELAY)
        if d is not None and d.get("stamp"):
            try:
                return int(el["delay"]["stamp"].timestamp())
            except Exception:
                pass
        return int(time.time()) if default is None else default

    class _XmppSession(slixmpp.ClientXMPP):
        def __init__(self, jid, password, history):
            super().__init__(jid, password)
            self.history = history
            self.online = False
            self.rooms = {}          # joined room bare JID -> our nick
            self.room_names = {}     # room bare JID -> display name
            self._backoff = RECONNECT_MIN
            self._reconnect_pending = False
            self.stopping = False
            self.use_origin_id = True    # outgoing <origin-id/> = message id = cmid
            apply_subscription_policy(self)
            self.gate = LiveGate()
            for p in PLUGINS:
                cfg = {"keepalive": True, "interval": 60} if p == "xep_0199" else None
                self.register_plugin(p, pconfig=cfg)
            on = self.add_event_handler
            on("session_start", self._on_session_start)
            on("disconnected", self._on_disconnected)
            on("failed_auth", lambda _: log.error("authentication failed for %s",
                                                  self.boundjid.bare))
            on("connection_failed", lambda e: log.warning("connection failed: %s", e))
            on("message", self._on_message)
            on("groupchat_message", self._on_groupchat)
            on("carbon_received", self._on_carbon)
            on("carbon_sent", self._on_carbon)
            on("changed_status", self._on_presence)
            on("groupchat_presence", self._on_room_presence)
            on("roster_update", self._on_roster_update)

        # ------------------------------------------------ device side

        def send_text(self, conv, text, cmid):
            def emit(jid, mtype, body, mid):
                m = self.make_message(mto=jid, mbody=body, mtype=mtype)
                m["id"] = mid       # with use_origin_id also sets XEP-0359 origin-id
                m.send()
            deliver(self.history, self.rooms if self.online else {}, conv, text,
                    cmid, emit)

        # ------------------------------------------------ connection

        def start(self):
            log.info("connecting as %s", self.boundjid.bare)
            self.connect()

        def stop(self):
            self.stopping = True
            self.disconnect(wait=2.0)

        def _on_disconnected(self, reason):
            self.online = False
            self.rooms.clear()
            try:
                with self.history.lock:
                    ids = [r[0] for r in self.history.db.execute(
                        "SELECT id FROM conversations")]
                for cid in ids:
                    self.history.set_presence(cid, "off")
            except Exception:
                log.exception("marking conversations offline failed")
            if self.stopping or self._reconnect_pending:
                return
            delay = self._backoff
            self._backoff = min(self._backoff * 2, RECONNECT_MAX)
            log.info("disconnected (%s); reconnecting in %d s", reason, delay)
            self._reconnect_pending = True
            self.loop.call_later(delay, self._do_reconnect)

        def _do_reconnect(self):
            self._reconnect_pending = False
            if self.stopping or self.is_connected():
                return
            # slixmpp may already be reconnecting by itself (e.g. the XEP-0199
            # keepalive calls reconnect() on a ping timeout); never start a
            # second connection beside it.
            attempt = getattr(self, "_current_connection_attempt", None)
            if attempt is not None and not attempt.done():
                return
            self.connect()

        async def _on_session_start(self, _):
            log.info("session started as %s", self.boundjid)
            self._backoff = RECONNECT_MIN
            # Live messages wait until backfill is stored (seq follows time),
            # and the device sees xmpp-offline until then, so its sends are
            # not interleaved with backfill either.
            self.gate.hold()
            try:
                self.send_presence()
                try:
                    await self.get_roster(timeout=30)
                except Exception as e:
                    log.warning("roster fetch failed: %r", e)
                log.info("roster has %d contacts", self._sync_roster())
                try:
                    await self["xep_0280"].enable(timeout=15)
                except Exception as e:
                    log.warning("carbons not enabled: %r", e)
                await self._join_rooms()
                await self._backfill()
            finally:
                self.gate.release()
            if self.is_connected():
                self.online = True
                log.info("ready")

        # ------------------------------------------------ roster and presence

        def _contact_name(self, jid):
            if self.client_roster.has_jid(jid):
                return self.client_roster[jid]["name"] or jid
            return jid

        def _contact_conv(self, jid):
            conv = chat_conv(self.history, self.rooms, jid, self._contact_name(jid))
            if conv is not None:
                self._update_presence(jid, conv)
            return conv

        def _sync_roster(self):
            own = self.boundjid.bare
            n = 0
            for jid in list(self.client_roster):
                if jid == own or not self.client_roster.has_jid(jid):
                    continue
                item = self.client_roster[jid]
                if is_contact(item["subscription"], item["pending_out"]) \
                        and self._contact_conv(jid) is not None:
                    n += 1
            return n

        def _update_presence(self, jid, conv):
            res = self.client_roster[jid].resources if self.client_roster.has_jid(jid) else {}
            self.history.set_presence(conv, presence_of(
                (v.get("show") or "") for v in res.values()))

        def _known_conv(self, jid):
            with self.history.lock:
                row = self.history.db.execute(
                    "SELECT id FROM conversations WHERE jid = ? AND kind = 'chat'",
                    (jid,)).fetchone()
            return row[0] if row else None

        def _on_presence(self, pres):
            try:
                jid = pres["from"].bare
                if jid in self.rooms or jid == self.boundjid.bare:
                    return
                conv = self._known_conv(jid)
                if conv is not None:
                    self._update_presence(jid, conv)
            except Exception:
                log.exception("presence handling failed")

        def _on_roster_update(self, _):
            try:
                self._sync_roster()
            except Exception:
                log.exception("roster update failed")

        # ------------------------------------------------ rooms

        async def _bookmarks(self):
            """{room_jid: (name, password)} for autojoin bookmarks: XEP-0402
            first, then legacy XEP-0048 in PEP (XEP-0223), then private XML."""
            own = self.boundjid.bare
            out = {}
            try:
                iq = await self["xep_0060"].get_items(own, NS_BOOKMARKS2, timeout=20)
                items = list(iq["pubsub"]["items"])
                for item in items:
                    conf = item["conference"]
                    if conf["autojoin"]:
                        out[str(item["id"])] = (conf["name"] or "", conf["password"] or None)
                if items:
                    log.info("bookmarks: %d via XEP-0402", len(items))
                    return out
            except Exception as e:
                log.info("no XEP-0402 bookmarks: %r", e)
            for method in ("xep_0223", "xep_0049"):
                try:
                    res = await self["xep_0048"].get_bookmarks(method=method, timeout=20)
                    if method == "xep_0223":
                        bm = res["pubsub"]["items"]["item"]["bookmarks"]
                    else:
                        bm = res["private"]["bookmarks"]
                    confs = list(bm["conferences"])
                    for conf in confs:
                        if conf["autojoin"]:
                            out[str(JID(conf["jid"]).bare)] = (
                                conf["name"] or "", conf["password"] or None)
                    if confs:
                        log.info("bookmarks: %d via XEP-0048/%s", len(confs), method)
                        return out
                except Exception as e:
                    log.info("no XEP-0048 bookmarks via %s: %r", method, e)
            return out

        async def _join_rooms(self):
            nick = self.boundjid.user or "wada"
            joined = 0
            for room, (name, password) in (await self._bookmarks()).items():
                if not self.is_connected():
                    break
                try:
                    pres, _, _, _ = await self["xep_0045"].join_muc_wait(
                        JID(room), nick, password=password, maxstanzas=0, timeout=30)
                    self.room_names[room] = name or JID(room).user or room
                    self.rooms[room] = pres["from"].resource or nick
                    conv = self.history.conv_for(room, "room", self.room_names[room])
                    self.history.set_presence(conv, "on")
                    joined += 1
                except Exception as e:
                    log.warning("could not join %s: %r", room, e)
            log.info("joined %d rooms", joined)

        def _on_room_presence(self, pres):
            try:
                room = pres["from"].bare
                if room not in self.rooms or pres["type"] != "unavailable":
                    return
                codes = pres["muc"]["status_codes"]
                if pres["from"].resource != self.rooms[room] and 110 not in codes:
                    return
                if 303 in codes:                       # nick change
                    new = pres["muc"]["nick"]
                    if new:
                        self.rooms[room] = new
                    return
                del self.rooms[room]
                log.info("left %s (codes %s)", room, sorted(codes))
                with self.history.lock:
                    row = self.history.db.execute(
                        "SELECT id FROM conversations WHERE jid = ?", (room,)).fetchone()
                if row:
                    self.history.set_presence(row[0], "off")
            except Exception:
                log.exception("room presence handling failed")

        # ------------------------------------------------ messages

        def _ids(self, msg, by, archive_id=None):
            ids = [archive_id]
            for el in msg.xml.findall(NS_SID + "stanza-id"):
                if el.get("by") == by:
                    ids.append(el.get("id"))
            for el in msg.xml.findall(NS_SID + "origin-id"):
                ids.append(el.get("id"))
            return ids

        def _ingest(self, msg, ts, archive_id=None):
            body = msg["body"]
            if not body:
                return False
            mtype = msg["type"]
            frm, to = msg["from"], msg["to"]
            own = self.boundjid.bare
            self_occ = False
            if mtype == "groupchat" and frm.bare in self.rooms \
                    and frm.resource != self.rooms[frm.bare]:
                try:
                    real = self["xep_0045"].get_jid_property(frm.bare, frm.resource, "jid")
                    self_occ = bool(real) and JID(real).bare == own
                except Exception:
                    pass
            rt = route(own, self.rooms, mtype, frm.bare, frm.resource, to.bare, self_occ)
            if rt is None:
                return False
            peer, kind, sender = rt
            if kind == "room":
                conv = self.history.conv_for(peer, "room", self.room_names.get(peer, peer))
                by = peer
            else:
                conv = chat_conv(self.history, self.rooms, peer, self._contact_name(peer))
                if conv is None:
                    return False
                by = own
            return ingest(self.history, conv, self._ids(msg, by, archive_id), ts,
                          sender, body) is not None

        def _ingest_live(self, msg, ts):
            def run():
                try:
                    self._ingest(msg, ts)
                except Exception:
                    log.exception("message handling failed")
            self.gate.submit(run)

        def _on_message(self, msg):
            if msg["type"] in ("groupchat", "error"):
                return
            self._ingest_live(msg, stamp(msg))

        def _on_groupchat(self, msg):
            self._ingest_live(msg, stamp(msg))

        def _on_carbon(self, msg):
            try:
                # msg["carbon_*"] is the forwarded inner <message/> itself
                if msg.xml.find(NS_CARBONS_RECEIVED) is not None:
                    inner = msg["carbon_received"]
                else:
                    inner = msg["carbon_sent"]
                if isinstance(inner, Message):
                    self._ingest_live(inner, stamp(inner))
            except Exception:
                log.exception("carbon handling failed")

        # ------------------------------------------------ MAM backfill

        async def _backfill(self):
            with self.history.lock:
                row = self.history.db.execute(
                    "SELECT MAX(m.ts) FROM messages m JOIN conversations c "
                    "ON c.id = m.conv WHERE c.kind = 'chat'").fetchone()
            n = await self._mam(None, row[0], self.history.keep * 4)
            log.info("backfilled %d messages for the account", n)
            for room in list(self.rooms):
                conv = self.history.conv_for(room, "room", self.room_names.get(room, room))
                n = await self._mam(room, self.history.newest_ts(conv), self.history.keep)
                log.info("backfilled %d messages for %s", n, room)

        async def _mam(self, room, since, cap):
            # Newest first, bounded below by what we already have, so after a
            # long outage it is the newest `cap` messages that are fetched.
            kw = {"rsm": {"max": MAM_PAGE}, "reverse": True, "total": cap}
            if room:
                kw["jid"] = JID(room)
            if since is not None:
                kw["start"] = datetime.fromtimestamp(max(0, since - MAM_SLACK), timezone.utc)
            got = []
            try:
                async for res in self["xep_0313"].iterate(**kw):
                    got.append(res)
            except Exception as e:
                log.warning("MAM query for %s failed: %r", room or "account", e)
            return apply_backfill(got, self._ingest_mam)

        def _ingest_mam(self, res):
            r = res["mam_result"]
            fwd = r["forwarded"]
            inner = fwd["stanza"]
            if not isinstance(inner, Message):
                return False
            return self._ingest(inner, stamp(fwd), archive_id=r["id"])

    _session_cls = _XmppSession
    return _session_cls


# ---------------------------------------------------------------- main

def run(cfg: Config) -> int:
    history = History(cfg.db, keep=cfg.history)
    keys = derive_keys(cfg.passphrase)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    xmpp = XmppSession(cfg.jid, cfg.password, history)
    handler = SyncHandler(history, DevicePort(xmpp))
    server = loop.run_until_complete(serve_http(
        cfg.host, cfg.port, lambda body: handle_body(body, keys, handler, history)))
    log.info("listening on %s:%d (db %s, history %d)", cfg.host, cfg.port, cfg.db,
             cfg.history)

    def shutdown():
        log.info("shutting down")
        server.close()
        xmpp.stop()
        loop.call_later(3, loop.stop)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown)
        except (NotImplementedError, RuntimeError):
            pass
    xmpp.start()
    try:
        loop.run_forever()
    finally:
        pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
        for t in pending:
            t.cancel()
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()
    return 0


def main(argv):
    if "--gen-vectors" in argv:
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")
        gen_vectors(sys.stdout)
        return 0
    if "--gen-reply-fixture" in argv:
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")
        gen_reply_fixture(sys.stdout)
        return 0
    if len(argv) != 1 or argv[0].startswith("-"):
        sys.stderr.write("usage: xmpp_relay.py relay.ini | --gen-vectors | --gen-reply-fixture\n")
        return 2
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        cfg = load_config(argv[0])
    except ValueError as e:
        log.error("%s", e)
        return 2
    return run(cfg)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
