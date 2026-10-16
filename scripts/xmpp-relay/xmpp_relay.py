#!/usr/bin/env python3
"""wadamesh XMPP relay.

Sections: seal (crypto), codec, history, sync handler. Networking is added later.
slixmpp must only be imported lazily, never at module top level.
"""
import hashlib
import hmac
import os
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


def main(argv):
    if "--gen-vectors" in argv:
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")
        gen_vectors(sys.stdout)
        return 0
    sys.stderr.write("usage: xmpp_relay.py --gen-vectors\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
