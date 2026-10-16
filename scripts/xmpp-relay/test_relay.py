import hashlib
import os
import unittest

import xmpp_relay as r

HERE = os.path.dirname(os.path.abspath(__file__))


class SealTests(unittest.TestCase):
    def setUp(self):
        self.enc, self.mac = r.derive_keys("hunter2")

    def test_derive_keys_matches_pbkdf2(self):
        k = hashlib.pbkdf2_hmac("sha256", b"hunter2", b"wada-xmpp-v1", 2000, 64)
        self.assertEqual(r.derive_keys("hunter2"), (k[:32], k[32:]))

    def test_round_trip(self):
        for n in (0, 1, 32, 33, 6000):
            pt = bytes(i % 251 for i in range(n))
            s = r.seal(self.enc, self.mac, b"Q", pt)
            self.assertEqual(len(s), 16 + n + 16)
            self.assertEqual(r.open_sealed(self.enc, self.mac, b"Q", s), pt)

    def test_tamper(self):
        s = r.seal(self.enc, self.mac, b"Q", b"hello world")
        for i in range(len(s)):
            t = bytearray(s)
            t[i] ^= 1
            self.assertIsNone(r.open_sealed(self.enc, self.mac, b"Q", bytes(t)), i)
        self.assertIsNone(r.open_sealed(self.enc, self.mac, b"Q", b"short"))

    def test_direction_bound(self):
        s = r.seal(self.enc, self.mac, b"Q", b"hello")
        self.assertIsNone(r.open_sealed(self.enc, self.mac, b"P", s))

    def test_vectors_file(self):
        keys = {}
        nv = 0
        with open(os.path.join(HERE, "seal_vectors.txt"), encoding="utf-8") as f:
            for line in f:
                p = line.rstrip("\n").split("\t")
                if p[0] == "K":
                    keys[p[1]] = (p[2], p[3])
                    e, m = r.derive_keys(p[1])
                    self.assertEqual((e.hex(), m.hex()), (p[2], p[3]))
                elif p[0] == "V":
                    e, m = r.derive_keys(p[1])
                    got = r.seal(e, m, p[2].encode(), bytes.fromhex(p[4]),
                                 nonce=bytes.fromhex(p[3]))
                    self.assertEqual(got.hex(), p[5])
                    nv += 1
        self.assertGreaterEqual(nv, 8)


import tempfile
from collections import Counter


def _tmpdb():
    d = tempfile.mkdtemp()
    return os.path.join(d, "h.db")


def _lines(reply):
    return [l.split("\t") for l in reply.split("\n") if l != ""]


class FakeXmpp:
    def __init__(self):
        self.online = True
        self.sent = []
        self.fail = None

    def send(self, conv, text, cmid):
        if self.fail:
            raise r.SendError(self.fail)
        self.sent.append((conv, text, cmid))


class CodecTests(unittest.TestCase):
    def test_esc_round_trip(self):
        s = "a\tb\nc\\d\U0001f600"
        e = r.esc(s)
        self.assertNotIn("\t", e)
        self.assertNotIn("\n", e)
        self.assertEqual(r.unesc(e), s)
        self.assertEqual(r.esc("x\r\ny"), "x\\ny")

    def test_cut_utf8(self):
        out = r.cut_utf8("\u00e9" * 600, 1000)
        self.assertLessEqual(len(out.encode("utf-8")), 1000)
        out.encode("utf-8").decode("utf-8")
        self.assertEqual(r.cut_utf8("abc", 1000), "abc")

    def test_parse_request(self):
        got = r.parse_request("S\tab12\t7\t0\nM\t3\tc1\thi\\tthere\nR\t3\t42\n")
        self.assertEqual(got, r.Request("ab12", 7, 0, [(3, "c1", "hi\tthere")], [(3, 42)]))
        with self.assertRaises(ValueError):
            r.parse_request("M\t3\tc1\thi\n")
        with self.assertRaises(ValueError):
            r.parse_request("S\tab\tx\t0\n")

    def test_parse_empty_text_and_unknown(self):
        got = r.parse_request("S\ta\t1\t0\nZ\tfoo\nM\t1\tc\t\n")
        self.assertEqual(got.sends, [(1, "c", "")])


class HistoryTests(unittest.TestCase):
    def test_dup_stanza(self):
        h = r.History(_tmpdb())
        c = h.conv_for("a@x", "chat", "A")
        self.assertIsNotNone(h.add_message(c, "s1", 100, "a@x", "hi"))
        self.assertIsNone(h.add_message(c, "s1", 100, "a@x", "hi"))
        n = h.db.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        self.assertEqual(n, 1)

    def test_conv_for_stable(self):
        h = r.History(_tmpdb())
        self.assertEqual(h.conv_for("a@x", "chat", "A"), h.conv_for("a@x", "chat", "A"))
        self.assertNotEqual(h.conv_for("a@x", "chat", "A"), h.conv_for("b@x", "chat", "B"))

    def test_trim_keeps_50(self):
        h = r.History(_tmpdb())
        c = h.conv_for("a@x", "chat", "A")
        for i in range(60):
            h.add_message(c, "s%d" % i, i, "a@x", "m%d" % i)
        rows = [x[0] for x in h.db.execute("SELECT text FROM messages ORDER BY seq")]
        self.assertEqual(len(rows), 50)
        self.assertEqual(rows[0], "m10")

    def test_accept_q(self):
        path = _tmpdb()
        h = r.History(path)
        self.assertTrue(h.accept_q("s1", 5))
        self.assertFalse(h.accept_q("s1", 5))
        self.assertFalse(h.accept_q("s1", 4))
        self.assertTrue(h.accept_q("s2", 1))
        h.db.close()
        h2 = r.History(path)
        self.assertFalse(h2.accept_q("s1", 5))
        self.assertTrue(h2.accept_q("s1", 6))

    def test_rev_and_presence(self):
        h = r.History(_tmpdb())
        c = h.conv_for("a@x", "chat", "A")
        r0 = h.rev()
        h.set_presence(c, "on")
        r1 = h.rev()
        self.assertGreater(r1, r0)
        h.set_presence(c, "on")
        self.assertEqual(h.rev(), r1)
        self.assertIsNone(h.newest_ts(c))
        h.add_message(c, None, 77, "a@x", "x")
        self.assertEqual(h.newest_ts(c), 77)


def _handler(convs=3, msgs=30, size=None):
    h = r.History(_tmpdb())
    x = FakeXmpp()
    ids = []
    for i in range(convs):
        c = h.conv_for("c%d@x" % i, "chat", "C%d" % i)
        ids.append(c)
        for j in range(msgs):
            t = ("m%d" % j) if size is None else ("%03d" % j + "x" * (size - 3))
            h.add_message(c, "s%d_%d" % (i, j), 1000 + j, "c%d@x" % i, t)
    return h, x, r.SyncHandler(h, x), ids


class SyncTests(unittest.TestCase):
    def test_initial_sync_window(self):
        h, x, sh, ids = _handler()
        reply = sh.handle("S\ts\t9\t0\n")
        ls = _lines(reply)
        self.assertEqual(ls[0], ["P", "9"])
        self.assertEqual(sum(1 for l in ls if l[0] == "C"), 3)
        per = Counter(l[1] for l in ls if l[0] == "G")
        self.assertTrue(all(v <= 10 for v in per.values()))
        self.assertEqual(sum(per.values()), 30)
        self.assertLessEqual(len(reply.encode()), 6000)
        self.assertEqual(ls[-1], ["N", str(h.rev()), "0"])
        seqs = [int(l[2]) for l in ls if l[0] == "G"]
        self.assertEqual(seqs, sorted(seqs))

    def test_initial_round_robin_budget(self):
        h, x, sh, ids = _handler(convs=40, msgs=10, size=200)
        reply = sh.handle("S\ts\t1\t0\n")
        self.assertLessEqual(len(reply.encode()), 6000)
        ls = _lines(reply)
        per = Counter(int(l[1]) for l in ls if l[0] == "G")
        self.assertGreater(len(per), 0)
        self.assertEqual(max(per.values()), 1)
        for l in ls:
            if l[0] == "G":
                self.assertTrue(l[5].startswith("009"))  # newest message
        self.assertEqual(ls[-1][2], "0")

    def test_initial_budget_favours_recent_conversation(self):
        h, x, sh, ids = _handler(convs=40, msgs=10, size=200)
        h.add_message(ids[-1], "fresh", 9999, "c39@x", "FRESH")
        ls = _lines(sh.handle("S\ts\t1\t0\n"))
        gs = [l for l in ls if l[0] == "G"]
        self.assertLess(len(gs), 40)
        self.assertIn((str(ids[-1]), "FRESH"), [(l[1], l[5]) for l in gs])
        seqs = [int(l[2]) for l in gs]
        self.assertEqual(seqs, sorted(seqs))

    def test_incremental_paging(self):
        h, x, sh, ids = _handler(convs=1, msgs=1)
        cursor = h.rev()
        for i in range(30):
            h.add_message(ids[0], "n%d" % i, 2000 + i, "c0@x", "%03d" % i + "y" * 297)
        first = sh.handle("S\ts\t1\t%d\n" % cursor)
        self.assertLessEqual(len(first.encode()), 6000)
        l1 = _lines(first)
        self.assertEqual(l1[-1][2], "1")
        g1 = [int(l[2]) for l in l1 if l[0] == "G"]
        self.assertEqual(int(l1[-1][1]), g1[-1])
        second = sh.handle("S\ts\t2\t%s\n" % l1[-1][1])
        l2 = _lines(second)
        self.assertEqual(l2[-1][2], "0")
        g2 = [int(l[2]) for l in l2 if l[0] == "G"]
        allg = g1 + g2
        self.assertEqual(len(allg), 30)
        self.assertEqual(allg, list(range(allg[0], allg[0] + 30)))
        self.assertEqual(int(l2[-1][1]), h.rev())

    def test_send_ack_and_idempotent(self):
        h, x, sh, ids = _handler(convs=1, msgs=0)
        req = "S\ts\t1\t0\nM\t%d\tc1\thello\n" % ids[0]
        for _ in range(2):
            ls = _lines(sh.handle(req))
            self.assertIn(["A", "c1", "ok"], ls)
        self.assertEqual(len(x.sent), 1)
        self.assertEqual(x.sent[0], (ids[0], "hello", "c1"))
        row = h.db.execute("SELECT sender, stanza_id FROM messages").fetchall()
        self.assertEqual(row, [("", "c1")])
        # reflection with origin-id == cmid is deduplicated
        self.assertIsNone(h.add_message(ids[0], "c1", 5, "", "hello"))

    def test_send_error(self):
        h, x, sh, ids = _handler(convs=1, msgs=0)
        x.fail = "forbidden"
        ls = _lines(sh.handle("S\ts\t1\t0\nM\t%d\tc1\thi\n" % ids[0]))
        self.assertIn(["A", "c1", "err", "forbidden"], ls)
        self.assertEqual(h.db.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 0)

    def test_offline(self):
        h, x, sh, ids = _handler(convs=1, msgs=0)
        x.online = False
        ls = _lines(sh.handle("S\ts\t1\t0\nM\t%d\tc1\thi\n" % ids[0]))
        self.assertIn(["E", "xmpp-offline"], ls)
        self.assertIn(["A", "c1", "err", "offline"], ls)
        self.assertEqual(x.sent, [])
        x.online = True
        ls = _lines(sh.handle("S\ts\t2\t0\nM\t%d\tc1\thi\n" % ids[0]))
        self.assertIn(["A", "c1", "ok"], ls)

    def test_empty_sender_not_collapsed(self):
        h, x, sh, ids = _handler(convs=1, msgs=0)
        sh.handle("S\ts\t1\t0\nM\t%d\tc1\ta\\tb\n" % ids[0])
        ls = _lines(sh.handle("S\ts\t2\t0\n"))
        g = [l for l in ls if l[0] == "G"][0]
        self.assertEqual(len(g), 6)
        self.assertEqual(g[4], "")
        self.assertEqual(r.unesc(g[5]), "a\tb")

    def test_read_mark(self):
        h, x, sh, ids = _handler(convs=1, msgs=3)
        cur = h.rev()
        c1 = [l for l in _lines(sh.handle("S\ts\t1\t0\n")) if l[0] == "C"][0]
        self.assertEqual(c1[6], "3")
        last = h.db.execute("SELECT MAX(seq) FROM messages").fetchone()[0]
        ls = _lines(sh.handle("S\ts\t2\t%d\nR\t%d\t%d\n" % (cur, ids[0], last)))
        c2 = [l for l in ls if l[0] == "C"][0]
        self.assertEqual(c2[6], "0")



import asyncio
import importlib.util


def _seal_req(keys, text):
    return r.seal(keys[0], keys[1], b"Q", text.encode("utf-8"))


def _open_rep(keys, body):
    pt = r.open_sealed(keys[0], keys[1], b"P", body)
    return None if pt is None else pt.decode("utf-8")


class BoomHandler:
    def handle(self, text):
        raise RuntimeError("boom")


class HandleBodyTests(unittest.TestCase):
    def setUp(self):
        self.keys = r.derive_keys("hunter2")
        self.h, self.x, self.sh, self.ids = _handler(convs=1, msgs=2)

    def test_handle_body_denied(self):
        self.assertEqual(r.handle_body(b"garbage", self.keys, self.sh, self.h), b"DENIED")
        self.assertEqual(r.handle_body(b"", self.keys, self.sh, self.h), b"DENIED")
        other = r.derive_keys("wrong")
        self.assertEqual(r.handle_body(_seal_req(other, "S\ts\t1\t0\n"),
                                       self.keys, self.sh, self.h), b"DENIED")
        # sealed but not a request
        self.assertEqual(r.handle_body(_seal_req(self.keys, "hello"),
                                       self.keys, self.sh, self.h), b"DENIED")
        body = _seal_req(self.keys, "S\ts\t5\t0\n")
        self.assertNotEqual(r.handle_body(body, self.keys, self.sh, self.h), b"DENIED")
        # replayed q (same and lower) is denied
        self.assertEqual(r.handle_body(body, self.keys, self.sh, self.h), b"DENIED")
        self.assertEqual(r.handle_body(_seal_req(self.keys, "S\ts\t4\t0\n"),
                                       self.keys, self.sh, self.h), b"DENIED")

    def test_handle_body_ok(self):
        out = r.handle_body(_seal_req(self.keys, "S\ts\t7\t0\n"), self.keys, self.sh, self.h)
        text = _open_rep(self.keys, out)
        self.assertIsNotNone(text)
        self.assertTrue(text.startswith("P\t7\n"))
        ls = _lines(text)
        self.assertEqual(ls[-1][0], "N")
        self.assertEqual(sum(1 for l in ls if l[0] == "G"), 2)
        # a reply never opens as a request (direction bound)
        self.assertIsNone(r.open_sealed(self.keys[0], self.keys[1], b"Q", out))

    def test_handle_body_internal_error_still_replies(self):
        with self.assertLogs("xmpp-relay", "ERROR"):
            out = r.handle_body(_seal_req(self.keys, "S\ts\t3\t42\n"),
                                self.keys, BoomHandler(), self.h)
        text = _open_rep(self.keys, out)
        self.assertEqual(_lines(text), [["P", "3"], ["N", "42", "0"]])


async def _raw(port, data):
    rd, wr = await asyncio.open_connection("127.0.0.1", port)
    wr.write(data)
    await wr.drain()
    resp = await rd.read()
    wr.close()
    head, _, body = resp.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1])
    hdrs = {}
    for l in lines[1:]:
        k, _, v = l.partition(b":")
        hdrs[k.strip().lower().decode()] = v.strip().decode()
    return status, hdrs, body


class HttpTests(unittest.TestCase):
    def test_http_roundtrip(self):
        calls = []

        def on_body(b):
            calls.append(b)
            return b"R:" + b

        async def go():
            srv = await r.serve_http("127.0.0.1", 0, on_body)
            port = srv.sockets[0].getsockname()[1]
            payload = bytes(range(256)) + b"\r\n\r\n\x00"
            res = {}
            res["ok"] = await _raw(port, b"POST /w HTTP/1.1\r\nHost: x\r\n"
                                   b"Content-Type: application/octet-stream\r\n"
                                   b"Content-Length: %d\r\n\r\n" % len(payload) + payload)
            res["get"] = await _raw(port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            res["path"] = await _raw(port, b"POST /x HTTP/1.1\r\nContent-Length: 1\r\n\r\nz")
            res["big"] = await _raw(port, b"POST /w HTTP/1.1\r\nContent-Length: 99999\r\n\r\n")
            res["nolen"] = await _raw(port, b"POST /w HTTP/1.1\r\nHost: x\r\n\r\n")
            res["junk"] = await _raw(port, b"\x00\x01garbage\r\n\r\n")
            srv.close()
            await srv.wait_closed()
            return payload, res

        payload, res = asyncio.run(go())
        st, hd, body = res["ok"]
        self.assertEqual(st, 200)
        self.assertEqual(body, b"R:" + payload)
        self.assertEqual(hd["content-type"], "application/octet-stream")
        self.assertEqual(hd["connection"], "close")
        self.assertEqual(int(hd["content-length"]), len(body))
        self.assertEqual(res["get"][0], 404)
        self.assertEqual(res["path"][0], 404)
        self.assertEqual(res["big"][0], 413)
        self.assertGreaterEqual(res["nolen"][0], 400)
        self.assertGreaterEqual(res["junk"][0], 400)
        self.assertEqual(calls, [payload])

    def test_http_on_body_error_does_not_kill_server(self):
        def on_body(b):
            if b == b"x":
                raise RuntimeError("boom")
            return b"ok"

        async def go():
            srv = await r.serve_http("127.0.0.1", 0, on_body)
            port = srv.sockets[0].getsockname()[1]
            a = await _raw(port, b"POST /w HTTP/1.1\r\nContent-Length: 1\r\n\r\nx")
            b = await _raw(port, b"POST /w HTTP/1.1\r\nContent-Length: 1\r\n\r\ny")
            srv.close()
            await srv.wait_closed()
            return a, b

        with self.assertLogs("xmpp-relay", "ERROR"):
            a, b = asyncio.run(go())
        self.assertEqual(a[0], 500)
        self.assertEqual((b[0], b[2]), (200, b"ok"))


class InboundTests(unittest.TestCase):
    def setUp(self):
        self.h = r.History(_tmpdb())

    def test_room_reflection_dedup(self):
        room = self.h.conv_for("room@conf.x", "room", "Room")
        x = FakeXmpp()
        sh = r.SyncHandler(self.h, x)
        sh.handle("S\ts\t1\t0\nM\t%d\tcmid42\thi all\n" % room)
        n = self.h.db.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        self.assertEqual(n, 1)
        # the room reflects our message: origin-id = cmid, plus the room's stanza-id
        self.assertIsNone(r.ingest(self.h, room, ["cmid42", "room-sid-1"], 5, "", "hi all"))
        # MAM backfill later carries the archive id first, origin-id inside
        self.assertIsNone(r.ingest(self.h, room, ["room-sid-1", "cmid42"], 5, "", "hi all"))
        self.assertEqual(self.h.db.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 1)

    def test_ingest_dedups_on_any_id(self):
        c = self.h.conv_for("a@x", "chat", "A")
        self.assertIsNotNone(r.ingest(self.h, c, [None, "sid1", "orig1"], 1, "a@x", "m"))
        self.assertIsNone(r.ingest(self.h, c, ["orig1"], 1, "a@x", "m"))
        self.assertIsNone(r.ingest(self.h, c, ["", "sid1"], 1, "a@x", "m"))
        # no id at all: stored every time (cannot be deduplicated)
        self.assertIsNotNone(r.ingest(self.h, c, [], 2, "a@x", "n"))
        self.assertIsNotNone(r.ingest(self.h, c, [None], 2, "a@x", "n"))

    def test_route(self):
        me = "me@x"
        rooms = {"room@c.x": "me"}
        self.assertEqual(r.route(me, rooms, "chat", "bob@x", "phone", "me@x"),
                         ("bob@x", "chat", "bob@x"))
        self.assertEqual(r.route(me, rooms, "normal", "bob@x", "", "me@x"),
                         ("bob@x", "chat", "bob@x"))
        # own message from another client (carbon sent / MAM outgoing)
        self.assertEqual(r.route(me, rooms, "chat", "me@x", "gajim", "bob@x"),
                         ("bob@x", "chat", ""))
        self.assertIsNone(r.route(me, rooms, "chat", "me@x", "gajim", "me@x"))
        self.assertEqual(r.route(me, rooms, "groupchat", "room@c.x", "alice", "me@x"),
                         ("room@c.x", "room", "alice"))
        self.assertEqual(r.route(me, rooms, "groupchat", "room@c.x", "me", "me@x"),
                         ("room@c.x", "room", ""))
        self.assertIsNone(r.route(me, rooms, "groupchat", "room@c.x", "", "me@x"))
        self.assertIsNone(r.route(me, rooms, "groupchat", "other@c.x", "z", "me@x"))
        self.assertIsNone(r.route(me, rooms, "chat", "room@c.x", "alice", "me@x"))
        self.assertIsNone(r.route(me, rooms, "error", "bob@x", "", "me@x"))
        self.assertIsNone(r.route(me, rooms, "headline", "bob@x", "", "me@x"))

    def test_presence_of(self):
        self.assertEqual(r.presence_of([]), "off")
        self.assertEqual(r.presence_of(["away"]), "away")
        self.assertEqual(r.presence_of(["xa", "dnd"]), "away")
        self.assertEqual(r.presence_of(["away", ""]), "on")
        self.assertEqual(r.presence_of(["chat"]), "on")

    def test_deliver(self):
        h = self.h
        c = h.conv_for("bob@x", "chat", "Bob")
        room = h.conv_for("room@c.x", "room", "Room")
        out = []
        emit = lambda jid, mtype, text, cmid: out.append((jid, mtype, text, cmid))
        r.deliver(h, {"room@c.x": "me"}, c, "hi", "m1", emit)
        r.deliver(h, {"room@c.x": "me"}, room, "yo", "m2", emit)
        self.assertEqual(out, [("bob@x", "chat", "hi", "m1"),
                               ("room@c.x", "groupchat", "yo", "m2")])
        with self.assertRaises(r.SendError) as e:
            r.deliver(h, {}, room, "yo", "m3", emit)
        self.assertEqual(e.exception.reason, "not-joined")
        with self.assertRaises(r.SendError) as e:
            r.deliver(h, {}, 999, "yo", "m4", emit)
        self.assertEqual(e.exception.reason, "unknown-conversation")

        def bad(*a):
            raise OSError("socket gone")
        with self.assertRaises(r.SendError) as e, self.assertLogs("xmpp-relay", "ERROR"):
            r.deliver(h, {}, c, "hi", "m5", bad)
        self.assertEqual(e.exception.reason, "internal")


class DevicePortTests(unittest.TestCase):
    def test_port_maps_send_to_send_text(self):
        class S:
            online = True
            def __init__(self):
                self.got = []
            def send_text(self, *a):
                self.got.append(a)
        s = S()
        p = r.DevicePort(s)
        self.assertTrue(p.online)
        p.send(3, "hi", "c1")
        self.assertEqual(s.got, [(3, "hi", "c1")])
        s.online = False
        self.assertFalse(p.online)


class FakeRosterItem(dict):
    pass


class SessionHelperTests(unittest.TestCase):
    def setUp(self):
        self.h = r.History(_tmpdb())

    def test_roster_rooms_and_strangers_not_contacts(self):
        # what slixmpp's client_roster holds after presence from a room and a stranger
        roster = {
            "friend@x": FakeRosterItem(subscription="both", pending_out=False),
            "asked@x": FakeRosterItem(subscription="none", pending_out=True),
            "room@c.x": FakeRosterItem(subscription="none", pending_out=False),
            "stranger@x": FakeRosterItem(subscription="none", pending_out=False),
        }
        room = self.h.conv_for("room@c.x", "room", "Room")
        rev = self.h.rev()
        made = {}
        for jid, item in roster.items():
            if r.is_contact(item["subscription"], item["pending_out"]):
                made[jid] = r.chat_conv(self.h, {}, jid, jid)
        self.assertEqual(sorted(made), ["asked@x", "friend@x"])
        kinds = dict(self.h.db.execute("SELECT jid, kind FROM conversations"))
        self.assertEqual(kinds, {"room@c.x": "room", "friend@x": "chat", "asked@x": "chat"})
        # even if something asks for the room as a chat, it is never downgraded
        self.assertIsNone(r.chat_conv(self.h, {}, "room@c.x", "room@c.x"))
        self.assertIsNone(r.chat_conv(self.h, {"other@c.x": "me"}, "other@c.x", "x"))
        self.assertEqual(self.h.db.execute(
            "SELECT kind, name FROM conversations WHERE id=?", (room,)).fetchone(),
            ("room", "Room"))
        self.assertNotIn("other@c.x", dict(self.h.db.execute(
            "SELECT jid, kind FROM conversations")))
        for sub in ("to", "from", "both"):
            self.assertTrue(r.is_contact(sub))
        for sub in ("none", "remove", ""):
            self.assertFalse(r.is_contact(sub))
        self.assertGreater(self.h.rev(), rev)

    def test_subscription_policy(self):
        class Roster:
            auto_authorize = True
            auto_subscribe = True

        class Client:
            roster = Roster()
        c = Client()
        r.apply_subscription_policy(c)
        self.assertIsNone(c.roster.auto_authorize)
        self.assertIs(c.roster.auto_subscribe, False)

    @unittest.skipUnless(importlib.util.find_spec("slixmpp"), "slixmpp not installed")
    def test_session_subscription_policy(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            s = r.XmppSession("me@example.org/relay", "pw", self.h)
            self.assertIsNone(s.roster.auto_authorize)
            self.assertIs(s.roster.auto_subscribe, False)
            node = s.client_roster
            self.assertIsNone(node.auto_authorize)
            self.assertIs(node.auto_subscribe, False)
        finally:
            asyncio.set_event_loop(None)
            loop.close()

    def test_live_during_backfill_gets_higher_seq(self):
        h = self.h
        c = h.conv_for("bob@x", "chat", "Bob")
        gate = r.LiveGate()
        gate.hold()
        # a live message arrives while backfill is in flight: held
        gate.submit(lambda: r.ingest(h, c, ["live1"], 2000, "bob@x", "live"))
        self.assertEqual(h.db.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 0)
        # reverse MAM query: newest first
        newest_first = [("a3", 1003), ("a2", 1002), ("a1", 1001)]
        n = r.apply_backfill(newest_first,
                             lambda res: r.ingest(h, c, [res[0]], res[1], "bob@x", res[0]))
        self.assertEqual(n, 3)
        gate.release()
        rows = h.db.execute("SELECT seq, stanza_id, ts FROM messages ORDER BY seq").fetchall()
        self.assertEqual([x[1] for x in rows], ["a1", "a2", "a3", "live1"])
        self.assertEqual([x[2] for x in rows], sorted(x[2] for x in rows))
        # after release, live work runs immediately again
        gate.submit(lambda: r.ingest(h, c, ["live2"], 2001, "bob@x", "x"))
        self.assertEqual(h.db.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 5)

    def test_live_gate_overflow_runs_instead_of_dropping(self):
        ran = []
        g = r.LiveGate(cap=2)
        g.hold()
        for i in range(4):
            g.submit(lambda i=i: ran.append(i))
        self.assertEqual(ran, [2, 3])
        g.release()
        self.assertEqual(ran, [2, 3, 0, 1])

    def test_backfill_keeps_newest_when_over_keep(self):
        h = r.History(_tmpdb(), keep=5)
        c = h.conv_for("bob@x", "chat", "Bob")
        newest_first = [("m%02d" % i, 1000 + i) for i in range(9, -1, -1)][:5]
        r.apply_backfill(newest_first,
                         lambda res: r.ingest(h, c, [res[0]], res[1], "bob@x", res[0]))
        ids = [x[0] for x in h.db.execute("SELECT stanza_id FROM messages ORDER BY seq")]
        self.assertEqual(ids, ["m05", "m06", "m07", "m08", "m09"])


class ConfigTests(unittest.TestCase):
    def test_load_config(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "relay.ini")
        with open(p, "w") as f:
            f.write("[relay]\njid = a@b\npassword = SECRETPW1\npassphrase = SECRETPP1\n")
        c = r.load_config(p)
        self.assertEqual((c.jid, c.password, c.passphrase), ("a@b", "SECRETPW1", "SECRETPP1"))
        self.assertEqual((c.host, c.port, c.history), ("0.0.0.0", 8765, 50))
        self.assertEqual(c.db, os.path.join(d, "relay.db"))
        self.assertNotIn("SECRET", repr(c))
        with open(p, "w") as f:
            f.write("[relay]\njid = a@b\npassword = SECRETPW1\npassphrase = SECRETPP1\n"
                    "listen = 127.0.0.1:9000\nhistory = 20\ndb = /var/x.db\n")
        c = r.load_config(p)
        self.assertEqual((c.host, c.port, c.history, c.db), ("127.0.0.1", 9000, 20, "/var/x.db"))
        with open(p, "w") as f:
            f.write("[relay]\njid = a@b\npassword = SECRETPW1\n")
        with self.assertRaises(ValueError):
            r.load_config(p)

    def test_example_config_parses(self):
        c = r.load_config(os.path.join(HERE, "relay.ini.example"))
        self.assertEqual((c.host, c.port, c.history), ("0.0.0.0", 8765, 50))
        self.assertTrue(c.jid.endswith("@example.org"))
        self.assertTrue(c.password.startswith("change-me"))

    def test_no_slixmpp_at_import(self):
        src = open(os.path.join(HERE, "xmpp_relay.py"), encoding="utf-8").read()
        top = [l for l in src.splitlines() if l.startswith(("import slixmpp", "from slixmpp"))]
        self.assertEqual(top, [])


if __name__ == "__main__":
    unittest.main()
