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
        if max(per.values()) > 1:
            self.assertEqual(len(per), 40)
        self.assertEqual(max(per.values()), 1)
        for l in ls:
            if l[0] == "G":
                self.assertTrue(l[5].startswith("009"))  # newest message
        self.assertEqual(ls[-1][2], "0")

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


if __name__ == "__main__":
    unittest.main()
