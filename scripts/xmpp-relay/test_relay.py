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


if __name__ == "__main__":
    unittest.main()
