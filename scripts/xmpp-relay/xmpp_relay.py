#!/usr/bin/env python3
"""wadamesh XMPP relay.

Sections: seal (crypto). Codec, history and networking are added later.
slixmpp must only be imported lazily, never at module top level.
"""
import hashlib
import hmac
import os
import sys

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


def main(argv):
    if "--gen-vectors" in argv:
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")
        gen_vectors(sys.stdout)
        return 0
    sys.stderr.write("usage: xmpp_relay.py --gen-vectors\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
