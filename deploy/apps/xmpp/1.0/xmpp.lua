-- XMPP chat through a wadamesh relay (scripts/xmpp-relay).
-- Protocol: docs/superpowers/specs/2026-10-16-xmpp-app-design.md, section 2.
-- Sections: seal, codec. Nothing here runs at load time beyond defining functions.

local app = {}

local spack, sunpack, schar, sbyte, ssub = string.pack, string.unpack, string.char, string.byte, string.sub
local concat = table.concat
local tonumber = tonumber

-- ---------------------------------------------------------------- seal
-- keys = PBKDF2-HMAC-SHA256(passphrase, "wada-xmpp-v1", 2000 rounds, 64 bytes)
-- message = nonce(16) | ciphertext | tag(16)
-- keystream block i = HMAC(enc, nonce | u32be(i)); tag = HMAC(mac, dir | nonce | ct)[1..16]

local SALT, ROUNDS = "wada-xmpp-v1", 2000
local NONCE_LEN, TAG_LEN = 16, 16
local W = ">i4i4i4i4i4i4i4i4"   -- one 32-byte block as eight signed words (LUA_32BITS)

-- PBKDF2 state. The 64 output bytes are two PBKDF2 blocks (u32be 1 and 2);
-- their U chains advance in lockstep, so one round = one HMAC per block.
local function kdf_new(passphrase)
  return { pw = passphrase, j = 0 }
end

-- Advance by `iters` rounds (each round steps both blocks). Returns true once
-- done; st.enc and st.mac are then set and the passphrase is dropped.
local function kdf_step(st, iters)
  if st.enc then return true end
  local hmac = wada.crypto.hmac_sha256
  local pw, j = st.pw, st.j
  local u1, u2 = st.u1, st.u2
  local a1, a2, a3, a4, a5, a6, a7, a8, b1, b2, b3, b4, b5, b6, b7, b8
  if j == 0 then
    u1 = hmac(pw, SALT .. "\0\0\0\1")
    u2 = hmac(pw, SALT .. "\0\0\0\2")
    a1, a2, a3, a4, a5, a6, a7, a8 = sunpack(W, u1)
    b1, b2, b3, b4, b5, b6, b7, b8 = sunpack(W, u2)
    j, iters = 1, iters - 1
  else
    local a, b = st.a, st.b
    a1, a2, a3, a4, a5, a6, a7, a8 = a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]
    b1, b2, b3, b4, b5, b6, b7, b8 = b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8]
  end
  local n = ROUNDS - j
  if iters < n then n = iters end
  for _ = 1, n do
    u1 = hmac(pw, u1)
    local x1, x2, x3, x4, x5, x6, x7, x8 = sunpack(W, u1)
    a1, a2, a3, a4 = a1 ~ x1, a2 ~ x2, a3 ~ x3, a4 ~ x4
    a5, a6, a7, a8 = a5 ~ x5, a6 ~ x6, a7 ~ x7, a8 ~ x8
    u2 = hmac(pw, u2)
    x1, x2, x3, x4, x5, x6, x7, x8 = sunpack(W, u2)
    b1, b2, b3, b4 = b1 ~ x1, b2 ~ x2, b3 ~ x3, b4 ~ x4
    b5, b6, b7, b8 = b5 ~ x5, b6 ~ x6, b7 ~ x7, b8 ~ x8
  end
  j = j + (n > 0 and n or 0)
  if j >= ROUNDS then
    st.enc = spack(W, a1, a2, a3, a4, a5, a6, a7, a8)
    st.mac = spack(W, b1, b2, b3, b4, b5, b6, b7, b8)
    st.pw, st.u1, st.u2, st.a, st.b, st.j = nil, nil, nil, nil, nil, ROUNDS
    return true
  end
  st.j, st.u1, st.u2 = j, u1, u2
  st.a = { a1, a2, a3, a4, a5, a6, a7, a8 }
  st.b = { b1, b2, b3, b4, b5, b6, b7, b8 }
  return false
end

-- data XOR keystream(enc, nonce): whole 32-byte blocks a word at a time, tail bytewise
local function xor_stream(enc, nonce, data)
  local hmac = wada.crypto.hmac_sha256
  local out, no = {}, 0
  local n, pos, blk = #data, 1, 0
  while pos + 31 <= n do
    local k1, k2, k3, k4, k5, k6, k7, k8 = sunpack(W, hmac(enc, nonce .. spack(">i4", blk)))
    local d1, d2, d3, d4, d5, d6, d7, d8 = sunpack(W, data, pos)
    no = no + 1
    out[no] = spack(W, d1 ~ k1, d2 ~ k2, d3 ~ k3, d4 ~ k4, d5 ~ k5, d6 ~ k6, d7 ~ k7, d8 ~ k8)
    pos, blk = pos + 32, blk + 1
  end
  if pos <= n then
    local k = hmac(enc, nonce .. spack(">i4", blk))
    local t = {}
    for i = pos, n do t[i - pos + 1] = schar(sbyte(data, i) ~ sbyte(k, i - pos + 1)) end
    no = no + 1
    out[no] = concat(t)
  end
  return concat(out)
end

local function tag(mac, dir, nonce, ct)
  return ssub(wada.crypto.hmac_sha256(mac, dir .. nonce .. ct), 1, TAG_LEN)
end

-- dir is "Q" (request) or "P" (reply); nonce is 16 bytes
local function seal(enc, mac, dir, nonce, plain)
  local ct = xor_stream(enc, nonce, plain)
  return nonce .. ct .. tag(mac, dir, nonce, ct)
end

-- plaintext, or nil on short input or bad tag (checked before decrypting)
local function open(enc, mac, dir, msg)
  if type(msg) ~= "string" or #msg < NONCE_LEN + TAG_LEN then return nil end
  local nonce = ssub(msg, 1, NONCE_LEN)
  local ct = ssub(msg, NONCE_LEN + 1, -TAG_LEN - 1)
  -- whole-string compare (interned 16-byte strings): no per-byte early exit in Lua
  if tag(mac, dir, nonce, ct) ~= ssub(msg, -TAG_LEN) then return nil end
  return xor_stream(enc, nonce, ct)
end

-- 16 bytes from the hardware RNG (wada.sys.random() is esp_random(), 32 bits)
local function nonce()
  local r = wada.sys.random
  return spack(">i4i4i4i4", r(), r(), r(), r())
end

-- ---------------------------------------------------------------- codec
-- Tab-separated, \n-terminated lines. Text fields escape \ TAB LF; CR dropped.

local MAX_SEND_BYTES = 1000
local ESC = { ["\\"] = "\\\\", ["\t"] = "\\t", ["\n"] = "\\n", ["\r"] = "" }
local UNESC = { t = "\t", n = "\n", ["\\"] = "\\" }
local function unesc1(c) return UNESC[c] or c end

local function esc(s)
  return (s:gsub("[\\\t\n\r]", ESC))
end

local function unesc(s)
  if not s:find("\\", 1, true) then return s end
  return (s:gsub("\\(.)", unesc1))
end

-- at most `max` bytes, never ending inside a UTF-8 sequence
local function cut_utf8(s, max)
  if #s <= max then return s end
  local i = max
  while i > 0 do
    local b = sbyte(s, i + 1)
    if b < 0x80 or b > 0xBF then break end
    i = i - 1
  end
  return ssub(s, 1, i)
end

-- split on TAB, keeping empty fields ("a\t\tb" -> {"a", "", "b"})
local function fields(line)
  local f, n = {}, 0
  for v in (line .. "\t"):gmatch("([^\t]*)\t") do n = n + 1; f[n] = v end
  return f
end

-- outbox: { {conv=, cmid=, text=}, ... }; reads: { {conv=, seq=}, ... }
local function build_request(sid, q, cursor, outbox, reads)
  local out = { "S\t" .. sid .. "\t" .. q .. "\t" .. cursor .. "\n" }
  for _, m in ipairs(outbox or {}) do
    out[#out + 1] = "M\t" .. m.conv .. "\t" .. m.cmid .. "\t" .. esc(cut_utf8(m.text, MAX_SEND_BYTES)) .. "\n"
  end
  for _, r in ipairs(reads or {}) do
    out[#out + 1] = "R\t" .. r.conv .. "\t" .. r.seq .. "\n"
  end
  return concat(out)
end

-- { q, offline, convs = {{id, kind, jid, name, presence, unread}},
--   msgs = {{conv, seq, ts, sender, text}}, acks = {{cmid, ok, reason}}, cursor, more }
-- ok / more / offline are booleans. nil unless the reply starts with P and ends with N.
local function parse_reply(plain)
  local r = { offline = false, convs = {}, msgs = {}, acks = {} }
  local convs, msgs, acks = r.convs, r.msgs, r.acks
  local first = true
  for line in plain:gmatch("([^\n]*)\n") do
    local f = fields(line)
    local t = f[1]
    if first then
      if t ~= "P" or not f[2] then return nil end
      r.q = tonumber(f[2])
      first = false
    elseif r.cursor then
      -- nothing may follow N
    elseif t == "G" and #f >= 6 then
      msgs[#msgs + 1] = { conv = tonumber(f[2]), seq = tonumber(f[3]), ts = tonumber(f[4]),
                          sender = unesc(f[5]), text = unesc(f[6]) }
    elseif t == "C" and #f >= 7 then
      convs[#convs + 1] = { id = tonumber(f[2]), kind = f[3], jid = f[4], name = unesc(f[5]),
                            presence = f[6], unread = tonumber(f[7]) }
    elseif t == "A" and #f >= 3 then
      acks[#acks + 1] = { cmid = f[2], ok = f[3] == "ok", reason = f[4] and unesc(f[4]) or nil }
    elseif t == "E" then
      if f[2] == "xmpp-offline" then r.offline = true end
    elseif t == "N" and #f >= 3 then
      r.cursor, r.more = tonumber(f[2]), f[3] == "1"
    end
  end
  if first or not r.cursor or not r.q then return nil end
  return r
end

-- internal, for scripts/lua-harness
app._t = {
  kdf_new = kdf_new, kdf_step = kdf_step,
  seal = seal, open = open, nonce = nonce,
  esc = esc, unesc = unesc, cut_utf8 = cut_utf8, fields = fields,
  build_request = build_request, parse_reply = parse_reply,
}

return app
