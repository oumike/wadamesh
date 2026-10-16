-- XMPP chat through a wadamesh relay (scripts/xmpp-relay).
-- Protocol: docs/superpowers/specs/2026-10-16-xmpp-app-design.md, section 2.
-- Sections: seal, codec, sync (setup, poll loop, outbox, SD history), screens,
-- app callbacks.
-- Nothing here runs at load time beyond defining functions.

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

-- ---------------------------------------------------------------- sync
-- One sealed POST <url>/w at a time. Poll every 5 s, back off to 30 s after six
-- failures, re-sync at once on `more = 1`, on a send and after a relay reset.
-- Store writes: setup, the qb reservation (open + every 1000 requests), and the
-- outbox on a user send / ack. Never per sync.

local POLL_MS, BACKOFF_MS, BACKOFF_AFTER = 5000, 30000, 6
local CORRUPT_AFTER = 3                -- bad replies in a row before the header says so
local QBLOCK = 1000                    -- q numbers reserved per qb write
local OUT_MAX = 1024                   -- bytes of escaped M lines kept in store "out"
local MAX_MSGS, MAX_CONVS, MAX_FAILED = 50, 40, 10
local KDF_ITERS = 400                  -- PBKDF2 rounds per tick (~57k instructions measured)
local MAX_REPLY = 8192
local CTYPE = "application/octet-stream"
local URL_MAX = 157                     -- url .. "/w" must fit the host's 160-byte s_net_url

local HEADERS = {
  connecting = "Connecting…",        -- session start until the first reply, whatever it says
  online = "Online",
  unreachable = "Relay unreachable",
  xmpp_offline = "Relay offline from XMPP",
  denied = "Passphrase rejected — check Settings",
}
local CORRUPTED = "Relay reply corrupted"
local POLLING = { connecting = true, online = true, unreachable = true, xmpp_offline = true }

local S = {
  state = "setup",
  gen = 0,          -- bumped on setup / reset: a reply for an older session is ignored
  convs = {}, nconv = 0,
  outbox = {},      -- { {conv, cmid, text}, ... } oldest first, mirrors store "out"
  cmids = {},       -- cmids used this session
  reads = {},       -- conv -> seq still to report with an R line
  failed = {},      -- conv -> { {cmid, text, err = true, reason}, ... }
  rev = 0,          -- bumped whenever anything a screen shows changes
  fails = 0, bad = 0, cursor = 0, next_at = 0,
  synced = false,   -- a reply was applied this session (the empty list is then really empty)
}

local function changed() S.rev = S.rev + 1 end
local function now() return wada.sys.millis() end
local function sget(k)
  local v = wada.store.get(k)
  if v == nil or v == "" then return nil end
  return tostring(v)
end

local function rhex(words)
  local r = wada.sys.random
  local t = {}
  for i = 1, words do t[i] = spack(">i4", r()) end
  return wada.crypto.hex(concat(t))
end

local function unhex(h)
  if type(h) ~= "string" or #h ~= 64 or h:find("[^0-9a-f]") then return nil end
  return (h:gsub("..", function(x) return schar(tonumber(x, 16)) end))
end

local function clear_view()
  S.convs, S.nconv, S.cursor = {}, 0, 0
  changed()
end

-- ---- outbox (store "out": escaped M lines joined by "\n")
local function out_line(m) return "M\t" .. m.conv .. "\t" .. m.cmid .. "\t" .. esc(m.text) end

local function out_string(list)
  local t = {}
  for i, m in ipairs(list) do t[i] = out_line(m) end
  return concat(t, "\n")
end

local function load_outbox()
  S.outbox = {}
  local s = sget("out")
  if not s then return end
  for line in (s .. "\n"):gmatch("([^\n]*)\n") do
    local f = fields(line)
    local conv = tonumber(f[2])
    if f[1] == "M" and conv and f[3] and f[3] ~= "" and f[4] then
      S.outbox[#S.outbox + 1] = { conv = conv, cmid = f[3], text = unesc(f[4]) }
      S.cmids[f[3]] = true
    end
  end
end

local function new_cmid()
  local c
  repeat c = rhex(1) until not S.cmids[c]
  S.cmids[c] = true
  return c
end

-- ---- session
local function reserve_q()
  S.qlim = S.q + QBLOCK
  wada.store.set("qb", tostring(S.qlim))
end

local function start_session(url, ek, mk, sid)
  S.url, S.ek, S.mk, S.sid = url .. "/w", ek, mk, sid
  S.gen = S.gen + 1
  S.q = math.tointeger(tonumber(sget("qb") or "0")) or 0
  reserve_q()
  S.fails, S.bad, S.next_at = 0, 0, 0
  S.reads = {}
  S.synced = false
  clear_view()
  S.state = "connecting"
  changed()
end

local function load_config()
  local url, sid = sget("url"), sget("sid")
  local ek, mk = unhex(sget("ek")), unhex(sget("mk"))
  if url and sid and ek and mk then
    start_session(url, ek, mk, sid)
    return true
  end
  return false
end

local function finish_setup(url, st)
  local sid = sget("sid")
  if not sid or not sid:match("^[0-9a-f]+$") or #sid ~= 16 then sid = rhex(2) end
  local hex = wada.crypto.hex
  wada.store.set("url", url)
  wada.store.set("ek", hex(st.enc))
  wada.store.set("mk", hex(st.mac))
  wada.store.set("sid", sid)
  start_session(url, st.enc, st.mac, sid)
end

local function ask_passphrase(u)
  wada.ui.input("Passphrase", "", function(pw)
    S.prompting = false
    if not pw or pw == "" then return end
    S.gen = S.gen + 1          -- stop the old session; its in-flight reply is ignored
    S.kdf, S.kdf_url = kdf_new(pw), u
    S.state = "deriving"
    changed()
  end)
end

-- Prompts "Relay URL" then "Passphrase" (only the passphrase when pass_only and
-- a URL is stored). Cancel at either step changes nothing.
local function setup(pass_only)
  if S.prompting then return end
  S.prompting = true
  local stored = sget("url")
  if pass_only == true and stored then return ask_passphrase(stored) end
  wada.ui.input("Relay URL", stored or "http://", function(u)
    if not u then S.prompting = false; return end
    u = u:match("^%s*(.-)%s*$")
    if ssub(u, -1) == "/" then u = ssub(u, 1, -2) end
    if not u:match("^http://[^%s/][^%s]*$") or #u > URL_MAX then
      S.prompting = false
      wada.sys.toast(#u > URL_MAX and "Relay URL too long" or "Relay URL must look like http://host:port")
      return
    end
    ask_passphrase(u)
  end)
end

-- Forget keys, cursor and pending sends; the next setup makes a new sid.
local function reset()
  for _, k in ipairs({ "url", "ek", "mk", "sid", "qb", "out" }) do wada.store.set(k, "") end
  S.gen = S.gen + 1
  S.kdf, S.url, S.ek, S.mk, S.sid = nil, nil, nil, nil, nil
  S.outbox, S.failed, S.reads = {}, {}, {}
  S.synced = false
  clear_view()
  S.state = "setup"
  changed()
end

-- ---- SD history (optional; spec section 3)
-- One file per conversation in wada.fs, c<conv>.log, one line per message:
--   <seq> TAB <ts> TAB <esc sender> TAB <esc text> LF
-- Only when caps.sd and caps.sdk_ext and store "sd" == "1". Lines are buffered
-- per conversation and flushed one fs call at a time (round robin), never
-- within SD_GAP of the previous call: the host refuses writes less than 1 s
-- apart with `false, "too fast"`, which just leaves the buffer for next time.
-- A log that would pass SD_ROTATE is rotated over two flushes, because wada.fs
-- has no rename: flush 1 copies the current .log to c<conv>.old (write
-- replaces it), flush 2 writes the buffer as the new .log. Lines that arrive in
-- between stay buffered. Any other write error (card pulled or full) stops the
-- history for this session with one toast. The last seq on the card is read
-- from the log's tail when a conversation's first message of the session comes
-- in, so the cursor-0 replay on every open is not buffered or appended again.
local SD_GAP, SD_ROTATE = 2000, 30720
-- buffered bytes per conversation / over all of them: the total fits the session
-- start (up to 40 conversations x 10 replayed messages) inside the 256 KB app heap
local SD_PEND, SD_PEND_ALL = 8192, 49152
local SD_TAIL, SD_HIST = 8192, 100         -- chat open: bytes read from the card, rows kept
local SD_SEED = 2048                       -- tail read for the last seq (SD_TAIL if no line in it)

local H = {
  allowed = false,  -- caps.sd and caps.sdk_ext
  on = false,       -- allowed, store sd == "1", and no write error this session
  dead = false,     -- a write failed: off until the app is opened again
  c = {},           -- conv -> { lines, seqs, bytes, top, logged, size, rot }
  bytes = 0,        -- buffered bytes over all conversations
  nrot = 0,         -- conversations between the two rotation flushes
  drops = 0,        -- buffered lines dropped by the bounds
  last = nil,       -- millis of the last write / append
  turn = 0,         -- conv flushed last (round robin)
  zero = false,     -- relay reset: seqs restarted, so a log's tail no longer counts
}

local function hist_conv(id)
  local c = H.c[id]
  if not c then
    c = { lines = {}, seqs = {}, bytes = 0, top = 0 }
    H.c[id] = c
  end
  return c
end

local function hist_unbuffer(c)
  H.bytes = H.bytes - c.bytes
  c.lines, c.seqs, c.bytes = {}, {}, 0
end

local function hist_drop_oldest(c)
  local b = #c.lines[1]
  table.remove(c.lines, 1)
  table.remove(c.seqs, 1)
  c.bytes, H.bytes, H.drops = c.bytes - b, H.bytes - b, H.drops + 1
end

-- seq of the last line in the tail of a log, and the file's size (nil, 0 when missing)
local function hist_last(name)
  local read = wada.fs.read
  local _, total = read(name, 0, 0)
  if not total or total == 0 then return nil, total or 0 end
  local want = SD_SEED
  repeat
    local off = total > want and total - want or 0
    local d = read(name, off, want)
    if not d then return nil, total end
    local last
    for v in (off == 0 and "\n" .. d or d):gmatch("\n(%d+)\t") do last = v end
    if last or off == 0 or want == SD_TAIL then return math.tointeger(tonumber(last)), total end
    want = SD_TAIL                         -- one long last line: look further back once
  until false
end

-- learn what is on the card; drop buffered lines it already holds
local function hist_seed(id, c)
  local last, size = hist_last("c" .. id .. ".log")
  if not last then last = hist_last("c" .. id .. ".old") end   -- .log lost mid-rotation
  c.size = size
  c.logged = H.zero and 0 or (last or 0)
  if c.logged > c.top then c.top = c.logged end
  local seqs = c.seqs
  while seqs[1] and seqs[1] <= c.logged do
    local b = #c.lines[1]
    table.remove(c.lines, 1)
    table.remove(seqs, 1)
    c.bytes, H.bytes = c.bytes - b, H.bytes - b
  end
end

-- store sd / caps changed (or the app opened)
local function hist_config()
  H.on = H.allowed and not H.dead and sget("sd") == "1"
  if not H.on then
    for _, c in pairs(H.c) do
      hist_unbuffer(c)
      if c.rot then c.rot = nil; H.nrot = H.nrot - 1 end
    end
  end
end

local function hist_fail(err)
  H.dead = true
  hist_config()
  wada.sys.toast("SD card history stopped: " .. tostring(err or "write failed"))
end

-- a confirmed message (seq from the relay) for conversation id
local function hist_add(id, m)
  if not H.on then return end
  local c = hist_conv(id)
  if not c.logged then hist_seed(id, c) end
  if m.seq <= c.top then return end
  c.top = m.seq
  local line = m.seq .. "\t" .. m.ts .. "\t" .. esc(m.sender) .. "\t" .. esc(m.text) .. "\n"
  local n = #c.lines + 1
  c.lines[n], c.seqs[n] = line, m.seq
  c.bytes, H.bytes = c.bytes + #line, H.bytes + #line
  while c.bytes > SD_PEND do hist_drop_oldest(c) end
  while H.bytes > SD_PEND_ALL do         -- many busy conversations: trim the biggest buffer
    local big
    for _, o in pairs(H.c) do if not big or o.bytes > big.bytes then big = o end end
    hist_drop_oldest(big)
  end
end

-- the relay's seqs restarted: what the card holds no longer filters anything
local function hist_relay_reset()
  H.zero = true
  for _, c in pairs(H.c) do
    c.top = 0
    if c.logged then c.logged = 0 end
  end
end

-- at most one fs call, and never within SD_GAP of the previous one
local function hist_flush(t)
  if not H.on or (H.bytes == 0 and H.nrot == 0) then return end
  if H.last and t - H.last < SD_GAP then return end
  local pick, first, turn = nil, nil, H.turn
  for id, c in pairs(H.c) do
    if c.bytes > 0 or c.rot then
      if id > turn and (not pick or id < pick) then pick = id end
      if not first or id < first then first = id end
    end
  end
  pick = pick or first
  H.turn = pick
  local c = H.c[pick]
  if not c.logged then
    hist_seed(pick, c)
    if c.bytes == 0 then return end      -- all of it was on the card already
  end
  local fs, name = wada.fs, "c" .. pick .. ".log"
  local block = concat(c.lines)
  local ok, err, replaced
  if c.rot then                            -- rotation, flush 2: the buffer is the new log
    ok, err = fs.write(name, block)
    replaced = ok
  elseif c.size + #block > SD_ROTATE then
    local cur = fs.read(name)
    if cur and cur ~= "" then              -- rotation, flush 1: keep the current log as .old
      ok, err = fs.write("c" .. pick .. ".old", cur)
      if ok then c.rot = true; H.nrot = H.nrot + 1 end
      block = nil
    else
      ok, err = fs.write(name, block)
      replaced = ok
    end
  else
    ok, err = fs.append(name, block)
  end
  H.last = t
  if not ok then
    if err ~= "too fast" then hist_fail(err) end
    return
  end
  if not block then return end
  if replaced then
    c.size = #block
    if c.rot then c.rot = nil; H.nrot = H.nrot - 1 end
  else
    c.size = c.size + #block
  end
  c.logged = c.seqs[#c.seqs] or c.logged
  hist_unbuffer(c)
end

-- {seq, sender, text} ascending: the card's tail for conversation id (the end
-- of .old too when .log is short) plus lines not flushed yet, older than
-- before_seq (nil = all), each seq once, at most SD_HIST.
local function hist_parse(d, out, seen, before)
  for line in d:gmatch("([^\n]*)\n") do
    local f = fields(line)
    local s = math.tointeger(tonumber(f[1]))
    if s and f[4] and not seen[s] and (not before or s < before) then
      seen[s] = true
      out[#out + 1] = { seq = s, sender = unesc(f[3]), text = unesc(f[4]) }
    end
  end
end

local function hist_tail_of(name, want)
  local read = wada.fs.read
  local _, total = read(name, 0, 0)
  if not total or total == 0 then return "", 0 end
  local off = total > want and total - want or 0
  local d = read(name, off, want) or ""
  if off > 0 then                          -- drop the partial first line
    local p = d:find("\n", 1, true)
    d = p and ssub(d, p + 1) or ""
  end
  return d, total
end

local function hist_tail(id, before)
  if not H.on then return {} end
  local c = hist_conv(id)
  if not c.logged then hist_seed(id, c) end
  local d, total = hist_tail_of("c" .. id .. ".log", SD_TAIL)
  local out, seen = {}, {}
  if total < SD_TAIL then
    hist_parse((hist_tail_of("c" .. id .. ".old", SD_TAIL - total)), out, seen, before)
  end
  hist_parse(d, out, seen, before)
  hist_parse(concat(c.lines), out, seen, before)
  local extra = #out - SD_HIST
  if extra > 0 then table.move(out, extra + 1, #out, 1); for i = #out, SD_HIST + 1, -1 do out[i] = nil end end
  return out
end

-- ---- applying a reply
local function evict_convs()
  local list = {}
  for _, c in pairs(S.convs) do list[#list + 1] = c end
  table.sort(list, function(a, b)
    if a.act ~= b.act then return a.act > b.act end
    return a.id > b.id
  end)
  for i = MAX_CONVS + 1, #list do S.convs[list[i].id] = nil end
  S.nconv = MAX_CONVS
end

local function apply_view(r)
  local convs = S.convs
  for _, c in ipairs(r.convs) do
    if c.id and c.unread then
      local cv = convs[c.id]
      if not cv then
        cv = { id = c.id, msgs = {}, seq = 0, act = 0 }
        convs[c.id] = cv
        S.nconv = S.nconv + 1
      end
      cv.kind, cv.jid, cv.name, cv.presence, cv.unread = c.kind, c.jid, c.name, c.presence, c.unread
    end
  end
  for _, m in ipairs(r.msgs) do
    local cv = m.conv and m.seq and m.ts and convs[m.conv]
    if cv and m.seq > cv.seq then
      local t = cv.msgs
      local nm = { seq = m.seq, ts = m.ts, sender = m.sender, text = m.text }
      t[#t + 1] = nm
      if #t > MAX_MSGS then
        local old = table.remove(t, 1)
        if S.on_drop then S.on_drop(m.conv, old) end   -- an open chat keeps it on screen
      end
      cv.seq, cv.act = m.seq, m.seq
      hist_add(m.conv, nm)
    end
  end
  if S.nconv > MAX_CONVS then evict_convs() end
end

local function apply_acks(acks)
  local hit = false
  for _, a in ipairs(acks) do
    local ob = S.outbox
    for i = 1, #ob do
      local m = ob[i]
      if m.cmid == a.cmid then
        table.remove(ob, i)
        hit = true
        if not a.ok then
          local f = S.failed[m.conv] or {}
          S.failed[m.conv] = f
          f[#f + 1] = { cmid = m.cmid, text = m.text, err = true,
                        reason = (a.reason and a.reason ~= "") and a.reason or nil }
          if #f > MAX_FAILED then table.remove(f, 1) end
        end
        break
      end
    end
  end
  if hit then
    wada.store.set("out", out_string(S.outbox))
    changed()
  end
end

-- network failure (corrupt = false) or a reply that failed tag / parse / q (true)
local function failed(t, corrupt)
  S.fails = S.fails + 1
  S.bad = corrupt and S.bad + 1 or 0
  S.state = "unreachable"
  S.next_at = t + (S.fails >= BACKOFF_AFTER and BACKOFF_MS or POLL_MS)
  changed()
end

local function on_reply(req, status, body)
  S.inflight = nil
  if req.gen ~= S.gen then return end
  local t = now()
  if status ~= 200 or type(body) ~= "string" then return failed(t, false) end
  if body == "DENIED" then
    S.state = "denied"
    changed()
    return
  end
  local plain = open(S.ek, S.mk, "P", body)
  local r = plain and parse_reply(plain)
  if not r or r.q ~= req.q then return failed(t, true) end
  S.fails, S.bad = 0, 0
  S.synced = true
  S.state = r.offline and "xmpp_offline" or "online"
  apply_acks(r.acks)
  for _, rd in ipairs(req.reads) do
    local s = S.reads[rd.conv]
    if s and s <= rd.seq then S.reads[rd.conv] = nil end
  end
  if req.cursor > 0 and r.cursor < req.cursor then
    clear_view()           -- relay database lost or replaced: resync from 0 now
    S.reads = {}           -- their seqs belong to the lost revision
    hist_relay_reset()
    S.next_at = t
  else
    apply_view(r)
    S.cursor = r.cursor
    S.next_at = r.more and t or t + POLL_MS
  end
  changed()
end

local function sync(t)
  if S.q >= S.qlim then reserve_q() end
  local q = S.q
  S.q = q + 1
  local reads = {}
  for conv, seq in pairs(S.reads) do reads[#reads + 1] = { conv = conv, seq = seq } end
  local plain = build_request(S.sid, q, S.cursor, S.outbox, reads)
  local req = { q = q, cursor = S.cursor, reads = reads, gen = S.gen }
  local ok, err = pcall(wada.net.http_post, S.url, seal(S.ek, S.mk, "Q", nonce(), plain), CTYPE,
                        function(st, b) on_reply(req, st, b) end, MAX_REPLY)
  if ok then
    S.inflight = req
  elseif tostring(err):find("already running", 1, true) then
    S.next_at = t + POLL_MS        -- net worker busy: try again later
  else
    failed(t, false)               -- e.g. "url too long", "no memory for the reply buffer"
  end
end

local function step()
  hist_flush(now())
  if S.state == "deriving" then
    if kdf_step(S.kdf, KDF_ITERS) then
      local st, url = S.kdf, S.kdf_url
      S.kdf, S.kdf_url = nil, nil
      finish_setup(url, st)
    end
    return
  end
  if POLLING[S.state] and not S.inflight then
    local t = now()
    if t >= S.next_at then sync(t) end
  end
end

-- ---- data API for the screens
-- queue text for conv; returns cmid, or nil + reason (toast on a full outbox)
local function send(conv, text)
  conv = math.tointeger(conv)
  if not conv or type(text) ~= "string" then return nil, "bad arguments" end
  text = cut_utf8(text:gsub("\r", ""), MAX_SEND_BYTES)
  if text:match("^%s*$") then return nil, "empty" end
  if not S.sid then return nil, "not set up" end
  local m = { conv = conv, text = text }
  m.cmid = new_cmid()
  local cur = out_string(S.outbox)
  local s = (cur ~= "" and (cur .. "\n") or "") .. out_line(m)
  if #s > OUT_MAX then
    wada.sys.toast("Too many unsent messages — wait for the relay")
    return nil, "outbox full"
  end
  S.outbox[#S.outbox + 1] = m
  wada.store.set("out", s)
  if POLLING[S.state] then S.next_at = 0 end
  changed()
  return m.cmid
end

local function by_activity(a, b)
  local ua, ub = (a.unread or 0) > 0, (b.unread or 0) > 0
  if ua ~= ub then return ua end
  if a.act ~= b.act then return a.act > b.act end
  return a.id < b.id
end

-- conversation tables {id, kind, jid, name, presence, unread, seq, act, msgs}: unread first, then latest
local function convs()
  local list = {}
  for _, c in pairs(S.convs) do list[#list + 1] = c end
  table.sort(list, by_activity)
  return list
end

-- {seq, ts, sender, text} ascending; sender "" = own message
local function msgs(conv)
  local cv = S.convs[conv]
  return cv and cv.msgs or {}
end

-- sends not yet confirmed ({cmid, text, err = false}) and failed ones ({..., err = true, reason})
local function pending(conv)
  local list = {}
  for _, f in ipairs(S.failed[conv] or {}) do list[#list + 1] = f end
  for _, m in ipairs(S.outbox) do
    if m.conv == conv then list[#list + 1] = { cmid = m.cmid, text = m.text, err = false } end
  end
  return list
end

local function mark_read(conv)
  local cv = S.convs[conv]
  if not cv then return end
  cv.unread = 0
  if cv.seq > 0 then S.reads[conv] = cv.seq end
  changed()
end

local function header()
  local st = S.state
  if st == "setup" or st == "deriving" then return nil end
  if S.bad >= CORRUPT_AFTER then return CORRUPTED end
  return HEADERS[st]
end

-- ---------------------------------------------------------------- screens
-- list (conversations), chat (one conversation), settings. A screen is built
-- once with wada.ui.clear(); after that on_tick only patches the rows whose
-- text or colour changed, and only when S.rev moved. An idle tick touches no
-- widget, and the list keeps its scroll position and keyboard focus.
-- Keyboard / trackball boards: list rows and buttons are focus stops in creation
-- order, so every screen creates its buttons first, above its list. There is
-- deliberately no app.on_input: declaring one makes the firmware send every key
-- to the app and turns its focus navigation off (UITask.cpp), so every action
-- here is a button or a list row.
-- Long rows: a list row's label has a fixed width and content height, so the
-- firmware wraps long text inside the row; no wrapping is done here.

local ui = { rows = {}, cols = {}, ids = {} }
-- ASCII / U+2022 only: the firmware fonts have no U+25xx circles (R9)
local DOTS = { on = "•", away = "~" }          -- anything else is "-"; rooms are "#"
local EMPTY = "No contacts or rooms yet. Add contacts or bookmark rooms from another XMPP client."
local SD_ROW, SD_DESC = "Keep history on SD card", "Stored unencrypted on the card."
local RESET_ROW, RESET_CONFIRM = "Reset", "Reset: press again to forget the relay keys"
local CONFIRM_MS = 5000                         -- a second Reset press must come within this
local TITLE_LINES = 2                           -- a top-bar text longer than this is cut

local show_list, show_chat, show_settings      -- forward declarations

local function status_text()
  return header() or (S.state == "deriving" and "Deriving keys…" or "Not set up")
end

local function status_color()
  local C, st = wada.ui.colors, S.state
  if st == "online" and S.bad < CORRUPT_AFTER then return C.good or C.text end
  if st == "setup" or st == "deriving" or st == "connecting" then return C.sub end
  return C.bad or C.text
end

-- sizes from the screen and the fonts, set in on_open
local function metrics(w, h)
  local U = wada.ui
  ui.W, ui.H = w, h
  ui.M = math.max(4, w // 64)
  ui.th12, ui.th14 = U.text_h(12), U.text_h(14)
  ui.BH = ui.th14 * 7 // 4
  ui.ROWH = ui.th12 * 7 // 4 + 2                -- a one-line list row (label + padding + gap)
end

local function btn_w(text) return wada.ui.text_w(text, 14) + ui.th14 end

local function fit_lines(text, w, size)
  local n = wada.ui.text_lines(text, w, size)
  return n > TITLE_LINES and TITLE_LINES or n
end

-- cut text (with "…") until it wraps to at most TITLE_LINES lines in w
local function fit_text(text, w, size)
  local lines = wada.ui.text_lines
  if lines(text, w, size) <= TITLE_LINES then return text end
  local n = #text
  repeat
    n = n - 1
    local t = cut_utf8(text, n) .. "…"
    if lines(t, w, size) <= TITLE_LINES then return t end
  until n <= 1
  return "…"
end

-- Top bar: optional buttons at the left and right edges, wrapped text between.
-- left / right are { text, fn }. Returns the label, its width and line count,
-- and the y where the content below starts.
local function top_bar(left, text, size, color, right)
  local U, M, BH = wada.ui, ui.M, ui.BH
  local x0, x1 = M, ui.W - M
  if left then
    local bw = btn_w(left[1])
    U.button(left[1], x0, M, bw, BH, left[2])
    x0 = x0 + bw + M
  end
  if right then
    local bw = btn_w(right[1])
    U.button(right[1], x1 - bw, M, bw, BH, right[2])
    x1 = x1 - bw - M
  end
  local tw = x1 - x0
  local th = U.text_h(size)
  local t = fit_text(text, tw, size)
  local lines = fit_lines(t, tw, size)
  local top = math.max(BH, lines * th)
  local lbl = U.label(t, x0, M + (top - lines * th) // 2, size, color)
  lbl:width(tw)
  return lbl, tw, lines, M + top + M
end

-- Bring ui.list in line with texts / cols: set what changed, add what is new,
-- rebuild only when rows went away (the list cannot drop one row). fn_for(i)
-- gives row i its callback when the row is created. Returns the old row count.
local function patch(texts, cols, fn_for)
  local l, rows, have = ui.list, ui.rows, ui.cols
  local plain = wada.ui.colors.text
  local n = #texts
  if n < #rows then
    l:clear()
    rows, have = {}, {}
    ui.rows, ui.cols = rows, have
  end
  local old = #rows
  for i = 1, n do
    local t, c = texts[i], cols and cols[i] or plain
    if i > old then
      l:add(t, fn_for and fn_for(i) or nil)
      rows[i] = t
      if c ~= plain then l:color(i, c) end
      have[i] = c
    else
      if rows[i] ~= t then l:set(i, t); rows[i] = t end
      if have[i] ~= c then l:color(i, c); have[i] = c end
    end
  end
  return old
end

local function new_screen(name)
  wada.ui.clear()
  ui.screen, ui.list, ui.rows, ui.cols, ui.ids = name, nil, {}, {}, {}
  ui.htexts, ui.hcols, S.on_drop = {}, {}, nil
end

-- ---- conversation list
local function conv_row(c)
  local dot = c.kind == "room" and "#" or DOTS[c.presence] or "-"
  local name = (c.name and c.name ~= "") and c.name or c.jid or "?"
  local s = dot .. " " .. name
  if (c.unread or 0) > 0 then s = s .. "  (" .. c.unread .. ")" end
  return s
end

local function list_mode()
  local st = S.state
  if st == "setup" then return "setup" end
  if st == "deriving" then return "wait" end
  if S.nconv > 0 then return "list" end
  return S.synced and "empty" or "wait"
end

local function opener(i)
  return function()
    local id = ui.ids[i]
    if id then show_chat(id) end
  end
end

local function refresh_list()
  local texts, ids = {}, {}
  for i, c in ipairs(convs()) do texts[i], ids[i] = conv_row(c), c.id end
  ui.ids = ids
  patch(texts, nil, opener)
end

function show_list()
  new_screen("list")
  local U, C, M = wada.ui, wada.ui.colors, ui.M
  ui.mode, ui.shown = list_mode(), status_text()
  local y
  ui.status, ui.status_w, ui.status_lines, y =
    top_bar(nil, ui.shown, 12, status_color(), { "Settings", function() show_settings() end })
  if ui.mode == "setup" then
    U.button("Set up relay", M, y, btn_w("Set up relay"), ui.BH, function() setup() end)
  elseif ui.mode == "empty" then
    U.label(EMPTY, M, y, 12, C.sub):width(ui.W - 2 * M)
  elseif ui.mode == "list" then
    ui.list = U.list(M, y, ui.W - 2 * M, ui.H - y - M)
    refresh_list()
  end
  ui.rev = S.rev
end

-- ---- chat
-- With SD history on, the rows start with the card's tail (ui.htexts), older
-- than the relay's window; a message the RAM bound drops while the chat is open
-- moves there too, so the rows only ever grow at the bottom.
local function msg_row(m, room)
  local C = wada.ui.colors
  if m.sender == "" then return "> " .. m.text, C.accent end
  if room then return m.sender .. ": " .. m.text, C.text end
  return m.text, C.text
end

local function hist_push(m)
  local n = #ui.htexts + 1
  ui.htexts[n], ui.hcols[n] = msg_row(m, ui.room)
  if n > SD_HIST then table.remove(ui.htexts, 1); table.remove(ui.hcols, 1) end
end

local function refresh_chat()
  local id = ui.conv
  local cv = S.convs[id]
  if cv and (cv.unread or 0) > 0 then mark_read(id) end   -- read while it is on screen
  local own = wada.ui.colors.accent
  local room = ui.room
  local texts, cols, n = {}, {}, #ui.htexts
  table.move(ui.htexts, 1, n, 1, texts)
  table.move(ui.hcols, 1, n, 1, cols)
  for _, m in ipairs(msgs(id)) do
    n = n + 1
    texts[n], cols[n] = msg_row(m, room)
  end
  for _, p in ipairs(pending(id)) do
    n = n + 1
    if p.err then
      texts[n] = "> " .. p.text .. " !" .. (p.reason and (" " .. p.reason) or "")
    else
      texts[n] = "> " .. p.text .. " …"
    end
    cols[n] = own
  end
  if patch(texts, cols) < n then ui.list:select(n) end   -- new rows: scroll to the newest
  ui.rev = S.rev
end

local function write()
  if S.prompting then return end
  local id = ui.conv
  S.prompting = true
  wada.ui.input("Message", "", function(t)
    S.prompting = false
    if t then send(id, t) end      -- send() toasts a full outbox; empty text is ignored
  end)
end

function show_chat(id)
  local cv = S.convs[id]
  if not cv then return end
  new_screen("chat")
  ui.conv, ui.room = id, cv.kind == "room"
  local name = (cv.name and cv.name ~= "") and cv.name or cv.jid or "?"
  local _, _, _, y = top_bar({ "Back", function() show_list() end }, name, 14, wada.ui.colors.text,
                             { "Write", write })
  ui.list = wada.ui.list(ui.M, y, ui.W - 2 * ui.M, ui.H - y - ui.M)
  if H.on then
    local first = cv.msgs[1]
    for _, m in ipairs(hist_tail(id, first and first.seq)) do hist_push(m) end
    S.on_drop = function(conv, m) if conv == id then hist_push(m) end end
  end
  mark_read(id)                    -- R <conv> <newest seq> on the next request
  refresh_chat()
end

-- ---- settings
local function sd_on() return sget("sd") == "1" end

local function settings_rows()
  local t = { "Relay URL", "Passphrase" }
  if ui.sd then t[#t + 1] = SD_ROW .. ": " .. (sd_on() and "On" or "Off") end
  t[#t + 1] = ui.confirm and RESET_CONFIRM or RESET_ROW
  return t
end

local function refresh_settings()
  local C = wada.ui.colors
  local t = settings_rows()
  local cols = {}
  for i = 1, #t do cols[i] = C.text end
  if ui.confirm then cols[#t] = C.bad or C.accent end
  patch(t, cols, function(i) return ui.acts[i] end)
end

-- Reset asks twice: the first press turns the row into a confirmation that
-- lapses after CONFIRM_MS, the second (within that time) resets.
local function press_reset()
  if ui.confirm and now() < ui.confirm then
    ui.confirm = nil
    reset()
    show_list()
    return
  end
  ui.confirm = now() + CONFIRM_MS
  refresh_settings()
end

function show_settings()
  new_screen("settings")
  local U, C, M = wada.ui, wada.ui.colors, ui.M
  ui.confirm = nil
  local _, _, _, y = top_bar({ "Back", function() show_list() end }, "Settings", 14, C.text, nil)
  local acts = { function() setup() end, function() setup(true) end }
  if ui.sd then
    acts[#acts + 1] = function()
      wada.store.set("sd", sd_on() and "0" or "1")   -- off stops writing; the files stay
      hist_config()
      refresh_settings()
    end
  end
  acts[#acts + 1] = press_reset
  ui.acts = acts
  local W, H = ui.W, ui.H
  local desc_h = ui.sd and (U.text_lines(SD_DESC, W - 2 * M, 12) * ui.th12 + M) or 0
  local lh = math.min(#acts * ui.ROWH + 4, H - y - M - desc_h)
  ui.list = U.list(M, y, W - 2 * M, math.max(lh, ui.ROWH))
  refresh_settings()
  if ui.sd then
    U.label(SD_DESC, M, y + math.max(lh, ui.ROWH) + M, 12, C.sub):width(W - 2 * M)
  end
end

-- ---------------------------------------------------------------- app
function app.on_open(w, h)
  S.cmids, S.failed, S.prompting = {}, {}, false
  load_outbox()
  metrics(w, h)
  local caps = wada.sys.caps and wada.sys.caps() or {}
  ui.sd = (caps.sd and caps.sdk_ext) and true or false
  H.allowed = ui.sd
  hist_config()
  local configured = load_config()
  if not configured then S.state = "setup" end
  show_list()
  if not configured then setup() end
  wada.timer.every(250)
end

function app.on_tick()
  step()
  local scr = ui.screen
  if scr == "list" then
    if list_mode() ~= ui.mode then return show_list() end
    local s = status_text()
    if s ~= ui.shown then
      if fit_lines(s, ui.status_w, 12) ~= ui.status_lines then return show_list() end
      ui.shown = s
      ui.status:set(fit_text(s, ui.status_w, 12))
      ui.status:color(status_color())
    end
    if ui.list and S.rev ~= ui.rev then
      ui.rev = S.rev
      refresh_list()
    end
  elseif scr == "chat" then
    if S.rev ~= ui.rev then refresh_chat() end
  elseif scr == "settings" then
    if S.state == "deriving" then return show_list() end   -- new keys: watch them come up
    if ui.confirm and now() >= ui.confirm then
      ui.confirm = nil
      refresh_settings()
    end
  end
end

function app.on_close()
  S.gen = S.gen + 1
end

-- internal, for scripts/lua-harness; also the data API for the screens
app._t = {
  kdf_new = kdf_new, kdf_step = kdf_step,
  seal = seal, open = open, nonce = nonce,
  esc = esc, unesc = unesc, cut_utf8 = cut_utf8, fields = fields,
  build_request = build_request, parse_reply = parse_reply,
  setup = setup, reset = reset, send = send,
  convs = convs, msgs = msgs, pending = pending, mark_read = mark_read,
  state = function() return S.state end,
  header = header,
  rev = function() return S.rev end,
  -- SD history: { on, dead, drops, pending = {conv -> buffered bytes} }
  sd_stats = function()
    local p = {}
    for id, c in pairs(H.c) do p[id] = c.bytes end
    return { on = H.on, dead = H.dead, drops = H.drops, pending = p }
  end,
}

return app
