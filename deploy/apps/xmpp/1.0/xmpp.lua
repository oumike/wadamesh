-- XMPP chat through a wadamesh relay (scripts/xmpp-relay).
-- Protocol: docs/superpowers/specs/2026-10-16-xmpp-app-design.md, section 2.
-- Sections: seal, codec, sync (setup, poll loop, outbox), app callbacks.
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
  online = "Online",
  unreachable = "Relay unreachable",
  xmpp_offline = "Relay offline from XMPP",
  denied = "Passphrase rejected — check Settings",
}
local CORRUPTED = "Relay reply corrupted"
local POLLING = { online = true, unreachable = true, xmpp_offline = true }

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
  clear_view()
  S.state = "online"
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

-- Prompts "Relay URL" then "Passphrase". Cancel at either step changes nothing.
local function setup()
  if S.prompting then return end
  S.prompting = true
  wada.ui.input("Relay URL", sget("url") or "http://", function(u)
    if not u then S.prompting = false; return end
    u = u:match("^%s*(.-)%s*$")
    if ssub(u, -1) == "/" then u = ssub(u, 1, -2) end
    if not u:match("^http://[^%s/][^%s]*$") or #u > URL_MAX then
      S.prompting = false
      wada.sys.toast(#u > URL_MAX and "Relay URL too long" or "Relay URL must look like http://host:port")
      return
    end
    wada.ui.input("Passphrase", "", function(pw)
      S.prompting = false
      if not pw or pw == "" then return end
      S.gen = S.gen + 1          -- stop the old session; its in-flight reply is ignored
      S.kdf, S.kdf_url = kdf_new(pw), u
      S.state = "deriving"
      changed()
    end)
  end)
end

-- Forget keys, cursor and pending sends; the next setup makes a new sid.
local function reset()
  for _, k in ipairs({ "url", "ek", "mk", "sid", "qb", "out" }) do wada.store.set(k, "") end
  S.gen = S.gen + 1
  S.kdf, S.url, S.ek, S.mk, S.sid = nil, nil, nil, nil, nil
  S.outbox, S.failed, S.reads = {}, {}, {}
  clear_view()
  S.state = "setup"
  changed()
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
      t[#t + 1] = { seq = m.seq, ts = m.ts, sender = m.sender, text = m.text }
      if #t > MAX_MSGS then table.remove(t, 1) end
      cv.seq, cv.act = m.seq, m.seq
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
  S.state = r.offline and "xmpp_offline" or "online"
  apply_acks(r.acks)
  for _, rd in ipairs(req.reads) do
    local s = S.reads[rd.conv]
    if s and s <= rd.seq then S.reads[rd.conv] = nil end
  end
  if req.cursor > 0 and r.cursor < req.cursor then
    clear_view()           -- relay database lost or replaced: resync from 0 now
    S.reads = {}           -- their seqs belong to the lost revision
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

-- conversation tables {id, kind, jid, name, presence, unread}: unread first, then latest
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

-- ---------------------------------------------------------------- app
-- Minimal screen: a status line and, until set up, a setup button. The list,
-- chat and settings screens are built on the app._t data API below.
local ui = {}

local function status_text()
  return header() or (S.state == "deriving" and "Deriving keys…" or "Not set up")
end

function app.on_open(w, h)
  S.cmids, S.failed, S.prompting = {}, {}, false
  load_outbox()
  ui.status = wada.ui.label(status_text(), 6, 4, 14, wada.ui.colors.text)
  ui.shown = status_text()
  if not load_config() then
    S.state = "setup"
    ui.setup = wada.ui.button("Set up relay", 6, 28, 140, 32, setup)
    setup()
  end
  wada.timer.every(250)
end

function app.on_tick()
  step()
  local s = status_text()
  if s ~= ui.shown then
    ui.shown = s
    ui.status:set(s)
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
}

return app
