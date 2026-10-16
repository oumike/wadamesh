-- Mock of the wada.* host (mirrors LuaAppHost.cpp argument checks) + scenarios.
local debug, io, loadfile, print, error, assert, pcall, type, tostring, string, math, table, ipairs, pairs =
      debug, io, loadfile, print, error, assert, pcall, type, tostring, string, math, table, ipairs, pairs
local APP_PATH, SCENARIO = APP_PATH, SCENARIO
local host_sha256, host_hmac_sha256 = __host_sha256, __host_hmac_sha256

local BUDGET, INIT_BUDGET = 100000, 500000
local clock_ms = 1000
local toasts, fails, maxinstr = {}, 0, 0
local net_log = {}   -- http_post request log: { {url, body, ctype}, ... }
local net_pending, input_pending   -- queued async results, delivered on the next tick
local rng_state = 1
local dm_sent = {}   -- send_dm call log: { {to, text}, ... }
local function checkint(v, what) assert(math.tointeger(v) ~= nil, what .. ": not an integer: " .. tostring(v)) end
local function checkcol(v, what) if v ~= nil then checkint(v, what .. " color") end end
local function checkstr(v, what) assert(type(v) == "string" or type(v) == "number", what .. ": not a string") end

local function valid_utf8(text)
  local i, n = 1, #text
  while i <= n do
    local first = text:byte(i)
    local width = first <= 0x7F and 1
      or (first >= 0xC2 and first <= 0xDF and 2)
      or (first >= 0xE0 and first <= 0xEF and 3)
      or (first >= 0xF0 and first <= 0xF4 and 4) or 0
    if width == 0 or i + width - 1 > n then return false end
    for j = 2, width do
      local byte = text:byte(i + j - 1)
      if byte < 0x80 or byte > 0xBF then return false end
    end
    local second = width > 1 and text:byte(i + 1) or 0
    if (first == 0xE0 and second < 0xA0) or (first == 0xED and second > 0x9F) or
       (first == 0xF0 and second < 0x90) or (first == 0xF4 and second > 0x8F) then return false end
    i = i + width
  end
  return true
end

-- instruction budget like guardedCall(): error() out of the hook, pcall catches
local function guarded(budget, fn, ...)
  local count = 0
  debug.sethook(function() count = count + budget; error("instruction budget exceeded (app tick too long)", 0) end, "", budget)
  local t0 = os and os.clock() or 0
  local ok, err = pcall(fn, ...)
  debug.sethook()
  if not ok then fails = fails + 1; print("  APP ERROR: " .. tostring(err)) end
  return ok
end

-- ---- mock wada ----------------------------------------------------------
local cfg = {}           -- per-scenario device config
local widgets = { canvases = 0, labels = 0, buttons = 0, scroll = false, timer_ms = nil }
local drawlog = { text = {}, circles = {}, ops = 0 }
local storekv = {}
local audio_state = { state = "stopped", path = "", source = "", format = "", error = nil }
local audio_log = {}

local function audio_host_close()
  audio_state.state = "stopped"
  audio_log[#audio_log + 1] = "release"
end

local function mkcanvas(w, h)
  checkint(w, "canvas w"); checkint(h, "canvas h")
  assert(w > 0 and w <= 480 and h > 0 and h <= 480, "canvas size 1..480")
  widgets.canvases = widgets.canvases + 1
  local c = { w = w, h = h }
  function c:fill(col) checkcol(col, "fill"); drawlog.ops = drawlog.ops + 1 end
  function c:rect(x, y, rw, rh, col, filled, radius)
    checkint(x, "rect x"); checkint(y, "rect y"); checkint(rw, "rect w"); checkint(rh, "rect h"); checkcol(col, "rect")
    drawlog.ops = drawlog.ops + 1 end
  function c:line(x1, y1, x2, y2, col, width)
    checkint(x1, "line x1"); checkint(y1, "line y1"); checkint(x2, "line x2"); checkint(y2, "line y2"); checkcol(col, "line")
    if width ~= nil then checkint(width, "line width") end
    drawlog.ops = drawlog.ops + 1 end
  function c:circle(x, y, r, col, filled, sw)
    checkint(x, "circle x"); checkint(y, "circle y"); checkint(r, "circle r"); checkcol(col, "circle")
    if sw ~= nil then checkint(sw, "circle stroke") end
    drawlog.circles[#drawlog.circles + 1] = { x = x, y = y, r = r, col = col, filled = filled }
    drawlog.ops = drawlog.ops + 1 end
  function c:text(x, y, s, col, size)
    checkint(x, "text x"); checkint(y, "text y"); checkstr(s, "text"); checkcol(col, "text")
    if size ~= nil then checkint(size, "text size") end
    drawlog.text[#drawlog.text + 1] = tostring(s); drawlog.ops = drawlog.ops + 1 end
  function c:pos(x, y) checkint(x, "canvas pos x"); checkint(y, "canvas pos y"); c.x, c.y = x, y end
  return c
end

local labels = {}
local function mklabel(text, x, y, size, col)
  checkstr(text, "label text"); if x then checkint(x, "label x") end; if y then checkint(y, "label y") end
  if size then checkint(size, "label size") end; checkcol(col, "label")
  widgets.labels = widgets.labels + 1
  widgets.seq = (widgets.seq or 0) + 1
  local l = { text = tostring(text), x = x, y = y, size = size, seq = widgets.seq }
  function l:set(s) checkstr(s, "label:set"); l.text = tostring(s) end
  function l:pos(px, py) checkint(px, "label:pos"); checkint(py, "label:pos") end
  function l:color(c) checkcol(c, "label:color") end
  function l:width(w) checkint(w, "label:width"); l.w = w end
  labels[#labels + 1] = l
  return l
end

local buttons = {}
local function mkbutton(text, x, y, w, h, fn)
  checkstr(text, "button text"); checkint(x, "button x"); checkint(y, "button y")
  if w then checkint(w, "button w") end; if h then checkint(h, "button h") end
  widgets.buttons = widgets.buttons + 1
  local b = mklabel(text, x, y, 14, nil); b.fn = fn; b.is_button = true; b.bw, b.bh = w, h
  buttons[#buttons + 1] = b
  return b
end

-- wada.ui.list: rows with optional callbacks, same argument checks as uiList/lsAdd
local lists = {}
local function mklist(x, y, w, h)
  checkint(x, "list x"); checkint(y, "list y"); checkint(w, "list w"); checkint(h, "list h")
  assert(w > 0 and h > 0, "list: width and height must be positive")
  widgets.seq = (widgets.seq or 0) + 1
  local l = { rows = {}, x = x, y = y, w = w, h = h, seq = widgets.seq }
  -- widgets.listops counts every row change, so a scenario can prove an idle
  -- tick touched nothing
  local function op() widgets.listops = (widgets.listops or 0) + 1 end
  function l:add(text, fn)
    checkstr(text, "list:add text"); assert(fn == nil or type(fn) == "function", "list:add fn")
    op(); l.rows[#l.rows + 1] = { text = tostring(text), fn = fn }; return #l.rows
  end
  function l:set(i, text) checkint(i, "list:set"); checkstr(text, "list:set"); op(); if l.rows[i] then l.rows[i].text = tostring(text) end end
  function l:color(i, c) checkint(i, "list:color"); checkcol(c, "list:color"); op(); if l.rows[i] then l.rows[i].color = c end end
  function l:clear() op(); l.rows = {}; l.sel = nil end
  function l:count() return #l.rows end
  function l:select(i) checkint(i, "list:select"); l.sel = l.rows[i] and i or nil end
  function l:selected() return l.sel end
  function l:pos(px, py) checkint(px, "list:pos"); checkint(py, "list:pos") end
  lists[#lists + 1] = l
  return l
end

-- ---- mock SD card: mirrors wada.sd in LuaAppHost.cpp -------------------------
-- cfg.sdtree is built by mktree(): a dir is { dir = {name -> node}, order = {names} },
-- a file is { data = "bytes" }. Paging, path rules, error strings and the threat
-- policy (SdThreat.h) all follow the firmware, so an app tested here behaves the
-- same on a card.
local SD_PAGE_MAX = 192
local SD_THREAT_EXT = {
  exe = "Windows program", scr = "Windows program", com = "Windows program",
  pif = "Windows program", cpl = "Windows program", msi = "Windows program",
  msp = "Windows program", dll = "Windows program", jar = "Windows program",
  bat = "Windows script", cmd = "Windows script", vbs = "Windows script",
  vbe = "Windows script", js = "Windows script", jse = "Windows script",
  wsf = "Windows script", wsh = "Windows script", hta = "Windows script",
  ps1 = "Windows script", reg = "Windows script", msc = "Windows script",
  lnk = "Windows shortcut", url = "Windows shortcut", scf = "Windows shortcut",
}
local function sd_safe(path)
  if type(path) ~= "string" or path == "" or path:sub(1, 1) ~= "/" or #path >= 192 then return false end
  if #path > 1 and path:sub(-1) == "/" then return false end
  if path:find("[\0-\31\127\\]") or path:find("//", 1, true) then return false end
  for seg in path:gmatch("[^/]+") do if seg == "." or seg == ".." then return false end end
  return true
end
local function sd_node(path)
  local node = cfg.sdtree or { dir = {}, order = {} }
  for seg in path:gmatch("[^/]+") do
    if not node.dir then return nil end
    node = node.dir[seg]
    if not node then return nil end
  end
  return node
end
local function sd_classify(path, node)
  local name = path:match("[^/]+$")
  if name:lower() == "autorun.inf" then return "autorun file" end
  local e = name:match("%.([^.]+)$")
  if e and SD_THREAT_EXT[e:lower()] then return SD_THREAT_EXT[e:lower()] end
  local d = node.data
  if #d >= 64 and d:sub(1, 2) == "MZ" then
    local off = d:byte(0x3D) | (d:byte(0x3E) << 8) | (d:byte(0x3F) << 16) | (d:byte(0x40) << 24)
    if off >= 64 and off <= 65536 and off <= #d - 4 and d:sub(off + 1, off + 4) == "PE\0\0" then
      return "renamed Windows program"
    end
  end
  return nil
end
local function sd_file(path)
  if not sd_safe(path) or path == "/" then return nil, "bad path" end
  if cfg.sd_nocard then return nil, "no sd" end
  local node = sd_node(path)
  if not node then return nil, "not found" end
  if node.dir then return nil, "not a file" end
  return node
end
local function sdmock_list(path, start, max)
  if path == nil then path = "/" end
  checkstr(path, "sd.list path")
  start = start or 1; checkint(start, "sd.list start")
  assert(start >= 1, "sd.list: start must be 1 or more")
  max = max or SD_PAGE_MAX; checkint(max, "sd.list max")
  assert(max >= 1 and max <= SD_PAGE_MAX, "sd.list: max must be 1..192")
  if not sd_safe(path) then return nil, "bad path" end
  if cfg.sd_nocard then return nil, "no sd" end
  local node = sd_node(path)
  if not node then return nil, "not found" end
  if not node.dir then return nil, "not a directory" end
  cfg.sd_calls = cfg.sd_calls or {}
  cfg.sd_calls[#cfg.sd_calls + 1] = { path = path, start = start, max = max }
  local out, count, i = {}, 0, start
  while node.order[i] do
    if count >= max then out.truncated = true; out.next = start + count; break end
    local name = node.order[i]
    local child = node.dir[name]
    count = count + 1
    out[count] = { name = name, type = child.dir and "dir" or "file",
                   size = child.data and #child.data or 0, mtime = 0 }
    i = i + 1
  end
  return out
end
local function sdmock_check(path)
  checkstr(path, "sd.check path")
  local node, err = sd_file(path)
  if not node then return nil, err end
  return sd_classify(path, node) or false
end
local function sdmock_remove(path)
  checkstr(path, "sd.remove path")
  local node, err = sd_file(path)
  if not node then return nil, err end
  local why = sd_classify(path, node)
  if not why then return nil, "not a threat" end
  if cfg.sd_remove_fail and cfg.sd_remove_fail[path] then return nil, cfg.sd_remove_fail[path] end
  local parent = sd_node(path:match("^(.*)/[^/]+$") ~= "" and path:match("^(.*)/[^/]+$") or "/")
  local name = path:match("[^/]+$")
  parent.dir[name] = nil
  for i, n in ipairs(parent.order) do if n == name then table.remove(parent.order, i); break end end
  cfg.sd_removed = cfg.sd_removed or {}
  cfg.sd_removed[#cfg.sd_removed + 1] = path
  return why
end

-- Build a card from { ["/path/file"] = "bytes" | true (an empty folder) }.
local function mktree(files)
  local root = { dir = {}, order = {} }
  local paths = {}
  for path in pairs(files) do paths[#paths + 1] = path end
  table.sort(paths)
  for _, path in ipairs(paths) do
    local node, segs = root, {}
    for seg in path:gmatch("[^/]+") do segs[#segs + 1] = seg end
    for i, seg in ipairs(segs) do
      if not node.dir[seg] then
        local is_dir = i < #segs or files[path] == true
        node.dir[seg] = is_dir and { dir = {}, order = {} } or { data = files[path] }
        node.order[#node.order + 1] = seg
      end
      node = node.dir[seg]
    end
  end
  return root
end
local function sd_exists(path) return sd_node(path) ~= nil end

local function build_wada()
  local wada = { ui = {}, sys = {}, mesh = {}, store = {}, timer = {}, net = {}, fs = {} }
  wada.ui.colors = { accent = 0x15B6A6, text = 0xE6E9ED, sub = 0x7A7F87, bg = 0x000000, panel = 0x15181B, bad = 0xD7574E, good = 0x53C06B }
  wada.ui.canvas = mkcanvas
  wada.ui.label = mklabel
  wada.ui.button = mkbutton
  wada.ui.scroll = function(on) widgets.scroll = (on == nil) or on end
  wada.ui.text_h = function(sz) return (sz or 12) + 4 end
  -- upstream's exact measurement: ~0.48 of the line height per character
  wada.ui.text_w = function(str, sz)
    local n = 0
    for _ in str:gmatch('[%z\1-\127\194-\244]') do n = n + 1 end
    return math.floor(n * ((sz or 12) + 4) * 0.48)
  end
  wada.ui.chart = function() error("chart not mocked") end
  wada.ui.list = mklist
  wada.ui.clear = function() labels, buttons, lists = {}, {}, {}; widgets.cleared = (widgets.cleared or 0) + 1 end
  wada.ui.text_lines = function(str, width, sz)
    checkstr(str, "text_lines"); checkint(width, "text_lines width")
    if width <= 0 then return 1 end
    local lines = 0
    for part in (tostring(str) .. "\n"):gmatch("(.-)\n") do
      local w = wada.ui.text_w(part, sz or 14)
      lines = lines + math.max(1, (w + width - 1) // width)
    end
    return lines
  end

  wada.sys.millis = function() return clock_ms end
  wada.sys.keep_awake = function(on) cfg.awake = (on == nil) or on end
  wada.sys.toast = function(msg, ms) checkstr(msg, "toast"); toasts[#toasts + 1] = tostring(msg) end
  wada.sys.board = function() return { w = cfg.w, h = cfg.h, touch = cfg.caps.touch } end
  -- No-arg random() is esp_random(): successive 32-bit values (seeded LCG so
  -- scenarios are deterministic). Ranged calls keep the old constant mock.
  wada.sys.random = function(lo, hi)
    if lo == nil and hi == nil then
      rng_state = (rng_state * 1664525 + 1013904223) & 0xFFFFFFFF
      return (rng_state ~ (rng_state >> 15)) & 0xFFFFFFFF   -- wraps negative under LUA_32BITS
    end
    lo = lo or 0; hi = hi or 0; if hi <= lo then return 12345 end return lo end
  wada.sys.epoch = function() return nil end
  wada.sys.datetime = function() return nil end
  wada.sys.beep = function() return false end
  wada.sys.caps = function() return { sdk_ext = cfg.caps.sdk_ext, keyboard = cfg.caps.keyboard,
                                       touch = cfg.caps.touch, sd = true, compass = cfg.caps.compass,
                                       accel = cfg.caps.accel, discover = cfg.caps.discover,
                                       sd_list = cfg.caps.sd_list or false,
                                       sd_clean = cfg.caps.sd_clean or false,
                                       audio = cfg.caps.audio or false,
                                       audio_wav = cfg.caps.audio or false,
                                       audio_mp3 = cfg.caps.audio or false,
                                       audio_sd = cfg.caps.audio_sd or false } end
  if cfg.caps.sdk_ext then
    wada.sys.battery = function() return { mv = 3900, pct = 70, charging = false } end
    wada.sys.gps = function() return cfg.gps and cfg.gps() or nil end
  end
  if cfg.caps.compass then
    wada.sys.compass = function() return cfg.compass and cfg.compass() or nil end
  end
  if cfg.caps.accel then
    wada.sys.accel = function() return cfg.accel and cfg.accel() or { x = 0, y = 0, z = 1 } end
  end

  -- wada.crypto: binary strings in and out, as LuaAppHost.cpp's cryptoDigest
  wada.crypto = {
    sha256 = function(m) checkstr(m, "sha256"); return host_sha256(tostring(m)) end,
    hmac_sha256 = function(k, m)
      checkstr(k, "hmac_sha256 key"); checkstr(m, "hmac_sha256 msg")
      return host_hmac_sha256(tostring(k), tostring(m)) end,
    hex = function(s) checkstr(s, "hex"); return (tostring(s):gsub(".", function(ch) return string.format("%02x", ch:byte()) end)) end,
  }

  -- wada.net.http_post(url, body [, ctype], cb [, max_reply]): same checks and
  -- single-in-flight rule as netHttpPost (which raises, not returns false). The
  -- reply comes from cfg.relay(url, body) -> status, reply on a LATER tick;
  -- device collapses any 2xx to 200 + body and everything else to -1, nil.
  wada.net.http_post = function(url, body, a3, a4, a5)
    checkstr(url, "http_post url"); checkstr(body, "http_post body")
    local ctype, cb, maxr = "application/octet-stream", a3, a4
    if type(a3) == "string" then ctype, cb, maxr = a3, a4, a5 else maxr = a4 end
    assert(type(cb) == "function", "http_post: callback must be a function")
    if maxr ~= nil then checkint(maxr, "http_post max_reply") end
    assert(url:sub(1, 7) == "http://", "http:// urls only")
    assert(#url < 160, "url too long")   -- s_net_url[160]
    assert(#body > 0 and #body <= 64 * 1024, "bad body length")
    assert(not net_pending, "a fetch is already running")
    net_log[#net_log + 1] = { url = url, body = body, ctype = ctype }
    net_pending = { url = url, body = body, cb = cb }
    return nil
  end

  -- wada.ui.input(title, initial, cb): exactly one cb(text | nil), answered from
  -- cfg.inputs (a queue; false or an empty queue = cancel, since nil cannot sit
  -- in a Lua array).
  wada.ui.input = function(title, initial, cb)
    if title ~= nil then checkstr(title, "input title") end
    if initial ~= nil then checkstr(initial, "input initial") end
    assert(type(cb) == "function", "input: callback must be a function")
    assert(not input_pending, "an input prompt is already open")
    input_pending = { title = title or "", initial = initial or "", cb = cb }
  end

  wada.mesh.contacts = function() return cfg.contacts or {} end
  wada.mesh.self = function() return { name = "me", lat = cfg.self_lat or 0, lon = cfg.self_lon or 0 } end
  wada.mesh.stats = function() return {} end
  wada.mesh.rx_log = function() return {} end
  wada.mesh.discover = function() return "probe-1" end
  wada.mesh.discovered = function() return cfg.discovered or {} end
  wada.mesh.discover_clear = function() cfg.discovered = {} end
  wada.mesh.send_dm = function(name, text)
    checkstr(name, "send_dm name"); checkstr(text, "send_dm text")
    dm_sent[#dm_sent + 1] = { to = name, text = text }
    return true
  end

  do
    local R = 6371000.0
    local function hav(a) local s = math.sin(a / 2); return s * s end
    local function geo_dist(la1, lo1, la2, lo2)
      local p1, p2 = math.rad(la1), math.rad(la2)
      local dp, dl = math.rad(la2 - la1), math.rad(lo2 - lo1)
      local a = hav(dp) + math.cos(p1) * math.cos(p2) * hav(dl)
      return R * 2 * math.atan(math.sqrt(a), math.sqrt(1 - a))
    end
    local function geo_bear(la1, lo1, la2, lo2)
      local p1, p2 = math.rad(la1), math.rad(la2)
      local dl = math.rad(lo2 - lo1)
      local y = math.sin(dl) * math.cos(p2)
      local x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
      return (math.deg(math.atan(y, x)) + 360) % 360
    end
    local CARDS = {"N","NE","E","SE","S","SW","W","NW"}
    wada.geo = {
      distance = geo_dist,
      bearing  = geo_bear,
      cardinal = function(d) return CARDS[math.floor((d + 22.5) / 45) % 8 + 1] end,
    }
  end

  -- wada.fs: a real in-memory filesystem, not a set of no-ops. append used to
  -- throw the data away and read/write/list were missing outright, so any app
  -- that wrote a file and read it back failed here while working perfectly on
  -- device. That is what made wardrive 1.2 look like it had regressed the
  -- emoji fix: it errored on a nil fs.read at the first flush, long before
  -- anything was rendered, and the scenario reported the unrendered label.
  -- Semantics follow LuaAppHost.cpp: read returns data plus the file's TOTAL
  -- size so a caller can window a growing log, an offset at or past the end is
  -- an empty string rather than nil, and a missing file is nil.
  fsfiles = {}
  wada.fs.write = function(name, data)
    checkstr(name, "fs.write name"); checkstr(data, "fs.write data")
    fsfiles[name] = data; return true
  end
  wada.fs.append = function(name, data)
    checkstr(name, "fs.append name"); checkstr(data, "fs.append data")
    fsfiles[name] = (fsfiles[name] or "") .. data; return true
  end
  wada.fs.read = function(name, off, want)
    checkstr(name, "fs.read name")
    local d = fsfiles[name]
    if d == nil then return nil end
    off = off or 0
    if off < 0 then return nil end
    local total = #d
    if off >= total then return "", total end
    want = want or (total - off)
    if want < 0 then return nil end
    return d:sub(off + 1, off + want), total
  end
  wada.fs.list = function()
    local out, names = {}, {}
    for n in pairs(fsfiles) do names[#names + 1] = n end
    table.sort(names)   -- deterministic: a hash order would make tests flaky
    for _, n in ipairs(names) do out[#out + 1] = { name = n, size = #fsfiles[n] } end
    return out
  end
  wada.fs.remove = function(name)
    checkstr(name, "fs.remove name")
    local had = fsfiles[name] ~= nil
    fsfiles[name] = nil
    return had
  end

  wada.store.get = function(k, d) assert(type(k) == "string"); local v = storekv[k]; if v == nil then return d end return v end
  wada.store.set = function(k, v) assert(type(k) == "string", "store key must be a string")
    assert(v == nil or type(v) == "string" or type(v) == "number", "store values must be strings or numbers")
    storekv[k] = v end

  wada.timer.every = function(ms) checkint(ms, "timer.every"); if ms < 33 then ms = 33 end; widgets.timer_ms = ms end
  wada.timer.stop = function() widgets.timer_ms = nil end

  if cfg.caps.audio then
    wada.audio = {}
    wada.audio.play = function(path)
      assert(type(path) == "string", "audio.play path must be a string")
      local source = "app"
      if path:sub(1, 3) == "sd:" then
        if not cfg.caps.audio_sd then return nil, "no sd" end
        local card_path = path:sub(4)
        if card_path:sub(1, 1) ~= "/" or card_path:find("//", 1, true) or
           card_path:find("/../", 1, true) or card_path:sub(-3) == "/.." or
           card_path:sub(-2) == "/." or card_path:sub(-1) == "/" then
          return nil, "bad path"
        end
        source = "sd"
      elseif #path == 0 or #path > 32 or path:sub(1, 1) == "." or
             not path:match("^[A-Za-z0-9._-]+$") then
        return nil, "bad path"
      end
      local format = path:lower():sub(-4)
      if format ~= ".wav" and format ~= ".mp3" then return nil, "unsupported format" end
      audio_state = { state = "playing", path = path, source = source,
              format = format:sub(2), error = nil }
      audio_log[#audio_log + 1] = "play:" .. path
      return true
    end
    wada.audio.pause = function()
      if audio_state.state ~= "playing" then return false end
      audio_state.state = "paused"; audio_log[#audio_log + 1] = "pause"; return true
    end
    wada.audio.resume = function()
      if audio_state.state ~= "paused" then return false end
      audio_state.state = "playing"; audio_log[#audio_log + 1] = "resume"; return true
    end
    wada.audio.stop = function()
      if audio_state.state ~= "playing" and audio_state.state ~= "paused" then return false end
      audio_state.state = "stopped"; audio_log[#audio_log + 1] = "stop"; return true
    end
    wada.audio.status = function()
      local out = {}
      for key, value in pairs(audio_state) do out[key] = value end
      return out
    end
  end
  if cfg.caps.sd_list then
    wada.sd = { list = sdmock_list }
    if cfg.caps.sd_clean then wada.sd.check = sdmock_check; wada.sd.remove = sdmock_remove end
  end
  return wada
end

-- ---- scenario driver -------------------------------------------------------------
local function load_app()
  local chunk, err = loadfile(APP_PATH)
  assert(chunk, err)
  local app
  assert(guarded(INIT_BUDGET, function() app = chunk() end), "chunk failed")
  assert(type(app) == "table", "app did not return a table")
  return app
end

local function send(app, ev) if app.on_input then guarded(BUDGET, app.on_input, ev) end end
local function tick(app, n, dt)
  for _ = 1, (n or 1) do clock_ms = clock_ms + (dt or 150)
    if net_pending then
      local p = net_pending; net_pending = nil
      local st, reply = -1, nil
      if cfg.relay then
        local s2, r2 = cfg.relay(p.url, p.body)
        if type(s2) == "number" and s2 >= 200 and s2 < 300 then st, reply = 200, r2 end
      end
      guarded(BUDGET, p.cb, st, reply)
    end
    if input_pending then
      local p = input_pending; input_pending = nil
      local v = cfg.inputs and table.remove(cfg.inputs, 1)
      if v == false then v = nil end
      guarded(BUDGET, p.cb, v)
    end
    if app.on_tick then guarded(BUDGET, app.on_tick, dt or 150) end end
end
local function key(app, k, code) send(app, { type = "key", key = k, code = code or (k and k:byte()) or 0 }) end
local function swipe(app, dir) send(app, { type = "swipe", dir = dir, x = 0, y = 0 }) end
local function tap(app, x, y) send(app, { type = "down", x = x, y = y }); send(app, { type = "up", x = x, y = y }) end
local function drag(app, x, y, x2, y2, dir) send(app, { type = "down", x = x, y = y }); send(app, { type = "swipe", dir = dir, x = 0, y = 0 }); send(app, { type = "up", x = x2, y = y2 }) end
local function enter(app, w, h) tap(app, w // 2, h // 2); key(app, "enter", 13) end

local function label_dump()
  local out = {}
  for _, l in ipairs(labels) do if l.text ~= "" then out[#out + 1] = l.text end end
  return table.concat(out, " | ")
end

local function reset_world()
  widgets = { canvases = 0, labels = 0, buttons = 0, scroll = false, timer_ms = nil }
  labels, buttons, toasts, drawlog = {}, {}, {}, { text = {}, circles = {}, ops = 0 }
  lists = {}
  clock_ms = 1000
  dm_sent = {}
  net_log, net_pending, input_pending, rng_state = {}, nil, nil, 1
  audio_state = { state = "stopped", path = "", source = "", format = "", error = nil }
  dm_sent = {}
  audio_log = {}
end

-- simulated magnetometer: Earth field 0.45 G at true heading `deg` (device frame ==
-- sensor frame, orient 0), plus a hard-iron bias; tilt ignored.
local BIAS = { x = 1.5, y = -0.8, z = 0.3 }
-- the real M9's accelerometer reads ~0.08 g high on Y lying flat: about 5
-- degrees of tilt that is not there
local ABIAS = { x = -0.02, y = 0.08, z = -0.01 }
-- Physical simulation of the M9 in a known attitude, in the MEASURED frames:
--   body/accel: +X top edge (forward), +Y right edge, +Z into the screen (down)
--   magnetometer: +Y forward, +X left, +Z down  ->  raw = (-by, bx, bz) + bias
-- Field: San Francisco-like, 0.24 G horizontal north, 0.42 G down (dip ~60).
-- The accelerometer reads specific force, so the skyward axis reads +1 and the
-- level device reads z = -1, exactly as the real one was measured to.
local BH, BV = 0.24, 0.42
local function attitude(hdg, roll, pitch)
  local h, r, p = math.rad(hdg), math.rad(roll or 0), math.rad(pitch or 0)
  -- earth (north, east, down) -> body, ZYX yaw-pitch-roll
  local function e2b(n, e, d)
    local x1 =  n * math.cos(h) + e * math.sin(h)      -- yaw
    local y1 = -n * math.sin(h) + e * math.cos(h)
    local z1 =  d
    local x2 =  x1 * math.cos(p) - z1 * math.sin(p)    -- pitch
    local y2 =  y1
    local z2 =  x1 * math.sin(p) + z1 * math.cos(p)
    local x3 =  x2                                      -- roll
    local y3 =  y2 * math.cos(r) + z2 * math.sin(r)
    local z3 = -y2 * math.sin(r) + z2 * math.cos(r)
    return x3, y3, z3
  end
  local bx, by, bz = e2b(BH, 0, BV)         -- magnetic field in body axes
  local gx, gy, gz = e2b(0, 0, 1)           -- "down" in body axes
  return { x = -by + BIAS.x, y = bx + BIAS.y, z = bz + BIAS.z },   -- magnetometer raw
         { x = -gx + ABIAS.x, y = -gy + ABIAS.y, z = -gz + ABIAS.z }  -- accelerometer raw
end

local contacts_fixture = {
  { name = "Repeater A", type = 2, ago_s = 10, lat = 37.80000, lon = -122.40000 },
  { name = "Bob", type = 1, ago_s = 300, lat = 37.70000, lon = -122.50000 },
  { name = "NoPos", type = 1, ago_s = 5, lat = 0, lon = 0 },
  { name = "Carol", type = 1, ago_s = 60, lat = 38.00000, lon = -122.00000 },
}

local scenarios = {}

scenarios.wardrive_utf8 = function()
  cfg = {
    w = 320, h = 196,
    caps = { sdk_ext = true, keyboard = true, touch = false, compass = false, accel = false, discover = true },
    discovered = {
      { pubkey = "01020304", name = "Ouderkerk☀️", type = 2,
        rssi = -72, snr = 7.25, their_snr = 6.5, hops = 0 }
    }
  }
  cfg.gps = function()
    return { lat = 52.295, lon = 4.907, lat_e6 = 52295000, lon_e6 = 4907000,
             sats = 9, alt_m = 3, time = 1787620000 }
  end
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  assert(buttons[1] and buttons[1].fn, "Wardrive Start button missing")
  assert(guarded(BUDGET, buttons[1].fn))
  tick(app, 1, 100)
  tick(app, 1, 4000)
  local found = false
  for _, label in ipairs(labels) do
    assert(valid_utf8(label.text), "Wardrive rendered invalid UTF-8")
    if label.text:find("Ouderkerk☀", 1, true) then found = true end
  end
  assert(found, "emoji-bearing repeater name was not rendered")
  if app.on_close then guarded(BUDGET, app.on_close) end
end

-- The declination model, as it actually ships. Rather than testing a copy in
-- out/wmm, this pulls the do-block straight out of the app file that gets
-- sideloaded, so an inlining mistake fails here instead of on the device.
-- Reference values are NOAA's own calculator for WMM2025 at epoch 2026.6.
scenarios.declination = function()
  local src = assert(io.open(APP_PATH)):read("a")
  local a = src:find("-- WMM-GEN BEGIN", 1, true)
  assert(a, "the declination module is missing from the app")
  local e = src:find("end -- WMM-GEN END", a, true)
  assert(e, "the generated block is not closed by its END marker")
  local chunk = src:sub(a, e + #"end -- WMM-GEN END") .. "\nreturn declination"
  local declination = assert(load(chunk, "decl"))()

  local REF = {
    {  37.75, -122.45,   12.8470, 22928.0, "harness fixture SF" },
    {  43.66,  -70.26,  -14.4653, 20159.9, "Portland ME" },
    { -33.87,  151.21,   12.8236, 24625.1, "Sydney" },
    {  64.13,  -21.90,  -11.0771, 13242.4, "Reykjavik" },
    { -70.00,  100.00, -103.9366, 12624.7, "Antarctic (steep)" },
    {  82.00, -100.00,  -34.1519,  1905.5, "82N: weak-field zone" },
  }
  local worst = 0
  for _, r in ipairs(REF) do
    local lat, lon, want_d, want_h, name = r[1], r[2], r[3], r[4], r[5]
    local got_d, got_h = declination(lat, lon, 2026.6)
    local err = math.abs(((got_d - want_d + 540) % 360) - 180)
    if err > worst then worst = err end
    print(string.format("  %-22s %9.4f vs %9.4f  (%.4f)  H=%.0f nT", name, got_d, want_d, err, got_h))
    assert(err < 0.02, "declination wrong at " .. name)
    assert(math.abs(got_h - want_h) < 30, "horizontal field wrong at " .. name)
  end
  print(string.format("  worst error vs NOAA: %.4f deg", worst))
  -- the secular variation has to be live, or this is a frozen 2025 snapshot
  local d25 = declination(43.66, -70.26, 2025.0)
  local d30 = declination(43.66, -70.26, 2030.0)
  assert(math.abs(d30 - d25) > 0.2,
         string.format("secular variation is not applied (%.3f -> %.3f)", d25, d30))
  print(string.format("  Portland ME drifts %+.2f deg across the model's 5 years", d30 - d25))
end

-- Pressing A means "this direction is TRUE north". With no fix the app has no
-- declination to work with, so the offset it stores quietly contains one; if
-- the model then added its own the heading would be wrong by twice the
-- declination -- the very error that sent every marker 22 deg west, but on the
-- dial instead. The offset has to give the declination back when the fix lands.
scenarios.align_nofix = function()
  local FIX_DECL = 12.847
  -- no self position either: on a real node the stored one is usually enough to
  -- get a declination before GPS locks, so being truly blind takes both gone
  cfg = { w = 320, h = 196, caps = { sdk_ext = true, keyboard = true, touch = false, compass = true, accel = true },
          contacts = contacts_fixture }
  local true_heading, true_roll, true_pitch = 0, 0, 0
  cfg.compass = function() return (attitude(true_heading, true_roll, true_pitch)) end
  cfg.accel = function() local _, a = attitude(true_heading, true_roll, true_pitch); return a end
  local have_fix = false
  cfg.gps = function()
    if not have_fix then return nil end
    return { lat = 37.75, lon = -122.45, sats = 9, alt_m = 42 }
  end
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))

  key(app, "c")                  -- calibrate with no fix at all
  for i = 1, 140 do
    true_heading = (i * 360 / 23) % 360
    true_roll    = (i * 360 / 11) % 360
    true_pitch   = ((i * 360 / 17) % 360) - 180
    tick(app, 1, 150)
  end
  true_roll, true_pitch = 0, 0
  assert(storekv.cal_ox, "calibration must still work with no GPS")

  local function shown()
    tick(app, 15)
    return tonumber(drawlog.text[#drawlog.text - 3]:match("^(%d+)$"))
  end

  -- the user believes they are facing true north and says so
  true_heading = 30            -- i.e. magnetic 30; with no model the app cannot know
  tick(app, 15)                -- settle: A reads the live tilt, not the sweep's last
  key(app, "a"); tick(app, 4)
  assert(storekv.align_pd, "an offset set with no declination must be remembered as such")
  assert(toasts[#toasts]:find("magnetic"), "the toast must admit it: " .. tostring(toasts[#toasts]))
  assert(math.abs(((shown() - 0 + 540) % 360) - 180) <= 2, "must read 000 where north was set")
  assert(drawlog.text[#drawlog.text - 1] == "M", "with no model the dial is magnetic")

  -- the fix arrives: the model now knows the declination the offset swallowed
  have_fix = true
  tick(app, 20)
  assert(not storekv.align_pd, "the pending flag must clear once the model has a value")
  assert(math.abs(((shown() - 0 + 540) % 360) - 180) <= 2,
         string.format("the fix must not move a direction the user already fixed (%d)", shown()))
  assert(drawlog.text[#drawlog.text - 1] == "T",
         "the dial must repaint as TRUE the moment the model has a declination")
  print(string.format("  align %d, decl %+.1f: %d before the fix, %d after",
                      storekv.align, FIX_DECL, 0, shown()))

  -- and a quarter turn still counts a quarter turn
  true_heading = 30 + 90
  assert(math.abs(((shown() - 90 + 540) % 360) - 180) <= 3, "a right turn must count UP")
  app.on_close()
end

-- Is a contact MIRRORED rather than merely rotated? A flip and a rotation look
-- identical at one heading, so the existing marker test cannot tell them apart:
-- it checks the dot against the app's OWN bearing, which stays self-consistent
-- even if that bearing has east and west swapped. This checks the bearing
-- against an absolute compass direction instead -- contacts placed due north,
-- east, south, west and north-east of the fixture -- and then checks the dot
-- against it. A longitude sign error puts east at 270; a lat/lon transpose
-- puts north-east at 51.7 instead of 38.3.
scenarios.bearings_absolute = function()
  local ME_LAT, ME_LON = 37.75, -122.45
  local POINTS = {
    { name = "N",  lat = 37.85, lon = -122.45, brg =   0.000 },
    { name = "E",  lat = 37.75, lon = -122.30, brg =  89.954 },
    { name = "S",  lat = 37.65, lon = -122.45, brg = 180.000 },
    { name = "W",  lat = 37.75, lon = -122.60, brg = 270.046 },
    { name = "NE", lat = 37.85, lon = -122.35, brg =  38.284 },
  }
  local marks = {}
  for i, pt in ipairs(POINTS) do
    marks[i] = { name = pt.name, type = 1, ago_s = 10, lat = pt.lat, lon = pt.lon }
  end
  cfg = { w = 320, h = 196, caps = { sdk_ext = true, keyboard = true, touch = false, compass = true, accel = true },
          contacts = marks, self_lat = ME_LAT, self_lon = ME_LON }
  local true_heading, true_roll, true_pitch = 0, 0, 0
  cfg.compass = function() return (attitude(true_heading, true_roll, true_pitch)) end
  cfg.accel = function() local _, a = attitude(true_heading, true_roll, true_pitch); return a end
  cfg.gps = function() return { lat = ME_LAT, lon = ME_LON, sats = 9, alt_m = 42 } end
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))

  key(app, "c")                          -- calibrate so the dial is live
  for i = 1, 140 do
    true_heading = (i * 360 / 23) % 360
    true_roll    = (i * 360 / 11) % 360
    true_pitch   = ((i * 360 / 17) % 360) - 180
    tick(app, 1, 150)
  end
  true_roll, true_pitch = 0, 0
  true_heading = 0
  tick(app, 20)

  local D2 = 144 / 2
  local by_name = {}
  for _, pt in ipairs(POINTS) do by_name[pt.name] = pt end
  local seen = 0
  -- the app picks its own target order (nearest first), so go by the name it
  -- reports rather than assuming the contact list order
  for _ = 1, #POINTS do
    swipe(app, "right"); tick(app, 6)
    local dump = label_dump()
    local shown_name = dump:match("TGT | ([%w]+) |") or dump:match("TGT | ([%w]+)")
    local pt = by_name[shown_name]
    assert(pt, "unexpected target selected: " .. tostring(shown_name))
    by_name[shown_name] = nil; seen = seen + 1
    local brg = tonumber(dump:match("mi%s+(%d%d%d)") or dump:match("km%s+(%d%d%d)")
                         or dump:match("m%s+(%d%d%d)"))
    assert(brg, "could not read a bearing for " .. pt.name .. ": " .. dump:sub(1, 130))
    local err = math.abs(((brg - pt.brg + 540) % 360) - 180)
    -- the drawn dot, as a screen angle clockwise from up
    local dot
    for _, c in ipairs(drawlog.circles) do if c.col == 0xE8A33D and c.filled then dot = c end end
    assert(dot, "no marker drawn for " .. pt.name)
    local ang = math.deg(math.atan(dot.x - D2, -(dot.y - D2))) % 360
    local hdg = tonumber(drawlog.text[#drawlog.text - 3]:match("^(%d+)$"))
    local want_ang = (pt.brg - hdg) % 360
    local aerr = math.abs(((ang - want_ang + 540) % 360) - 180)
    print(string.format("  %-2s (%s): bearing %3d want %6.2f err %4.1f | dot %6.1f want %6.2f err %4.1f",
                        pt.name, tostring(shown_name), brg, pt.brg, err, ang, want_ang, aerr))
    assert(err <= 1.5, string.format("%s reads %d, should be %.1f -- bearings are wrong, not just offset",
                                     pt.name, brg, pt.brg))
    assert(aerr <= 3, string.format("%s is drawn %.1f deg from where its own bearing puts it", pt.name, aerr))
  end
  assert(seen == #POINTS, "every contact must be reachable, saw " .. seen)
  app.on_close()
end

scenarios.m9 = function()
  local FIX_DECL = 12.847   -- WMM2025 at the fixture position, epoch 2026.6
  cfg = { w = 320, h = 196, caps = { sdk_ext = true, keyboard = true, touch = false, compass = true, accel = true },
          contacts = contacts_fixture, self_lat = 37.75, self_lon = -122.45 }
  local true_heading, true_roll, true_pitch = 0, 0, 0
  cfg.compass = function() return (attitude(true_heading, true_roll, true_pitch)) end
  cfg.accel = function() local _, a = attitude(true_heading, true_roll, true_pitch); return a end
  local moving = false
  cfg.gps = function()
    local g = { lat = 37.75000, lon = -122.45000, sats = 9, alt_m = 42 }
    if moving then g.speed_kmh = 23.4; g.course = 215.0 end
    return g
  end
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  print("  widgets:", "canvases=" .. widgets.canvases, "labels=" .. widgets.labels, "buttons=" .. widgets.buttons,
        "timer=" .. tostring(widgets.timer_ms))
  assert(widgets.timer_ms and widgets.timer_ms >= 33)
  tick(app, 10)
  print("  uncal:", label_dump())
  -- calibration: press C, rotate through 360 over 20 s, auto-finish
  key(app, "c")
  assert(cfg.awake == true, "calibration must hold the screen awake")
  for i = 1, 140 do
    true_heading = (i * 360 / 23) % 360    -- rotated every way, in one place
    true_roll    = (i * 360 / 11) % 360
    true_pitch   = ((i * 360 / 17) % 360) - 180
    tick(app, 1, 150)
  end
  true_roll, true_pitch = 0, 0
  assert(cfg.awake == false, "the hold must be released when calibration ends")
  assert(storekv.cal_ox, "calibration did not persist; last toast: " .. tostring(toasts[#toasts]))
  print(string.format("  cal offsets: %.3f %.3f r=%.3f (bias %.3f %.3f)", storekv.cal_ox, storekv.cal_oy, storekv.cal_r, BIAS.x, BIAS.y))
  assert(math.abs(storekv.cal_ox - BIAS.x) < 0.02 and math.abs(storekv.cal_oy - BIAS.y) < 0.02
         and math.abs(storekv.cal_oz - BIAS.z) < 0.02, "hard-iron offsets wrong")
  assert(storekv.cal_r and math.abs(storekv.cal_r - 0.484) < 0.02, "fitted field radius wrong: " .. tostring(storekv.cal_r))
  -- Heading accuracy after calibration. The simulated field points at MAGNETIC
  -- north, so a correct app shows magnetic + declination: at the fixture's
  -- position (37.75, -122.45) WMM2025 gives +12.85 deg east for 2026.6, which
  -- is the clock the app falls back to because this harness returns no
  -- datetime. Asserting the offset is present is the regression test for the
  -- fault Chris saw on hardware -- every contact sitting ~22 deg west.
  for _, th in ipairs({ 0, 45, 90, 180, 270, 359 }) do
    true_heading = th; tick(app, 15)
    -- drawn order at the centre: digits, degree sign, T/M reference, cardinal
    local shown = drawlog.text[#drawlog.text - 3]
    local num = tonumber(shown:match("^(%d+)$"))
    assert(num, "expected bare digits at the dial centre, got: " .. tostring(shown))
    assert(drawlog.text[#drawlog.text - 2] == "\194\176", "degree sign must follow the digits")
    assert(drawlog.text[#drawlog.text - 1] == "T",
           "with a fix the heading must be marked true, got: " .. tostring(drawlog.text[#drawlog.text - 1]))
    local want = (th + FIX_DECL) % 360
    local err = math.abs(((num - want + 540) % 360) - 180)
    print(string.format("  mag %3d -> true %6.1f  shown %s (err %.0f)", th, want, shown, err))
    assert(err <= 2, "heading error too large at " .. th)
  end
  -- targets: d-pad right/left arrive as swipes; enter = tap at body centre
  swipe(app, "right"); tick(app, 2); print("  target1:", label_dump())
  swipe(app, "right"); swipe(app, "right"); swipe(app, "right"); tick(app, 2); print("  wrap:", label_dump())
  swipe(app, "left"); tick(app, 2)
  -- OK (synthetic down/up + an enter key event) switches the SELECTED row's
  -- units exactly once; up/down moves the selection between ALT and SPD
  assert(storekv.u_alt == nil and label_dump():find("ft"), "altitude must default to imperial")
  enter(app, cfg.w, cfg.h); tick(app, 2)
  assert(storekv.u_alt == 0 and label_dump():find("42 m"), "OK must switch altitude to metric exactly once: " .. label_dump())
  enter(app, cfg.w, cfg.h); tick(app, 2)
  assert(storekv.u_alt == 1 and label_dump():find("ft"), "OK must switch it back")
  swipe(app, "down"); tick(app, 1); clock_ms = clock_ms + 400
  enter(app, cfg.w, cfg.h); tick(app, 2)
  assert(storekv.u_spd == 0 and storekv.u_alt == 1, "down then OK must switch SPEED, not altitude")
  swipe(app, "up"); tick(app, 1); clock_ms = clock_ms + 400
  enter(app, cfg.w, cfg.h); tick(app, 2)
  assert(storekv.u_alt == 0, "up then OK must switch altitude again")
  enter(app, cfg.w, cfg.h); tick(app, 2)          -- back to imperial for the rest
  swipe(app, "right"); tick(app, 2); print("  target:", label_dump())
  -- saturation flag: heading must hold, src line must say so
  local keep = cfg.compass
  cfg.compass = function() local m = attitude(true_heading, 0, 0); m.ovfl = true; return m end
  tick(app, 3); print("  saturated:", label_dump()); assert(label_dump():find("Field saturated"))
  cfg.compass = keep; tick(app, 3); assert(not label_dump():find("Field saturated"))
  -- every readout string must fit the 320-wide column (~23 glyphs at 12 px)
  for _, l in ipairs(labels) do if l.x ~= 0 then assert(#l.text <= 23, "too wide for the M9 column: " .. l.text) end end
  -- orientation / flip / clear / unknown keys
  -- A PARTIAL turn must be REFUSED: an arc leaves the centre almost anywhere,
  -- which is exactly how a silently-accepted bad fit broke north on hardware.
  do
    local saved = { storekv.cal_ox, storekv.cal_oy }
    key(app, "c")
    for i = 1, 80 do true_heading = (i * 60 / 80) % 360; tick(app, 1, 150) end   -- flat, 60 deg only
    key(app, "c"); tick(app, 2)
    assert(toasts[#toasts]:find("Not calibrated"), "a partial turn must be refused, got: " .. toasts[#toasts])
    assert(storekv.cal_ox == saved[1] and storekv.cal_oy == saved[2],
           "a refused calibration must not overwrite the stored one")
  end
  -- the measured default must be right out of the box: no A press, no offset
  do
    local function shown0() return tonumber(drawlog.text[#drawlog.text - 3]:match("^(%d+)$")) end
    for _, th in ipairs({ 0, 90, 180, 270 }) do
      true_heading = th; tick(app, 15)
      local err = math.abs(((shown0() - (th + FIX_DECL) + 540) % 360) - 180)
      assert(err <= 2, string.format("default mapping wrong at %d: showed %d", th, shown0()))
    end
    assert(storekv.align == nil or storekv.align == 0, "no offset should be needed by default")
    assert(storekv.mirror == nil or storekv.mirror == 0, "no mirror should be needed by default")
  end
  -- the accelerometer's own zero-g offset must come out of the same sweep,
  -- or the tilt correction is applied against a gravity vector that is 5
  -- degrees wrong
  assert(storekv.acc_by and math.abs(storekv.acc_by - ABIAS.y) < 0.02,
         "accel bias not recovered: " .. tostring(storekv.acc_by))
  do
    true_heading, true_roll, true_pitch = 0, 0, 0
    tick(app, 10)
    local t = label_dump():match("north%s+tilt%s+(%d+)")   -- "MAG north  tilt 0°"
    assert(t and tonumber(t) <= 2, "flat device should read ~0 tilt, got: " .. tostring(t))
  end
  -- TILT COMPENSATION, the whole point of the IMU: heading must hold while the
  -- device is tipped. Without it the error is ~1.5 deg per deg of tilt here.
  do
    local function shown() return tonumber(drawlog.text[#drawlog.text - 3]:match("^(%d+)$")) end
    for _, hdg in ipairs({ 0, 90, 200 }) do
      true_heading, true_roll, true_pitch = hdg, 0, 0
      tick(app, 15)
      local level = shown()
      for _, tilt in ipairs({ { 20, 0 }, { 0, 20 }, { -15, 15 } }) do
        true_roll, true_pitch = tilt[1], tilt[2]
        tick(app, 15)
        local err = math.abs(((shown() - level + 540) % 360) - 180)
        assert(err <= 3, string.format("tilt %d/%d at heading %d moved the reading %d deg (%d -> %d)",
                                       tilt[1], tilt[2], hdg, err, level, shown()))
      end
      true_roll, true_pitch = 0, 0
    end
    print("  tilt: heading held within 3 deg through 20 deg of roll and pitch")
  end
  -- WAYPOINT PLACEMENT: with a known heading and a known target bearing, the
  -- amber dot must sit at (bearing - heading) clockwise from the top of the
  -- dial. AMBER is 0xE8A33D; the dial centre is (D/2, D/2).
  do
    true_heading, true_roll, true_pitch = 0, 0, 0
    swipe(app, "right"); tick(app, 12)          -- pick the first target
    print("  rows: " .. label_dump())
    -- the target row reads like "7.09 km  brg 038° NE": take THAT number, not
    -- the first degree sign on the page (the course readout also has one)
    local brg = tonumber((label_dump():match("mi%s+(%d%d%d)")) or (label_dump():match("km%s+(%d%d%d)")))
    assert(brg, "could not read the target bearing from the panel")
    for _, hdg in ipairs({ 0, 90, 210 }) do
      true_heading = hdg; tick(app, 20)
      local dot
      for _, c in ipairs(drawlog.circles) do if c.col == 0xE8A33D and c.filled then dot = c end end
      assert(dot, "no waypoint marker drawn")
      -- screen angle of the dot, clockwise from up, around the dial centre
      local D2 = 144 / 2                        -- landscape D on the M9 body
      local ang = math.deg(math.atan(dot.x - D2, -(dot.y - D2))) % 360
      local want = (brg - hdg) % 360
      local err = math.abs(((ang - want + 540) % 360) - 180)
      print(string.format("  waypoint: heading %3d  bearing %3d  -> want %3d, drawn %6.1f, err %.1f",
                          hdg, brg, want, ang, err))
    end
  end
  -- DIAGNOSTICS must fit: at 12 px the panel is ~22 characters wide in normal
  -- layout and ~26 with the key column reclaimed, and a longer line wraps onto
  -- the row beneath it.
  do
    key(app, "d"); tick(app, 4)
    for _, l in ipairs(labels) do
      if l.text ~= "" and l.x ~= 0 then
        assert(#l.text <= 26, "diagnostic row too wide (" .. #l.text .. "): " .. l.text)
      end
    end
    print("  diag rows: " .. label_dump())
    key(app, "d"); tick(app, 2)
  end
  -- align north: with the device pointing at an arbitrary true heading, one
  -- press must make THAT direction read 000 and keep the dial turning the
  -- right way (a later true heading must read back as itself minus the offset)
  true_heading = 137; tick(app, 8)
  key(app, "a"); tick(app, 8)
  assert(storekv.align ~= nil, "align must persist")
  assert(storekv.mirror == nil, "mirror is gone: the frames are measured, not hand-flipped")
  assert(toasts[#toasts] == "North set here", "A must set the offset: " .. tostring(toasts[#toasts]))
  local function shown_deg()
    return tonumber(drawlog.text[#drawlog.text - 3]:match("^(%d+)$"))
  end
  assert(math.abs(((shown_deg() - 0 + 540) % 360) - 180) <= 2, "the aligned direction must read 000")
  true_heading = 137 + 90; tick(app, 15)
  assert(math.abs(((shown_deg() - 90 + 540) % 360) - 180) <= 3, "a right turn must count UP")
  -- F and O must do NOTHING now: both frames are measured, so a key that
  -- hand-flips handedness can only break a correct compass
  local before_f = { storekv.align, storekv.mirror, storekv.orient, storekv.flip }
  key(app, "f"); key(app, "F"); key(app, "o"); key(app, "O"); tick(app, 5)
  assert(storekv.align == before_f[1] and storekv.mirror == before_f[2]
         and storekv.orient == before_f[3] and storekv.flip == before_f[4],
         "F and O must have no effect")
  key(app, "a"); tick(app, 8)
  true_heading = 0
  key(app, nil, 0x87); key(app, "backspace", 8); key(app, "z"); tick(app, 2)
  -- moving: GPS course appears in the readout while the compass still drives the rose
  moving = true; tick(app, 5); print("  moving:", label_dump())
  -- compass drops out -> GPS course takes over, then nothing
  cfg.compass = function() return nil end; tick(app, 15); print("  mag lost:", label_dump())
  assert(label_dump():find("GPS course"), "expected GPS-course fallback")
  moving = false; tick(app, 5); print("  still:", label_dump())
  cfg.gps = function() return nil end; tick(app, 5); print("  no fix:", label_dump())
  key(app, "x"); tick(app, 1); assert(storekv.cal_ox == nil, "clear cal")
  if app.on_close then guarded(BUDGET, app.on_close) end
  print("  toasts:", table.concat(toasts, " / "))
end

scenarios.r8 = function()
  cfg = { w = 240, h = 276, caps = { sdk_ext = true, keyboard = false, touch = true, compass = false },
          contacts = contacts_fixture, self_lat = 0, self_lon = 0 }
  local moving = true
  cfg.gps = function() return { lat = 37.75, lon = -122.45, sats = 6, alt_m = 10, speed_kmh = 5.5, course = 90.0 } end
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  print("  widgets:", "canvases=" .. widgets.canvases, "labels=" .. widgets.labels, "buttons=" .. widgets.buttons, "scroll=" .. tostring(widgets.scroll))
  assert(widgets.buttons == 1, "portrait touch board without compass should get one button")
  tick(app, 10); print("  gps heading:", label_dump())
  assert(label_dump():find("GPS course"))
  tap(app, 120, 60); tick(app, 2); print("  tap rose:", label_dump())
  drag(app, 120, 60, 40, 62, "left"); tick(app, 2)   -- swipe handled once (left), not also as a tap
  print("  drag:", label_dump()); assert(label_dump():find("none"), "swipe must cycle exactly once")
  local before = label_dump()
  send(app, { type = "down", x = 120, y = 60 }); send(app, { type = "up", x = 150, y = 60 }); tick(app, 1)  -- 30 px drag, no swipe event
  assert(label_dump() == before, "a drag without a swipe must be ignored")
  tap(app, 120, 270); tick(app, 2)          -- below the rose: no-op
  buttons[1].fn(); tick(app, 2); print("  button:", label_dump())
  -- portrait rows sit under the dial: ALT/SPD near y=280/298, so tap those to
  -- switch units and something well clear of them to prove it is bounded
  local u0 = storekv.u_alt
  tap(app, 20, 282); tick(app, 2)
  assert(storekv.u_alt ~= u0, "a tap on the ALT row must switch its units")
  local u1, s1 = storekv.u_alt, storekv.u_spd
  tap(app, 20, 440); tick(app, 2)      -- well below every row
  assert(storekv.u_alt == u1 and storekv.u_spd == s1, "a tap outside the rows must not change units")
  local b2 = label_dump(); swipe(app, "right"); swipe(app, "right"); tick(app, 1)   -- duplicate within 300 ms
  print("  dbl swipe:", label_dump()); assert(label_dump() ~= b2, "first swipe must count")
  clock_ms = clock_ms + 400; local b3 = label_dump(); swipe(app, "right"); tick(app, 1); assert(label_dump() ~= b3, "a later swipe must count")
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.v4 = function()
  cfg = { w = 240, h = 276, caps = { sdk_ext = false, keyboard = false, touch = true, compass = false },
          contacts = {}, self_lat = 37.1, self_lon = -122.1 }
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  tick(app, 10); print("  base sdk:", label_dump())
  swipe(app, "right"); tick(app, 1)
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.pager = function()
  cfg = { w = 480, h = 178, caps = { sdk_ext = true, keyboard = true, touch = false, compass = false },
          contacts = contacts_fixture, self_lat = 37.75, self_lon = -122.45 }
  cfg.gps = function() return nil end
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  tick(app, 10); print("  pager:", label_dump())
  key(app, "c"); tick(app, 1)
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.pager_portrait_jumbo = function()
  cfg = { w = 222, h = 436, caps = { sdk_ext = true, keyboard = true, touch = false, compass = false },
          contacts = { { name = "WADAMESH-BASE-NODE-EXTRA", type = 2, ago_s = 1, lat = 37.8, lon = -122.4 } }, self_lat = 37.75, self_lon = -122.45 }
  cfg.gps = function() return { lat = 37.75, lon = -122.45, sats = 7, alt_m = 5, speed_kmh = 12.3, course = 215 } end
  storekv = {}
  wada = build_wada(); wada.ui.text_h = function(sz) return ({ [12] = 21, [14] = 22, [16] = 27 })[sz] or 21 end
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  tick(app, 3); swipe(app, "right"); tick(app, 3); print("  pager-portrait-jumbo:", label_dump())
  for _, l in ipairs(labels) do if l.x ~= 0 then assert(#l.text <= 19, "too wide for a 210 px column at 18 px: " .. l.text) end end
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.tanmatsu = function()
  cfg = { w = 480, h = 756, caps = { sdk_ext = true, keyboard = true, touch = false, compass = false },
          contacts = contacts_fixture, self_lat = 37.75, self_lon = -122.45 }
  cfg.gps = function() return { lat = 37.75, lon = -122.45, sats = 12, alt_m = 1203 } end
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  tick(app, 5); swipe(app, "right"); tick(app, 5); print("  tanmatsu:", label_dump())
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.audio_api = function()
  cfg = { w = 320, h = 196,
     caps = { sdk_ext = true, keyboard = true, touch = false,
         audio = true, audio_sd = true, sd_list = true } }
  wada = build_wada()
  local caps = wada.sys.caps()
    assert(caps.audio and caps.audio_wav and caps.audio_mp3 and caps.audio_sd,
      "audio capability flags do not match the WAV/MP3 contract")
  assert(wada.audio and wada.audio.play and wada.audio.pause and wada.audio.resume and
    wada.audio.stop and wada.audio.status, "wada.audio API is incomplete")

  assert(wada.audio.play("track.wav"))
  local status = wada.audio.status()
  assert(status.state == "playing" and status.path == "track.wav" and
    status.source == "app" and status.format == "wav", "app-storage play status is wrong")
  assert(wada.audio.pause() and wada.audio.status().state == "paused", "pause failed")
  assert(wada.audio.resume() and wada.audio.status().state == "playing", "resume failed")
  assert(wada.audio.play("next.wav") and wada.audio.status().path == "next.wav",
    "a second play must replace the active track")
  assert(wada.audio.play("sd:/Music/card.wav"))
  assert(wada.audio.status().source == "sd", "sd: source was not reported")

  local value, err = wada.audio.play("../escape.wav")
  assert(value == nil and err == "bad path", "app sandbox traversal was accepted")
  value, err = wada.audio.play("sd:/Music/../escape.wav")
  assert(value == nil and err == "bad path", "SD traversal was accepted")
    assert(wada.audio.play("track.mp3") and wada.audio.status().format == "mp3",
      "MP3 playback was not accepted or reported")
    value, err = wada.audio.play("track.flac")
    assert(value == nil and err == "unsupported format", "unknown audio format was accepted")

  assert(wada.audio.stop() and wada.audio.status().state == "stopped", "stop failed")
  assert(wada.audio.play("close.wav"))
  audio_host_close()
  assert(wada.audio.status().state == "stopped" and audio_log[#audio_log] == "release",
    "host close did not release playback")
  print("  transport + storage sandbox: PASS (" .. #audio_log .. " host calls)")

  if APP_PATH:match("audio_test%.lua$") then
    local app = load_app()
    assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
    assert(#buttons == 5, "audio test app did not create all transport/source buttons")
    buttons[1].fn(); assert(wada.audio.status().state == "playing", "Play button failed")
    buttons[2].fn(); assert(wada.audio.status().state == "paused", "Pause button failed")
    buttons[3].fn(); assert(wada.audio.status().state == "playing", "Resume button failed")
    buttons[4].fn(); assert(wada.audio.status().state == "stopped", "Stop button failed")
    buttons[5].fn(); buttons[1].fn()
    assert(wada.audio.status().source == "app", "source switch did not select app storage")
    guarded(BUDGET, app.on_tick)
    guarded(BUDGET, app.on_close)
    assert(wada.audio.status().state == "stopped", "test app close did not stop playback")
    print("  scripts/audio_test.lua UI: PASS")
  end
end

-- instruction cost of one heavy tick (redraw forced every tick by spinning the heading)
scenarios.cost = function()
  cfg = { w = 320, h = 196, caps = { sdk_ext = true, keyboard = true, touch = false, compass = true, accel = true },
          contacts = contacts_fixture, self_lat = 37.75, self_lon = -122.45 }
  local th = 0
  cfg.compass = function() th = th + 7; return (attitude(th, 0, 0)) end
  cfg.accel = function() local _, a = attitude(th, 0, 0); return a end
  cfg.gps = function() return { lat = 37.75, lon = -122.45, sats = 9, alt_m = 42, speed_kmh = 10, course = 100 } end
  storekv = { cal_ox = BIAS.x, cal_oy = BIAS.y, cal_oz = BIAS.z, cal_r = 0.484 }
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  swipe(app, "right")
  local worst = 0
  for i = 1, 50 do
    local n = 0
    debug.sethook(function() n = n + 1000 end, "", 1000)
    clock_ms = clock_ms + 150
    if i == 25 then clock_ms = clock_ms + 10000 end  -- force a contacts refresh inside a tick
    local ok, err = pcall(app.on_tick, 150)
    debug.sethook()
    assert(ok, err)
    if n > worst then worst = n end
  end
  print(string.format("  worst tick ~%d instructions (budget %d), draw ops so far %d", worst, BUDGET, drawlog.ops))
  assert(worst < BUDGET / 4, "tick too expensive")
end

-- ---- Tetris (deploy/apps/tetris) --------------------------------------------

scenarios.tetris_tdeck = function()
  cfg = { w = 320, h = 240, caps = { touch = true, keyboard = false } }
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  assert(widgets.canvases == 2, "expected 2 canvases (board + side), got " .. widgets.canvases)
  assert(widgets.timer_ms == 700, "initial tick rate must be 700 ms, got " .. tostring(widgets.timer_ms))
  tick(app, 5)
  swipe(app, "right"); swipe(app, "left"); swipe(app, "up"); swipe(app, "down")
  tick(app, 5)
  print("  t-deck: OK  canvases=" .. widgets.canvases .. " timer=" .. tostring(widgets.timer_ms))
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.tetris_v4 = function()
  cfg = { w = 240, h = 276, caps = { touch = true, keyboard = false } }
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  assert(widgets.canvases == 2, "expected 2 canvases")
  tick(app, 20)
  print("  v4: OK  timer=" .. tostring(widgets.timer_ms))
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.tetris_keyboard = function()
  cfg = { w = 480, h = 178, caps = { touch = false, keyboard = true } }
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  tick(app, 5)
  key(app, "left"); key(app, "right"); key(app, "up"); key(app, "down"); key(app, "enter")
  tick(app, 5)
  print("  keyboard: OK  timer=" .. tostring(widgets.timer_ms))
  if app.on_close then guarded(BUDGET, app.on_close) end
end

local function tetris_text_has(s)
  for i = #drawlog.text, math.max(1, #drawlog.text - 30), -1 do
    if drawlog.text[i] == s then return true end
  end
  return false
end

local function tetris_run_to_gameover(app)
  -- hard-drop repeatedly; draw_board() adds "tap to retry" before draw_side()
  -- overwrites the tail of drawlog.text, so scan the last 30 entries
  for _ = 1, 2000 do
    tick(app, 1); swipe(app, "down")
    if tetris_text_has("tap to retry") then return true end
  end
  return false
end

scenarios.tetris_logic = function()
  cfg = { w = 320, h = 240, caps = { touch = true, keyboard = false } }
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  assert(tetris_run_to_gameover(app), "game over never triggered in 2000 swipe-drops")
  local ops_before = drawlog.ops
  guarded(BUDGET, app.on_input, { type = "down", x = 0, y = 0 })
  assert(drawlog.ops > ops_before, "tap after game over must redraw")
  assert(widgets.timer_ms == 700, "restart must reset timer to 700 ms")
  print("  logic: game-over triggered, restart OK")
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.tetris_hiscore = function()
  cfg = { w = 320, h = 240, caps = { touch = true, keyboard = false } }
  storekv = { hiscore = 0 }
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  assert(tetris_run_to_gameover(app), "game over never triggered")
  local saved = storekv.hiscore
  assert(type(saved) == "number", "hiscore must be saved as a number, got " .. type(saved))
  print("  hiscore: saved=" .. tostring(saved))
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.tetris_cost = function()
  cfg = { w = 320, h = 240, caps = { touch = true, keyboard = false } }
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  local worst = 0
  for i = 1, 100 do
    local n = 0
    debug.sethook(function() n = n + 1000 end, "", 1000)
    clock_ms = clock_ms + 700
    local ok, err = pcall(app.on_tick, 700)
    debug.sethook()
    assert(ok, err)
    if n > worst then worst = n end
  end
  print(string.format("  worst tick ~%d instructions (budget %d), draw ops %d", worst, BUDGET, drawlog.ops))
  assert(worst < BUDGET / 4, "tick too expensive: " .. worst .. " > " .. BUDGET / 4)
end

-- ---- Breakout (deploy/apps/breakout) ----------------------------------------

local function breakout_text_has(s)
  for i = #drawlog.text, math.max(1, #drawlog.text - 20), -1 do
    if drawlog.text[i] == s then return true end
  end
  return false
end

local function breakout_drive_to_gameover(app)
  -- keep launching (swipe up is a no-op once launched) and ticking;
  -- scan backward through the last 20 text entries for "tap to restart"
  for _ = 1, 3000 do
    swipe(app, "up"); tick(app, 1)
    if breakout_text_has("tap to restart") then return true end
  end
  return false
end

scenarios.breakout_tdeck = function()
  cfg = { w = 320, h = 240, caps = { touch = true, keyboard = false } }
  storekv = {}; wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  assert(widgets.canvases == 1, "expected 1 canvas, got " .. widgets.canvases)
  assert(widgets.timer_ms == 33, "timer must be 33 ms, got " .. tostring(widgets.timer_ms))
  swipe(app, "left"); swipe(app, "right"); swipe(app, "up")
  tick(app, 20)
  print("  t-deck: OK  timer=" .. tostring(widgets.timer_ms) .. " ops=" .. drawlog.ops)
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.breakout_v4 = function()
  cfg = { w = 240, h = 276, caps = { touch = true, keyboard = false } }
  storekv = {}; wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  swipe(app, "up"); tick(app, 20)
  print("  v4: OK  ops=" .. drawlog.ops)
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.breakout_keyboard = function()
  cfg = { w = 480, h = 178, caps = { touch = false, keyboard = true } }
  storekv = {}; wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  key(app, "left"); key(app, "right"); key(app, "up")
  tick(app, 20)
  print("  keyboard: OK  ops=" .. drawlog.ops)
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.breakout_logic = function()
  cfg = { w = 320, h = 240, caps = { touch = true, keyboard = false } }
  storekv = {}; wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  assert(breakout_drive_to_gameover(app), "game over never triggered in 3000 ticks")
  local ops_before = drawlog.ops
  guarded(BUDGET, app.on_input, { type = "down", x = 0, y = 0 })
  assert(drawlog.ops > ops_before, "tap after game over must redraw")
  print("  logic: game-over triggered, restart OK")
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.breakout_hiscore = function()
  cfg = { w = 320, h = 240, caps = { touch = true, keyboard = false } }
  storekv = { hiscore = 0 }; wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  assert(breakout_drive_to_gameover(app), "game over never triggered")
  local saved = storekv.hiscore
  assert(type(saved) == "number", "hiscore must be saved as a number, got " .. type(saved))
  print("  hiscore: saved=" .. tostring(saved))
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.breakout_cost = function()
  cfg = { w = 320, h = 240, caps = { touch = true, keyboard = false } }
  storekv = {}; wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  swipe(app, "up"); tick(app, 2)  -- launch
  local worst = 0
  for i = 1, 100 do
    local n = 0
    debug.sethook(function() n = n + 1000 end, "", 1000)
    clock_ms = clock_ms + 33
    local ok, err = pcall(app.on_tick, 33)
    debug.sethook()
    assert(ok, err)
    if n > worst then worst = n end
  end
  print(string.format("  worst tick ~%d instructions (budget %d), draw ops %d", worst, BUDGET, drawlog.ops))
  assert(worst < BUDGET / 4, "tick too expensive: " .. worst .. " > " .. BUDGET / 4)
  if app.on_close then guarded(BUDGET, app.on_close) end
end

-- ---- Trip Odometer (deploy/apps/tripodometer) --------------------------------

scenarios.trip_v4 = function()
  -- portrait touch board, no GPS fix → shows "no fix", all zeros
  cfg = { w = 240, h = 276, caps = { touch = true, keyboard = false, sdk_ext = true } }
  cfg.gps = function() return nil end
  storekv = {}; wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  assert(widgets.buttons == 2, "expected 2 buttons (Start/Stop + Reset)")
  tick(app, 5)
  local dump = label_dump()
  print("  no fix:", dump)
  assert(dump:find("no fix") or dump:find("no GPS"), "expected no-fix indicator")
  assert(dump:find("0:00"), "expected zero elapsed time")
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.trip_tdeck = function()
  -- landscape T-Deck with GPS fix, start tracking
  cfg = { w = 320, h = 240, caps = { touch = true, keyboard = false, sdk_ext = true } }
  cfg.gps = function() return { lat = 37.75, lon = -122.45, sats = 8, alt_m = 42, speed_kmh = 25.0, course = 90.0 } end
  storekv = {}; wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  tick(app, 2)
  local dump = label_dump()
  print("  fix before start:", dump)
  assert(dump:find("25") or dump:find("25.0"), "expected speed displayed")
  -- start tracking
  buttons[1].fn(); tick(app, 3)
  dump = label_dump()
  print("  tracking:", dump)
  assert(dump:find("tracking"), "expected tracking status after Start")
  -- stop
  buttons[1].fn(); tick(app, 1)
  dump = label_dump()
  print("  paused:", dump)
  assert(dump:find("paused"), "expected paused status after Stop")
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.trip_moving = function()
  -- simulate movement: distance and max speed accumulate
  cfg = { w = 240, h = 276, caps = { touch = true, keyboard = false, sdk_ext = true } }
  local step = 0
  cfg.gps = function()
    step = step + 1
    return { lat = 37.75 + step * 0.001, lon = -122.45, sats = 8, alt_m = 100 + step, speed_kmh = 30.0 + step }
  end
  storekv = {}; wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  buttons[1].fn()   -- start tracking
  tick(app, 20)     -- 20 GPS fixes, each ~111 m north → ~2.2 km total
  local dump = label_dump()
  print("  after 20 ticks:", dump)
  assert(not dump:find("| 0 m |"), "expected non-zero distance after movement")
  assert(dump:find("km/h"), "expected max speed displayed")
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.trip_persist = function()
  -- on_close saves; on_open restores
  cfg = { w = 240, h = 276, caps = { touch = true, keyboard = false, sdk_ext = true } }
  local step = 0
  cfg.gps = function()
    step = step + 1
    return { lat = 37.75 + step * 0.001, lon = -122.45, sats = 7, alt_m = 50, speed_kmh = 15.0 }
  end
  storekv = {}; wada = build_wada()
  local app = load_app()
  guarded(BUDGET, app.on_open, cfg.w, cfg.h)
  buttons[1].fn(); tick(app, 10)   -- run ~1 km
  if app.on_close then guarded(BUDGET, app.on_close) end
  assert(storekv.trip_km_x1000 ~= nil and storekv.trip_km_x1000 > 0, "expected trip_km_x1000 saved")
  -- re-open same store → distance should be restored
  wada = build_wada()
  local app2 = load_app()
  guarded(BUDGET, app2.on_open, cfg.w, cfg.h)
  local dump = label_dump()
  print("  restored:", dump)
  assert(not dump:find("| 0 m |"), "expected restored non-zero distance")
  if app2.on_close then guarded(BUDGET, app2.on_close) end
end

scenarios.trip_reset = function()
  -- Reset button clears everything
  cfg = { w = 240, h = 276, caps = { touch = true, keyboard = false, sdk_ext = true } }
  local step = 0
  cfg.gps = function()
    step = step + 1
    return { lat = 37.75 + step * 0.001, lon = -122.45, sats = 6, alt_m = 50, speed_kmh = 20.0 }
  end
  storekv = {}; wada = build_wada()
  local app = load_app()
  guarded(BUDGET, app.on_open, cfg.w, cfg.h)
  buttons[1].fn(); tick(app, 10)   -- accumulate some distance
  buttons[2].fn(); tick(app, 1)    -- Reset
  local dump = label_dump()
  print("  after reset:", dump)
  assert(dump:find("0:00"), "expected zero time after reset")
  assert(dump:find("| 0 m |") or dump:find("0.00"), "expected zero distance after reset")
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.trip_cost = function()
  cfg = { w = 240, h = 276, caps = { touch = true, keyboard = false, sdk_ext = true } }
  local step = 0
  cfg.gps = function()
    step = step + 1
    return { lat = 37.75 + step * 0.0001, lon = -122.45, sats = 8, alt_m = 42, speed_kmh = 10.0 }
  end
  storekv = {}; wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  buttons[1].fn()  -- start tracking
  local worst = 0
  for i = 1, 100 do
    local n = 0
    debug.sethook(function() n = n + 1000 end, "", 1000)
    clock_ms = clock_ms + 2000
    local ok, err = pcall(app.on_tick, 2000)
    debug.sethook()
    assert(ok, err)
    if n > worst then worst = n end
  end
  print(string.format("  worst tick ~%d instructions (budget %d)", worst, BUDGET))
  assert(worst < BUDGET / 4, "tick too expensive: " .. worst .. " > " .. BUDGET / 4)
  if app.on_close then guarded(BUDGET, app.on_close) end
end

-- ---- Ping (deploy/apps/ping) ------------------------------------------------
local function deliver_dm(app, sender, text)
  if app.on_message then
    guarded(BUDGET, app.on_message, { kind = "dm", sender = sender, text = text, channel = "" })
  end
end

-- contacts used by all ping scenarios
local PING_CONTACTS = {
  { name = "Node-Alpha", lat = 48.9000, lon = 2.4000 },
  { name = "Node-Beta",  lat = 48.8000, lon = 2.3000 },
}
local MY_GPS = { lat = 48.8566, lon = 2.3522, lat_e6 = 48856600, lon_e6 = 2352200, sats = 9 }
local function gps_fix() return MY_GPS end

scenarios.ping_tdeck = function()
  cfg = { w = 320, h = 240, caps = { touch = true, sdk_ext = true },
          contacts = PING_CONTACTS, gps = gps_fix }
  storekv = {}; wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  assert(widgets.labels >= 3,  "expected at least 3 labels (gps + 2 names), got " .. widgets.labels)
  assert(widgets.buttons >= 2, "expected 2 Ping buttons, got " .. widgets.buttons)
  assert(widgets.scroll,       "scroll should be enabled")
  assert(widgets.timer_ms,     "timer not started")
  print(string.format("  labels=%d buttons=%d timer=%dms", widgets.labels, widgets.buttons, widgets.timer_ms))
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.ping_v4 = function()
  cfg = { w = 240, h = 276, caps = { touch = true, sdk_ext = true },
          contacts = PING_CONTACTS, gps = gps_fix }
  storekv = {}; wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  assert(widgets.buttons >= 2, "expected 2 Ping buttons on V4")
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.ping_no_contacts = function()
  cfg = { w = 320, h = 240, caps = { touch = true, sdk_ext = true }, contacts = {} }
  storekv = {}; wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  assert(widgets.buttons == 0, "no Ping buttons when no contacts")
  local found = false
  for _, l in ipairs(labels) do if l.text:find("No contacts") then found = true end end
  assert(found, "should show 'No contacts' label")
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.ping_round_trip = function()
  cfg = { w = 320, h = 240, caps = { touch = true, sdk_ext = true },
          contacts = PING_CONTACTS, gps = gps_fix }
  storekv = {}; wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))

  local btn = buttons[1]; assert(btn and btn.fn, "no ping button")
  assert(guarded(BUDGET, btn.fn))

  assert(#dm_sent == 1, "expected 1 DM sent, got " .. #dm_sent)
  assert(dm_sent[1].to == "Node-Alpha", "wrong target: " .. tostring(dm_sent[1].to))
  local ping_msg = dm_sent[1].text
  assert(ping_msg:sub(1, 9) == "WADAPING:", "wrong prefix: " .. ping_msg:sub(1, 9))
  local ts_s, lat_s, lon_s = ping_msg:sub(10):match("(-?%d+):(-?%d+):(-?%d+)")
  assert(ts_s, "could not parse PING message: " .. ping_msg)
  print("  sent: " .. ping_msg)

  clock_ms = clock_ms + 250
  local their_lat6, their_lon6 = 48900000, 2400000
  local pong = string.format("WADAPONG:%s:%d:%d", ts_s, their_lat6, their_lon6)
  deliver_dm(app, "Node-Alpha", pong)

  local result_ok = false
  for _, l in ipairs(labels) do
    if l.text:find("ms") then
      print("  result: " .. l.text)
      result_ok = true
    end
  end
  assert(result_ok, "no RTT label found after PONG")
  local last_toast = toasts[#toasts]
  assert(last_toast and last_toast:find("Node-Alpha", 1, true), "toast must mention sender, got: " .. tostring(last_toast))
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.ping_auto_reply = function()
  cfg = { w = 320, h = 240, caps = { touch = true, sdk_ext = true },
          contacts = PING_CONTACTS, gps = gps_fix }
  storekv = {}; wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))

  local remote_ts = 999888
  local remote_lat6, remote_lon6 = 48900000, 2400000
  local ping_in = string.format("WADAPING:%d:%d:%d", remote_ts, remote_lat6, remote_lon6)
  dm_sent = {}
  deliver_dm(app, "Node-Alpha", ping_in)

  assert(#dm_sent == 1, "expected auto-reply DM, got " .. #dm_sent)
  assert(dm_sent[1].to == "Node-Alpha", "reply must go back to sender")
  local reply = dm_sent[1].text
  assert(reply:sub(1, 9) == "WADAPONG:", "reply must start with WADAPONG:")
  -- timestamp in reply must match original
  local rts = reply:sub(10):match("(-?%d+):")
  assert(rts == tostring(remote_ts),
    string.format("reply ts %s != original %d", rts, remote_ts))
  print("  auto-reply: " .. reply)

  -- non-DM messages are ignored
  local before = #dm_sent
  guarded(BUDGET, app.on_message, { kind = "channel", sender = "x", text = ping_in, channel = "c" })
  assert(#dm_sent == before, "channel messages must not trigger auto-reply")
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.ping_cost = function()
  cfg = { w = 320, h = 240, caps = { touch = true, sdk_ext = true },
          contacts = PING_CONTACTS, gps = gps_fix }
  storekv = {}; wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  local worst = 0
  for _ = 1, 20 do
    local n = 0
    debug.sethook(function() n = n + 1000 end, "", 1000)
    clock_ms = clock_ms + 5000
    local ok, err = pcall(app.on_tick, 5000)
    debug.sethook()
    assert(ok, err)
    if n > worst then worst = n end
  end
  print(string.format("  worst tick ~%d instructions (budget %d)", worst, BUDGET))
  assert(worst < BUDGET / 4, "tick too expensive: " .. worst .. " > " .. BUDGET / 4)
  if app.on_close then guarded(BUDGET, app.on_close) end
end

-- ---- SD Scan (deploy/apps/sdscan) --------------------------------------------
local PNG = "\137PNG\r\n\26\n" .. string.rep("\0", 120)
-- A file carrying real DOS + PE headers and nothing else: no code at all.
local function pe_bytes(n, e_lfanew)
  e_lfanew = e_lfanew or 0x80
  local t = {}
  for i = 1, n do t[i] = "\0" end
  t[1], t[2] = "M", "Z"
  for k = 0, 3 do t[0x3C + 1 + k] = string.char((e_lfanew >> (8 * k)) & 0xFF) end
  t[e_lfanew + 1], t[e_lfanew + 2] = "P", "E"
  return table.concat(t)
end
local NBSP = "\194\160"   -- the worm's blank-looking folder name
-- The M9 card as the advisory describes it, plus wadamesh's own data and tiles.
local function infected_card(extra)
  local f = {
    ["/autorun.inf"] = "[autorun]\r\nopen=" .. NBSP .. "\\svchost.exe\r\n",
    ["/" .. NBSP .. "/svchost.exe"] = pe_bytes(512),
    ["/tiles.lnk"] = "L\0\0\0\1\20\2\0" .. string.rep("\0", 80),
    ["/RECYCLER/S-1-5-21-1004/desktop.dat"] = pe_bytes(300, 0x78),   -- a program under a harmless name
    ["/copyright.png"] = PNG,
    ["/test file.txt"] = "test",
    ["/wadamesh/contacts3"] = "MZ" .. string.rep("\165", 200),        -- starts with MZ by chance
    ["/wadamesh/ui_threads_v1.bin"] = string.rep("\1", 300),
    ["/wadamesh/lang/hu.lang"] = "# ver: 22\n",
    ["/autorun"] = true,                                              -- an empty "vaccine" folder
  }
  for z = 8, 10 do for x = 130, 133 do for y = 80, 83 do
    f[string.format("/maps/osm/%d/%d/%d.png", z, x, y)] = PNG
  end end end
  for k, v in pairs(extra or {}) do f[k] = v end
  return mktree(f)
end
local function sd_cfg(w, h, extra_caps)
  local c = { w = w or 320, h = h or 196,
              caps = { sdk_ext = true, keyboard = true, touch = false, sd_list = true, sd_clean = true } }
  for k, v in pairs(extra_caps or {}) do c.caps[k] = v end
  return c
end
local function press(text)
  for i = #buttons, 1, -1 do
    if buttons[i].text == text then
      assert(guarded(BUDGET, buttons[i].fn), "button '" .. text .. "' failed")
      return
    end
  end
  error("no '" .. text .. "' button; screen: " .. label_dump())
end
local function has_button(text)
  for _, b in ipairs(buttons) do if b.text == text then return true end end
  return false
end
local function screen_has(text) return label_dump():find(text, 1, true) ~= nil end
local function scan_until(app, text, max_ticks)
  for _ = 1, max_ticks or 4000 do
    if screen_has(text) then return end
    tick(app, 1, 50)
  end
  error("never reached '" .. text .. "'; screen: " .. label_dump())
end
local function found_paths()
  local out = {}
  for _, l in ipairs(lists) do for _, r in ipairs(l.rows) do out[#out + 1] = r.text end end
  return out
end
local function rows_mention(needle)
  for _, r in ipairs(found_paths()) do if r:find(needle, 1, true) then return true end end
  return false
end

-- Wrapped text on the current screen must end above every button below it.
local function assert_no_overlap(where)
  for _, l in ipairs(labels) do
    if l.w and l.text ~= "" then
      local bottom = l.y + wada.ui.text_lines(l.text, l.w, l.size or 12) * wada.ui.text_h(l.size or 12)
      for _, b in ipairs(buttons) do
        if b.y > l.y then
          assert(bottom <= b.y, string.format("%s: text runs into the '%s' button (%d > %d): %s",
            where, b.text, bottom, b.y, l.text:sub(1, 40)))
        end
      end
    end
  end
end
local NOTICE_START = "SD Scan only removes files it recognises"

-- SD Scan 1.1: on a keyboard board the focus order is creation order, and the
-- firmware's key navigation collects at most kNavMax = 160 focus stops per
-- screen. So the buttons must be created before (and sit above) any list, and
-- a screen must stay well under 160 stops however many files were found.
local NAV_MAX = 160
local function assert_buttons_first(where)
  local stops = #buttons
  for _, l in ipairs(lists) do
    stops = stops + #l.rows
    for _, b in ipairs(buttons) do
      assert(b.seq < l.seq, where .. ": the '" .. b.text .. "' button comes after the list in focus order")
      assert(b.y + 32 <= l.y, where .. ": the '" .. b.text .. "' button is not above the list")
    end
  end
  assert(stops < NAV_MAX, where .. ": " .. stops .. " focus stops, the firmware collects " .. NAV_MAX)
end

scenarios.sdscan_layouts = function()
  for _, dims in ipairs({ { 320, 196 }, { 240, 276 }, { 480, 178 }, { 222, 436 } }) do
    reset_world()
    cfg = sd_cfg(dims[1], dims[2])
    cfg.sdtree = infected_card()
    wada = build_wada()
    local app = load_app()
    local where = dims[1] .. "x" .. dims[2]
    assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
    assert(screen_has(NOTICE_START), where .. ": the start screen must carry the notice")
    assert_no_overlap(where .. " start")
    press("Scan")
    scan_until(app, "threats found")
    assert_no_overlap(where .. " results")
    assert_buttons_first(where .. " results")
    press("Remove all")
    assert_no_overlap(where .. " confirm")
    press("Remove")
    scan_until(app, "Removed 4 files.")
    assert(screen_has(NOTICE_START), where .. ": the removal screen must carry the notice")
    assert(not screen_has("safe to put"), where .. ": do not tell people the card is safe")
    assert_no_overlap(where .. " removed")
    press("Scan again")
    press("Scan")
    scan_until(app, "No known Windows malware found.")
    assert(screen_has(NOTICE_START), where .. ": a clean result must carry the notice")
    assert_no_overlap(where .. " clean")
  end
end

-- The card root of a real infected M9 (photographed 2026-09-18), autorun.inf text
-- as it was on the card: Sality's pattern, with the payload as xlfqf.pif.
local SALITY_AUTORUN = table.concat({
  ";jedgRfgxKpOwxYkkslpwEyPfQXwXltdBYsJ", "XCmmWo aRguMqaH",
  "sHell\\EXplore\\COmmanD=xlfqf.pif", "sHELl\\OpEN\\Default=1",
  ";qaApt  hKlVtplou hjPQkb", "shell\\opEn\\CoMmanD = xlfqf.pif",
  ";vpWCt WxgC", "ShelL\\AUTopLay\\ComMaNd=xlfqf.pif", ";", "" }, "\r\n")
scenarios.sdscan_real_m9 = function()
  cfg = sd_cfg(320, 196)
  local f = {
    ["/autorun.inf"] = SALITY_AUTORUN,
    ["/xlfqf.pif"] = pe_bytes(4096),
    ["/copyright.png"] = PNG,
    ["/bl/list"] = "0",
    ["/meshcomod/contacts3"] = string.rep("\3", 300),
    ["/meshcomod/ui_threads_v1.bin"] = string.rep("\1", 300),
  }
  for x = 130, 133 do for y = 80, 83 do f[string.format("/tiles/8/%d/%d.png", x, y)] = PNG end end
  cfg.sdtree = mktree(f)
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  press("Scan")
  scan_until(app, "threats found")
  assert(screen_has("2 threats found"), label_dump())
  assert(rows_mention("autorun file: /autorun.inf"))
  assert(rows_mention("Windows program: /xlfqf.pif"))
  press("Remove all")
  press("Remove")
  scan_until(app, "Removed 2 files.")
  assert(not sd_exists("/autorun.inf") and not sd_exists("/xlfqf.pif"))
  for _, keep in ipairs({ "/copyright.png", "/bl/list", "/meshcomod/contacts3",
                          "/meshcomod/ui_threads_v1.bin", "/tiles/8/130/80.png" }) do
    assert(sd_exists(keep), "removed something that is not the worm: " .. keep)
  end
  press("Scan again")
  press("Scan")
  scan_until(app, "No known Windows malware found.")
end

scenarios.sdscan_many = function()
  cfg = sd_cfg(320, 196)
  local f = { ["/autorun.inf"] = SALITY_AUTORUN, ["/copyright.png"] = PNG, ["/meshcomod/contacts3"] = "x" }
  for i = 1, 372 do f[string.format("/RECYCLER/p%03d.pif", i)] = pe_bytes(256) end
  cfg.sdtree = mktree(f)
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  press("Scan")
  scan_until(app, "threats found")
  assert(screen_has("373 threats found"), label_dump())
  assert(#lists == 1)
  local rows = lists[1].rows
  assert(#rows == 61, "expected 60 rows plus the summary row, got " .. #rows)
  assert(rows[61].text:find("and 313 more", 1, true), "last row: " .. rows[61].text)
  assert_buttons_first("373 findings")
  press("Remove all")
  press("Remove")
  scan_until(app, "Removed 373 files.", 2000)
  assert(sd_exists("/copyright.png") and sd_exists("/meshcomod/contacts3"))
  assert(not sd_exists("/autorun.inf"))
end

scenarios.sdscan_m9 = function()
  cfg = sd_cfg(320, 196)
  cfg.sdtree = infected_card()
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  assert(widgets.timer_ms and widgets.timer_ms <= 100, "the scan needs a steady tick")
  press("Scan")
  assert(cfg.awake, "the screen must stay on while scanning")
  scan_until(app, "threats found")
  assert(not cfg.awake, "keep_awake must be released when the scan ends")
  assert(screen_has("4 threats found"), "expected exactly 4 threats; " .. label_dump())
  assert(rows_mention("autorun file: /autorun.inf"))
  assert(rows_mention("Windows program: /" .. NBSP .. "/svchost.exe"))
  assert(rows_mention("Windows shortcut: /tiles.lnk"))
  assert(rows_mention("renamed Windows program"), "a program under another name was missed")
  assert(not rows_mention("contacts3"), "a data file that starts with MZ is not a program")
  assert(screen_has("map tiles skipped"), "a quick scan should say it skipped the tile folders")
  for _, c in ipairs(cfg.sd_calls) do assert(c.max <= 24, "pages must stay small: " .. c.max) end

  press("Remove all")
  assert(screen_has("Remove 4 files?"))
  assert(buttons[1].text == "Cancel", "Cancel must come first so a stray Enter deletes nothing")
  press("Cancel")
  assert(screen_has("4 threats found") and not cfg.sd_removed, "Cancel must not remove anything")
  press("Remove all")
  press("Remove")
  scan_until(app, "Removed 4 files.")
  assert(#cfg.sd_removed == 4)
  for _, keep in ipairs({ "/copyright.png", "/test file.txt", "/wadamesh/contacts3",
                          "/wadamesh/ui_threads_v1.bin", "/wadamesh/lang/hu.lang",
                          "/maps/osm/8/130/80.png", "/autorun" }) do
    assert(sd_exists(keep), "removed something that is not a threat: " .. keep)
  end
  assert(not sd_exists("/autorun.inf") and not sd_exists("/tiles.lnk"))

  press("Scan again")
  press("Scan")
  scan_until(app, "No known Windows malware found.")
end

scenarios.sdscan_paging_and_full = function()
  cfg = sd_cfg(320, 196)
  local extra = { ["/maps/osm/8/130/evil.exe"] = pe_bytes(200), ["/wadamesh/history/zz.vbs"] = "WScript.Echo 1" }
  for i = 1, 100 do extra[string.format("/wadamesh/history/seg%03d", i)] = string.rep("\2", 90) end
  cfg.sdtree = infected_card(extra)
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  press("Scan")
  scan_until(app, "threats found")
  assert(rows_mention("zz.vbs"), "the 101st file of a folder was never reached: paging broken")
  assert(not rows_mention("evil.exe"), "a quick scan should not walk the tiles")
  local paged = 0
  for _, c in ipairs(cfg.sd_calls) do if c.path == "/wadamesh/history" and c.start > 1 then paged = paged + 1 end end
  assert(paged >= 4, "expected the history folder to be read in pages, got " .. paged)
  press("Scan again")
  press("Full scan")
  scan_until(app, "threats found")
  assert(rows_mention("evil.exe"), "a full scan must walk the tile folders")
  assert(not screen_has("map tiles skipped"))
end

scenarios.sdscan_old_firmware = function()
  cfg = sd_cfg(320, 196, { sd_clean = false })
  cfg.sdtree = infected_card()
  wada = build_wada()
  assert(not wada.sd.remove and not wada.sd.check)
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  assert(screen_has("can only find them"), "the intro should say removal needs newer firmware")
  press("Scan")
  scan_until(app, "threats found")
  assert(screen_has("3 threats found"), "by name: autorun, program, shortcut; " .. label_dump())
  assert(not has_button("Remove all"), "no Remove button without firmware support")
  assert(has_button("Scan again"))
  assert(screen_has("format the card"))
end

scenarios.sdscan_no_access = function()
  cfg = sd_cfg(320, 196, { sd_list = false, sd_clean = false })
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  assert(screen_has("no SD card access"), label_dump())
  assert(not has_button("Scan"))
end

scenarios.sdscan_no_card = function()
  cfg = sd_cfg(320, 196)
  cfg.sd_nocard = true
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  press("Scan")
  scan_until(app, "No SD card found.")
  assert(has_button("Scan again"))
end

scenarios.sdscan_remove_fails = function()
  cfg = sd_cfg(320, 196)
  cfg.sdtree = infected_card()
  cfg.sd_remove_fail = { ["/tiles.lnk"] = "remove failed" }
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  press("Scan")
  scan_until(app, "threats found")
  press("Remove all")
  press("Remove")
  scan_until(app, "could not be removed")
  assert(screen_has("Removed 3, 1 could not be removed."), label_dump())
  assert(rows_mention("/tiles.lnk") and rows_mention("remove failed"))
end

scenarios.sdscan_portrait = function()
  cfg = sd_cfg(240, 276, { keyboard = false, touch = true })
  cfg.sdtree = infected_card()
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  press("Scan")
  scan_until(app, "threats found")
  assert_buttons_first("portrait")
end

scenarios.sdscan_cost = function()
  cfg = sd_cfg(320, 196)
  local extra = {}
  for i = 1, 400 do extra[string.format("/wadamesh/history/seg%03d", i)] = string.rep("\2", 90) end
  cfg.sdtree = infected_card(extra)
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  press("Full scan")
  local worst, ticks = 0, 0
  while not screen_has("threats found") and ticks < 5000 do
    local n = 0
    debug.sethook(function() n = n + 100 end, "", 100)
    clock_ms = clock_ms + 50
    local ok, err = pcall(app.on_tick, 50)
    debug.sethook()
    assert(ok, err)
    if n > worst then worst = n end
    ticks = ticks + 1
  end
  print(string.format("  full scan of %d files: %d ticks, worst tick ~%d instructions (budget %d)",
    400 + 60, ticks, worst, BUDGET))
  assert(worst < BUDGET / 4, "tick too expensive")
end

-- ---- ProTreck (deploy/apps/protreck) --------------------------------------------

local function pt_has_text(s)
  for i = #drawlog.text, math.max(1, #drawlog.text - 40), -1 do
    if drawlog.text[i] == s then return true end
  end
  return false
end

scenarios.protreck_tdeck = function()
  cfg = { w = 320, h = 240, caps = { touch = true, keyboard = false, sdk_ext = true } }
  cfg.gps = function() return { lat = 48.85, lon = 2.35, sats = 8, alt_m = 35, speed_kmh = 0, course = 0 } end
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  assert(widgets.canvases == 1, "expected 1 canvas")
  assert(widgets.timer_ms == 500, "tick rate must be 500 ms, got " .. tostring(widgets.timer_ms))
  tick(app, 5)
  -- swipe through all 4 tabs
  swipe(app, "left"); tick(app, 2)   -- CHRONO
  swipe(app, "left"); tick(app, 2)   -- TIMER
  swipe(app, "left"); tick(app, 2)   -- ALTI
  swipe(app, "left"); tick(app, 2)   -- back to ASTRO
  print("  t-deck: OK  canvases=" .. widgets.canvases .. " timer=" .. tostring(widgets.timer_ms))
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.protreck_v4 = function()
  cfg = { w = 240, h = 276, caps = { touch = true, keyboard = false, sdk_ext = true } }
  cfg.gps = function() return { lat = 37.75, lon = -122.45, sats = 6, alt_m = 120, speed_kmh = 5, course = 90 } end
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  tick(app, 3)
  swipe(app, "left"); tick(app, 2)   -- CHRONO
  swipe(app, "right"); tick(app, 2)  -- back ASTRO
  swipe(app, "right"); tick(app, 2)  -- wrap to ALTI
  if app.on_close then guarded(BUDGET, app.on_close) end
  print("  v4: OK")
end

scenarios.protreck_no_gps = function()
  cfg = { w = 320, h = 240, caps = { touch = true, keyboard = false, sdk_ext = true } }
  cfg.gps = function() return nil end
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  tick(app, 5)
  -- must render without crash even when GPS is absent
  swipe(app, "left"); tick(app, 2)   -- CHRONO
  swipe(app, "left"); tick(app, 2)   -- TIMER
  swipe(app, "left"); tick(app, 2)   -- ALTI
  print("  no-gps: OK (no crash)")
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.protreck_chrono = function()
  cfg = { w = 320, h = 240, caps = { touch = true, keyboard = false, sdk_ext = true } }
  cfg.gps = function() return nil end
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  -- switch to CHRONO tab
  swipe(app, "left"); tick(app, 1)
  -- start chrono
  local ops0 = drawlog.ops
  guarded(BUDGET, app.on_input, { type = "down", x = 0, y = 0 })
  tick(app, 3)
  -- lap
  swipe(app, "up"); tick(app, 1)
  assert(pt_has_text("Lap 1"), "lap must appear in draw after swipe-up")
  -- stop
  guarded(BUDGET, app.on_input, { type = "down", x = 0, y = 0 })
  tick(app, 1)
  -- reset
  swipe(app, "down"); tick(app, 1)
  print("  chrono: start / lap / stop / reset OK")
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.protreck_timer = function()
  cfg = { w = 320, h = 240, caps = { touch = true, keyboard = false, sdk_ext = true } }
  cfg.gps = function() return nil end
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  -- switch to TIMER
  swipe(app, "left"); swipe(app, "left"); tick(app, 1)
  -- cycle preset a few times
  swipe(app, "up"); swipe(app, "up"); tick(app, 1)
  -- start timer
  guarded(BUDGET, app.on_input, { type = "down", x = 0, y = 0 })
  tick(app, 3)
  -- stop
  guarded(BUDGET, app.on_input, { type = "down", x = 0, y = 0 })
  tick(app, 1)
  -- reset
  swipe(app, "down"); tick(app, 1)
  assert(type(storekv.tmr_pi) == "number", "preset index must persist as a number")
  print("  timer: preset cycle / start / stop / reset OK  preset_i=" .. tostring(storekv.tmr_pi))
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.protreck_alti = function()
  local alt = 1200
  cfg = { w = 320, h = 240, caps = { touch = true, keyboard = false, sdk_ext = true } }
  cfg.gps = function()
    alt = alt + 1
    return { lat = 45.8, lon = 6.9, sats = 10, alt_m = alt, speed_kmh = 3, course = 45 }
  end
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  -- switch to ALTI
  swipe(app, "left"); swipe(app, "left"); swipe(app, "left"); tick(app, 1)
  tick(app, 20)   -- accumulate samples
  assert(storekv.alti_max ~= nil, "alti_max must be saved to store after GPS samples")
  assert(type(storekv.alti_max) == "number", "alti_max must be a number")
  -- reset min/max
  swipe(app, "down"); tick(app, 2)
  print("  alti: sampling OK  max=" .. tostring(storekv.alti_max))
  if app.on_close then guarded(BUDGET, app.on_close) end
end

scenarios.protreck_cost = function()
  local alt = 500
  cfg = { w = 320, h = 240, caps = { touch = true, keyboard = false, sdk_ext = true } }
  cfg.gps = function() alt = alt + 0.5; return { lat = 48.85, lon = 2.35, sats = 8, alt_m = alt, speed_kmh = 2, course = 0 } end
  storekv = {}
  wada = build_wada()
  local app = load_app()
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h))
  -- switch to ALTI (heaviest draw: graph over 60 samples)
  swipe(app, "left"); swipe(app, "left"); swipe(app, "left")
  local worst = 0
  for i = 1, 80 do
    local n = 0
    debug.sethook(function() n = n + 1000 end, "", 1000)
    clock_ms = clock_ms + 500
    local ok, err = pcall(app.on_tick, 500)
    debug.sethook()
    assert(ok, err)
    if n > worst then worst = n end
  end
  print(string.format("  worst tick ~%d instructions (budget %d), ops %d", worst, BUDGET, drawlog.ops))
  assert(worst < BUDGET / 4, "tick too expensive: " .. worst)
  if app.on_close then guarded(BUDGET, app.on_close) end
end

-- ---- xmpp app ---------------------------------------------------------------
scenarios.harness_crypto = function()
  cfg = { w = 320, h = 196, caps = { sdk_ext = true, keyboard = true, touch = false } }
  wada = build_wada()
  local c = wada.crypto
  assert(c.hex(c.hmac_sha256("Jefe", "what do ya want for nothing?")) ==
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "RFC 4231 case 2")
  assert(c.hex(c.sha256("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256 abc")
  assert(c.hex(c.sha256("")) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256 empty")
  -- key longer than the block size is hashed first (RFC 4231 case 6)
  assert(c.hex(c.hmac_sha256(("\xaa"):rep(131), "Test Using Larger Than Block-Size Key - Hash Key First")) ==
    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", "RFC 4231 case 6")
  assert(#c.sha256(("a"):rep(1000)) == 32)
  assert(c.hex("\0\255\16") == "00ff10", "hex")
  -- random(): seeded, successive, deterministic across reset_world
  local a, b = wada.sys.random(), wada.sys.random()
  assert(a ~= b and math.type(a) == "integer", "random() should vary")
  reset_world()
  wada = build_wada()
  assert(wada.sys.random() == a and wada.sys.random() == b, "random() reseeded by reset_world")
  assert(wada.sys.random(5, 5) == 12345, "ranged random unchanged")
  -- http_post: async via tick, recorded, one in flight
  cfg.relay = function(url, body) if body == "bad" then return 500, "x" end return 200, "echo:" .. body end
  local got
  wada.net.http_post("http://h/x", "hello", "text/plain", function(st, body) got = { st, body } end)
  assert(got == nil, "reply must not be synchronous")
  assert(not pcall(wada.net.http_post, "http://h/x", "again", function() end), "second post while pending")
  local app = { on_tick = function() end }
  tick(app, 1)
  assert(got and got[1] == 200 and got[2] == "echo:hello", "reply delivered on tick")
  assert(#net_log == 1 and net_log[1].url == "http://h/x" and net_log[1].body == "hello")
  wada.net.http_post("http://h/x", "bad", function(st, body) got = { st, body } end)  -- ctype omitted
  tick(app, 1)
  assert(got[1] == -1 and got[2] == nil, "non-2xx collapses to -1, nil")
  assert(not pcall(wada.net.http_post, "https://h/x", "b", function() end), "http:// only")
  assert(not pcall(wada.net.http_post, "http://h/x", "", function() end), "empty body")
  -- ui.input: answered from cfg.inputs, one prompt at a time, exactly one cb
  cfg.inputs = { "typed", false }
  local r = {}
  wada.ui.input("T", "init", function(t) r[#r + 1] = t == nil and "nil" or t end)
  assert(#r == 0, "input answers later")
  assert(not pcall(wada.ui.input, "T", "", function() end), "second prompt while open")
  tick(app, 1)
  assert(r[1] == "typed")
  wada.ui.input("T", "", function(t) r[#r + 1] = t == nil and "nil" or t end)
  tick(app, 1)
  assert(r[2] == "nil" and #r == 2, "false in queue means cancel")
  print("  crypto, http_post, input and random mocks ok")
end

-- repo-relative file next to the app under test (APP_PATH may be relative)
local function repo_file(rel)
  local root = APP_PATH:match("^(.-)deploy/apps/") or ""
  local f = assert(io.open(root .. rel, "rb"), "cannot open " .. root .. rel)
  local s = f:read("a"); f:close()
  return s
end
local function unhex(h) return (h:gsub("..", function(x) return string.char(tonumber(x, 16)) end)) end

-- instructions one call costs (exact: hook every instruction)
local function measure(fn, ...)
  local n = 0
  debug.sethook(function() n = n + 1 end, "", 1)
  local r = table.pack(pcall(fn, ...))
  debug.sethook()
  assert(r[1], r[2])
  return n, table.unpack(r, 2, r.n)
end

local function xmpp_derive(T, pw)
  local st = T.kdf_new(pw)
  local calls = 0
  repeat
    calls = calls + 1
    local done
    assert(guarded(BUDGET, function() done = T.kdf_step(st, 100) end), "kdf_step over budget")
  until done or calls > 100
  assert(st.enc and st.mac and #st.enc == 32 and #st.mac == 32, "kdf did not finish")
  return st.enc, st.mac, calls
end

scenarios.xmpp_seal_vectors = function()
  cfg = { w = 320, h = 196, caps = { sdk_ext = true, keyboard = true, touch = false } }
  wada = build_wada()
  local app = load_app()
  local T = assert(app._t, "app._t missing")
  local hex = wada.crypto.hex
  -- fields(): TAB split keeping empty fields
  local f = T.fields("a\t\tb\t")
  assert(#f == 4 and f[1] == "a" and f[2] == "" and f[3] == "b" and f[4] == "", "fields keeps empties")
  assert(#T.fields("") == 1 and T.fields("")[1] == "", "fields of empty line")
  -- K / V vectors from the relay
  local keys, nk, nv = {}, 0, 0
  for line in repo_file("scripts/xmpp-relay/seal_vectors.txt"):gmatch("([^\n]*)\n") do
    local p = T.fields(line)
    if p[1] == "K" then
      local e, m = xmpp_derive(T, p[2])
      assert(hex(e) == p[3] and hex(m) == p[4], "K mismatch for " .. p[2])
      keys[p[2]] = { e, m }; nk = nk + 1
    elseif p[1] == "V" then
      assert(#p == 6, "V line must have 6 fields, got " .. #p)
      local k = assert(keys[p[2]], "V before K")
      local nonce, plain, want = unhex(p[4]), unhex(p[5]), p[6]
      local got, opened
      assert(guarded(BUDGET, function() got = T.seal(k[1], k[2], p[3], nonce, plain) end))
      assert(hex(got) == want, "seal mismatch, len " .. #plain)
      assert(guarded(BUDGET, function() opened = T.open(k[1], k[2], p[3], got) end))
      assert(opened == plain, "open mismatch, len " .. #plain)
      -- tamper: flip one byte in nonce, ciphertext and tag; wrong direction
      for _, at in ipairs({ 1, 17, #got }) do
        local b = got:byte(at) ~ 1
        local bad = got:sub(1, at - 1) .. string.char(b) .. got:sub(at + 1)
        assert(T.open(k[1], k[2], p[3], bad) == nil, "tampered byte " .. at .. " accepted")
      end
      assert(T.open(k[1], k[2], p[3] == "Q" and "P" or "Q", got) == nil, "wrong dir accepted")
      nv = nv + 1
    end
  end
  assert(nk >= 2 and nv >= 9, "too few vectors")
  local k1 = keys["correct horse battery staple"]
  assert(T.open(k1[1], k1[2], "P", ("x"):rep(31)) == nil, "short input")
  assert(T.open(k1[1], k1[2], "P", "") == nil, "empty input")
  -- nonce(): 16 bytes from four random() calls, different each time
  local n1, n2 = T.nonce(), T.nonce()
  assert(#n1 == 16 and #n2 == 16 and n1 ~= n2, "nonce")
  -- esc / unesc / cut_utf8
  local s = "a\tb\nc\\d\u{1F600}"
  assert(not T.esc(s):find("[\t\n]"), "esc leaves raw tab/newline")
  assert(T.unesc(T.esc(s)) == s, "esc round trip")
  assert(T.esc("x\r\ny") == "x\\ny", "CR dropped")
  assert(T.unesc("a\\qb\\") == "aqb\\", "unknown escape / trailing backslash like relay")
  local cut = T.cut_utf8(("\u{E9}"):rep(600), 1000)
  assert(#cut <= 1000 and #cut == 1000 and cut:byte(#cut) ~= 0xC3, "cut on boundary")
  local cut2 = T.cut_utf8("ab" .. ("\u{1F600}"):rep(300), 1000)
  assert(#cut2 == 998, "cut drops partial 4-byte char: " .. #cut2)
  assert(T.cut_utf8("short", 1000) == "short")
  -- build_request
  local rq = T.build_request("sid1", 42, 7,
    { { conv = 3, cmid = "m1", text = "hi\tthere\n" .. ("\u{E9}"):rep(600) } }, { { conv = 2, seq = 9 } })
  local rl = {}
  for l in rq:gmatch("([^\n]*)\n") do rl[#rl + 1] = T.fields(l) end
  assert(#rl == 3 and rq:sub(-1) == "\n", "request lines")
  assert(rl[1][1] == "S" and rl[1][2] == "sid1" and rl[1][3] == "42" and rl[1][4] == "7", "S line")
  assert(rl[2][1] == "M" and rl[2][2] == "3" and rl[2][3] == "m1" and #rl[2] == 4, "M line")
  local mt = T.unesc(rl[2][4])
  assert(mt:sub(1, 9) == "hi\tthere\n" and #mt <= 1000, "M text escaped and cut")
  assert(rl[3][1] == "R" and rl[3][2] == "2" and rl[3][3] == "9", "R line")
  -- parse_reply: small hand-written reply with E, unknown line types
  local r = T.parse_reply("P\t5\nE\txmpp-offline\nZ\twhat\nC\t1\troom\tr@c.x\tA\\tB\ton\t3\n" ..
    "G\t1\t9\t100\t\tmine\\nok\nA\tc1\tok\nA\tc2\terr\toffline\nN\t9\t1\n")
  assert(r and r.q == 5 and r.offline == true and r.cursor == 9 and r.more == true, "small reply header")
  assert(#r.convs == 1 and r.convs[1].id == 1 and r.convs[1].kind == "room" and r.convs[1].name == "A\tB"
    and r.convs[1].presence == "on" and r.convs[1].unread == 3 and r.convs[1].jid == "r@c.x", "C line")
  assert(#r.msgs == 1 and r.msgs[1].sender == "" and r.msgs[1].text == "mine\nok" and r.msgs[1].seq == 9
    and r.msgs[1].ts == 100 and r.msgs[1].conv == 1, "G line")
  assert(#r.acks == 2 and r.acks[1].ok == true and r.acks[2].ok == false and r.acks[2].reason == "offline", "A lines")
  assert(T.parse_reply("N\t1\t0\n") == nil, "reply without P")
  assert(T.parse_reply("P\t1\nG\t1\t2\t3\tx\ty\n") == nil, "reply without N (truncated)")
  -- the relay-generated 6000-byte reply: seal it, then open + parse in ONE callback
  local plain = repo_file("scripts/xmpp-relay/reply_fixture.txt")
  assert(#plain > 5500 and #plain <= 6000, "fixture size " .. #plain)
  local sealed = T.seal(k1[1], k1[2], "P", T.nonce(), plain)
  local rep
  assert(guarded(BUDGET, function()
    local pt = T.open(k1[1], k1[2], "P", sealed)
    rep = pt and T.parse_reply(pt)
  end), "open + parse of the 6000-byte reply over budget")
  assert(rep, "fixture did not open/parse")
  local cost = measure(function() return T.parse_reply(T.open(k1[1], k1[2], "P", sealed)) end)
  local ocost = measure(T.open, k1[1], k1[2], "P", sealed)
  assert(rep.q == 7 and rep.offline == false and rep.more == false and rep.cursor == 110, "fixture header")
  assert(#rep.convs == 8 and #rep.acks == 2, "fixture convs/acks")
  assert(rep.acks[1].cmid == "cm-ok" and rep.acks[1].ok and rep.acks[2].reason == "not-acceptable: room\tclosed")
  assert(rep.convs[3].name == "The\tLounge" and rep.convs[5].name == "Dev \\ team", "names unescaped")
  local own, tabbed, nl, emoji, last = 0, false, false, false, 0
  for _, m in ipairs(rep.msgs) do
    assert(m.seq > last, "ascending seq"); last = m.seq
    if m.sender == "" then own = own + 1 end
    if m.sender == "hacker\twith tab" then tabbed = true end
    if m.text:find("\n", 1, true) then nl = true end
    if m.text:find("\u{1F600}", 1, true) then emoji = true end
  end
  assert(#rep.msgs >= 60 and own > 0 and tabbed and nl and emoji, "fixture messages")
  print(string.format("  %d K, %d V vectors ok; %d-byte reply: open %d, open+parse %d instructions (budget %d)",
    nk, nv, #plain, ocost, cost, BUDGET))
end

scenarios.xmpp_kdf_budget = function()
  cfg = { w = 320, h = 196, caps = { sdk_ext = true, keyboard = true, touch = false } }
  wada = build_wada()
  local T = assert(load_app()._t, "app._t missing")
  local st = T.kdf_new("correct horse battery staple")
  local calls, worst, done = 0, 0, false
  while not done do
    calls = calls + 1
    assert(calls <= 25, "kdf needs more than 25 kdf_step(st, 100) calls")
    assert(guarded(BUDGET, function() done = T.kdf_step(st, 100) end), "kdf_step over budget")
    if not done then
      local n = measure(T.kdf_step, T.kdf_new("x"), 100)
      if n > worst then worst = n end
    end
  end
  assert(wada.crypto.hex(st.enc) == "eee73a31a544ac716f9eea8c10ff8fce2c5ffac710af3758e115cdaf2b3aa849", "enc")
  assert(st.pw == nil, "passphrase kept in kdf state after done")
  assert(T.kdf_step(st, 100) == true, "done stays done")
  print(string.format("  kdf done in %d calls, ~%d instructions per kdf_step(st, 100)", calls, worst))
end

-- ---- xmpp: setup, sync engine and outbox (Task 6) --------------------------
local XM = { tick = 0, cb = 0 }   -- worst on_tick / async-callback instruction counts
local XM_URL, XM_SID = "http://relay.test:8765", "00112233aabbccdd"
local function L(...) return table.concat({ ... }, "\t") .. "\n" end

-- guarded() that also reports the instruction count (to within 100)
local function xm_metered(fn, ...)
  local n = 0
  debug.sethook(function()
    n = n + 100
    if n >= BUDGET then error("instruction budget exceeded (app tick too long)", 0) end
  end, "", 100)
  local ok, err = pcall(fn, ...)
  debug.sethook()
  if not ok then fails = fails + 1; print("  APP ERROR: " .. tostring(err)) end
  return n
end

-- tick() at the app's 250 ms timer, metering every callback
local function xm_tick(app, n, dt)
  dt = dt or 250
  for _ = 1, (n or 1) do
    clock_ms = clock_ms + dt
    if net_pending then
      local p = net_pending; net_pending = nil
      local st, reply = -1, nil
      if cfg.relay then
        local s2, r2 = cfg.relay(p.url, p.body)
        if type(s2) == "number" and s2 >= 200 and s2 < 300 then st, reply = 200, r2 end
      end
      local c = xm_metered(p.cb, st, reply)
      if c > XM.cb then XM.cb = c end
    end
    if input_pending then
      local p = input_pending; input_pending = nil
      local v = cfg.inputs and table.remove(cfg.inputs, 1)
      if v == false then v = nil end
      xm_metered(p.cb, v)
    end
    if app.on_tick then
      local c = xm_metered(app.on_tick, dt)
      if c > XM.tick then XM.tick = c end
    end
  end
end

local function xm_until(app, pred, max_ticks, what)
  for _ = 1, max_ticks or 400 do
    if pred() then return end
    xm_tick(app)
  end
  assert(pred(), "timed out waiting for " .. (what or "condition"))
end

local xm_keycache = {}
local function xm_keys(T, pw)
  pw = pw or "pw"
  if not xm_keycache[pw] then
    local e, m = xmpp_derive(T, pw)
    xm_keycache[pw] = { e, m }
  end
  return xm_keycache[pw][1], xm_keycache[pw][2]
end

local function xm_world()
  cfg = { w = 320, h = 196, caps = { sdk_ext = true, keyboard = true, touch = false } }
  wada = build_wada()
  storekv = {}
  XM.tick, XM.cb = 0, 0
end

-- the store as a finished setup leaves it
local function xm_configured_store(T)
  local e, m = xm_keys(T)
  storekv = { url = XM_URL, ek = wada.crypto.hex(e), mk = wada.crypto.hex(m), sid = XM_SID, qb = "0" }
end

-- counts wada.store.set calls per key
local function xm_count_writes()
  local w, set = {}, wada.store.set
  wada.store.set = function(k, v) w[k] = (w[k] or 0) + 1; return set(k, v) end
  return w
end

local function xm_open(app)
  assert(guarded(BUDGET, app.on_open, cfg.w, cfg.h), "on_open failed")
end

-- Relay stub: every request must open with the scenario keys; it is recorded
-- decoded ({url, at, sid, q, cursor, m = {{conv, cmid, text}}, r = {{conv, seq}}}).
-- handler(req, n) returns reply plaintext (sealed here), -1 (unreachable) or
-- { raw = bytes } sent as-is.
local function xm_relay(T, handler)
  local e, m = xm_keys(T)
  local log = {}
  cfg.relay = function(url, body)
    local pt = T.open(e, m, "Q", body)
    assert(pt, "request did not open with the scenario keys")
    local req = { url = url, at = clock_ms, m = {}, r = {}, raw = pt }
    for l in pt:gmatch("([^\n]*)\n") do
      local f = T.fields(l)
      if f[1] == "S" then req.sid, req.q, req.cursor = f[2], tonumber(f[3]), tonumber(f[4])
      elseif f[1] == "M" then req.m[#req.m + 1] = { conv = tonumber(f[2]), cmid = f[3], text = T.unesc(f[4]) }
      elseif f[1] == "R" then req.r[#req.r + 1] = { conv = tonumber(f[2]), seq = tonumber(f[3]) } end
    end
    assert(req.sid and req.q and req.cursor, "request without a valid S line")
    log[#log + 1] = req
    local out = handler(req, #log)
    if out == -1 or out == nil then return -1 end
    if type(out) == "table" then return 200, out.raw end
    return 200, T.seal(e, m, "P", T.nonce(), out)
  end
  return log
end

scenarios.xmpp_setup = function()
  xm_world()
  local app = load_app()
  local T = assert(app._t, "app._t missing")
  local e, m = xm_keys(T, "pw")
  local hex = wada.crypto.hex
  local posts = {}
  local post = wada.net.http_post
  wada.net.http_post = function(url, body, ct, cb, mr)
    posts[#posts + 1] = { url = url, ct = ct, mr = mr }
    return post(url, body, ct, cb, mr)
  end
  local log = xm_relay(T, function(req) return L("P", req.q) .. L("N", 0, 0) end)
  -- first run prompts; cancelling leaves the app in setup with nothing stored
  cfg.inputs = { false }
  xm_open(app)
  assert(T.state() == "setup" and T.header() == nil, "fresh app must be in setup")
  xm_tick(app, 3)
  assert(T.state() == "setup" and next(storekv) == nil, "cancel must leave setup and store nothing")
  -- a non-http URL is refused with a toast
  cfg.inputs = { "https://relay.test" }
  T.setup()
  xm_tick(app, 3)
  assert(T.state() == "setup" and next(storekv) == nil and #toasts > 0, "https:// URL must be refused")
  -- url .. "/w" must fit the host's 160-byte URL buffer: 158 chars refused, 157 accepted
  local long = "http://" .. ("h"):rep(151)
  assert(#long == 158)
  local nt = #toasts
  cfg.inputs = { long }
  T.setup()
  xm_tick(app, 3)
  assert(T.state() == "setup" and next(storekv) == nil and #toasts == nt + 1, "158-char URL must be refused")
  cfg.inputs = { long:sub(1, 157), false }
  T.setup()
  xm_tick(app, 1)
  assert(input_pending and input_pending.title == "Passphrase", "157-char URL must be accepted")
  xm_tick(app, 2)
  assert(T.state() == "setup" and next(storekv) == nil, "cancelled passphrase stores nothing")
  -- real setup, URL with a trailing slash
  cfg.inputs = { XM_URL .. "/", "pw" }
  T.setup()
  local seen, kdf_ticks = { T.state() }, 0
  xm_until(app, function()
    local s = T.state()
    if s == "deriving" then kdf_ticks = kdf_ticks + 1 end
    if seen[#seen] ~= s then seen[#seen + 1] = s end
    return s == "connecting"
  end, 60, "connecting after the KDF")
  print(string.format("  states %s; KDF in %d ticks, worst tick ~%d instructions (budget %d)",
    table.concat(seen, " > "), kdf_ticks, XM.tick, BUDGET))
  assert(table.concat(seen, ",") == "setup,deriving,connecting", "state sequence " .. table.concat(seen, ","))
  assert(storekv.url == XM_URL, "url stored without the trailing slash: " .. tostring(storekv.url))
  assert(storekv.ek == hex(e) and storekv.mk == hex(m), "derived keys stored as hex")
  assert(type(storekv.sid) == "string" and #storekv.sid == 16 and storekv.sid:match("^[0-9a-f]+$"), "sid: " .. tostring(storekv.sid))
  assert(storekv.qb == "1000", "qb reserved: " .. tostring(storekv.qb))
  for k, v in pairs(storekv) do
    assert(not tostring(v):find("pw", 1, true), "passphrase leaked into store key " .. k)
  end
  assert(T.header() == "Connecting…", "header before the first reply " .. tostring(T.header()))
  xm_until(app, function() return #log >= 1 end, 4, "first request")
  assert(log[1].url == XM_URL .. "/w" and log[1].sid == storekv.sid and log[1].cursor == 0 and log[1].q == 0,
    "first request " .. log[1].url .. " q=" .. log[1].q)
  assert(posts[1].ct == "application/octet-stream" and posts[1].mr == 8192, "content type / max_reply")
  xm_until(app, function() return net_pending == nil end, 4)
  assert(T.state() == "online" and T.header() == "Online", "first reply: " .. tostring(T.header()))
  -- reopen: no prompt, same sid, q from the next reserved block
  xm_until(app, function() return net_pending == nil end, 4)
  if app.on_close then guarded(BUDGET, app.on_close) end
  local sid = storekv.sid
  local app2 = load_app()
  cfg.inputs = {}
  xm_open(app2)
  assert(app2._t.state() == "connecting", "configured app opens connecting")
  xm_until(app2, function() return #log >= 2 end, 4, "request after reopen")
  assert(log[2].sid == sid and log[2].q == 1000 and storekv.qb == "2000", "reopen q " .. log[2].q)
  -- Reset forgets keys and makes a new sid at the next setup
  xm_until(app2, function() return net_pending == nil end, 4)
  app2._t.reset()
  assert(app2._t.state() == "setup" and (storekv.ek or "") == "" and (storekv.mk or "") == "", "reset keeps keys")
  cfg.inputs = { XM_URL, "pw" }
  app2._t.setup()
  xm_until(app2, function() return #log >= 3 end, 60, "request after re-setup")
  assert(log[3].sid ~= sid and #storekv.sid == 16, "Reset must regenerate sid")
  print("  setup, reopen and reset ok")
end

scenarios.xmpp_sync = function()
  xm_world()
  local app = load_app()
  local T = app._t
  xm_configured_store(T)
  local writes = xm_count_writes()
  local mode = "script"
  local log = xm_relay(T, function(req, n)
    if mode == "more" then return L("P", req.q) .. L("N", 41, 1) end
    if n == 1 then
      return L("P", req.q) .. L("C", 1, "chat", "alice@x.test", "Alice", "on", 2)
        .. L("C", "x", "chat", "bad@x.test", "Bad", "on", 0)          -- malformed id: skipped
        .. L("G", 1, 40, 1700000000, "alice@x.test", "hi\\tthere")
        .. L("G", 1, "zz", 1700000001, "alice@x.test", "bad seq")    -- malformed seq: skipped
        .. L("G", 99, 41, 1700000002, "who", "unknown conv")         -- unknown conv: dropped
        .. L("G", 1, 41, 1700000003, "", "mine")
        .. L("N", 41, 0)
    elseif n == 2 then
      return L("P", req.q) .. L("N", 41, 1)
    end
    return L("P", req.q) .. L("N", 41, 0)
  end)
  xm_open(app)
  assert(T.state() == "connecting" and T.header() == "Connecting…", "configured app opens connecting")
  xm_until(app, function() return #log >= 1 end, 4, "first request")
  assert(log[1].cursor == 0 and log[1].q == 0 and log[1].sid == XM_SID, "first request S line")
  xm_until(app, function() return #log >= 2 end, 40, "second request")
  local gap = log[2].at - log[1].at
  assert(log[2].cursor == 41, "cursor after N 41: " .. log[2].cursor)
  assert(gap >= 5000 and gap <= 5500, "poll gap " .. gap)
  local cs = T.convs()
  assert(#cs == 1 and cs[1].id == 1 and cs[1].name == "Alice" and cs[1].unread == 2 and cs[1].presence == "on"
    and cs[1].kind == "chat" and cs[1].jid == "alice@x.test", "conversation from C line")
  local ms = T.msgs(1)
  assert(#ms == 2 and ms[1].seq == 40 and ms[1].text == "hi\tthere" and ms[1].sender == "alice@x.test"
    and ms[1].ts == 1700000000 and ms[2].seq == 41 and ms[2].sender == "" and ms[2].text == "mine", "messages")
  assert(#T.msgs(99) == 0 and #T.msgs(1234) == 0, "unknown conversation must stay empty")
  -- more = 1: the next request follows on the next tick
  xm_until(app, function() return #log >= 3 end, 2, "more=1 resync")
  assert(log[3].at - log[2].at <= 250, "more=1 gap " .. (log[3].at - log[2].at))
  XM.tick = 0
  xm_until(app, function() return #log >= 50 end, 50 * 25, "50 syncs")
  for i = 2, #log do assert(log[i].q == log[i - 1].q + 1, "q must increase by one") end
  assert(writes.qb == 1 and storekv.qb == "1000", "qb written " .. tostring(writes.qb) .. " times in 50 syncs")
  for k, v in pairs(writes) do assert(k == "qb", "store written during sync: " .. k) end
  print(string.format("  50 syncs, qb written once; steady on_tick worst ~%d, reply callback worst ~%d instructions",
    XM.tick, XM.cb))
  assert(XM.tick < 25000, "steady-state tick too expensive: " .. XM.tick)
  -- mark_read: unread cleared now, R sent once with the newest seq
  T.mark_read(1)
  assert(T.convs()[1].unread == 0, "mark_read clears unread")
  local n0 = #log
  xm_until(app, function() return #log > n0 + 1 end, 60, "two syncs after mark_read")
  assert(#log[n0 + 1].r == 1 and log[n0 + 1].r[1].conv == 1 and log[n0 + 1].r[1].seq == 41, "R line")
  assert(#log[n0 + 2].r == 0, "R must not repeat after a successful sync")
  -- qb rollover: back-to-back syncs (more = 1) past the reserved block
  mode = "more"
  xm_until(app, function() return #log > 0 and log[#log].q >= 1001 end, 1200, "q past 1000")
  assert(writes.qb == 2 and storekv.qb == "2000", "second block reserved once: " .. writes.qb .. " " .. storekv.qb)
  mode = "idle"
  xm_until(app, function() return net_pending == nil end, 4)
  xm_tick(app, 2)
  if app.on_close then guarded(BUDGET, app.on_close) end
  local app2 = load_app()
  xm_open(app2)
  local n1 = #log
  xm_until(app2, function() return #log > n1 end, 4, "request after reopen")
  assert(log[#log].q == 2000 and log[#log].cursor == 0 and storekv.qb == "3000", "reopen: q from qb, cursor 0")
  print("  qb blocks ok; reopen starts at q " .. log[#log].q)
end

scenarios.xmpp_failures = function()
  xm_world()
  local app = load_app()
  local T = app._t
  xm_configured_store(T)
  local e, m = xm_keys(T)
  local mode = "down"
  local log = xm_relay(T, function(req)
    if mode == "down" then return -1 end
    if mode == "denied" then return { raw = "DENIED" } end
    if mode == "badtag" then
      local s = T.seal(e, m, "P", T.nonce(), L("P", req.q) .. L("N", 0, 0))
      return { raw = s:sub(1, -2) .. string.char(s:byte(-1) ~ 1) }
    end
    if mode == "wrongq" then
      return L("P", req.q + 5) .. L("C", 1, "chat", "a@x.test", "A", "on", 0) .. L("N", 9, 0)
    end
    if mode == "offline" then return L("P", req.q) .. "E\txmpp-offline\n" .. L("N", 0, 0) end
    return L("P", req.q) .. L("N", 0, 0)
  end)
  xm_open(app)
  -- six failures at the normal 5 s interval, then back off to 30 s
  xm_until(app, function() return #log >= 6 end, 6 * 25, "six failed requests")
  for i = 2, 6 do
    local gap = log[i].at - log[i - 1].at
    assert(gap >= 5000 and gap <= 5500, "retry gap " .. i .. ": " .. gap)
  end
  assert(T.state() == "unreachable" and T.header() == "Relay unreachable", "header " .. tostring(T.header()))
  xm_until(app, function() return #log >= 7 end, 32000 // 250, "seventh request")
  assert(log[7].at - log[6].at >= 30000, "backoff gap " .. (log[7].at - log[6].at))
  mode = "ok"
  xm_until(app, function() return #log >= 9 end, 40000 // 250, "recovery")
  assert(T.header() == "Online", "recovered header " .. tostring(T.header()))
  assert(log[9].at - log[8].at <= 5500, "interval back to 5 s after success")
  -- E xmpp-offline
  mode = "offline"
  local n = #log
  xm_until(app, function() return #log > n end, 25)
  assert(T.state() == "xmpp_offline" and T.header() == "Relay offline from XMPP", "offline header " .. tostring(T.header()))
  -- three bad tags in a row
  mode = "badtag"
  n = #log
  xm_until(app, function() return #log >= n + 2 end, 50)
  assert(T.header() ~= "Relay reply corrupted", "two bad replies must not say corrupted yet")
  xm_until(app, function() return #log >= n + 3 end, 25)
  assert(T.header() == "Relay reply corrupted", "three bad replies: " .. tostring(T.header()))
  mode = "ok"
  n = #log
  xm_until(app, function() return #log > n end, 25)
  assert(T.header() == "Online", "good reply clears corrupted")
  -- reply echoing the wrong q: dropped
  mode = "wrongq"
  n = #log
  xm_until(app, function() return #log > n end, 25)
  assert(#T.convs() == 0, "reply with the wrong q must be dropped")
  assert(T.header() ~= "Online", "wrong q counts as a bad reply")
  mode = "ok"
  xm_until(app, function() return #log > n + 1 end, 25)
  assert(log[n + 2].cursor == 0, "cursor must not move on a dropped reply: " .. log[n + 2].cursor)
  -- DENIED: no further requests until settings change
  mode = "denied"
  n = #log
  xm_until(app, function() return #log > n end, 25)
  assert(T.state() == "denied" and T.header() == "Passphrase rejected — check Settings", "denied header " .. tostring(T.header()))
  n = #log
  xm_tick(app, 200000 // 250)
  assert(#log == n, "requests after DENIED: " .. (#log - n))
  mode = "ok"
  cfg.inputs = { XM_URL, "pw" }
  T.setup()
  xm_until(app, function() return #log > n end, 60, "polling resumes after setup")
  xm_tick(app, 2)
  assert(T.header() == "Online", "online after new settings")
  print("  backoff, DENIED, corrupted, wrong q and xmpp-offline ok")
end

-- http_post itself raising: the busy error just waits, anything else is a failure
scenarios.xmpp_post_raises = function()
  xm_world()
  local app = load_app()
  local T = app._t
  xm_configured_store(T)
  local calls, err = {}, "no memory for the reply buffer"
  wada.net.http_post = function() calls[#calls + 1] = clock_ms; error(err) end
  xm_open(app)
  xm_until(app, function() return #calls >= 6 end, 6 * 25, "six raising posts")
  for i = 2, 6 do
    local gap = calls[i] - calls[i - 1]
    assert(gap >= 5000 and gap <= 5500, "retry gap " .. i .. ": " .. gap)
  end
  assert(T.state() == "unreachable" and T.header() == "Relay unreachable", "header " .. tostring(T.header()))
  xm_until(app, function() return #calls >= 7 end, 32000 // 250, "seventh post")
  assert(calls[7] - calls[6] >= 30000, "backoff gap " .. (calls[7] - calls[6]))
  -- busy: not a failure, state untouched
  xm_world()
  app = load_app()
  T = app._t
  xm_configured_store(T)
  calls, err = {}, "a fetch is already running"
  wada.net.http_post = function() calls[#calls + 1] = clock_ms; error(err) end
  xm_open(app)
  xm_until(app, function() return #calls >= 8 end, 8 * 25, "busy posts")
  -- no reply ever arrives, so the header stays "Connecting…" (R7), never "unreachable"
  assert(T.state() == "connecting" and T.header() == "Connecting…", "busy must not count as a failure: " .. tostring(T.header()))
  assert(calls[8] - calls[7] <= 5500, "no backoff while busy")
  print("  raising http_post: backoff + unreachable; busy: retried, still connecting")
end

scenarios.xmpp_relay_reset = function()
  xm_world()
  local app = load_app()
  local T = app._t
  xm_configured_store(T)
  local log = xm_relay(T, function(req, n)
    if n == 1 then
      return L("P", req.q) .. L("C", 1, "chat", "a@x.test", "A", "on", 1) .. L("C", 2, "room", "r@c.x.test", "Room", "on", 0)
        .. L("G", 1, 41, 1700000000, "a@x.test", "old") .. L("N", 41, 0)
    elseif n == 2 then
      return L("P", req.q) .. L("C", 3, "chat", "z@x.test", "Z", "on", 0) .. L("N", 7, 0)
    elseif n == 3 then
      return L("P", req.q) .. L("C", 1, "chat", "a@x.test", "A", "on", 1) .. L("G", 1, 5, 1700000100, "a@x.test", "new")
        .. L("N", 7, 0)
    end
    return L("P", req.q) .. L("N", 7, 0)
  end)
  xm_open(app)
  xm_until(app, function() return #log >= 1 and net_pending == nil end, 4)
  assert(#T.convs() == 2 and #T.msgs(1) == 1, "two conversations after the first sync")
  xm_until(app, function() return #log >= 2 end, 40)
  assert(log[2].cursor == 41, "cursor 41: " .. log[2].cursor)
  assert(#T.convs() == 0 and #T.msgs(1) == 0, "relay behind the device must clear the view")
  xm_until(app, function() return #log >= 3 end, 2, "immediate resync from 0")
  assert(log[3].cursor == 0, "resync cursor " .. log[3].cursor)
  xm_until(app, function() return #log >= 4 end, 40)
  assert(log[4].cursor == 7, "cursor after resync " .. log[4].cursor)
  local ms = T.msgs(1)
  assert(#T.convs() == 1 and #ms == 1 and ms[1].seq == 5 and ms[1].text == "new", "view rebuilt from the relay")
  print("  relay reset detected, resynced from 0")
end

scenarios.xmpp_outbox = function()
  xm_world()
  local app = load_app()
  local T = app._t
  xm_configured_store(T)
  local writes = xm_count_writes()
  local mode = "down"
  local delivered, ndelivered = {}, 0   -- relay-side cmid dedupe
  local log = xm_relay(T, function(req)
    if mode == "down" then return -1 end
    local out = L("P", req.q)
    for _, mm in ipairs(req.m) do
      if not delivered[mm.cmid] then delivered[mm.cmid] = mm.text; ndelivered = ndelivered + 1 end
      if mode == "err" then out = out .. L("A", mm.cmid, "err", "room\\tclosed")
      elseif mode == "errblank" then out = out .. L("A", mm.cmid, "err", "")
      else out = out .. L("A", mm.cmid, "ok") end
    end
    return out .. L("N", 0, 0)
  end)
  local function m_lines(s)
    local t = {}
    for l in ((s or "") ~= "" and (s .. "\n") or ""):gmatch("([^\n]*)\n") do t[#t + 1] = T.fields(l) end
    return t
  end
  xm_open(app)
  xm_until(app, function() return #log >= 1 and net_pending == nil end, 4, "first (failing) request")
  local text = "hello\tworld\nline \u{1F600}"
  local cmid = T.send(1, text)
  assert(type(cmid) == "string" and #cmid == 8 and cmid:match("^[0-9a-f]+$"), "cmid " .. tostring(cmid))
  local ol = m_lines(storekv.out)
  assert(#ol == 1 and ol[1][1] == "M" and ol[1][2] == "1" and ol[1][3] == cmid and T.unesc(ol[1][4]) == text,
    "out holds one M line: " .. tostring(storekv.out))
  assert(writes.out == 1, "out written once on send")
  local p = T.pending(1)
  assert(#p == 1 and p[1].cmid == cmid and p[1].text == text and not p[1].err, "pending entry")
  xm_until(app, function() return #log >= 2 and net_pending == nil end, 25, "request carrying M")
  assert(#log[2].m == 1 and log[2].m[1].cmid == cmid and log[2].m[1].text == text and log[2].m[1].conv == 1,
    "M line sent")
  assert(log[2].at - log[1].at < 5000, "a send syncs right away")
  -- app closes before the ack; a new session resends the same cmid
  if app.on_close then guarded(BUDGET, app.on_close) end
  local app2 = load_app()
  local T2 = app2._t
  mode = "ok"
  xm_open(app2)
  assert(#T2.pending(1) == 1, "outbox restored from store")
  xm_until(app2, function() return #log >= 3 and net_pending == nil end, 4, "resend")
  assert(#log[3].m == 1 and log[3].m[1].cmid == cmid, "resent with the same cmid")
  assert((storekv.out or "") == "", "ack ok empties out: " .. tostring(storekv.out))
  assert(#T2.pending(1) == 0, "acked send no longer pending")
  local total = 0
  for _, r in ipairs(log) do for _, mm in ipairs(r.m) do if mm.cmid == cmid then total = total + 1 end end end
  assert(total == 2 and ndelivered == 1, "M lines for cmid: " .. total .. ", relay messages " .. ndelivered)
  assert(writes.out == 2, "out written on send and on ack only: " .. writes.out)
  xm_until(app2, function() return #log >= 4 end, 25)
  assert(#log[4].m == 0, "nothing resent after the ack")
  -- error acks: removed from out, kept as failed with the reason ("" = none)
  mode = "err"
  local c2 = T2.send(1, "x")
  xm_until(app2, function() return net_pending == nil and (storekv.out or "") == "" end, 25, "err ack")
  p = T2.pending(1)
  assert(#p == 1 and p[1].cmid == c2 and p[1].err and p[1].reason == "room\tclosed", "err ack kept with reason")
  mode = "errblank"
  local c3 = T2.send(2, "y")
  assert(c3 ~= c2 and c3 ~= cmid, "cmid unique per session")
  xm_until(app2, function() return net_pending == nil and (storekv.out or "") == "" end, 25, "blank err ack")
  p = T2.pending(2)
  assert(#p == 1 and p[1].err and p[1].reason == nil, "empty reason is no reason")
  -- overflow: out stays <= 1024 bytes, refused with a toast
  mode = "down"
  assert(T2.send(1, "") == nil, "empty text refused")
  local big = ("a"):rep(300)
  local nt = #toasts
  local ok_sends = 0
  for _ = 1, 5 do if T2.send(3, big) then ok_sends = ok_sends + 1 end end
  assert(ok_sends == 3 and #toasts == nt + 2, "sends accepted " .. ok_sends .. ", toasts " .. (#toasts - nt))
  assert(#storekv.out <= 1024 and #m_lines(storekv.out) == 3, "out size " .. #storekv.out)
  local r1, why = T2.send(3, big)
  assert(r1 == nil and type(why) == "string", "overflow returns nil + reason")
  print("  outbox persisted, resent once, acked; err/overflow ok")
end

scenarios.xmpp_bounds = function()
  xm_world()
  local app = load_app()
  local T = app._t
  xm_configured_store(T)
  local parts = {}
  local log = xm_relay(T, function(req, n)
    if n > 1 then return L("P", req.q) .. L("N", 200, 0) end
    parts = { L("P", req.q) }
    for i = 1, 45 do parts[#parts + 1] = L("C", i, "chat", "u" .. i .. "@x.test", "U" .. i, "on", i == 10 and 5 or 0) end
    for i = 1, 45 do parts[#parts + 1] = L("G", i, i, 1700000000 + i, "u" .. i .. "@x.test", "m" .. i) end
    for s = 100, 159 do parts[#parts + 1] = L("G", 45, s, 1700000000 + s, "u45@x.test", "n" .. s) end
    parts[#parts + 1] = L("N", 200, 0)
    return table.concat(parts)
  end)
  xm_open(app)
  xm_until(app, function() return #log >= 1 and net_pending == nil end, 4)
  local cs = T.convs()
  assert(#cs == 40, "conversations kept: " .. #cs)
  local have = {}
  for _, c in ipairs(cs) do have[c.id] = true end
  for i = 1, 5 do assert(not have[i], "least recent conversation " .. i .. " must be dropped") end
  assert(cs[1].id == 10 and cs[2].id == 45 and cs[3].id == 44, "order: unread first, then most recent")
  local ms = T.msgs(45)
  assert(#ms == 50 and ms[1].seq == 110 and ms[50].seq == 159, "50 newest messages kept: " .. #ms)
  print(string.format("  bounds ok; %d-byte reply processed in ~%d instructions", #table.concat(parts), XM.cb))
  -- the relay's 6000-byte fixture (q = 7) in one callback
  xm_world()
  app = load_app()
  T = app._t
  xm_configured_store(T)
  storekv.qb = "7"
  local plain = repo_file("scripts/xmpp-relay/reply_fixture.txt")
  log = xm_relay(T, function(req) return req.q == 7 and plain or (L("P", req.q) .. L("N", 110, 0)) end)
  xm_open(app)
  xm_until(app, function() return #log >= 1 and net_pending == nil end, 4)
  assert(T.header() == "Online" and #T.convs() == 8, "fixture applied: " .. #T.convs() .. " convs, " .. tostring(T.header()))
  print(string.format("  6000-byte fixture reply processed in ~%d instructions (budget %d)", XM.cb, BUDGET))
  assert(XM.cb < BUDGET)
end

-- ---- xmpp: screens (Task 7) -------------------------------------------------
local XM_EMPTY = "No contacts or rooms yet. Add contacts or bookmark rooms from another XMPP client."

local function xm_ui_world(w, h, caps)
  xm_world()
  cfg.w, cfg.h = w, h
  for k, v in pairs(caps or {}) do cfg.caps[k] = v end
  wada = build_wada()
end

-- the one list on the current screen (nil when there is none)
local function xm_list()
  assert(#lists <= 1, "one list per screen, found " .. #lists)
  return lists[1]
end
local function xm_rows()
  local l, t = xm_list(), {}
  if l then for i, r in ipairs(l.rows) do t[i] = r.text end end
  return t
end
local function xm_row_is(i, text)
  local r = xm_rows()
  assert(r[i] == text, string.format("row %d: expected %q, got %q (rows: %s)", i, text, tostring(r[i]),
    table.concat(r, " / ")))
end
-- what enter on a focused row (or a tap) does: run that row's callback
local function xm_pick(i)
  local l = assert(xm_list(), "no list on screen: " .. label_dump())
  local r = assert(l.rows[i], "no row " .. i)
  assert(r.fn, "row " .. i .. " (" .. r.text .. ") does nothing")
  local c = xm_metered(r.fn)
  if c > XM.cb then XM.cb = c end
end
local function xm_pick_text(text)
  for i, t in ipairs(xm_rows()) do if t == text or t:sub(1, #text) == text then return xm_pick(i) end end
  error("no row starting with '" .. text .. "': " .. table.concat(xm_rows(), " / "))
end
local function xm_label(text)
  for _, l in ipairs(labels) do if not l.is_button and l.text == text then return l end end
  return nil
end
local function xm_screen_text()
  return label_dump() .. " || " .. table.concat(xm_rows(), " / ")
end

-- Every widget inside the screen, none overlapping another; on keyboard boards
-- buttons come first in focus order and sit above the list.
local function xm_assert_layout(where)
  local W, H = cfg.w, cfg.h
  local boxes = {}
  for _, l in ipairs(labels) do
    if l.text ~= "" then
      local bw, bh
      if l.is_button then
        bw, bh = l.bw, l.bh
      else
        local size = l.size or 12
        bw = l.w or wada.ui.text_w(l.text, size)
        local lines = l.w and wada.ui.text_lines(l.text, l.w, size) or select(2, l.text:gsub("\n", "")) + 1
        bh = lines * wada.ui.text_h(size)
        if not l.w then assert(bw <= W - l.x, where .. ": unwrapped label runs off the screen: " .. l.text) end
      end
      boxes[#boxes + 1] = { what = (l.is_button and "button '" or "label '") .. l.text:sub(1, 30) .. "'",
                            x = l.x, y = l.y, w = bw, h = bh }
    end
  end
  for _, l in ipairs(lists) do boxes[#boxes + 1] = { what = "list", x = l.x, y = l.y, w = l.w, h = l.h } end
  for i, b in ipairs(boxes) do
    assert(b.x >= 0 and b.y >= 0 and b.x + b.w <= W and b.y + b.h <= H,
      string.format("%s: %s outside %dx%d at %d,%d %dx%d", where, b.what, W, H, b.x, b.y, b.w, b.h))
    for j = i + 1, #boxes do
      local o = boxes[j]
      local apart = b.x + b.w <= o.x or o.x + o.w <= b.x or b.y + b.h <= o.y or o.y + o.h <= b.y
      assert(apart, string.format("%s: %s overlaps %s", where, b.what, o.what))
    end
  end
  local stops = #buttons
  for _, l in ipairs(lists) do
    stops = stops + #l.rows
    for _, b in ipairs(buttons) do
      assert(b.seq < l.seq, where .. ": the '" .. b.text .. "' button comes after the list in focus order")
      assert(b.y + b.bh <= l.y, where .. ": the '" .. b.text .. "' button is not above the list")
    end
  end
  assert(stops < 160, where .. ": " .. stops .. " focus stops")
end

-- canned account: Alice has 2 unread, Bob is away, a room, and Dave offline with no messages
local function xm_account(req)
  return L("P", req.q)
    .. L("C", 1, "chat", "alice@x.test", "Alice", "on", 2)
    .. L("C", 2, "chat", "bob@x.test", "Bob", "away", 0)
    .. L("C", 3, "room", "lounge@conf.x.test", "Lounge", "on", 0)
    .. L("C", 4, "chat", "dave@x.test", "Dave", "off", 0)
    .. L("G", 1, 10, 1700000000, "alice@x.test", "hello")
    .. L("G", 3, 11, 1700000001, "carol", "hey all")
    .. L("G", 3, 12, 1700000002, "", "me too")
    .. L("G", 2, 13, 1700000003, "bob@x.test", "yo")
    .. L("G", 2, 14, 1700000004, "bob@x.test", "you there?")
    .. L("N", 14, 0)
end

scenarios.xmpp_chat = function()
  xm_ui_world(320, 240, { touch = true, keyboard = false })
  local app = load_app()
  local T = app._t
  xm_configured_store(T)
  local mode, seq = "noack", 14
  local log = xm_relay(T, function(req, n)
    if n == 1 then return xm_account(req) end
    local out = L("P", req.q)
    for _, mm in ipairs(req.m) do
      if mode == "ack" then
        seq = seq + 1
        out = out .. L("A", mm.cmid, "ok") .. L("G", mm.conv, seq, 1700000100, "", T.esc(mm.text))
      elseif mode == "err" then
        out = out .. L("A", mm.cmid, "err", "recipient unavailable")
      end
    end
    return out .. L("N", seq, 0)
  end)
  xm_open(app)
  -- R7: "Connecting…" from session start until the first reply
  assert(T.state() == "connecting" and xm_label("Connecting…"), "header before the first reply: " .. xm_screen_text())
  assert(#xm_rows() == 0 and not xm_label(XM_EMPTY), "nothing listed before the first reply")
  xm_until(app, function() return #log >= 1 and net_pending == nil end, 4, "first reply")
  xm_tick(app)
  assert(xm_label("Online"), "header after the first reply: " .. xm_screen_text())
  assert(has_button("Settings"), "list screen has Settings")
  local rows = xm_rows()
  assert(#rows == 4, "four conversations: " .. table.concat(rows, " / "))
  xm_row_is(1, "• Alice  (2)")      -- unread first
  xm_row_is(2, "~ Bob")             -- then latest message seq (14)
  xm_row_is(3, "# Lounge")          -- (12)
  xm_row_is(4, "- Dave")            -- (no messages)
  xm_assert_layout("list")
  -- open Alice: header = name, plain rows, R for the newest seq on the next request
  xm_pick(1)
  assert(xm_label("Alice") and has_button("Write") and has_button("Back"), "chat screen: " .. xm_screen_text())
  assert(table.concat(xm_rows(), "|") == "hello", "chat rows: " .. table.concat(xm_rows(), " / "))
  xm_assert_layout("chat")
  local n = #log
  xm_until(app, function() return #log > n end, 25, "request after opening")
  assert(#log[#log].r == 1 and log[#log].r[1].conv == 1 and log[#log].r[1].seq == 10, "R 1 10 sent")
  assert(log[#log].raw:find("\nR\t1\t10\n", 1, true), "R line in the request")
  press("Back")
  xm_tick(app)
  xm_row_is(1, "~ Bob")
  xm_row_is(3, "• Alice")         -- read: no count, back in activity order
  -- a room: sender prefix, own messages "> " in the accent colour
  xm_pick_text("# Lounge")
  assert(xm_label("Lounge"), "room header")
  xm_row_is(1, "carol: hey all")
  xm_row_is(2, "> me too")
  local l = xm_list()
  assert(l.rows[2].color == wada.ui.colors.accent, "own message in the accent colour")
  assert(l.rows[1].color ~= wada.ui.colors.accent, "others not in the accent colour")
  press("Back")
  -- Write in a chat: pending " …" until A ok, then the relay's copy only
  xm_pick_text("~ Bob")
  xm_row_is(1, "yo")
  xm_row_is(2, "you there?")
  cfg.inputs = { false }
  press("Write")
  assert(input_pending and input_pending.title == "Message" and input_pending.initial == "", "Write prompt")
  xm_tick(app)
  assert(#xm_rows() == 2 and #T.pending(2) == 0, "cancelled Write sends nothing")
  cfg.inputs = { "hi\tthere" }
  press("Write")
  n = #log
  xm_tick(app)
  xm_row_is(3, "> hi\tthere …")
  assert(xm_list().rows[3].color == wada.ui.colors.accent, "pending own row in the accent colour")
  xm_until(app, function() return #log > n and net_pending == nil end, 4, "request carrying M")
  xm_tick(app)
  local cmid = T.pending(2)[1].cmid
  assert(log[#log].raw:find("\nM\t2\t" .. cmid .. "\thi\\tthere\n", 1, true), "escaped M line: " .. log[#log].raw)
  xm_row_is(3, "> hi\tthere …")   -- no ack yet
  mode = "ack"
  n = #log
  xm_until(app, function() return #log > n and net_pending == nil end, 25, "acked request")
  xm_tick(app)
  assert(#xm_rows() == 3, "one copy after the ack: " .. table.concat(xm_rows(), " / "))
  xm_row_is(3, "> hi\tthere")
  assert(xm_list().rows[3].color == wada.ui.colors.accent, "confirmed own row in the accent colour")
  -- a refused send keeps its reason
  mode = "err"
  cfg.inputs = { "nope" }
  press("Write")
  n = #log
  xm_until(app, function() return #log > n and net_pending == nil end, 25, "err ack")
  xm_tick(app)
  xm_row_is(4, "> nope ! recipient unavailable")
  xm_assert_layout("chat after sends")
  print(string.format("  list order, chat rows, Write, ack and err ok; worst tick ~%d, worst callback ~%d", XM.tick, XM.cb))
end

scenarios.xmpp_empty = function()
  xm_ui_world(320, 240, { touch = true, keyboard = false })
  local app = load_app()
  local T = app._t
  xm_configured_store(T)
  local full = false
  local log = xm_relay(T, function(req)
    if full then return xm_account(req) end
    return L("P", req.q) .. L("N", 0, 0)
  end)
  xm_open(app)
  assert(not xm_label(XM_EMPTY), "no empty-state text before the relay answered")
  xm_until(app, function() return #log >= 1 and net_pending == nil end, 4)
  xm_tick(app)
  local lb = xm_label(XM_EMPTY)
  assert(lb, "empty-state label: " .. xm_screen_text())
  assert(lb.w and lb.w <= cfg.w, "empty-state text wraps inside the screen")
  assert(has_button("Settings"), "Settings reachable from the empty list")
  xm_assert_layout("empty")
  full = true
  local n = #log
  xm_until(app, function() return #log > n and net_pending == nil end, 25)
  xm_tick(app)
  assert(not xm_label(XM_EMPTY) and #xm_rows() == 4, "conversations replace the empty state: " .. xm_screen_text())
  print("  empty state shown, then replaced")
end

-- Heltec V4: 240x276 portrait, touch, no extended SDK (so no SD option)
scenarios.xmpp_v4 = function()
  xm_ui_world(240, 276, { touch = true, keyboard = false, sdk_ext = false })
  local app = load_app()
  local T = app._t
  xm_configured_store(T)
  local denied = false
  local long = ("a really long message that goes on "):rep(8)
  local log = xm_relay(T, function(req, n)
    if denied then return { raw = "DENIED" } end
    if n == 1 then
      return L("P", req.q) .. L("C", 1, "room", "r@c.x.test", "A room with an unusually long name for this screen", "on", 120)
        .. L("C", 2, "chat", "b@x.test", "B", "on", 0)
        .. L("G", 1, 5, 1700000000, "somebody-with-a-long-nick", long) .. L("N", 5, 0)
    end
    return L("P", req.q) .. L("N", 5, 0)
  end)
  xm_open(app)
  xm_assert_layout("v4 connecting")
  xm_until(app, function() return #log >= 1 and net_pending == nil end, 4)
  xm_tick(app)
  xm_row_is(1, "# A room with an unusually long name for this screen  (120)")
  xm_assert_layout("v4 list")
  xm_pick(1)
  xm_row_is(1, "somebody-with-a-long-nick: " .. long)   -- the list row wraps on device
  xm_assert_layout("v4 chat")
  press("Back")
  press("Settings")
  local rows = table.concat(xm_rows(), "|")
  assert(rows == "Relay URL|Passphrase|Reset", "V4 settings rows: " .. rows)
  assert(not xm_label("Stored unencrypted on the card."), "no SD description without sdk_ext")
  xm_assert_layout("v4 settings")
  press("Back")
  -- the longest header still fits beside the Settings button
  denied = true
  local n = #log
  xm_until(app, function() return #log > n and net_pending == nil end, 25)
  xm_tick(app)
  assert(xm_label("Passphrase rejected — check Settings"), "denied header: " .. xm_screen_text())
  xm_assert_layout("v4 denied")
  print("  V4 list, chat, settings and long header fit; no SD option")
end

-- ThinkNode M9: 320x196, keyboard/trackball, no touch
scenarios.xmpp_m9 = function()
  xm_ui_world(320, 196, { touch = false, keyboard = true, sdk_ext = true })
  local app = load_app()
  local T = app._t
  xm_configured_store(T)
  local log = xm_relay(T, function(req)
    if req.cursor == 0 then return xm_account(req) end   -- every new session starts from 0
    return L("P", req.q) .. L("N", 14, 0)
  end)
  xm_open(app)
  xm_until(app, function() return #log >= 1 and net_pending == nil end, 4)
  xm_tick(app)
  assert(#xm_rows() == 4, "list built: " .. xm_screen_text())
  for i = 1, 4 do assert(xm_list().rows[i].fn, "conversation row " .. i .. " is not pressable") end
  assert(has_button("Settings"), "Settings is a button")
  xm_assert_layout("m9 list")
  -- The firmware only runs its own focus navigation (arrows move between
  -- buttons and list rows, enter presses) for apps WITHOUT on_input; declaring
  -- one routes every key to the app instead (UITask.cpp, luaAppHasOnInput).
  -- key() here does not model that gate, so assert it directly.
  assert(app.on_input == nil, "on_input would switch off keyboard navigation on the M9")
  -- enter on a focused row opens it; the Back button returns
  xm_pick(2)
  assert(xm_label("Bob") and #xm_rows() == 2, "chat built: " .. xm_screen_text())
  assert(has_button("Back") and has_button("Write"), "chat actions are buttons")
  xm_assert_layout("m9 chat")
  press("Back")
  assert(has_button("Settings") and #xm_rows() == 4, "Back returns to the list: " .. xm_screen_text())
  press("Settings")
  xm_assert_layout("m9 settings")
  xm_row_is(1, "Relay URL")
  xm_row_is(2, "Passphrase")
  xm_row_is(3, "Keep history on SD card: Off")
  xm_row_is(4, "Reset")
  for i = 1, 4 do assert(xm_list().rows[i].fn, "settings row " .. i .. " is not pressable") end
  assert(has_button("Back"), "settings Back is a button")
  assert(xm_label("Stored unencrypted on the card."), "SD description: " .. xm_screen_text())
  xm_pick(3)
  assert(storekv.sd == "1", "SD on stores sd=1")
  xm_row_is(3, "Keep history on SD card: On")
  xm_pick(3)
  assert(storekv.sd == "0", "SD off stores sd=0")
  xm_row_is(3, "Keep history on SD card: Off")
  -- Relay URL prompts with the stored URL; cancel changes nothing
  cfg.inputs = { false }
  xm_pick(1)
  assert(input_pending and input_pending.title == "Relay URL" and input_pending.initial == XM_URL, "Relay URL prompt")
  xm_tick(app)
  -- Passphrase asks for the passphrase only, keeps the URL; the screen goes back
  -- to the list while the keys derive
  cfg.inputs = { "pw" }
  xm_pick(2)
  assert(input_pending and input_pending.title == "Passphrase", "Passphrase row prompts the passphrase only")
  xm_tick(app)
  assert(T.state() == "deriving" and xm_label("Deriving keys…") and has_button("Settings"),
    "deriving shown on the list: " .. xm_screen_text())
  xm_assert_layout("m9 deriving")
  xm_until(app, function() return #xm_rows() == 4 end, 60, "list back after the new keys")
  assert(storekv.url == XM_URL, "URL kept")
  press("Settings")
  -- Reset needs a second press
  xm_pick(4)
  assert(storekv.ek ~= "" and T.state() ~= "setup", "one press must not reset")
  assert(xm_rows()[4] ~= "Reset", "Reset row asks for confirmation")
  xm_assert_layout("m9 reset confirm")
  xm_pick(4)
  assert(T.state() == "setup" and storekv.ek == "", "second press resets")
  assert(xm_label("Not set up") and has_button("Set up relay"), "back on the list, not set up: " .. xm_screen_text())
  xm_assert_layout("m9 not set up")
  -- the confirmation lapses
  xm_world(); cfg.w, cfg.h = 320, 196
  wada = build_wada()
  app = load_app(); T = app._t
  xm_configured_store(T)
  xm_relay(T, function(req) return L("P", req.q) .. L("N", 0, 0) end)
  xm_open(app)
  press("Settings")
  xm_pick_text("Reset")
  xm_tick(app, 6000 // 250)
  xm_row_is(#xm_rows(), "Reset")
  xm_pick(#xm_rows())
  assert(T.state() ~= "setup", "a lapsed confirmation must not reset on the next press")
  -- no card interface: no SD option
  xm_world(); cfg.w, cfg.h = 320, 196
  wada = build_wada()
  local caps = wada.sys.caps
  wada.sys.caps = function() local c = caps(); c.sd = false; return c end
  app = load_app(); T = app._t
  xm_configured_store(T)
  xm_open(app)
  press("Settings")
  assert(table.concat(xm_rows(), "|") == "Relay URL|Passphrase|Reset", "no SD row without caps.sd")
  print("  M9 list, chat, settings, SD toggle and Reset confirmation ok")
end

-- 40 conversations x 50 messages: steady ticks stay cheap and idle ticks touch nothing
scenarios.xmpp_cost = function()
  xm_ui_world(320, 240, { touch = true, keyboard = false })
  local app = load_app()
  local T = app._t
  xm_configured_store(T)
  local lines = {}
  for c = 1, 40 do lines[#lines + 1] = L("C", c, c % 5 == 0 and "room" or "chat", "u" .. c .. "@x.test", "User " .. c, "on", c % 7) end
  local s = 0
  for k = 1, 50 do
    for c = 1, 40 do
      s = s + 1
      lines[#lines + 1] = L("G", c, s, 1700000000 + s, "u" .. c .. "@x.test", "message number " .. k .. " in conversation " .. c)
    end
  end
  local pos, extra = 1, nil
  local log = xm_relay(T, function(req)
    local out = { L("P", req.q) }
    local bytes = 0
    while pos <= #lines and bytes + #lines[pos] < 5900 do
      out[#out + 1] = lines[pos]; bytes = bytes + #lines[pos]; pos = pos + 1
    end
    if extra then out[#out + 1] = extra; extra = nil end
    out[#out + 1] = L("N", s, pos <= #lines and 1 or 0)
    return table.concat(out)
  end)
  xm_open(app)
  xm_until(app, function() return pos > #lines and net_pending == nil end, 200, "loading 2000 messages")
  xm_tick(app)
  assert(#xm_rows() == 40, "40 conversations listed")
  assert(#T.msgs(1) == 50 and #T.msgs(40) == 50, "50 messages each")
  local load_tick = XM.tick
  XM.tick = 0
  local ops, clears = widgets.listops or 0, widgets.cleared or 0
  xm_tick(app, 20)
  assert(#log >= 2, "a sync happened during the idle ticks")
  assert((widgets.listops or 0) == ops and (widgets.cleared or 0) == clears,
    "idle ticks must not touch the list: " .. ((widgets.listops or 0) - ops) .. " row ops")
  local list_idle = XM.tick
  -- a full chat: open it, then a new message arrives and the oldest drops
  XM.cb = 0
  xm_pick(1)
  local open_cost = XM.cb
  assert(#xm_rows() == 50, "50 rows in the chat")
  XM.tick = 0
  s = s + 1
  local top = xm_rows()[1]
  local open_id
  for _, c in ipairs(T.convs()) do if xm_label(c.name) then open_id = c.id end end
  assert(open_id, "open conversation")
  extra = L("G", open_id, s, 1700009999, "u" .. open_id .. "@x.test", "the newest one")
  xm_tick(app, 24)                 -- one 5 s poll interval plus a tick
  local last = xm_rows()[50] or ""
  assert(#xm_rows() == 50 and last:sub(-#"the newest one") == "the newest one", "newest row: " .. last)
  assert(xm_rows()[1] ~= top, "oldest row dropped")
  local chat_ticks = XM.tick
  print(string.format("  loading ticks worst ~%d; idle list ticks worst ~%d; open chat ~%d; chat ticks worst ~%d",
    load_tick, list_idle, open_cost, chat_ticks))
  assert(load_tick < 25000 and list_idle < 25000 and chat_ticks < 25000, "tick over 25,000")
  assert(open_cost < BUDGET, "opening a chat over budget")
end

-- True (and says so) when this app has no scenarios of its own. Returning a
-- truthy value makes the dispatch below pick an EMPTY list rather than running
-- someone else's tests against it.
local function UNTESTED_APPS()
  io.write("== no scenarios for this app; nothing was tested\n")
  return true
end

local order = APP_PATH:find("/sdscan/", 1, true)
  and { "sdscan_real_m9", "sdscan_many", "sdscan_m9", "sdscan_layouts", "sdscan_paging_and_full", "sdscan_old_firmware", "sdscan_no_access",
        "sdscan_no_card", "sdscan_remove_fails", "sdscan_portrait", "sdscan_cost" }
  or APP_PATH:find("/wardrive/", 1, true)
  and { "wardrive_utf8" }
  or APP_PATH:find("/tetris/", 1, true)
  and { "tetris_tdeck", "tetris_v4", "tetris_keyboard", "tetris_logic", "tetris_hiscore", "tetris_cost" }
  or APP_PATH:find("/breakout/", 1, true)
  and { "breakout_tdeck", "breakout_v4", "breakout_keyboard", "breakout_logic", "breakout_hiscore", "breakout_cost" }
  or APP_PATH:find("/tripodometer/", 1, true)
  and { "trip_v4", "trip_tdeck", "trip_moving", "trip_persist", "trip_reset", "trip_cost" }
  or APP_PATH:find("/protreck/", 1, true)
  and { "protreck_tdeck", "protreck_v4", "protreck_no_gps", "protreck_chrono", "protreck_timer", "protreck_alti", "protreck_cost" }
  or APP_PATH:find("/xmpp/", 1, true)
  and { "harness_crypto", "xmpp_seal_vectors", "xmpp_kdf_budget", "xmpp_setup", "xmpp_sync", "xmpp_failures",
        "xmpp_post_raises", "xmpp_relay_reset", "xmpp_outbox", "xmpp_bounds",
        "xmpp_chat", "xmpp_empty", "xmpp_v4", "xmpp_m9", "xmpp_cost" }
  or APP_PATH:find("/ping/", 1, true)
  and { "ping_tdeck", "ping_v4", "ping_no_contacts", "ping_round_trip", "ping_auto_reply", "ping_cost" }
  -- The compass list below is gpscompass's own, NOT a default. An app with no
  -- branch used to fall through to it and "fail" on tests written for a
  -- different app -- six of the store apps do, so a full run came back red and
  -- a real regression would not have stood out. Name them: they are untested,
  -- which is worth saying out loud, but it is not a failure of the app.
  or ((not APP_PATH:find("/gpscompass/", 1, true)) and UNTESTED_APPS() and {})
  or { "declination", "align_nofix", "bearings_absolute", "m9", "r8", "v4", "pager", "pager_portrait_jumbo", "tanmatsu", "audio_api", "cost" }
for _, name in ipairs(order) do
  if SCENARIO == "all" or SCENARIO == name then
    print("== " .. name)
    reset_world()
    local ok, err = pcall(scenarios[name])
    if not ok then fails = fails + 1; print("  SCENARIO FAILED: " .. tostring(err)) end
  end
end
print(fails == 0 and "ALL OK" or ("FAILURES: " .. fails))
if fails ~= 0 then error("harness failures") end
