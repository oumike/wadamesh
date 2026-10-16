// Host harness for wadamesh Lua apps: vendored Lua 5.4.7 (LUA_32BITS, same
// numeric model as the device) + the same library set the firmware opens, plus
// the debug lib for the harness's own instruction-budget hook.
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// ---- SHA-256 + HMAC-SHA256 (FIPS 180-4 / RFC 2104), standing in for the
// mbedTLS calls behind wada.crypto on the device. Binary strings in and out.
typedef struct { uint32_t h[8]; uint64_t len; unsigned char buf[64]; size_t n; } sha_ctx;
static const uint32_t K256[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
#define ROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
static void sha_block(sha_ctx* c, const unsigned char* p) {
  uint32_t w[64], a, b, d, e, f, g, h, cc, t1, t2; int i;
  for (i = 0; i < 16; i++) w[i] = (uint32_t)p[4*i] << 24 | p[4*i+1] << 16 | p[4*i+2] << 8 | p[4*i+3];
  for (; i < 64; i++) {
    uint32_t s0 = ROR(w[i-15],7) ^ ROR(w[i-15],18) ^ (w[i-15] >> 3);
    uint32_t s1 = ROR(w[i-2],17) ^ ROR(w[i-2],19) ^ (w[i-2] >> 10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }
  a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3]; e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
  for (i = 0; i < 64; i++) {
    t1 = h + (ROR(e,6) ^ ROR(e,11) ^ ROR(e,25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
    t2 = (ROR(a,2) ^ ROR(a,13) ^ ROR(a,22)) + ((a & b) ^ (a & cc) ^ (b & cc));
    h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
  }
  c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}
static void sha_init(sha_ctx* c) {
  static const uint32_t iv[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
  memcpy(c->h, iv, sizeof iv); c->len = 0; c->n = 0;
}
static void sha_update(sha_ctx* c, const unsigned char* p, size_t n) {
  c->len += n;
  while (n) {
    size_t k = 64 - c->n; if (k > n) k = n;
    memcpy(c->buf + c->n, p, k); c->n += k; p += k; n -= k;
    if (c->n == 64) { sha_block(c, c->buf); c->n = 0; }
  }
}
static void sha_final(sha_ctx* c, unsigned char out[32]) {
  uint64_t bits = c->len * 8; unsigned char pad = 0x80, z = 0, lb[8]; int i;
  sha_update(c, &pad, 1);
  while (c->n != 56) sha_update(c, &z, 1);
  for (i = 0; i < 8; i++) lb[i] = (unsigned char)(bits >> (56 - 8*i));
  sha_update(c, lb, 8);
  for (i = 0; i < 8; i++) { out[4*i] = c->h[i] >> 24; out[4*i+1] = c->h[i] >> 16; out[4*i+2] = c->h[i] >> 8; out[4*i+3] = c->h[i]; }
}
static void sha256(const unsigned char* m, size_t n, unsigned char out[32]) {
  sha_ctx c; sha_init(&c); sha_update(&c, m, n); sha_final(&c, out);
}
static void hmac_sha256(const unsigned char* k, size_t kn, const unsigned char* m, size_t mn, unsigned char out[32]) {
  unsigned char kb[64] = {0}, ip[64], op[64], in[32]; sha_ctx c; int i;
  if (kn > 64) sha256(k, kn, kb); else memcpy(kb, k, kn);
  for (i = 0; i < 64; i++) { ip[i] = kb[i] ^ 0x36; op[i] = kb[i] ^ 0x5c; }
  sha_init(&c); sha_update(&c, ip, 64); sha_update(&c, m, mn); sha_final(&c, in);
  sha_init(&c); sha_update(&c, op, 64); sha_update(&c, in, 32); sha_final(&c, out);
}
static int host_sha256(lua_State* L) {
  size_t n; const char* m = luaL_checklstring(L, 1, &n); unsigned char o[32];
  sha256((const unsigned char*)m, n, o); lua_pushlstring(L, (const char*)o, 32); return 1;
}
static int host_hmac_sha256(lua_State* L) {
  size_t kn, mn; const char* k = luaL_checklstring(L, 1, &kn); const char* m = luaL_checklstring(L, 2, &mn);
  unsigned char o[32]; hmac_sha256((const unsigned char*)k, kn, (const unsigned char*)m, mn, o);
  lua_pushlstring(L, (const char*)o, 32); return 1;
}
int main(int argc, char** argv) {
  if (argc < 3) { fprintf(stderr, "usage: luah harness.lua app.lua [scenario]\n"); return 2; }
  lua_State* L = luaL_newstate();
  luaL_requiref(L, LUA_GNAME, luaopen_base, 1);        lua_pop(L, 1);
  luaL_requiref(L, LUA_MATHLIBNAME, luaopen_math, 1);  lua_pop(L, 1);
  luaL_requiref(L, LUA_STRLIBNAME, luaopen_string, 1); lua_pop(L, 1);
  luaL_requiref(L, LUA_TABLIBNAME, luaopen_table, 1);  lua_pop(L, 1);
  luaL_requiref(L, LUA_DBLIBNAME, luaopen_debug, 1);   lua_pop(L, 1);
  luaL_requiref(L, LUA_IOLIBNAME, luaopen_io, 1);      lua_pop(L, 1);
  lua_pushcfunction(L, host_sha256);      lua_setglobal(L, "__host_sha256");
  lua_pushcfunction(L, host_hmac_sha256); lua_setglobal(L, "__host_hmac_sha256");
  lua_pushstring(L, argv[2]); lua_setglobal(L, "APP_PATH");
  lua_pushstring(L, argc > 3 ? argv[3] : "all"); lua_setglobal(L, "SCENARIO");
  if (luaL_dofile(L, argv[1]) != LUA_OK) { fprintf(stderr, "harness: %s\n", lua_tostring(L, -1)); return 1; }
  lua_close(L);
  return 0;
}
