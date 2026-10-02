// The only code of ours inside app/js/argon2.wasm: the handful of libc
// symbols the Argon2 reference implementation calls, a bump allocator over
// the module's own linear memory, and one exported entry that fills an
// argon2_context and hands it to the reference's argon2_ctx. No imports, so
// the module cannot reach the network, the clock, or anything outside its
// own memory. tools/build-argon2.sh is the build; docs/ARGON2.md says why.
#include <stddef.h>
#include <stdint.h>
#include "argon2.h"

extern unsigned char __heap_base;
static uintptr_t heap_top;

void *memcpy(void *dst, const void *src, size_t n) {
  unsigned char *d = dst;
  const unsigned char *s = src;
  for (size_t i = 0; i < n; i++) d[i] = s[i];
  return dst;
}

void *memset(void *dst, int c, size_t n) {
  volatile unsigned char *d = dst;
  for (size_t i = 0; i < n; i++) d[i] = (unsigned char)c;
  return dst;
}

size_t strlen(const char *s) {
  size_t n = 0;
  while (s[n]) n++;
  return n;
}

static uintptr_t top(void) { return heap_top ? heap_top : (uintptr_t)&__heap_base; }

// Bump allocation only. Argon2 makes one large allocation per hash and frees
// it at the end, so free is a no-op and reset() rewinds the whole arena.
__attribute__((export_name("alloc"))) void *alloc(size_t n) {
  uintptr_t base = (top() + 63) & ~(uintptr_t)63;
  uintptr_t end = base + n;
  if (end < base) return NULL;
  uintptr_t have = (uintptr_t)__builtin_wasm_memory_size(0) * 65536;
  if (end > have) {
    uintptr_t pages = (end - have + 65535) / 65536;
    if (__builtin_wasm_memory_grow(0, pages) == (size_t)-1) return NULL;
  }
  heap_top = end;
  return (void *)base;
}

void *malloc(size_t n) { return alloc(n); }
void free(void *p) { (void)p; }

// Zero everything handed out since the last reset, then rewind.
__attribute__((export_name("reset"))) void reset(void) {
  uintptr_t base = (uintptr_t)&__heap_base;
  memset((void *)base, 0, top() - base);
  heap_top = base;
}

__attribute__((export_name("argon2id"))) int argon2id_raw(
    uint32_t t, uint32_t m, uint32_t p,
    const uint8_t *pwd, uint32_t pwdlen,
    const uint8_t *salt, uint32_t saltlen,
    const uint8_t *secret, uint32_t secretlen,
    const uint8_t *ad, uint32_t adlen,
    uint8_t *out, uint32_t outlen) {
  argon2_context ctx;
  ctx.out = out;
  ctx.outlen = outlen;
  ctx.pwd = (uint8_t *)pwd;
  ctx.pwdlen = pwdlen;
  ctx.salt = (uint8_t *)salt;
  ctx.saltlen = saltlen;
  ctx.secret = (uint8_t *)secret;
  ctx.secretlen = secretlen;
  ctx.ad = (uint8_t *)ad;
  ctx.adlen = adlen;
  ctx.t_cost = t;
  ctx.m_cost = m;
  ctx.lanes = p;
  ctx.threads = p;
  ctx.version = ARGON2_VERSION_13;
  ctx.allocate_cbk = NULL;
  ctx.free_cbk = NULL;
  ctx.flags = ARGON2_DEFAULT_FLAGS;
  return argon2_ctx(&ctx, Argon2_id);
}
