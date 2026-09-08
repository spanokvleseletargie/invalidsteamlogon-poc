#include "scan.h"
#include <cstring>
#include <cstdint>
#include <link.h>
#include <elf.h>

namespace {

static uint8_t HexNib(char c) {
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
    return 0xFF;
}

static int ParseSig(const char *sig, uint8_t *bytes, uint8_t *mask) {
    int len = 0;
    const char *p = sig;
    while (*p && len < 256) {
        if (*p == ' ') { p++; continue; }
        if (*p == '?') {
            bytes[len] = 0; mask[len] = 0; len++;
            if (p[1] == '?') p++;
            p++;
            continue;
        }
        uint8_t hi = HexNib(p[0]);
        uint8_t lo = HexNib(p[1]);
        if (hi == 0xFF || lo == 0xFF) { p++; continue; }
        bytes[len] = (uint8_t)((hi << 4) | lo);
        mask[len]  = 0xFF;
        len++;
        p += 2;
    }
    return len;
}

struct ScanCtx {
    void       *base;
    const char *sig;
    uint8_t     bytes[256];
    uint8_t     mask[256];
    int         len;
    void       *result;
};

static int PhdrCallback(struct dl_phdr_info *info, size_t, void *data) {
    ScanCtx *ctx = reinterpret_cast<ScanCtx *>(data);
    if (reinterpret_cast<void *>(info->dlpi_addr) != ctx->base)
        return 0;

    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD) continue;
        if (!(ph.p_flags & PF_X))  continue;
        if (ph.p_memsz == 0)       continue;

        auto  *seg = reinterpret_cast<uint8_t *>(info->dlpi_addr + ph.p_vaddr);
        size_t sz  = ph.p_memsz;
        if ((size_t)ctx->len > sz) continue;

        for (size_t j = 0; j <= sz - (size_t)ctx->len; j++) {
            bool ok = true;
            for (int k = 0; k < ctx->len; k++) {
                if (ctx->mask[k] && seg[j + k] != ctx->bytes[k]) { ok = false; break; }
            }
            if (ok) { ctx->result = seg + j; return 1; }
        }
    }
    return 0;
}

} // namespace

void *scan::Pattern(void *base, const char *sig) {
    if (!base || !sig) return nullptr;
    ScanCtx ctx{};
    ctx.base   = base;
    ctx.sig    = sig;
    ctx.result = nullptr;
    ctx.len    = ParseSig(sig, ctx.bytes, ctx.mask);
    if (ctx.len == 0) return nullptr;
    dl_iterate_phdr(PhdrCallback, &ctx);
    return ctx.result;
}
