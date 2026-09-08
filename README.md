# invalidsteamlogon

recreation of the cs2 invalidsteamlogon poc, but for linux.

hooks `FrameStageNotify` and dispatches `InvalidSteamLogon` KeyValues events (180/frame) when holding insert.

## building

### 1. funchook

clone and build [funchook](https://github.com/kubo/funchook) inside `third_party`:

```bash
cd third_party
git clone --recurse-submodules https://github.com/kubo/funchook.git
cd funchook
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DFUNCHOOK_BUILD_SHARED=OFF
make -j$(nproc)
```

cmake expects:
- `third_party/funchook/include/funchook.h`
- `third_party/funchook/build/libfunchook.a`
- `third_party/funchook/build/libdistorm.a`

### 2. build the so

from the project root:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

output is `build/libinvalidsteamlogon.so`.