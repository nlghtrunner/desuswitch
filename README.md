# desuswitch - osu!lazer proxy switcher for osudesu

## Description
Proxy switcher with tiny GUI that points the **official** osu!lazer client at the [osudesu](https://osudesu.su) private server without **ANY** interactions with game files, only traffic to osu!bancho is intercepted locally. It switches between osu!bancho and osudesu only.

## CAUTION!!!
- DO NOT reuse the same password on both servers.

- DO NOT advertise this repo in official **osu!** chat or forums.

- Make sure proxy is **OFF** when you going to play official server.

- Administrator rights are required (hosts, trusted local certificate). Only run builds you trust.

- If the app crashes (for some reason), run it again and make sure it's on/off — `hosts` may still point `osu.ppy.sh` at `127.0.0.1`.

- While connected to osudesu, any query routes to osu!bancho are redirected.

- This is **not** `-devserver` and **not** a patch for osu!lazer, **no** any injection to processes or files of game.

- If you have any questions or issues, please DM in Discord `pr0t0type_00`.

## Build
**Requirements:** Windows 10+, [CMake](https://cmake.org/download/) 3.16+ and Visual Studio **or** Build Tools with the MSVC x64 C++ toolset. No extra libs needed.


```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

Output: `build\Release\desuswitch.exe`. Run as Administrator.

## How it works
**Connection**:
1. Installing a self-signed certificate `CN=osu.ppy.sh` (SAN: `osu.ppy.sh`, `spectator.osu.ppy.sh`, `a.ppy.sh`, `bss.ppy.sh`) into `LocalMachine\My` and trust it in `LocalMachine\Root`.
2. Appending a block to `C:\Windows\System32\drivers\etc\hosts` mapping those names to `127.0.0.1` and `::1`.
3. Listening on `127.0.0.1:443` / `[::1]:443`, terminate TLS with SChannel, parse HTTP.

**You can delete certificate manually:**
`certlm.msc` → Trusted Root and Personal, find desuswitch. Disconnection doesn't delete it automatically. No need delete it for bancho.

**Proxy:**
* `/oauth/*`, `/api/v2/*`, `POST /users`, `/spectator`, `/multiplayer`, `/metadata` → `https://osudesu.su`.
* `a.ppy.sh` → `https://a.osudesu.su`.
* WebSocket upgrades (spectator, multiplayer, metadata, notifications) are bridged to the same upstream.

## Usage 
* Read all the text above.
* Build or download `desuswitch.exe` from Releases.
* Run as administrator.
* Press **Connect**.
* Open osu!lazer and login or register with credentials.
* **Disconnect** when finished.

### Note
The project was created carefully with Cursor AI (Grok) support.
