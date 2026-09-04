#pragma once

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SECURITY_WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdarg>
#include <cstdint>
#include <string>
#include <vector>

namespace oc {

inline constexpr wchar_t kAppTitle[] = L"desuswitch";
inline constexpr char kDefaultUpstream[] = "https://osudesu.su";
inline constexpr wchar_t kCertFriendly[] = L"desuswitch";
inline constexpr wchar_t kCertFriendlyPrev[] = L"desupatch";
inline constexpr wchar_t kCertFriendlyOld[] = L"osudesu-lazer-connector";
inline constexpr char kMarkerBegin[] = "# desuswitch BEGIN";
inline constexpr char kMarkerEnd[] = "# desuswitch END";
inline constexpr char kMarkerBeginPrev[] = "# desupatch BEGIN";
inline constexpr char kMarkerEndPrev[] = "# desupatch END";
inline constexpr char kMarkerBeginOld[] = "# osudesu-lazer-connector BEGIN";
inline constexpr char kMarkerEndOld[] = "# osudesu-lazer-connector END";
inline constexpr int kListenPort = 443;

inline const wchar_t* const kHostNames[] = {
    L"osu.ppy.sh",
    L"spectator.osu.ppy.sh",
    L"bss.ppy.sh",
    L"a.ppy.sh",
};
inline constexpr int kHostCount = 4;

using LogFn = void (*)(const char* line);
void set_logger(LogFn fn);
void log(const char* fmt, ...);
void log_exe_identity();

std::wstring utf16(const std::string& s);
std::string utf8(const std::wstring& s);
std::wstring data_dir();
std::string data_dir_utf8();
std::string win_error(const char* prefix);

bool is_admin();
bool relaunch_as_admin();

}  // namespace oc
