#include "hosts.hpp"

#include <cstring>
#include <sstream>

#pragma comment(lib, "dnsapi.lib")

extern "C" BOOL WINAPI DnsFlushResolverCache();

namespace oc {
namespace {

std::wstring hosts_path() {
    wchar_t windir[MAX_PATH]{};
    GetWindowsDirectoryW(windir, MAX_PATH);
    return std::wstring(windir) + L"\\System32\\drivers\\etc\\hosts";
}

std::string read_file(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    DWORD sz = GetFileSize(h, nullptr);
    std::string s(sz == INVALID_FILE_SIZE ? 0 : sz, '\0');
    DWORD n = 0;
    if (!s.empty()) ReadFile(h, s.data(), (DWORD)s.size(), &n, nullptr);
    s.resize(n);
    CloseHandle(h);
    return s;
}

bool write_file(const std::wstring& path, const std::string& s) {
    std::wstring tmp = path + L".desuswitch.tmp";
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD n = 0;
    BOOL ok = WriteFile(h, s.data(), (DWORD)s.size(), &n, nullptr);
    if (ok) ok = FlushFileBuffers(h);
    CloseHandle(h);
    if (!ok || n != (DWORD)s.size()) {
        DeleteFileW(tmp.c_str());
        return false;
    }
    if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tmp.c_str());
        return false;
    }
    return true;
}

std::string strip_one(const std::string& raw, const char* begin, const char* end) {
    auto a = raw.find(begin);
    if (a == std::string::npos) return raw;
    auto b = raw.find(end, a);
    if (b == std::string::npos) return raw;
    b += strlen(end);
    while (b < raw.size() && (raw[b] == '\r' || raw[b] == '\n')) ++b;
    return raw.substr(0, a) + raw.substr(b);
}

std::string strip_block(const std::string& raw) {
    return strip_one(
        strip_one(strip_one(raw, kMarkerBegin, kMarkerEnd), kMarkerBeginPrev, kMarkerEndPrev),
        kMarkerBeginOld, kMarkerEndOld);
}

}  // namespace

void flush_dns() {
    DnsFlushResolverCache();
}

bool apply_hosts(std::string& err, bool ipv6) {
    const auto path = hosts_path();
    std::string raw = strip_block(read_file(path));
    while (!raw.empty() && (raw.back() == '\n' || raw.back() == '\r' || raw.back() == ' '))
        raw.pop_back();
    std::ostringstream block;
    block << "\r\n\r\n" << kMarkerBegin << "\r\n";
    for (int i = 0; i < kHostCount; ++i) {
        std::string name = utf8(kHostNames[i]);
        block << "127.0.0.1 " << name << "\r\n";
        if (ipv6) block << "::1 " << name << "\r\n";
    }
    block << kMarkerEnd << "\r\n";
    if (!write_file(path, raw + block.str())) {
        err = "Failed to write hosts file (need Administrator)";
        return false;
    }
    flush_dns();
    return true;
}

bool restore_hosts(std::string& err) {
    const auto path = hosts_path();
    std::string raw = read_file(path);
    if (raw.find(kMarkerBegin) == std::string::npos &&
        raw.find(kMarkerBeginPrev) == std::string::npos &&
        raw.find(kMarkerBeginOld) == std::string::npos) {
        return true;
    }
    std::string next = strip_block(raw);
    while (!next.empty() && (next.back() == '\n' || next.back() == '\r')) next.pop_back();
    next += "\r\n";
    if (!write_file(path, next)) {
        err = "Failed to restore hosts file";
        return false;
    }
    flush_dns();
    return true;
}

}  // namespace oc
