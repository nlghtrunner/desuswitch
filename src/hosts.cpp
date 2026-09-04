#include "hosts.hpp"

#include <iphlpapi.h>
#include <cstring>
#include <sstream>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
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
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD n = 0;
    BOOL ok = WriteFile(h, s.data(), (DWORD)s.size(), &n, nullptr);
    CloseHandle(h);
    return ok == TRUE;
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

void kill_listener_on_443() {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
    std::vector<char> buf(size);
    auto* table = (MIB_TCPTABLE_OWNER_PID*)buf.data();
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) != NO_ERROR)
        return;
    DWORD self = GetCurrentProcessId();
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        if (ntohs((u_short)row.dwLocalPort) != 443) continue;
        if (row.dwLocalAddr != htonl(INADDR_LOOPBACK) && row.dwLocalAddr != 0) continue;
        if (row.dwOwningPid == 0 || row.dwOwningPid == self) continue;
        HANDLE p = OpenProcess(PROCESS_TERMINATE, FALSE, row.dwOwningPid);
        if (p) {
            TerminateProcess(p, 0);
            CloseHandle(p);
        }
    }
}

bool apply_hosts(std::string& err) {
    const auto path = hosts_path();
    std::string raw = strip_block(read_file(path));
    while (!raw.empty() && (raw.back() == '\n' || raw.back() == '\r' || raw.back() == ' '))
        raw.pop_back();
    std::ostringstream block;
    block << "\r\n\r\n" << kMarkerBegin << "\r\n";
    for (int i = 0; i < kHostCount; ++i) {
        std::string name = utf8(kHostNames[i]);
        block << "127.0.0.1 " << name << "\r\n";
        block << "::1 " << name << "\r\n";
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
