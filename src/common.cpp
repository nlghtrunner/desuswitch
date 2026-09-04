#include "common.hpp"

#include <shlobj.h>
#include <shellapi.h>

#include <cstdio>
#include <mutex>

namespace oc {
namespace {

LogFn g_log = nullptr;
std::mutex g_log_mu;

}  // namespace

void set_logger(LogFn fn) {
    std::lock_guard<std::mutex> lock(g_log_mu);
    g_log = fn;
}

void log(const char* fmt, ...) {
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    LogFn fn;
    {
        std::lock_guard<std::mutex> lock(g_log_mu);
        fn = g_log;
    }
    if (fn) fn(buf);
}

void log_exe_identity() {
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) {
        log("desupatch (path unknown)");
        return;
    }
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    SYSTEMTIME st{};
    if (GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) {
        FILETIME local{};
        FileTimeToLocalFileTime(&fad.ftLastWriteTime, &local);
        FileTimeToSystemTime(&local, &st);
        log("desupatch  %s  file %04d-%02d-%02d %02d:%02d:%02d",
            utf8(path).c_str(), st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    } else {
        log("desupatch  %s", utf8(path).c_str());
    }
}

std::wstring utf16(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

std::string utf8(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring data_dir() {
    wchar_t path[MAX_PATH]{};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, path)))
        return L".";
    std::wstring dir = std::wstring(path) + L"\\desupatch";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

std::string data_dir_utf8() { return utf8(data_dir()); }

std::string win_error(const char* prefix) {
    DWORD code = GetLastError();
    wchar_t* msg = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, code, 0, (LPWSTR)&msg, 0, nullptr);
    std::string extra;
    if (msg) {
        extra = utf8(msg);
        while (!extra.empty() && (extra.back() == '\r' || extra.back() == '\n' || extra.back() == ' '))
            extra.pop_back();
        LocalFree(msg);
    }
    char buf[640];
    snprintf(buf, sizeof(buf), "%s (error %lu%s%s)", prefix, (unsigned long)code,
             extra.empty() ? "" : ": ", extra.c_str());
    return buf;
}

bool is_admin() {
    BOOL admin = FALSE;
    PSID group = nullptr;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &group)) {
        CheckTokenMembership(nullptr, group, &admin);
        FreeSid(group);
    }
    return admin == TRUE;
}

bool relaunch_as_admin() {
    wchar_t exe[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    HINSTANCE h = ShellExecuteW(nullptr, L"runas", exe, nullptr, nullptr, SW_SHOWNORMAL);
    return (INT_PTR)h > 32;
}

}  // namespace oc
