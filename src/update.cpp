#include "update.hpp"

#include "common.hpp"

#include <winhttp.h>
#include <bcrypt.h>

#include <cctype>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

namespace oc {
namespace {

constexpr wchar_t kReleaseUrl[] =
    L"https://api.github.com/repos/nlghtrunner/desuswitch/releases/latest";
constexpr char kDownloadPrefix[] =
    "https://github.com/nlghtrunner/desuswitch/releases/download/";
constexpr size_t kJsonCap = 1024 * 1024;
constexpr size_t kExeCap = 20 * 1024 * 1024;

std::vector<int> version_parts(std::string s) {
    if (!s.empty() && (s[0] == 'v' || s[0] == 'V')) s.erase(0, 1);
    std::vector<int> parts;
    size_t i = 0;
    while (i < s.size() && parts.size() < 8) {
        if (s[i] < '0' || s[i] > '9') break;
        int n = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            n = n * 10 + (s[i] - '0');
            ++i;
        }
        parts.push_back(n);
        if (i < s.size() && s[i] == '.') ++i;
        else break;
    }
    return parts;
}

bool json_string_at(const std::string& json, size_t key_at, const std::string& key, std::string& out) {
    std::string pat = "\"" + key + "\"";
    if (json.compare(key_at, pat.size(), pat) != 0) return false;
    size_t p = json.find(':', key_at + pat.size());
    if (p == std::string::npos) return false;
    p = json.find('"', p + 1);
    if (p == std::string::npos) return false;
    ++p;
    out.clear();
    while (p < json.size()) {
        char c = json[p++];
        if (c == '\\') {
            if (p >= json.size()) return false;
            char e = json[p++];
            if (e == 'n') out.push_back('\n');
            else out.push_back(e);
            continue;
        }
        if (c == '"') return true;
        out.push_back(c);
    }
    return false;
}

bool sha256_hex(const std::string& data, std::string& out) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return false;
    DWORD hash_len = 0, written = 0;
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len, sizeof(hash_len), &written, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }
    std::vector<UCHAR> dig(hash_len);
    bool ok = BCryptHashData(hash, (PUCHAR)data.data(), (ULONG)data.size(), 0) == 0
              && BCryptFinishHash(hash, dig.data(), (ULONG)dig.size(), 0) == 0;
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!ok) return false;
    static const char* hex = "0123456789abcdef";
    out.resize(dig.size() * 2);
    for (size_t i = 0; i < dig.size(); ++i) {
        out[i * 2] = hex[dig[i] >> 4];
        out[i * 2 + 1] = hex[dig[i] & 0xF];
    }
    return true;
}

bool http_get(const std::wstring& url, std::string& body, size_t cap, bool github_json) {
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256]{};
    wchar_t path[4096]{};
    wchar_t extra[2048]{};
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 4096;
    uc.lpszExtraInfo = extra;
    uc.dwExtraInfoLength = 2048;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) return false;
    if (uc.nScheme != INTERNET_SCHEME_HTTPS) return false;

    HINTERNET sess = WinHttpOpen(L"desuswitch", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!sess) return false;
    WinHttpSetTimeouts(sess, 10000, 15000, 20000, 60000);
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
#ifdef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
    protocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
#endif
    WinHttpSetOption(sess, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));

    HINTERNET conn = WinHttpConnect(sess, host, uc.nPort, 0);
    if (!conn) {
        WinHttpCloseHandle(sess);
        return false;
    }
    std::wstring target = path;
    if (extra[0]) target += extra;
    HINTERNET req = WinHttpOpenRequest(conn, L"GET", target.c_str(), nullptr, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!req) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(sess);
        return false;
    }
    const wchar_t* hdr = github_json
        ? L"User-Agent: desuswitch\r\nAccept: application/vnd.github+json\r\n"
        : L"User-Agent: desuswitch\r\n";
    WinHttpAddRequestHeaders(req, hdr, (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        || !WinHttpReceiveResponse(req, nullptr)) {
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(sess);
        return false;
    }
    DWORD status = 0, slen = sizeof(status);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &slen, WINHTTP_NO_HEADER_INDEX);
    body.clear();
    bool too_big = false;
    if (status == 200) {
        for (;;) {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0) break;
            if (body.size() + avail > cap) {
                too_big = true;
                break;
            }
            size_t at = body.size();
            body.resize(at + avail);
            DWORD got = 0;
            if (!WinHttpReadData(req, body.data() + at, avail, &got)) {
                body.resize(at);
                break;
            }
            body.resize(at + got);
            if (got == 0) break;
        }
    }
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(sess);
    return status == 200 && !too_big && !body.empty();
}

bool write_bytes(const std::wstring& path, const std::string& bytes) {
    std::wstring tmp = path + L".tmp";
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD n = 0;
    BOOL ok = WriteFile(h, bytes.data(), (DWORD)bytes.size(), &n, nullptr);
    if (ok) ok = FlushFileBuffers(h);
    CloseHandle(h);
    if (!ok || n != (DWORD)bytes.size()) {
        DeleteFileW(tmp.c_str());
        return false;
    }
    if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tmp.c_str());
        return false;
    }
    return true;
}

std::wstring ps_quote(const std::wstring& s) {
    std::wstring o;
    for (wchar_t c : s) {
        if (c == L'\'') o += L"''";
        else o.push_back(c);
    }
    return o;
}

bool launch_replacer(const std::wstring& src, const std::wstring& dst, std::string& err) {
    if (src.find_first_of(L"\r\n'") != std::wstring::npos || dst.find_first_of(L"\r\n'") != std::wstring::npos) {
        err = "Install path cannot be updated automatically";
        return false;
    }
    std::wstring ps1 = data_dir() + L"\\update.ps1";
    std::wstring body =
        L"$src = '" + ps_quote(src) + L"'\r\n"
        L"$dst = '" + ps_quote(dst) + L"'\r\n"
        L"for ($i = 0; $i -lt 30; $i++) {\r\n"
        L"  Start-Sleep -Seconds 1\r\n"
        L"  try {\r\n"
        L"    Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop\r\n"
        L"    Start-Process -FilePath $dst\r\n"
        L"    Remove-Item -LiteralPath $src -Force -ErrorAction SilentlyContinue\r\n"
        L"    Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue\r\n"
        L"    exit 0\r\n"
        L"  } catch {}\r\n"
        L"}\r\n"
        L"exit 1\r\n";
    std::string file = std::string("\xEF\xBB\xBF") + utf8(body);
    if (!write_bytes(ps1, file)) {
        err = "Could not write the updater script";
        return false;
    }
    std::wstring cmd = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + ps1 + L"\"";
    std::vector<wchar_t> mutable_cmd(cmd.begin(), cmd.end());
    mutable_cmd.push_back(0);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, mutable_cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        err = "Could not start the updater";
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

}  // namespace

bool version_newer(const std::string& remote, const std::string& local) {
    auto a = version_parts(remote);
    auto b = version_parts(local);
    if (a.empty() || b.empty()) return false;
    size_t n = a.size() > b.size() ? a.size() : b.size();
    for (size_t i = 0; i < n; ++i) {
        int av = i < a.size() ? a[i] : 0;
        int bv = i < b.size() ? b[i] : 0;
        if (av != bv) return av > bv;
    }
    return false;
}

bool parse_release(const std::string& json, Release& out) {
    auto tag = json.find("\"tag_name\"");
    if (tag == std::string::npos || !json_string_at(json, tag, "tag_name", out.version)) return false;
    size_t search = 0;
    while (search < json.size()) {
        auto key = json.find("\"browser_download_url\"", search);
        if (key == std::string::npos) return false;
        std::string url;
        if (!json_string_at(json, key, "browser_download_url", url)) return false;
        search = key + 24;
        if (url.rfind(kDownloadPrefix, 0) != 0) continue;
        if (url.size() < 15 || url.compare(url.size() - 15, 15, "/desuswitch.exe") != 0) continue;
        std::string digest;
        size_t best = std::string::npos;
        size_t from = 0;
        while (from < json.size()) {
            auto dig = json.find("\"digest\"", from);
            if (dig == std::string::npos) break;
            size_t dist = dig > key ? dig - key : key - dig;
            std::string candidate;
            if (dist < 2000 && dist < best && json_string_at(json, dig, "digest", candidate)) {
                best = dist;
                digest = candidate;
            }
            from = dig + 8;
        }
        if (digest.empty()) return false;
        const std::string pfx = "sha256:";
        if (digest.rfind(pfx, 0) != 0 || digest.size() != pfx.size() + 64) return false;
        out.url = url;
        out.sha256 = digest.substr(pfx.size());
        for (char& c : out.sha256) c = (char)tolower((unsigned char)c);
        return true;
    }
    return false;
}

bool self_test_update() {
    if (!version_newer("0.0.2", "0.0.1")) return false;
    if (!version_newer("0.0.10", "0.0.9")) return false;
    if (!version_newer("v0.0.3", "0.0.2")) return false;
    if (version_newer("0.0.1", "0.0.2")) return false;
    if (version_newer("1.0", "1.0.0")) return false;
    if (version_newer("nope", "0.0.1")) return false;

    const char* ok_json =
        "{\"tag_name\":\"0.0.3\",\"assets\":[{\"name\":\"desuswitch.exe\","
        "\"browser_download_url\":\"https://github.com/nlghtrunner/desuswitch/releases/download/0.0.3/desuswitch.exe\","
        "\"digest\":\"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}]}";
    Release rel;
    if (!parse_release(ok_json, rel)) return false;
    if (rel.version != "0.0.3") return false;
    if (rel.url.find("/0.0.3/desuswitch.exe") == std::string::npos) return false;
    if (rel.sha256.size() != 64) return false;

    const char* bad =
        "{\"tag_name\":\"9.0.0\",\"assets\":[{\"name\":\"desuswitch.exe\","
        "\"browser_download_url\":\"https://evil.example/desuswitch.exe\","
        "\"digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}]}";
    Release rejected;
    if (parse_release(bad, rejected)) return false;
    return true;
}

bool check_update(Release& out) {
    std::string body;
    if (!http_get(kReleaseUrl, body, kJsonCap, true)) return false;
    Release rel;
    if (!parse_release(body, rel)) return false;
    if (!version_newer(rel.version, kAppVersion)) return false;
    out = rel;
    return true;
}

bool download_and_apply(const Release& rel, std::string& err) {
    if (rel.url.rfind(kDownloadPrefix, 0) != 0) {
        err = "Update url was rejected";
        return false;
    }
    std::string bytes;
    if (!http_get(utf16(rel.url), bytes, kExeCap, false)) {
        err = "Could not download the update";
        return false;
    }
    std::string got;
    if (!sha256_hex(bytes, got) || got != rel.sha256) {
        err = "Update file did not match the published checksum";
        return false;
    }
    std::wstring src = data_dir() + L"\\desuswitch-update.exe";
    if (!write_bytes(src, bytes)) {
        err = "Could not save the update";
        return false;
    }
    wchar_t exe[MAX_PATH]{};
    DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        err = "Could not find this program's path";
        return false;
    }
    return launch_replacer(src, exe, err);
}

}  // namespace oc
