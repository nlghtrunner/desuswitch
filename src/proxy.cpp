#include "proxy.hpp"

#include <security.h>
#include <schannel.h>
#include <schnlsp.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <winreg.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif
#ifndef WINHTTP_OPTION_REDIRECT_POLICY
#define WINHTTP_OPTION_REDIRECT_POLICY 88
#endif
#ifndef WINHTTP_OPTION_REDIRECT_POLICY_NEVER
#define WINHTTP_OPTION_REDIRECT_POLICY_NEVER 0
#endif
#ifndef WINHTTP_OPTION_DECOMPRESSION
#define WINHTTP_OPTION_DECOMPRESSION 118
#endif
#ifndef WINHTTP_DECOMPRESSION_FLAG_GZIP
#define WINHTTP_DECOMPRESSION_FLAG_GZIP 0x00000001
#define WINHTTP_DECOMPRESSION_FLAG_DEFLATE 0x00000002
#define WINHTTP_DECOMPRESSION_FLAG_ALL 0x00000003
#endif
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace oc {
namespace {

std::atomic<bool> g_run{false};
std::string g_upstream = kDefaultUpstream;
std::string g_avatar_host = "a.osudesu.su";
CredHandle g_cred{};
bool g_cred_ok = false;
PCCERT_CONTEXT g_cred_cert = nullptr;
SOCKET g_listen4 = INVALID_SOCKET;
SOCKET g_listen6 = INVALID_SOCKET;
std::thread g_thr;

constexpr size_t kMaxBody = 32 * 1024 * 1024;

std::string lower(std::string s) {
    for (char& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && isspace((unsigned char)s[a])) ++a;
    while (b > a && isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

std::string reason_phrase(int status) {
    switch (status) {
        case 101: return "Switching Protocols";
        case 302: return "Found";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        default: return "OK";
    }
}

std::string json_text(const std::string& obj, int status = 200) {
    char head[320];
    snprintf(head, sizeof(head),
             "HTTP/1.1 %d %s\r\nContent-Type: application/json; charset=utf-8\r\n"
             "Content-Length: %zu\r\nConnection: keep-alive\r\n\r\n",
             status, reason_phrase(status).c_str(), obj.size());
    return std::string(head) + obj;
}

std::string text_resp(const std::string& body, int status = 200) {
    char head[320];
    snprintf(head, sizeof(head),
             "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\n"
             "Content-Length: %zu\r\nConnection: keep-alive\r\n\r\n",
             status, reason_phrase(status).c_str(), body.size());
    return std::string(head) + body;
}

std::string raw_resp(int status, const std::string& ctype, const std::string& body,
                     const std::vector<std::pair<std::string, std::string>>& extra = {}) {
    std::ostringstream o;
    o << "HTTP/1.1 " << status << " " << reason_phrase(status) << "\r\n";
    if (!ctype.empty()) o << "Content-Type: " << ctype << "\r\n";
    for (auto& [k, v] : extra) o << k << ": " << v << "\r\n";
    o << "Content-Length: " << body.size() << "\r\nConnection: keep-alive\r\n\r\n";
    o << body;
    return o.str();
}

bool hop_by_hop(const std::string& k) {
    auto l = lower(k);
    return l == "connection" || l == "keep-alive" || l == "proxy-authenticate" ||
           l == "proxy-authorization" || l == "te" || l == "trailer" ||
           l == "transfer-encoding" || l == "upgrade" || l == "host" ||
           l == "content-length" || l == "expect" || l == "accept-encoding";
}

std::string header_get(const std::map<std::string, std::string>& headers, const char* key) {
    auto it = headers.find(key);
    return it == headers.end() ? std::string() : it->second;
}

std::string ctype_boundary(const std::string& ctype) {
    auto l = lower(ctype);
    auto p = l.find("boundary=");
    if (p == std::string::npos) return {};
    std::string b = ctype.substr(p + 9);
    b = trim(b);
    if (!b.empty() && b.front() == '"') {
        auto q = b.find('"', 1);
        return q == std::string::npos ? b.substr(1) : b.substr(1, q - 1);
    }
    auto sc = b.find(';');
    if (sc != std::string::npos) b.resize(sc);
    return trim(b);
}

bool looks_like_form_body(const std::string& s) {
    size_t i = 0;
    while (i < s.size() && isspace((unsigned char)s[i])) ++i;
    if (i + 2 < s.size() && s[i] == '-' && s[i + 1] == '-') return true;
    if (s.compare(i, 11, "grant_type=") == 0) return true;
    if (i < s.size() && s[i] == '{') return true;
    return false;
}

std::string sniff_multipart_ctype(const std::string& body) {
    size_t i = 0;
    while (i < body.size() && (body[i] == '\r' || body[i] == '\n' ||
                               isspace((unsigned char)body[i])))
        ++i;
    if (i + 2 >= body.size() || body[i] != '-' || body[i + 1] != '-') return {};
    auto eol = body.find("\r\n", i);
    if (eol == std::string::npos) eol = body.find('\n', i);
    if (eol == std::string::npos) return {};
    std::string line = body.substr(i, eol - i);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    if (line.size() >= 4 && line.compare(line.size() - 2, 2, "--") == 0)
        line.resize(line.size() - 2);
    if (line.size() < 3) return {};
    return std::string("multipart/form-data; boundary=") + line.substr(2);
}

std::string md5_hex_win(const std::string& in) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    if (!CryptAcquireContextA(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return {};
    std::string out;
    if (CryptCreateHash(prov, CALG_MD5, 0, 0, &hash)) {
        CryptHashData(hash, (const BYTE*)in.data(), (DWORD)in.size(), 0);
        BYTE digest[16];
        DWORD n = 16;
        if (CryptGetHashParam(hash, HP_HASHVAL, digest, &n, 0)) {
            static const char* hex = "0123456789abcdef";
            out.resize(32);
            for (DWORD i = 0; i < 16; ++i) {
                out[i * 2] = hex[(digest[i] >> 4) & 0xF];
                out[i * 2 + 1] = hex[digest[i] & 0xF];
            }
        }
        CryptDestroyHash(hash);
    }
    CryptReleaseContext(prov, 0);
    return out;
}

struct LocalFp {
    std::string adapters;
    std::string uninstall;
    std::string disk;
};
LocalFp g_fp;
std::once_flag g_fp_once;

void collect_fingerprint() {
    std::call_once(g_fp_once, []() {
        char guid[128]{};
        DWORD glen = sizeof(guid);
        HKEY k = nullptr;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0,
                          KEY_READ | KEY_WOW64_64KEY, &k) == ERROR_SUCCESS) {
            DWORD t = REG_SZ;
            if (RegQueryValueExA(k, "MachineGuid", nullptr, &t, (LPBYTE)guid, &glen) == ERROR_SUCCESS)
                g_fp.uninstall = md5_hex_win(guid);
            RegCloseKey(k);
        }
        DWORD serial = 0;
        if (GetVolumeInformationA("C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
            char buf[16];
            snprintf(buf, sizeof(buf), "%08lx", (unsigned long)serial);
            g_fp.disk = md5_hex_win(buf);
        }
        ULONG sz = 16 * 1024;
        std::vector<unsigned char> raw(sz);
        auto* info = reinterpret_cast<IP_ADAPTER_INFO*>(raw.data());
        if (GetAdaptersInfo(info, &sz) == ERROR_BUFFER_OVERFLOW) {
            raw.resize(sz);
            info = reinterpret_cast<IP_ADAPTER_INFO*>(raw.data());
        }
        std::string macs;
        if (GetAdaptersInfo(info, &sz) == NO_ERROR) {
            for (auto* a = info; a; a = a->Next) {
                for (UINT i = 0; i < a->AddressLength; ++i) {
                    char b[4];
                    snprintf(b, sizeof(b), "%02x", a->Address[i]);
                    macs += b;
                }
                macs += ",";
            }
        }
        if (!macs.empty()) g_fp.adapters = md5_hex_win(macs);
    });
}

void inject_fingerprint(std::map<std::string, std::string>& headers) {
    collect_fingerprint();
    if (!g_fp.adapters.empty()) headers["x-osudesu-adapters"] = g_fp.adapters;
    if (!g_fp.uninstall.empty()) headers["x-osudesu-uninstall"] = g_fp.uninstall;
    if (!g_fp.disk.empty()) headers["x-osudesu-disk"] = g_fp.disk;
}

std::string b64(const BYTE* data, DWORD n) {
    DWORD len = 0;
    CryptBinaryToStringA(data, n, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &len);
    std::string out(len, '\0');
    CryptBinaryToStringA(data, n, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out.data(), &len);
    while (!out.empty() && (out.back() == '\0' || out.back() == '\r' || out.back() == '\n'))
        out.pop_back();
    return out;
}

std::string ws_accept_key(const std::string& key) {
    std::string src = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return {};
    CryptCreateHash(prov, CALG_SHA1, 0, 0, &hash);
    CryptHashData(hash, (BYTE*)src.data(), (DWORD)src.size(), 0);
    BYTE digest[20];
    DWORD n = 20;
    CryptGetHashParam(hash, HP_HASHVAL, digest, &n, 0);
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
    return b64(digest, n);
}

struct UpstreamResult {
    int status = 502;
    std::string content_type = "application/json";
    std::string body;
    std::map<std::string, std::string> headers;
};

std::wstring to_wide_path(const std::string& path, const std::string& query) {
    std::string t = path;
    if (!query.empty()) {
        t += "?";
        t += query;
    }
    return utf16(t);
}

UpstreamResult fail_upstream() {
    UpstreamResult r;
    r.status = 502;
    r.content_type = "application/json";
    r.body = "{\"error\":\"upstream timeout\"}";
    return r;
}

UpstreamResult winhttp_call(const std::wstring& host, INTERNET_PORT port, bool tls,
                            const std::string& method, const std::string& path,
                            const std::string& query,
                            const std::map<std::string, std::string>& headers,
                            const std::string& body, int timeout_ms = 30000) {
    UpstreamResult r;
    HINTERNET sess = WinHttpOpen(L"desuswitch/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!sess) return fail_upstream();
    DWORD to = (DWORD)timeout_ms;
    WinHttpSetTimeouts(sess, to, to, to, to);
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(sess, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));
    HINTERNET conn = WinHttpConnect(sess, host.c_str(), port, 0);
    if (!conn) {
        WinHttpCloseHandle(sess);
        return fail_upstream();
    }
    DWORD flags = tls ? WINHTTP_FLAG_SECURE : 0;
    flags |= WINHTTP_FLAG_REFRESH;
    HINTERNET req = WinHttpOpenRequest(conn, utf16(method).c_str(),
                                       to_wide_path(path, query).c_str(), nullptr,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(sess);
        return fail_upstream();
    }
    WinHttpSetOption(req, WINHTTP_OPTION_CLIENT_CERT_CONTEXT, WINHTTP_NO_CLIENT_CERT_CONTEXT, 0);
    DWORD never = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    WinHttpSetOption(req, WINHTTP_OPTION_REDIRECT_POLICY, &never, sizeof(never));
    DWORD decomp = WINHTTP_DECOMPRESSION_FLAG_ALL;
    WinHttpSetOption(req, WINHTTP_OPTION_DECOMPRESSION, &decomp, sizeof(decomp));

    std::wstring hdr;
    std::string content_type;
    for (auto& [k, v] : headers) {
        auto lk = lower(k);
        if (hop_by_hop(k)) continue;
        if (lk == "content-type") {
            content_type = v;
            continue;
        }
        hdr += utf16(k);
        hdr += L": ";
        hdr += utf16(v);
        hdr += L"\r\n";
    }
    if (content_type.empty()) {
        auto sniff = sniff_multipart_ctype(body);
        if (!sniff.empty()) content_type = sniff;
    }
    if (!content_type.empty()) {
        std::wstring ct = L"Content-Type: " + utf16(content_type);
        WinHttpAddRequestHeaders(req, ct.c_str(), (DWORD)-1,
                                 WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }
    WinHttpAddRequestHeaders(req, L"Accept-Encoding: identity", (DWORD)-1,
                             WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    BOOL sent = WinHttpSendRequest(req, hdr.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : hdr.c_str(),
                                   hdr.empty() ? 0 : (DWORD)-1,
                                   WINHTTP_NO_REQUEST_DATA, 0, (DWORD)body.size(), 0);
    if (sent && !body.empty()) {
        DWORD written = 0;
        sent = WinHttpWriteData(req, body.data(), (DWORD)body.size(), &written);
        if (!sent || written != (DWORD)body.size()) {
            sent = FALSE;
        }
    }
    if (!sent || !WinHttpReceiveResponse(req, nullptr)) {
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(sess);
        return fail_upstream();
    }
    DWORD status = 0, slen = sizeof(status);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &slen, WINHTTP_NO_HEADER_INDEX);
    r.status = (int)status;
    DWORD ctlen = 0;
    WinHttpQueryHeaders(req, WINHTTP_QUERY_CONTENT_TYPE, WINHTTP_HEADER_NAME_BY_INDEX,
                        nullptr, &ctlen, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && ctlen) {
        std::wstring ct(ctlen / sizeof(wchar_t), L'\0');
        if (WinHttpQueryHeaders(req, WINHTTP_QUERY_CONTENT_TYPE, WINHTTP_HEADER_NAME_BY_INDEX,
                                ct.data(), &ctlen, WINHTTP_NO_HEADER_INDEX)) {
            if (!ct.empty() && ct.back() == L'\0') ct.pop_back();
            r.content_type = utf8(ct);
        }
    }
    {
        DWORD n = 0;
        WinHttpQueryHeaders(req, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                            nullptr, &n, WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && n) {
            std::wstring loc(n / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(req, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                                    loc.data(), &n, WINHTTP_NO_HEADER_INDEX)) {
                if (!loc.empty() && loc.back() == L'\0') loc.pop_back();
                r.headers["location"] = utf8(loc);
            }
        }
    }
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0) break;
        if (r.body.size() + avail > kMaxBody) break;
        size_t at = r.body.size();
        r.body.resize(at + avail);
        DWORD got = 0;
        if (!WinHttpReadData(req, r.body.data() + at, avail, &got)) {
            r.body.resize(at);
            break;
        }
        r.body.resize(at + got);
        if (got == 0) break;
    }
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(sess);
    return r;
}

UpstreamResult proxy_osudesu(const std::string& method, const std::string& path,
                             const std::string& query,
                             const std::map<std::string, std::string>& headers,
                             const std::string& body) {
    auto hdrs = headers;
    inject_fingerprint(hdrs);
    std::string host = g_upstream;
    bool tls = true;
    INTERNET_PORT port = 443;
    if (host.rfind("https://", 0) == 0) host = host.substr(8);
    else if (host.rfind("http://", 0) == 0) {
        host = host.substr(7);
        tls = false;
        port = 80;
    }
    auto slash = host.find('/');
    if (slash != std::string::npos) host = host.substr(0, slash);
    auto colon = host.find(':');
    if (colon != std::string::npos) {
        port = (INTERNET_PORT)atoi(host.c_str() + colon + 1);
        host = host.substr(0, colon);
    }
    int timeout = 45000;
    if (path.find("/download") != std::string::npos)
        timeout = 120000;
    else if (method == "PUT" || path.find("/solo/scores") != std::string::npos)
        timeout = 90000;
    else if (path.find("/wiki") != std::string::npos)
        timeout = 60000;
    return winhttp_call(utf16(host), port, tls, method, path, query, hdrs, body, timeout);
}

UpstreamResult proxy_avatars(const std::string& path, const std::string& query,
                             const std::map<std::string, std::string>& headers) {
    return winhttp_call(utf16(g_avatar_host), 443, true, "GET", path, query, headers, "", 15000);
}

#ifndef WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET
#define WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET 114
#endif

void split_upstream(std::string& host, INTERNET_PORT& port, bool& tls) {
    host = g_upstream;
    tls = true;
    port = 443;
    if (host.rfind("https://", 0) == 0) host = host.substr(8);
    else if (host.rfind("http://", 0) == 0) {
        host = host.substr(7);
        tls = false;
        port = 80;
    }
    auto slash = host.find('/');
    if (slash != std::string::npos) host = host.substr(0, slash);
    auto colon = host.find(':');
    if (colon != std::string::npos) {
        port = (INTERNET_PORT)atoi(host.c_str() + colon + 1);
        host = host.substr(0, colon);
    }
}

std::string dispatch(const std::string& method, const std::string& host_in,
                     std::string path, const std::string& query,
                     const std::map<std::string, std::string>& headers,
                     const std::string& body) {
    std::string host = lower(host_in);
    auto colon = host.find(':');
    if (colon != std::string::npos) host = host.substr(0, colon);
    if (path.size() > 1) {
        while (path.size() > 1 && path.back() == '/') path.pop_back();
    }

    if ((path == "/" || path == "/health" || path == "/osudesu-lazer") && method == "GET") {
        return text_resp(std::string("osudesu connector is running\nupstream: ") + g_upstream + "\n");
    }
    if (host == "a.ppy.sh") {
        auto up = proxy_avatars(path, query, headers);
        return raw_resp(up.status, up.content_type.empty() ? "image/png" : up.content_type, up.body);
    }
    if (host == "bss.ppy.sh") {
        std::string rest = path;
        if (rest.rfind("/d/", 0) == 0) rest = rest.substr(3);
        else if (!rest.empty() && rest[0] == '/') rest = rest.substr(1);
        while (!rest.empty()) {
            char c = rest.back();
            if (c == 'n' || c == 'N' || c == 'h' || c == 'H') rest.pop_back();
            else break;
        }
        std::string id;
        for (char c : rest) {
            if (c >= '0' && c <= '9') id.push_back(c);
            else break;
        }
        if (id.empty()) return json_text("{\"error\":\"beatmap not found\"}", 404);
        std::vector<std::pair<std::string, std::string>> extra;
        extra.emplace_back("Location", "https://mirror.hinamizawa.ai/api/v1/hinai/d/" + id);
        return raw_resp(302, "text/plain", "", extra);
    }

    auto last = path;
    auto slash = last.find_last_of('/');
    if (slash != std::string::npos) last = last.substr(slash + 1);

    auto starts = [&](const char* p) { return path.rfind(p, 0) == 0; };
    if (starts("/wiki/") || starts("/home/"))
        return json_text("{\"error\":\"not available on osudesu\"}", 404);

    if (path == "/oauth/token" || starts("/oauth/") || starts("/api/v2") || path == "/users"
        || host == "spectator.osu.ppy.sh"
        || starts("/spectator") || starts("/multiplayer") || starts("/metadata")
        || last == "negotiate" || last.rfind("negotiate?", 0) == 0) {
        auto up = proxy_osudesu(method, path, query, headers, body);
        std::vector<std::pair<std::string, std::string>> extra;
        if (up.status == 302) {
            auto loc = up.headers.find("location");
            if (loc != up.headers.end()) extra.emplace_back("Location", loc->second);
        }
        std::string ctype = up.content_type.empty() ? "application/json; charset=utf-8" : up.content_type;
        return raw_resp(up.status, ctype, up.body, extra);
    }

    if (method == "GET") return json_text("[]");
    return json_text("{}");
}

struct TlsConn {
    SOCKET s = INVALID_SOCKET;
    CtxtHandle ctx{};
    bool ctx_ok = false;
    SecPkgContext_StreamSizes sizes{};
    std::string enc;
    std::string app;

    ~TlsConn() {
        if (ctx_ok) DeleteSecurityContext(&ctx);
        if (s != INVALID_SOCKET) closesocket(s);
    }

    bool handshake() {
        DWORD req = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY |
                    ASC_REQ_EXTENDED_ERROR | ASC_REQ_STREAM | ASC_REQ_ALLOCATE_MEMORY;
        std::vector<char> buf(16 * 1024);
        SECURITY_STATUS st = SEC_I_CONTINUE_NEEDED;
        bool first = true;
        while (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_INCOMPLETE_MESSAGE) {
            if (st != SEC_E_INCOMPLETE_MESSAGE) enc.clear();
            int n = recv(s, buf.data(), (int)buf.size(), 0);
            if (n <= 0) return false;
            enc.append(buf.data(), buf.data() + n);

            SecBuffer in[2]{};
            in[0].BufferType = SECBUFFER_TOKEN;
            in[0].cbBuffer = (ULONG)enc.size();
            in[0].pvBuffer = enc.empty() ? nullptr : enc.data();
            in[1].BufferType = SECBUFFER_EMPTY;
            SecBufferDesc in_desc{SECBUFFER_VERSION, 2, in};

            SecBuffer out[1]{};
            out[0].BufferType = SECBUFFER_TOKEN;
            SecBufferDesc out_desc{SECBUFFER_VERSION, 1, out};

            DWORD attr = 0;
            st = AcceptSecurityContext(&g_cred, first ? nullptr : &ctx, &in_desc, req, 0,
                                       &ctx, &out_desc, &attr, nullptr);
            first = false;
            ctx_ok = true;
            if (out[0].pvBuffer && out[0].cbBuffer) {
                send(s, (char*)out[0].pvBuffer, (int)out[0].cbBuffer, 0);
                FreeContextBuffer(out[0].pvBuffer);
            }
            if (st == SEC_E_INCOMPLETE_MESSAGE) continue;
            if (FAILED(st) && st != SEC_I_CONTINUE_NEEDED) return false;
            if (in[1].BufferType == SECBUFFER_EXTRA && in[1].cbBuffer > 0 && in[1].pvBuffer) {
                size_t extra = in[1].cbBuffer;
                enc = std::string((char*)enc.data() + (enc.size() - extra), extra);
            } else {
                enc.clear();
            }
        }
        if (st != SEC_E_OK) return false;
        if (QueryContextAttributes(&ctx, SECPKG_ATTR_STREAM_SIZES, &sizes) != SEC_E_OK)
            return false;
        return true;
    }

    bool read_plain(std::string& out) {
        if (!app.empty()) {
            out.swap(app);
            app.clear();
            return true;
        }
        char buf[16 * 1024];
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) return false;
        enc.append(buf, buf + n);

        SecBuffer bufs[4]{};
        bufs[0].BufferType = SECBUFFER_DATA;
        bufs[0].cbBuffer = (ULONG)enc.size();
        bufs[0].pvBuffer = enc.data();
        bufs[1].BufferType = SECBUFFER_EMPTY;
        bufs[2].BufferType = SECBUFFER_EMPTY;
        bufs[3].BufferType = SECBUFFER_EMPTY;
        SecBufferDesc desc{SECBUFFER_VERSION, 4, bufs};
        SECURITY_STATUS st = DecryptMessage(&ctx, &desc, 0, nullptr);
        if (st == SEC_E_INCOMPLETE_MESSAGE) {
            out.clear();
            return true;
        }
        if (st == SEC_I_CONTEXT_EXPIRED || st == SEC_E_CONTEXT_EXPIRED) return false;
        if (FAILED(st)) return false;
        enc.clear();
        for (int i = 0; i < 4; ++i) {
            if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].pvBuffer && bufs[i].cbBuffer)
                out.append((char*)bufs[i].pvBuffer, bufs[i].cbBuffer);
            if (bufs[i].BufferType == SECBUFFER_EXTRA && bufs[i].pvBuffer && bufs[i].cbBuffer)
                enc.assign((char*)bufs[i].pvBuffer, bufs[i].cbBuffer);
        }
        return true;
    }

    bool write_plain(const char* data, size_t n) {
        size_t off = 0;
        while (off < n) {
            size_t chunk = std::min((size_t)sizes.cbMaximumMessage, n - off);
            std::vector<char> pkt(sizes.cbHeader + chunk + sizes.cbTrailer);
            memcpy(pkt.data() + sizes.cbHeader, data + off, chunk);
            SecBuffer bufs[4]{};
            bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
            bufs[0].cbBuffer = sizes.cbHeader;
            bufs[0].pvBuffer = pkt.data();
            bufs[1].BufferType = SECBUFFER_DATA;
            bufs[1].cbBuffer = (ULONG)chunk;
            bufs[1].pvBuffer = pkt.data() + sizes.cbHeader;
            bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
            bufs[2].cbBuffer = sizes.cbTrailer;
            bufs[2].pvBuffer = pkt.data() + sizes.cbHeader + chunk;
            bufs[3].BufferType = SECBUFFER_EMPTY;
            SecBufferDesc desc{SECBUFFER_VERSION, 4, bufs};
            if (FAILED(EncryptMessage(&ctx, 0, &desc, 0))) return false;
            int total = (int)(bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer);
            int sent = send(s, pkt.data(), total, 0);
            if (sent != total) return false;
            off += chunk;
        }
        return true;
    }

    bool write_all(const std::string& s) { return write_plain(s.data(), s.size()); }

    bool read_until(std::string& acc, const std::string& needle, size_t cap) {
        while (acc.find(needle) == std::string::npos) {
            if (acc.size() > cap) return false;
            std::string chunk;
            if (!read_plain(chunk)) return false;
            if (chunk.empty()) continue;
            acc += chunk;
        }
        return true;
    }
};

bool parse_headers(const std::string& raw, std::map<std::string, std::string>& out) {
    size_t i = 0;
    while (i < raw.size()) {
        size_t nl = raw.find("\r\n", i);
        std::string line = raw.substr(i, nl == std::string::npos ? std::string::npos : nl - i);
        if (nl == std::string::npos) break;
        i = nl + 2;
        if (line.empty()) break;
        auto c = line.find(':');
        if (c == std::string::npos) continue;
        out[lower(trim(line.substr(0, c)))] = trim(line.substr(c + 1));
    }
    return true;
}

bool finish_multipart_body(TlsConn& tls, std::string& body, std::string& leftover,
                           const std::string& boundary) {
    const std::string end = "--" + boundary + "--";
    body += leftover;
    leftover.clear();
    if (!tls.read_until(body, end, kMaxBody)) return !body.empty();
    auto pos = body.find(end);
    pos += end.size();
    if (pos + 1 < body.size() && body[pos] == '\r') pos += 2;
    else if (pos < body.size() && body[pos] == '\n') pos += 1;
    leftover = body.substr(pos);
    body.resize(pos);
    return true;
}

std::string read_chunked(TlsConn& tls, std::string& leftover) {
    std::string body;
    std::string acc = leftover;
    leftover.clear();
    for (;;) {
        if (!tls.read_until(acc, "\r\n", 64 * 1024)) return {};
        auto nl = acc.find("\r\n");
        std::string size_line = acc.substr(0, nl);
        acc.erase(0, nl + 2);
        auto sc = size_line.find(';');
        if (sc != std::string::npos) size_line = size_line.substr(0, sc);
        size_t sz = 0;
        try {
            sz = (size_t)std::stoul(trim(size_line), nullptr, 16);
        } catch (...) {
            return {};
        }
        if (sz == 0) {
            leftover = acc;
            return body;
        }
        while (acc.size() < sz + 2) {
            std::string chunk;
            if (!tls.read_plain(chunk)) return {};
            acc += chunk;
        }
        body.append(acc, 0, sz);
        acc.erase(0, sz);
        if (acc.size() >= 2 && acc[0] == '\r' && acc[1] == '\n') acc.erase(0, 2);
        if (body.size() > kMaxBody) return {};
    }
}

std::string ws_frame(int opcode, const std::string& payload) {
    std::string f;
    f.push_back((char)(0x80 | (opcode & 0x0F)));
    size_t n = payload.size();
    if (n < 126) {
        f.push_back((char)n);
    } else if (n < 65536) {
        f.push_back(126);
        f.push_back((char)((n >> 8) & 0xFF));
        f.push_back((char)(n & 0xFF));
    } else {
        f.push_back(127);
        for (int i = 7; i >= 0; --i) f.push_back((char)((n >> (i * 8)) & 0xFF));
    }
    f += payload;
    return f;
}

bool proxy_ws_upstream(TlsConn& tls, const std::string& path, const std::string& query,
                       std::map<std::string, std::string> headers, std::string leftover,
                       const std::string& ws_key) {
    inject_fingerprint(headers);
    std::string host;
    INTERNET_PORT port = 443;
    bool use_tls = true;
    split_upstream(host, port, use_tls);

    HINTERNET sess = WinHttpOpen(L"desuswitch/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!sess) return false;
    WinHttpSetTimeouts(sess, 30000, 30000, 0, 0);
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(sess, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));
    HINTERNET conn = WinHttpConnect(sess, utf16(host).c_str(), port, 0);
    if (!conn) {
        WinHttpCloseHandle(sess);
        return false;
    }
    DWORD flags = use_tls ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET req = WinHttpOpenRequest(conn, L"GET", to_wide_path(path, query).c_str(),
                                       nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(sess);
        return false;
    }
    WinHttpSetOption(req, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0);
    std::wstring hdr;
    for (auto& [k, v] : headers) {
        if (hop_by_hop(k)) continue;
        hdr += utf16(k);
        hdr += L": ";
        hdr += utf16(v);
        hdr += L"\r\n";
    }
    if (!WinHttpSendRequest(req, hdr.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : hdr.c_str(),
                            hdr.empty() ? 0 : (DWORD)-1, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        || !WinHttpReceiveResponse(req, nullptr)) {
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(sess);
        return false;
    }
    HINTERNET ws = WinHttpWebSocketCompleteUpgrade(req, 0);
    WinHttpCloseHandle(req);
    if (!ws) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(sess);
        return false;
    }

    std::string accept = ws_accept_key(ws_key);
    std::ostringstream o;
    o << "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
         "Connection: Upgrade\r\nSec-WebSocket-Accept: "
      << accept << "\r\n\r\n";
    if (!tls.write_all(o.str())) {
        WinHttpCloseHandle(ws);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(sess);
        return false;
    }

    std::atomic<bool> run{true};
    std::thread up2down([&]() {
        char buf[64 * 1024];
        while (run && g_run) {
            DWORD got = 0;
            WINHTTP_WEB_SOCKET_BUFFER_TYPE t{};
            DWORD err = WinHttpWebSocketReceive(ws, buf, sizeof(buf), &got, &t);
            if (err != NO_ERROR) break;
            if (t == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) break;
            int opcode = 1;
            if (t == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE
                || t == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE)
                opcode = 2;
            if (!tls.write_all(ws_frame(opcode, std::string(buf, buf + got)))) break;
        }
        run = false;
    });

    std::string acc = leftover;
    auto need = [&](size_t n) {
        while (acc.size() < n) {
            std::string c;
            if (!tls.read_plain(c) || c.empty()) return false;
            acc += c;
        }
        return true;
    };
    while (run && g_run) {
        if (!need(2)) break;
        unsigned char b0 = (unsigned char)acc[0];
        unsigned char b1 = (unsigned char)acc[1];
        int opcode = b0 & 0x0F;
        bool masked = (b1 & 0x80) != 0;
        uint64_t len = b1 & 0x7F;
        size_t hdrn = 2;
        if (len == 126) {
            if (!need(4)) break;
            len = ((unsigned char)acc[2] << 8) | (unsigned char)acc[3];
            hdrn = 4;
        } else if (len == 127) {
            if (!need(10)) break;
            len = 0;
            for (int i = 0; i < 8; ++i) len = (len << 8) | (unsigned char)acc[2 + i];
            hdrn = 10;
        }
        size_t mask_off = hdrn;
        if (masked) hdrn += 4;
        if (len > 1024 * 1024) break;
        if (!need(hdrn + (size_t)len)) break;
        std::string payload = acc.substr(hdrn, (size_t)len);
        if (masked) {
            unsigned char m[4];
            for (int i = 0; i < 4; ++i) m[i] = (unsigned char)acc[mask_off + i];
            for (size_t i = 0; i < payload.size(); ++i)
                payload[i] = (char)((unsigned char)payload[i] ^ m[i % 4]);
        }
        acc.erase(0, hdrn + (size_t)len);
        if (opcode == 0x8) {
            WinHttpWebSocketClose(ws, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
            break;
        }
        if (opcode == 0x9) {
            tls.write_all(ws_frame(0xA, payload));
            continue;
        }
        WINHTTP_WEB_SOCKET_BUFFER_TYPE t = (opcode == 0x2)
            ? WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE
            : WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE;
        if (WinHttpWebSocketSend(ws, t, (PVOID)payload.data(), (DWORD)payload.size()) != NO_ERROR)
            break;
    }
    run = false;
    WinHttpWebSocketShutdown(ws, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
    if (up2down.joinable()) up2down.join();
    WinHttpCloseHandle(ws);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(sess);
    return true;
}

void handle_client(SOCKET s) {
    TlsConn tls;
    tls.s = s;
    DWORD timeout = 120000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    BOOL nd = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&nd, sizeof(nd));
    if (!tls.handshake()) return;

    while (g_run) {
        std::string acc;
        if (!tls.read_until(acc, "\r\n\r\n", 1024 * 1024)) return;
        auto sep = acc.find("\r\n\r\n");
        std::string head = acc.substr(0, sep);
        std::string leftover = acc.substr(sep + 4);
        auto line_end = head.find("\r\n");
        std::string reqline = line_end == std::string::npos ? head : head.substr(0, line_end);
        std::istringstream rs(reqline);
        std::string method, target, ver;
        rs >> method >> target >> ver;
        if (method.empty() || target.empty()) return;
        for (char& c : method) c = (char)toupper((unsigned char)c);
        std::map<std::string, std::string> headers;
        parse_headers(line_end == std::string::npos ? "" : head.substr(line_end + 2), headers);
        auto exp = headers.find("expect");
        if (exp != headers.end() && lower(exp->second).find("100-continue") != std::string::npos) {
            tls.write_all("HTTP/1.1 100 Continue\r\n\r\n");
        }
        std::string path = target, query;
        auto qpos = target.find('?');
        if (qpos != std::string::npos) {
            path = target.substr(0, qpos);
            query = target.substr(qpos + 1);
        }
        std::string body;
        auto te = header_get(headers, "transfer-encoding");
        auto cl_s = header_get(headers, "content-length");
        const bool is_chunked = lower(te).find("chunked") != std::string::npos;
        const bool wants_body = method == "POST" || method == "PUT" || method == "PATCH";
        size_t len = 0;
        bool has_cl = false;
        if (!cl_s.empty()) {
            has_cl = true;
            try {
                len = (size_t)std::stoull(cl_s);
            } catch (...) {
                len = 0;
            }
        }
        const std::string boundary = ctype_boundary(header_get(headers, "content-type"));

        if (is_chunked) {
            body = read_chunked(tls, leftover);
        } else if (has_cl && len > 0) {
            if (len > kMaxBody) return;
            body = leftover;
            leftover.clear();
            while (body.size() < len) {
                std::string chunk;
                if (!tls.read_plain(chunk)) return;
                if (chunk.empty()) continue;
                body += chunk;
            }
            leftover = body.substr(len);
            body.resize(len);
        } else if (wants_body && (!boundary.empty() || looks_like_form_body(leftover))) {
            if (!boundary.empty()) {
                finish_multipart_body(tls, body, leftover, boundary);
            } else {
                body = leftover;
                leftover.clear();
                if (body.empty()) {
                    std::string chunk;
                    if (tls.read_plain(chunk)) body += chunk;
                }
            }
        } else {
            body = leftover;
            leftover.clear();
            leftover = body.substr(len);
            body.resize(len);
        }

        std::string host = headers.count("host") ? headers["host"] : "";
        std::string upgrade = headers.count("upgrade") ? lower(headers["upgrade"]) : "";

        if (upgrade == "websocket") {
            auto key_it = headers.find("sec-websocket-key");
            if (key_it == headers.end()) {
                tls.write_all(text_resp("missing key", 400));
                return;
            }
            if (!proxy_ws_upstream(tls, path, query, headers, leftover, key_it->second))
                tls.write_all(text_resp("upstream websocket failed", 502));
            return;
        }

        std::string resp = dispatch(method, host, path, query, headers, body);
        if (!tls.write_all(resp)) return;
        auto c = headers.find("connection");
        if (c != headers.end() && lower(c->second) == "close") return;
    }
}

SOCKET listen_on(int family, const void* addr, int addrlen) {
    SOCKET s = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    BOOL reuse = TRUE;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    if (bind(s, (sockaddr*)addr, addrlen) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    if (listen(s, 128) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

void accept_loop() {
    while (g_run) {
        fd_set fds;
        FD_ZERO(&fds);
        int maxfd = 0;
        if (g_listen4 != INVALID_SOCKET) {
            FD_SET(g_listen4, &fds);
            maxfd = (int)g_listen4;
        }
        if (g_listen6 != INVALID_SOCKET) {
            FD_SET(g_listen6, &fds);
            if ((int)g_listen6 > maxfd) maxfd = (int)g_listen6;
        }
        timeval tv{0, 250000};
        int n = select(maxfd + 1, &fds, nullptr, nullptr, &tv);
        if (n <= 0) continue;
        auto take = [&](SOCKET ls) {
            if (ls == INVALID_SOCKET || !FD_ISSET(ls, &fds)) return;
            SOCKET c = accept(ls, nullptr, nullptr);
            if (c == INVALID_SOCKET) return;
            u_long nb = 0;
            ioctlsocket(c, FIONBIO, &nb);
            std::thread([c]() {
                handle_client(c);
            }).detach();
        };
        take(g_listen4);
        take(g_listen6);
    }
}

}  // namespace

bool start_proxy(PCCERT_CONTEXT cert, const std::string& upstream, std::string& err) {
    if (g_run) {
        err = "Already connected";
        return false;
    }
    g_upstream = upstream;
    while (!g_upstream.empty() && g_upstream.back() == '/') g_upstream.pop_back();
    std::string host = g_upstream;
    if (host.rfind("https://", 0) == 0) host = host.substr(8);
    else if (host.rfind("http://", 0) == 0) host = host.substr(7);
    auto slash = host.find('/');
    if (slash != std::string::npos) host.resize(slash);
    auto colon = host.find(':');
    if (colon != std::string::npos) host.resize(colon);
    g_avatar_host = std::string("a.") + host;

    g_cred_cert = cert;
    SCHANNEL_CRED sc{};
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.cCreds = 1;
    sc.paCred = &g_cred_cert;
    sc.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
    sc.dwFlags = SCH_CRED_NO_SYSTEM_MAPPER | SCH_CRED_NO_DEFAULT_CREDS;

    TimeStamp ts{};
    SECURITY_STATUS st = AcquireCredentialsHandleW(nullptr, const_cast<wchar_t*>(UNISP_NAME_W),
                                                   SECPKG_CRED_INBOUND, nullptr, &sc, nullptr,
                                                   nullptr, &g_cred, &ts);
    if (st != SEC_E_OK) {
        err = "AcquireCredentialsHandle failed";
        return false;
    }
    g_cred_ok = true;

    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    sockaddr_in a4{};
    a4.sin_family = AF_INET;
    a4.sin_port = htons(kListenPort);
    inet_pton(AF_INET, "127.0.0.1", &a4.sin_addr);
    g_listen4 = listen_on(AF_INET, &a4, sizeof(a4));
    if (g_listen4 == INVALID_SOCKET) {
        FreeCredentialsHandle(&g_cred);
        g_cred_ok = false;
        err = "Cannot bind 127.0.0.1:443 (is another connector still running?)";
        return false;
    }

    sockaddr_in6 a6{};
    a6.sin6_family = AF_INET6;
    a6.sin6_port = htons(kListenPort);
    a6.sin6_addr = in6addr_loopback;
    g_listen6 = listen_on(AF_INET6, &a6, sizeof(a6));

    g_run = true;
    g_thr = std::thread(accept_loop);
    return true;
}

void stop_proxy() {
    g_run = false;
    if (g_listen4 != INVALID_SOCKET) {
        closesocket(g_listen4);
        g_listen4 = INVALID_SOCKET;
    }
    if (g_listen6 != INVALID_SOCKET) {
        closesocket(g_listen6);
        g_listen6 = INVALID_SOCKET;
    }
    if (g_thr.joinable()) g_thr.join();
    if (g_cred_ok) {
        FreeCredentialsHandle(&g_cred);
        g_cred_ok = false;
    }
}

bool proxy_running() { return g_run.load(); }

}  // namespace oc
