#include "connector.hpp"

#include "certs.hpp"
#include "hosts.hpp"
#include "proxy.hpp"

#include <mutex>
#include <cstdlib>

namespace oc {
namespace {

std::mutex g_mu;
Cert g_cert;
bool g_connected = false;
HANDLE g_singleton = nullptr;

LONG WINAPI crash_restore_hosts(EXCEPTION_POINTERS*) {
    std::string ignored;
    restore_hosts(ignored);
    return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

bool recover_hosts_on_startup() {
    g_singleton = CreateMutexW(nullptr, TRUE, L"Local\\desuswitch-singleton");
    if (g_singleton && GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(g_singleton);
        g_singleton = nullptr;
        return false;
    }
    std::string ignored;
    restore_hosts(ignored);
    SetUnhandledExceptionFilter(crash_restore_hosts);
    std::atexit([]() {
        std::string err;
        restore_hosts(err);
    });
    return true;
}

bool connect_now(std::string& err) {
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_connected) {
        err = "Already connected";
        return false;
    }
    if (!ensure_trusted_cert(g_cert, err)) return false;
    bool listen_v6 = false;
    if (!start_proxy(g_cert.ctx, kDefaultUpstream, listen_v6, err)) return false;
    if (!apply_hosts(err, listen_v6)) {
        stop_proxy();
        return false;
    }
    g_connected = true;
    return true;
}

void disconnect_now() {
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_connected && !proxy_running()) {
        std::string ignored;
        restore_hosts(ignored);
        return;
    }
    stop_proxy();
    std::string err;
    restore_hosts(err);
    g_connected = false;
}

bool is_connected() {
    std::lock_guard<std::mutex> lock(g_mu);
    return g_connected;
}

}  // namespace oc
