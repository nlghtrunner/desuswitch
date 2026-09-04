#include "connector.hpp"

#include "certs.hpp"
#include "hosts.hpp"
#include "proxy.hpp"

#include <mutex>

namespace oc {
namespace {

std::mutex g_mu;
Cert g_cert;
bool g_connected = false;

}  // namespace

bool connect_now(std::string& err) {
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_connected) {
        err = "Already connected";
        return false;
    }
    log("Connecting to %s", kDefaultUpstream);
    if (!ensure_trusted_cert(g_cert, err)) return false;
    kill_listener_on_443();
    if (!apply_hosts(err)) return false;
    if (!start_proxy(g_cert.ctx, kDefaultUpstream, err)) {
        std::string ignored;
        restore_hosts(ignored);
        return false;
    }
    g_connected = true;
    log("Connected. Launch official osu!lazer and sign in with your osudesu account.");
    return true;
}

void disconnect_now() {
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_connected && !proxy_running()) {
        std::string ignored;
        restore_hosts(ignored);
        return;
    }
    log("Disconnecting...");
    stop_proxy();
    std::string err;
    restore_hosts(err);
    g_connected = false;
    log("Disconnected. osu!lazer will talk to ppy again.");
}

bool is_connected() {
    std::lock_guard<std::mutex> lock(g_mu);
    return g_connected;
}

}  // namespace oc
