#pragma once

#include "certs.hpp"

#include <string>

namespace oc {

bool start_proxy(PCCERT_CONTEXT cert, const std::string& upstream, bool& listen_v6, std::string& err);
void stop_proxy();
bool proxy_running();

}  // namespace oc
