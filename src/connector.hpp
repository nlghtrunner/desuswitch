#pragma once

#include "common.hpp"

#include <string>

namespace oc {

void recover_hosts_on_startup();
bool connect_now(std::string& err);
void disconnect_now();
bool is_connected();

}  // namespace oc
