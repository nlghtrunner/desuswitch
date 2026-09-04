#pragma once

#include "common.hpp"

namespace oc {

bool apply_hosts(std::string& err);
bool restore_hosts(std::string& err);
void flush_dns();
void kill_listener_on_443();

}  // namespace oc
