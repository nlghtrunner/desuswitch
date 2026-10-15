#pragma once

#include "common.hpp"

namespace oc {

bool apply_hosts(std::string& err, bool ipv6);
bool restore_hosts(std::string& err);
void flush_dns();

}  // namespace oc
