#pragma once

#include "common.hpp"

#include <string>

namespace oc {

bool connect_now(std::string& err);
void disconnect_now();
bool is_connected();

}  // namespace oc
