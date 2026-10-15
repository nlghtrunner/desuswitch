#pragma once

#include <string>

namespace oc {

struct Release {
    std::string version;
    std::string url;
    std::string sha256;
};

bool version_newer(const std::string& remote, const std::string& local);
bool parse_release(const std::string& json, Release& out);
bool self_test_update();

bool check_update(Release& out);
bool download_and_apply(const Release& rel, std::string& err);

}  // namespace oc
