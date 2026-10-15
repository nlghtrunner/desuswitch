#pragma once

#include "common.hpp"

#include <wincrypt.h>

namespace oc {

struct Cert {
    PCCERT_CONTEXT ctx = nullptr;
    ~Cert() {
        if (ctx) CertFreeCertificateContext(ctx);
    }
    Cert() = default;
    Cert(const Cert&) = delete;
    Cert& operator=(const Cert&) = delete;
};

bool ensure_trusted_cert(Cert& out, std::string& err);

}  // namespace oc
