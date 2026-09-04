#include "certs.hpp"

#include <bcrypt.h>
#include <ncrypt.h>
#include <cstdio>
#include <vector>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace oc {
namespace {

constexpr wchar_t kKeyName[] = L"desupatch-tls";

void set_friendly_name(PCCERT_CONTEXT ctx) {
    std::wstring name = kCertFriendly;
    CRYPT_DATA_BLOB blob{};
    blob.cbData = (DWORD)((name.size() + 1) * sizeof(wchar_t));
    blob.pbData = (BYTE*)name.data();
    CertSetCertificateContextProperty(ctx, CERT_FRIENDLY_NAME_PROP_ID, 0, &blob);
}

std::wstring friendly_name(PCCERT_CONTEXT ctx) {
    DWORD n = 0;
    if (!CertGetCertificateContextProperty(ctx, CERT_FRIENDLY_NAME_PROP_ID, nullptr, &n) || !n)
        return {};
    std::wstring name(n / sizeof(wchar_t), L'\0');
    if (!CertGetCertificateContextProperty(ctx, CERT_FRIENDLY_NAME_PROP_ID, name.data(), &n))
        return {};
    while (!name.empty() && name.back() == L'\0') name.pop_back();
    return name;
}

bool is_ours(PCCERT_CONTEXT ctx) {
    auto name = friendly_name(ctx);
    if (name == kCertFriendly || name == kCertFriendlyOld) return true;
    wchar_t subj[256]{};
    wchar_t iss[256]{};
    CertNameToStrW(X509_ASN_ENCODING, &ctx->pCertInfo->Subject, CERT_X500_NAME_STR, subj, 256);
    CertNameToStrW(X509_ASN_ENCODING, &ctx->pCertInfo->Issuer, CERT_X500_NAME_STR, iss, 256);
    return wcsstr(subj, L"CN=osu.ppy.sh") && wcscmp(subj, iss) == 0;
}

bool has_private_key(PCCERT_CONTEXT ctx) {
    DWORD n = 0;
    return CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &n) == TRUE;
}

void purge_old(HCERTSTORE store) {
    PCCERT_CONTEXT prev = nullptr;
    while ((prev = CertEnumCertificatesInStore(store, prev)) != nullptr) {
        if (!is_ours(prev)) continue;
        PCCERT_CONTEXT del = CertDuplicateCertificateContext(prev);
        CertDeleteCertificateFromStore(del);
        prev = nullptr;
    }
}

PCCERT_CONTEXT find_usable(HCERTSTORE store) {
    PCCERT_CONTEXT prev = nullptr;
    while ((prev = CertEnumCertificatesInStore(store, prev)) != nullptr) {
        if (!is_ours(prev) || !has_private_key(prev)) continue;
        PCCERT_CONTEXT dup = CertDuplicateCertificateContext(prev);
        CertFreeCertificateContext(prev);
        return dup;
    }
    return nullptr;
}

bool encode_san(CRYPT_DATA_BLOB& blob) {
    std::wstring names[kHostCount];
    std::vector<CERT_ALT_NAME_ENTRY> entries(kHostCount);
    for (int i = 0; i < kHostCount; ++i) {
        names[i] = kHostNames[i];
        entries[i].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
        entries[i].pwszDNSName = names[i].data();
    }
    CERT_ALT_NAME_INFO info{};
    info.cAltEntry = (DWORD)entries.size();
    info.rgAltEntry = entries.data();
    blob.cbData = 0;
    blob.pbData = nullptr;
    return CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, &info,
                               CRYPT_ENCODE_ALLOC_FLAG, nullptr, &blob.pbData, &blob.cbData) != 0;
}

bool encode_eku(CRYPT_DATA_BLOB& blob) {
    LPSTR usage[] = {const_cast<LPSTR>(szOID_PKIX_KP_SERVER_AUTH)};
    CERT_ENHKEY_USAGE eku{};
    eku.cUsageIdentifier = 1;
    eku.rgpszUsageIdentifier = usage;
    blob.cbData = 0;
    blob.pbData = nullptr;
    return CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &eku,
                               CRYPT_ENCODE_ALLOC_FLAG, nullptr, &blob.pbData, &blob.cbData) != 0;
}

void validity(SYSTEMTIME& not_before, SYSTEMTIME& not_after) {
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    const ULONGLONG day = 864000000000ULL;
    u.QuadPart -= day;
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    FileTimeToSystemTime(&ft, &not_before);
    u.QuadPart += day + 10ULL * 365ULL * day;
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    FileTimeToSystemTime(&ft, &not_after);
}

PCCERT_CONTEXT create_cert(std::string& err) {
    NCRYPT_PROV_HANDLE provider = 0;
    SECURITY_STATUS st = NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0);
    if (st != ERROR_SUCCESS) {
        err = "NCryptOpenStorageProvider failed";
        return nullptr;
    }

    NCRYPT_KEY_HANDLE key = 0;
    st = NCryptCreatePersistedKey(provider, &key, BCRYPT_RSA_ALGORITHM, kKeyName, 0,
                                  NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG);
    if (st != ERROR_SUCCESS) {
        NCryptFreeObject(provider);
        err = "NCryptCreatePersistedKey failed";
        return nullptr;
    }
    DWORD bits = 2048;
    NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, sizeof(bits), 0);
    DWORD usage = NCRYPT_ALLOW_DECRYPT_FLAG | NCRYPT_ALLOW_SIGNING_FLAG;
    NCryptSetProperty(key, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&usage, sizeof(usage), 0);
    st = NCryptFinalizeKey(key, 0);
    if (st != ERROR_SUCCESS) {
        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        err = "NCryptFinalizeKey failed";
        return nullptr;
    }

    BYTE name_buf[256];
    DWORD name_len = sizeof(name_buf);
    if (!CertStrToNameW(X509_ASN_ENCODING, L"CN=osu.ppy.sh", CERT_X500_NAME_STR, nullptr,
                        name_buf, &name_len, nullptr)) {
        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        err = win_error("CertStrToName failed");
        return nullptr;
    }
    CERT_NAME_BLOB subject{name_len, name_buf};

    CRYPT_DATA_BLOB san{}, eku{};
    if (!encode_san(san) || !encode_eku(eku)) {
        if (san.pbData) LocalFree(san.pbData);
        if (eku.pbData) LocalFree(eku.pbData);
        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        err = win_error("Failed to encode certificate extensions");
        return nullptr;
    }

    CERT_EXTENSION exts[2]{};
    exts[0].pszObjId = const_cast<char*>(szOID_SUBJECT_ALT_NAME2);
    exts[0].fCritical = FALSE;
    exts[0].Value = san;
    exts[1].pszObjId = const_cast<char*>(szOID_ENHANCED_KEY_USAGE);
    exts[1].fCritical = FALSE;
    exts[1].Value = eku;
    CERT_EXTENSIONS ext_list{};
    ext_list.cExtension = 2;
    ext_list.rgExtension = exts;

    CRYPT_KEY_PROV_INFO kpi{};
    kpi.pwszContainerName = const_cast<wchar_t*>(kKeyName);
    kpi.pwszProvName = const_cast<wchar_t*>(MS_KEY_STORAGE_PROVIDER);
    kpi.dwProvType = 0;
    kpi.dwFlags = NCRYPT_MACHINE_KEY_FLAG;
    kpi.dwKeySpec = 0;

    CRYPT_ALGORITHM_IDENTIFIER sig{};
    sig.pszObjId = const_cast<char*>(szOID_RSA_SHA256RSA);

    SYSTEMTIME not_before{}, not_after{};
    validity(not_before, not_after);

    PCCERT_CONTEXT ctx = CertCreateSelfSignCertificate(
        (HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)key, &subject, 0, &kpi, &sig,
        &not_before, &not_after, &ext_list);
    if (!ctx) {
        ctx = CertCreateSelfSignCertificate(0, &subject, 0, &kpi, &sig,
                                            &not_before, &not_after, &ext_list);
    }

    LocalFree(san.pbData);
    LocalFree(eku.pbData);
    NCryptFreeObject(key);
    NCryptFreeObject(provider);

    if (!ctx) {
        err = win_error("CertCreateSelfSignCertificate failed");
        return nullptr;
    }
    set_friendly_name(ctx);
    return ctx;
}

}  // namespace

bool ensure_trusted_cert(Cert& out, std::string& err) {
    HCERTSTORE my = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                  CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY");
    HCERTSTORE root = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                    CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT");
    if (!my || !root) {
        if (my) CertCloseStore(my, 0);
        if (root) CertCloseStore(root, 0);
        err = "Failed to open certificate stores (need Administrator)";
        return false;
    }

    if (PCCERT_CONTEXT existing = find_usable(my)) {
        set_friendly_name(existing);
        CertAddCertificateContextToStore(root, existing, CERT_STORE_ADD_REPLACE_EXISTING, nullptr);
        CertCloseStore(my, 0);
        CertCloseStore(root, 0);
        out.ctx = existing;
        log("Reusing existing TLS certificate");
        return true;
    }

    PCCERT_CONTEXT ctx = create_cert(err);
    if (!ctx) {
        CertCloseStore(my, 0);
        CertCloseStore(root, 0);
        return false;
    }

    purge_old(my);
    purge_old(root);

    PCCERT_CONTEXT stored = nullptr;
    if (!CertAddCertificateContextToStore(my, ctx, CERT_STORE_ADD_REPLACE_EXISTING, &stored)) {
        err = win_error("Failed to install certificate into LocalMachine\\My");
        CertFreeCertificateContext(ctx);
        CertCloseStore(my, 0);
        CertCloseStore(root, 0);
        return false;
    }
    if (!CertAddCertificateContextToStore(root, stored, CERT_STORE_ADD_REPLACE_EXISTING, nullptr)) {
        log("%s", win_error("Warning: could not add cert to Trusted Root").c_str());
    }

    CertFreeCertificateContext(ctx);
    CertCloseStore(my, 0);
    CertCloseStore(root, 0);

    out.ctx = stored;
    log("Installed trusted TLS certificate for osu.ppy.sh");
    return true;
}

}  // namespace oc
