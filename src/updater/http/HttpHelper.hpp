#pragma once

// The HTTP layer is compiled out unless ENABLE_HTTP_UPDATER is defined.
//
// Why: libcurl is linked statically, and referencing even one of its symbols
// pulls the whole network stack into the import table. The released binary was
// importing:
//
//   WS2_32.dll   getaddrinfo, WSAEventSelect, WSAIoctl, inet_pton ...
//   CRYPT32.dll  CertCreateCertificateChainEngine, PFXImportCertStore,
//                CryptQueryObject, CertGetCertificateChain ...
//   bcrypt.dll   BCryptGenRandom
//   ADVAPI32.dll CryptAcquireContextW, CryptImportKey, CryptEncrypt ...
//
// A full PKI certificate-chain implementation inside a DirectX overlay is one
// of the strangest things a scanner can see, and none of it is used when the
// update check is off (which is now the default).
//
// Build with -DENABLE_HTTP_UPDATER to get the updater back.

#ifdef ENABLE_HTTP_UPDATER

#ifndef CURL_STATICLIB
#define CURL_STATICLIB
#endif

#include <curl/curl.h>
#pragma comment(lib, "libcurl.lib")
#pragma comment(lib, "zlib.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

#endif // ENABLE_HTTP_UPDATER

using json = nlohmann::json;

class HttpHelper {
public:
    ~HttpHelper() = default;
    HttpHelper(const HttpHelper&) = delete;
    HttpHelper(HttpHelper&&) = delete;
    HttpHelper& operator=(const HttpHelper&) = delete;
    HttpHelper& operator=(HttpHelper&&) = delete;

#ifdef ENABLE_HTTP_UPDATER
    static int Get(std::string url, json& response);
    static int Post(std::string url, json body, json& response);
#else
    // Stubs: keep the signature so Updater.cpp compiles either way, but never
    // touch the network.
    static int Get(std::string, json&)  { return -1; }
    static int Post(std::string, json, json&) { return -1; }
#endif
private:
    HttpHelper() {};

    static HttpHelper& GetInstance()
    {
        static HttpHelper i{};
        return i;
    }

#ifdef ENABLE_HTTP_UPDATER
    int GetImpl(std::string url, json& response);
    int PostImpl(std::string url, json body, json& response);

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
#endif
};
