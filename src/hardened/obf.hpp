// obf.hpp — compile-time string encryption.
//
// Why: every plaintext API name, DLL name, window title, project name and
// offset-signature string in this project is greppable in the shipped binary
// (.rdata). A signature scanner matches those bytes; it cannot see behaviour.
// This turns each literal into ciphertext in .rdata and decrypts into a local
// buffer only at the point of use.
//
// IMPORTANT — the object must live at namespace scope. A function-local or
// by-reference temporary keeps the original plaintext in .rdata (verified:
// `OBF("x")` inline still emitted "x"; `DEFOBJ(name, "x")` does not).
//
// Not cryptographic. It defeats static byte-matching and string dumps, which
// is the whole threat model for a user-mode binary sitting on disk.

#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

namespace obf {

#ifndef OBF_SEED
#define OBF_SEED 0x5Au
#endif

constexpr uint8_t key_for(uint32_t line, size_t i) {
    return static_cast<uint8_t>((line * 131u) + (i * 37u) + OBF_SEED);
}

template <size_t N, uint32_t L>
struct Lit {
    char enc[N];

    constexpr Lit(const char (&s)[N]) : enc{} {
        for (size_t i = 0; i < N; ++i)
            enc[i] = static_cast<char>(static_cast<uint8_t>(s[i]) ^ key_for(L, i));
    }

    void dec_into(char* out) const {
        for (size_t i = 0; i < N; ++i)
            out[i] = static_cast<char>(static_cast<uint8_t>(enc[i]) ^ key_for(L, i));
    }

    std::string dec() const {
        char buf[N];
        dec_into(buf);
        return std::string(buf, N - 1); // strip trailing NUL
    }
};

template <size_t N, uint32_t L>
struct LitW {
    wchar_t enc[N];

    constexpr LitW(const wchar_t (&s)[N]) : enc{} {
        for (size_t i = 0; i < N; ++i) {
            uint16_t v = static_cast<uint16_t>(s[i]);
            enc[i] = static_cast<wchar_t>(v ^ (static_cast<uint16_t>(key_for(L, i)) * 0x0101u));
        }
    }

    void dec_into(wchar_t* out) const {
        for (size_t i = 0; i < N; ++i) {
            uint16_t v = static_cast<uint16_t>(enc[i]);
            out[i] = static_cast<wchar_t>(v ^ (static_cast<uint16_t>(key_for(L, i)) * 0x0101u));
        }
    }
};

} // namespace obf

// Namespace-scope definition. Use this — the inline OBF() form leaks plaintext.
#define DEFOBJ(name, s)  static constexpr auto name = \
    ::obf::Lit<sizeof(s), static_cast<uint32_t>(__LINE__)>(s)

#define DEFOBJW(name, s) static constexpr auto name = \
    ::obf::LitW<(sizeof(s) / sizeof(wchar_t)), static_cast<uint32_t>(__LINE__)>(s)
