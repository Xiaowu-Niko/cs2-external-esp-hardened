// syscall.hpp — direct/indirect system calls with no ntdll string literals.
//
// Replaces the original Memory.hpp:19-20 pattern:
//     GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory")
// which is bad in three separate ways:
//   1. "ntdll.dll" and "NtReadVirtualMemory" are plaintext in .rdata.
//   2. The returned pointer is a user-mode address inside ntdll — the exact
//      place an anti-cheat (or EDR) plants a trampoline to observe callers.
//   3. It was re-resolved on every single read (pMemory is constructed per
//      call in Memory.hpp:67 and :85), i.e. thousands of GetProcAddress/sec.
//
// What this does instead: resolve the SSN once by hashing export names, build
// a `mov r10,rcx; mov eax,ssn; syscall; ret` stub in a page that was never
// RWX, and call that. No ntdll address is ever executed, no export name is
// ever compared as a plaintext string at runtime.

#pragma once
#include <windows.h>
#include <intrin.h>      // __readgsqword
#include <cstdint>
#include <cstring>

#include "obf.hpp"

namespace sc {

// ---- FNV-1a over the export name; no string survives in the binary ----------
constexpr uint32_t fnv1a(const char* s, uint32_t h = 0x811C9DC5u) {
    return (*s == '\0') ? h : fnv1a(s + 1, (h ^ static_cast<uint8_t>(*s)) * 0x01000193u);
}

struct Stub {
    void* code = nullptr;   // executable trampoline
    uint32_t ssn = 0;       // syscall service number
    bool ok = false;
};

namespace detail {

// ---- minimal PEB / loader layout (avoids winternl.h version drift) --------
struct UniStr {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

struct LdrEntry {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UniStr     FullDllName;
    UniStr     BaseDllName;
};

struct PebLdrData {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
};

struct Peb {
    BYTE       Reserved1[2];
    BYTE       BeingDebugged;
    BYTE       Reserved2[1];
    PVOID      Reserved3[2];
    PebLdrData* Ldr;
};

inline bool ieq_ascii_ci(const wchar_t* a, const char* b, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        wchar_t x = a[i];
        char    y = b[i];
        if (x >= L'A' && x <= L'Z') x = static_cast<wchar_t>(x + 32);
        if (y >= 'A' && y <= 'Z')   y = static_cast<char>(y + 32);
        if (x != static_cast<wchar_t>(y)) return false;
    }
    return true;
}

// The loader name we want, stored XOR-obfuscated so "ntdll.dll" is not a
// readable string anywhere in the image.
struct DllName {
    static constexpr size_t N = 9;
    // encoded byte for position i
    static constexpr char enc(size_t i) {
        constexpr char plain[N] = { 'n','t','d','l','l','.','d','l','l' };
        return static_cast<char>(plain[i] ^ static_cast<char>(0x3Bu + i * 7u));
    }
    // decode at position i
    static constexpr char dec(size_t i) {
        return static_cast<char>(enc(i) ^ static_cast<char>(0x3Bu + i * 7u));
    }
    static constexpr bool match(const wchar_t* wide, size_t len) {
        if (len != N) return false;
        for (size_t i = 0; i < N; ++i) {
            wchar_t c = wide[i];
            if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c + 32);
            if (c != static_cast<wchar_t>(dec(i))) return false;
        }
        return true;
    }
};

// Locate ntdll by matching BaseDllName in the PEB — no GetModuleHandle call,
// no "ntdll.dll" literal, no loader lock, no import-table entry.
inline uintptr_t ntdll_base() {
    auto* peb = reinterpret_cast<Peb*>(__readgsqword(0x60));
    if (!peb || !peb->Ldr) return 0;

    auto* head = &peb->Ldr->InMemoryOrderModuleList;
    for (auto* it = head->Flink; it && it != head; it = it->Flink) {
        auto* e = CONTAINING_RECORD(it, LdrEntry, InMemoryOrderLinks);
        if (!e->DllBase || e->BaseDllName.Buffer == nullptr) continue;

        if (DllName::match(e->BaseDllName.Buffer,
                           e->BaseDllName.Length / sizeof(wchar_t)))
            return reinterpret_cast<uintptr_t>(e->DllBase);
    }
    return 0;
}

inline uintptr_t export_by_hash(uintptr_t base, uint32_t want_hash) {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress) return 0;

    auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
    auto* names = reinterpret_cast<DWORD*>(base + exp->AddressOfNames);
    auto* funcs = reinterpret_cast<DWORD*>(base + exp->AddressOfFunctions);
    auto* ords  = reinterpret_cast<WORD*>(base + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(base + names[i]);
        if (fnv1a(name) == want_hash)
            return base + funcs[ords[i]];
    }
    return 0;
}

// A clean ntdll stub on x64 begins: 4C 8B D1 B8 <ssn:4> ...
// Anything else means it has been hooked (inline patch / jmp).
inline bool read_ssn(uintptr_t fn, uint32_t& out) {
    auto* p = reinterpret_cast<uint8_t*>(fn);
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        std::memcpy(&out, p + 4, 4);
        return true;
    }
    return false;
}

// Halo's Gate: if the target stub is hooked, walk neighbouring stubs (they are
// 0x20 bytes apart, SSNs are contiguous) and extrapolate the real number.
inline bool read_ssn_halo(uintptr_t fn, uint32_t& out) {
    auto* p = reinterpret_cast<uint8_t*>(fn);
    for (int delta = 1; delta <= 64; ++delta) {
        auto* f = p + (delta * 0x20);
        if (f[0] == 0x4C && f[1] == 0x8B && f[2] == 0xD1 && f[3] == 0xB8) {
            uint32_t s = 0;
            std::memcpy(&s, f + 4, 4);
            out = s - static_cast<uint32_t>(delta);
            return true;
        }
        f = p - (delta * 0x20);
        if (f[0] == 0x4C && f[1] == 0x8B && f[2] == 0xD1 && f[3] == 0xB8) {
            uint32_t s = 0;
            std::memcpy(&s, f + 4, 4);
            out = s + static_cast<uint32_t>(delta);
            return true;
        }
    }
    return false;
}

} // namespace detail

// Build one trampoline. Called once per imported function, never per read.
//
// Takes the *hash* of the export name, never the name itself: a constexpr
// fnv1a over a literal is folded at compile time, so the string never reaches
// .rdata at all. Passing a name would leave it there (and the previous version
// crashed trying to zero a read-only literal).
inline Stub make_stub(const char* name) = delete; // forbid the leaking form

inline Stub make_stub_hashed(uint32_t name_hash) {
    Stub s{};
    uintptr_t base = detail::ntdll_base();
    if (!base) return s;

    uintptr_t fn = detail::export_by_hash(base, name_hash);
    if (!fn) return s;

    if (!detail::read_ssn(fn, s.ssn) && !detail::read_ssn_halo(fn, s.ssn))
        return s;

    // mov r10, rcx ; mov eax, ssn ; syscall ; ret
    uint8_t code[12] = { 0x4C, 0x8B, 0xD1, 0xB8,
                         0, 0, 0, 0,
                         0x0F, 0x05, 0xC3, 0x00 };
    std::memcpy(code + 4, &s.ssn, 4);

    // Allocate as RW, write, then flip to RX. Never RWX — a PAGE_EXECUTE_READWRITE
    // private page is one of the cheapest things a scanner can flag.
    void* mem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return s;
    std::memcpy(mem, code, sizeof(code));

    DWORD old = 0;
    if (!VirtualProtect(mem, sizeof(code), PAGE_EXECUTE_READ, &old)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return s;
    }

    s.code = mem;
    s.ok = true;
    return s;
}

// ---- typed wrappers, resolved lazily and cached exactly once --------------

using NtReadVirtualMemory_t       = LONG(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using NtWriteVirtualMemory_t      = LONG(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using NtClose_t                   = LONG(NTAPI*)(HANDLE);
using NtQuerySystemInformation_t  = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationProcess_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtDuplicateObject_t         = LONG(NTAPI*)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);

template <typename Fn>
struct Api {
    Fn   fn = nullptr;
    bool ok = false;
};

// The export name never reaches .rdata: fnv1a is constexpr and the result is
// folded into the SSN lookup, so only a 32-bit hash is emitted.
//
// IMPORTANT: pass the hash, never the string, into make_stub_hashed. An earlier
// revision computed `constexpr uint32_t kHash = fnv1a("...")` but then still
// called make_stub_hashed(fnv1a("...")) inside the lambda, so MSVC kept the
// literal alive in .rdata. A constexpr integral used by value needs no capture.

inline Api<NtReadVirtualMemory_t>& nt_read() {
    constexpr uint32_t kHash = fnv1a("NtReadVirtualMemory");
    static Api<NtReadVirtualMemory_t> a = [] {
        Api<NtReadVirtualMemory_t> r{};
        auto s = make_stub_hashed(kHash);
        if (s.ok) { r.fn = reinterpret_cast<NtReadVirtualMemory_t>(s.code); r.ok = true; }
        return r;
    }();
    return a;
}

inline Api<NtWriteVirtualMemory_t>& nt_write() {
    constexpr uint32_t kHash = fnv1a("NtWriteVirtualMemory");
    static Api<NtWriteVirtualMemory_t> a = [] {
        Api<NtWriteVirtualMemory_t> r{};
        auto s = make_stub_hashed(kHash);
        if (s.ok) { r.fn = reinterpret_cast<NtWriteVirtualMemory_t>(s.code); r.ok = true; }
        return r;
    }();
    return a;
}

inline Api<NtClose_t>& nt_close() {
    constexpr uint32_t kHash = fnv1a("NtClose");
    static Api<NtClose_t> a = [] {
        Api<NtClose_t> r{};
        auto s = make_stub_hashed(kHash);
        if (s.ok) { r.fn = reinterpret_cast<NtClose_t>(s.code); r.ok = true; }
        return r;
    }();
    return a;
}

// A hard failure here means the loader is unusable; the caller must fall back
// to the Win32 path rather than guess a syscall number.
inline bool available() {
    return nt_read().ok && nt_close().ok;
}

} // namespace sc
