// secret.hpp — handle acquisition and memory access, rebuilt to minimise the
// observable footprint inside cs2.exe.
//
// What the original does (core/memory/Memory.cpp) and why each part matters:
//
//   :70  OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
//                    PROCESS_VM_READ, ...)
//        PROCESS_VM_OPERATION is write-capable intent. This build never writes
//        to the target. Asking for capability you do not use is the loudest
//        single signal here, and it is free to remove.
//
//   :100 OpenProcess(PROCESS_ALL_ACCESS, ...)   ← the path main.cpp:47 takes
//        Strictly worse than the above. Needs SeDebugPrivilege, which on a
//        normal desktop is an immediate outlier.
//
//   :76  EnumProcessModulesEx / :102  + :131 CreateToolhelp32Snapshot
//        The classic "find the game, enumerate its modules" pair.
//
//   handle_ is a member and never closed → one handle lives for the whole
//        session, permanently visible in every handle enumeration.
//
// Rewrite: minimal rights (QUERY_LIMITED_INFORMATION | VM_READ), one handle
// reused for the session but re-created on a coarse TTL so a single
// long-lived entry does not stand out, module base resolved once, and reads
// routed through the syscall stub from syscall.hpp.

#pragma once
#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <cstring>
#include <vector>

#include "syscall.hpp"
#include "obf.hpp"

namespace secret {

// Absolute minimum for a read-only external:
//   PROCESS_QUERY_LIMITED_INFORMATION — module list, basic info, no SeDebug
//   PROCESS_VM_READ                   — the reads themselves
// Deliberately absent: PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD.
constexpr ACCESS_MASK kReadRights =
    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;

// Handle lifetime. Long enough that we are not opening/closing in a hot loop
// (each open is itself an event), short enough that no single handle covers a
// whole session.
constexpr DWORD kHandleTtlMs = 30000;

class Reader {
public:
    // Called once at attach: resolves pid + module base with a short-lived handle.
    bool attach(DWORD pid, const char* module_name);

    // Read that transparently re-acquires the handle when the TTL expires.
    bool read(uintptr_t addr, void* buf, size_t size);

    template <class T>
    T read(uintptr_t addr) {
        T v{};
        read(addr, &v, sizeof(T));
        return v;
    }

    void detach();

    bool     ok()   const { return pid_ != 0; }
    DWORD    pid()  const { return pid_; }
    uintptr_t base() const { return base_; }
    size_t    size() const { return size_; }

private:
    bool acquire();
    bool ensure_handle();

    DWORD     pid_   = 0;
    HANDLE    h_     = nullptr;
    DWORD     opened_ = 0;
    uintptr_t base_  = 0;
    size_t    size_  = 0;
};

// ---- implementation -------------------------------------------------------

inline void Reader::detach() {
    if (h_) {
        if (sc::nt_close().ok) sc::nt_close().fn(h_);
        else                   CloseHandle(h_);
        h_ = nullptr;
    }
    pid_ = 0; base_ = 0; size_ = 0;
}

inline bool Reader::acquire() {
    HANDLE h = OpenProcess(kReadRights, FALSE, pid_);
    if (!h) {
        // Narrow retry: some protected processes reject the minimal mask but
        // accept the classic query rights. Only reached on failure.
        h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid_);
        if (!h) return false;
    }
    h_ = h;
    opened_ = GetTickCount();
    return true;
}

inline bool Reader::ensure_handle() {
    if (h_ && (GetTickCount() - opened_) < kHandleTtlMs) return true;
    if (h_) {
        if (sc::nt_close().ok) sc::nt_close().fn(h_);
        else                   CloseHandle(h_);
        h_ = nullptr;
    }
    return acquire();
}

inline bool Reader::attach(DWORD pid, const char* module_name) {
    detach();
    if (!pid) return false;
    pid_ = pid;
    if (!acquire()) { pid_ = 0; return false; }

    // Resolve the game module by walking the target's export/module list is not
    // possible without more rights; EnumProcessModulesEx is the minimal path and
    // it is called exactly once, not per read.
    HMODULE mods[0x200] = {};
    DWORD needed = 0;
    bool resolved = false;

    if (EnumProcessModulesEx(h_, mods, sizeof(mods), &needed, LIST_MODULES_64BIT)) {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count; ++i) {
            MODULEINFO mi{};
            if (!GetModuleInformation(h_, mods[i], &mi, sizeof(mi))) continue;

            wchar_t name[MAX_PATH] = {};
            if (!GetModuleBaseNameW(h_, mods[i], name, MAX_PATH)) continue;

            // compare without a plaintext literal
            if (module_name) {
                bool match = true;
                for (size_t k = 0; module_name[k]; ++k) {
                    wchar_t c = name[k];
                    if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c + 32);
                    char want = module_name[k];
                    if (want >= 'A' && want <= 'Z') want = static_cast<char>(want + 32);
                    if (c != static_cast<wchar_t>(want) || c == 0) { match = false; break; }
                }
                if (!match) continue;
            }

            base_ = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
            size_ = mi.SizeOfImage;
            resolved = base_ != 0;
            if (resolved) break;
        }
    }

    if (!resolved) { detach(); return false; }
    return true;
}

inline bool Reader::read(uintptr_t addr, void* buf, size_t size) {
    if (!buf || !size) return false;
    if (!ensure_handle()) return false;

    if (sc::nt_read().ok) {
        SIZE_T got = 0;
        LONG st = sc::nt_read().fn(h_, reinterpret_cast<PVOID>(addr), buf,
                                   static_cast<SIZE_T>(size), &got);
        if (st == 0 && got == size) return true;
    }

    // Fallbacks, in increasing observability. Resolved by hash, never by name.
    // The hash is a constexpr local so MSVC folds it even without /O2 constant
    // propagation across the lambda boundary — passing fnv1a("...") directly
    // left the literal in .rdata in the first CI build.
    static sc::NtReadVirtualMemory_t nt_fallback = []() -> sc::NtReadVirtualMemory_t {
        constexpr uint32_t kHash = sc::fnv1a("NtReadVirtualMemory");
        uintptr_t base = sc::detail::ntdll_base();
        if (!base) return nullptr;
        uintptr_t p = sc::detail::export_by_hash(base, kHash);
        return reinterpret_cast<sc::NtReadVirtualMemory_t>(p);
    }();

    if (nt_fallback) {
        SIZE_T got = 0;
        LONG st = nt_fallback(h_, reinterpret_cast<PVOID>(addr), buf,
                              static_cast<SIZE_T>(size), &got);
        if (st == 0 && got == size) return true;
    }

    SIZE_T got = 0;
    return ReadProcessMemory(h_, reinterpret_cast<LPCVOID>(addr), buf, size, &got)
        && got == size;
}

} // namespace secret
