// overlay.hpp — remove the fixed window fingerprint.
//
// The original overlay (gui/renderer/window/Window.cpp:110-166) is a textbook
// signature, and it is identical on every machine that builds this repo:
//
//   :117  wc.lpszClassName = "wa"        ← 2-char class name, same for everyone
//   :137  title            = "wa"        ← same
//   :135  WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_TOOLWINDOW
//   :134  full-screen popup, size = GetSystemMetrics(SM_CXSCREEN/CY_SCREEN)
//   :151  SetLayeredWindowAttributes(hwnd, RGB(0,0,0), 255, LWA_ALPHA)
//   :157  DwmExtendFrameIntoClientArea(margins = -1)
//   :320  SetWindowDisplayAffinity(..., WDA_EXCLUDEFROMCAPTURE)   ← streamproof
//
// A single pass over the desktop's top-level windows finds class "wa" with a
// black-keyed layered popup covering exactly the screen. Nothing about that
// requires reading cs2.exe, which is why this is the highest-value fix that
// costs nothing in behaviour.
//
// WDA_EXCLUDEFROMCAPTURE deserves its own note: excluding a window from capture
// is legitimate for DRM players, but a lone unsigned process excluding a
// full-screen overlay is a pattern that capture-aware tooling reports.

#pragma once
#include <windows.h>
#include <cstdint>
#include <cstdio>

namespace overlay {

// xorshift64* — enough for naming, no CRT rand() (which is itself a shared
// state a scanner can predict and therefore correlate across samples).
inline uint64_t& rng_state() {
    static uint64_t s = 0;
    return s;
}

inline void seed_rng() {
    LARGE_INTEGER qpc{}, freq{};
    QueryPerformanceCounter(&qpc);
    QueryPerformanceFrequency(&freq);
    uint64_t s = static_cast<uint64_t>(qpc.QuadPart) ^
                 (static_cast<uint64_t>(GetTickCount64()) << 17) ^
                 (static_cast<uint64_t>(GetCurrentProcessId()) << 33) ^
                 (reinterpret_cast<uintptr_t>(&qpc) >> 4);
    if (!s) s = 0x9E3779B97F4A7C15ull;
    rng_state() = s;
}

inline uint64_t next_u64() {
    uint64_t& s = rng_state();
    s ^= s >> 12;
    s ^= s << 25;
    s ^= s >> 27;
    return s * 0x2545F4914F6CDD1Dull;
}

inline uint32_t next_u32() { return static_cast<uint32_t>(next_u64() >> 32); }

inline size_t wlen(const wchar_t* s) { size_t n = 0; while (s && s[n]) ++n; return n; }

inline void wcopy(wchar_t* dst, size_t cap, const wchar_t* src) {
    if (!cap) return;
    size_t i = 0;
    for (; src && src[i] && i + 1 < cap; ++i) dst[i] = src[i];
    dst[i] = 0;
}

inline void wappend_u32(wchar_t* dst, size_t cap, uint32_t v) {
    wchar_t tmp[12];
    int n = 0;
    if (!v) { tmp[n++] = L'0'; }
    while (v) { tmp[n++] = static_cast<wchar_t>(L'0' + (v % 10)); v /= 10; }
    size_t at = wlen(dst);
    for (int i = n - 1; i >= 0 && at + 1 < cap; --i) dst[at++] = tmp[i];
    dst[at] = 0;
}

// Random class name that still looks like a real framework window, rather than
// 8 random bytes that stand out as "generated". Real Windows UI classes look
// like "Chrome_WidgetWin_1", "ApplicationFrameWindow", "WindowsForms10.Window".
inline void random_class_name(wchar_t* out, size_t cap) {
    static const wchar_t* prefixes[] = {
        L"Chrome_WidgetWin_", L"ApplicationFrame", L"DirectUIHWND",
        L"WindowsForms10.Window.", L"Chrome_RenderWidgetHostHWND",
        L"HwndWrapper", L"MSCTFIME UI", L"ToolTips_Class32",
    };
    const size_t n = sizeof(prefixes) / sizeof(prefixes[0]);
    const wchar_t* p = prefixes[next_u32() % n];
    wcopy(out, cap, p);
    wappend_u32(out, cap, 1 + (next_u32() % 8));
}

inline void random_title(wchar_t* out, size_t cap) {
    // Match the class rather than inventing a title; a mismatched title is its
    // own tell (e.g. class "ApplicationFrame" + title "wa").
    static const wchar_t* titles[] = {
        L"", L"Default IME", L"", L"MSCTFIME UI",
    };
    const size_t n = sizeof(titles) / sizeof(titles[0]);
    wcopy(out, cap, titles[next_u32() % n]);
}

// Recommendation surface — these are the choices that actually change how the
// window reads to an external observer, ordered by value.
struct WindowProfile {
    bool   use_toolwindow   = true;   // no taskbar entry, no Alt-Tab entry
    bool   use_layered      = true;   // needed for per-pixel alpha
    bool   use_transparent  = true;   // click-through
    bool   exclude_capture  = false;  // WDA_EXCLUDEFROMCAPTURE — see note above
    bool   match_game_size  = true;   // follow the game's client rect, not SM_CXSCREEN
    DWORD  class_atom       = 0;
};

} // namespace overlay
