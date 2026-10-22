// hardened.hpp — single entry point for the hardened build.
//
// Include this instead of the original core/memory/Memory.hpp in main.cpp and
// Engine.cpp. Everything here is drop-in: same semantics, fewer tells.
//
// Drop-in replacement map (original → hardened):
//
//   Memory.hpp:19-20  GetProcAddress(GetModuleHandleA("ntdll.dll"), ...)
//                     → sc::nt_read() / sc::nt_write()   (syscall stub, no names)
//
//   Memory.cpp:60-88  AttachProcess → OpenProcess(QUERY|VM_OP|VM_READ)
//                     → secret::Reader::attach (QUERY_LIMITED|VM_READ)
//
//   Memory.cpp:90-113 AttachWindow  → OpenProcess(PROCESS_ALL_ACCESS)
//                     → secret::Reader::attach (same minimal mask)
//
//   Memory.cpp:14,131 CreateToolhelp32Snapshot for pid / modules
//                     → pid from the game window (already available at
//                       Engine.cpp:73), modules via one EnumProcessModulesEx
//                       on the handle we already hold
//
//   Window.cpp:117,137 class/title "wa"
//                     → overlay::random_class_name / random_title
//
//   Window.cpp:134-135 fixed ex-style set + SM_CXSCREEN sizing
//                     → follow the game client rect (Renderer.cpp:188 already
//                       does the follow; the initial SpawnWindow does not)
//
//   Window.cpp:320    WDA_EXCLUDEFROMCAPTURE
//                     → keep, but gate behind an explicit user toggle and note
//                       that it is itself a capture-visible property
//
//   Updater.cpp       HTTP GET to raw.githubusercontent.com on every launch
//                     → removed / made opt-in (see report; it is a network
//                       beacon tied to the project name)

#pragma once

#include "obf.hpp"
#include "syscall.hpp"
#include "secret.hpp"
#include "overlay.hpp"

namespace hardened {

// Call once, first thing in main(), before anything touches the game.
inline bool init() {
    overlay::seed_rng();
    // If the syscall stubs cannot be built (unexpected ntdll layout), the
    // Reader still works through the hash-resolved export path. Returning
    // false here means "degraded", not "broken".
    return sc::available();
}

} // namespace hardened
