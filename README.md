# 🕹️ CS2 External ESP — Hardened Fork

> **Upstream:** [IMXNOOBX/cs2-external-esp](https://github.com/IMXNOOBX/cs2-external-esp) @ `58f02c1`
> **This fork:** an audit-driven hardening pass. No gameplay features added or removed.
> **License:** CC BY-NC 4.0 (inherited, unchanged — see [LICENSE](LICENSE))

External ESP for Counter-Strike 2. Pure external, read-only, no injection, no hooking,
no touching the game thread. This fork keeps that architecture and removes the
client-observable fingerprints the original shipped with.

---

## ⚠️ Read this before anything else

**What this is:** a code-hardening exercise on an open-source project, published so the
diff is auditable.

**What this is not:** a ban guarantee. CS2's enforcement is dominated by **server-side
behavioural analysis and report-driven review** — that layer does not care how you read
memory, it cares whether you play like a human. An ESP that only draws boxes is close to
immune to behavioural detection, and equally exposed to being reported and reviewed by a
person. Hardening reduces *client-side fingerprint* risk. It does nothing for *"your
overlay is obviously not a normal UI"* risk. That is a settings problem, not a code problem.

**Use:** single-player / offline / private servers only. You are accountable for your own
actions; the upstream authors and this fork's maintainer accept no responsibility.

---

## What changed vs upstream

The full reasoning, with `file:line` evidence and a cost/benefit ranking, is in
**[AUDIT-隐蔽性加固.md](AUDIT-隐蔽性加固.md)**. Summary:

### 1. Removed write capability that was never used

`src/core/memory/Memory.cpp:70` requested `PROCESS_VM_OPERATION`; `:100` requested
`PROCESS_ALL_ACCESS`. Every write path in the project (`Allocate`, `FindCodeCave`,
`write<T>`, `write_bytes`, `FindSignature(ProcessModule,…)`) has **zero call sites** —
the entire write chain is dead code. A read-only ESP asking the kernel for write rights
is pure downside: nothing depends on it, and it makes the handle look like something
that intends to modify the game.

Now: `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ` only.

### 2. Handle lifetime is bounded

The original held one handle for the whole session (`Memory.hpp:36`). Now handles carry a
30 s TTL and are re-created, so no single handle covers an entire session.

### 3. Reads no longer funnel through `ntdll!NtReadVirtualMemory`'s exported stub

`Memory.hpp:67,85` constructed a `pMemory` on **every** read, each doing two
`GetProcAddress` calls — at 5 ms cache refresh across 64 players that is tens of
thousands of resolutions per second. Worse than the cost: it delivers every read to the
exact function a user-mode hook would be planted on.

Now: a syscall trampoline (`hardened/syscall.hpp`) built once, resolving the SSN by
hashing export names (no `"ntdll.dll"`, no `"NtReadVirtualMemory"` string in the image),
with Halo's Gate fallback if the stub is hooked. Page is RW → RX, never RWX.

### 4. Window fingerprint is no longer identical for every user

`src/gui/renderer/window/Window.cpp:117,137` hardcoded class name and title `"wa"`,
combined with a fixed `WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_TOOLWINDOW`
full-screen popup. One `EnumWindows` pass matched it on every machine that built the repo.

Now: class/title drawn from realistic framework names (`hardened/overlay.hpp`).

### 5. Compile-time string encryption

Project name, GitHub URLs and author strings were plaintext in `.rdata`
(`Menu.cpp:45,47,93`, `Overlays.cpp:76`, `Updater.cpp:70,88`, `Updater.hpp:41`,
`main.cpp:35`). `hardened/obf.hpp` encrypts literals at compile time.

**Note the trap:** the inline `OBF("x")` form still leaves plaintext in `.rdata` —
a by-reference-bound literal gets materialised. Only the namespace-scope `DEFOBJ(name, "x")`
form is clean. Verified by byte-searching the produced binary both ways.

### 6. Removed upstream mirroring

`.github/workflows/mirror_gitlab.yml` and `mirror_codeberg.yml` pushed this repository to
`gitlab.com/IMXNOOBX/...` and `codeberg.org/IMXNOOBX/...` using secrets this account does
not have. Removed.

### 7. Removed the four empty submodule references

`src/external/{imgui,json,AsyncLogger,curl}` were gitlinks to commits that were never
checked out — cloning produced empty directories and a build that could not possibly
succeed. The gitlinks and `.gitmodules` are gone; see **Dependencies** below.

---

## Dependencies

The four externals are **not vendored** in this fork (upstream tracked them as submodules;
this fork drops the broken gitlinks). Fetch them into place before building:

```sh
git clone --depth 1 https://github.com/ocornut/imgui            src/external/imgui
git clone --depth 1 https://github.com/nlohmann/json            src/external/json
git clone --depth 1 https://github.com/Yimura/AsyncLogger       src/external/AsyncLogger
git clone --depth 1 https://github.com/curl/curl                src/external/curl
```

`src/external/lib/libcurl.lib` and `zlib.lib` are committed by upstream and still present.

---

## Building

**Visual Studio 2022** (or later): open `cs2-external-esp.sln`, build **`x64 - Release`**.
Output lands in `x64/Release`.

Alternatively `scripts/build.bat` with [zig](https://ziglang.org/) on `PATH`.

If the app fails to start, install the latest
[VC++ redistributables](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)
(x64).

> The game must be in **fullscreen windowed**, not exclusive fullscreen.

---

## Hardened module

`hardened/` is header-only and does not change existing call conventions — each part can
be adopted independently.

| File | Purpose |
|---|---|
| `hardened/obf.hpp` | Compile-time string encryption (`DEFOBJ` — not the inline `OBF` form) |
| `hardened/syscall.hpp` | PEB→ntdll lookup, hash-resolved exports, syscall trampoline |
| `hardened/secret.hpp` | Minimal-rights handle, TTL re-acquire, three-tier read fallback |
| `hardened/overlay.hpp` | Randomised window class/title |
| `hardened/hardened.hpp` | Single `hardened::init()` entry point |

Verified on this machine with mingw-w64 g++ 8.1 (`-std=c++17 -O2 -Wall -Wextra`, no
warnings): syscall stub resolves and self-reads (`STATUS_SUCCESS`), PEB walk finds ntdll,
string encryption leaves no plaintext in the binary, `Reader` attaches with the minimal
mask and correctly rejects a mismatched module name.

**Not verified:** a full project build (no MSVC or zig on the audit machine, and the
submodules were empty), and any behaviour against a live `cs2.exe`.

---

## Credits & license

Original project by [**IMXNOOBX**](https://github.com/IMXNOOBX) and contributors, licensed
**CC BY-NC 4.0**. Offset signatures derive from [**a2x**'s cs2-dumper](https://github.com/a2x/cs2-dumper).

This fork is a derivative work under the same license: attribution retained, changes
documented in the audit report. **Non-commercial** — selling or sublicensing this material
is not permitted by the license.
