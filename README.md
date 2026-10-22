# 🕹️ CS2 External ESP — 加固分支

> **上游项目：** [IMXNOOBX/cs2-external-esp](https://github.com/IMXNOOBX/cs2-external-esp) @ `58f02c1`
> **本仓库：** 一次以审计为驱动的隐蔽性加固。没有增加或删减任何游戏功能。
> **协议：** CC BY-NC 4.0（继承上游，未改动 —— 见 [LICENSE](LICENSE)）

Counter-Strike 2 的外部 ESP。纯外部、只读、不注入、不 hook、不碰游戏线程。本分支保留
这一架构，并去掉了原版会暴露给客户端的那些指纹。

完整的推导过程、`file:line` 证据和性价比排序，都在
**[AUDIT-隐蔽性加固.md](AUDIT-隐蔽性加固.md)** 里。

---

## ⚠️ 先读这段

**这是什么：** 对一个开源项目做的代码加固，公开出来是为了让 diff 可被审计。

**这不是什么：** 不是免封承诺。CS2 现在的判定主要来自**服务端行为分析和举报驱动的复核**
—— 那一层不关心你怎么读内存，只关心你打得像不像人。只画框、不改瞄准和移动的 ESP 对行为
判定接近免疫，但同时完全暴露在"被人举报然后人工看"这条路上。加固降低的是**客户端特征**
风险，对**"你这覆盖层一看就不是正常 UI"**这类风险毫无作用 —— 那是配置问题，不是代码问题。

**用途：** 仅限单人 / 离线 / 私服。你自己为自己的行为负责；上游作者和本分支维护者不承担
任何责任。

---

## 相对上游改了什么

### 1. 删掉了从未使用的写入权限

`src/core/memory/Memory.cpp:70` 申请了 `PROCESS_VM_OPERATION`；`:100` 申请了
`PROCESS_ALL_ACCESS`。而项目里每一条写入路径（`Allocate`、`FindCodeCave`、`write<T>`、
`write_bytes`、`FindSignature(ProcessModule,…)`）**调用点数量为零** —— 整条写入链是死代码。

一个只读 ESP 向内核申请写权限，是纯粹的负收益：没有任何功能依赖它，但它让句柄在句柄表里
看起来像"准备修改游戏内存的东西"。

现在只申请：`PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`。

### 2. 句柄生命周期有了上限

原版整个会话只持有一个句柄（`Memory.hpp:36`）。现在句柄带 30 秒 TTL 会重建，没有单个
句柄能覆盖整个会话。

### 3. 读取不再集中打到 `ntdll!NtReadVirtualMemory` 的导出 stub

`Memory.hpp:67,85` **每次读**都构造一个 `pMemory`，每次做两次 `GetProcAddress` —— 在 5ms
缓存刷新、64 名玩家的规模下，每秒上万次解析。比开销更糟的是：它把每一次读都送到了用户态
钩子最可能被安装的那个函数上。

现在改成一次性构建的系统调用蹦床（`hardened/syscall.hpp`）：通过哈希导出名解析 SSN（镜像
里不存在 `"ntdll.dll"`、`"NtReadVirtualMemory"` 字符串），stub 被 hook 时用 Halo's Gate
反推。页属性 RW → RX，全程不出现 RWX。

### 4. 窗口指纹不再每个用户都一样

`src/gui/renderer/window/Window.cpp:117,137` 把类名和标题硬编码成 `"wa"`，配上固定的
`WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_TOOLWINDOW` 全屏 popup。
一遍 `EnumWindows`，在每一台编译过这个仓库的机器上都能命中。

现在类名/标题从真实的框架窗口名里随机取（`hardened/overlay.hpp`）。

### 5. 编译期字符串加密

项目名、GitHub 地址、作者名原本以明文躺在 `.rdata` 里（`Menu.cpp:45,47,93`、
`Overlays.cpp:76`、`Updater.cpp:70,88`、`Updater.hpp:41`、`main.cpp:35`）。
`hardened/obf.hpp` 在编译期把字面量加密。

**这里有个坑要注意：** 内联的 `OBF("x")` 写法仍然会把明文留在 `.rdata` —— 按引用绑定的
字面量被具现化了。只有命名空间作用域的 `DEFOBJ(name, "x")` 写法才是干净的。两种写法都
用字节搜索验证过。

### 6. 删掉了上游镜像

`.github/workflows/mirror_gitlab.yml` 和 `mirror_codeberg.yml` 会把本仓库推送到
`gitlab.com/IMXNOOBX/...` 和 `codeberg.org/IMXNOOBX/...`，用的是本账号没有的 secret。
已删除。

### 7. 删掉了四个空的 submodule 引用

`src/external/{imgui,json,AsyncLogger,curl}` 是指向从未 checkout 过的 commit 的 gitlink ——
clone 下来只会得到四个空目录，构建不可能成功。gitlink 和 `.gitmodules` 已移除，依赖获取
方式见下方。

---

## 依赖

这四个外部库在本分支里**没有内置**（上游是用 submodule 跟踪的，本分支去掉了那些坏掉的
gitlink）。构建前先拉到对应位置：

```sh
git clone --depth 1 https://github.com/ocornut/imgui            src/external/imgui
git clone --depth 1 https://github.com/nlohmann/json            src/external/json
git clone --depth 1 https://github.com/Yimura/AsyncLogger       src/external/AsyncLogger
git clone --depth 1 https://github.com/curl/curl                src/external/curl
```

`src/external/lib/libcurl.lib` 和 `zlib.lib` 由上游提交，仍然保留。

---

## 构建

**Visual Studio 2022**（或更新）：打开 `cs2-external-esp.sln`，构建 **`x64 - Release`**。
产物在 `x64/Release`。

或者用 `scripts/build.bat`，需要 [zig](https://ziglang.org/) 在 `PATH` 上。

如果程序启动即崩溃，装一下最新的
[VC++ 运行库](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)（x64）。

> 游戏必须是**全屏窗口化**，不能是独占全屏。

---

## 加固模块

`src/hardened/` 是纯头文件，不改变现有调用约定 —— 每一部分都可以单独接入。

| 文件 | 作用 |
|---|---|
| `src/hardened/obf.hpp` | 编译期字符串加密（用 `DEFOBJ`，不要用内联 `OBF`） |
| `src/hardened/syscall.hpp` | PEB→ntdll 定位、哈希解析导出、系统调用蹦床 |
| `src/hardened/secret.hpp` | 最小权限句柄、TTL 重建、三级读取回退 |
| `src/hardened/overlay.hpp` | 随机化窗口类名/标题 |
| `src/hardened/hardened.hpp` | 单一入口 `hardened::init()` |

本机用 mingw-w64 g++ 8.1 验证通过（`-std=c++17 -O2 -Wall -Wextra`，零警告）：syscall
蹦床能解析并成功自读（`STATUS_SUCCESS`），PEB 链能找到 ntdll，字符串加密后二进制里没有
明文，`Reader` 能以最小权限 attach 并正确拒绝不匹配的模块名。

**未验证：** 完整项目构建（审计机器上没有 MSVC 也没有 zig，且 submodule 是空的），以及
任何针对真实 `cs2.exe` 的行为。

---

## 署名与协议

原项目由 [**IMXNOOBX**](https://github.com/IMXNOOBX) 及贡献者开发，协议
**CC BY-NC 4.0**。偏移签名来自 [**a2x** 的 cs2-dumper](https://github.com/a2x/cs2-dumper)。

本分支是基于同一协议的衍生作品：保留署名，改动记录在审计报告里。**禁止商用** ——
本协议不允许销售或再授权本材料。

---

<details>
<summary><b>English summary</b></summary>

Audit-driven hardening fork of [IMXNOOBX/cs2-external-esp](https://github.com/IMXNOOBX/cs2-external-esp)
@ `58f02c1`. Architecture unchanged: external, read-only, no injection, no hooking.

Changes: dropped unused `PROCESS_VM_OPERATION` / `PROCESS_ALL_ACCESS` access rights
(every write path in the project has zero call sites); bounded handle lifetime (30 s TTL);
replaced the per-read `GetProcAddress(GetModuleHandleA("ntdll.dll"), ...)` pattern with a
syscall trampoline resolved once by export hash (no plaintext API names, RW→RX, never RWX);
per-process window class/title instead of the hardcoded `"wa"`; compile-time string
encryption; removed upstream mirror workflows and four empty submodule gitlinks.

Note: the inline `OBF("x")` form still leaves plaintext in `.rdata` — only the
namespace-scope `DEFOBJ(name, "x")` form is clean. Verified by byte-searching the binary.

Full reasoning with `file:line` evidence: [AUDIT-隐蔽性加固.md](AUDIT-隐蔽性加固.md).

Verified with mingw-w64 g++ 8.1 `-Wall -Wextra` (clean); full project build not verified
(no MSVC or zig on the audit machine, submodules were empty).

Licensed CC BY-NC 4.0, inherited. Non-commercial.

</details>
