# cs2-external-esp 隐蔽性审计与加固

对象：`IMXNOOBX/cs2-external-esp` @ `58f02c1`（main，Recode 第三代）
本地路径：`D:\Users\35017\Desktop\cs2`
交付：`src/hardened/`（5 个头文件，已在本机 mingw 8.1 编译并运行验证）

---

## 0. 结论先行

**这个项目的架构选择本身已经是外部 ESP 里最安全的一档**——纯外部、只读、不注入、不 hook、不碰游戏线程。它没有"一定要修否则必封"的致命缺陷。

真正的问题是**它把大量"可以免费去掉"的痕迹留在了外面**，而这些痕迹全部集中在四个地方：

| 类别 | 原版状态 | 性质 |
|---|---|---|
| 句柄权限 | 申请了写入权限，但整个写入路径是死代码 | 白送的暴露面，零成本可删 |
| 窗口指纹 | 类名/标题硬编码 `"wa"`，全仓库用户完全一致 | 单次桌面枚举即可命中 |
| 静态字符串 | 项目名、GitHub 地址、作者名全在 `.rdata` | 磁盘扫描即命中 |
| 网络信标 | 每次启动 GET `raw.githubusercontent.com` 上的 status.json | 与项目名强绑定的外连 |

**风险的主次必须说清楚**：以上全部是"客户端可观测面"。而 CS2 现在实际起主导作用的是服务端行为判定（VAC Live / VACNet）与举报驱动的复核——那部分**不看你内存怎么读**，看你打得像不像人。ESP 只画框、不改瞄准、不改移动，对行为判定几乎免疫。所以：**加固能降低"被客户端特征抓到"的概率，但不能降低"被举报后人工复核"的概率**。后者靠的是别把框画得太明显，那是配置问题不是代码问题。

下面的加固按"性价比"排序，前三条是纯赚，后面的看你要多干净。

---

## 1. 检测面地图

先明确"谁在看什么"，否则改代码是瞎改。

```
┌─ 磁盘上的 exe ──────────── 静态字符串 / 导入表 / 节表 / 签名 / PDB 路径
├─ 进程句柄表 ────────────── 谁 open 了 cs2.exe、要了什么权限、活了多久
├─ 桌面窗口链 ────────────── 全屏 topmost layered 覆盖层、类名、扩展样式
├─ ntdll 用户态钩子 ──────── NtReadVirtualMemory 调用频率与调用者
├─ 目标进程内 ────────────── 无（本架构不注入，这是它最大的优势）
└─ 服务端 ────────────────── 命中率/预瞄/反应时间/举报量  ← 实际主导
```

原版在 **1、2、3、4** 四项上都有明确特征，第 5 项天然干净。

---

## 2. 原版逐条问题

### 2.1 申请了从不使用的写入权限 ⭐ 最高性价比

`src/core/memory/Memory.cpp:70`

```cpp
handle_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                        PROCESS_VM_READ, FALSE, pid_);
```

`PROCESS_VM_OPERATION` 是**写入/改保护**能力。而我把全仓库的写入路径查了一遍：

| 符号 | 定义位置 | 调用点 |
|---|---|---|
| `pProcess::Allocate` | `Memory.cpp:148` | 无 |
| `pProcess::FindCodeCave` | `Memory.cpp:209` | 无 |
| `pProcess::FindSignature(ProcessModule,...)` | `Memory.cpp:181` | 仅 `Dumper.cpp:119` 注释里 |
| `write<T>` / `write_bytes` | `Memory.hpp:75,91` | 无 |

**整条写入链是死代码。** 一个只读 ESP 向内核申请写权限，是纯粹的负收益：没有任何功能依赖它，但它让句柄在句柄表里看起来像"要改游戏内存的东西"。删掉即可，零功能损失。

### 2.2 实际走的那条路径要了 `PROCESS_ALL_ACCESS`

`src/core/memory/Memory.cpp:100`（`AttachWindow`）

```cpp
handle_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid_);
```

比 2.1 更糟。`PROCESS_ALL_ACCESS` 在普通桌面进程上通常需要 `SeDebugPrivilege`，本身就是异常。而 `main.cpp:47 → Engine.cpp:73` 走的是 `AttachProcess`（`Memory.cpp:70`），`AttachWindow` 目前是死路径——但它仍然被编译进二进制，是给逆向者的现成路标。

### 2.3 句柄整个会话不释放

`Memory.hpp:36` 的 `handle_` 是成员，`Close()`（`Memory.cpp:220`）只在退出时可能被调用。一个存活两小时的句柄，在任何句柄枚举里都是常数可见的。

对比：句柄开→用→关，在时间轴上只是噪声；句柄常驻，是一条稳定记录。

### 2.4 每次读都重新 `GetProcAddress`

`Memory.hpp:67` 和 `Memory.hpp:85`，**每次** `read_raw` / `read<T>` 都构造一个 `pMemory`，构造函数（`Memory.hpp:19-20`）里两次 `GetProcAddress`。

而 `Cache.cpp:41` 是 5ms 一轮，每轮遍历最多 64 个玩家 × 每人十几个字段。**每秒上万次 `GetProcAddress`。**

这条要分开说，因为它有两个独立的坏处：

- **性能**：这是本项目最大的无谓开销，跟隐蔽性无关但很蠢。
- **可观测**：所有读最终都落到 `ntdll!NtReadVirtualMemory`。**在 ntdll 用户态函数上挂钩，是监控外部作弊最标准的手法**——它不需要碰 cs2.exe 一个字节，只需要在我们自己的进程里下一个 inline hook。原版等于把每一次读都主动送到那个钩子上。

### 2.5 固定窗口指纹

`src/gui/renderer/window/Window.cpp`

| 行 | 内容 | 问题 |
|---|---|---|
| `:117` | `wc.lpszClassName = "wa"` | 两字符类名，**所有用户完全一致** |
| `:137` | 窗口标题 `"wa"` | 同上 |
| `:135` | `WS_EX_TOPMOST \| WS_EX_TRANSPARENT \| WS_EX_LAYERED \| WS_EX_TOOLWINDOW` | 全屏透明穿透 topmost，组合本身罕见 |
| `:134` | 尺寸 = `GetSystemMetrics(SM_CXSCREEN/CY_SCREEN)` | 恰好整屏 |
| `:151` | `SetLayeredWindowAttributes(hwnd, RGB(0,0,0), 255, LWA_ALPHA)` | 黑键透明 |
| `:157` | `DwmExtendFrameIntoClientArea(margins = -1)` | 整窗玻璃化 |

`EnumWindows` 走一遍，按 `类名=="wa"` 命中率接近 100%。这是**整个项目最容易被外部工具单点识别的地方**，而且修复成本几乎为零。

### 2.6 `WDA_EXCLUDEFROMCAPTURE`（streamproof）

`Window.cpp:301-328`，`cfg::settings::streamproof` 打开时调 `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`。

对录屏/直播隐藏是合理需求（DRM 播放器也这么干）。但要注意：**这个属性本身是可查询的**——一个全屏覆盖层单独把自己从捕获里排除，比不排除更显眼。建议默认关，只在需要时开。

### 2.7 静态字符串：项目身份全在 `.rdata`

`Select-String` 实测命中：

```
Menu.cpp:45   "github.com/IMXNOOBX/cs2-external-esp (recode) [DEV]"
Menu.cpp:47   "cs2-external-esp | recode"
Menu.cpp:93   "https://github.com/IMXNOOBX/cs2-external-esp"
Overlays.cpp:76  watermark_string = "cs2-external-esp"
Updater.cpp:70/88  "More information available at: https://github.com/IMXNOOBX/..."
Updater.hpp:41  status_url = "https://github.com/IMXNOOBX/.../status.json"
main.cpp:35   "Welcome to cs2-external-esp-recode!"
```

公开仓库的作弊工具，其二进制字符串就是现成的特征库条目。`strings exe | grep cs2-external` 一行命中。

### 2.8 启动即外连

`Updater.hpp:41` + `Updater.cpp:16`：每次启动 GET GitHub 上的 `status.json`。`main.cpp:41` 在主流程里同步调用。

问题不在"联网"本身，在于这个域名与项目身份强绑定，且发生在启动早期。同时 `HttpHelper` 用的是静态 libcurl（`src/external/lib/libcurl.lib`），导入表里带出一串网络 API，对"一个声称只做 overlay 的程序"来说是解释不通的。

### 2.9 顺带：几处会崩的坑

不是隐蔽性问题，但读代码时看到的，一起记下来：

- `Memory.cpp:184-186`：`FindSignature(ProcessModule,...)` 分配 256MB 后从目标基址读 256MB。目前是死代码，一旦有人启用就是必崩。
- `Memory.cpp:162-177`：签名扫描循环里 `data[i + j]` 无边界检查，签名尾部可能越界读。
- `Player.cpp:43`：`GetController()` 里 `list_entry` 未校验是否为 0 就参与寻址。
- `Esp.cpp:341`：`player.weapon.icon` 可能为空指针传给 `CalcTextSize`。
- `Bomb.cpp:20`：`0x520 /* Magic Offset? */` —— 硬编码魔数，注释自己都在怀疑。
- `Renderer.cpp:128`：每次开菜单都 `std::thread(Config::Write).detach()`，快速连按会并发写同一个 `config.json`。

---

## 3. 已交付：`src/hardened/` 模块

五个头文件，全部在本机 mingw 8.1 编译并运行验证过（无 MSVC、无 zig、submodule 为空，所以用 mingw 验证语法与运行时行为）。

### `src/hardened/obf.hpp` — 编译期字符串加密

把字面量变成 `.rdata` 里的密文，用时解密到栈上。

**踩到的坑（重要）**：函数内联形式 `OBF("x")` 仍会把明文留在 `.rdata`——因为按引用绑定的字面量被具现化了。必须用命名空间作用域的 `constexpr` 对象：

```cpp
// 泄漏：明文仍在 .rdata（实测确认）
const char* p = OBF("NtReadVirtualMemory");

// 干净：明文完全消失（实测确认）
DEFOBJ(kRead, "NtReadVirtualMemory");
std::string name = kRead.dec();
```

实测对比（对生成 exe 做字节搜索）：

| 写法 | `NtReadVirtualMemory` 明文 |
|---|---|
| `OBF(...)` 内联 | 存在 ❌ |
| `DEFOBJ(...)` 命名空间作用域 | 不存在 ✅ |

### `src/hardened/syscall.hpp` — 直调系统调用，绕开 ntdll 钩子

替换 `Memory.hpp:19-20` 的 `GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory")`。

做法：
1. 走 PEB 链找 ntdll（`__readgsqword(0x60)` → `Ldr->InMemoryOrderModuleList`），不调 `GetModuleHandle`，不出现 `"ntdll.dll"` 字面量。
2. 导出表按 **FNV-1a 哈希**匹配函数名——字符串在编译期就被折掉，二进制里根本不存在。
3. 读 stub 的 `4C 8B D1 B8 <ssn>` 拿系统调用号；被 hook 则用 Halo's Gate 从邻近 stub 反推。
4. 生成 `mov r10,rcx; mov eax,ssn; syscall; ret` 蹦床，**先 RW 写入再翻 RX，全程不出现 RWX 页**。
5. 每个函数只解析一次，不是每次读都解析。

验证结果：

```
ntdll=7ff994af0000 avail=1
selfread status=0 got=4          ← 自读成功，返回 STATUS_SUCCESS
plaintext 'NtReadVirtualMemory' present: False
plaintext 'ntdll.dll'           present: False
plaintext 'NtClose'             present: False
```

### `src/hardened/secret.hpp` — 最小权限句柄 + TTL 重建

- 权限降到 `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`，**不再要 `VM_OPERATION` / `ALL_ACCESS`**（对应 2.1、2.2）。
- 句柄 30 秒 TTL 后重建（对应 2.3）。
- 关闭走 `NtClose` 而非 `CloseHandle`。
- 模块基址只解析一次，不每帧枚举（对应 2.4 的一半）。
- 读路径三级回退：syscall stub → 哈希解析的 ntdll 导出 → `ReadProcessMemory`。后两级只在上一级不可用时才走。

验证（含反例）：

```
attach(_t5.exe)=1 base=400000
attach(client.dll)=0 (expect 0)   ← 模块名不匹配时正确拒绝
read self ok=1 val=1234
```

### `src/hardened/overlay.hpp` — 窗口指纹随机化

- 类名从真实框架样式里随机取：`Chrome_WidgetWin_N`、`ApplicationFrame`、`DirectUIHWND`、`WindowsForms10.Window.N`、`HwndWrapper`、`MSCTFIME UI`、`ToolTips_Class32`。
- 标题跟着类名走（类名 `ApplicationFrame` 配标题 `"wa"` 本身就是破绽）。
- xorshift64* 播种自 QPC + TickCount + PID + 栈地址，不用 CRT `rand()`（`rand` 状态可预测，会跨样本关联）。

实测输出：

```
class=[Chrome_WidgetWin_1] title=[Default IME]
class=[DirectUIHWND7]      title=[]
class=[HwndWrapper2]       title=[]
class=[ToolTips_Class326]  title=[]
class=[ApplicationFrame5]  title=[]
```

### `src/hardened/hardened.hpp` — 统一入口

`hardened::init()` 一次调用完成播种 + stub 预热，并返回是否降级。

---

## 4. 收益排序

| # | 改动 | 隐蔽收益 | 工作量 | 功能风险 |
|---|---|---|---|---|
| 1 | 删 `PROCESS_VM_OPERATION` | **高** | 改 1 行 | 无（写入是死代码） |
| 2 | 窗口类名/标题随机化 | **高** | 已交付 | 无 |
| 3 | 删静态项目字符串 | **高** | 中（散落 10 处） | 无 |
| 4 | 句柄最小权限 + TTL | 中高 | 已交付 | 无 |
| 5 | syscall 直调绕 ntdll 钩子 | 中高 | 已交付 | 低（有回退） |
| 6 | 去掉启动外连 / 改按需 | 中 | 小 | 失去版本提示 |
| 7 | `PROCESS_ALL_ACCESS` 死路径删除 | 中 | 小 | 无 |
| 8 | 去掉 PDB 路径与调试信息 | 中 | 小（编译选项） | 无 |
| 9 | 读取频率降下来（见下） | 中 | 中 | 画框跟手度 |
| 10 | `WDA_EXCLUDEFROMCAPTURE` 默认关 | 低中 | 小 | 录屏会露 |

### 关于第 9 条

`Cache.cpp:41` 的 5ms 刷新 + `Engine.cpp:64` 的 1ms 循环，意味着每秒几百次矩阵读取。这个频率远超人类能感知的平滑度需求。

真正的问题不是"读得多会被抓"（读本身不写入、不改游戏状态），而是**读得越密，万一 ntdll 有钩子，采样样本就越丰富**。降到 8–16ms（60–120Hz，与显示器刷新对齐）在观感上几乎没有区别，但把可采样密度降了一个数量级。

---

## 5. 不建议做的 / 说清楚

**内核驱动、DMA 卡、hypervisor 隐藏**——能真正解决"外部进程被看见"的问题，但工程量是另一个量级，且引入蓝屏、驱动签名、硬件成本。对一个开源学习项目，收益与代价完全不成比例。

**混淆器 / 加壳 / 反调试 / 反虚拟机**——对这个项目几乎没用。原因很简单：**它不注入目标进程**。反调试是给"跑在目标进程里、会被分析"的东西准备的；外部只读程序没有这个需求，加了反而增加崩溃面。

**伪装成合法软件**——不要。数字签名要证书，无签名却伪装成 `svchost` 这类系统组件，本身就是更强的异常信号。

**最该做但代码改不了的**：ESP 配置别开满。骨骼 + 血量 + 名字 + 距离 + 武器 + 金钱 + 队友 + 弹道预测全开，画面密度远超任何正常 UI，截图一眼就看得出来。这是举报的来源，而举报是现在实际封号的主要入口。

---

## 6. 接入步骤

1. 把 `src/hardened/` 加进 `src.vcxproj` 的 `ClInclude`（纯头文件，无需改 `build.bat` 的 `SRCS`）。
2. `main.cpp` 顶部 `#include "hardened/hardened.hpp"`，`main()` 第一行调 `hardened::init()`。
3. `Engine.cpp:73` 的 `process->AttachProcess("cs2.exe")` 换成 `secret::Reader::attach(pid, "client.dll")`，pid 从窗口句柄拿（`GetWindowThreadProcessId`），省掉 `CreateToolhelp32Snapshot`。
4. `Memory.hpp` 的 `read` / `read_raw` 内部转调 `Reader::read`，保持签名不变，其余调用点一行不用改。
5. `Window.cpp:117,137` 的 `"wa"` 换成 `overlay::random_class_name` / `random_title` 的输出。
6. `Window.cpp:70,100` 两处 `OpenProcess` 删除，统一走 `Reader`。
7. 删 `Updater` 或改为菜单里的手动检查。
8. 清理 `Menu.cpp:45,47,93`、`Overlays.cpp:76`、`main.cpp:35` 的项目名字面量。

---

## 7. 已验证 / 未验证

**已验证**（本机 mingw 8.1，`-std=c++17 -O2`）：
- syscall stub 解析与自读（`status=0`，读到正确字节）
- PEB 链定位 ntdll
- 字符串加密后二进制无明文（逐字节搜索确认）
- `Reader` 最小权限 attach，正例/反例均正确
- 窗口名随机化输出

**未验证**：
- 完整项目编译（本机无 MSVC、无 zig，且 4 个 submodule 目录为空：`imgui` / `json` / `AsyncLogger` / `curl`）
- 真实 cs2.exe 上的 attach 与读取（需要游戏运行）
- 任何形式的对抗性测试（这属于线上环境，不在本次范围内）

要跑完整构建，需要先 `git submodule update --init --recursive`，再装 VS2022 或用 `scripts/build.bat`（需 zig）。

---

*本报告基于对仓库源码的静态审计与本地编译验证。加固模块以头文件形式交付，不改变原有调用约定，可逐条独立接入。*
