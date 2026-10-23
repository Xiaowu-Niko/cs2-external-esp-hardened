#include "Memory.hpp"

// ---------------------------------------------------------------------------
// Process discovery
//
// The original found cs2.exe by walking CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)
// and comparing every entry's szExeFile. Together with the module lookup
// (CreateToolhelp32Snapshot(TH32CS_SNAPMODULE) + Module32NextW) that is *the*
// textbook external-cheat fingerprint: no legitimate overlay enumerates every
// process on the box looking for a game by name.
//
// Both are gone now, and tlhelp32.h is no longer included:
//   pid     — EnumWindows + QueryFullProcessImageNameW on visible top-level
//             windows only, which is ordinary desktop-app behaviour
//   modules — EnumProcessModulesEx on the handle already held
// ---------------------------------------------------------------------------

namespace {

// Compare a wide basename against a narrow ASCII name, case-insensitively.
bool basename_equals(const wchar_t* wide_path, const char* narrow_name) {
    if (!wide_path || !narrow_name) return false;

    const wchar_t* base = wcsrchr(wide_path, L'\\');
    base = base ? base + 1 : wide_path;

    size_t i = 0;
    for (; narrow_name[i]; ++i) {
        wchar_t w = base[i];
        if (!w) return false;
        if (w >= L'A' && w <= L'Z') w = static_cast<wchar_t>(w + 32);
        char n = narrow_name[i];
        if (n >= 'A' && n <= 'Z') n = static_cast<char>(n + 32);
        if (w != static_cast<wchar_t>(n)) return false;
    }
    return base[i] == L'\0';
}

struct FindCtx {
    const char* exe_name;
    DWORD pid;
};

// Enumerate top-level windows and resolve each to its process image name.
//
// This replaces CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) + Process32First/
// Next, which is the canonical "external cheat looking for the game" pattern:
// it snapshots every process on the box and compares szExeFile. Here we only
// touch processes that own a visible top-level window, which is what a normal
// desktop application does anyway.
BOOL CALLBACK find_by_exe_cb(HWND hwnd, LPARAM lparam) {
    auto* ctx = reinterpret_cast<FindCtx*>(lparam);

    if (!IsWindowVisible(hwnd))
        return TRUE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (!pid || pid == GetCurrentProcessId())
        return TRUE;

    // QUERY_LIMITED is enough to read the image path; no SeDebugPrivilege.
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return TRUE;

    wchar_t path[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    bool match = false;

    if (QueryFullProcessImageNameW(h, 0, path, &size))
        match = basename_equals(path, ctx->exe_name);

    CloseHandle(h);

    if (match) {
        ctx->pid = pid;
        return FALSE; // stop enumerating
    }
    return TRUE;
}

} // namespace

uint32_t pProcess::FindProcessIdByProcessName(const char* ProcessName)
{
    FindCtx ctx{ ProcessName, 0 };
    EnumWindows(find_by_exe_cb, reinterpret_cast<LPARAM>(&ctx));
    return ctx.pid;
}

uint32_t pProcess::FindProcessIdByWindowName(const char* WindowName)
{
	DWORD process_id = 0;
	HWND windowHandle = FindWindowA(nullptr, WindowName);
	if (windowHandle)
		GetWindowThreadProcessId(windowHandle, &process_id);
	return process_id;
}

HWND pProcess::GetWindowHandleFromProcessId(DWORD ProcessId) {
	HWND hwnd = NULL;
	do {
		hwnd = FindWindowEx(NULL, hwnd, NULL, NULL);
		DWORD pid = 0;
		GetWindowThreadProcessId(hwnd, &pid);
		if (pid == ProcessId) {
			TCHAR windowTitle[MAX_PATH];
			GetWindowText(hwnd, windowTitle, MAX_PATH);
			if (IsWindowVisible(hwnd) && windowTitle[0] != '\0') {
				return hwnd;
			}
		}
	} while (hwnd != NULL);
	return NULL; // No main window found for the given process ID
}

bool pProcess::refresh_handle()
{
    if (!this->pid_)
        return false;

    // Fast path: still inside the TTL.
    if (this->handle_ && (GetTickCount() - this->handle_opened_at_) < kHandleTtlMs)
        return true;

    // Expired: drop it and open a fresh one. Closing through NtClose rather
    // than CloseHandle keeps the call off the kernel32 export that hooking
    // frameworks like to intercept.
    if (this->handle_)
    {
        if (sc::nt_close().ok) sc::nt_close().fn(this->handle_);
        else                   CloseHandle(this->handle_);
        this->handle_ = nullptr;
    }

    this->handle_ = OpenProcess(secret::kReadRights, FALSE, this->pid_);
    if (!this->handle_)
    {
        // The game may have restarted under a new pid; try to re-resolve once.
        this->pid_ = this->FindProcessIdByProcessName("cs2.exe");
        if (!this->pid_)
            return false;
        this->handle_ = OpenProcess(secret::kReadRights, FALSE, this->pid_);
        if (!this->handle_)
            return false;
    }

    this->handle_opened_at_ = GetTickCount();
    return true;
}

bool pProcess::AttachProcess(const char* ProcessName)
{
	this->pid_ = this->FindProcessIdByProcessName(ProcessName);

	if (pid_)
	{
		HMODULE modules[0xFF];
		MODULEINFO module_info;
		DWORD _;

		// Was: PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ
		// PROCESS_VM_OPERATION is write/change-protection capability, and every
		// write path in this project (Allocate, FindCodeCave, write<T>,
		// write_bytes) has zero call sites. This is a read-only ESP; asking for
		// write rights buys nothing and is the loudest thing in the handle table.
		//
		// PROCESS_QUERY_LIMITED_INFORMATION also avoids requiring
		// SeDebugPrivilege on protected targets.
		handle_ = OpenProcess(secret::kReadRights, FALSE, pid_);

		if (!handle_)
			return false;

		handle_opened_at_ = GetTickCount();

		EnumProcessModulesEx(this->handle_, modules, sizeof(modules), &_, LIST_MODULES_64BIT);
		base_client_.base = (uintptr_t)modules[0];

		GetModuleInformation(this->handle_, modules[0], &module_info, sizeof(module_info));
		base_client_.size = module_info.SizeOfImage;

		hwnd_ = this->GetWindowHandleFromProcessId(pid_);

		return true;
	}

	return false;
}

bool pProcess::AttachWindow(const char* WindowName)
{
	this->pid_ = this->FindProcessIdByWindowName(WindowName);

	if (pid_)
	{
		HMODULE modules[0xFF];
		MODULEINFO module_info;
		DWORD _;

		// Was: PROCESS_ALL_ACCESS — needs SeDebugPrivilege and is strictly worse
		// than the path above. This function is not on the live path
		// (Engine.cpp uses AttachProcess), but it still compiled in, so it is a
		// free signpost for anyone reading the binary.
		handle_ = OpenProcess(secret::kReadRights, FALSE, pid_);
		handle_opened_at_ = GetTickCount();

		EnumProcessModulesEx(this->handle_, modules, sizeof(modules), &_, LIST_MODULES_64BIT);
		base_client_.base = (uintptr_t)modules[0];

		GetModuleInformation(this->handle_, modules[0], &module_info, sizeof(module_info));
		base_client_.size = module_info.SizeOfImage;

		hwnd_ = this->GetWindowHandleFromProcessId(pid_);

		return true;
	}
	return false;
}

bool pProcess::UpdateHWND()
{
	hwnd_ = this->GetWindowHandleFromProcessId(pid_);
	return hwnd_ != nullptr;
}

ProcessModule pProcess::GetModule(const char* lModule)
{
	// Was: CreateToolhelp32Snapshot(TH32CS_SNAPMODULE) + Module32NextW, i.e. a
	// module snapshot of the target taken purely to look up a base address.
	// EnumProcessModulesEx on the handle we already hold gives the same answer
	// without a second snapshot handle, and it is the same call the module
	// resolver in hardened/secret.hpp uses.
	if (!this->handle_)
		return { 0, 0 };

	HMODULE mods[0x200] = {};
	DWORD needed = 0;

	if (!EnumProcessModulesEx(this->handle_, mods, sizeof(mods), &needed, LIST_MODULES_64BIT))
		return { 0, 0 };

	const DWORD count = needed / sizeof(HMODULE);
	for (DWORD i = 0; i < count; ++i)
	{
		wchar_t name[MAX_PATH] = {};
		if (!GetModuleBaseNameW(this->handle_, mods[i], name, MAX_PATH))
			continue;

		if (!basename_equals(name, lModule))
			continue;

		MODULEINFO info{};
		if (!GetModuleInformation(this->handle_, mods[i], &info, sizeof(info)))
			continue;

		return { (DWORD_PTR)info.lpBaseOfDll, info.SizeOfImage };
	}

	return { 0, 0 };
}

LPVOID pProcess::Allocate(size_t size_in_bytes)
{
	return VirtualAllocEx(this->handle_, NULL, size_in_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

uintptr_t pProcess::FindSignature(std::vector<uint8_t> signature)
{
	if (signature.empty() || !this->base_client_.size)
		return 0x0;

	const size_t module_size = this->base_client_.size;
	std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(module_size);

	if (!ReadProcessMemory(this->handle_, (void*)(this->base_client_.base), data.get(), module_size, NULL)) {
		return 0x0;
	}

	// Bound the start index so that i + j always stays inside the buffer.
	// The original looped i < size and indexed data[i + j] unguarded, so a
	// signature that partially matched at the end read past the allocation.
	for (size_t i = 0; i + signature.size() <= module_size; i++)
	{
		for (size_t j = 0; j < signature.size(); j++)
		{
			if (signature.at(j) == 0x00)
				continue;

			if (data[i + j] == signature.at(j))
			{
				if (j == signature.size() - 1)
					return this->base_client_.base + i;
				continue;
			}
			break;
		}
	}
	return 0x0;
}

uintptr_t pProcess::FindSignature(ProcessModule target_module, std::vector<uint8_t> signature)
{
	if (signature.empty() || !target_module.size)
		return 0x0;

	// Was: a fixed 0xFFFFFFF (256 MB) allocation, unconditionally read from the
	// module base. Modules are far smaller, so that read almost always failed
	// and the 256 MB was wasted; when it did succeed the scan indexed past the
	// buffer. Read exactly the module, and bound the scan.
	const size_t scan_size = target_module.size;
	std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(scan_size);

	if (!ReadProcessMemory(this->handle_, (void*)(target_module.base), data.get(), scan_size, NULL)) {
		return 0x0;
	}

	for (size_t i = 0; i + signature.size() <= scan_size; i++)
	{
		for (size_t j = 0; j < signature.size(); j++)
		{
			if (signature.at(j) == 0x00)
				continue;

			if (data[i + j] == signature.at(j))
			{
				if (j == signature.size() - 1)
					return target_module.base + i; // was base_client_.base — wrong module
				continue;
			}
			break;
		}
	}
	return 0x0;
}

uintptr_t pProcess::FindCodeCave(uint32_t length_in_bytes)
{
	std::vector<uint8_t> cave_pattern = {};

	for (uint32_t i = 0; i < length_in_bytes; i++) {
		cave_pattern.push_back(0x00);
	}

	return FindSignature(cave_pattern);
}

void pProcess::Close()
{
	// Same reasoning as refresh_handle(): NtClose keeps the call off the
	// kernel32 export that user-mode hooks tend to intercept.
	if (!handle_)
		return;
	if (sc::nt_close().ok) sc::nt_close().fn(handle_);
	else                   CloseHandle(handle_);
	handle_ = nullptr;
	handle_opened_at_ = 0;
}
