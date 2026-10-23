#include "Memory.hpp"
#include <tlhelp32.h>

uint32_t pProcess::FindProcessIdByProcessName(const char* ProcessName)
{
	std::wstring wideProcessName;
	int wideCharLength = MultiByteToWideChar(CP_UTF8, 0, ProcessName, -1, nullptr, 0);
	if (wideCharLength > 0)
	{
		wideProcessName.resize(wideCharLength);
		MultiByteToWideChar(CP_UTF8, 0, ProcessName, -1, &wideProcessName[0], wideCharLength);
	}

	HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32W process_entry_{ };
	process_entry_.dwSize = sizeof(PROCESSENTRY32W);

	DWORD pid = 0;
	if (Process32FirstW(hPID, &process_entry_))
	{
		do
		{
			if (!wcscmp(process_entry_.szExeFile, wideProcessName.c_str()))
			{
				pid = process_entry_.th32ProcessID;
				break;
			}
		} while (Process32NextW(hPID, &process_entry_));
	}
	CloseHandle(hPID);
	return pid;
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
	std::wstring wideModule;
	int wideCharLength = MultiByteToWideChar(CP_UTF8, 0, lModule, -1, nullptr, 0);
	if (wideCharLength > 0)
	{
		wideModule.resize(wideCharLength);
		MultiByteToWideChar(CP_UTF8, 0, lModule, -1, &wideModule[0], wideCharLength);
	}

	HANDLE handle_module = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid_);
	MODULEENTRY32W module_entry_{};
	module_entry_.dwSize = sizeof(MODULEENTRY32W);

	do
	{
		if (!wcscmp(module_entry_.szModule, wideModule.c_str()))
		{
			CloseHandle(handle_module);
			return { (DWORD_PTR)module_entry_.modBaseAddr, module_entry_.dwSize };
		}
	} while (Module32NextW(handle_module, &module_entry_));

	CloseHandle(handle_module);
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
	CloseHandle(handle_);
}
