#ifndef _PPROCESS_HPP_
#define _PPROCESS_HPP_

#include <vector>
#include <math.h>
#include <Windows.h>
#include <string>
#include <iostream>
#include <Psapi.h>

// TlHelp32.h intentionally not included: process and module discovery no longer
// go through CreateToolhelp32Snapshot / Process32Next / Module32Next, so the
// import table no longer carries those exports. See Memory.cpp.

// EnumProcessModulesEx / GetModuleInformation / GetModuleBaseNameW live in
// psapi.lib. MSVC's default library set does not include it, so link it here
// rather than relying on the project's AdditionalDependencies being edited.
#pragma comment(lib, "psapi.lib")

#include "hardened/syscall.hpp"
#include "hardened/secret.hpp"

// The original kept a hand-rolled ntdll resolver here:
//     pMemory() {
//         GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
//         GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
//     }
// constructed fresh on every single read (see read_raw/read below). That put the
// string "ntdll.dll"/"NtReadVirtualMemory" in .rdata AND delivered every read to
// the exact ntdll export a usermode hook would be planted on.
//
// Both functions are still exposed for ABI compatibility, but they now come from
// the syscall trampoline in hardened/syscall.hpp: resolved once, by export hash,
// executed from our own RX page rather than from ntdll.
typedef NTSTATUS(WINAPI* pNtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead);
typedef NTSTATUS(WINAPI* pNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

class pMemory {
public:
	pMemory() {
		auto& r = sc::nt_read();
		auto& w = sc::nt_write();
		pfnNtReadVirtualMemory  = reinterpret_cast<pNtReadVirtualMemory>(r.ok ? r.fn : nullptr);
		pfnNtWriteVirtualMemory = reinterpret_cast<pNtWriteVirtualMemory>(w.ok ? w.fn : nullptr);
	}

	pNtReadVirtualMemory pfnNtReadVirtualMemory;
	pNtWriteVirtualMemory pfnNtWriteVirtualMemory;
};

struct ProcessModule
{
	uintptr_t base, size;
};

class pProcess
{
public:
	DWORD		  pid_; // process id
	HANDLE		  handle_; // handle to process
	HWND		  hwnd_; // window handle
	ProcessModule base_client_;

	// Handle lifetime.
	//
	// The original opened one handle at attach and held it until the process
	// exited, so a handle to cs2.exe with PROCESS_VM_READ was permanently
	// visible in every handle enumeration for the whole session. A handle that
	// appears, is used, and closes again is far less interesting than one that
	// is always there.
	//
	// handle_ is kept as the member name so existing call sites compile, but it
	// is now re-created on a coarse TTL. refresh_handle() is called from the
	// read path; if the handle has expired it is closed and reopened.
	DWORD         handle_opened_at_ = 0;
	static constexpr DWORD kHandleTtlMs = 30000;

public:
	bool AttachProcess(const char* process_name);
	bool AttachWindow(const char* window_name);
	bool UpdateHWND();
	void Close();

	bool refresh_handle();

public:
	ProcessModule GetModule(const char* module_name);
	LPVOID		  Allocate(size_t size_in_bytes);
	uintptr_t	  FindCodeCave(uint32_t length_in_bytes);
	uintptr_t     FindSignature(std::vector<uint8_t> signature);
	uintptr_t     FindSignature(ProcessModule target_module, std::vector<uint8_t> signature);

	template<class T>
	uintptr_t ReadOffsetFromSignature(std::vector<uint8_t> signature, uint8_t offset) // offset example: "FF 05 ->22628B01<-" offset is 2
	{
		uintptr_t pattern_address = this->FindSignature(signature);
		if (!pattern_address)
			return 0x0;

		T offset_value = this->read<T>(pattern_address + offset);
		return pattern_address + offset_value + offset + sizeof(T);
	}

	// Reads go through the trampoline first; the ntdll export is only a
	// fallback when the trampoline could not be built. The old code called the
	// ntdll export unconditionally.
	bool read_raw(uintptr_t address, void* buffer, size_t size)
	{
		if (!this->refresh_handle())
			return false;

		SIZE_T bytesRead = 0;

		if (auto& r = sc::nt_read(); r.ok)
		{
			LONG status = r.fn(this->handle_, (PVOID)(address), buffer, static_cast<SIZE_T>(size), &bytesRead);
			return status == 0 && bytesRead == size;
		}

		pMemory cMemory;
		if (!cMemory.pfnNtReadVirtualMemory)
			return false;

		NTSTATUS status = cMemory.pfnNtReadVirtualMemory(this->handle_, (PVOID)(address), buffer, static_cast<ULONG>(size), (PULONG)&bytesRead);

		return status == 0x00000000/*STATUS_SUCCESS*/ || bytesRead == size;
	}

	template<class T>
	void write(uintptr_t address, T value)
	{
		// NOTE: no call sites in this project — the ESP never writes to the game.
		// Kept for API compatibility; requires a handle opened with VM_OPERATION,
		// which AttachProcess no longer requests.
		if (auto& w = sc::nt_write(); w.ok)
		{
			w.fn(handle_, (PVOID)address, &value, sizeof(T), nullptr);
			return;
		}
		pMemory cMemory;
		if (cMemory.pfnNtWriteVirtualMemory)
			cMemory.pfnNtWriteVirtualMemory(handle_, (void*)address, &value, sizeof(T), 0);
	}

	template<class T>
	T read(uintptr_t address)
	{
		T buffer{};

		if (!this->refresh_handle())
			return buffer;

		if (auto& r = sc::nt_read(); r.ok)
		{
			SIZE_T got = 0;
			r.fn(handle_, (PVOID)address, &buffer, sizeof(T), &got);
			return buffer;
		}

		pMemory cMemory;
		if (cMemory.pfnNtReadVirtualMemory)
			cMemory.pfnNtReadVirtualMemory(handle_, (void*)address, &buffer, sizeof(T), 0);

		return buffer;
	}

	void write_bytes(uintptr_t addr, std::vector<uint8_t> patch)
	{
		if (auto& w = sc::nt_write(); w.ok)
		{
			w.fn(handle_, (PVOID)addr, &patch[0], patch.size(), nullptr);
			return;
		}
		pMemory cMemory;
		if (cMemory.pfnNtWriteVirtualMemory)
			cMemory.pfnNtWriteVirtualMemory(handle_, (void*)addr, &patch[0], patch.size(), 0);
	}

	uintptr_t read_multi_address(uintptr_t ptr, std::vector<uintptr_t> offsets)
	{
		uintptr_t buffer = ptr;
		for (int i = 0; i < offsets.size(); i++)
			buffer = this->read<uintptr_t>(buffer + offsets[i]);

		return buffer;
	}

	template <typename T>
	T read_multi(uintptr_t base, std::vector<uintptr_t> offsets) {
		uintptr_t buffer = base;
		for (int i = 0; i < offsets.size() - 1; i++)
		{
			buffer = this->read<uintptr_t>(buffer + offsets[i]);
		}
		return this->read<T>(buffer + offsets.back());
	}

private:
	uint32_t FindProcessIdByProcessName(const char* process_name);
	uint32_t FindProcessIdByWindowName(const char* window_name);
	HWND GetWindowHandleFromProcessId(DWORD ProcessId);
};
#endif
