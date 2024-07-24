#pragma once
#include <TlHelp32.h>

class _dexzsdriver
{
private:
	typedef __int64(*NtUserFunction)(uintptr_t);
	NtUserFunction nt_user_function = 0;
	enum REQUEST_TYPE : int
	{
		NONE,
		BASE,
		WRITE,
		READ
	};
	typedef struct _dexzsdriver_REQUEST
	{
		REQUEST_TYPE type;
		HANDLE pid;
		PVOID address;
		PVOID buffer;
		SIZE_T size;
		PVOID base;
	} DRIVER_REQUEST, *PDRIVER_REQUEST;
	void send_request(PDRIVER_REQUEST out)
	{
		RtlSecureZeroMemory(out, 0);
		nt_user_function(reinterpret_cast<uintptr_t>(out));
	}
public:
	int process_id;
	uintptr_t base_address;
	DWORD get_process_id(LPCTSTR process_name)
	{
		PROCESSENTRY32 pt{};
		HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pt.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hsnap, &pt))
		{
			do {
				if (!lstrcmpi(pt.szExeFile, process_name))
				{
					CloseHandle(hsnap);
					return pt.th32ProcessID;
				}
			} while (Process32Next(hsnap, &pt));
		}
		CloseHandle(hsnap);
		return 0;
	}
	bool setup()
	{
		nt_user_function = reinterpret_cast<NtUserFunction>(GetProcAddress(librarys::user32, "NtUserRegisterErrorReportingDialog"));
		if (!nt_user_function)
		{
			nt_user_function = reinterpret_cast<NtUserFunction>(GetProcAddress(librarys::win32u, "NtUserRegisterErrorReportingDialog"));
			if (!nt_user_function) return false;
		}
		return true;
	}
	uintptr_t get_base_address()
	{
		DRIVER_REQUEST out{};
		out.type = BASE;
		out.pid = (HANDLE)process_id;
		send_request(&out);
		return (uintptr_t)out.base;
	}
	void writem(PVOID address, PVOID buffer, DWORD size)
	{
		DRIVER_REQUEST out{};
		out.type = WRITE;
		out.pid = (HANDLE)process_id;
		out.address = address;
		out.buffer = buffer;
		out.size = size;
		send_request(&out);
	}
	void readm(PVOID address, PVOID buffer, DWORD size)
	{
		DRIVER_REQUEST out{};
		out.type = READ;
		out.pid = (HANDLE)process_id;
		out.address = address;
		out.buffer = buffer;
		out.size = size;
		send_request(&out);
	}
	template<typename T> void write(uintptr_t address, T value)
	{
		writem((PVOID)address, &value, sizeof(T));
	}
	template<typename T> T read(uintptr_t address)
	{
		T buffer{};
		readm((PVOID)address, &buffer, sizeof(T));
		return buffer;
	}
};
_dexzsdriver driver;