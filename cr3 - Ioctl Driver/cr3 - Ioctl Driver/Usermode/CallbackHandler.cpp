#include "stdafx.h"

NTSTATUS CallbackWRITE(PREQUEST_WRITE args)
{
	if (((PBYTE)args->Src + args->Size < (PBYTE)args->Src) ||
		((PBYTE)args->Dest + args->Size < (PBYTE)args->Dest) ||
		((PVOID)((PBYTE)args->Src + args->Size) > MM_HIGHEST_USER_ADDRESS) ||
		((PVOID)((PBYTE)args->Dest + args->Size) > MM_HIGHEST_USER_ADDRESS)) {
		return STATUS_ACCESS_VIOLATION;
	}

	if (args->bPhysicalMem) {
		PEPROCESS pProcess = NULL;
		if (args->ProcessId == 0) 
			return STATUS_UNSUCCESSFUL;

		NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)args->ProcessId, &pProcess);
		if (NtRet != STATUS_SUCCESS) return NtRet;

		ULONG_PTR process_dirbase = Utils::PhysicalMemory::GetProcessCr3(pProcess);
		ObDereferenceObject(pProcess);

		SIZE_T CurOffset = 0;
		SIZE_T TotalSize = args->Size;
		while (TotalSize)
		{
			INT64 CurPhysAddr = Utils::PhysicalMemory::TranslateLinearAddress(process_dirbase, (ULONG64)args->Src + CurOffset);
			if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

			ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
			SIZE_T BytesWritten = 0;
			NtRet = Utils::PhysicalMemory::WritePhysicalAddress(PVOID(CurPhysAddr), (PVOID)((ULONG64)args->Dest+ CurOffset), WriteSize, &BytesWritten);
			TotalSize -= BytesWritten;
			CurOffset += BytesWritten;
			if (NtRet != STATUS_SUCCESS) break;
			if (BytesWritten == 0) break;
		}

		return NtRet;
	}
	else {
		PEPROCESS process = NULL;
		NTSTATUS status = (PsLookupProcessByProcessId)((HANDLE)args->ProcessId, &process);
		if (NT_SUCCESS(status)) {
			SIZE_T outSize = 0;
			status = (MmCopyVirtualMemory)((PsGetCurrentProcess)(), args->Src, process, args->Dest, (SIZE_T)args->Size, KernelMode, &outSize);
			(ObfDereferenceObject)(process);
		}
		return status;
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS CallbackREAD(PREQUEST_READ args)
{
	if (((PBYTE)args->Src + args->Size < (PBYTE)args->Src) ||
		((PBYTE)args->Dest + args->Size < (PBYTE)args->Dest) ||
		((PVOID)((PBYTE)args->Src + args->Size) > MM_HIGHEST_USER_ADDRESS) ||
		((PVOID)((PBYTE)args->Dest + args->Size) > MM_HIGHEST_USER_ADDRESS)) {

		return STATUS_ACCESS_VIOLATION;
	}

	if (args->bPhysicalMem) {
		PEPROCESS pProcess = NULL;
		if (args->ProcessId == 0) return STATUS_UNSUCCESSFUL;

		NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)args->ProcessId, &pProcess);
		if (NtRet != STATUS_SUCCESS) return NtRet;

		ULONG_PTR process_dirbase = Utils::PhysicalMemory::GetProcessCr3(pProcess);
		ObDereferenceObject(pProcess);

		SIZE_T CurOffset = 0;
		SIZE_T TotalSize = args->Size;
		while (TotalSize)
		{

			INT64 CurPhysAddr = Utils::PhysicalMemory::TranslateLinearAddress(process_dirbase, (ULONG64)args->Src + CurOffset);
			if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

			ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
			SIZE_T BytesRead = 0;
			NtRet = Utils::PhysicalMemory::ReadPhysicalAddress(PVOID(CurPhysAddr), (PVOID)((ULONG64)args->Dest + CurOffset), ReadSize, &BytesRead);
			TotalSize -= BytesRead;
			CurOffset += BytesRead;
			if (NtRet != STATUS_SUCCESS) break;
			if (BytesRead == 0) break;
		}

		return NtRet;
	}
	else {
		PEPROCESS process = NULL;
		NTSTATUS status = (PsLookupProcessByProcessId)((HANDLE)args->ProcessId, &process);
		if (NT_SUCCESS(status)) {
			SIZE_T outSize = 0;
			status = (MmCopyVirtualMemory)(process, args->Src, (PsGetCurrentProcess)(), args->Dest, (SIZE_T)args->Size, KernelMode, &outSize);
			(ObfDereferenceObject)(process);
		}
		return status;
	}

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS CallbackPROTECT(PREQUEST_PROTECT args)
{
	if (!args->ProcessId || !args->Address || !args->Size || !args->InOutProtect)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS target_process = NULL;

	if (!NT_SUCCESS((PsLookupProcessByProcessId)((HANDLE)args->ProcessId, &target_process)))
	{
		return STATUS_NOT_FOUND;
	}
	SIZE_T size = args->Size;
	DWORD protect = 0;
	RtlCopyMemory(&protect, args->InOutProtect, sizeof(protect));

	(KeAttachProcess)((PKPROCESS)target_process);
	status = (ZwProtectVirtualMemory)(NtCurrentProcess(), &args->Address, &size, protect, &protect);
	(KeDetachProcess)();
	if (NT_SUCCESS(status))
		RtlCopyMemory(args->InOutProtect, &protect, sizeof(protect));

	(ObfDereferenceObject)(target_process);
	return status;
}

NTSTATUS CallbackALLOC(PREQUEST_ALLOC args)
{
	PEPROCESS process = NULL;
	NTSTATUS status = (PsLookupProcessByProcessId)((HANDLE)args->ProcessId, &process);
	if (NT_SUCCESS(status)) {
		PVOID address = NULL;
		SIZE_T size = args->Size;

		(KeAttachProcess)(process);
		(ZwAllocateVirtualMemory)(NtCurrentProcess(), &address, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		(KeDetachProcess)();

		RtlCopyMemory(args->OutAddress, &address, sizeof(address));

		(ObfDereferenceObject)(process);
	}
	return status;
}

NTSTATUS CallbackFREE(PREQUEST_FREE args)
{
	PEPROCESS process = NULL;
	NTSTATUS status = (PsLookupProcessByProcessId)((HANDLE)args->ProcessId, &process);
	if (NT_SUCCESS(status)) {
		SIZE_T size = 0;

		(KeAttachProcess)(process);
		(ZwFreeVirtualMemory)(NtCurrentProcess(), &args->Address, &size, MEM_RELEASE);
		(KeDetachProcess)();

		(ObfDereferenceObject)(process);
	}
	return status;
}

NTSTATUS CallbackMODULE(PREQUEST_MODULE args)
{
	PEPROCESS process = NULL;
	NTSTATUS status = (PsLookupProcessByProcessId)((HANDLE)args->ProcessId, &process);
	if (NT_SUCCESS(status)) {
		PVOID base = NULL;
		DWORD size = 0;
		(KeAttachProcess)(process);
		PLDR_DATA_TABLE_ENTRY module = Utils::GetModuleByName(process, args->Module);
		if (module) {
			base = module->DllBase;
			size = module->SizeOfImage;
		}
		else {
			status = STATUS_NOT_FOUND;
		}
		(KeDetachProcess)();
		if (NT_SUCCESS(status)) {
			RtlCopyMemory(args->OutAddress, &base, sizeof(base));
			RtlCopyMemory(args->OutSize, &size, sizeof(size));
		}
		(ObfDereferenceObject)(process);
	}
	return status;
}

NTSTATUS CallbackMAINBASE(PREQUEST_MAINBASE args)
{
	PEPROCESS pProcess = NULL;
	if (args->ProcessId == 0)
		return STATUS_UNSUCCESSFUL;

	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)args->ProcessId, &pProcess);
	if (NtRet != STATUS_SUCCESS)
		return STATUS_UNSUCCESSFUL;

	auto base = PsGetProcessSectionBaseAddress(pProcess);
	RtlCopyMemory(args->OutAddress, &base, sizeof(base));
	ObDereferenceObject(pProcess);
	return STATUS_SUCCESS;
}
