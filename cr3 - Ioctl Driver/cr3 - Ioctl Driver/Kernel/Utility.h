#pragma once
#define RVA(addr, size) (uint64_t)((PBYTE)((UINT_PTR)(addr) + *(PINT)((UINT_PTR)(addr) + ((size) - sizeof(INT))) + (size)))
#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

extern "C" POBJECT_TYPE * IoDriverObjectType;
extern "C" {
	NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
	NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(PUNICODE_STRING ObjectPath, ULONG Attributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext, PVOID* ObjectPtr);
	NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
	NTKERNELAPI PPEB  NTAPI PsGetProcessPeb(IN PEPROCESS Process);
	NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
}

namespace Utils {
	namespace Registry
	{
		ULONG GetKeyInfoSize(HANDLE hKey, PUNICODE_STRING Key);
		template <typename type>
		type ReadRegistry(UNICODE_STRING RegPath, UNICODE_STRING Key);
		bool WriteRegistry(UNICODE_STRING RegPath, UNICODE_STRING Key, PVOID Address, ULONG Type, ULONG Size);
		template<typename type>
		static type ReadRegistry(UNICODE_STRING RegPath, UNICODE_STRING Key)
		{
			HANDLE hKey;
			OBJECT_ATTRIBUTES ObjAttr;
			NTSTATUS Status = STATUS_UNSUCCESSFUL;

			InitializeObjectAttributes(&ObjAttr, &RegPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

			Status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &ObjAttr);

			if (NT_SUCCESS(Status))
			{
				ULONG KeyInfoSize = GetKeyInfoSize(hKey, &Key);
				ULONG KeyInfoSizeNeeded;

				if (KeyInfoSize == NULL)
				{
					ZwClose(hKey);
					return 0;
				}

				PKEY_VALUE_FULL_INFORMATION pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePool(NonPagedPool, KeyInfoSize);
				RtlZeroMemory(pKeyInfo, KeyInfoSize);

				Status = ZwQueryValueKey(hKey, &Key, KeyValueFullInformation, pKeyInfo, KeyInfoSize, &KeyInfoSizeNeeded);

				if (!NT_SUCCESS(Status) || (KeyInfoSize != KeyInfoSizeNeeded))
				{
					ZwClose(hKey);
					ExFreePoolWithTag(pKeyInfo, 0);
					return 0;
				}

				ZwClose(hKey);
				ExFreePoolWithTag(pKeyInfo, 0);

				return *(type*)((LONG64)pKeyInfo + pKeyInfo->DataOffset);
			}

			return 0;
		}
	}

	PLDR_DATA_TABLE_ENTRY GetModuleByName(PEPROCESS process, PWCHAR moduleName);

	namespace PhysicalMemory {
		const DWORD GetUserDirectoryTableBaseOffset();
		const UINT64 GetProcessCr3(const PEPROCESS pProcess);
		const UINT64 GetKernelDirBase();
		const UINT64 TranslateLinearAddress(UINT64 directoryTableBase, UINT64 virtualAddress);
		NTSTATUS ReadVirtual(UINT64 dirbase, UINT64 address, UINT8* buffer, SIZE_T size, SIZE_T* read);
		NTSTATUS WriteVirtual(UINT64 dirbase, UINT64 address, UINT8* buffer, SIZE_T size, SIZE_T* written);
		NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead);
		NTSTATUS WritePhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten);
	}
}
