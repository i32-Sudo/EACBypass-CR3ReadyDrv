#pragma once
#define DEFAULT_MAGGICCODE 0x59002360218c1e2dul //length 16 max

#define CallbackHandler(name)												\
 case REQUEST_TYPE::name: {													\
		REQUEST_##name args;												\
        RtlCopyMemory(&args, data.Arguments, sizeof(args));					\
        *data.Status = Callback##name(&args);								\
        break;																\
    }

typedef enum _REQUEST_TYPE : UINT{
	WRITE,
	READ,
	PROTECT,
	ALLOC,
	FREE,
	MODULE,
	MAINBASE,
	THREADCALL,
} REQUEST_TYPE;

typedef struct _REQUEST_DATA {
	ULONG64* MaggicCode;
	UINT Type;
	PVOID Arguments;
	NTSTATUS* Status;
} REQUEST_DATA, * PREQUEST_DATA;

typedef struct _REQUEST_WRITE {
	DWORD ProcessId;
	PVOID Dest;
	PVOID Src;
	DWORD Size;
	BOOL bPhysicalMem;
} REQUEST_WRITE, * PREQUEST_WRITE;

typedef struct _REQUEST_READ {
	DWORD ProcessId;
	PVOID Dest;
	PVOID Src;
	DWORD Size;
	BOOL bPhysicalMem;
} REQUEST_READ, * PREQUEST_READ;

typedef struct _REQUEST_PROTECT {
	DWORD ProcessId;
	PVOID Address;
	DWORD Size;
	PDWORD InOutProtect;
} REQUEST_PROTECT, * PREQUEST_PROTECT;

typedef struct _REQUEST_ALLOC {
	DWORD ProcessId;
	PVOID OutAddress;
	DWORD Size;
	DWORD Protect;
} REQUEST_ALLOC, * PREQUEST_ALLOC;

typedef struct _REQUEST_FREE {
	DWORD ProcessId;
	PVOID Address;
} REQUEST_FREE, * PREQUEST_FREE;

typedef struct _REQUEST_MODULE {
	DWORD ProcessId;
	WCHAR Module[0xFF];
	PBYTE* OutAddress;
	DWORD* OutSize;
} REQUEST_MODULE, * PREQUEST_MODULE;

typedef struct _REQUEST_MAINBASE {
	DWORD ProcessId;
	PBYTE* OutAddress;
} REQUEST_MAINBASE, * PREQUEST_MAINBASE;

NTSTATUS CallbackWRITE(PREQUEST_WRITE args);
NTSTATUS CallbackREAD(PREQUEST_READ args);
NTSTATUS CallbackPROTECT(PREQUEST_PROTECT args);
NTSTATUS CallbackALLOC(PREQUEST_ALLOC args);
NTSTATUS CallbackFREE(PREQUEST_FREE args);
NTSTATUS CallbackMODULE(PREQUEST_MODULE args);
NTSTATUS CallbackMAINBASE(PREQUEST_MAINBASE args);