/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		core.h
 *
 * Abstract:
 *
 *		This module is the main header .
 *
 * Author:
 *
 *		GamingMasteR
 *
 */

#pragma once

//#define _REPORT_
#include "ntifs.h"
#include <ntddk.h>
#include <WinDef.h>
#include <ntimage.h>
#include <stdio.h>
#include <stdlib.h>
#include "dasm.h"
#include "memory.h"
#include "help.h"
#include "VM.h"
#include "dbg.h"
#include "DispatchLock.h"
#include "wdbgexts.h"

#ifdef __cplusplus
	extern "C" {
#endif

#pragma warning(disable : 4995)
#pragma warning(disable : 4090)
#pragma warning(disable : 4996)
		


#define FILE_DEVICE_CORE  0x00008300
#define CORE_IOCTL_INDEX  0x830
#define CODE(CTL)						CTL_CODE(FILE_DEVICE_CORE,CTL,METHOD_NEITHER,FILE_ANY_ACCESS)
typedef enum {
	IOCTL_INITIALIZE = 1,
	IOCTL_ENUM_PROCESS,
	IOCTL_VM_READ,
	IOCTL_VM_WRITE,
	IOCTL_ENUM_DLL,
	IOCTL_DBG_MSG,
	IOCTL_ENUM_SSDT,
	IOCTL_SET_SSDT,
	IOCTL_ENUM_IDT,
	IOCTL_GET_MODULE,
	IOCTL_IDT_OFFSET,
	IOCTL_IDT_SELECTOR,
	IOCTL_ENUM_SHADOW_SSDT,
	IOCTL_SET_SHADOW_SSDT,
	IOCTL_ENUM_HOOKS,
	IOCTL_UNHOOK_KERNEL,
	IOCTL_ENUM_HANDLES,
	IOCTL_PROCESS_KILL,
	IOCTL_ENUM_DRIVER,
	IOCTL_RESTORE_SSDT,
	IOCTL_RESTORE_SHADOW_SSDT,
	IOCTL_HOOK_KIDEBUGSERVICE,
	IOCTL_UNHOOK_KIDEBUGSERVICE	,
	IOCTL_ALLOCATE_PROCESS_VM,
	IOCTL_DEALLOCATE_PROCESS_VM,
	IOCTL_PROCESS_OPEN,
	IOCTL_CLOSE_HANDLE,
	IOCTL_UPDATE_MODULE_LIST,
	IOCTL_THREAD_TO_PROCESS,
	IOCTL_GET_OBJECT_TYPE,
	IOCTL_ENUM_THREADS,
    IOCTL_THREAD_KILL,
	IOCTL_THREAD_SET_SSDT,
	IOCTL_THREAD_RESTORE_SSDT,
	IOCTL_THREAD_SUSPEND,
	IOCTL_PROCESS_SUSPEND,
	IOCTL_THREAD_RESUME,
	IOCTL_PROCESS_RESUME,
	IOCTL_ENUM_UNLOADED_DRIVERS,
	IOCTL_ENUM_TIMERS,
	IOCTL_ENUM_OBJECT_TYPES	,
	IOCTL_CANCEL_TIMER,
	IOCTL_CHANGE_OBJECT_PROC,
	IOCTL_ENUM_IMAGE_NOTIFY	,
	IOCTL_ENUM_PROCESS_NOTIFY,
	IOCTL_ENUM_THREAD_NOTIFY,
	IOCTL_ENUM_LEGO_NOTIFY,
	IOCTL_ENUM_CM_NOTIFY,
	IOCTL_DELETE_NOTIFY,
	IOCTL_DELETE_FILE,
	IOCTL_COPY_FILE	,
	IOCTL_ENUM_BUGCHECK,
	IOCTL_ENUM_BUGCHECK_REASON,
	IOCTL_ENUM_THREAD_TRACE,
	IOCTL_THREAD_OPEN,
	IOCTL_UNMAP_SECTION	,
	IOCTL_GET_PROCESS_INFO,
	IOCTL_PROCESS_BY_PID,
	IOCTL_PROCESS_BY_HANDLE	,
	IOCTL_THREAD_BY_PID	,
	IOCTL_THREAD_BY_HANDLE,
	IOCTL_THREAD_CONTEXT,
	IOCTL_GET_MEMORY_INFO,
	IOCTL_ALLOC_NONPAGED_POOL,
	IOCTL_FREE_NONPAGED_POOL,
	IOCTL_PROTECT_PROCESS_VM,
	IOCTL_QUERY_PROCESS_VM,
	IOCTL_PHYSICAL_PAGE_READ,
	IOCTL_PHYSICAL_PAGE_WRITE,
	IOCTL_GET_FILENAME_BY_OBJECT,
	IOCTL_GET_FILENAME_BY_HANDLE,
	IOCTL_READ_FILE_BY_HANDLE,
	IOCTL_WRITE_FILE_BY_HANDLE,
	IOCTL_READ_FILE_BY_NAME,
	IOCTL_WRITE_FILE_BY_NAME,
	IOCTL_OPEN_FILE	,
	IOCTL_ENUM_DEVICES,
	IOCTL_GET_DRIVER_INFO,
	IOCTL_GET_OBJECT_NAME,
	IOCTL_GET_CONTROL_REG,
	IOCTL_SET_CONTROL_REG,
	IOCTL_GET_KERNEL_INFO,
    IOCTL_CALL_BIOS,
    IOCTL_DISK_READWRITE,
    IOCTL_PORT_READ,
    IOCTL_PORT_WRITE,
    IOCTL_MSR,
    IOCTL_IO_PACKET,
    IOCTL_GET_OBJECT_BY_HANDLE,
	IOCTL_CREATE_THREAD,
    IOCTL_GET_TYPE_NAME
}IOCTL;
		



#define MAX_PATH 260
#define MAX_FAST_REFS 7
#define PSP_MAX_NOTIFY 8
#define CM_MAX_CALLBACKS 100

#define COF(_array) (sizeof(_array)/sizeof(_array[0]))
#define SYSCALL_INDEX(_address) *(PULONG)((PUCHAR)_address+1)
#define OBJECT_TO_OBJECT_HEADER(o) ((POBJECT_HEADER)CONTAINING_RECORD((o), OBJECT_HEADER, Body))

#define IsXp		((KdBuildNumber == 2600))
#define	IsVista		((KdBuildNumber == 6000) || (KdBuildNumber == 6001) || (KdBuildNumber == 6002))
#define	IsVistaSE	((KdBuildNumber == 6001) || (KdBuildNumber == 6002))
#define	IsWin7		((KdBuildNumber == 7600) || (KdBuildNumber == 7601))

#define	parseobject(_obj, _mem, _type)((_type*)((ULONG)_obj + info.Ps##_mem))

#define UpdateModulesList()\
{\
	if (gDrivers)\
	{\
		delete gDrivers;\
	}\
	gDrivers = new CDriver();\
	gDrivers->Scan();\
	gDrivers->ScanPhysicalMemory();\
}


typedef struct _DEVICE_EXTENSION {
    CSHORT          Type;
    USHORT          Size;
    PDEVICE_OBJECT  DeviceObject;               // owning device object
    ULONG           PowerFlags; 
    PVOID	        Dope;
    ULONG           ExtensionFlags;
    PVOID           DeviceNode;
    PDEVICE_OBJECT  AttachedTo;
    LONG            StartIoCount;       // Used to keep track of number of pending start ios.
    LONG            StartIoKey;         // Next startio key
    ULONG           StartIoFlags;       // Start Io Flags. Need a separate flag so that it can be accessed without locks
    PVPB            Vpb;                // If not NULL contains the VPB of the mounted volume.
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;


typedef struct _PLATFORM_OPTIONS{					/*	 XP   - Vista	*/
	ULONG		Max_ServiceID;						/*	0x11c - 0x11c	*/
	PVOID*		SDT;								/*	----- - -----	*/
	ULONG		Max_ShadowServiceID;				/*	0x29B - 0x29B	*/
	PVOID*		ShadowSDT;							/*	----- - -----	*/
	ULONG		PsSizeofProcess;					/*	0x25c - 0x26c	*/
	ULONG		PsSizeofThread;						/*	0x256 - 0x284	*/
	ULONG		PsServiceTable;						/*	0x0e0 - 0x12c	*/
	ULONG		PsProcessRundown;					/*	0x080 - 0x098	*/
	ULONG		PsThreadRundown;					/*	0x234 - 0x250	*/
	ULONG		PsStartAddress;						/*	0x224 - 0x1f8	*/
	ULONG		PsDeviceMap;						/*	0x15c - 0x134	*/
	ULONG		PsExceptionPort;					/*	0x0c0 - 0x0d8	*/
	ULONG		PsActiveProcessLinks;				/*	0x088 - 0x0a0	*/
	ULONG		PsThreadListHead;					/*	0x190 - 0x168	*/
	ULONG		PsKiThreadListEntry;				/*	0x1b0 - 0x1c4	*/
	ULONG		PsKeThreadListEntry;				/*	0x22c - 0x248	*/
	ULONG		PsVirtualSize;						/*	0x0b0 - 0x0c8	*/
	ULONG		PsSeAuditProcessCreationInfo;		/*	0x1f4 - 0x1cc	*/
	ULONG		PsThreadFlags;						/*	0x248 - 0x260	*/
	ULONG		PsProcessFlags;						/*	0x248 - 0x228	*/
	ULONG		PsPreviousMode;						/*	0x140 - 0x0e7	*/
	ULONG		PsObjectListHead;					/*	0x038 - 0x000	*/ //VSP1
	ULONG		PsObjectTypeName;					/*	0x040 - 0x008	*/ //VSP1
	ULONG		PsFreezeCount;						/*	0x1b8 - 0x16b	*/
	ULONG		PsSuspendSemaphore;					/*	0x19c - 0x1ac	*/
}PLATFORM_OPTIONS, *PPLATFORM_OPTIONS;

#define	MAKE_FLAG(pos)	1<<pos
#define	ProcessExiting		MAKE_FLAG(2)
#define	ProcessDelete		MAKE_FLAG(3)
#define	BreakOnTermination	MAKE_FLAG(13)
#define	DeadThread			MAKE_FLAG(1)
#define	SystemThread		MAKE_FLAG(4)



typedef struct DECLSPEC_ALIGN(1) _KD_IO_PACKET {
    UCHAR MajorFunction;
    union {

        struct {
            PVOID Buffer;
            ULONG Length;
            PLARGE_INTEGER StartingOffset;
        } Read;

        struct {
            PVOID Buffer;
            ULONG Length;
            PLARGE_INTEGER StartingOffset;
        } Write;

        struct {
            ULONG IoControlCode;
            PVOID InputBuffer;
            ULONG InputBufferLength;
            PVOID OutputBuffer;
            ULONG OutputBufferLength;
            BOOL  InternalDeviceIoControl;
        } DeviceIoControl;

    } Parameters;
    DEVICE_OBJECT *DeviceObject;
    FILE_OBJECT *FileObject;
} KD_IO_PACKET, *PKD_IO_PACKET;

typedef	struct DECLSPEC_ALIGN(1) _PROCESS_ENTRY {
	PVOID ProcessObject;
	ULONG ImageBase;
	PVOID Peb;
	ULONG Status;
	ULONG Pid;
	ULONG ParentId;
	ULONG Cb;
	WCHAR Name[MAX_PATH];
} PROCESS_ENTRY, *PPROCESS_ENTRY;

typedef struct DECLSPEC_ALIGN(1) _THREAD_ENTRY {
	PVOID Process;
	ULONG ParentId;
	PVOID Thread;
	ULONG Cid;
	PVOID Teb;
	PVOID ServiceTable;
	PVOID Address;
	ULONG Type;
	ULONG ThreadState;
	ULONG WaitReason;
	ULONG Status;
} THREAD_ENTRY, *PTHREAD_ENTRY;

typedef struct DECLSPEC_ALIGN(1) _DLL_ENTRY {
	PVOID BaseAddress;
	PVOID EntryPoint;
	ULONG SizeOfImage;
    WCHAR FullDllName[MAX_PATH];
} DLL_ENTRY, *PDLL_ENTRY;

typedef struct DECLSPEC_ALIGN(1) _SDT_ENTRY {
	ULONG Index;
	ULONG Current;
	ULONG Original;
	ULONG Status;
	WCHAR Module[MAX_PATH];
} SDT_ENTRY, *PSDT_ENTRY;

typedef struct DECLSPEC_ALIGN(1) _DRIVER_ENTRY {
	PVOID ImageBase;
	PVOID DriverObject;
	PVOID Unload;
	PVOID EntryPoint;
	ULONG ImageSize;
	WCHAR ImagePath[MAX_PATH];
} DRIVER_ENTRY, *PDRIVER_ENTRY;

typedef struct DECLSPEC_ALIGN(1) _HANDLE_ENTRY {
    PVOID QuotaProcess;
	PVOID UniqueProcessId;
    HANDLE Handle;
    PVOID Object;
    PVOID ObjectType;
    ULONG GrantedAccess;
	ULONG HandleCount;
	WCHAR Name[MAX_PATH];
} HANDLE_ENTRY, *PHANDLE_ENTRY;

typedef struct DECLSPEC_ALIGN(1) _OBJECT_TYPE_ENTRY {
	PVOID Address;
	DWORD Count;
	DWORD Index;
	struct {
		PVOID DumpProcedure;
		PVOID OpenProcedure;
		PVOID CloseProcedure;
		PVOID DeleteProcedure;
		PVOID ParseProcedure;
		PVOID SecurityProcedure;
		PVOID QueryNameProcedure;
		PVOID OkayToCloseProcedure;
	} ProcedureTable;
	WCHAR Name[MAX_PATH];
} OBJECT_TYPE_ENTRY, *POBJECT_TYPE_ENTRY;

typedef	struct DECLSPEC_ALIGN(1) _HOOK_ENTRY {
	ULONG ImageBase;
	ULONG Rva;
	ULONG Size;
	ULONG State;
	ULONG Parameter1;
	ULONG Parameter2;
    ULONG Parameter3;
    ULONG Parameter4;
	UCHAR Origin[64];
	UCHAR Current[64];
} HOOK_ENTRY, *PHOOK_ENTRY;

typedef struct DECLSPEC_ALIGN(1) _KIDT_ENTRY {
	USHORT Offset;
	USHORT Selector;
	struct {
		USHORT __unnamed1	: 8;
		USHORT type			: 2;
		USHORT __unnamed2	: 1;
		USHORT size			: 2;
		USHORT DPL			: 2;
		USHORT P			: 1;
	} Access;
	USHORT ExtendedOffset;
} KIDT_ENTRY, *PKIDT_ENTRY;

typedef struct DECLSPEC_ALIGN(1) _TIMER_ENTRY {
	PVOID Object;
	PVOID Thread;
	KTIMER Timer;
	KDPC Dpc;
} TIMER_ENTRY, *PTIMER_ENTRY;

typedef struct DECLSPEC_ALIGN(1) _DBGMSG{
	CLIENT_ID Cid;
	LARGE_INTEGER time;
	WCHAR process[16];
	WCHAR Msg[512];
}DBGMSG, *LPDBGMSG;

typedef struct DECLSPEC_ALIGN(1) _BIOS_REGISTERS {
    ULONG Eax;
    ULONG Ecx;
    ULONG Edx;
    ULONG Ebx;
    ULONG Ebp;
    ULONG Esi;
    ULONG Edi;
    USHORT SegDs;
    USHORT SegEs;
    ULONG EFlags;
} BIOS_REGISTERS, *PBIOS_REGISTERS;

typedef struct DECLSPEC_ALIGN(8) _IO_INPUT_BUFFER {
	union {
		ULONG Key;
		struct {
			ULONG Index : CHAR_BIT;
		};
	};
	ULONG ControlCode[UCHAR_MAX + 1];
	PVOID InputBuffer[UCHAR_MAX + 1];
} IO_INPUT_BUFFER, *PIO_INPUT_BUFFER;

typedef struct DECLSPEC_ALIGN(8) _KI_PACKET {

	union {

		struct {
			ULONG_PTR Parameter1;
			ULONG_PTR Parameter2;
			ULONG_PTR Parameter3;
			ULONG_PTR Parameter4;
			ULONG_PTR Parameter5;
			ULONG_PTR Parameter6;
			ULONG_PTR Parameter7;
			ULONG_PTR Parameter8;
		} Common;


        struct {
	        ULONG_PTR *InterruptServiceRoutines;
	        ULONG_PTR *Ssdt;
	        ULONG_PTR *ShadowSsdt;
	        BOOL      CaptureDbgMode;
	        USHORT    NtBuildNumber;
	        PWCHAR    KernelFileName;
	        PWCHAR    SystemrootPath;
            PVOID     KiKdProcess;
            PVOID     KiCsrProcess;
            PVOID     KiSystemProcess;
            PVOID     KiIdleProcess;
            PVOID     CsrProcessId;
        } Initialize;


        struct {
            KD_IO_PACKET Packet;
        } IoPacket;


        struct {
            PVOID Process;
            PKSTART_ROUTINE StartAddress;
            PVOID Context;
        } CreateThread;


        struct {
            ULONG Register;
            ULONGLONG Value;
            BOOL Write;
        } Msr;


        struct {
	        ULONG LowestPhysicalPage;
	        ULONG HighestPhysicalPage;
	        ULONG NumberOfPhysicalPages;
	        ULONG_PTR HighestUserAddress;
	        ULONG_PTR SystemRangeStart;
	        ULONG_PTR UserProbeAddress;
        } SystemInformation;


        struct {
	        PVOID KernelBase;
		    ULONG KernelSize;
		    PVOID PsLoadedModuleList;
		    PVOID MmLoadedUserImageList;
		    PVOID PspCidTable;
        } KernelInformation;


		struct {
			ULONG_PTR Address;
			BOOL GetExports;
            BOOL GetSymbols;
			PWCHAR Buffer;
            SIZE_T Size;
		} GetModuleInfo;


		struct {
			PVOID ProcessObject;
			PVOID VirtualAddress;
			PVOID Buffer;
			SIZE_T Size;
			PULONG NumberOfBytesRead;
		} VirtualRead;


		struct {
			PVOID ProcessObject;
			PVOID VirtualAddress;
			PVOID Buffer;
			SIZE_T Size;
			PULONG NumberOfBytesWritten;
		} VirtualWrite;


		struct {
			PLARGE_INTEGER PhysicalAddress;
			PVOID Buffer;
			SIZE_T Size;
		} PhysicalRead;


		struct {
			PLARGE_INTEGER PhysicalAddress;
			PVOID Buffer;
			SIZE_T Size;
		} PhysicalWrite;


		struct {
			PVOID ProcessObject;
			SIZE_T Size;
			PVOID Address;
		} VirtualAlloc;


		struct {
			PVOID ProcessObject;
			PVOID Address;
			SIZE_T Size;
		} VirtualFree;


		struct {
			PVOID ProcessObject;
			PVOID Address;
			SIZE_T Size;
			ULONG NewProtection;
			PULONG OldProtection;
		} VirtualProtect;


		struct {
			PVOID ProcessObject;
			PVOID Address;
			PMEMORY_BASIC_INFORMATION MemoryBasicInformation;
			SIZE_T Size;
		} VirtualQuery;


		struct {
			PVOID ProcessObject;
			PVOID SectionBase;
		} SectionUnmap;


		struct {
			PPROCESS_ENTRY Processes;
			ULONG Count;
		} ProcessEnumerate;


        struct {
			PVOID ProcessObject;
			PPROCESS_ENTRY Process;
		} ProcessQueryInformation;


		struct {
			PVOID ProcessObject;
            ULONG ProcessId;
			HANDLE Handle;
		} ProcessOpen;


		struct {
			PVOID ProcessObject;
		} ProcessSuspend;


		struct {
			PVOID ProcessObject;
			BOOL ForceResume;
		} ProcessResume;


		struct {
			PVOID ProcessObject;
            BOOL ForceKill;
		} ProcessKill;


        struct {
			PVOID ProcessObject;
            PDLL_ENTRY Dlls;
			ULONG Count;
		} DllEnumerate;


		struct {
			PVOID ProcessObject;
			PTHREAD_ENTRY Threads;
			ULONG Count;
		} ThreadEnumerate;


        struct {
			PVOID ThreadObject;
			PPROCESS_ENTRY Process;
            PTHREAD_ENTRY Thread;
		} ThreadQueryInformation;


		struct {
			PVOID ThreadObject;
            ULONG ThreadId;
			HANDLE Handle;
		} ThreadOpen;


		struct {
			PVOID ThreadObject;
		} ThreadSuspend;


		struct {
			PVOID ThreadObject;
			BOOL ForceResume;
		} ThreadResume;


		struct {
			PVOID ThreadObject;
		} ThreadKill;


		struct {
			PVOID ThreadObject;
			PCONTEXT Context;
		} ThreadCaptureStack;


		struct {
			PVOID ThreadObject;
			PCONTEXT Context;
			BOOL Set;
		} ThreadContext;


		struct {
			PVOID ProcessObject;
			HANDLE Handle;
		} CloseHandle;


		struct {
			PWCHAR FilePath;
			BOOL ForceDelete;
		} FileDelete;


		struct {
			PWCHAR SourceFilePath;
			PWCHAR DestinationFilePath;
		} FileCopy;


		struct {
			PKIDT_ENTRY InterruptEntries;
		} InterruptEnumerate;


		struct {
			ULONG Index;
			union {
				ULONG_PTR Offset;
				USHORT Selector;
			};
		} InterrupHook;


		struct {
			PSDT_ENTRY Ssdt;
			ULONG Count;
		} SsdtEnumerate;


		struct {
			PDRIVER_ENTRY Drivers;
			ULONG Count;
		} DriversEnumerate;


		struct {
			PVOID DriverObject;
			PDRIVER_ENTRY DriverInformation;
		} DriversQueryInformation;


		struct {
			PVOID *DeviceObjects;
			ULONG Count;
		} DevicesEnumerate;


		struct {
			PVOID Object;
			PWCHAR ObjectName;
		} ObjectQueryName;

        struct {
			PVOID Object;
			PWCHAR ObjectTypeName;
		} ObjectQueryTypeName;


		struct {
			PWCHAR ImagePath;
			ULONG Flags;
			ULONG Count;
			PHOOK_ENTRY HookEntries;
		} ImageHooksEnumerate;


		struct {
			PVOID ProcessObject;
			PHANDLE_ENTRY HandleEntries;
			ULONG Count;
		} HandlesEnumerate;


        struct {
            ULONG BiosCommand;
            PBIOS_REGISTERS BiosArguments;
        } BiosCall;


        struct {
            ULONG Disk;
            ULONG SectorNumber;
            USHORT SectorCount;
            PVOID Buffer;
            BOOL IsWrite;
        } DiskReadWrite;


	} Parameters;
} KI_PACKET, *PKI_PACKET;


typedef struct _CONTROL_AREA {
	PVOID			Segment; // 0x00
	LIST_ENTRY		DereferenceList; // 0x04
	ULONG			NumberOfSectionReferences; // 0x0c
	ULONG			NumberOfPfnReferences; // 0x10
	ULONG			NumberOfMappedViews; // 0x14
	USHORT			NumberOfSubsections; // 0x18
	USHORT			FlushInProgressCount; // 0x1a
	ULONG			NumberOfUserReferences; // 0x1c
	ULONG			Flags; // MMSECTION_FLAGS // 0x20
	PFILE_OBJECT	FilePointer; // 0x24
	PVOID			WaitingForDeletion; // PEVENT_COUNTER // 0x28
	USHORT			ModifiedWriteCount; // 0x2c
	USHORT			NumberOfSystemCacheViews; // 0x2e
	ULONG			PagedPoolUsage; // 0x30
	ULONG			NonPagedPoolUsage; // 0x34
} CONTROL_AREA, *PCONTROL_AREA;

typedef struct _SEGMENT {
	PCONTROL_AREA				ControlArea; // 0x00
	PVOID						SegmentBaseAddress; // 0x04
	ULONG						TotalNumberOfPtes; // 0x08
	ULONG						NonExtendedPtes; // 0x0c
	LARGE_INTEGER				SizeOfSegment; // 0x10
	ULONG						ImageCommitment; // 0x18
	PVOID						ImageInformation; // 0x1c PSECTION_IMAGE_INFORMATION
	PVOID						SystemImageBase; // 0x20
	ULONG						NumberOfCommittedPages; // 0x24
	ULONG						SegmentPteTemplate; // 0x28
	PVOID						BaseAddress; // 0x2c
	PVOID						BaseAddrPae; // 0x30 if PAE enabled
	PULONG						PrototypePte; // 0x34
	ULONG						ThePtes[1]; // 0x38
} SEGMENT, *PSEGMENT;


typedef struct _EX_CALLBACK {
    EX_FAST_REF RoutineBlock;
} EX_CALLBACK, *PEX_CALLBACK;

typedef struct _EX_CALLBACK_ROUTINE_BLOCK { 
    EX_RUNDOWN_REF RundownProtect;
    PVOID          Function;
    PVOID          Context;
} EX_CALLBACK_ROUTINE_BLOCK, *PEX_CALLBACK_ROUTINE_BLOCK;

typedef struct _CM_CALLBACK_CONTEXT_BLOCK {
    LARGE_INTEGER Cookie;             // to identify a specific callback for deregistration purposes
    LIST_ENTRY    ThreadListHead;     // Active threads inside this callback
    EX_PUSH_LOCK  ThreadListLock;     // synchronize access to the above
    PVOID         CallerContext;
} CM_CALLBACK_CONTEXT_BLOCK, *PCM_CALLBACK_CONTEXT_BLOCK;

typedef struct _CM_VISTA_CALLBACK_BLOCK {
    LIST_ENTRY    CallbackListHead;
    LIST_ENTRY    ThreadListHead;
    LARGE_INTEGER Cookie;
	PVOID         CallerContext;
    PVOID         Function;
} CM_VISTA_CALLBACK_BLOCK, *PCM_VISTA_CALLBACK_BLOCK;


typedef enum _MEMORY_INFORMATION_ {
	MemoryBasicInformation,
	MemoryWorkingSetList,
	MemorySectionName,
	MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;



// NtQuerySystemInformation
extern NTSTATUS
(NTAPI *KdQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

// NtTerminateProcess
extern NTSTATUS
(NTAPI *KdTerminateProcess)(IN HANDLE ProcessHandle, IN NTSTATUS  ExitStatus);

// NtTerminateThread
extern NTSTATUS
(NTAPI *KdTerminateThread)(IN HANDLE ThreadHandle, IN NTSTATUS  ExitStatus);

// KeStackAttachProcess
extern VOID
(NTAPI *KdStackAttachProcess)(PKPROCESS Process, PKAPC_STATE ApcState);

// KeUnstackDetachProcess
extern VOID
(NTAPI *KdUnstackDetachProcess)(PKAPC_STATE ApcState);

// PsLookupProcessByProcessId
extern NTSTATUS
(NTAPI *KdLookupProcessByProcessId)(HANDLE ProcessId, PEPROCESS *Process);

// PsLookupThreadByThreadId
extern NTSTATUS
(NTAPI *KdLookupThreadByThreadId)(PVOID UniqueThreadId, PETHREAD *Thread);

// ObOpenObjectByPointer
extern NTSTATUS
(NTAPI *KdOpenObjectByPointer)(PVOID Object, ULONG HandleAttributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType OPTIONAL, KPROCESSOR_MODE AccessMode, PHANDLE Handle);

// NtClose
extern NTSTATUS 
(NTAPI *KdClose)(HANDLE Handle);

// NtOpenFile
extern NTSTATUS
(NTAPI *KdOpenFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);

// NtAllocateVirtualMemory
extern NTSTATUS 
(NTAPI *KdAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

// NtFreeVirtualMemory
extern NTSTATUS 
(NTAPI *KdFreeVirtualMemory)( HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType); 

// MmGetPhysicalAddress
extern ULONGLONG
(NTAPI *KdGetPhysicalAddress)(PVOID BaseAddress);

// MmGetVirtualForPhysical
extern PVOID
(NTAPI *KdGetVirtualForPhysical)(ULONGLONG PhysicalAddress);

// NtReadVirtualMemory
extern NTSTATUS
(NTAPI *KdReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);

// NtWriteVirtualMemory
extern NTSTATUS
(NTAPI *KdWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);

// NtProtectVirtualMemory
extern NTSTATUS
(NTAPI *KdProtectVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

// NtQueryVirtualMemory
extern NTSTATUS
(NTAPI *KdQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, ULONG MemoryInformationLength, PULONG ReturnLength OPTIONAL);

// NtFlushInstructionCache
extern NTSTATUS
(NTAPI *KdFlushInstructionCache)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG FlushSize);

// NtOpenProcess
extern NTSTATUS
(NTAPI *KdOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

// NtOpenThread
extern NTSTATUS
(NTAPI *KdOpenThread)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

// MmCopyVirtualMemory
extern NTSTATUS
(NTAPI *MmCopyVirtualMemory)(PEPROCESS FromProcess, PVOID FromAddress, PEPROCESS ToProcess, PVOID ToAddress, ULONG BufferSize, KPROCESSOR_MODE PreviousMode, PULONG NumberOfBytesCopied);

// NtDuplicateObject
extern NTSTATUS
(NTAPI *KdDuplicateObject)(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);

// KeInsertQueueApc
extern BOOLEAN
(NTAPI *KdInsertQueueApc)(PKAPC Apc, PVOID SystemArgument1, PVOID SystemArgument2, KPRIORITY Increment);

// PsTerminateSystemThread
extern NTSTATUS
(NTAPI *KdTerminateSystemThread)(NTSTATUS ExitStatus);

// ObReferenceObjectByHandle
extern NTSTATUS
(NTAPI *KdReferenceObjectByHandle)(HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType OPTIONAL, KPROCESSOR_MODE AccessMode, PVOID *Object, POBJECT_HANDLE_INFORMATION HandleInformation OPTIONAL); 

// ObOpenObjectByName
extern NTSTATUS 
(NTAPI *KdOpenObjectByName)(POBJECT_ATTRIBUTES ObjectAttributes,  POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PACCESS_STATE AccessState, ACCESS_MASK DesiredAccess, PVOID ParseContext, PHANDLE Handle);

// NtResumeThread
extern NTSTATUS
(NTAPI *KdResumeThread)(HANDLE ThreadHandle, PULONG SuspendCount);

// NtOpenDirectoryObject
extern NTSTATUS
(NTAPI *KdOpenDirectoryObject)(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

// NtUnloadDriver
extern NTSTATUS
(NTAPI *KdUnloadDriver)(PUNICODE_STRING RegistryPath);

// Ke386CallBios
extern NTSTATUS
(NTAPI *Kd386CallBios)(ULONG BiosCommand, PCONTEXT BiosArguments);

// MmMapViewOfSection
extern NTSTATUS
(NTAPI *KdMapViewOfSection)(PVOID SectionObject, PEPROCESS Process, PVOID *BaseAddress, ULONG ZeroBits, ULONG CommitSize, PLARGE_INTEGER SectionOffset, PULONG ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect);

// KdUnmapViewOfSection
extern NTSTATUS
(NTAPI *KdUnmapViewOfSection)(PEPROCESS Process, PVOID BaseAddress);

// PsSuspendThread
extern NTSTATUS
(NTAPI *KdSuspendThread)(PKTHREAD Thread, PULONG PreviousCount);

// KeAlertThread
extern BOOLEAN
(NTAPI *KdAlertThread)(PKTHREAD Thread, KPROCESSOR_MODE AlertMode);




NTKERNELAPI
KPROCESSOR_MODE KeGetPreviousMode(void);

NTSTATUS
  RtlMultiByteToUnicodeN(
    PWSTR  UnicodeString,
    ULONG  MaxBytesInUnicodeString,
    PULONG  BytesInUnicodeString  OPTIONAL,
    PCHAR  MultiByteString,
    ULONG  BytesInMultiByteString
    ); 


NTSTATUS 
ObOpenObjectByName(
	IN POBJECT_ATTRIBUTES ObjectAttributes, 
    IN POBJECT_TYPE ObjectType OPTIONAL,
	IN KPROCESSOR_MODE AccessMode, 
    IN OUT PACCESS_STATE AccessState OPTIONAL,
	IN ACCESS_MASK DesiredAccess OPTIONAL,
	IN OUT PVOID ParseContext OPTIONAL, 
	OUT PHANDLE Handle
	);

PVOID
RtlImageDirectoryEntryToData(
    PVOID Base,
    BOOLEAN MappedAsImage,
    USHORT DirectoryEntry,
    PULONG Size
    );



NTKERNELAPI
PPEB
PsGetProcessPeb(PEPROCESS);

NTKERNELAPI
PVOID
PsGetProcessId(PEPROCESS);

NTKERNELAPI
PVOID
PsGetProcessInheritedFromUniqueProcessId(PEPROCESS);

NTKERNELAPI
PCHAR
PsGetProcessImageFileName(PEPROCESS);

NTKERNELAPI
PVOID
PsGetProcessSectionBaseAddress(PEPROCESS);

NTKERNELAPI
PVOID
PsGetThreadWin32Thread(PETHREAD);

NTKERNELAPI
PVOID
PsGetThreadProcessId(PETHREAD);

NTKERNELAPI
PVOID
PsGetThreadId(PETHREAD);

NTKERNELAPI
PTEB
PsGetThreadTeb(PETHREAD);


NTKERNELAPI
VOID
KeSetSystemAffinityThread(IN KAFFINITY);


NTKERNELAPI
ULONG
PsSetLegoNotifyRoutine(PVOID LegoNotifyRoutine);

NTKERNELAPI
NTSTATUS
PsGetContextThread(
    __in PETHREAD Thread,
    __inout PCONTEXT ThreadContext,
    __in KPROCESSOR_MODE Mode);

NTKERNELAPI
NTSTATUS
PsSetContextThread(
    __in PETHREAD Thread,
    __inout PCONTEXT ThreadContext,
    __in KPROCESSOR_MODE Mode);

NTKERNELAPI
NTSTATUS
KeSetAffinityThread(
   PKTHREAD Thread,
   KAFFINITY Affinity);


unsigned char __inbyte(unsigned short Port);
unsigned short __inword(unsigned short Port);
unsigned long __indword(unsigned short Port);
void __outbyte(unsigned short Port, unsigned char Data);
void __outword(unsigned short Port, unsigned short Data);
void __outdword(unsigned short Port, unsigned long Data);
void __inbytestring(unsigned short Port, unsigned char *Buffer, unsigned long Count);
void __inwordstring(unsigned short Port, unsigned short *Buffer, unsigned long Count);
void __indwordstring(unsigned short Port, unsigned long *Buffer, unsigned long Count);
void __outbytestring(unsigned short Port, unsigned char *Buffer, unsigned long Count);
void __outwordstring(unsigned short Port, unsigned short *Buffer, unsigned long Count);
void __outdwordstring(unsigned short Port, unsigned long *Buffer, unsigned long Count);
unsigned __int64 __readmsr(unsigned long);
void __writemsr(unsigned long, unsigned __int64);




bool IsPAEenabled();


extern POBJECT_TYPE *ExEventPairObjectType;
extern POBJECT_TYPE *PsProcessType;
extern POBJECT_TYPE *PsThreadType;
extern POBJECT_TYPE *PsJobType;
extern POBJECT_TYPE *LpcPortObjectType;
extern POBJECT_TYPE *LpcWaitablePortObjectType;
extern POBJECT_TYPE *IoDriverObjectType;
extern POBJECT_TYPE *IoDeviceObjectType;
extern POBJECT_TYPE *ExEventObjectType;
extern POBJECT_TYPE *ExDesktopObjectType;



typedef void (*PCALLBACK_PROC)(ULONG Param);

typedef struct _DPC_PARAMS {
	KDPC		 Dpc;
	PCALLBACK_PROC Proc;
	ULONG		Param;
	PKEVENT	   SyncEvent;
	BOOLEAN	   Syncronous;
} DPC_PARAMS, *PDPC_PARAMS;





LONG Initialize(PKI_PACKET KiPacket);


VOID 
ExecuteOnAllProcessors(
	PCALLBACK_PROC Proc,
	BOOLEAN Syncronous
	);

POBJECT_TYPE
TypeFromObject(
	POBJECT_HEADER ObjectHeader
	);




#define SystemPath L"\\Systemroot\\system32\\"



extern PVOID ntoskrnl;
extern PVOID w32k;
extern PVOID KernelBase;
extern ULONG KernelSize;
extern PVOID w32kBase;
extern ULONG w32kSize;
extern ULONG KernelDelta;
extern ULONG w32kDelta;
extern WCHAR CurrentKernel[MAX_PATH];
extern WCHAR SystemrootPath[MAX_PATH];
extern PKDDEBUGGER_DATA64 KdVersionBlock;
extern PLATFORM_OPTIONS info;
extern SHORT KdBuildNumber;
extern POBJECT_TYPE TypesArray[];
extern PDRIVER_OBJECT KdDriverObject;
extern PEPROCESS CsrProcess;



PHANDLE_TABLE __forceinline GetProcessHandleTable(PVOID Process)
{
    ULONG HandleTable = 0;

    if (IsXp)
        HandleTable = 0xc4;
    else if (IsVista)
        HandleTable = 0xdc;
    else if (IsWin7)
        HandleTable = 0xf4;
    
    return *(PHANDLE_TABLE*)((ULONG_PTR)Process + HandleTable);
}

BOOL __forceinline IsValidHandleTable(PVOID Process)
{
    return MmIsAddressValid(GetProcessHandleTable(Process));
}


#ifdef __cplusplus
	}
#endif