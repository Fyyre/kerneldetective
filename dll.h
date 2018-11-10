/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		dll.h
 *
 * Abstract:
 *
 *		This module defines various routines used to scan for DLLs .
 *
 * Author:
 *
 *		GamingMasteR
 *
 */


#include "KeDetective.h"

#ifdef __cplusplus
	extern "C" {
#endif



typedef struct _PEB_LDR_DATA {
  ULONG                   Length;
  BOOLEAN                 Initialized;
  PVOID                   SsHandle;
  LIST_ENTRY              InLoadOrderModuleList;
  LIST_ENTRY              InMemoryOrderModuleList;
  LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;




typedef struct _PEB {
  BOOLEAN                 InheritedAddressSpace;
  BOOLEAN                 ReadImageFileExecOptions;
  BOOLEAN                 BeingDebugged;
  BOOLEAN                 Spare;
  HANDLE                  Mutant;
  PVOID                   ImageBaseAddress;
  PPEB_LDR_DATA           LoaderData;
  PVOID					  ProcessParameters;
  PVOID                   SubSystemData;
  PVOID                   ProcessHeap;
  PVOID                   FastPebLock;
  PVOID					  FastPebLockRoutine;
  PVOID					  FastPebUnlockRoutine;
  ULONG                   EnvironmentUpdateCount;
  PVOID                   *KernelCallbackTable;
  PVOID                   EventLogSection;
  PVOID                   EventLog;
  PVOID			          FreeList;
  ULONG                   TlsExpansionCounter;
  PVOID                   TlsBitmap;
  ULONG                   TlsBitmapBits[0x2];
  PVOID                   ReadOnlySharedMemoryBase;
  PVOID                   ReadOnlySharedMemoryHeap;
  PVOID                   *ReadOnlyStaticServerData;
  PVOID                   AnsiCodePageData;
  PVOID                   OemCodePageData;
  PVOID                   UnicodeCaseTableData;
  ULONG                   NumberOfProcessors;
  ULONG                   NtGlobalFlag;
  CHAR                    Spare2[0x4];
  LARGE_INTEGER           CriticalSectionTimeout;
  ULONG                   HeapSegmentReserve;
  ULONG                   HeapSegmentCommit;
  ULONG                   HeapDeCommitTotalFreeThreshold;
  ULONG                   HeapDeCommitFreeBlockThreshold;
  ULONG                   NumberOfHeaps;
  ULONG                   MaximumNumberOfHeaps;
  PVOID                   **ProcessHeaps;
  PVOID                   GdiSharedHandleTable;
  PVOID                   ProcessStarterHelper;
  PVOID                   GdiDCAttributeList;
  PVOID                   LoaderLock;
  ULONG                   OSMajorVersion;
  ULONG                   OSMinorVersion;
  ULONG                   OSBuildNumber;
  ULONG                   OSPlatformId;
  ULONG                   ImageSubSystem;
  ULONG                   ImageSubSystemMajorVersion;
  ULONG                   ImageSubSystemMinorVersion;
  ULONG                   GdiHandleBuffer[0x22];
  ULONG                   PostProcessInitRoutine;
  ULONG                   TlsExpansionBitmap;
  CHAR                    TlsExpansionBitmapBits[0x80];
  ULONG                   SessionId;
} PEB, *PPEB;


typedef struct _MMVAD_FLAGS // 10 elements, 0x4 bytes (sizeof) 
{ 
	ULONG_PTR CommitCharge : 19; // 0 BitPosition 
	ULONG_PTR PhysicalMapping : 1; // 19 BitPosition 
	ULONG_PTR ImageMap : 1; // 20 BitPosition 
	ULONG_PTR UserPhysicalPages : 1; // 21 BitPosition 
	ULONG_PTR NoChange : 1; // 22 BitPosition 
	ULONG_PTR WriteWatch : 1; // 23 BitPosition 
	ULONG_PTR Protection : 5; // 24 BitPosition 
	ULONG_PTR LargePages : 1; // 29 BitPosition 
	ULONG_PTR MemCommit : 1; // 30 BitPosition 
	ULONG_PTR PrivateMemory : 1; // 31 BitPosition 
}MMVAD_FLAGS, *PMMVAD_FLAGS;

typedef struct _MMVAD
{
	ULONG_PTR StartingVpn;
	ULONG_PTR EndingVpn;
	struct _MMVAD* Parent;
	struct _MMVAD* LeftChild;
	struct _MMVAD* RightChild;
	struct _MMVAD_FLAGS VadFlags;
	struct _CONTROL_AREA* ControlArea;
	struct _MMPTE* FirstPrototypePte;
	struct _MMPTE* LastContiguousPte;
	ULONG_PTR LongFlags2;
}MMVAD, *PMMVAD;


typedef struct _MMVAD_FLAGS_VISTA // 7 elements, 0x4 bytes (sizeof) 
{ 
	ULONG32 CommitCharge : 19; // 0 BitPosition 
	ULONG32 NoChange : 1; // 19 BitPosition 
	ULONG32 VadType : 3; // 20 BitPosition 
	ULONG32 MemCommit : 1; // 23 BitPosition 
	ULONG32 Protection : 5; // 24 BitPosition 
	ULONG32 Spare : 2; // 29 BitPosition 
	ULONG32 PrivateMemory : 1; // 31 BitPosition 
}MMVAD_FLAGS_VISTA, *PMMVAD_FLAGS_VISTA; 

typedef struct _MMVAD_VISTA // 13 elements, 0x30 bytes (sizeof) 
{ 
	union 
	{ 
		LONG32 Balance : 2;
		struct _MMVAD_VISTA* Parent; 
	}u1;
	struct _MMVAD_VISTA* LeftChild; 
	struct _MMVAD_VISTA* RightChild; 
	ULONG32 StartingVpn; 
	ULONG32 EndingVpn; 
	struct _MMVAD_FLAGS_VISTA VadFlags;
	struct _EX_PUSH_LOCK PushLock;
	ULONG32 LongFlags3;
	ULONG32 LongFlags2;
	struct _SEGMENT* Section; 
	struct _MMPTE* FirstPrototypePte; 
	struct _MMPTE* LastContiguousPte; 
}MMVAD_VISTA, *PMMVAD_VISTA; 



NTSTATUS
HackDLL(
	PEPROCESS eProcess,
    PDLL_ENTRY* lpBase,
    PULONG lpCount
	);


#ifdef __cplusplus
	}
#endif