/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		memory.h
 *
 * Abstract:
 *
 *		This module defines various routines used to manage memory such as read/write .
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



extern POBJECT_TYPE *MmSectionObjectType;



BOOLEAN
__fastcall
ExAcquireRundownProtection(
	IN PEX_RUNDOWN_REF RunRef
	);


VOID
__fastcall
ExReleaseRundownProtection(
	IN PEX_RUNDOWN_REF RunRef
	);



NTSTATUS
KiReadProcessMemory(
	PEPROCESS Process,
	PVOID lpBaseAddress,
	PVOID lpBuffer,
	ULONG nSize,
	PULONG lpNumberOfBytesRead
	);


NTSTATUS
KiWriteProcessMemory(
	PEPROCESS Process,
	PVOID lpBaseAddress,
	PVOID lpBuffer,
	ULONG nSize,
	PULONG lpNumberOfBytesWritten
	);


NTSTATUS
MmCommitUserBuffer(
	HANDLE hProcess,
	PVOID *BaseAddress,
	ULONG Size);


NTSTATUS
MmFreeUserBuffer(
	HANDLE hProcess,
	PVOID BaseAddress,
	ULONG Size,
	ULONG Release);





VOID
MemOpen(
	);


VOID
MemClose(
	);


ULONG 
GetSystemBufferSize(
	PVOID Address,
	ULONG Size
	);


BOOLEAN
IsValidSystemAddress(
	PVOID Address
	);


ULONGLONG
GetSystemPagesSize(
	);


ULONG
ReadUlong(
	PEPROCESS eProcess,
	PVOID lpAddress
	);


VOID
WriteUlong(
	PEPROCESS eProcess,
	PVOID lpAddress,
	ULONG Value
	);


PVOID
MapVirtualAddress(
	PVOID VirtualAddress,
	ULONG Size,
	PMDL *MemoryDescriptorList, 
	CSHORT Flags = 0
	);


VOID 
UnmapVirtualAddress(
	PVOID VirtualAddress, 
	PMDL MemoryDescriptorList
	);


NTSTATUS
MmReadPhysicalPages(PLARGE_INTEGER PhysicalAddress,
                    PVOID Buffer,
                    SIZE_T szBuffer);

NTSTATUS
MmWritePhysicalPages(PLARGE_INTEGER PhysicalAddress, 
                     PVOID Buffer,
                     SIZE_T Size);




#ifdef _REPORT_
struct __MemoryRef {
	ULONGLONG Counter;
	ULONGLONG Mount;
};

extern __MemoryRef MemoryRef;
#endif

#ifdef __cplusplus
	}
#endif


#define MEMORY_TAG 'abiS'


PVOID FORCEINLINE MmAlloc(SIZE_T Size)
{
	PVOID Block = ExAllocatePoolWithTag(NonPagedPool, Size + sizeof(SIZE_T), MEMORY_TAG);
	if (Block) 
	{
		RtlZeroMemory(Block, Size + sizeof(SIZE_T));
		*(PSIZE_T)Block = Size;
#ifdef _REPORT_
		MemoryRef.Counter ++;
		MemoryRef.Mount += Size;
#endif
		return (PVOID)((PSIZE_T)Block + 1);
	}
	return NULL;
}

VOID FORCEINLINE MmFree(PVOID MemoryBlock)
{
	if (MemoryBlock)
	{
		PVOID Block = (PVOID)((PSIZE_T)MemoryBlock - 1);
#ifdef _REPORT_
		MemoryRef.Counter --;
		MemoryRef.Mount -= *((PSIZE_T)Block);
#endif
		ExFreePoolWithTag(Block, MEMORY_TAG);
	}
}

PVOID FORCEINLINE MmRealloc(PVOID MemoryBlock, SIZE_T Size)
{
	PVOID Block;
	SIZE_T PrevSize;

	if (!MemoryBlock)
	{
		return MmAlloc(Size);
	}
	else
	{
		PrevSize = *((PSIZE_T)MemoryBlock - 1);
		Block = MmAlloc(Size);
		if (Block)
		{
			RtlCopyMemory(Block, MemoryBlock, min(PrevSize, Size));
			MmFree(MemoryBlock);
		}
		return Block;
	}
}

SIZE_T FORCEINLINE MmGetSize(PVOID MemoryBlock)
{
    PVOID Block = (PVOID)((SIZE_T *)MemoryBlock - 1);

    if (Block == NULL || MemoryBlock == NULL)
        return 0;
	
	if (!MemoryBlock || !Block)
	{
		return 0;
	}
	else
	{
		return (*(SIZE_T *)Block);
	}
}