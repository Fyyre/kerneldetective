/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		memory.c
 *
 * Abstract:
 *
 *		This module implements various routines used to manage memory such as read/write .
 *
 * Author:
 *
 *		GamingMasteR
 *
 */








#include "KeDetective.h"
#include "process.h"




#ifdef _REPORT_
__MemoryRef MemoryRef;
#endif

NTSTATUS 
KiReadProcessMemory(
	PEPROCESS Process,
	PVOID lpBaseAddress,
	PVOID lpBuffer,
	ULONG nSize,
	PULONG lpNumberOfBytesRead
	)
{
	VMProtectBegin;

	NTSTATUS		Status = STATUS_SUCCESS;
	ULONG			cb = 0;
	KPROCESSOR_MODE PrevMode;
	HANDLE hProcess = 0;
	
    if (BAD_PROCESS_STATUS(Process))
        return STATUS_INVALID_PARAMETER;
	if (nSize == 0)
        return STATUS_SUCCESS;
	if (((ULONG)lpBaseAddress + nSize < (ULONG)lpBaseAddress)||
        ((ULONG)lpBuffer + nSize < (ULONG)lpBuffer))
        return STATUS_ACCESS_VIOLATION;

	if	(lpBaseAddress < MM_HIGHEST_USER_ADDRESS)
	{
		if (((ULONG)lpBaseAddress + nSize > (ULONG)MM_HIGHEST_USER_ADDRESS)||
			((ULONG)lpBuffer + nSize > (ULONG)MM_HIGHEST_USER_ADDRESS))
			return STATUS_ACCESS_VIOLATION;

		if (ExAcquireRundownProtection(parseobject(Process, ProcessRundown, EX_RUNDOWN_REF))) 
        {
			PrevMode = KeSetPreviousMode(KernelMode);
			Status = MmCopyVirtualMemory(Process, lpBaseAddress, IoGetCurrentProcess(), lpBuffer, nSize, KernelMode, &cb);
			KeSetPreviousMode(PrevMode);
			if (lpNumberOfBytesRead)
                *lpNumberOfBytesRead = cb;
            ExReleaseRundownProtection(parseobject(Process, ProcessRundown, EX_RUNDOWN_REF));
		}
        else 
        {
			Status = STATUS_UNSUCCESSFUL;
		}
	}
	else if (lpBaseAddress >= MM_SYSTEM_RANGE_START)
    {
        ULONG MemoryCopied = 0;
        ULONG SizeLeft = nSize;
        ULONG nPages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(lpBaseAddress, nSize);
        ULONG_PTR Offset = 0;
        ULONG Chunk;
        PUCHAR PageOffset;
        PUCHAR BufferOffset;
        PVOID NonpagedBuffer;
        KAPC_STATE ApcState;
        
        NonpagedBuffer = MmAlloc(nSize);
        KdStackAttachProcess(&CsrProcess->Pcb, &ApcState);
        for (ULONG N = 0; N < nPages; N++)
        {
            Chunk = PAGE_SIZE;
            PageOffset = Offset + (PUCHAR)lpBaseAddress;
            BufferOffset = (PUCHAR)NonpagedBuffer + nSize - SizeLeft;

            if (N == 0)
            {
                Chunk = min(nSize, PAGE_SIZE - BYTE_OFFSET(lpBaseAddress));
            }
            else if (N == nPages - 1)
            {
                Chunk = SizeLeft;
            }

            if (MmIsAddressValid(PageOffset))
            {
                MemoryCopied += Chunk;
                __try
                {
                    RtlCopyMemory(BufferOffset, PageOffset, Chunk);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    
                }
            }

            Offset += Chunk;
            SizeLeft -= Chunk;
        }

        KdUnstackDetachProcess(&ApcState);
        RtlCopyMemory(lpBuffer, NonpagedBuffer, nSize);
        MmFree(NonpagedBuffer);

        if (lpNumberOfBytesRead)
            *lpNumberOfBytesRead = MemoryCopied;

        if (MemoryCopied == 0)
            Status = STATUS_UNSUCCESSFUL;
        else
            Status = STATUS_SUCCESS;
	}
	else
	{
		Status = STATUS_UNSUCCESSFUL;
	}

	VMProtectEnd;
	return Status;
}


NTSTATUS 
KiWriteProcessMemory(
	PEPROCESS Process,
	PVOID lpBaseAddress,
	PVOID lpBuffer,
	ULONG nSize,
	PULONG lpNumberOfBytesWritten
	)
{
	VMProtectBegin;

	NTSTATUS	Status = STATUS_SUCCESS;
	ULONG	cb = 0;
	KPROCESSOR_MODE	PrevMode;
	HANDLE	hProcess = 0;
	ULONG	dwOldProtect;
	ULONG	lpPageSize = nSize;
	PVOID	lpPageStartAddress = lpBaseAddress;
	
    if (BAD_PROCESS_STATUS(Process))
        return STATUS_INVALID_PARAMETER;
	if (nSize == 0)
        return STATUS_SUCCESS;

	if (((ULONG)lpBaseAddress + nSize < (ULONG)lpBaseAddress)||
		((ULONG)lpBuffer + nSize < (ULONG)lpBuffer)) return STATUS_ACCESS_VIOLATION;

	if	(lpBaseAddress < MM_HIGHEST_USER_ADDRESS)
	{
		if (((ULONG)lpBaseAddress + nSize > (ULONG)MM_HIGHEST_USER_ADDRESS)||
			((ULONG)lpBuffer + nSize > (ULONG)MM_HIGHEST_USER_ADDRESS))
			return STATUS_ACCESS_VIOLATION;

		__try 
        {
			Status = KdOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, 0, 0, 0, KernelMode, &hProcess);
		} 
        __except(EXCEPTION_EXECUTE_HANDLER) 
        {
			Status = STATUS_SUCCESS;
			hProcess = 0;
		}
		PrevMode = KeSetPreviousMode(KernelMode);
		if (STATUS_SUCCESS == Status)
		{
			if (hProcess && STATUS_SUCCESS == KdProtectVirtualMemory(hProcess, &lpPageStartAddress, &lpPageSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
			{
				Status = MmCopyVirtualMemory(IoGetCurrentProcess(), lpBuffer, Process, lpBaseAddress, nSize, KernelMode, &cb);
				KdProtectVirtualMemory(hProcess, &lpPageStartAddress, &lpPageSize, dwOldProtect, &dwOldProtect);
			}
			else if (hProcess && STATUS_SUCCESS == KdProtectVirtualMemory(hProcess, &lpPageStartAddress, &lpPageSize, PAGE_READWRITE, &dwOldProtect))
			{
				Status = MmCopyVirtualMemory(IoGetCurrentProcess(), lpBuffer, Process, lpBaseAddress, nSize, KernelMode, &cb);
				KdProtectVirtualMemory(hProcess, &lpPageStartAddress, &lpPageSize, dwOldProtect, &dwOldProtect);
			}
			else
			{
				MemOpen();
				Status = MmCopyVirtualMemory(IoGetCurrentProcess(), lpBuffer, Process, lpBaseAddress, nSize, KernelMode, &cb);
				MemClose();
			}
			if (hProcess) 
            {
				KdFlushInstructionCache(hProcess, lpBaseAddress, nSize);
				KdClose(hProcess);
			}
		};
		KeSetPreviousMode(PrevMode);
		if (lpNumberOfBytesWritten)
            *lpNumberOfBytesWritten = cb;
	}
	else if (lpBaseAddress >= MM_SYSTEM_RANGE_START)
	{
		ULONG MemoryCopied = 0;
        ULONG SizeLeft = nSize;
        ULONG nPages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(lpBaseAddress, nSize);
        ULONG_PTR Offset = 0;
        ULONG Chunk;
        PUCHAR PageOffset;
        PUCHAR BufferOffset;
        PVOID NonpagedBuffer;
        KAPC_STATE ApcState;
        
        NonpagedBuffer = MmAlloc(nSize);
        RtlCopyMemory(NonpagedBuffer, lpBuffer, nSize);
        KdStackAttachProcess(&CsrProcess->Pcb, &ApcState);
        
        for (ULONG N = 0; N < nPages; N++)
        {
            Chunk = PAGE_SIZE;
            PageOffset = Offset + (PUCHAR)lpBaseAddress;
            BufferOffset = (PUCHAR)NonpagedBuffer + nSize - SizeLeft;

            if (N == 0)
            {
                Chunk = min(nSize, PAGE_SIZE - BYTE_OFFSET(lpBaseAddress));
            }
            else if (N == nPages - 1)
            {
                Chunk = SizeLeft;
            }

            if (MmIsAddressValid(PageOffset))
            {
                MemoryCopied += Chunk;
                MemOpen();
                __try
                {
                    RtlCopyMemory(PageOffset, BufferOffset, Chunk);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    
                }
                MemClose();
            }

            Offset += Chunk;
            SizeLeft -= Chunk;
        }

        KdUnstackDetachProcess(&ApcState);
        MmFree(NonpagedBuffer);

        if (lpNumberOfBytesWritten)
            *lpNumberOfBytesWritten = MemoryCopied;

        if (MemoryCopied == 0)
            Status = STATUS_UNSUCCESSFUL;
        else
            Status = STATUS_SUCCESS;
	}
	else
	{
		Status = STATUS_UNSUCCESSFUL;
	};
	VMProtectEnd;
	return Status;
};


NTSTATUS
MmCommitUserBuffer(
	HANDLE hProcess,
	PVOID *BaseAddress,
	ULONG Size)
{
	ULONG RegionSize = Size;
	KPROCESSOR_MODE PrevMode = KeSetPreviousMode(KernelMode);
	NTSTATUS NtStatus = KdAllocateVirtualMemory(hProcess, BaseAddress, 0L, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
	KeSetPreviousMode(PrevMode);
	return NtStatus;
};


NTSTATUS
MmFreeUserBuffer(
	HANDLE hProcess,
	PVOID BaseAddress,
	ULONG Size,
	ULONG Release)
{
	PVOID Address = BaseAddress;
	ULONG RegionSize = (Release ? 0 : Size);
	ULONG dwAccess = (Release ? MEM_RELEASE : MEM_DECOMMIT);
	
	if (BaseAddress > MM_HIGHEST_USER_ADDRESS)
		return STATUS_INVALID_PARAMETER;
	if ((ULONG_PTR)MM_HIGHEST_USER_ADDRESS - (ULONG_PTR)Address < Size)
		return STATUS_INVALID_PARAMETER;
	KPROCESSOR_MODE PrevMode = KeSetPreviousMode(KernelMode);
	NTSTATUS NtStatus = KdFreeVirtualMemory(hProcess, &Address, &RegionSize, dwAccess);
	KeSetPreviousMode(PrevMode);
	return NtStatus;
};



VOID 
__declspec(naked) 
MemOpen(
	)
{
	__asm	pushad;
	__asm	cli;
	__asm	mov eax, cr0;
	__asm	and eax, ~0x10000;
	__asm	mov cr0, eax;
	__asm	popad;
	__asm	ret;
};


VOID
__declspec(naked) 
MemClose(
	)
{
	__asm	pushad;
	__asm	WBINVD;
	__asm	mov eax, cr0;
	__asm	or eax, 0x10000;
	__asm	mov cr0, eax;
	__asm	sti;
	__asm	popad;
	__asm	ret;
};


ULONG 
GetSystemBufferSize(
	PVOID Address,
	ULONG Size
	)
{
	ULONG offset;
	for (offset = 0; offset < Size; offset++)
		if (!MmIsAddressValid((PVOID)((ULONG)Address + offset)))
			return offset;
	return Size;
};


BOOLEAN
IsValidSystemAddress(
	PVOID SystemAddress
	)
{
	PVOID VirtualAddress;
	ULONGLONG PhysicalAddress;

	if (!MmIsAddressValid(SystemAddress)) 
		return FALSE;

	PhysicalAddress = (ULONGLONG)KdGetPhysicalAddress(SystemAddress);
	if (PhysicalAddress > GetSystemPagesSize())
		return FALSE;

	VirtualAddress = KdGetVirtualForPhysical(PhysicalAddress);
	if (VirtualAddress != SystemAddress)
		return FALSE;

	if (!MmIsNonPagedSystemAddressValid(SystemAddress))
		return FALSE;

	return TRUE;
};


ULONGLONG
FORCEINLINE
GetSystemPagesSize(
	)
{
	return (*(PULONG)KdVersionBlock->MmNumberOfPhysicalPages * PAGE_SIZE);
};


ULONG
ReadUlong(
	PEPROCESS eProcess,
	PVOID lpAddress
	)
{
	ULONG dwData = 0;
	KiReadProcessMemory(eProcess, lpAddress, &dwData, sizeof(ULONG), 0);
	return dwData;
};


VOID
WriteUlong(
	PEPROCESS eProcess,
	PVOID lpAddress,
	ULONG Value
	)
{
	ULONG dwData = Value;
	KiWriteProcessMemory(eProcess, lpAddress, &dwData, sizeof(ULONG), 0);
};


PVOID MapVirtualAddress(PVOID VirtualAddress, ULONG Size, PMDL *MemoryDescriptorList, CSHORT Flags)
{
	PVOID Address = NULL;

	if (MemoryDescriptorList && MmIsAddressValid(VirtualAddress)) {
		*MemoryDescriptorList = IoAllocateMdl(VirtualAddress, Size, FALSE, FALSE, NULL);
		if (*MemoryDescriptorList) {
			MmBuildMdlForNonPagedPool(*MemoryDescriptorList);
			(*MemoryDescriptorList)->MdlFlags |= Flags;
			Address = MmMapLockedPagesSpecifyCache(*MemoryDescriptorList, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
			if (Address == NULL) {
				IoFreeMdl(*MemoryDescriptorList);
			}
		}
	}
	return Address;
}


VOID UnmapVirtualAddress(PVOID VirtualAddress, PMDL MemoryDescriptorList)
{
	if (MemoryDescriptorList && VirtualAddress) {
		MmUnmapLockedPages(VirtualAddress, MemoryDescriptorList);
		IoFreeMdl(MemoryDescriptorList);
	}
}


NTSTATUS MmMapPhysicalPages(PVOID Section, PULONGLONG Address, PSIZE_T Size, PVOID *BaseAddress, ULONG Access)
{
    NTSTATUS Status;
    LARGE_INTEGER SectionOffset;
    SIZE_T ViewSize;


    *BaseAddress = NULL;
    SectionOffset.QuadPart = *Address;
    ViewSize = *Size;
    Status = KdMapViewOfSection(Section,
                                IoGetCurrentProcess(),
								BaseAddress,
								0L,
								0L,
								&SectionOffset,
								&ViewSize,
								ViewUnmap,
								0,
								Access);
    if (!NT_SUCCESS(Status))
    {
        *BaseAddress = NULL;
        SectionOffset.QuadPart = *Address;
        ViewSize = *Size;
        Status = KdMapViewOfSection(Section,
                                    IoGetCurrentProcess(),
								    BaseAddress,
								    0L,
								    0L,
								    &SectionOffset,
								    &ViewSize,
								    ViewUnmap,
								    0,
								    PAGE_NOCACHE | Access);
    }

    if (NT_SUCCESS(Status))
    {
        *Address = SectionOffset.QuadPart;
        *Size = ViewSize;
    }

    return Status;
}


NTSTATUS MmReadPhysicalPages(PLARGE_INTEGER PhysicalAddress, PVOID Buffer, SIZE_T Size)
{
	NTSTATUS Status;
    UNICODE_STRING PhysicalMemoryDevice;
    OBJECT_ATTRIBUTES MemoryAttributes;
    SIZE_T ViewSize;
    PVOID BaseAddress = NULL;
	HANDLE MemoryHandle = NULL;
    PVOID Section = NULL;
    KPROCESSOR_MODE PreviousMode;


	VMProtectBegin;

    PreviousMode = KeSetPreviousMode(KernelMode);

    ViewSize = Size;

	RtlInitUnicodeString(&PhysicalMemoryDevice, L"\\Device\\PhysicalMemory");

	InitializeObjectAttributes(&MemoryAttributes,
							   &PhysicalMemoryDevice,
							   OBJ_CASE_INSENSITIVE,
							   NULL,
							   NULL);

	Status = KdOpenObjectByName(&MemoryAttributes,
								*MmSectionObjectType,
								KernelMode,
								NULL,
								SECTION_MAP_READ,
								NULL,
								&MemoryHandle);

	if (!NT_SUCCESS(Status))
	{
        KeSetPreviousMode(PreviousMode);
		return Status;
	}

	Status = KdReferenceObjectByHandle(MemoryHandle,
									   SYNCHRONIZE,
									   *MmSectionObjectType,
									   KernelMode,
									   &Section,
									   NULL);
	
	if (NT_SUCCESS(Status))
    {
        ULONGLONG StartAddress = PhysicalAddress->QuadPart;
        Status = MmMapPhysicalPages(Section, &StartAddress, &ViewSize, &BaseAddress, PAGE_READONLY);
		
        __try
        {
		    if (NT_SUCCESS(Status))
		    {
                ULONG Offset = (ULONG)(PhysicalAddress->QuadPart - StartAddress);
                SIZE_T szBuffer = min(Size, ViewSize - Offset);

			    RtlCopyMemory(Buffer, (PUCHAR)BaseAddress + Offset, szBuffer);
			    KdUnmapViewOfSection(IoGetCurrentProcess(), BaseAddress);
                
		    }
		    else
		    {
			    RtlZeroMemory(Buffer, Size);
		    }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) 
        {
            Status = GetExceptionCode();
        }
		
        ObfDereferenceObject(Section);
    }

    ZwClose(MemoryHandle);

    KeSetPreviousMode(PreviousMode);

	VMProtectEnd;
    return Status;
}


NTSTATUS MmWritePhysicalPages(PLARGE_INTEGER PhysicalAddress, PVOID Buffer, SIZE_T Size)
{
	NTSTATUS Status;
    UNICODE_STRING PhysicalMemoryDevice;
    OBJECT_ATTRIBUTES MemoryAttributes;
    SIZE_T ViewSize;
    PVOID BaseAddress = NULL;
	HANDLE MemoryHandle = NULL;
    PVOID Section = NULL;
    KPROCESSOR_MODE PreviousMode;


	VMProtectBegin;

    PreviousMode = KeSetPreviousMode(KernelMode);

    ViewSize = Size;

	RtlInitUnicodeString(&PhysicalMemoryDevice, L"\\Device\\PhysicalMemory");

	InitializeObjectAttributes(&MemoryAttributes,
							   &PhysicalMemoryDevice,
							   OBJ_CASE_INSENSITIVE,
							   NULL,
							   NULL);

	Status = KdOpenObjectByName(&MemoryAttributes,
								*MmSectionObjectType,
								KernelMode,
								NULL,
								SECTION_MAP_READ,
								NULL,
								&MemoryHandle);

	if (!NT_SUCCESS(Status))
	{
        KeSetPreviousMode(PreviousMode);
		return Status;
	}

	Status = KdReferenceObjectByHandle(MemoryHandle,
									   SYNCHRONIZE,
									   *MmSectionObjectType,
									   KernelMode,
									   &Section,
									   NULL);
	
	if (NT_SUCCESS(Status))
    {
        ULONGLONG StartAddress = PhysicalAddress->QuadPart;
        Status = MmMapPhysicalPages(Section, &StartAddress, &ViewSize, &BaseAddress, PAGE_READWRITE);
		
        __try
        {
		    if (NT_SUCCESS(Status))
		    {
                ULONG Offset = (ULONG)(PhysicalAddress->QuadPart - StartAddress);
                SIZE_T szBuffer = min(Size, ViewSize - Offset);

			    RtlCopyMemory((PUCHAR)BaseAddress + Offset, Buffer, szBuffer);
			    KdUnmapViewOfSection(IoGetCurrentProcess(), BaseAddress);
                
		    }
		    else
		    {
			    RtlZeroMemory(Buffer, Size);
		    }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) 
        {
            Status = GetExceptionCode();
        }
		
        ObfDereferenceObject(Section);
    }

    ZwClose(MemoryHandle);

    KeSetPreviousMode(PreviousMode);

	VMProtectEnd;
    return Status;
}