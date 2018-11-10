/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		dll.c
 *
 * Abstract:
 *
 *		This module implements various routines used to scan for DLLs .
 *
 * Author:
 *
 *		GamingMasteR
 *
 */








#include "KeDetective.h"
#include "dll.h"
#include "module.h"
#include "fsd.h"
#include "process.h"


#define MI_CONVERT_FROM_PTE_PROTECTION(PROTECTION_MASK)      \
	(MmProtectToValue[PROTECTION_MASK])

ULONG MmProtectToValue[32] = {
	PAGE_NOACCESS,
	PAGE_READONLY,
	PAGE_EXECUTE,								// Execute
	PAGE_EXECUTE_READ,							// Execute
	PAGE_READWRITE,
	PAGE_WRITECOPY,
	PAGE_EXECUTE_READWRITE,						// Execute
	PAGE_EXECUTE_WRITECOPY,						// Execute
	PAGE_NOACCESS,
	PAGE_NOCACHE | PAGE_READONLY,
	PAGE_NOCACHE | PAGE_EXECUTE,				// Execute
	PAGE_NOCACHE | PAGE_EXECUTE_READ,			// Execute
	PAGE_NOCACHE | PAGE_READWRITE,
	PAGE_NOCACHE | PAGE_WRITECOPY,
	PAGE_NOCACHE | PAGE_EXECUTE_READWRITE,		// Execute
	PAGE_NOCACHE | PAGE_EXECUTE_WRITECOPY,		// Execute
	PAGE_NOACCESS,
	PAGE_GUARD | PAGE_READONLY,
	PAGE_GUARD | PAGE_EXECUTE,					// Execute
	PAGE_GUARD | PAGE_EXECUTE_READ,				// Execute
	PAGE_GUARD | PAGE_READWRITE,
	PAGE_GUARD | PAGE_WRITECOPY,
	PAGE_GUARD | PAGE_EXECUTE_READWRITE,		// Execute
	PAGE_GUARD | PAGE_EXECUTE_WRITECOPY,		// Execute
	PAGE_NOACCESS,
	PAGE_WRITECOMBINE | PAGE_READONLY,
	PAGE_WRITECOMBINE | PAGE_EXECUTE,			// Execute
	PAGE_WRITECOMBINE | PAGE_EXECUTE_READ,		// Execute
	PAGE_WRITECOMBINE | PAGE_READWRITE,
	PAGE_WRITECOMBINE | PAGE_WRITECOPY,
	PAGE_WRITECOMBINE | PAGE_EXECUTE_READWRITE,	// Execute
	PAGE_WRITECOMBINE | PAGE_EXECUTE_WRITECOPY	// Execute
};


VOID XpParseVadTree(PMMVAD Vad, PDLL_ENTRY &InfoBlock, ULONG &Count, PWCHAR FileName)
{
	if (Vad != NULL)
	{
		if (Vad->ControlArea)
		{
			if (Vad->VadFlags.ImageMap)
			{
				ULONG Protection = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
				if (Protection & MI_CONVERT_FROM_PTE_PROTECTION(Vad->VadFlags.Protection))
				{
					if (MmIsAddressValid(Vad->ControlArea->FilePointer) || Vad->ControlArea->FilePointer == NULL)
					{
						InfoBlock = (PDLL_ENTRY)MmRealloc(InfoBlock, (Count + 1)*sizeof(DLL_ENTRY));
						if (InfoBlock)
						{
							InfoBlock[Count].BaseAddress = (PVOID)(Vad->StartingVpn << 12);
							InfoBlock[Count].EntryPoint  = NULL;
							InfoBlock[Count].SizeOfImage = (Vad->EndingVpn - Vad->StartingVpn + 1) << 12;
							RtlZeroMemory(FileName, 0x200);
                            if (!GetFileName(Vad->ControlArea->FilePointer, FileName, MAX_PATH))
							{
								wcsncpy(FileName, L"unknown module name", MAX_PATH);
							}
							wcsncpy(InfoBlock[Count].FullDllName, FileName, MAX_PATH);
							Count++;
						}
					}
				}
			}
		}
		XpParseVadTree(Vad->LeftChild, InfoBlock, Count, FileName);
		XpParseVadTree(Vad->RightChild, InfoBlock, Count, FileName);
	}
}


VOID VistaParseVadTree(PMMVAD_VISTA Vad, PDLL_ENTRY &InfoBlock, ULONG &Count, PWCHAR FileName)
{
	if (Vad != NULL)
	{
		if (!Vad->VadFlags.PrivateMemory)
		{
			if (MmIsAddressValid(Vad->Section))
			{
				if (MmIsAddressValid(Vad->Section->ControlArea))
				{
					PFILE_OBJECT FileObject = (PFILE_OBJECT)((ULONG)Vad->Section->ControlArea->FilePointer & 0xfffffff8);
					if (MmIsAddressValid(FileObject))
					{
						ULONG Protection = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
						if (Protection & MI_CONVERT_FROM_PTE_PROTECTION(Vad->VadFlags.Protection))
						{
							RtlZeroMemory(FileName, 0x200);
							if (GetFileName(FileObject, FileName, MAX_PATH))
							{
								InfoBlock = (PDLL_ENTRY)MmRealloc(InfoBlock, (Count + 1)*sizeof(DLL_ENTRY));
								if (InfoBlock)
								{
									InfoBlock[Count].BaseAddress = (PVOID)(Vad->StartingVpn << 12);
									InfoBlock[Count].EntryPoint  = NULL;
									InfoBlock[Count].SizeOfImage = (Vad->EndingVpn - Vad->StartingVpn + 1) << 12;
									wcsncpy(InfoBlock[Count].FullDllName, FileName, MAX_PATH);
									Count++;
								}
							}
						}
					}
				}
			}
		}
		VistaParseVadTree(Vad->LeftChild, InfoBlock, Count, FileName);
		VistaParseVadTree(Vad->RightChild, InfoBlock, Count, FileName);
	}
}


BOOLEAN IsDllFound(PDLL_ENTRY InfoBlock, PLDR_DATA_TABLE_ENTRY Ldr)
{
    if (InfoBlock != NULL)
    {
	    for	(ULONG c = 0; c < MmGetSize(InfoBlock)/sizeof(PVOID); ++c) 
	    {
		    if (InfoBlock[c].BaseAddress == Ldr->DllBase) 
		    {
			    if (Ldr->EntryPoint)
				    InfoBlock[c].EntryPoint = Ldr->EntryPoint;
			    else
				    InfoBlock[c].EntryPoint = Ldr->DllBase;
			    return TRUE;
		    }
	    }
    }
	return FALSE;
}

NTSTATUS 
HackDLL(
	PEPROCESS eProcess, 
	PDLL_ENTRY* lpBase,
    PULONG lpCount
	)
{
	PPEB_LDR_DATA lpLoader;
	PLIST_ENTRY Next;
	PLDR_DATA_TABLE_ENTRY LdrDataTableEntry;
	KAPC_STATE ApcState;
	PDLL_ENTRY lpInfo = 0;
	NTSTATUS NtStatus = STATUS_SUCCESS;
	PVOID BaseAddress;
	SIZE_T RegionSize; 
	ULONG Count = 0;
	BOOLEAN Attached = FALSE;
	PWCHAR FileName;


	VMProtectBegin;

    FileName = (PWCHAR)MmAlloc((MAX_PATH * sizeof(WCHAR)) + 32);
    *lpCount = 0;
	if (BAD_PROCESS_STATUS(eProcess))
		return STATUS_UNSUCCESSFUL;
	__try
	{
		__try
		{
			//
			// Scan vad tree
			//
			if (IsXp)
				XpParseVadTree((PMMVAD)eProcess->VadRoot, lpInfo, Count, FileName);
			else
			{
				if (IsVista)
					VistaParseVadTree((PMMVAD_VISTA)((ULONG_PTR)eProcess + 0x238), lpInfo, Count, FileName);
				else if (IsWin7)
					VistaParseVadTree((PMMVAD_VISTA)((ULONG_PTR)eProcess + 0x278), lpInfo, Count, FileName);
			}

			if (PsGetProcessPeb(eProcess))
			{
				KdStackAttachProcess((PKPROCESS)eProcess, &ApcState);
				Attached = TRUE;
				ProbeForRead(PsGetProcessPeb(eProcess), sizeof(PEB), sizeof(ULONG));
				ProbeForRead(PsGetProcessPeb(eProcess)->LoaderData, sizeof(PEB_LDR_DATA), sizeof(ULONG));
				lpLoader = PsGetProcessPeb(eProcess)->LoaderData;
				
				//
				// Scan InMemoryOrderModuleList
				//
				Next = lpLoader->InMemoryOrderModuleList.Flink;
				while (Next != &lpLoader->InMemoryOrderModuleList)
				{
					LdrDataTableEntry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList);
					if (!IsDllFound(lpInfo, LdrDataTableEntry))
					{
						lpInfo = (PDLL_ENTRY)MmRealloc(lpInfo, (Count + 1)*sizeof(DLL_ENTRY));
						if (lpInfo)
						{
							lpInfo[Count].BaseAddress = LdrDataTableEntry->DllBase;
							lpInfo[Count].EntryPoint  = LdrDataTableEntry->EntryPoint;
							lpInfo[Count].SizeOfImage = LdrDataTableEntry->SizeOfImage;
							CopyUnicodeStringFile(lpInfo[Count].FullDllName, &LdrDataTableEntry->FullDllName, COF(lpInfo[Count].FullDllName));
							Count++;
						}
					}
					Next = Next->Flink;
				}
			}
		}
		__finally
		{
			if (Attached)
				KdUnstackDetachProcess(&ApcState);
			*lpBase = 0;
			if (lpInfo)
			{
                *lpCount = Count;
				RegionSize = Count*sizeof(DLL_ENTRY);
				BaseAddress = 0;
				NtStatus = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
				if (NtStatus == STATUS_SUCCESS)
				{
					*lpBase = (PDLL_ENTRY)BaseAddress;
					memcpy(BaseAddress, lpInfo, Count*sizeof(DLL_ENTRY));
				}
				MmFree(lpInfo);
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		Print("sss");
		NtStatus = STATUS_UNSUCCESSFUL;
	}

    MmFree(FileName);
	VMProtectEnd;

	return NtStatus ;
};