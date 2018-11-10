/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		unhook.c
 *
 * Abstract:
 *
 *		This module implements various routines used to detect code hooks .
 *
 * Author:
 *
 *		GamingMasteR
 *
 */








#include "KeDetective.h"
#include "unhook.h"
#include "fsd.h"
#include "module.h"


#define	IsDataDirectory(ID)	offset >= nt->OptionalHeader.DataDirectory[ID].VirtualAddress && \
		offset < nt->OptionalHeader.DataDirectory[ID].VirtualAddress + nt->OptionalHeader.DataDirectory[ID].Size





PHOOK_ENTRY
AddBlock(
	PHOOK_ENTRY HookInfo,
	ULONG &Count,
	ULONG cb,
	ULONG Base,
	ULONG File,
	ULONG rva,
	ULONG state,
	ULONG param1,
	ULONG param2
	)
{
	HookInfo = (PHOOK_ENTRY)MmRealloc(HookInfo, (Count + 1) * sizeof(HOOK_ENTRY));
	if (HookInfo)
	{
		HookInfo[Count].ImageBase = Base;
		HookInfo[Count].Rva = rva;
		HookInfo[Count].Size = cb;
		HookInfo[Count].State = state;
		HookInfo[Count].Parameter1 = param1;
		HookInfo[Count].Parameter2 = param2;
		memcpy(HookInfo[Count].Current, (PVOID)(rva+Base), (cb>64)?64:cb);
		memcpy(HookInfo[Count].Origin, (PVOID)(rva+File), (cb>64)?64:cb);
		++Count;
	};
	return HookInfo;
};


#define KRNL_SCAN_SECTIONS		1L
#define KRNL_SCAN_IAT			2L
#define KRNL_SCAN_EAT			4L



SIZE_T FixCodeSize(PUCHAR BytePtr, SIZE_T Length)
{
    SIZE_T CmdSize = 0, TotalCmdSize = 0;
    PUCHAR OpCode;

    if (MmIsAddressValid(BytePtr))
    {
        ULONG_PTR Offset = min(16, BYTE_OFFSET(BytePtr));
        if (MmIsAddressValid(BytePtr - Offset))
        {
            while (TotalCmdSize + CmdSize <= Offset)
            {
                TotalCmdSize += CmdSize;
                CmdSize = SizeOfCode(BytePtr - Offset + TotalCmdSize, &OpCode);
            }
            return (Offset - TotalCmdSize);
        }
    }
    return 0;
}


ULONG
ScanModule(
	PHOOK_ENTRY *lpBuffer,
	ULONG file,
	ULONG Base,
	ULONG Flags
	)
{
	ULONG			i = 0;
	ULONG			offset = 0;
	ULONG			Len = 0;
	PHOOK_ENTRY	lpHook = 0;
	ULONG			delta = file - Base;
	char			kernelimage[MAX_PATH] = "";
	ULONG_PTR BasePtr = 0;
	ULONG_PTR FilePtr = 0;
	ULONG Count = 0;

	
	
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)
		(file + ((PIMAGE_DOS_HEADER)file)->e_lfanew);
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
	ULONG size;

	PIMAGE_IMPORT_DESCRIPTOR pImpDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)
		RtlImageDirectoryEntryToData((PVOID)file, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
	
	PIMAGE_EXPORT_DIRECTORY pExpDescriptor = (PIMAGE_EXPORT_DIRECTORY)
		RtlImageDirectoryEntryToData((PVOID)file, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);
	
	sprintf(kernelimage, "%ls", CurrentKernel);
	// Check for EAT hooks
	if (Flags & KRNL_SCAN_EAT && pExpDescriptor != 0)
	{
		PULONG ExRFunctions =(PULONG)(file + pExpDescriptor->AddressOfFunctions);
		PULONG ExCFunctions =(PULONG)(Base + pExpDescriptor->AddressOfFunctions);
		PSHORT ExpOrdinals  =(PSHORT)(file + pExpDescriptor->AddressOfNameOrdinals);
		for (i = 0; i < pExpDescriptor->NumberOfFunctions; i++)
		{
		    ULONG ord = ExpOrdinals[i];
			if (ExRFunctions[ord] != ExCFunctions[ord])
			{
				ULONG lparam		= ExRFunctions[ord] + Base;
				ULONG destination	= ExCFunctions[ord] + Base;
				lpHook = AddBlock(lpHook, Count, 4, Base, file, (ULONG)&ExRFunctions[ord] - file, 8, lparam, destination);
			};
		};
	};

	// Check for IAT hooks
	if (Flags & KRNL_SCAN_IAT  && pImpDescriptor != 0)
	{
		while (pImpDescriptor->Name)
		{
			ULONG pThunks = (ULONG)file;
			PIMAGE_THUNK_DATA pData;
			PULONG pFunctions;
			LPSTR ModName = (LPSTR)(pImpDescriptor->Name + file);
			if (0 == _strnicmp(ModName, "ntoskrnl", sizeof("ntoskrnl")-1))
				ModName = kernelimage;
			{
				PVOID imp_base = GetModuleHandle(ModName);
				PVOID ifile = LoadSystemFile(ModName, imp_base, FALSE);
				if (ifile)
				{
					if (pImpDescriptor->OriginalFirstThunk != pImpDescriptor->FirstThunk)
						pThunks += pImpDescriptor->OriginalFirstThunk;
					else
						pThunks += pImpDescriptor->FirstThunk;

					pFunctions = (PULONG)pImpDescriptor->FirstThunk;
					pData = (PIMAGE_THUNK_DATA)pThunks;
					while (pData->u1.AddressOfData)
					{
						if (MmIsAddressValid((PVOID)((ULONG)pFunctions+(ULONG)Base))&&
							MmIsAddressValid((PVOID)((ULONG)pFunctions+(ULONG)file)))
						{
							ULONG lparam		= *(PULONG)((ULONG)pFunctions + file);
							ULONG destination	= *(PULONG)((ULONG)pFunctions + Base);
							if (destination != lparam)
							{
								lpHook = AddBlock(lpHook, Count, 4, Base, file, (ULONG)pFunctions, 7, lparam, destination);
							};
						};
						pData++;
						pFunctions++;
					};
					MmFree(ifile);
				};
				pImpDescriptor++;
			};
		};
	};
	if (Flags & KRNL_SCAN_SECTIONS)
    {
		ULONG sec_attr_inc = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE ;
		ULONG sec_attr_exc = IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_LNK_NRELOC_OVFL |
			IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA ;
        KAPC_STATE ApcState;

        KdStackAttachProcess(&CsrProcess->Pcb, &ApcState);
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
		{
            if ((sec[i].Characteristics & sec_attr_inc) == 0) continue;
			if ((sec[i].Characteristics & sec_attr_exc) != 0) continue;
			if (*(PULONGLONG)sec[i].Name == 0x5946525645474150) continue; //PAGEVRFY
			if (*(PULONGLONG)sec[i].Name == 0x4345505345474150) continue; //PAGESPEC
			if (*(PULONGLONG)sec[i].Name == 0x0000444B45474150) continue; //PAGEKD

            if (!MmIsAddressValid((PVOID)(sec[i].VirtualAddress+file)))
                continue;
			

			ULONG ByteIndex = 0;
			for (offset = sec[i].VirtualAddress;
				ByteIndex < sec[i].Misc.VirtualSize;
				offset += Len + 1, ByteIndex += Len + 1)
			{
				ULONG_PTR BasePtr = ByteIndex + Base + sec[i].VirtualAddress;
				ULONG_PTR FilePtr = offset + file;

				// skip ssdt
				if ((BasePtr >= (ULONG)info.SDT - KernelDelta) && (BasePtr < (ULONG)info.SDT - KernelDelta + info.Max_ServiceID*sizeof(ULONG)))	
					continue;
				
				// skip shadow ssdt
				if ((BasePtr >= (ULONG)info.ShadowSDT - w32kDelta) && (BasePtr < (ULONG)info.ShadowSDT - w32kDelta + info.Max_ShadowServiceID*sizeof(ULONG)))	
					continue;

                if (!MmIsAddressValid((PVOID)BasePtr))
                {
                    continue;
                }

				for (Len = 0; Len + ByteIndex < sec[i].Misc.VirtualSize; ++Len) 
                {
                    if (*(PUCHAR)(BasePtr + Len) == *(PUCHAR)(FilePtr + Len))
					    break;
				}
				if (Len)
				{
                    ULONG CmdSizeFix = FixCodeSize((PUCHAR)BasePtr, Len);
                    if (CmdSizeFix)
                    {
                        Len += CmdSizeFix; ByteIndex -= CmdSizeFix; offset -= CmdSizeFix;
                        BasePtr -= CmdSizeFix; FilePtr -= CmdSizeFix;
                    }

                    ULONG destination = 0;
					ULONG Status = AnalyzeHook((PUCHAR)BasePtr, (PUCHAR)FilePtr, Len, &destination);
					lpHook = AddBlock(lpHook, Count, Len, Base, file, offset, Status, destination, destination);
				}
			}
		}
        KdUnstackDetachProcess(&ApcState);
	}
	*lpBuffer = lpHook;
	
    return (Count * sizeof(HOOK_ENTRY)) ;
}


ULONG
AnalyzeHook(
	PUCHAR Current, 
	PUCHAR Origin,
	ULONG cb, 
	ULONG *Destination
	)
{

	*Destination = 0;
	__try
	{
        for (ULONG i = 0; i < cb; i++)
        {
            if (Current[i] != 0x90)
                break;
            Current++; Origin++;
        }
		switch (*Current)
		{
		case	0xE9:				// relative jump
			*Destination = *(ULONG*)(Current+1) + (ULONG)Current + 5;
			return 1;
		case	0xEA:				// far jump
			*Destination = *(ULONG*)(Current+1);
			return 2;
		case	0xE8:				// relative call
			*Destination = *(ULONG*)(Current+1) + (ULONG)Current + 5;
			return 3;
		case	0x9A:				// far call
			*Destination = *(ULONG*)(Current+1);
			return 4;
		}

		switch (*(PUSHORT)Current)
		{
		case	0x25FF:				// direct jump
			if (MmIsAddressValid((PVOID)(*(ULONG*)(Current+2))))
				*Destination = *(ULONG*)(*(ULONG*)(Current+2));
			return 5;
		case	0x15FF:				// direct call
			if (MmIsAddressValid((PVOID)(*(ULONG*)(Current+2))))
				*Destination = *(ULONG*)(*(ULONG*)(Current+2));
			return 6;
		}
	}
	__except(1)
	{
		Print("error analyzing");
	}
	return 0;					// code modification
}


VOID
UnhookCode(
	PVOID Address,
	ULONG cb
	)
{
	WCHAR Path[MAX_PATH];
	CHAR AnsiPath[MAX_PATH];
	PVOID BaseAddress, DiskImage;


	ModuleFromAddress((PVOID)Address, FALSE, FALSE, Path, COF(Path));
	Print("%s", Path);
	if (Path[0] != '-' && Path[0] != '\0') 
	{
		BaseAddress = GetModuleHandleW(wExtractFileName(Path));
		Print("%p", BaseAddress);
		if (BaseAddress) 
		{
			_snprintf(AnsiPath, MAX_PATH, "%ls", Path);
			DiskImage = LoadSystemFile(AnsiPath, BaseAddress, TRUE);
			Print("%p", DiskImage);
			if (DiskImage) 
			{
				KiWriteProcessMemory(CsrProcess, (PVOID)Address, (PCHAR)Address - (ULONG_PTR)BaseAddress + (ULONG_PTR)DiskImage, cb, 0);
				MmFree(DiskImage);
			};
		};
	};
}