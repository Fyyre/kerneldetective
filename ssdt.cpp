/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		ssdt.c
 *
 * Abstract:
 *
 *		This module implements various routines used to deal with SSDT.
 *
 * Author:
 *
 *		GamingMasteR
 *
 */








#include "KeDetective.h"
#include "ssdt.h"
#include "module.h"


PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTableShadow;
PSERVICE_DESCRIPTOR_TABLE KdServiceDescriptorTable;

PSDT_ENTRY
HackSSDT(
	PVOID* lpBuffer
	)
{
	VMProtectBegin;

	NTSTATUS			NtStatus = STATUS_SUCCESS;
	unsigned int		ServiceID = 0;
	PSDT_ENTRY		result = 0;
	PVOID				BaseAddress;
	SIZE_T				RegionSize;
	
	UpdateModulesList();
	result = (PSDT_ENTRY)MmAlloc(KdServiceDescriptorTable->TableSize * sizeof(SDT_ENTRY));
	if ( result )
	{
		for ( ServiceID = 0; ServiceID < KdServiceDescriptorTable->TableSize; ServiceID++ )
		{
			result[ServiceID].Index		= ServiceID;
			result[ServiceID].Current	= (ULONG)KdServiceDescriptorTable->ServiceTable[ServiceID];
			if ( ServiceID < info.Max_ServiceID )
			{
				result[ServiceID].Original	= (ULONG)info.SDT[ServiceID];
				if ( result[ServiceID].Current == result[ServiceID].Original )
					result[ServiceID].Status	= 0;
				else
					result[ServiceID].Status	= 1;
			}
			else
			{
				result[ServiceID].Original	= 0;
				result[ServiceID].Status	= 2;
			};
			ModuleFromAddress(KdServiceDescriptorTable->ServiceTable[ServiceID], FALSE, FALSE, result[ServiceID].Module, COF(result[ServiceID].Module));
		};
		RegionSize = KdServiceDescriptorTable->TableSize * sizeof(SDT_ENTRY);
		BaseAddress = 0;
		NtStatus = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
		if ( NtStatus == STATUS_SUCCESS )
		{
			*lpBuffer = BaseAddress;
			memcpy( BaseAddress, result, KdServiceDescriptorTable->TableSize * sizeof(SDT_ENTRY) );
		};
		MmFree( result );
	};

	VMProtectEnd;
	return result;
};


PVOID*
GetRealServiceTable(
	PVOID file,
	ULONG Size
	)
{
	PUCHAR			cPtr = (PUCHAR)file;
	PVOID			NtAddAtom = 0;
	PVOID			NtAdjustPrivilegesToken = 0;
	PVOID			NtAllocateLocallyUniqueId = 0;
	ULONG			p1,p2,p3;

	__try
	{
		NtAddAtom = GetSystemRoutineAddress(L"NtAddAtom");
		NtAdjustPrivilegesToken = GetSystemRoutineAddress(L"NtAdjustPrivilegesToken");
		NtAllocateLocallyUniqueId = GetSystemRoutineAddress(L"NtAllocateLocallyUniqueId");

		if (IsXp) {
			p1 = 8; p2 = 11; p3 = 14;
		} else if (IsVista || IsWin7) {
			p1 = 8; p2 = 12; p3 = 15;
		} else {
			return 0;
		};
		do
		{
			if (((*(PULONG)(cPtr+p1*sizeof(ULONG))) == (ULONG)NtAddAtom) &&
				((*(PULONG)(cPtr+p2*sizeof(ULONG))) == (ULONG)NtAdjustPrivilegesToken) &&
				((*(PULONG)(cPtr+p3*sizeof(ULONG))) == (ULONG)NtAllocateLocallyUniqueId))
				return (PVOID*)cPtr;
			cPtr++;
		} while (cPtr < (PUCHAR)file + Size - (info.Max_ServiceID*sizeof(ULONG)));
	}
	__except(1)
	{};

	return 0;
};


PSERVICE_DESCRIPTOR_TABLE
GetAddrssofServiceTable(
	)
{
	return (PSERVICE_DESCRIPTOR_TABLE)GetRealProcAddress(KernelBase, ntoskrnl, "KeServiceDescriptorTable");
};



PSERVICE_DESCRIPTOR_TABLE 
GetAddrssofShadowTable(
	)
{
    PSERVICE_DESCRIPTOR_TABLE ServiceDescriptorTableShadow;

	if (IsXp)
		ServiceDescriptorTableShadow = (PSERVICE_DESCRIPTOR_TABLE)((PCHAR)KdServiceDescriptorTable-0x40);
	else if (IsVista || IsWin7)
		ServiceDescriptorTableShadow = (PSERVICE_DESCRIPTOR_TABLE)((PCHAR)KdServiceDescriptorTable+0x40);
	return &ServiceDescriptorTableShadow[0];
};


PVOID*
GetRealShadowServiceTable( 
	PVOID file,
	PVOID Base,
	ULONG Size 
	)
{
	PCHAR			ptr = (PCHAR)file;
	ULONG			srv0 = 0, srv1 = 12, srv2 = 14, srv3 = 44;


	// Services' Index
	// 00 = NtGdiAbortDoc
	// 12 = NtGdiBeginPath
	// 14 = NtGdiCancelDC
	// 44 = NtGdiCreateSolidBrush


	if (IsVista)
		srv3 = 46;
	else if (IsWin7)
		srv3 = 47;

	__try
	{
		do
		{
            ULONG i;
            for (i = 0; i < info.Max_ShadowServiceID; i++)
            {
                if (((PULONG_PTR)ptr)[i] <= (ULONG_PTR)Base || ((PULONG_PTR)ptr)[i] >= (ULONG_PTR)Base + Size)
                {
                    break;
                }
            }
            if (i >= info.Max_ShadowServiceID - 1)
                return (PVOID *)ptr;
            ptr += sizeof(ULONG_PTR);
		}while (ptr < (PCHAR)file + Size - (info.Max_ShadowServiceID*sizeof(ULONG)));
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		Print("exception accured");
	}
	return 0;
}


PSDT_ENTRY
HackShadowSSDT( 
	PVOID* lpBuffer 
	)
{
	VMProtectBegin;

	NTSTATUS			NtStatus = STATUS_SUCCESS;
	unsigned int		ServiceID = 0;
	PSDT_ENTRY		result = 0;
	PVOID				BaseAddress;
	SIZE_T				RegionSize;
	
	UpdateModulesList();
	result = (PSDT_ENTRY)MmAlloc(KeServiceDescriptorTableShadow[1].TableSize * sizeof(SDT_ENTRY));
	if ( result )
	{
		for ( ServiceID = 0; ServiceID < KeServiceDescriptorTableShadow[1].TableSize; ServiceID++ )
		{
			result[ServiceID].Index		= ServiceID;
			result[ServiceID].Current	= (ULONG)KeServiceDescriptorTableShadow[1].ServiceTable[ServiceID];
			if (ServiceID < info.Max_ShadowServiceID)
			{
				result[ServiceID].Original	= (ULONG)info.ShadowSDT[ServiceID];
				if ( result[ServiceID].Current == result[ServiceID].Original )
					result[ServiceID].Status	= 0;
				else
					result[ServiceID].Status	= 1;
			}
			else
			{
				result[ServiceID].Original	= 0;
				result[ServiceID].Status	= 2;
			};
			ModuleFromAddress(KeServiceDescriptorTableShadow[1].ServiceTable[ServiceID], FALSE, FALSE, result[ServiceID].Module, COF(result[ServiceID].Module));
		};
		RegionSize = KeServiceDescriptorTableShadow[1].TableSize * sizeof(SDT_ENTRY);
		BaseAddress = 0;
		NtStatus = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
		if ( NtStatus == STATUS_SUCCESS )
		{
			*lpBuffer = BaseAddress;
			memcpy( BaseAddress, result, KeServiceDescriptorTableShadow[1].TableSize * sizeof(SDT_ENTRY) );
		};
		MmFree( result );
	};

	VMProtectEnd;
	return result;
};