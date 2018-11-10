/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		module.c
 *
 * Abstract:
 *
 *		This module implements various routines used to deal with kernel-mode drivers.
 *
 * Author:
 *
 *		GamingMasteR
 *
 */


#include "KeDetective.h"
#include "module.h"


PLIST_ENTRY PsLoadedModuleList;
PLIST_ENTRY MmLoadedUserImageList;
CDriver *gDrivers;

/*
\Filesystem\Raw
\Driver\WMIxWDM
\Driver\PnpManager
\Driver\Win32k
\Driver\ACPI_HAL
*/


VOID WalkDirectory(POBJECT_DIRECTORY Directory, POBJECT_TYPE Type, PVOID **ObjectArray)
{
	ULONG Bucket;
	POBJECT_DIRECTORY_ENTRY DirectoryEntry;
	POBJECT_DIRECTORY_ENTRY DirectoryEntryNext;
	PVOID Object;
	POBJECT_HEADER ObjectHeader;
	POBJECT_TYPE ObjectType, ObRootType;

    ObRootType = TypeFromObject(OBJECT_TO_OBJECT_HEADER(Directory));
    if (MmIsAddressValid(ObRootType))
    {
	    for(Bucket = 0; Bucket < NUMBER_HASH_BUCKETS; Bucket++)
	    {
		    DirectoryEntry = DirectoryEntryNext = Directory->HashBuckets[Bucket];
		    while (MmIsAddressValid(DirectoryEntryNext))
		    {
			    Object = DirectoryEntryNext->Object;
                if (MmIsAddressValid(Object))
                {
			        ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
			        ObjectType = TypeFromObject(ObjectHeader);
			        if (ObjectType == Type || ObjectType == NULL)
			        {
				        ULONG Index = MmGetSize((*ObjectArray))/sizeof(PVOID);
				        (*ObjectArray) = (PVOID *)MmRealloc((*ObjectArray), (Index + 1) * sizeof(PVOID));
				        (*ObjectArray)[Index] = Object;
			        }
			        else if (ObjectType == ObRootType)
			        {
				        WalkDirectory((POBJECT_DIRECTORY)Object, Type, ObjectArray);
			        }
                }
			    DirectoryEntryNext = DirectoryEntryNext->ChainLink;
		    }
	    }
    }
}


VOID
GetModuleRange(
	PVOID* Base,
	ULONG* Size,
	PCWSTR FileName
	)
{
	VMProtectBegin;
	ULONG c;
	CDriver Driver;
	PDRIVER_ENTRY DriverInfo;

	*Base = 0;
	*Size = 0;
	Driver.Scan();
    DriverInfo = (PDRIVER_ENTRY)MmAlloc(sizeof(DRIVER_ENTRY));
	for (c = 0; c < Driver.DriverCount; ++c) 
    {
		GetDriverInfo(&Driver.Objects[c], DriverInfo);
		if (_wcsicmp(wExtractFileName(DriverInfo->ImagePath), FileName) == 0) 
        {
			*Base = DriverInfo->ImageBase;
			*Size = DriverInfo->ImageSize;
            MmFree(DriverInfo);
			return;
		}
	}
    MmFree(DriverInfo);
	VMProtectEnd;
}


PVOID
GetModuleHandle(
	LPSTR lpModuleName
	)
{
	PVOID rc;
	ULONG sz;
	WCHAR UnicodeString[MAX_PATH] = L"";

	if (STATUS_SUCCESS != RtlMultiByteToUnicodeN(UnicodeString, MAX_PATH, 0, lpModuleName, MAX_PATH))
		return 0;
	GetModuleRange(&rc, &sz, UnicodeString);
	return rc;
};


PVOID GetModuleHandleW(PWCHAR lpModuleName)
{
	PVOID rc;
	ULONG sz;

	GetModuleRange(&rc, &sz, lpModuleName);
	return rc;
};


PWCHAR
ModuleFromAddress(
	PVOID Addr,
	BOOL GetSymbol,
	BOOL GetExport,
    PWCHAR Module,
    SIZE_T Size
	)
{
	ULONG disp = 0;
	WCHAR temp[MAX_PATH] = L"";
	ULONG c;
	PDRIVER_ENTRY DriverInfo;

    DriverInfo = (PDRIVER_ENTRY)MmAlloc(sizeof(DRIVER_ENTRY));
	wcscpy(Module, L"-");
	for (c = 0; c < gDrivers->DriverCount; ++c)
	{
		GetDriverInfo(&gDrivers->Objects[c], DriverInfo);
		if ((Addr >= DriverInfo->ImageBase) && (Addr < (PCHAR)DriverInfo->ImageBase + DriverInfo->ImageSize)) 
		{
			__try
			{
				wcsncpy(Module, DriverInfo->ImagePath, Size);
				if (GetSymbol)
				{
					PIMAGE_SECTION_HEADER sec = ImageVaToSection(DriverInfo->ImageBase, (ULONG)Addr);
                    if (sec)
					    _snwprintf(temp, 256, L" [%.8S]", sec->Name[0] ? (PCHAR)sec->Name : "~");
                    else
                        wcscpy(temp, L" [MZ]");
					wcsncat(Module, temp, Size);
					if (GetExport) 
					{
						PCHAR Exp = GetAddressProc(DriverInfo->ImageBase, Addr);
						if (MmIsAddressValid(Exp))
						{
							_snwprintf(Module, Size, L"%S", Exp);
						} 
						else 
						{
							wcscpy(Module, L"-");
						}
					}
				}
				break;
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				break;
			}
		}
	}

    MmFree(DriverInfo);
	return Module;
}


VOID GetDriverInfo(PCDRIVER_OBJECT DriverObject, PDRIVER_ENTRY lpBuffer)
{
	lpBuffer->EntryPoint	= DriverObject->EntryPoint;
    lpBuffer->Unload		= DriverObject->Unload;
    lpBuffer->DriverObject	= DriverObject->DriverObject;
    lpBuffer->ImageBase		= DriverObject->ImageBase;
    lpBuffer->ImageSize		= DriverObject->ImageSize;
    if (MmIsAddressValid(DriverObject->ImagePath.Buffer) && DriverObject->ImagePath.Buffer[0])
    {
        CopyUnicodeStringFile(lpBuffer->ImagePath, &DriverObject->ImagePath, COF(lpBuffer->ImagePath));
    }
    else
    {
        wcsncpy(lpBuffer->ImagePath, L"- unknown hidden module -", COF(lpBuffer->ImagePath));
    }
}


BOOLEAN
IsValidDriverObject(
	PDRIVER_OBJECT Driver
	)
{
	__try
	{
		if (!MmIsAddressValid(Driver) || !MmIsAddressValid(OBJECT_TO_OBJECT_HEADER(Driver)))
			return 0;

		if (Driver->Type != KdDriverObject->Type || Driver->Size != KdDriverObject->Size)
			return FALSE;
		
		//if (TypeFromObject(OBJECT_TO_OBJECT_HEADER(Driver)) != *IoDriverObjectType)
		//	return 0;

		if (!Driver->DriverSize)
			return FALSE;

		if (Driver->DriverExtension)
		{
			if (!MmIsAddressValid(Driver->DriverExtension))
				return FALSE;
		}

		if (Driver->DriverStart < MM_SYSTEM_RANGE_START)
			return 0;

		if (!MmIsAddressValid(Driver->DriverStart))
			return 0;

		if (Driver->DriverSection)
		{
			if (Driver->DriverSection < MM_SYSTEM_RANGE_START)
				return 0;
			if (!MmIsAddressValid(Driver->DriverSection))
				return 0;
		}

		if (Driver->DriverInit < MM_SYSTEM_RANGE_START)
			return 0;

		if (Driver->DriverName.Buffer < MM_SYSTEM_RANGE_START)
			return 0;

		if (!MmIsAddressValid(Driver->DriverName.Buffer))
			return 0;

		for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		{
			if (Driver->MajorFunction[i] < MM_SYSTEM_RANGE_START)
				return 0;

			if (!MmIsAddressValid(Driver->MajorFunction[i]))
				return 0;
		};
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}


	return TRUE;
};

/*
BOOLEAN IsValidDeviceObject(PDEVICE_OBJECT Device)
{

	__try
	{
		if (!MmIsAddressValid(Device))
			return FALSE;

		if (Device->Size > 0x200)
			return FALSE;

		if (!Device->DriverObject || !MmIsAddressValid(Device->DriverObject))
			return FALSE;

		//if (!IsValidDriverObject(Device->DriverObject))
		//	return FALSE;

		if (Device->Type != KdDriverObject->DeviceObject->Type)
			return FALSE;

		if (Device->SectorSize != KdDriverObject->DeviceObject->SectorSize)
			return FALSE;

		if (Device->DeviceExtension && !MmIsAddressValid(Device->DeviceExtension))
			return FALSE;

		if (Device->DeviceObjectExtension && !MmIsAddressValid(Device->DeviceObjectExtension))
			return FALSE;

		if (Device->DeviceObjectExtension && Device->DeviceObjectExtension->DeviceObject != Device)
			return FALSE;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}

	return TRUE;
};
*/

VOID CDriver::ScanPhysicalMemory()
{
	PCHAR Offset;
	ULONG DrvMaxPage, MaxPage, Increase;
	PDRIVER_OBJECT DriverObject;
	//PDEVICE_OBJECT DeviceObject;
	DispatchLock Lock;
	PCHAR StartOffset, EndOffset;

	StartOffset = *(PCHAR *)KdVersionBlock->MmNonPagedPoolStart;
	EndOffset = (PCHAR)(((ULONG)StartOffset & 0xf0000000) | 0x0f000000);

	//Lock.Lock();
	for (Offset = StartOffset; Offset <= EndOffset; Offset += PAGE_SIZE) 
	{
		if (IsValidSystemAddress(Offset)) 
		{
			PMDL Mdl = MmCreateMdl(NULL, Offset, PAGE_SIZE);
			if (Mdl)
			{
				MmBuildMdlForNonPagedPool(Mdl);
				Mdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
				PVOID MdlSystemAddress = MmMapLockedPages(Mdl, KernelMode);
				if (MdlSystemAddress)
				{
					DriverObject = (PDRIVER_OBJECT)MdlSystemAddress;
					//DeviceObject = (PDEVICE_OBJECT)MdlSystemAddress;
					DrvMaxPage = ((PAGE_SIZE - sizeof(DRIVER_OBJECT) - sizeof(OBJECT_HEADER)) / 8);
					//DevMaxPage = ((PAGE_SIZE - sizeof(DEVICE_OBJECT) - sizeof(OBJECT_HEADER)) / 8);
					MaxPage = DrvMaxPage;
					for (ULONG i = 0; i < MaxPage; )
					{
						if (IsValidDriverObject(DriverObject))
						{
							PDRIVER_OBJECT RealDriverObject = (PDRIVER_OBJECT)((PCHAR)DriverObject - (PCHAR)MdlSystemAddress + Offset);
							this->GrabDriver(RealDriverObject);
                            this->GrabDriver((PKLDR_DATA_TABLE_ENTRY)RealDriverObject->DriverSection);
							Increase = (sizeof(DRIVER_OBJECT) + sizeof(OBJECT_HEADER));
							i += (sizeof(DRIVER_OBJECT) + sizeof(OBJECT_HEADER)) / 8;
						}
						//else if (IsValidDeviceObject(DeviceObject))
						//{
						//	PDRIVER_OBJECT dObj = DeviceObject->DriverObject;
						//	if (MmIsAddressValid(dObj))
						//		this->GrabDriver((PKLDR_DATA_TABLE_ENTRY)dObj->DriverSection, DeviceObject->DriverObject);
						//	Increase = (sizeof(DEVICE_OBJECT) + sizeof(OBJECT_HEADER));
						//	i += (sizeof(DEVICE_OBJECT) + sizeof(OBJECT_HEADER)) / 8;
						//}
						else
						{
							Increase = 8;
							i ++;
						}
						*(PULONG_PTR)&DriverObject += Increase;
						//*(PULONG_PTR)&DeviceObject += Increase;
						if ((ULONG_PTR)DriverObject >= (ULONG_PTR)MdlSystemAddress + (MaxPage * 8))
							break;
					}
					MmUnmapLockedPages(MdlSystemAddress, Mdl);
				}
				IoFreeMdl(Mdl);
			}
		}
	}
	//Lock.Unlock();
};


VOID CDriver::ScanModuleList()
{
	PKLDR_DATA_TABLE_ENTRY LdrDataTableEntry;
	PLIST_ENTRY Next;

	Next = PsLoadedModuleList->Flink;
	while (Next != PsLoadedModuleList)
    {
		if (!MmIsAddressValid(Next)) return;
		LdrDataTableEntry = CONTAINING_RECORD(Next, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if(!MmIsAddressValid(LdrDataTableEntry)) 
            break;
		this->GrabDriver(LdrDataTableEntry);
		Next = Next->Flink;
	}
}


VOID CDriver::ScanDriverType()
{
	POBJECT_TYPE ObjectType = *IoDriverObjectType;
	PLIST_ENTRY Next;
	PDRIVER_OBJECT driver;

	if (parseobject(ObjectType, ObjectListHead, LIST_ENTRY)->Blink == parseobject(ObjectType, ObjectListHead, LIST_ENTRY)->Flink) return;
	Next = parseobject(ObjectType, ObjectListHead, LIST_ENTRY)->Flink;
	while (Next != parseobject(ObjectType, ObjectListHead, LIST_ENTRY))
    {
		if (!MmIsAddressValid(Next))
            return;
		if (Next < MM_SYSTEM_RANGE_START)
            return;
		driver = (PDRIVER_OBJECT)((PCHAR)Next + 0x28);
		if (MmIsAddressValid(driver->DriverSection) || driver->DriverSection == NULL) 
        {
			this->GrabDriver(driver);
            this->GrabDriver((PKLDR_DATA_TABLE_ENTRY)driver->DriverSection);
		}
		Next = Next->Flink;
	}
}


VOID CDriver::ScanDeviceType()
{
	POBJECT_TYPE ObjectType = *IoDeviceObjectType;
	PLIST_ENTRY Next;
	PDEVICE_OBJECT device;

	if (parseobject(ObjectType, ObjectListHead, LIST_ENTRY)->Blink == parseobject(ObjectType, ObjectListHead, LIST_ENTRY)->Flink) 
        return;
	Next = parseobject(ObjectType, ObjectListHead, LIST_ENTRY)->Flink;
	while (Next != parseobject(ObjectType, ObjectListHead, LIST_ENTRY)) 
    {
		if (!MmIsAddressValid(Next))
            return;
		if (Next < MM_SYSTEM_RANGE_START)
            return;
		device = (PDEVICE_OBJECT)((PCHAR)Next + 0x28);
		if (MmIsAddressValid(device->DriverObject)) 
        {
			if (MmIsAddressValid(device->DriverObject->DriverSection)) 
            {
                this->GrabDriver(device->DriverObject);
                this->GrabDriver((PKLDR_DATA_TABLE_ENTRY)device->DriverObject->DriverSection);
			}
		}
		Next = Next->Flink;
	}
}


VOID CDriver::ScanDriverDirectory()
{
    POBJECT_DIRECTORY Directory = NULL;
	PDRIVER_OBJECT *Objects = NULL;
	ULONG ObjCount;
	
	
    Directory = *(POBJECT_DIRECTORY *)KdVersionBlock->ObpRootDirectoryObject;
    Print("Directory = %p", Directory);
    WalkDirectory(Directory, *IoDriverObjectType, (PVOID **)&Objects);
    if (Objects)
    {
        ObjCount = MmGetSize(Objects) / sizeof(PVOID);
        for(ULONG Index = 0; Index < ObjCount; Index++)
        {
            if (MmIsAddressValid(Objects[Index]))
            {
                if (MmIsAddressValid(Objects[Index]->DriverSection) || Objects[Index]->DriverSection == NULL) 
				{
				    this->GrabDriver(Objects[Index]);
                    this->GrabDriver((PKLDR_DATA_TABLE_ENTRY)Objects[Index]->DriverSection);
				}
            }
        }
        MmFree(Objects);
    }
}


VOID CDriver::ScanDeviceDirectory()
{
	POBJECT_DIRECTORY Directory = NULL;
	PDEVICE_OBJECT *Objects = NULL;
	ULONG ObjCount;
	
	
    Directory = *(POBJECT_DIRECTORY *)KdVersionBlock->ObpRootDirectoryObject;
    Print("Directory = %p", Directory);
    WalkDirectory(Directory, *IoDeviceObjectType, (PVOID **)&Objects);
    if (Objects)
    {
        ObjCount = MmGetSize(Objects) / sizeof(PVOID);
        for(ULONG Index = 0; Index < ObjCount; Index++)
        {
            if (MmIsAddressValid(Objects[Index]) && MmIsAddressValid(Objects[Index]->DriverObject))
            {
                if (MmIsAddressValid(Objects[Index]->DriverObject->DriverSection) || Objects[Index]->DriverObject->DriverSection == NULL) 
                {
                    this->GrabDriver(Objects[Index]->DriverObject);
                    this->GrabDriver((PKLDR_DATA_TABLE_ENTRY)Objects[Index]->DriverObject->DriverSection);
                }
            }
        }
        MmFree(Objects);
    }
}


VOID CDriver::GrabDriver(PDRIVER_OBJECT DriverObject)
{
    CDRIVER_OBJECT cdo;
    PKLDR_DATA_TABLE_ENTRY dte = NULL;

    if (DriverObject && MmIsAddressValid(DriverObject))
    {
        if (DriverObject->DriverSection && MmIsAddressValid(DriverObject->DriverSection))
        {
            dte = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
            if (MmIsAddressValid(dte->FullDllName.Buffer) && dte->FullDllName.Buffer[0])
            {
                cdo.ImagePath = dte->FullDllName;
            }
            else if (MmIsAddressValid(dte->BaseDllName.Buffer) && dte->BaseDllName.Buffer[0])
            {
                cdo.ImagePath = dte->BaseDllName;
            }
            else if (MmIsAddressValid(DriverObject->DriverName.Buffer) && DriverObject->DriverName.Buffer[0])
            {
                cdo.ImagePath = DriverObject->DriverName;
            }
            else
            {
                RtlInitUnicodeString(&cdo.ImagePath, L"- unknown hidden module -");
            }
            if (DriverObject->DriverInit)
                cdo.EntryPoint = DriverObject->DriverInit;
            else
                cdo.EntryPoint = dte->EntryPoint;

            if (DriverObject->DriverStart)
                cdo.ImageBase = DriverObject->DriverStart;
            else
                cdo.ImageBase = dte->DllBase;

            if (DriverObject->DriverSize)
                cdo.ImageSize = DriverObject->DriverSize;
            else
                cdo.ImageSize = dte->SizeOfImage;
        }
        else
        {
            if (MmIsAddressValid(DriverObject->DriverName.Buffer) && DriverObject->DriverName.Buffer[0])
            {
                cdo.ImagePath = DriverObject->DriverName;
            }
            else
            {
                RtlInitUnicodeString(&cdo.ImagePath, L"- unknown hidden module -");
            }
            cdo.EntryPoint = DriverObject->DriverInit;
            cdo.ImageBase = DriverObject->DriverStart;
            cdo.ImageSize = DriverObject->DriverSize;
        }
        cdo.LdrEntry = dte;
        cdo.DriverObject = DriverObject;
        cdo.Unload = DriverObject->DriverUnload;
    }
    else
    {
        return;
    }

	for (ULONG Index = 0; Index < this->DriverCount; Index++)
	{
        if (this->Objects[Index].DriverObject == cdo.DriverObject)
        {
            return;
        }

        /*if (cdo.LdrEntry && this->Objects[Index].LdrEntry == cdo.LdrEntry)
        {
            return;
        }*/
	}

	this->Objects = (PCDRIVER_OBJECT)MmRealloc(this->Objects, (this->DriverCount + 1) * sizeof(CDRIVER_OBJECT));
	if (this->Objects)
	{
		this->Objects[this->DriverCount] = cdo;
		this->DriverCount++;
	}
}


VOID CDriver::GrabDriver(PKLDR_DATA_TABLE_ENTRY LdrEntry)
{
    CDRIVER_OBJECT cdo;

    if (LdrEntry && MmIsAddressValid(LdrEntry))
    {
        if (MmIsAddressValid(LdrEntry->FullDllName.Buffer) && LdrEntry->FullDllName.Buffer[0])
        {
            cdo.ImagePath = LdrEntry->FullDllName;
        }
        else if (MmIsAddressValid(LdrEntry->BaseDllName.Buffer) && LdrEntry->BaseDllName.Buffer[0])
        {
            cdo.ImagePath = LdrEntry->BaseDllName;
        }
        else
        {
            RtlInitUnicodeString(&cdo.ImagePath, L"- unknown hidden module -");
        }
        cdo.LdrEntry = LdrEntry;
        cdo.DriverObject = NULL;
        cdo.EntryPoint = LdrEntry->EntryPoint;
        cdo.ImageBase = LdrEntry->DllBase;
        cdo.ImageSize = LdrEntry->SizeOfImage;
        cdo.Unload = NULL;
    }
    else
    {
        return;
    }

	for (ULONG Index = 0; Index < this->DriverCount; Index++)
	{
        if (cdo.LdrEntry && this->Objects[Index].LdrEntry == cdo.LdrEntry)
        {
            return;
        }
	}

    this->Objects = (PCDRIVER_OBJECT)MmRealloc(this->Objects, (this->DriverCount + 1) * sizeof(CDRIVER_OBJECT));
	if (this->Objects) 
	{
		this->Objects[this->DriverCount] = cdo;
		this->DriverCount++;
	}
}



PVOID
GetProcAddressW(
	PCHAR DllBase,
	PWCHAR RoutineName
)
{
	CHAR ansi[MAX_PATH] = "";
	wcstombs(ansi, RoutineName, MAX_PATH - 1);
	return GetProcAddress(DllBase, ansi);
};


PVOID
GetProcAddress(
	PVOID DllBase,
	PCHAR RoutineName
	)
{
	USHORT OrdinalNumber;
	PULONG NameTableBase;
	PUSHORT NameOrdinalTableBase;
	PULONG Addr;
	ULONG High;
	ULONG Low;
	ULONG Middle = 0;
	LONG Result;
	ULONG ExportSize;
	PVOID FunctionAddress;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory;

	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(
						  DllBase,
						  TRUE,
						  IMAGE_DIRECTORY_ENTRY_EXPORT,
						  &ExportSize
					  );

	if (ExportDirectory == NULL) 
	{
		return NULL;
	};


	//
	// Initialize the pointer to the array of RVA-based ansi export strings.
	//

	NameTableBase = (PULONG)((ULONG)DllBase + ExportDirectory->AddressOfNames);

	//
	// Initialize the pointer to the array of USHORT ordinal numbers.
	//

	NameOrdinalTableBase = (PUSHORT)((ULONG)DllBase + ExportDirectory->AddressOfNameOrdinals);

	//
	// Lookup the desired name in the name table using a binary search.
	//

	Low = 0;
	High = ExportDirectory->NumberOfNames - 1;

	while (High >= Low)
	{

		//
		// Compute the next probe index and compare the import name
		// with the export name entry.
		//

		Middle = (Low + High) >> 1;

		Result = strcmp(RoutineName,
						((PCHAR)DllBase + NameTableBase[Middle]));

		if (Result < 0)
		{
			High = Middle - 1;
		}
		else if (Result > 0)
		{
			Low = Middle + 1;
		}
		else
		{
			break;
		};
	};

	//
	// If the high index is less than the low index, then a matching
	// table entry was not found. Otherwise, get the ordinal number
	// from the ordinal table.
	//

	if (High < Low)
	{
		return NULL;
	};

	OrdinalNumber = NameOrdinalTableBase[Middle];

	//
	// If the OrdinalNumber is not within the Export Address Table,
	// then this image does not implement the function.  Return not found.
	//

	if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions)
	{
		return NULL;
	};

	//
	// Index into the array of RVA export addresses by ordinal number.
	//

	Addr = (PULONG)((ULONG)DllBase + ExportDirectory->AddressOfFunctions);

	FunctionAddress = (PVOID)((ULONG)DllBase + Addr[OrdinalNumber]);
	return FunctionAddress;
};



PCHAR
GetAddressProc(
	PVOID DllBase,
	PVOID RoutineAddress
	)
{
	USHORT OrdinalNumber;
	PULONG NameTableBase;
	PUSHORT NameOrdinalTableBase;
	PULONG Addr;
	ULONG High;
	ULONG Low;
	ULONG ExportSize;
	PVOID FunctionAddress;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory;

	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(
						  DllBase,
						  TRUE,
						  IMAGE_DIRECTORY_ENTRY_EXPORT,
						  &ExportSize
					  );


	if (ExportDirectory == NULL)
	{
		return NULL;
	};


	//
	// Initialize the pointer to the array of RVA-based ansi export strings.
	//

	NameTableBase = (PULONG)((ULONG)DllBase + ExportDirectory->AddressOfNames);

	//
	// Initialize the pointer to the array of USHORT ordinal numbers.
	//

	NameOrdinalTableBase = (PUSHORT)((ULONG)DllBase + ExportDirectory->AddressOfNameOrdinals);

	//
	// Lookup the desired name in the name table using a binary search.
	//

	Low = 0;
	High = ExportDirectory->NumberOfNames - 1;

	while (High >= Low)
	{

		OrdinalNumber = NameOrdinalTableBase[Low];

		//
		// If the OrdinalNumber is not within the Export Address Table,
		// then this image does not implement the function.  Return not found.
		//

		if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions)
		{
			return NULL;
		};

		//
		// Index into the array of RVA export addresses by ordinal number.
		//

		Addr = (PULONG)((ULONG)DllBase + ExportDirectory->AddressOfFunctions);

		FunctionAddress = (PVOID)((ULONG)DllBase + Addr[OrdinalNumber]);

		if (FunctionAddress == RoutineAddress)
		{
			return ((PCHAR)DllBase + NameTableBase[Low]);
		};

		Low += 1;
	};

	return NULL;
};



PVOID
KdGetSystemRoutineAddress(
	PCWSTR SystemRoutineName
)
{
	PVOID rc = GetProcAddressW((PCHAR)ntoskrnl, (PWCHAR)SystemRoutineName);
	if (!rc)
		rc = GetProcAddressW((PCHAR)KernelBase, (PWCHAR)SystemRoutineName);
	//Print("%S = %p", SystemRoutineName, rc);
	return (PVOID)rc;
};


PVOID
GetSystemRoutineAddress(
	PCWSTR SystemRoutineName
)
{
	return GetProcAddressW((PCHAR)KernelBase, (PWCHAR)SystemRoutineName);
}


PIMAGE_SECTION_HEADER RtlImageRvaToSection(PVOID Base, ULONG Rva)
{
    ULONG i;
    PIMAGE_SECTION_HEADER NtSection;
	PIMAGE_NT_HEADERS NtHeaders;

	NtHeaders = (PIMAGE_NT_HEADERS)RtlImageNtHeader(Base);
    NtSection = IMAGE_FIRST_SECTION( NtHeaders );
    for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) 
	{
		ULONG dwSize = NtSection->SizeOfRawData ? NtSection->SizeOfRawData : NtSection->Misc.VirtualSize;
		if (Rva >= NtSection->VirtualAddress && Rva < NtSection->VirtualAddress + dwSize) 
		{
            return NtSection;
		}
        ++NtSection;
	}

    return NULL;
}


PIMAGE_SECTION_HEADER
ImageVaToSection(
	PVOID Base,
	ULONG Va
)
{
	return RtlImageRvaToSection( Base, Va-(ULONG)Base );
};


PVOID
GetRealProcAddress(
	PVOID hModule,
	PVOID file,
	LPSTR lpProcName
)
{
	PVOID rc;

	if (!hModule || !file)
		return 0;
	rc = GetProcAddress((PCHAR)file, lpProcName);
	if (rc)
		return (PVOID)((ULONG)rc - (ULONG)file + (ULONG)hModule);
	return 0;
};


ULONG EnumUnloadedDrivers(PDRIVER_ENTRY *ptrBuffer)
{
	PDRIVER_ENTRY Buffer;
	PUNLOADED_DRIVERS MmUnloadedDrivers = NULL;
	ULONG Counter;

	if (KdVersionBlock->MmUnloadedDrivers != NULL)
	{
		MmUnloadedDrivers = *(PUNLOADED_DRIVERS *)KdVersionBlock->MmUnloadedDrivers;
	}
	
	if (!MmIsAddressValid(MmUnloadedDrivers))
	{
		*ptrBuffer = NULL;
		return 0;
	}

	Buffer = (PDRIVER_ENTRY)MmAlloc(MI_UNLOADED_DRIVERS * sizeof(DRIVER_ENTRY));

	for (Counter = 0; Counter < MI_UNLOADED_DRIVERS; ++Counter)
	{
		if (MmUnloadedDrivers[Counter].StartAddress == NULL && MmUnloadedDrivers[Counter].Name.Buffer == NULL)
			break;
		Buffer[Counter].ImageBase = MmUnloadedDrivers[Counter].StartAddress;
		Buffer[Counter].ImageSize = (ULONG_PTR)MmUnloadedDrivers[Counter].EndAddress - (ULONG_PTR)MmUnloadedDrivers[Counter].StartAddress;
		CopyUnicodeStringFile(Buffer[Counter].ImagePath, &MmUnloadedDrivers[Counter].Name, COF(Buffer[Counter].ImagePath));
	}

	*ptrBuffer = Buffer;
	return Counter;
}


VOID CDevice::ScanDeviceType()
{
	POBJECT_TYPE ObjectType = *IoDeviceObjectType;
	PLIST_ENTRY Next;
	PDEVICE_OBJECT device;

	if (parseobject(ObjectType, ObjectListHead, LIST_ENTRY)->Blink == parseobject(ObjectType, ObjectListHead, LIST_ENTRY)->Flink)
        return;
	Next = parseobject(ObjectType, ObjectListHead, LIST_ENTRY)->Flink;
	while (Next != parseobject(ObjectType, ObjectListHead, LIST_ENTRY)) 
    {
		if (!MmIsAddressValid(Next))
            return;
		if (Next < MM_SYSTEM_RANGE_START)
            return;
		device = (PDEVICE_OBJECT)((PCHAR)Next + 0x28);
		if (MmIsAddressValid(device->DriverObject)) 
        {
			if (MmIsAddressValid(device->DriverObject->DriverSection) || device->DriverObject->DriverSection == NULL)
            {
				this->GrabDevice(device);
			}
		}
		Next = Next->Flink;
	}
}


VOID CDevice::ScanDeviceDirectory()
{
	POBJECT_DIRECTORY Directory = NULL;
	PDEVICE_OBJECT *Objects = NULL;
	ULONG ObjCount;
	
	
    Directory = *(POBJECT_DIRECTORY *)KdVersionBlock->ObpRootDirectoryObject;
    Print("Directory = %p", Directory);
    WalkDirectory(Directory, *IoDeviceObjectType, (PVOID **)&Objects);
    if (Objects)
    {
        ObjCount = MmGetSize(Objects) / sizeof(PVOID);
        for(ULONG Index = 0; Index < ObjCount; Index++)
        {
            if (MmIsAddressValid(Objects[Index]) && MmIsAddressValid(Objects[Index]->DriverObject))
            {
                if (MmIsAddressValid(Objects[Index]->DriverObject->DriverSection) || Objects[Index]->DriverObject->DriverSection == NULL) 
                {
                    this->GrabDevice(Objects[Index]);
                }
            }
        }
        MmFree(Objects);
    }
}


VOID CDevice::GrabDevice(PDEVICE_OBJECT DeviceObject)
{
	if (!MmIsAddressValid(DeviceObject))
        return;
	if (!this->IsFound(DeviceObject))
	{
		this->DeviceArray = (PDEVICE_OBJECT *)MmRealloc(this->DeviceArray, (this->DeviceCount + 1)*sizeof(PDEVICE_OBJECT));
		if (this->DeviceArray)
		{
			this->DeviceArray[this->DeviceCount] = DeviceObject;
			this->DeviceCount++;
		}
        if (DeviceObject->NextDevice != NULL && MmIsAddressValid(DeviceObject->NextDevice))
        {
            if (!this->IsFound(DeviceObject->NextDevice))
                GrabDevice(DeviceObject->NextDevice);
        }
        if (DeviceObject->AttachedDevice != NULL && MmIsAddressValid(DeviceObject->AttachedDevice))
        {
            if (!this->IsFound(DeviceObject->AttachedDevice))
                GrabDevice(DeviceObject->AttachedDevice);
        }
        if (DeviceObject->DeviceObjectExtension != NULL && MmIsAddressValid(DeviceObject->DeviceObjectExtension))
        {
            if (DeviceObject->DeviceObjectExtension->DeviceObject != NULL && MmIsAddressValid(DeviceObject->DeviceObjectExtension->DeviceObject))
            {
                if (!this->IsFound(DeviceObject->DeviceObjectExtension->DeviceObject))
                    GrabDevice(DeviceObject->DeviceObjectExtension->DeviceObject);
            }
            PDEVICE_OBJECT AttachedTo = *(PDEVICE_OBJECT *)((ULONG_PTR)DeviceObject->DeviceObjectExtension + 0x18);
            if (AttachedTo != NULL && MmIsAddressValid(AttachedTo))
            {
                if (!this->IsFound(AttachedTo))
                    GrabDevice(AttachedTo);
            }
        }
	}
}


BOOLEAN CDevice::IsFound(PDEVICE_OBJECT DeviceObject)
{
	ULONG c;
	for	(c = 0; c < this->DeviceCount; ++c) 
    {
		if (this->DeviceArray[c] == DeviceObject) 
            return TRUE;
	}
	return FALSE;
}