/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		handle.c
 *
 * Abstract:
 *
 *		This module implements a set of functions for detecting executive handles.
 *
 * Author:
 *
 *		GamingMasteR
 *
 */



#include "KeDetective.h"
#include "handle.h"
#include "process.h"
#include "fsd.h"


typedef struct _OBJECT_HEADER_NAME_INFO {
    POBJECT_DIRECTORY Directory;
    UNICODE_STRING Name;
    ULONG Reserved;
} OBJECT_HEADER_NAME_INFO, *POBJECT_HEADER_NAME_INFO;

#define OBJECT_HEADER_TO_NAME_INFO( oh ) ((POBJECT_HEADER_NAME_INFO) \
((oh)->Flags.NameInfoOffset == 0 ? NULL : ((PCHAR)(oh) - (oh)->Flags.NameInfoOffset)))

class CHandle {
public:
	CHandle(PHANDLE_TABLE HandleTable, BOOLEAN Extended) 
    { 
		this->HandleCount = 0; this->HandleInformation = 0; this->HandleInformationLite = 0;
		this->HandleTable = HandleTable; this->ExtendedMode = Extended;
	};
public:
	ULONG HandleCount;
	PHANDLE_ENTRY HandleInformation;
	PHANDLE_INFORMATION_LITE HandleInformationLite;
	PHANDLE_TABLE HandleTable;
	BOOLEAN ExtendedMode;
};


struct obj_struct {
	PVOID Object;
	PWCHAR string;
	LONG volatile Valid;
};


VOID FileThread(obj_struct *ObjStruct)
{
    POBJECT_NAME_INFORMATION Info;
	CHAR AnsiName[0x800] = "";
	ULONG dwRet;
	
    Info = (POBJECT_NAME_INFORMATION)AnsiName;
	ObQueryNameString(ObjStruct->Object, Info, sizeof(AnsiName), &dwRet);
	if (InterlockedOr(&ObjStruct->Valid, 0))
    {
		if (Info->Name.Length > 0) 
        {
			CopyUnicodeString(ObjStruct->string, &Info->Name, 260);
		}
	}
	MmFree(ObjStruct);
	PsTerminateSystemThread(0);
}


BOOLEAN EnumHandleRoutine(
    IN PHANDLE_TABLE_ENTRY HandleTableEntry,
    IN HANDLE Handle,
    IN PVOID EnumParameter
    )
{
	ULONG Size = 0;
	CHandle *HandleClass = (CHandle *)EnumParameter;
	ULONG HandlesCount = HandleClass->HandleCount;
	PHANDLE_ENTRY HandleInformation = HandleClass->HandleInformation;
	PHANDLE_INFORMATION_LITE HandleInformationLite = HandleClass->HandleInformationLite;
	PHANDLE_TABLE HandleTable = HandleClass->HandleTable;
	POBJECT_HEADER ObjectHeader = (POBJECT_HEADER)((ULONG)HandleTableEntry->Object & ~7);
	HANDLE ThreadHandle;
	obj_struct *ObjStruct = NULL;

	if (MmIsAddressValid(ObjectHeader))
	{
		if (MmIsAddressValid(TypeFromObject(ObjectHeader)))
		{
			if (HandleClass->ExtendedMode == TRUE) 
            {
				Size = HandlesCount * sizeof(HANDLE_ENTRY);
				HandleInformation = (PHANDLE_ENTRY)MmRealloc(HandleInformation, Size + sizeof(HANDLE_ENTRY));
				HandleInformation[HandlesCount].QuotaProcess = HandleTable->QuotaProcess;
				HandleInformation[HandlesCount].UniqueProcessId = HandleTable->UniqueProcessId;
				HandleInformation[HandlesCount].Object = &ObjectHeader->Body;
                HandleInformation[HandlesCount].ObjectType = TypeFromObject(ObjectHeader);
				HandleInformation[HandlesCount].Handle = Handle;
				HandleInformation[HandlesCount].GrantedAccess = HandleTableEntry->GrantedAccess;
				HandleInformation[HandlesCount].HandleCount = ObjectHeader->HandleCount;
				ObjStruct = (obj_struct *)MmAlloc(sizeof(obj_struct));
				ObjStruct->Object = &ObjectHeader->Body;
				ObjStruct->string = HandleInformation[HandlesCount].Name;
				ObjStruct->Valid = TRUE;
				NTSTATUS Status = PsCreateSystemThread(&ThreadHandle, 0, NULL, NULL, NULL, (PKSTART_ROUTINE)FileThread, ObjStruct);
				if (NT_SUCCESS(Status)) 
                {
					LARGE_INTEGER TimeOut;
                    TimeOut.QuadPart = -30000000;
					if (STATUS_TIMEOUT == ZwWaitForSingleObject(ThreadHandle, FALSE, &TimeOut))
                    {
						InterlockedDecrement(&ObjStruct->Valid);
					}
					ZwClose(ThreadHandle);
				}
			} 
            else
            {
				Size = HandlesCount * sizeof(HANDLE_INFORMATION_LITE);
				HandleInformationLite = (PHANDLE_INFORMATION_LITE)MmRealloc(HandleInformationLite, Size + sizeof(HANDLE_INFORMATION_LITE));
				HandleInformationLite[HandlesCount].QuotaProcess = HandleTable->QuotaProcess;
				HandleInformationLite[HandlesCount].Object = &ObjectHeader->Body;
			}
			HandlesCount += 1;
		}
	}
	HandleClass->HandleCount = HandlesCount;
	HandleClass->HandleInformation = HandleInformation;
	HandleClass->HandleInformationLite = HandleInformationLite;

	return FALSE;
}


PVOID
GetProcessHandles(
	PEPROCESS Process,
	ULONG &HandlesCount,
	BOOLEAN Extended
	)
{
	PHANDLE_TABLE HandleTable = 0;

	if (!MmIsAddressValid(Process))
        return NULL;
	HandleTable = Process->ObjectTable;
	if (IsVista) 
        HandleTable = *(PHANDLE_TABLE*)((PCHAR)Process + 0xdc);
	else if (IsWin7)
        HandleTable = *(PHANDLE_TABLE*)((PCHAR)Process + 0xf4);
	if (!MmIsAddressValid(HandleTable)) 
        return NULL;

	VMProtectBegin;
	CHandle HandleClass(HandleTable, Extended);
	KdEnumHandleTable(HandleTable, EnumHandleRoutine, &HandleClass, NULL);
	HandlesCount = HandleClass.HandleCount;
	VMProtectEnd;
	if (Extended)
    {
		return HandleClass.HandleInformation;
	} 
    else 
    {
		return HandleClass.HandleInformationLite;
	}
}


NTSTATUS
CloseHandle(
	HANDLE Handle,
	PEPROCESS Process
	)
{
	VMProtectBegin;

	NTSTATUS Status = STATUS_SUCCESS;
	KAPC_STATE ApcState;

	if	(BAD_PROCESS_STATUS(Process))
		return STATUS_UNSUCCESSFUL;
	KdStackAttachProcess(&Process->Pcb, &ApcState);
	__try
	{
		Status = KdClose(Handle);
		KdUnstackDetachProcess(&ApcState);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		KdUnstackDetachProcess(&ApcState);
		return STATUS_UNSUCCESSFUL;
	}

	VMProtectEnd;
	return Status;
}