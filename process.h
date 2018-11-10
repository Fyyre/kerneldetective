/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		process.h
 *
 * Abstract:
 *
 *		This module defines various routines used to scan for processes .
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


#define BAD_PROCESS_STATUS(_ps)	(!MmIsAddressValid(_ps)) || !IsValidHandleTable(_ps) || (*parseobject(_ps, ProcessFlags, ULONG)&ProcessDelete)




VOID
GetProcessInfo(
	PEPROCESS eProcess,
	PPROCESS_ENTRY Process
	);


VOID
ForceTerminateProcess(
	PEPROCESS eProcess
	);


PLIST_ENTRY
GetKiWaitListHead(
	);


class CProcess
{
public:
	CProcess() {
		this->ProcessArray = 0;
		this->ProcessCount = 0;
	};
	~CProcess() {
		MmFree(this->ProcessArray);
	};
	VOID ScanHandles();
	VOID ScanCidTable();
	VOID ScanTypeList();
	VOID ScanSessionList();
	//VOID ScanPhysicalMemory();
	VOID GrabProcess(PEPROCESS Process);
    VOID GrabObject(PVOID Obj);

private:
	BOOLEAN IsFound(PEPROCESS Process);

public:
	PEPROCESS *ProcessArray;
	ULONG ProcessCount;
};


__declspec(dllimport)
PEPROCESS PsInitialSystemProcess;


extern PEPROCESS	PsIdleProcess;


#ifdef __cplusplus
	}
#endif