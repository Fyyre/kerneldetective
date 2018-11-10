/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		Thread.h
 *
 * Abstract:
 *
 *		This module defines various routines used to scan for threads .
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



#define THREAD_SCAN_NORMAL		(0x00000001L)
#define THREAD_SCAN_BRUTE		(0x00000002L)


PEPROCESS KdThreadToProcess(PETHREAD Thread, BOOLEAN GetApc = FALSE);

VOID KeForceResumeThread(PKTHREAD Thread, BOOLEAN Flush);
VOID ForceTerminateThread(PETHREAD Thread);
THREAD_STATE PsGetThreadState(PETHREAD Thread);
NTSTATUS KeSuspendThread(PKTHREAD Thread);
NTSTATUS KeResumeThread(PKTHREAD Thread);
VOID GetThreadInfo(PETHREAD eThread, PTHREAD_ENTRY Thread);



class CThread 
{
public:
	CThread(PEPROCESS Process = 0) {
		this->Process = Process;
		this->ThreadArray = 0;
		this->ThreadCount = 0;
	};
	~CThread() {
		MmFree(this->ThreadArray);
	};
	VOID ScanProcessList();
	VOID ScanHandles();
	VOID ScanCidTable();
	VOID ScanTypeList();
	VOID ScanKiWaitList();
	//VOID ScanPhysicalMemory();
	VOID GrabThread(PETHREAD Thread);
    VOID GrabObject(PVOID Obj);

private:
	BOOLEAN IsFound(PETHREAD Thread);

public:
	PEPROCESS Process;
	PETHREAD *ThreadArray;
	ULONG ThreadCount;
};

extern PLIST_ENTRY KiWaitListHead;


#ifdef __cplusplus
	}
#endif