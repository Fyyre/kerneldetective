/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		Thread.cpp
 *
 * Abstract:
 *
 *		This module implements various routines used to scan for threads .
 *
 * Author:
 *
 *		GamingMasteR
 *
 */









#include "KeDetective.h"
#include "process.h"
#include "Thread.h"
#include "handle.h"
#include "ssdt.h"


PLIST_ENTRY KiWaitListHead;



VOID GetThreadInfo(PETHREAD eThread, PTHREAD_ENTRY Thread)
{
    if (MmIsAddressValid(eThread))
    {
        __try
        {
            Thread->Process		= KdThreadToProcess(eThread, TRUE);
            Thread->ParentId	= (ULONG)PsGetThreadProcessId(eThread);
            Thread->Thread		= eThread;
            Thread->Cid			= (ULONG)PsGetThreadId(eThread);
            Thread->Teb			= PsGetThreadTeb(eThread);
            Thread->ServiceTable	= *parseobject(eThread, ServiceTable, PVOID);
            Thread->ThreadState	= PsGetThreadState(eThread);
            if (IsVista) // ETHREAD->Win32StartAddress
            {
                Thread->Address	= *(PVOID*)((ULONG_PTR)eThread + 0x240);
                Thread->WaitReason = *(PUCHAR)((ULONG_PTR)eThread + 0x6c);
            }
            else if (IsWin7) // ETHREAD->Win32StartAddress
            {
                Thread->Address	= *(PVOID*)((ULONG_PTR)eThread + 0x260);
                Thread->WaitReason = *(PUCHAR)((ULONG_PTR)eThread + 0x187);
            }
            else
            {
                Thread->WaitReason = eThread->Tcb.WaitReason;
                if (eThread->Win32StartAddress && eThread->LpcReceivedMsgIdValid == 0)
                    Thread->Address = eThread->Win32StartAddress;
                else
                    Thread->Address = eThread->StartAddress;
            }
            Thread->Status = 0;
            if (PsGetThreadWin32Thread(eThread) == 0)
            {
                if (Thread->ServiceTable != KdServiceDescriptorTable)
                    Thread->Status |= (1 << 0);
                Thread->Type = 0;
            }
            else
            {
                if (Thread->ServiceTable != KeServiceDescriptorTableShadow) Thread->Status |= (1 << 0);
                Thread->Type = 1;
            }
            if (PsIsThreadTerminating(eThread))
            {
                Thread->Status |= (1 << 1);
            }
            if (*parseobject(eThread, ThreadFlags, ULONG)&(1 << 6))
            {
                Thread->Status |= (1 << 2); //BreakOnTermination
            }
            if (*parseobject(eThread, ThreadFlags, ULONG)&(1 << 2))
            {
                Thread->Status |= (1 << 3); //HiddenFromDebugger
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }
}


BOOLEAN
IsValidThread(
    PETHREAD eThread
)
{
    if (!MmIsAddressValid(OBJECT_TO_OBJECT_HEADER(eThread)))
        return 0;

    if (((PKTHREAD)eThread)->Header.SignalState != 0)
        return 0;

    if (TypeFromObject(OBJECT_TO_OBJECT_HEADER(eThread)) != *PsThreadType)
        return 0;

    if (IsXp && *parseobject(eThread, ThreadFlags, ULONG)&DeadThread)
        return 0;

    if (PsGetThreadTeb(eThread) >= MM_HIGHEST_USER_ADDRESS)
        return 0;

    if (!MmIsAddressValid(KdThreadToProcess(eThread, TRUE)))
        return 0;

    if (IsXp)
    {
        if (!MmIsAddressValid((PVOID)eThread->ThreadsProcess))
            return 0;

        if ((ULONG)eThread->Tcb.ApcState.Process != (ULONG)eThread->ThreadsProcess)
            return 0;
    }

    return 1;
}


/*VOID CThread::ScanPhysicalMemory()
{
    PETHREAD Thread;
    PCHAR Offset;
    ULONG i, counter;
    DispatchLock lock;

    for (Offset = (PCHAR)MM_SYSTEM_RANGE_START; Offset <= (PCHAR)0xffff0000; Offset += PAGE_SIZE)
    {
        if (IsValidSystemAddress(Offset))
        {
            Thread = (PETHREAD)Offset;
            if (IsValidSystemAddress(Offset + PAGE_SIZE))
            {
                counter = (PAGE_SIZE)/8;
            }
            else
            {
                counter = ((PAGE_SIZE - info.PsSizeofThread)/8);
            }
            lock.Lock();
            for (i = 0; i < counter; i++, *(ULONG_PTR*)&Thread += 8)
            {
                if (IsValidThread(Thread))
                {
                    this->GrabThread(Thread);
                }
            }
            lock.Unlock();
        }
    }
}*/


VOID CThread::ScanProcessList()
{
    PETHREAD Thread;
    PLIST_ENTRY Next;
    CProcess Process;
    ULONG Count;

    Process.GrabProcess(PsIdleProcess);
    Process.ScanCidTable();
    Process.ScanSessionList();

    for (Count = 0; Count < Process.ProcessCount; ++Count)
    {
        Next = parseobject(Process.ProcessArray[Count], ThreadListHead, LIST_ENTRY)->Flink;
        while (Next != parseobject(Process.ProcessArray[Count], ThreadListHead, LIST_ENTRY))
        {
            if (!MmIsAddressValid(Next) || Next < MM_SYSTEM_RANGE_START)
                break;
            Thread = (PETHREAD)((ULONG)Next - info.PsKeThreadListEntry);
            this->GrabThread(Thread);
            Next = Next->Flink;
        }

        Next = Process.ProcessArray[Count]->Pcb.ThreadListHead.Flink;
        while (Next != &Process.ProcessArray[Count]->Pcb.ThreadListHead)
        {
            if (!MmIsAddressValid(Next) || Next < MM_SYSTEM_RANGE_START)
                break;
            Thread = (PETHREAD)((ULONG)Next - info.PsKiThreadListEntry);
            this->GrabThread(Thread);
            Next = Next->Flink;
        }
    }
}


VOID CThread::ScanHandles()
{
    CProcess Process;
    ULONG Count, nHandles, HandlesCount;
    PHANDLE_INFORMATION_LITE HandleInfo;

    Process.ScanCidTable();
    Process.ScanSessionList();
    for (Count = 0; Count < Process.ProcessCount; ++Count)
    {
        HandleInfo = (PHANDLE_INFORMATION_LITE)GetProcessHandles(Process.ProcessArray[Count], HandlesCount, FALSE);
        if (HandleInfo != NULL)
        {
            for (nHandles = 0; nHandles < HandlesCount; ++nHandles)
            {
                this->GrabObject(HandleInfo[nHandles].Object);
            }
            MmFree(HandleInfo);
        }
    }
}


BOOLEAN EnumThreadCidRoutine(
    IN PHANDLE_TABLE_ENTRY HandleTableEntry,
    IN HANDLE Handle,
    IN PVOID EnumParameter
    )
{
    CThread *ThreadList;
    PVOID Object;

    ThreadList = (CThread *)EnumParameter;
    Object = (PVOID)(HandleTableEntry->Value & ~7);
    ThreadList->GrabObject(Object);

    return FALSE;
}


VOID CThread::ScanCidTable()
{
    PHANDLE_TABLE PspCidTable;

    PspCidTable = *(PHANDLE_TABLE *)KdVersionBlock->PspCidTable;
    if (PspCidTable && MmIsAddressValid(PspCidTable))
    {
        KdEnumHandleTable(PspCidTable, EnumThreadCidRoutine, this, NULL);
    }
}


VOID CThread::ScanTypeList()
{
    POBJECT_TYPE ObjectType = *PsThreadType;
    PLIST_ENTRY Next;
    PETHREAD Thread;

    if (parseobject(ObjectType, ObjectListHead, LIST_ENTRY)->Blink == parseobject(ObjectType, ObjectListHead, LIST_ENTRY)->Flink)
        return;
    Next = parseobject(ObjectType, ObjectListHead, LIST_ENTRY)->Flink;
    while (Next != parseobject(ObjectType, ObjectListHead, LIST_ENTRY))
    {
        if (!MmIsAddressValid(Next) || Next < MM_SYSTEM_RANGE_START)
            return;
        Thread = (PETHREAD)((PCHAR)Next + 0x28);
        this->GrabThread(Thread);
        Next = Next->Flink;
    }
}


VOID CThread::ScanKiWaitList()
{
    ULONG WaitProcOffset = 0x60;
    PLIST_ENTRY Item;
    PETHREAD Thread;

    if (IsVista)
        WaitProcOffset = 0x70;
    else if (IsWin7)
        WaitProcOffset = 0x74;
    if (MmIsAddressValid(KiWaitListHead))
    {
        Item = KiWaitListHead->Flink;
        while (Item != KiWaitListHead)
        {
            Thread = (PETHREAD)((ULONG)Item - WaitProcOffset);
            if (!MmIsAddressValid(Thread))
                return;
            this->GrabThread(Thread);
            Item = Item->Flink;
        }
    }
}


VOID CThread::GrabThread(PETHREAD Thread)
{
    PEPROCESS Process;

    if (!MmIsAddressValid(OBJECT_TO_OBJECT_HEADER(Thread)))
        return;
    if (!MmIsAddressValid(Thread))
        return;
    Process = KdThreadToProcess(Thread, TRUE);
    if (!MmIsAddressValid(Process))
        return;
    if ((this->Process == 0 || this->Process == PsIdleProcess || this->Process == Process) && (!this->IsFound(Thread)))
    {
        if (PsIsThreadTerminating(Thread) && PsGetThreadState(Thread) == StateTerminated && !PsGetThreadTeb(Thread))
            return;
        this->ThreadArray = (PETHREAD *)MmRealloc(this->ThreadArray, (this->ThreadCount + 1)*sizeof(PETHREAD));
        if (this->ThreadArray)
        {
            this->ThreadArray[this->ThreadCount] = Thread;
            this->ThreadCount++;
        }
    }
}


VOID CThread::GrabObject(PVOID Obj)
{
    POBJECT_HEADER ObjHeader;
    *(ULONG *)&Obj &= ~7;
    ObjHeader = OBJECT_TO_OBJECT_HEADER(Obj);
    if (!MmIsAddressValid(ObjHeader))
        return;
    if (TypeFromObject(ObjHeader) == *PsThreadType)
        this->GrabThread((PETHREAD)Obj);
}


BOOLEAN CThread::IsFound(PETHREAD Thread)
{
    ULONG c;
    for	(c = 0; c < this->ThreadCount; ++c)
    {
        if (this->ThreadArray[c] == Thread)
            return TRUE;
    }
    return FALSE;
}


PEPROCESS KdThreadToProcess(PETHREAD Thread, BOOLEAN GetApc)
{
    VMProtectBegin;
    ULONG Offset = 0x034;
    PEPROCESS Process = NULL;
    if (!GetApc)
    {
        Process = IoThreadToProcess(Thread);
    }
    if (!Process)
    {
        if (IsVista)
            Offset = 0x038;
        else if (IsWin7)
            Offset = 0x040;
        Process = (PEPROCESS)((PKAPC_STATE)((ULONG_PTR)Thread + Offset))->Process;
        if (!Process || !MmIsAddressValid(Process))
            Process = IoThreadToProcess(Thread);
    }
    if (!MmIsAddressValid(Process))
        Process = NULL;
    VMProtectEnd;
    return Process;
}


VOID KernelTerminateThreadRoutine(PKAPC Apc, PKNORMAL_ROUTINE *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1, PVOID *SystemArgument2)
{
    VMProtectBegin;
    MmFree(Apc);
    KdTerminateSystemThread(EXIT_FAILURE);
    VMProtectEnd;
}


VOID FlushThreadApc(PKAPC Apc, PKNORMAL_ROUTINE *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1, PVOID *SystemArgument2)
{
    MmFree(Apc);
}


VOID KeForceResumeThread(PKTHREAD Thread, BOOLEAN Flush)
{
    ULONG PreviousCount;
    PCHAR lpFreezeCount = parseobject(Thread, FreezeCount, CHAR);
    PCHAR lpSuspendCount;
    PKSEMAPHORE lpSuspendSemaphore = parseobject(Thread, SuspendSemaphore, KSEMAPHORE);

    VMProtectBegin;

    if (IsWin7)
    {
        lpSuspendCount = (PCHAR)Thread + 0x188;
    }
    else
    {
        lpSuspendCount = lpFreezeCount + 1;
    }
    PreviousCount = *lpFreezeCount + *lpSuspendCount;
    if (PreviousCount)
    {
        *lpFreezeCount = *lpSuspendCount = 0;
        lpSuspendSemaphore->Header.SignalState += 1;
        KdAlertThread(Thread, KernelMode);
    }

    if (Flush)
    {
        PKAPC Apc = (PKAPC)MmAlloc(sizeof(KAPC));
        KeInitializeApc(Apc, Thread, OriginalApcEnvironment, FlushThreadApc, NULL, NULL, KernelMode, NULL);
        KdInsertQueueApc(Apc, NULL, NULL, 0);
    }

    VMProtectEnd;
}


VOID ForceTerminateThread(PETHREAD Thread)
{
    VMProtectBegin;

    PKAPC Apc = (PKAPC)MmAlloc(sizeof(KAPC));
    DispatchLock lock;


    lock.Lock();
    //
    // Enable APC
    //
    if (IsXp)
    {
        *((PUCHAR)Thread + 0x166) |= TRUE;
    }
    else if (IsVista)
    {
        *(PULONG)((PUCHAR)Thread + 0xb0) |= (ULONG)(1 << 6);
    }
    else if (IsWin7)
    {
        *(PULONG)((PUCHAR)Thread + 0xb8) |= (ULONG)(1 << 5);
    };

    //
    // Mark as system thread
    //
    *parseobject(Thread, ThreadFlags, ULONG) |= 0x00000010;

    //
    // Force thread to resume execution
    //
    KeForceResumeThread(&Thread->Tcb, FALSE);

    //
    // Send APC
    //
    KeInitializeApc(Apc, &Thread->Tcb, OriginalApcEnvironment, KernelTerminateThreadRoutine, NULL, NULL, KernelMode, NULL);
    KdInsertQueueApc(Apc, NULL, NULL, 0);

    lock.Unlock();

    VMProtectEnd;
};


THREAD_STATE PsGetThreadState(PETHREAD Thread)
{
    if (IsVista)
    {
        return ((THREAD_STATE)(*((PUCHAR)Thread + 0x5c)));
    }
    else if (IsWin7)
    {
        return ((THREAD_STATE)(*((PUCHAR)Thread + 0x068)));
    };
    return ((THREAD_STATE)Thread->Tcb.State);
};


NTSTATUS KeSuspendThread(PKTHREAD Thread)
{
    NTSTATUS NtStatus;
    ULONG OldCount;


    if (IsXp) // Enable APC
    {
        *((PUCHAR)Thread + 0x166) |= TRUE;
    }
    else if (IsVista)
    {
        *(PULONG)((PUCHAR)Thread + 0xb0) |= (ULONG)(1 << 6);
    }
    else if (IsWin7)
    {
        *(PULONG)((PUCHAR)Thread + 0xb8) |= (ULONG)(1 << 5);
    }
    NtStatus = KdSuspendThread(Thread, &OldCount);
    return NtStatus;
}


NTSTATUS KeResumeThread(PKTHREAD Thread)
{
    VMProtectBegin;

    PCHAR lpFreezeCount = parseobject(Thread, FreezeCount, CHAR);
    PCHAR lpSuspendCount;
    PKSEMAPHORE lpSuspendSemaphore = parseobject(Thread, SuspendSemaphore, KSEMAPHORE);

    

    if (IsWin7)
    {
        lpSuspendCount = (PCHAR)Thread + 0x188;
    }
    else
    {
        lpSuspendCount = lpFreezeCount + 1;
    }

    if (*lpSuspendCount != 0)
    {
        *lpSuspendCount -= 1;
        if (*lpSuspendCount == 0)
        {
            lpSuspendSemaphore->Header.SignalState += 1;
            KdAlertThread(Thread, KernelMode);
        }
    }

    PKAPC Apc = (PKAPC)MmAlloc(sizeof(KAPC));
    KeInitializeApc(Apc, Thread, OriginalApcEnvironment, FlushThreadApc, NULL, NULL, KernelMode, NULL);
    KdInsertQueueApc(Apc, NULL, NULL, 0);

    VMProtectEnd;
    return STATUS_SUCCESS;
}
