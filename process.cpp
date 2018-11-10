/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		process.c
 *
 * Abstract:
 *
 *		This module implements various routines used to scan for processes .
 *
 * Author:
 *
 *		GamingMasteR
 *
 */









#include "KeDetective.h"
#include "process.h"
#include "thread.h"
#include "module.h"
#include "dll.h"
#include "handle.h"
#include "dasm.h"
#include "fsd.h"


PEPROCESS	PsIdleProcess;



VOID GetProcessPath(ULONG eProcess,	PWCHAR buffer, SIZE_T Count)
{
    VMProtectBegin;

    PSECTION_OBJECT SectionObject = 0;
    PFILE_OBJECT FileObject = 0;
    POBJECT_NAME_INFORMATION ImageFileName;
    ULONG dwData = 0;
    PEPROCESS Process = (PEPROCESS)eProcess;


    if (MmIsAddressValid(Process) == 0) return;

    if (IsXp) SectionObject = *(PSECTION_OBJECT*)(eProcess + 0x138);
    else if (IsVista) SectionObject = *(PSECTION_OBJECT*)(eProcess + 0x110);
    else if (IsWin7) SectionObject = *(PSECTION_OBJECT*)(eProcess + 0x128);
    if (MmIsAddressValid(SectionObject))
    {
        if (MmIsAddressValid(SectionObject->Segment))
        {
            if (MmIsAddressValid(((PSEGMENT)SectionObject->Segment)->ControlArea))
            {
                FileObject = ((PSEGMENT)SectionObject->Segment)->ControlArea->FilePointer;
                if (KdBuildNumber >= 6000) FileObject = (PFILE_OBJECT)((ULONG)FileObject&0xfffffff8);
                if (MmIsAddressValid(FileObject))
                {
                    if (GetFileName(FileObject, buffer, Count))
                    {
                        return;
                    }
                }
            }
        }
    }

    ImageFileName = parseobject(eProcess, SeAuditProcessCreationInfo, SE_AUDIT_PROCESS_CREATION_INFO)->ImageFileName;
    if (MmIsAddressValid(ImageFileName))
    {
        if (MmIsAddressValid(ImageFileName->Name.Buffer))
        {
            CopyUnicodeStringFile(buffer, &ImageFileName->Name, Count);
            return;
        }
    }
    _snwprintf(buffer, 16, L"%S", PsGetProcessImageFileName((PEPROCESS)eProcess));

    VMProtectEnd;
}


VOID
GetProcessInfo(
    PEPROCESS eProcess,
    PPROCESS_ENTRY Process
)
{
    //VMProtectBegin;

    PHANDLE_TABLE HandleTable = 0;
    __try
    {
        if (MmIsAddressValid(eProcess))
        {
            if (*parseobject(eProcess, ProcessFlags, ULONG)&BreakOnTermination)
                Process->Status     = 2;
            else
                Process->Status     = 0;
            Process->ImageBase	    = (ULONG)PsGetProcessSectionBaseAddress(eProcess);
            Process->ProcessObject	= eProcess;
            Process->Peb		    = PsGetProcessPeb(eProcess);
            Process->Cb			    = *parseobject(eProcess, VirtualSize, ULONG);
            Process->ParentId	    = (ULONG)PsGetProcessInheritedFromUniqueProcessId(eProcess);
            Process->Pid		    = (ULONG)PsGetProcessId(eProcess);
            HandleTable             = GetProcessHandleTable(eProcess);
            if (MmIsAddressValid(HandleTable))
            {
                ULONG RealPid = (ULONG)HandleTable->UniqueProcessId;
                if (RealPid > 4)
                {
                    Process->Pid = RealPid;
                }
            }

            if (eProcess == PsIdleProcess)
                wcscpy(Process->Name, L"System Idle Process");
            else if (eProcess == PsInitialSystemProcess)
                wcscpy(Process->Name, L"System");
            else
                GetProcessPath((ULONG)eProcess, Process->Name, COF(Process->Name));
        }
    } 
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        Print("expection");
    }

    //VMProtectEnd;
}


VOID
ForceTerminateProcess(
    PEPROCESS eProcess
)
{
    VMProtectBegin;

    NTSTATUS			NtStatus ;
    HANDLE				hProcess = 0 ;
    KPROCESSOR_MODE		pm;

    NtStatus = KdOpenObjectByPointer(eProcess, OBJ_KERNEL_HANDLE, NULL, 0, NULL, KernelMode, &hProcess);
    if	(STATUS_SUCCESS != NtStatus)
        return;
    pm = KeSetPreviousMode(KernelMode);
    KdTerminateProcess(hProcess, EXIT_FAILURE);
    KdClose(hProcess);
    KeSetPreviousMode(pm);
    VMProtectEnd;
};


BOOLEAN
IsValidProcess(
    ULONG eProcess
)
{

    __try
    {
        if (!MmIsAddressValid(OBJECT_TO_OBJECT_HEADER(eProcess)))
            return 0;

        if (TypeFromObject(OBJECT_TO_OBJECT_HEADER(eProcess)) != *PsProcessType)
            return 0;


        if (*parseobject(eProcess, ProcessFlags, ULONG)&ProcessDelete)
            return 0;


        if (*parseobject(eProcess, VirtualSize, ULONG) == 0)
            return 0;


        //->Pcb.SignalState
        if (((PEPROCESS)eProcess)->Pcb.Header.SignalState != 0)
            return 0;

        //->UniqueProcessId
        if (PsGetProcessId((PEPROCESS)eProcess) >= (PVOID)0x100000)
            return 0;


        //->InheritedFromUniqueProcessId
        if (PsGetProcessInheritedFromUniqueProcessId((PEPROCESS)eProcess) >= (PVOID)0x100000)
            return 0;


        //->Peb
        if (PsGetProcessPeb((PEPROCESS)eProcess) >= MM_HIGHEST_USER_ADDRESS ||
                PsGetProcessPeb((PEPROCESS)eProcess) <= MM_LOWEST_USER_ADDRESS)
            return 0;

        if (!MmIsAddressValid(*parseobject(eProcess, DeviceMap, PVOID)) &&
                *parseobject(eProcess, DeviceMap, PVOID))
            return 0;


        //->ExceptionPort
        if (!MmIsAddressValid(*parseobject(eProcess, ExceptionPort, PVOID)) &&
                *parseobject(eProcess, ExceptionPort, PVOID))
            return 0;


        //->VadRoot
        //if (eProcess->VadRoot <= SystemStart)
        //	return 0;
        //if (!MmIsAddressValid((PVOID)eProcess->VadRoot))
        //	return 0;


        //->SectionBaseAddress
        if (PsGetProcessSectionBaseAddress((PEPROCESS)eProcess) != 0)
            if (PsGetProcessSectionBaseAddress((PEPROCESS)eProcess) >= MM_HIGHEST_USER_ADDRESS ||
                    PsGetProcessSectionBaseAddress((PEPROCESS)eProcess) <= MM_LOWEST_USER_ADDRESS)
                return 0;


        //->ActiveProcessLinks.Flink
        if ((PVOID)(parseobject(eProcess, ActiveProcessLinks, LIST_ENTRY))->Flink <= MM_SYSTEM_RANGE_START)
            return 0;
        if (!MmIsAddressValid((PVOID)(parseobject(eProcess, ActiveProcessLinks, LIST_ENTRY))->Flink))
            return 0;


        if ((PVOID)(parseobject(eProcess, ActiveProcessLinks, LIST_ENTRY))->Blink <= MM_SYSTEM_RANGE_START)
            return 0;
        if (!MmIsAddressValid((PVOID)(parseobject(eProcess, ActiveProcessLinks, LIST_ENTRY))->Blink))
            return 0;


        //->ThreadListHead.Flink
        if ((PVOID)(parseobject(eProcess, ThreadListHead, LIST_ENTRY))->Flink <= MM_SYSTEM_RANGE_START)
            return 0;
        if (!MmIsAddressValid((PVOID)(parseobject(eProcess, ThreadListHead, LIST_ENTRY))->Flink))
            return 0;


        //->ThreadListHead.Blink
        if ((PVOID)(parseobject(eProcess, ThreadListHead, LIST_ENTRY))->Blink <= MM_SYSTEM_RANGE_START)
            return 0;
        if (!MmIsAddressValid((PVOID)(parseobject(eProcess, ThreadListHead, LIST_ENTRY))->Blink))
            return 0;


        //->Pcb.ThreadListHead.Flink
        if ((PVOID)((PEPROCESS)eProcess)->Pcb.ThreadListHead.Flink <= MM_SYSTEM_RANGE_START)
            return 0;
        if (!MmIsAddressValid((PVOID)((PEPROCESS)eProcess)->Pcb.ThreadListHead.Flink))
            return 0;


        //->Pcb.ThreadListHead.Blink
        if ((PVOID)((PEPROCESS)eProcess)->Pcb.ThreadListHead.Blink <= MM_SYSTEM_RANGE_START)
            return 0;
        if (!MmIsAddressValid((PVOID)((PEPROCESS)eProcess)->Pcb.ThreadListHead.Blink))
            return 0;


        //->Pcb.ReadyListHead.Flink
        if ((PVOID)((PEPROCESS)eProcess)->Pcb.ReadyListHead.Flink <= MM_SYSTEM_RANGE_START)
            return 0;
        if (!MmIsAddressValid((PVOID)((PEPROCESS)eProcess)->Pcb.ReadyListHead.Flink))
            return 0;


        //->Pcb.ReadyListHead.Blink
        if ((PVOID)((PEPROCESS)eProcess)->Pcb.ReadyListHead.Blink <= MM_SYSTEM_RANGE_START)
            return 0;
        if (!MmIsAddressValid((PVOID)((PEPROCESS)eProcess)->Pcb.ReadyListHead.Blink))
            return 0;


        //->Pcb.Header.WaitListHead.Flink
        if ((PVOID)((PEPROCESS)eProcess)->Pcb.Header.WaitListHead.Flink <= MM_SYSTEM_RANGE_START)
            return 0;
        if (!MmIsAddressValid((PVOID)((PEPROCESS)eProcess)->Pcb.Header.WaitListHead.Flink))
            return 0;

        //->Pcb.Header.WaitListHead.Blink
        if ((PVOID)((PEPROCESS)eProcess)->Pcb.Header.WaitListHead.Blink <= MM_SYSTEM_RANGE_START)
            return 0;
        if (!MmIsAddressValid((PVOID)((PEPROCESS)eProcess)->Pcb.Header.WaitListHead.Blink))
            return 0;
    }
    __except(1)
    {
        return 0;
    };

    return 1;
};


/*VOID CProcess::ScanPhysicalMemory()
{
    PEPROCESS Process;
    PCHAR Offset;
    ULONG i, counter;
    DispatchLock lock;


    for (Offset = (PCHAR)MM_SYSTEM_RANGE_START; Offset <= (PCHAR)0xffc00000; Offset += PAGE_SIZE)
    {
        if (IsValidSystemAddress(Offset))
        {
            Process = (PEPROCESS)Offset;
            if (IsValidSystemAddress(Offset + PAGE_SIZE))
            {
                counter = (PAGE_SIZE)/8;
            }
            else
            {
                counter = ((PAGE_SIZE - info.PsSizeofProcess)/8);
            }
            lock.Lock();
            for (i = 0; i < counter; i++, *(ULONG_PTR*)&Process += 8)
            {
                if (IsValidProcess((ULONG)Process))
                {
                    this->GrabProcess(Process);
                }
            }
            lock.Unlock();
        }
    }
}*/


PLIST_ENTRY
GetVistaKiWaitListHead(
)
{
    PCHAR Prcb = 0;

    __asm mov eax, _PCR KPCR.Prcb;
    __asm mov Prcb, eax;
    if (Prcb)
    {
        if (KdBuildNumber == 6000)
            return (PLIST_ENTRY)(Prcb + 0x1A20);
        else if (IsWin7)
            return (PLIST_ENTRY)(Prcb + 0x31E0);
        else
            return (PLIST_ENTRY)(Prcb + 0x1AA0);
    }
    return 0;
}


PLIST_ENTRY
GetKiWaitListHead(
)
{
    PUCHAR cPtr, pOpcode;
    ULONG Length;

    if (IsVista || IsWin7)
        return GetVistaKiWaitListHead();

    for (cPtr = (PUCHAR)KeDelayExecutionThread;
            cPtr < (PUCHAR)KeDelayExecutionThread + PAGE_SIZE;
            cPtr += Length)
    {
        Length = SizeOfCode(cPtr, &pOpcode);

        if (!Length) return 0;

        if (Length != 6) continue;

        if (*(PUSHORT)cPtr == 0x03c7 && *(PUSHORT)(pOpcode + 6) == 0x4389)
            return *(PLIST_ENTRY *)(pOpcode + 2);
    }
    return 0;
}


VOID CProcess::ScanHandles()
{
    ULONG nProcess;
    ULONG nHandles, HandlesCount;
    PHANDLE_INFORMATION_LITE HandleInfo;
    PLIST_ENTRY Next, HandleTableListHead = 0;
    PHANDLE_TABLE HandleTable, PspCidTable;
    ULONG HandleOffset = 0;

    if (IsXp)
    {
        HandleOffset = 0x1c;
        HandleTableListHead = (PLIST_ENTRY)((ULONG_PTR)PsGetCurrentProcess()->ObjectTable + HandleOffset);
    }
    else if (IsVista)
    {
        HandleOffset = 0x10;
        HandleTableListHead = (PLIST_ENTRY)((ULONG_PTR)(*(PHANDLE_TABLE*)((PCHAR)PsGetCurrentProcess() + 0xdc)) + HandleOffset);
    }
    else if (IsWin7)
    {
        HandleOffset = 0x10;
        HandleTableListHead = (PLIST_ENTRY)((ULONG_PTR)(*(PHANDLE_TABLE*)((PCHAR)PsGetCurrentProcess() + 0xf4)) + HandleOffset);
    }

    PspCidTable = *(PHANDLE_TABLE*)KdVersionBlock->PspCidTable;

    Next = HandleTableListHead->Flink;
    while (Next != HandleTableListHead)
    {
        if (!MmIsAddressValid(Next))
            break;
        if (Next < MM_SYSTEM_RANGE_START)
            break;
        HandleTable = (PHANDLE_TABLE)((PCHAR)Next - HandleOffset);
        if (HandleTable->QuotaProcess != NULL && MmIsAddressValid(HandleTable->QuotaProcess))
        {
            this->GrabProcess(HandleTable->QuotaProcess);
        }
        Next = Next->Flink;
    }

    for (nProcess = 0; nProcess < this->ProcessCount; ++nProcess)
    {
        HandleInfo = (PHANDLE_INFORMATION_LITE)GetProcessHandles(this->ProcessArray[nProcess], HandlesCount, FALSE);
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


BOOLEAN EnumProcessCidRoutine(
    IN PHANDLE_TABLE_ENTRY HandleTableEntry,
    IN HANDLE Handle,
    IN PVOID EnumParameter
    )
{
    CProcess *ProcessList;
    PVOID Object;

    ProcessList = (CProcess *)EnumParameter;
    Object = (PVOID)(HandleTableEntry->Value & ~7);
    //Print("Object = %p", Object);
    ProcessList->GrabObject(Object);

    return FALSE;
}

VOID CProcess::ScanCidTable()
{
    PHANDLE_TABLE PspCidTable;

    PspCidTable = *(PHANDLE_TABLE *)KdVersionBlock->PspCidTable;
    if (PspCidTable && MmIsAddressValid(PspCidTable))
    {
        KdEnumHandleTable(PspCidTable, EnumProcessCidRoutine, this, NULL);
    }
}


VOID CProcess::ScanTypeList()
{
    //VMProtectBegin;
    POBJECT_TYPE ObjectType = *PsProcessType;
    PLIST_ENTRY Next;
    PEPROCESS Process;

    if (parseobject(ObjectType, ObjectListHead, LIST_ENTRY)->Blink == parseobject(ObjectType, ObjectListHead, LIST_ENTRY)->Flink)
        return;
    Next = parseobject(ObjectType, ObjectListHead, LIST_ENTRY)->Flink;
    //VMProtectEnd;
    while (Next != parseobject(ObjectType, ObjectListHead, LIST_ENTRY))
    {
        if (!MmIsAddressValid(Next) || Next < MM_SYSTEM_RANGE_START)
            return;
        Process = (PEPROCESS)((PCHAR)Next + 0x28);
        this->GrabProcess(Process);
        Next = Next->Flink;
    }
}


VOID CProcess::ScanSessionList()
{
    //VMProtectBegin;

    ULONG VmOffset = 0x21c;
    ULONG HandleTable = 0xc4;
    PLIST_ENTRY Next;
    PVOID Process;

    if (IsVista)
    {
        VmOffset = 0x1d0;
        HandleTable = 0xdc;
    }
    else if (IsWin7)
    {
        VmOffset = 0x1FC;
        HandleTable = 0xf4;
    }

    Next = (PLIST_ENTRY)((ULONG_PTR)PsInitialSystemProcess + VmOffset);
    do
    {
        //Print("Session = %p", Next);
        if (!MmIsAddressValid(Next) || Next < MM_SYSTEM_RANGE_START)
            return;
        Process = (PCHAR)Next - VmOffset;
        if (Process > ((PCHAR)KernelBase + KernelSize) && MmIsAddressValid(Process))
        {
            if (IsValidHandleTable(Process))
            {
                GrabProcess((PEPROCESS)Process);
            }
        }
        Next = Next->Flink;
    }
    while (Next != (PLIST_ENTRY)((ULONG_PTR)PsInitialSystemProcess + VmOffset));

    //VMProtectEnd;
}


VOID CProcess::GrabProcess(PEPROCESS Process)
{
    if (!MmIsAddressValid(Process))
        return;

    if (!this->IsFound(Process))
    {
        //VMProtectBegin;
        if (ExAcquireRundownProtection(parseobject(Process, ProcessRundown, EX_RUNDOWN_REF)))
        {
            ExReleaseRundownProtection(parseobject(Process, ProcessRundown, EX_RUNDOWN_REF));
        }
        else
        {
            return;
        }
        //VMProtectEnd;
        this->ProcessArray = (PEPROCESS *)MmRealloc((PVOID)this->ProcessArray, (this->ProcessCount + 1)*sizeof(PEPROCESS));
        if (this->ProcessArray)
        {
            this->ProcessArray[this->ProcessCount] = Process;
            this->ProcessCount++;
        }
    }
}


VOID CProcess::GrabObject(PVOID Obj)
{
    POBJECT_HEADER ObjHeader;

    *(ULONG *)&Obj &= ~7;
    ObjHeader = OBJECT_TO_OBJECT_HEADER(Obj);
    if (!MmIsAddressValid(ObjHeader))
        return;

    if (TypeFromObject(ObjHeader) == *PsProcessType)
    {
        this->GrabProcess((PEPROCESS)Obj);
    }

    if (TypeFromObject(ObjHeader) == *PsThreadType)
    {
        this->GrabProcess(KdThreadToProcess((PETHREAD)Obj));
        this->GrabProcess(KdThreadToProcess((PETHREAD)Obj, TRUE));
    }
}


BOOLEAN CProcess::IsFound(PEPROCESS Process)
{
    ULONG c;
    for	(c = 0; c < this->ProcessCount; ++c)
    {
        if (this->ProcessArray[c] == Process) return TRUE;
    }
    return FALSE;
}
