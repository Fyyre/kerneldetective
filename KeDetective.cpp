#include "KeDetective.h"
#include "process.h"
#include "dll.h"
#include "ssdt.h"
#include "interrupt.h"
#include "debugv.h"
#include "fsd.h"
#include "unhook.h"
#include "module.h"
#include "handle.h"
#include "Thread.h"



//#define NT_DEVICE_NAME  L"\\Device\\KeDetective"
//#define DOS_DEVICE_NAME  L"\\DosDevices\\KeDetective"


// NtQuerySystemInformation
NTSTATUS
(NTAPI *KdQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

// NtTerminateProcess
NTSTATUS
(NTAPI *KdTerminateProcess)(IN HANDLE ProcessHandle, IN NTSTATUS  ExitStatus);

// NtTerminateThread
NTSTATUS
(NTAPI *KdTerminateThread)(IN HANDLE ThreadHandle, IN NTSTATUS  ExitStatus);

// KeStackAttachProcess
VOID
(NTAPI *KdStackAttachProcess)(PKPROCESS Process, PKAPC_STATE ApcState);

// KeUnstackDetachProcess
VOID
(NTAPI *KdUnstackDetachProcess)(PKAPC_STATE ApcState);

// PsLookupProcessByProcessId
NTSTATUS
(NTAPI *KdLookupProcessByProcessId)(HANDLE ProcessId, PEPROCESS *Process);

// PsLookupThreadByThreadId
NTSTATUS
(NTAPI *KdLookupThreadByThreadId)(PVOID UniqueThreadId, PETHREAD    *Thread);

// ObOpenObjectByPointer
NTSTATUS
(NTAPI *KdOpenObjectByPointer)(PVOID Object, ULONG HandleAttributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType OPTIONAL, KPROCESSOR_MODE AccessMode, PHANDLE Handle);

// NtClose
NTSTATUS
(NTAPI *KdClose)(HANDLE Handle);

// NtOpenFile
NTSTATUS
(NTAPI *KdOpenFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);

// NtAllocateVirtualMemory
NTSTATUS
(NTAPI *KdAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

// NtFreeVirtualMemory
NTSTATUS
(NTAPI *KdFreeVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

// MmGetPhysicalAddress
ULONGLONG
(NTAPI *KdGetPhysicalAddress)(PVOID BaseAddress);

// MmGetVirtualForPhysical
PVOID
(NTAPI *KdGetVirtualForPhysical)(ULONGLONG PhysicalAddress);

// NtReadVirtualMemory
NTSTATUS
(NTAPI *KdReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);

// NtWriteVirtualMemory
NTSTATUS
(NTAPI *KdWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);

// NtProtectVirtualMemory
NTSTATUS
(NTAPI *KdProtectVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

// NtQueryVirtualMemory
NTSTATUS
(NTAPI *KdQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, ULONG MemoryInformationLength, PULONG ReturnLength OPTIONAL);

// NtFlushInstructionCache
NTSTATUS
(NTAPI *KdFlushInstructionCache)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG FlushSize);

// NtOpenProcess
NTSTATUS
(NTAPI *KdOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

// NtOpenThread
NTSTATUS
(NTAPI *KdOpenThread)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

// MmCopyVirtualMemory
NTSTATUS
(NTAPI *MmCopyVirtualMemory)(PEPROCESS FromProcess, PVOID FromAddress, PEPROCESS ToProcess, PVOID ToAddress, ULONG BufferSize, KPROCESSOR_MODE PreviousMode, PULONG NumberOfBytesCopied);

// NtDuplicateObject
NTSTATUS
(NTAPI *KdDuplicateObject)(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);

// ExEnumHandleTable
BOOLEAN
(NTAPI *KdEnumHandleTable)(PHANDLE_TABLE HandleTable, EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure, PVOID EnumParameter, PHANDLE Handle OPTIONAL);

// KeInsertQueueApc
BOOLEAN
(NTAPI *KdInsertQueueApc)(PKAPC Apc, PVOID SystemArgument1, PVOID SystemArgument2, KPRIORITY Increment);

// PsTerminateSystemThread
NTSTATUS
(NTAPI *KdTerminateSystemThread)(NTSTATUS ExitStatus);

// ObReferenceObjectByHandle
NTSTATUS
(NTAPI *KdReferenceObjectByHandle)(HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType OPTIONAL, KPROCESSOR_MODE AccessMode, PVOID *Object, POBJECT_HANDLE_INFORMATION HandleInformation OPTIONAL);

// ObOpenObjectByName
NTSTATUS
(NTAPI *KdOpenObjectByName)(POBJECT_ATTRIBUTES ObjectAttributes,  POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PACCESS_STATE AccessState, ACCESS_MASK DesiredAccess, PVOID ParseContext, PHANDLE Handle);

// NtResumeThread
NTSTATUS
(NTAPI *KdResumeThread)(HANDLE ThreadHandle, PULONG SuspendCount);

// NtOpenDirectoryObject
NTSTATUS
(NTAPI *KdOpenDirectoryObject)(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

// NtUnloadDriver
NTSTATUS
(NTAPI *KdUnloadDriver)(PUNICODE_STRING RegistryPath);

// Ke386CallBios
NTSTATUS
(NTAPI *Kd386CallBios)(ULONG BiosCommand, PCONTEXT BiosArguments);

// MmMapViewOfSection
NTSTATUS
(NTAPI *KdMapViewOfSection)(PVOID SectionObject, PEPROCESS Process, PVOID *BaseAddress, ULONG ZeroBits, ULONG CommitSize, PLARGE_INTEGER SectionOffset, PULONG ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect);

// KdUnmapViewOfSection
NTSTATUS
(NTAPI *KdUnmapViewOfSection)(PEPROCESS Process, PVOID BaseAddress);

// KeDeregisterBugCheckReasonCallback
BOOLEAN
(NTAPI *KdDeregisterBugCheckReasonCallback)(PKBUGCHECK_REASON_CALLBACK_RECORD CallbackRecord);

// KeFlushQueuedDpcs
VOID
(NTAPI *KdFlushQueuedDpcs)(VOID);

// PsGetContextThread
NTSTATUS
(NTAPI *KdGetContextThread)(PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE Mode);

// PsSetContextThread
NTSTATUS
(NTAPI *KdSetContextThread)(PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE Mode);

// PsSuspendThread
NTSTATUS
(NTAPI *KdSuspendThread)(PKTHREAD Thread, PULONG PreviousCount);

// KeAlertThread
BOOLEAN
(NTAPI *KdAlertThread)(PKTHREAD Thread, KPROCESSOR_MODE AlertMode);




WCHAR nt_DeviceName[MAX_PATH], dos_DeviceName[MAX_PATH];
PVOID KernelBase;
ULONG KernelSize;
PVOID ntoskrnl;
ULONG KernelDelta;
PVOID w32kBase;
ULONG w32kSize;
PVOID w32k;
ULONG w32kDelta;
WCHAR CurrentKernel[MAX_PATH] = L"ntoskrnl.exe";
WCHAR SystemrootPath[MAX_PATH];
PKDDEBUGGER_DATA64 KdVersionBlock;
PLATFORM_OPTIONS info;
SHORT KdBuildNumber;
POBJECT_TYPE TypesArray[256];
PDRIVER_OBJECT KdDriverObject;
ERESOURCE DispatchResourceObject;
PEPROCESS CsrProcess;

PEX_CALLBACK PspLoadImageNotifyRoutine;
PEX_CALLBACK PspCreateProcessNotifyRoutine;
PEX_CALLBACK PspCreateThreadNotifyRoutine;
PEX_CALLBACK PspLegoNotifyRoutine;
PEX_CALLBACK CmpCallBackVector;
PLIST_ENTRY CmCallbackListHead;
PLIST_ENTRY KeBugCheckCallbackListHead;
PLIST_ENTRY KeBugCheckReasonCallbackListHead;


ULONG MaxCreateProcess;




BOOLEAN GetNotifyRoutinesHeadLists()
{
    ULONG Index;
    PUCHAR ptrCodeBase, ptrCode, ptrAcqPushLock;
    BOOLEAN AcqPushLockFound = FALSE;

    VMProtectBegin;
    Index = 0;
    ptrCodeBase = (PUCHAR)KdGetSystemRoutineAddress(L"PsSetLoadImageNotifyRoutine");
    while (Index < 0x64)
    {
        ptrCode = ptrCodeBase + Index;
        Index += SizeOfCode(ptrCode, NULL);
        if (ptrCode[0] == 0xbe) // mov esi, offset
        {
            if (ptrCode[5] == 0x6a && ptrCode[6] == 0x00) // push 0x00
            {
                PspLoadImageNotifyRoutine = *(PEX_CALLBACK *)(ptrCode + 1);
                break;
            }
            else if (ptrCode[7] == 0x6a && ptrCode[8] == 0x00) // push 0x00
            {
                PspLoadImageNotifyRoutine = *(PEX_CALLBACK *)(ptrCode + 1);
                break;
            }
        }
    }

    if (!PspLoadImageNotifyRoutine || !MmIsAddressValid(PspLoadImageNotifyRoutine))
    {
        return FALSE;
    }

    KeBugCheckCallbackListHead = (PLIST_ENTRY)KdVersionBlock->KeBugCheckCallbackListHead;
    KeBugCheckReasonCallbackListHead = KeBugCheckCallbackListHead - 1;

    switch (KdBuildNumber)
    {
    case 2600:
        PspCreateProcessNotifyRoutine = (PEX_CALLBACK)((PCHAR)PspLoadImageNotifyRoutine + 0x60);
        PspCreateThreadNotifyRoutine = (PEX_CALLBACK)((PCHAR)PspLoadImageNotifyRoutine + 0x20);
        break;
    case 6000:
        PspCreateProcessNotifyRoutine = (PEX_CALLBACK)((PCHAR)PspLoadImageNotifyRoutine + 0x80);
        PspCreateThreadNotifyRoutine = (PEX_CALLBACK)((PCHAR)PspLoadImageNotifyRoutine + 0x40);
        break;
    case 6001:
    case 6002:
    case 7600:
    case 7601:
        PspCreateProcessNotifyRoutine = (PEX_CALLBACK)((PCHAR)PspLoadImageNotifyRoutine + 0x160);
        PspCreateThreadNotifyRoutine = (PEX_CALLBACK)((PCHAR)PspLoadImageNotifyRoutine + 0x40);
        break;
    }
    PspLegoNotifyRoutine = *(PEX_CALLBACK *)((PCHAR)KdGetSystemRoutineAddress(L"PsSetLegoNotifyRoutine") + 9);

    Index = 0;
    ptrCodeBase = (PUCHAR)KdGetSystemRoutineAddress(L"CmUnRegisterCallback");
    ptrAcqPushLock = (PUCHAR)KdGetSystemRoutineAddress(L"ExfAcquirePushLockExclusive");
    while (Index < 256)
    {
        ptrCode = ptrCodeBase + Index;
        Index += SizeOfCode(ptrCode, NULL);
        if (IsXp)
        {
            if ((ptrCode[0] & 0xf0) == 0xb0)
            {
                if ((ptrCode[0] & 0x0f) >= 0x8 && (ptrCode[0] & 0x0f) <= 0xf)
                {
                    CmpCallBackVector = *(PEX_CALLBACK *)(ptrCode + 1);
                    break;
                }
            }
        }
        else
        {
            if (!AcqPushLockFound)
            {
                if (ptrCode[0] == 0xe8)
                {
                    PUCHAR Call = *(PUCHAR *)(ptrCode + 1) + (ULONG_PTR)ptrCode + 5;
                    if (Call == ptrAcqPushLock)
                    {
                        AcqPushLockFound = TRUE;
                    }
                }
            }
            else
            {
                if ((ptrCode[0] & 0xf0) == 0xb0)
                {
                    if ((ptrCode[0] & 0x0f) >= 0x8 && (ptrCode[0] & 0x0f) <= 0xf)
                    {
                        CmCallbackListHead = *(PLIST_ENTRY *)(ptrCode + 1);
                        break;
                    }
                }
            }
        }
    }


    Print("PspLoadImageNotifyRoutine = %p", PspLoadImageNotifyRoutine);
    Print("PspCreateProcessNotifyRoutine = %p", PspCreateProcessNotifyRoutine);
    Print("PspCreateThreadNotifyRoutine = %p", PspCreateThreadNotifyRoutine);
    Print("PspLegoNotifyRoutine = %p", PspLegoNotifyRoutine);
    Print("KeBugCheckCallbackListHead = %p", KeBugCheckCallbackListHead);
    Print("KeBugCheckReasonCallbackListHead = %p", KeBugCheckReasonCallbackListHead);
    if (IsXp)
    {
        Print("CmpCallBackVector = %p", CmpCallBackVector);
    }
    else
    {
        Print("CmCallbackListHead = %p", CmCallbackListHead);
    }


    VMProtectEnd;
    return TRUE;
}


ULONG EnumTimerObjects(PTIMER_ENTRY *ptrBuffer)
{
    PLIST_ENTRY KiTimerTableListHead, ListHead, NextEntry;
    ULONG Index, TIMER_TABLE_SIZE, ThreadOffset, Count = 0;
    PKTIMER Timer;
    PTIMER_ENTRY TimerInfo = NULL;
    PKTHREAD Thread;

    if (IsXp)
    {
        TIMER_TABLE_SIZE = 256;
        KiTimerTableListHead = (PLIST_ENTRY)((ULONG_PTR)KdServiceDescriptorTable + 0x80);
        ThreadOffset = FIELD_OFFSET(KTHREAD, Timer);
    }
    else
    {
        TIMER_TABLE_SIZE = 512;
        if (IsVista)
        {
            KiTimerTableListHead = (PLIST_ENTRY)((ULONG_PTR)PsIdleProcess + 0x280);
            ThreadOffset = 0x88;
        }
        else if (IsWin7)
        {
            ThreadOffset = 0x90;
            TIMER_TABLE_SIZE = 256;
        }
    }

    if (IsWin7)
    {
        for (CCHAR i = 0; i < KeNumberProcessors; i++)
        {
            PCHAR Prcb = NULL;
            KAFFINITY Affinity = 1 << i;
            KeSetAffinityThread(KeGetCurrentThread(), Affinity);
            __asm mov eax, _PCR KPCR.Prcb;
            __asm mov Prcb, eax;
            Affinity = KeQueryActiveProcessors();
            KeSetAffinityThread(KeGetCurrentThread(), Affinity);
            if (Prcb)
            {
                KiTimerTableListHead = (PLIST_ENTRY)(Prcb + 0x19A0); // TimerTable
                Print("WIN7 : KiTimerTableListHead = %p", KiTimerTableListHead);
                Index = 0;
                do
                {
                    ListHead = (PLIST_ENTRY)((ULONG_PTR)&KiTimerTableListHead[Index*3] + 0x4);
                    if (!MmIsAddressValid(ListHead->Flink)) 
                        break;
                    NextEntry = ListHead->Flink;
                    while (NextEntry != ListHead)
                    {
			            POBJECT_HEADER ThreadHeader;
                        Timer = CONTAINING_RECORD(NextEntry, KTIMER, TimerListEntry);
			            Thread = (PKTHREAD)((ULONG_PTR)Timer - ThreadOffset);
			            ThreadHeader = OBJECT_TO_OBJECT_HEADER(Thread);
                        Print("Timer = %p", Timer);
			            if (Timer->Dpc != NULL || (MmIsAddressValid(ThreadHeader) && TypeFromObject(ThreadHeader) == *PsThreadType))
			            {
				            TimerInfo = (PTIMER_ENTRY)MmRealloc(TimerInfo, (Count + 1) * sizeof(TIMER_ENTRY));
				            TimerInfo[Count].Object = Timer;
				            TimerInfo[Count].Timer = *Timer;
				            if (Timer->Dpc)
				            {
					            TimerInfo[Count].Dpc = *Timer->Dpc;
				            }
            	            
				            if (MmIsAddressValid(ThreadHeader) && TypeFromObject(ThreadHeader) == *PsThreadType)
				            {
					            TimerInfo[Count].Thread = Thread;
				            }

				            Count += 1;
			            }
                        NextEntry = NextEntry->Flink;
                    }

                    Index += 1;
                } while (Index < TIMER_TABLE_SIZE);
            }
        }
    }
    else
    {
        Print("KiTimerTableListHead = %p", KiTimerTableListHead);
        Index = 0;
        do
        {
            if (IsXp)
            {
                ListHead = &KiTimerTableListHead[Index];
            }
            else
            {
                ListHead = &KiTimerTableListHead[Index*2];
            }
            if (!MmIsAddressValid(ListHead->Flink)) break;
            NextEntry = ListHead->Flink;
            while (NextEntry != ListHead)
            {
			    POBJECT_HEADER ThreadHeader;
                Timer = CONTAINING_RECORD(NextEntry, KTIMER, TimerListEntry);
			    Thread = (PKTHREAD)((ULONG_PTR)Timer - ThreadOffset);
			    ThreadHeader = OBJECT_TO_OBJECT_HEADER(Thread);
                Print("Timer = %p", Timer);
			    if (Timer->Dpc != NULL || (MmIsAddressValid(ThreadHeader) && TypeFromObject(ThreadHeader) == *PsThreadType))
			    {
				    TimerInfo = (PTIMER_ENTRY)MmRealloc(TimerInfo, (Count + 1) * sizeof(TIMER_ENTRY));
				    TimerInfo[Count].Object = Timer;
				    TimerInfo[Count].Timer = *Timer;
				    if (Timer->Dpc)
				    {
					    TimerInfo[Count].Dpc = *Timer->Dpc;
				    }
    	            
				    if (MmIsAddressValid(ThreadHeader) && TypeFromObject(ThreadHeader) == *PsThreadType)
				    {
					    TimerInfo[Count].Thread = Thread;
				    }

				    Count += 1;
			    }
                NextEntry = NextEntry->Flink;
            }

            Index += 1;
        } while (Index < TIMER_TABLE_SIZE);
    }

    *ptrBuffer = TimerInfo;
    return Count;
}


VOID GetObjectTypeInfo(PVOID Object, POBJECT_TYPE_ENTRY ptrBuffer)
{
    ULONG_PTR ProcedureTableOffset, IndexOffset, TotalNumberOffset, NameOffset;
    PUNICODE_STRING Name;

    if (KdBuildNumber >= 6001)
    {
        ProcedureTableOffset = 0x58;
        IndexOffset = 0x14;
        TotalNumberOffset = 0x18;
        NameOffset = 0x8;
    }
    else
    {
        ProcedureTableOffset = (ULONG_PTR)&((POBJECT_TYPE)0)->TypeInfo.DumpProcedure;
        IndexOffset = FIELD_OFFSET(OBJECT_TYPE, ObjectTypeIndex);
        TotalNumberOffset = FIELD_OFFSET(OBJECT_TYPE, ObjectCount);
        NameOffset = FIELD_OFFSET(OBJECT_TYPE, ObjectTypeName);
    }
    ptrBuffer->Address = Object;
    ptrBuffer->Count = *(PULONG)((ULONG_PTR)Object + TotalNumberOffset);
    ptrBuffer->Index = *(PUCHAR)((ULONG_PTR)Object + IndexOffset);
    RtlCopyMemory(&ptrBuffer->ProcedureTable, ((PCHAR)Object + ProcedureTableOffset), sizeof(ptrBuffer->ProcedureTable));
    Name = (PUNICODE_STRING)((ULONG_PTR)Object + NameOffset);
    RtlCopyMemory(ptrBuffer->Name, Name->Buffer, Name->MaximumLength > sizeof(ptrBuffer->Name) ? sizeof(ptrBuffer->Name) : Name->MaximumLength);
}


typedef struct _BUGCHECK_CALLBACK
{
    PVOID Record;
    PVOID Routine;
    PVOID Buffer;
    KBUGCHECK_CALLBACK_REASON State;
    WCHAR Name[256];
}BUGCHECK_CALLBACK, *PBUGCHECK_CALLBACK;



PBUGCHECK_CALLBACK KiScanBugCheckReasonCallbackList(ULONG &Count)
{
    PKBUGCHECK_REASON_CALLBACK_RECORD CallbackRecord;
    ULONG_PTR Checksum;
    PLIST_ENTRY LastEntry;
    PLIST_ENTRY ListHead;
    PLIST_ENTRY NextEntry;
    PUCHAR Va;
    ULONG Pages;
    PBUGCHECK_CALLBACK Result;

    //
    // If the bugcheck callback listhead is not initialized, then the
    // bugcheck has occured before the system has gotten far enough
    // in the initialization code to enable anyone to register a callback.
    //

    Count = 0;
    Result = NULL;
    ListHead = KeBugCheckReasonCallbackListHead;
    if (ListHead->Flink == NULL || ListHead->Blink == NULL)
    {
        return Result;
    }

    //
    // Scan the bugcheck callback list.
    //

    LastEntry = ListHead;
    NextEntry = ListHead->Flink;
    while (NextEntry != ListHead)
    {

        //
        // The next entry address must be aligned properly, the
        // callback record must be readable, and the callback record
        // must have back link to the last entry.
        //
        if (((ULONG_PTR)NextEntry & (sizeof(ULONG_PTR) - 1)) != 0)
        {
            return Result;
        }

        CallbackRecord = CONTAINING_RECORD(NextEntry, KBUGCHECK_REASON_CALLBACK_RECORD, Entry);

        //
        // Verify that the callback record is still valid.
        //
        Va = (PUCHAR)PAGE_ALIGN(CallbackRecord);
        Pages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(CallbackRecord, sizeof (*CallbackRecord));
        while (Pages)
        {
            if (!MmIsAddressValid(Va))
            {
                return Result;
            }
            Va += PAGE_SIZE;
            Pages--;
        }

        if (CallbackRecord->Entry.Blink != LastEntry)
        {
            return Result;
        }

        LastEntry = NextEntry;
        NextEntry = NextEntry->Flink;

        //
        // If the callback record has a state of inserted and the
        // computed checksum matches the callback record checksum,
        // then call the specified bugcheck callback routine.
        //

        Checksum = (ULONG_PTR)CallbackRecord->CallbackRoutine;
        Checksum += (ULONG_PTR)CallbackRecord->Reason;
        Checksum += (ULONG_PTR)CallbackRecord->Component;
        if ((CallbackRecord->State != BufferInserted) ||
                (CallbackRecord->Checksum != Checksum) ||
                MmIsAddressValid((PVOID)(ULONG_PTR)CallbackRecord->CallbackRoutine) == FALSE)
        {
            continue;
        }

        //
        // Call the specified bugcheck callback routine and
        // handle any exceptions that occur.
        //

        Result = (PBUGCHECK_CALLBACK)MmRealloc(Result, (Count + 1) * sizeof(BUGCHECK_CALLBACK));
        Result[Count].Record = CallbackRecord;
        Result[Count].Routine = CallbackRecord->CallbackRoutine;
        Result[Count].Buffer = NULL;
        Result[Count].State = CallbackRecord->Reason;
        if (CallbackRecord->Component)
        {
            _snwprintf(Result[Count].Name, 256, L"%S", CallbackRecord->Component);
        }
        Count += 1;
    }

    return Result;
}


PBUGCHECK_CALLBACK KiScanBugCheckCallbackList(ULONG &Count)
{
    PKBUGCHECK_CALLBACK_RECORD CallbackRecord;
    ULONG_PTR Checksum;
    ULONG Index;
    PLIST_ENTRY LastEntry;
    PLIST_ENTRY ListHead;
    PLIST_ENTRY NextEntry;
    PUCHAR Source;
    PBUGCHECK_CALLBACK Result;

    //
    // If the bugcheck callback listhead is not initialized, then the
    // bugcheck has occured before the system has gotten far enough
    // in the initialization code to enable anyone to register a callback.
    //

    Count = 0;
    Result = NULL;
    ListHead = KeBugCheckCallbackListHead;
    if ((ListHead->Flink != NULL) && (ListHead->Blink != NULL))
    {

        //
        // Scan the bugcheck callback list.
        //
        LastEntry = ListHead;
        NextEntry = ListHead->Flink;
        while (NextEntry != ListHead)
        {

            //
            // The next entry address must be aligned properly, the
            // callback record must be readable, and the callback record
            // must have back link to the last entry.
            //
            if (((ULONG_PTR)NextEntry & (sizeof(ULONG_PTR) - 1)) != 0)
            {
                return Result;
            }
            else
            {
                CallbackRecord = CONTAINING_RECORD(NextEntry, KBUGCHECK_CALLBACK_RECORD, Entry);

                Source = (PUCHAR)CallbackRecord;
                for (Index = 0; Index < sizeof(KBUGCHECK_CALLBACK_RECORD); Index += 1)
                {
                    if (MmIsAddressValid((PVOID)Source) == FALSE)
                    {
                        return Result;
                    }
                    Source += 1;
                }

                if (CallbackRecord->Entry.Blink != LastEntry)
                {
                    return Result;
                }

                //
                // If the callback record has a state of inserted and the
                // computed checksum matches the callback record checksum,
                // then call the specified bugcheck callback routine.
                //

                Checksum = (ULONG_PTR)CallbackRecord->CallbackRoutine;
                Checksum += (ULONG_PTR)CallbackRecord->Buffer;
                Checksum += CallbackRecord->Length;
                Checksum += (ULONG_PTR)CallbackRecord->Component;
                if ((CallbackRecord->State == BufferInserted) &&
                        (CallbackRecord->Checksum == Checksum))
                {

                    //
                    // Call the specified bugcheck callback routine and
                    // handle any exceptions that occur.
                    //

                    Result = (PBUGCHECK_CALLBACK)MmRealloc(Result, (Count + 1) * sizeof(BUGCHECK_CALLBACK));
                    Result[Count].Record = CallbackRecord;
                    Result[Count].Routine = CallbackRecord->CallbackRoutine;
                    Result[Count].Buffer = CallbackRecord->Buffer;
                    Result[Count].State = KbCallbackInvalid;
                    if (CallbackRecord->Component)
                    {
                        _snwprintf(Result[Count].Name, 256, L"%S", CallbackRecord->Component);
                    }
                    Count += 1;
                }
            }

            LastEntry = NextEntry;
            NextEntry = NextEntry->Flink;
        }
    }

    return Result;
}


PVOID *EnumCmNotifyRoutines(ULONG &Count)
{
    PVOID *ptrBuffer = NULL;

    Count = 0;
    if (IsXp)
    {
        PEX_CALLBACK Callback;
        PEX_CALLBACK_ROUTINE_BLOCK CallbackRoutineBlock;

        if (!MmIsAddressValid(CmpCallBackVector)) return NULL;
        for (ULONG Index = 0; Index < CM_MAX_CALLBACKS; ++Index)
        {
            Callback = &CmpCallBackVector[Index];
            if (Callback->RoutineBlock.Value)
            {
                ptrBuffer = (PVOID *)MmRealloc(ptrBuffer, (Count + 1) * sizeof(PVOID));
                CallbackRoutineBlock = (PEX_CALLBACK_ROUTINE_BLOCK)(Callback->RoutineBlock.Value & ~MAX_FAST_REFS);
                ptrBuffer[Count] = CallbackRoutineBlock->Function;
                Count++;
            }
        }
    }
    else
    {
        PLIST_ENTRY ListEntry;
        PCM_VISTA_CALLBACK_BLOCK CallbackRoutineBlock;

        if (!MmIsAddressValid(CmCallbackListHead)) return NULL;
        ListEntry = CmCallbackListHead->Flink;
        while (ListEntry != CmCallbackListHead)
        {
            ptrBuffer = (PVOID *)MmRealloc(ptrBuffer, (Count + 1) * sizeof(PVOID));
            CallbackRoutineBlock = CONTAINING_RECORD(ListEntry, CM_VISTA_CALLBACK_BLOCK, CallbackListHead);
            Print("Callback = %p", CallbackRoutineBlock->Function);
            ptrBuffer[Count] = CallbackRoutineBlock->Function;
            ListEntry = ListEntry->Flink;
            Count++;
        }
    }

    return ptrBuffer;
}


PDEVICE_OBJECT IoGetLowestDeviceObject(PDEVICE_OBJECT Source)
{
	PDEVICE_OBJECT deviceObject = Source;
	PDEVICE_EXTENSION deviceExtension;
    ULONG Count = 0;

	while (deviceObject && Count < 64) {

		deviceExtension = (PDEVICE_EXTENSION)deviceObject->DeviceObjectExtension;

		if (deviceExtension == NULL)
			break;

		if (deviceExtension->AttachedTo == NULL)
			break;

		deviceObject = deviceExtension->AttachedTo;

        Count += 1;

	}

	return deviceObject;
}


NTSTATUS IoGetDeviceObjectByName(PWCHAR deviceName, PDEVICE_OBJECT *deviceObject)
{
	NTSTATUS status;
	IO_STATUS_BLOCK ioStatus;
	UNICODE_STRING unDeviceName;
	OBJECT_ATTRIBUTES objectAttributes;
	HANDLE fileHandle;
	PFILE_OBJECT fileObject;
    KPROCESSOR_MODE PrevMode;


	*deviceObject = NULL;
	RtlInitUnicodeString(&unDeviceName, deviceName);
	InitializeObjectAttributes(&objectAttributes,
                               &unDeviceName,
                               OBJ_KERNEL_HANDLE,
                               (HANDLE)NULL,
                               (PSECURITY_DESCRIPTOR)NULL);

    PrevMode = KeSetPreviousMode(KernelMode);
	status = KdOpenFile(&fileHandle, 
						  FILE_READ_ATTRIBUTES,
						  &objectAttributes,
						  &ioStatus,
						  0, 
						  FILE_NON_DIRECTORY_FILE);

	if (NT_SUCCESS(status)) {

		status = KdReferenceObjectByHandle(fileHandle,
                                           SYNCHRONIZE,
                                           *IoFileObjectType,
										   KernelMode,
                                           (PVOID *)&fileObject,
                                           NULL);

		if (NT_SUCCESS(status)) {

			*deviceObject = IoGetBaseFileSystemDeviceObject(fileObject);
			ObDereferenceObject(fileObject);
		}

		ZwClose(fileHandle);
	}

    KeSetPreviousMode(PrevMode);
	return status;
}


NTSTATUS ReadWriteSector(ULONG DiskNumber, ULONG SectorNumber, USHORT SectorCount,BOOL IsWrite, PVOID Buffer)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    PDEVICE_OBJECT deviceObject = NULL;
    PDRIVER_OBJECT driverObject = NULL;
    WCHAR deviceName[512];
    PVOID NonpagedBuffer;
    CDevice iDevice;


    VMProtectBegin;
    NonpagedBuffer = MmAlloc(SectorCount * 512);
    if (NonpagedBuffer)
    {
        if (IsWrite)
            RtlCopyMemory(NonpagedBuffer, Buffer, SectorCount * 512);

        _snwprintf(deviceName, 512, L"\\??\\PhysicalDrive%d", DiskNumber, DiskNumber);
        ntStatus = IoGetDeviceObjectByName(deviceName, &deviceObject);
	    Print("DeviceObject = %p", deviceObject);
	    if (NT_SUCCESS(ntStatus) && deviceObject)
	    {
		    deviceObject = IoGetLowestDeviceObject(deviceObject);
		    Print("DeviceObject = %p", deviceObject);
		    driverObject = deviceObject->DriverObject;
		    Print("driverObject = %p", driverObject);
		    if (driverObject->DriverExtension && driverObject->DriverExtension->DriverObject)
		    {
			    driverObject = driverObject->DriverExtension->DriverObject;
			    Print("driverObject = %p", driverObject);
		    }
		    if (deviceObject)
		    {
			    Print("dev -> %p, drv -> %p", deviceObject, driverObject);
			    ntStatus = ReadWriteDisk(driverObject, deviceObject, SectorNumber, SectorCount, IsWrite, NonpagedBuffer);
			    Print("ReadDisk = %p", ntStatus);
			    if (NT_SUCCESS(ntStatus))
			    {
                    if (!IsWrite)
                        RtlCopyMemory(Buffer, NonpagedBuffer, SectorCount * 512);
			    }
		    }
	    }
        MmFree(NonpagedBuffer);
    }

    VMProtectEnd;
    return ntStatus;
}


NTSTATUS SendIoPacket(PKD_IO_PACKET IoPacket)
{
    NTSTATUS status;
    PIRP Irp;
    IO_STATUS_BLOCK IoStatus;
    KEVENT Event;


    if (IoPacket->DeviceObject == NULL && (IoPacket->FileObject == NULL || !MmIsAddressValid(IoPacket->FileObject)))
        return STATUS_INVALID_PARAMETER;

    if (IoPacket->DeviceObject == NULL)
        IoPacket->DeviceObject = IoPacket->FileObject->DeviceObject;

    Irp = NULL;
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    switch (IoPacket->MajorFunction)
    {
    case IRP_MJ_READ:
        Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ,
                                           IoPacket->DeviceObject,
                                           IoPacket->Parameters.Read.Buffer,
                                           IoPacket->Parameters.Read.Length,
                                           IoPacket->Parameters.Read.StartingOffset,
                                           &Event,
                                           &IoStatus);
        break;

    case IRP_MJ_WRITE:
        Irp = IoBuildSynchronousFsdRequest(IRP_MJ_WRITE,
                                           IoPacket->DeviceObject,
                                           IoPacket->Parameters.Write.Buffer,
                                           IoPacket->Parameters.Write.Length,
                                           IoPacket->Parameters.Write.StartingOffset,
                                           &Event,
                                           &IoStatus);
        break;

    case IRP_MJ_DEVICE_CONTROL:
        Irp = IoBuildDeviceIoControlRequest(IoPacket->Parameters.DeviceIoControl.IoControlCode,
                                            IoPacket->DeviceObject,
                                            IoPacket->Parameters.DeviceIoControl.InputBuffer,
                                            IoPacket->Parameters.DeviceIoControl.InputBufferLength,
                                            IoPacket->Parameters.DeviceIoControl.OutputBuffer,
                                            IoPacket->Parameters.DeviceIoControl.OutputBufferLength,
                                            IoPacket->Parameters.DeviceIoControl.InternalDeviceIoControl,
                                            &Event,
                                            &IoStatus);
        break;

    default:
        return STATUS_NOT_IMPLEMENTED;
    }

    if (Irp == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        if (IoPacket->FileObject)
            IoGetNextIrpStackLocation(Irp)->FileObject = IoPacket->FileObject;

        status = FsCallDriver(NULL, IoPacket->DeviceObject, Irp);

        if (status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            status = IoStatus.Status;
        }
    }

    Print("status = %p", status);

    return status;
}

typedef struct _NULL_THREAD_CONTEXT {
	PVOID			Process;
	PKSTART_ROUTINE StartAddress;
	PVOID			Context;
}NULL_THREAD_CONTEXT, *PNULL_THREAD_CONTEXT;

VOID NullSystemThread(IN PVOID StartContext)
{
	PNULL_THREAD_CONTEXT Context = (PNULL_THREAD_CONTEXT)StartContext;
    KAPC_STATE ApcState;


	if (Context->Process != NULL && Context->Process != PsInitialSystemProcess)
	    KdStackAttachProcess((PKPROCESS)Context->Process, &ApcState);

    Context->StartAddress(Context->Context);
	
    if (Context->Process != NULL && Context->Process != PsInitialSystemProcess)
	    KdUnstackDetachProcess(&ApcState);

	MmFree(Context);
	PsTerminateSystemThread(STATUS_SUCCESS);
}


NTSTATUS
IoDispatchHandler(
    ULONG ControlCode,
    PKI_PACKET KiPacket
)
{
    VMProtectBegin;

    NTSTATUS Status = STATUS_SUCCESS;
    PVOID BaseAddress = NULL;
    SIZE_T RegionSize = 0;


    switch (ControlCode)
    {
    case IOCTL_INITIALIZE:
    {
        Status = Initialize(KiPacket);
        break;
    }
    case IOCTL_ENUM_PROCESS:
    {
        CProcess Process;
        PPROCESS_ENTRY lpProcesses;
        ULONG c;

        DispatchLock lock;
        lock.Lock();

        CThread Thread;
        Thread.ScanCidTable();
        Thread.ScanKiWaitList();
        //Thread.ScanProcessList();
        Thread.ScanTypeList();

        Process.GrabProcess(PsIdleProcess);
        Process.ScanCidTable();
        Process.ScanTypeList();
        Process.ScanSessionList();

        for (c = 0; c < Thread.ThreadCount; ++c)
        {
            Process.GrabProcess(KdThreadToProcess(Thread.ThreadArray[c], TRUE));
            Process.GrabProcess(KdThreadToProcess(Thread.ThreadArray[c], FALSE));
        }

        for (ULONG i = 0; i < Process.ProcessCount; i++)
        {
            ExAcquireRundownProtection(parseobject(Process.ProcessArray[i], ProcessRundown, EX_RUNDOWN_REF));
        }

        lock.Unlock();

        /*if (KiPacket->Parameters.ProcessEnumerate.Flags & PROCESS_SCAN_BRUTE)
        {
            Thread.ScanHandles();
            Process.ScanHandles();
        }*/
        
        RegionSize = Process.ProcessCount * sizeof(PROCESS_ENTRY);
        BaseAddress = 0;
        Status = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
        if (Status == STATUS_SUCCESS)
        {
            KiPacket->Parameters.ProcessEnumerate.Processes = (PPROCESS_ENTRY)BaseAddress;
            KiPacket->Parameters.ProcessEnumerate.Count = Process.ProcessCount;
            lpProcesses = (PPROCESS_ENTRY)BaseAddress;
            for (c = 0; c < Process.ProcessCount; ++c)
            {
                GetProcessInfo(Process.ProcessArray[c], lpProcesses);
                ExReleaseRundownProtection(parseobject(Process.ProcessArray[c], ProcessRundown, EX_RUNDOWN_REF));
                lpProcesses += 1;
            }
        }
        break;
    }
    case IOCTL_GET_PROCESS_INFO:
    {
        GetProcessInfo((PEPROCESS)KiPacket->Parameters.ProcessQueryInformation.ProcessObject, KiPacket->Parameters.ProcessQueryInformation.Process);
        break;
    }
    case IOCTL_ENUM_THREADS:
    {
        PEPROCESS Process = (PEPROCESS)KiPacket->Parameters.ThreadEnumerate.ProcessObject;
        CThread Thread(Process);
        PTHREAD_ENTRY lpThreads;
        ULONG c;

        DispatchLock lock;
        lock.Lock();

        Thread.ScanCidTable();
        Thread.ScanKiWaitList();
        Thread.ScanTypeList();
        Thread.ScanProcessList();

        lock.Unlock();

        //if (KiPacket->Parameters.ThreadEnumerate.Flags & PROCESS_SCAN_BRUTE)
        {
            Thread.ScanHandles();
        }
        RegionSize = Thread.ThreadCount * sizeof(THREAD_ENTRY);
        BaseAddress = 0;
        Status = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
        if (Status == STATUS_SUCCESS)
        {
            KiPacket->Parameters.ThreadEnumerate.Threads = (PTHREAD_ENTRY)BaseAddress;
            KiPacket->Parameters.ThreadEnumerate.Count = Thread.ThreadCount;
            lpThreads = (PTHREAD_ENTRY)BaseAddress;
            for (c = 0; c < Thread.ThreadCount; ++c)
            {
                GetThreadInfo(Thread.ThreadArray[c], &lpThreads[c]);
            }
        }
        break;
    }
    case IOCTL_ENUM_DRIVER:
    {
        CDriver Driver;
        PDRIVER_ENTRY lpDrivers;
        ULONG c;

        Driver.Scan();
        Driver.ScanPhysicalMemory();
        RegionSize = Driver.DriverCount * sizeof(DRIVER_ENTRY);
        BaseAddress = 0;
        Status = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
        if (Status == STATUS_SUCCESS)
        {
            KiPacket->Parameters.DriversEnumerate.Drivers = (PDRIVER_ENTRY)BaseAddress;
            KiPacket->Parameters.DriversEnumerate.Count = Driver.DriverCount;
            lpDrivers = (PDRIVER_ENTRY)BaseAddress;
            for (c = 0; c < Driver.DriverCount; ++c)
            {
                GetDriverInfo(&Driver.Objects[c], &lpDrivers[c]);
            }
        }
        break;
    }
    case IOCTL_ENUM_DEVICES:
    {
        CDevice Device;
        PVOID *lpDevices;

        Device.Scan();
        RegionSize = Device.DeviceCount * sizeof(PVOID);
        BaseAddress = 0;
        Status = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
        if (Status == STATUS_SUCCESS)
        {
            KiPacket->Parameters.DevicesEnumerate.DeviceObjects = (PVOID *)BaseAddress;
            KiPacket->Parameters.DevicesEnumerate.Count = Device.DeviceCount;
            lpDevices = (PVOID *)BaseAddress;
            for (ULONG c = 0; c < Device.DeviceCount; ++c)
            {
                lpDevices[c] = Device.DeviceArray[c];
            }
        }
        break;
    }
    case IOCTL_VM_READ:
    {
        Status = KiReadProcessMemory((PEPROCESS)KiPacket->Parameters.VirtualRead.ProcessObject,
                                   KiPacket->Parameters.VirtualRead.VirtualAddress,
                                   KiPacket->Parameters.VirtualRead.Buffer,
                                   KiPacket->Parameters.VirtualRead.Size,
                                   KiPacket->Parameters.VirtualRead.NumberOfBytesRead);
        break;
    }
    case IOCTL_VM_WRITE:
    {
        Status = KiWriteProcessMemory((PEPROCESS)KiPacket->Parameters.VirtualWrite.ProcessObject,
                                    KiPacket->Parameters.VirtualWrite.VirtualAddress,
                                    KiPacket->Parameters.VirtualWrite.Buffer,
                                    KiPacket->Parameters.VirtualWrite.Size,
                                    KiPacket->Parameters.VirtualWrite.NumberOfBytesWritten);
        break;
    }
    case IOCTL_PROCESS_KILL:
    {
        PEPROCESS Process = (PEPROCESS)KiPacket->Parameters.ProcessKill.ProcessObject;
        if (KiPacket->Parameters.ProcessKill.ForceKill)
        {
            if (IoGetCurrentProcess() != Process)
            {
                CThread Thread(Process);
                DispatchLock lock;
                lock.Lock();
                Thread.ScanCidTable();
                Thread.ScanKiWaitList();
                Thread.ScanTypeList();
                Thread.ScanProcessList();
                lock.Unlock();
                for (ULONG c = 0; c < Thread.ThreadCount; ++c)
                {
                    ForceTerminateThread(Thread.ThreadArray[c]);
                }
                ZwYieldExecution();
            }
        }
        else
        {
            if (IoGetCurrentProcess() != Process)
            {
                ForceTerminateProcess(Process);
                ZwYieldExecution();
            }
        }
        break;
    }
    case IOCTL_THREAD_KILL:
    {
        if (KiPacket->Parameters.ThreadKill.ThreadObject != PsGetCurrentThread())
        {
            ForceTerminateThread((PETHREAD)KiPacket->Parameters.ThreadKill.ThreadObject);
            ZwYieldExecution();
        }
        break;
    }
    case IOCTL_ENUM_DLL:
    {
        PEPROCESS Process = (PEPROCESS)KiPacket->Parameters.DllEnumerate.ProcessObject;
        if (Process == PsInitialSystemProcess || Process == PsIdleProcess)
        {
            KiPacket->Parameters.DllEnumerate.Dlls = NULL;
            KiPacket->Parameters.DllEnumerate.Count = 0;
            Status = STATUS_UNSUCCESSFUL;
        }
        else if (ExAcquireRundownProtection(parseobject(Process, ProcessRundown, EX_RUNDOWN_REF)))
        {
            Status = HackDLL(Process, &KiPacket->Parameters.DllEnumerate.Dlls, &KiPacket->Parameters.DllEnumerate.Count);
            ExReleaseRundownProtection(parseobject(Process, ProcessRundown, EX_RUNDOWN_REF));
        }
        else
        {
            KiPacket->Parameters.DllEnumerate.Dlls = NULL;
            KiPacket->Parameters.DllEnumerate.Count = 0;
            Status = STATUS_UNSUCCESSFUL;
        }
        break;
    }
    case IOCTL_UNMAP_SECTION:
    {
        PEPROCESS Process = (PEPROCESS)KiPacket->Parameters.SectionUnmap.ProcessObject;
        PVOID BaseAddress = KiPacket->Parameters.SectionUnmap.SectionBase;
        Status = KdUnmapViewOfSection(Process, BaseAddress);
        break;
    }
    case IOCTL_DBG_MSG:
    {
        KIRQL Irql;
        PVOID Buffer = NULL;
        ULONG Count = DbgCount;

        KiPacket->Parameters.Common.Parameter1 = NULL;
        KiPacket->Parameters.Common.Parameter2 = NULL;

        Irql = LockSpin();
        if (Count)
        {
            Buffer = MmAlloc(Count * sizeof(DBGMSG));
            if (Buffer)
            {
                RtlCopyMemory(Buffer, DbgBuffer, Count * sizeof(DBGMSG));
                MmFree(DbgBuffer);
                DbgCount = 0;
                DbgBuffer = NULL;
            }
        }
        UnlockSpin(Irql);

        if (Buffer)
        {
            RegionSize = Count * sizeof(DBGMSG);
            BaseAddress = 0;
            Status = MmCommitUserBuffer(NtCurrentProcess(), &BaseAddress, RegionSize);
            if (NT_SUCCESS(Status))
            {
                KiPacket->Parameters.Common.Parameter1 = (ULONG_PTR)BaseAddress;
                KiPacket->Parameters.Common.Parameter2 = Count;
                RtlCopyMemory(BaseAddress, Buffer, Count * sizeof(DBGMSG));
            }
            MmFree(Buffer);
        }

        break;
    }
    case IOCTL_ENUM_SSDT:
    {
        HackSSDT((PVOID *)&KiPacket->Parameters.SsdtEnumerate.Ssdt);
        KiPacket->Parameters.SsdtEnumerate.Count = KdServiceDescriptorTable->TableSize;
        break;
    }
    case IOCTL_SET_SSDT:
    {
        volatile PLONG service_addr =
            (PLONG)&KdServiceDescriptorTable->ServiceTable[KiPacket->Parameters.Common.Parameter1];
        ULONG new_service_addr = KiPacket->Parameters.Common.Parameter2;
        MemOpen();
        InterlockedExchange(service_addr, new_service_addr);
        MemClose();
        break;
    }
    case IOCTL_RESTORE_SSDT:
    {
        volatile PLONG service_addr = 0;
        MemOpen();
        for (ULONG c = 0; c < info.Max_ServiceID; ++c)
        {
            service_addr =
                (PLONG)&KdServiceDescriptorTable->ServiceTable[c];
            InterlockedExchange(service_addr, (ULONG)info.SDT[c]);
        }
        MemClose();
        break;
    }
    case IOCTL_ENUM_SHADOW_SSDT:
    {
        HackShadowSSDT((PVOID *)&KiPacket->Parameters.SsdtEnumerate.Ssdt);
        KiPacket->Parameters.SsdtEnumerate.Count = KeServiceDescriptorTableShadow[1].TableSize;
        break;
    }
    case IOCTL_SET_SHADOW_SSDT:
    {
        volatile PLONG service_addr =
            (PLONG)&KeServiceDescriptorTableShadow[1].ServiceTable[KiPacket->Parameters.Common.Parameter1];
        ULONG new_service_addr = KiPacket->Parameters.Common.Parameter2;
        MemOpen();
        InterlockedExchange(service_addr, new_service_addr);
        MemClose();
        break;
    }
    case IOCTL_RESTORE_SHADOW_SSDT:
    {
        volatile PLONG service_addr = 0;
        MemOpen();
        for (ULONG c = 0; c < info.Max_ShadowServiceID; ++c)
        {
            service_addr =
                (PLONG)&KeServiceDescriptorTableShadow[1].ServiceTable[c];
            InterlockedExchange(service_addr, (ULONG)info.ShadowSDT[c]);
        }
        MemClose();
        break;
    }
    case IOCTL_ENUM_IDT:
    {
        HackIDT((PVOID *)&KiPacket->Parameters.InterruptEnumerate.InterruptEntries);
        break;
    }
    case IOCTL_GET_MODULE:
    {
        ModuleFromAddress((PVOID)KiPacket->Parameters.GetModuleInfo.Address, KiPacket->Parameters.GetModuleInfo.GetSymbols, KiPacket->Parameters.GetModuleInfo.GetExports, KiPacket->Parameters.GetModuleInfo.Buffer, KiPacket->Parameters.GetModuleInfo.Size);
        break;
    }
    case IOCTL_IDT_OFFSET:
    {
        KiPacket->Parameters.InterrupHook.Offset = HookInterrup(KiPacket->Parameters.InterrupHook.Index, KiPacket->Parameters.InterrupHook.Offset);
        break;
    }
    case IOCTL_IDT_SELECTOR:
    {
        KiPacket->Parameters.InterrupHook.Selector = HookInterrupSel(KiPacket->Parameters.InterrupHook.Index, KiPacket->Parameters.InterrupHook.Selector);
        break;
    }
    case IOCTL_ENUM_HOOKS:
    {
        PHOOK_ENTRY Block = NULL;
        ULONG Cb = 0, ImageSize;
        PVOID DiskImage, MemoryImage;
        PWCHAR FilePath = KiPacket->Parameters.ImageHooksEnumerate.ImagePath;

        BaseAddress = 0;
        GetModuleRange(&MemoryImage, &ImageSize, wExtractFileName(FilePath));
        if (MemoryImage)
        {
            DiskImage = LoadFile(FilePath, MemoryImage, TRUE);
            if (DiskImage)
            {
                Cb = ScanModule(&Block, (ULONG)DiskImage, (ULONG)MemoryImage, KiPacket->Parameters.ImageHooksEnumerate.Flags);
                if (Block)
                {
                    RegionSize = Cb;
                    Status = MmCommitUserBuffer(NtCurrentProcess(), &BaseAddress, RegionSize);
                    if (Status == STATUS_SUCCESS)
                    {
                        memcpy(BaseAddress, Block, Cb);
                    }
                    MmFree(Block);
                }
                MmFree(DiskImage);
            }
        }
        KiPacket->Parameters.ImageHooksEnumerate.Count = Cb/sizeof(HOOK_ENTRY);
        KiPacket->Parameters.ImageHooksEnumerate.HookEntries = (PHOOK_ENTRY)BaseAddress;
        break;
    }
    case IOCTL_UNHOOK_KERNEL:
    {
        UnhookCode((PVOID)KiPacket->Parameters.Common.Parameter1, KiPacket->Parameters.Common.Parameter2);
        break;
    }
    case IOCTL_ENUM_HANDLES:
    {
        ULONG HandlesCount = 0;
        PHANDLE_ENTRY HandleInformation = (PHANDLE_ENTRY)GetProcessHandles((PEPROCESS)KiPacket->Parameters.HandlesEnumerate.ProcessObject, HandlesCount, TRUE);
        if (HandleInformation)
        {
            KiPacket->Parameters.HandlesEnumerate.Count = HandlesCount;
            BaseAddress = 0;
            RegionSize = HandlesCount * sizeof(HANDLE_ENTRY);
            Status = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
            KiPacket->Parameters.HandlesEnumerate.HandleEntries = (PHANDLE_ENTRY)BaseAddress;
            if (Status == STATUS_SUCCESS)
            {
                memcpy(BaseAddress, HandleInformation, HandlesCount * sizeof(HANDLE_ENTRY));
            }
            MmFree(HandleInformation);
        }
        else
        {
            Status = STATUS_UNSUCCESSFUL;
        }
        break;
    }
    case IOCTL_ALLOCATE_PROCESS_VM:
    {
        OBJECT_ATTRIBUTES Object =
            RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)0, OBJ_CASE_INSENSITIVE);
        CLIENT_ID ClientId = {(HANDLE)PsGetProcessId((PEPROCESS)KiPacket->Parameters.VirtualAlloc.ProcessObject), 0};
        HANDLE hProcess = 0;
        KPROCESSOR_MODE PrevMode = KeSetPreviousMode(KernelMode);
        Status = KdOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &Object, &ClientId);
        if	(STATUS_SUCCESS == Status)
        {
            BaseAddress = 0;
            RegionSize = KiPacket->Parameters.VirtualAlloc.Size;
            Status = KdAllocateVirtualMemory(hProcess, &BaseAddress, 0L, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
            KiPacket->Parameters.VirtualAlloc.Size = RegionSize;
            KiPacket->Parameters.VirtualAlloc.Address = BaseAddress;
            KdClose(hProcess);
        }
        KeSetPreviousMode(PrevMode);
        break;
    }
    case IOCTL_DEALLOCATE_PROCESS_VM:
    {
        OBJECT_ATTRIBUTES Object =
            RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)0, OBJ_CASE_INSENSITIVE);
        CLIENT_ID ClientId = {(HANDLE)PsGetProcessId((PEPROCESS)KiPacket->Parameters.VirtualFree.ProcessObject), 0};
        HANDLE hProcess = 0;
        KPROCESSOR_MODE PrevMode = KeSetPreviousMode(KernelMode);
        Status = KdOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &Object, &ClientId);
        if	(STATUS_SUCCESS == Status)
        {
            BaseAddress = (PVOID)KiPacket->Parameters.VirtualFree.Address;
            RegionSize = KiPacket->Parameters.VirtualFree.Size;
            Status = MmFreeUserBuffer(hProcess, BaseAddress, RegionSize, true);
            KdClose(hProcess);
        }
        KeSetPreviousMode(PrevMode);
        break;
    }
    case IOCTL_PROTECT_PROCESS_VM:
    {
        OBJECT_ATTRIBUTES Object =
            RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)0, OBJ_CASE_INSENSITIVE);
        CLIENT_ID ClientId = {(HANDLE)PsGetProcessId((PEPROCESS)KiPacket->Parameters.VirtualProtect.ProcessObject), 0};
        HANDLE hProcess = 0;
        KPROCESSOR_MODE PrevMode = KeSetPreviousMode(KernelMode);
        Status = KdOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &Object, &ClientId);
        if	(STATUS_SUCCESS == Status)
        {
            BaseAddress = (PVOID)KiPacket->Parameters.VirtualProtect.Address;
            RegionSize = KiPacket->Parameters.VirtualProtect.Size;
            ULONG NewProtection = KiPacket->Parameters.VirtualProtect.NewProtection;
            Status = KdProtectVirtualMemory(hProcess, &BaseAddress, &RegionSize, NewProtection, KiPacket->Parameters.VirtualProtect.OldProtection);
            KdClose(hProcess);
        }
        KeSetPreviousMode(PrevMode);
        break;
    }
    case IOCTL_QUERY_PROCESS_VM:
    {
        OBJECT_ATTRIBUTES Object =
            RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)0, OBJ_CASE_INSENSITIVE);
        CLIENT_ID ClientId = {(HANDLE)PsGetProcessId((PEPROCESS)KiPacket->Parameters.VirtualQuery.ProcessObject), 0};
        HANDLE hProcess = 0;
        KPROCESSOR_MODE PrevMode = KeSetPreviousMode(KernelMode);
        Status = KdOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &Object, &ClientId);
        if	(STATUS_SUCCESS == Status)
        {
            Status = KdQueryVirtualMemory(hProcess, KiPacket->Parameters.VirtualQuery.Address, MemoryBasicInformation, (PVOID)KiPacket->Parameters.VirtualQuery.MemoryBasicInformation, KiPacket->Parameters.VirtualQuery.Size, NULL);
            KdClose(hProcess);
        }
        KeSetPreviousMode(PrevMode);
        break;
    }
    case IOCTL_PROCESS_BY_PID:
    {
        PEPROCESS Process = NULL;
        Status = KdLookupProcessByProcessId((PHANDLE)KiPacket->Parameters.Common.Parameter1, &Process);
        if (NT_SUCCESS(Status))
        {
            ObDereferenceObject(Process);
        }
        KiPacket->Parameters.Common.Parameter2 = (ULONG_PTR)Process;
        break;
    }
    case IOCTL_PROCESS_BY_HANDLE:
    {
        PEPROCESS Process = NULL;
        Status = KdReferenceObjectByHandle((PHANDLE)KiPacket->Parameters.Common.Parameter1, SYNCHRONIZE, NULL, KernelMode, (PVOID *)&Process, NULL);
        if (NT_SUCCESS(Status))
        {
            ObDereferenceObject(Process);
        }
        KiPacket->Parameters.Common.Parameter2 = (ULONG_PTR)Process;
        break;
    }
    case IOCTL_THREAD_BY_PID:
    {
        PETHREAD Thread = NULL;
        Status = KdLookupThreadByThreadId((PHANDLE)KiPacket->Parameters.Common.Parameter1, &Thread);
        if (NT_SUCCESS(Status))
        {
            ObDereferenceObject(Thread);
        }
        KiPacket->Parameters.Common.Parameter2 = (ULONG_PTR)Thread;
        break;
    }
    case IOCTL_THREAD_BY_HANDLE:
    {
        PETHREAD Thread = NULL;
        Status = KdReferenceObjectByHandle((PHANDLE)KiPacket->Parameters.Common.Parameter1, SYNCHRONIZE, NULL, KernelMode, (PVOID *)&Thread, NULL);
        if (NT_SUCCESS(Status))
        {
            ObDereferenceObject(Thread);
        }
        KiPacket->Parameters.Common.Parameter2 = (ULONG_PTR)Thread;
        break;
    }
    case IOCTL_PROCESS_OPEN:
    {
        HANDLE hProcess = 0;
        OBJECT_ATTRIBUTES Object =
            RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)0, OBJ_CASE_INSENSITIVE);
        CLIENT_ID ClientId;
        ClientId.UniqueProcess = (HANDLE)KiPacket->Parameters.ProcessOpen.ProcessId;
        ClientId.UniqueThread = 0;
        KiPacket->Parameters.ProcessOpen.Handle = NULL;
        if (MmIsAddressValid(KiPacket->Parameters.ProcessOpen.ProcessObject))
        {
            Status = KdOpenObjectByPointer(KiPacket->Parameters.ProcessOpen.ProcessObject,
                                           0,
                                           0,
                                           PROCESS_ALL_ACCESS,
                                           *PsProcessType,
                                           UserMode,
                                           &hProcess);
        }
        else
        {
            KPROCESSOR_MODE PrevMode = KeSetPreviousMode(KernelMode);
            Status = KdOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &Object, &ClientId);
            KeSetPreviousMode(PrevMode);
        }
        KiPacket->Parameters.ProcessOpen.Handle = hProcess;
        break;
    }
    case IOCTL_THREAD_OPEN:
    {
        HANDLE hThread = 0;
        OBJECT_ATTRIBUTES Object =
            RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)0, OBJ_CASE_INSENSITIVE);
        CLIENT_ID ClientId;
        ClientId.UniqueProcess = 0;
        ClientId.UniqueThread = (HANDLE)KiPacket->Parameters.ThreadOpen.ThreadId;
        KiPacket->Parameters.ThreadOpen.Handle = NULL;
        if (MmIsAddressValid(KiPacket->Parameters.ThreadOpen.ThreadObject))
        {
            Status = KdOpenObjectByPointer(
                         KiPacket->Parameters.ThreadOpen.ThreadObject,
                         0,
                         0,
                         THREAD_ALL_ACCESS,
                         *PsThreadType,
                         UserMode,
                         &hThread
                     );
        }
        else
        {
            KPROCESSOR_MODE PrevMode = KeSetPreviousMode(KernelMode);
            Status = KdOpenThread(&hThread, THREAD_ALL_ACCESS, &Object, &ClientId);
            KeSetPreviousMode(PrevMode);
        }
        KiPacket->Parameters.ThreadOpen.Handle = hThread;
        break;
    }
    case IOCTL_CLOSE_HANDLE:
    {
        KPROCESSOR_MODE PrevMode = KeSetPreviousMode(KernelMode);
        Status = CloseHandle(KiPacket->Parameters.CloseHandle.Handle, (PEPROCESS)KiPacket->Parameters.CloseHandle.ProcessObject);
        KeSetPreviousMode(PrevMode);
        break;
    }
    case IOCTL_UPDATE_MODULE_LIST:
    {
        Print("Updating ...");
        if (gDrivers)
        {
            delete gDrivers;
        }
        gDrivers = new CDriver();
        gDrivers->Scan();
        gDrivers->ScanPhysicalMemory();
        break;
    }
    case IOCTL_THREAD_TO_PROCESS:
    {
        PETHREAD Thread = (PETHREAD)KiPacket->Parameters.ThreadQueryInformation.ThreadObject;
        THREAD_ENTRY *ThreadInfo = KiPacket->Parameters.ThreadQueryInformation.Thread;
        POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Thread);
        if (MmIsAddressValid(ObjectHeader))
        {
            if (TypeFromObject(ObjectHeader) == *PsThreadType)
            {
                PEPROCESS Process = KdThreadToProcess(Thread);
                ObjectHeader = OBJECT_TO_OBJECT_HEADER(Process);
                if (MmIsAddressValid(ObjectHeader))
                {
                    if (TypeFromObject(ObjectHeader) == *PsProcessType)
                    {
                        GetThreadInfo(Thread, ThreadInfo);
                        GetProcessInfo((PEPROCESS)ThreadInfo->Process, KiPacket->Parameters.ThreadQueryInformation.Process);
                    }
                }
            }
        }
        break;
    }
    case IOCTL_GET_OBJECT_TYPE:
    {
        PVOID Object = KiPacket->Parameters.ObjectQueryTypeName.Object;
        POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
        if (MmIsAddressValid(ObjectHeader))
        {
            POBJECT_TYPE ObjectType = TypeFromObject(ObjectHeader);
            if (MmIsAddressValid(ObjectType))
            {
                CopyUnicodeString(KiPacket->Parameters.ObjectQueryTypeName.ObjectTypeName, parseobject(ObjectType, ObjectTypeName, UNICODE_STRING), MAX_PATH);
            }
        }
        break;
    }
    case IOCTL_GET_TYPE_NAME:
    {
        POBJECT_TYPE ObjectType = (POBJECT_TYPE)KiPacket->Parameters.Common.Parameter1;
        if (ObjectType && MmIsAddressValid(ObjectType))
        {
            CopyUnicodeString((PWSTR)KiPacket->Parameters.Common.Parameter2, parseobject(ObjectType, ObjectTypeName, UNICODE_STRING), MAX_PATH);
        }
        break;
    }
    case IOCTL_THREAD_SET_SSDT:
    {
        PETHREAD Thread = (PETHREAD)KiPacket->Parameters.Common.Parameter1;
        ULONG NewServiceTable = KiPacket->Parameters.Common.Parameter2;
        if (!MmIsAddressValid(Thread)) break;
        volatile PLONG ThreadServiceTable = parseobject(Thread, ServiceTable, LONG);
        InterlockedExchange(ThreadServiceTable, NewServiceTable);
        break;
    }
    case IOCTL_THREAD_RESTORE_SSDT:
    {
        PETHREAD Thread = (PETHREAD)KiPacket->Parameters.Common.Parameter1;
        if (!MmIsAddressValid(Thread)) break;
        volatile PLONG ThreadServiceTable = parseobject(Thread, ServiceTable, LONG);
        if (PsGetThreadWin32Thread(Thread) == 0)
        {
            InterlockedExchange(ThreadServiceTable, (ULONG)KdServiceDescriptorTable);
        }
        else
        {
            InterlockedExchange(ThreadServiceTable, (ULONG)KeServiceDescriptorTableShadow);
        }
        break;
    }
    case IOCTL_THREAD_SUSPEND:
    {
        PKTHREAD Thread = (PKTHREAD)KiPacket->Parameters.ThreadSuspend.ThreadObject;
        if (MmIsAddressValid(Thread))
        {
            if (Thread != KeGetCurrentThread())
            {
                Status = KeSuspendThread(Thread);
            }
        }
        break;
    }
    case IOCTL_PROCESS_SUSPEND:
    {
        PEPROCESS Process = (PEPROCESS)KiPacket->Parameters.ProcessSuspend.ProcessObject;
        if (MmIsAddressValid(Process))
        {
            if (Process != PsGetCurrentProcess())
            {
                CThread Thread(Process);
                DispatchLock lock;
                lock.Lock();
                Thread.ScanCidTable();
                Thread.ScanKiWaitList();
                Thread.ScanTypeList();
                Thread.ScanProcessList();
                lock.Unlock();
                for (ULONG c = 0; c < Thread.ThreadCount; ++c)
                {
                    KeSuspendThread(&Thread.ThreadArray[c]->Tcb);
                }
            }
        }
        break;
    }
    case IOCTL_THREAD_RESUME:
    {
        PKTHREAD Thread = (PKTHREAD)KiPacket->Parameters.ThreadResume.ThreadObject;
        BOOL bForce = KiPacket->Parameters.ThreadResume.ForceResume;
        if (MmIsAddressValid(Thread))
        {
            if (Thread != KeGetCurrentThread())
            {
                if (!bForce)
                {
                    Status = KeResumeThread(Thread);
                }
                else
                {
                    Print("KeForceResumeThread %p", Thread);
                    Status = STATUS_SUCCESS;
                    KeForceResumeThread(Thread, TRUE);
                }
            }
        }
        break;
    }
    case IOCTL_PROCESS_RESUME:
    {
        PEPROCESS Process = (PEPROCESS)KiPacket->Parameters.ProcessResume.ProcessObject;
        BOOL bForce = KiPacket->Parameters.ProcessResume.ForceResume;
        if (MmIsAddressValid(Process))
        {
            if (Process != PsGetCurrentProcess())
            {
                CThread Thread(Process);
                DispatchLock lock;
                lock.Lock();
                Thread.ScanCidTable();
                Thread.ScanKiWaitList();
                Thread.ScanTypeList();
                Thread.ScanProcessList();
                lock.Unlock();
                for (ULONG c = 0; c < Thread.ThreadCount; ++c)
                {
                    if (!bForce)
                    {
                        Status = KeResumeThread(&Thread.ThreadArray[c]->Tcb);
                    }
                    else
                    {
                        Print("KeForceResumeThread %p", &Thread.ThreadArray[c]->Tcb);
                        KeForceResumeThread(&Thread.ThreadArray[c]->Tcb, TRUE);
                    }
                }
            }
        }
        break;
    }
    case IOCTL_ENUM_UNLOADED_DRIVERS:
    {
        PDRIVER_ENTRY ptrDrivers;
        ULONG Count;
        Count = EnumUnloadedDrivers(&ptrDrivers);
        Print("Unloaded drivers count = %d", Count);
        if (ptrDrivers)
        {
            RegionSize = Count * sizeof(DRIVER_ENTRY);
            BaseAddress = 0;
            Status = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
            if (Status == STATUS_SUCCESS)
            {
                KiPacket->Parameters.Common.Parameter1 = (ULONG_PTR)BaseAddress;
                KiPacket->Parameters.Common.Parameter2 = Count;
                RtlCopyMemory(BaseAddress, ptrDrivers, Count * sizeof(DRIVER_ENTRY));
            }
            MmFree(ptrDrivers);
        }
        else
        {
            Status = STATUS_UNSUCCESSFUL;
        }
        break;
    }
    case IOCTL_ENUM_TIMERS:
    {
        PTIMER_ENTRY ptrTimer = NULL;
        ULONG Count;
        DispatchLock Lock;

        Lock.Lock();
        Count = EnumTimerObjects(&ptrTimer);
        Lock.Unlock();
        Print("Timer objects count = %d", Count);
        if (ptrTimer)
        {
            RegionSize = Count * sizeof(TIMER_ENTRY);
            BaseAddress = 0;
            Status = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
            if (Status == STATUS_SUCCESS)
            {
                KiPacket->Parameters.Common.Parameter1 = (ULONG_PTR)BaseAddress;
                KiPacket->Parameters.Common.Parameter2 = Count;
                RtlCopyMemory(BaseAddress, ptrTimer, Count * sizeof(TIMER_ENTRY));
            }
            MmFree(ptrTimer);
        }
        else
        {
            Status = STATUS_UNSUCCESSFUL;
        }
        break;
    }
    case IOCTL_ENUM_OBJECT_TYPES:
    {
        POBJECT_TYPE_ENTRY ptrTypeInfo = NULL;
        ULONG Index, Count;
        Count = 0;
        for (Index = 0; Index < sizeof(TypesArray)/sizeof(*TypesArray); ++Index)
        {
            if (TypesArray[Index])
            {
                ptrTypeInfo = (POBJECT_TYPE_ENTRY)MmRealloc(ptrTypeInfo, (Count + 1)*sizeof(OBJECT_TYPE_ENTRY));
                GetObjectTypeInfo(TypesArray[Index], &ptrTypeInfo[Count]);
                Count++;
            }
        }
        if (ptrTypeInfo)
        {
            RegionSize = Count * sizeof(OBJECT_TYPE_ENTRY);
            BaseAddress = 0;
            Status = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
            if (Status == STATUS_SUCCESS)
            {
                KiPacket->Parameters.Common.Parameter1 = (ULONG_PTR)BaseAddress;
                KiPacket->Parameters.Common.Parameter2 = Count;
                RtlCopyMemory(BaseAddress, ptrTypeInfo, Count * sizeof(OBJECT_TYPE_ENTRY));
            }
            MmFree(ptrTypeInfo);
        }
        else
        {
            Status = STATUS_UNSUCCESSFUL;
        }
        break;
    }
    case IOCTL_CANCEL_TIMER:
    {
        PKTIMER Timer = (PKTIMER)KiPacket->Parameters.Common.Parameter1;
        if (Timer->Dpc && Timer->Period)
        {
            Status = KeCancelTimer(Timer) == TRUE ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
            if (*(PVOID *)&KdFlushQueuedDpcs = KdGetSystemRoutineAddress(L"KeFlushQueuedDpcs"))
            {
                KdFlushQueuedDpcs();
            }
        }
        else
        {
            Status = KeCancelTimer(Timer) == TRUE ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        }
        break;
    }
    case IOCTL_CHANGE_OBJECT_PROC:
    {
        PVOID *ProcedureTable;
        DispatchLock Lock;

        if (KdBuildNumber >= 6001)
        {
            ProcedureTable = (PVOID *)(0x58 + KiPacket->Parameters.Common.Parameter2);
        }
        else
        {
            ProcedureTable = &((POBJECT_TYPE)KiPacket->Parameters.Common.Parameter2)->TypeInfo.DumpProcedure;
        }
        Lock.Lock();
        ProcedureTable[KiPacket->Parameters.Common.Parameter1] = (PVOID)KiPacket->Parameters.Common.Parameter3;
        Lock.Unlock();
        break;
    }
    case IOCTL_ENUM_IMAGE_NOTIFY:
    {
        PEX_CALLBACK Callback;
        PEX_CALLBACK_ROUTINE_BLOCK CallbackRoutineBlock;
        PVOID *ptrBuffer;
        ULONG Count = 0;

        if (!MmIsAddressValid(PspLoadImageNotifyRoutine))
        {
            Status = STATUS_UNSUCCESSFUL;
            break;
        }
        RegionSize = sizeof(PVOID) * PSP_MAX_NOTIFY;
        BaseAddress = NULL;
        Status = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
        if (NT_SUCCESS(Status))
        {
            KiPacket->Parameters.Common.Parameter1 = (ULONG_PTR)BaseAddress;
            ptrBuffer = (PVOID *)BaseAddress;
            for (ULONG Index = 0; Index < PSP_MAX_NOTIFY; ++Index)
            {
                Callback = &PspLoadImageNotifyRoutine[Index];
                if (Callback->RoutineBlock.Value)
                {
                    CallbackRoutineBlock = (PEX_CALLBACK_ROUTINE_BLOCK)(Callback->RoutineBlock.Value & ~MAX_FAST_REFS);
                    ptrBuffer[Count] = CallbackRoutineBlock->Function;
                    Count++;
                }
            }
            KiPacket->Parameters.Common.Parameter2 = Count;
        }
        break;
    }
    case IOCTL_ENUM_PROCESS_NOTIFY:
    {
        PEX_CALLBACK Callback;
        PEX_CALLBACK_ROUTINE_BLOCK CallbackRoutineBlock;
        PVOID *ptrBuffer;
        ULONG Count = 0;

        if (!MmIsAddressValid(PspCreateProcessNotifyRoutine))
        {
            Status = STATUS_UNSUCCESSFUL;
            break;
        }
        RegionSize = sizeof(PVOID) * MaxCreateProcess;
        BaseAddress = NULL;
        Status = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
        if (NT_SUCCESS(Status))
        {
            KiPacket->Parameters.Common.Parameter1 = (ULONG_PTR)BaseAddress;
            ptrBuffer = (PVOID *)BaseAddress;
            for (ULONG Index = 0; Index < MaxCreateProcess; ++Index)
            {
                Callback = &PspCreateProcessNotifyRoutine[Index];
                if (Callback->RoutineBlock.Value)
                {
                    CallbackRoutineBlock = (PEX_CALLBACK_ROUTINE_BLOCK)(Callback->RoutineBlock.Value & ~MAX_FAST_REFS);
                    ptrBuffer[Count] = CallbackRoutineBlock->Function;
                    Count++;
                }
            }
            KiPacket->Parameters.Common.Parameter2 = Count;
        }
        break;
    }
    case IOCTL_ENUM_THREAD_NOTIFY:
    {
        PEX_CALLBACK Callback;
        PEX_CALLBACK_ROUTINE_BLOCK CallbackRoutineBlock;
        PVOID *ptrBuffer;
        ULONG Count = 0;
        ULONG MaxThing = (KdBuildNumber == 6000) ? 8 : MaxCreateProcess;

        if (!MmIsAddressValid(PspCreateThreadNotifyRoutine))
        {
            Status = STATUS_UNSUCCESSFUL;
            break;
        }
        RegionSize = sizeof(PVOID) * MaxThing;
        BaseAddress = NULL;
        Status = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
        if (NT_SUCCESS(Status))
        {
            KiPacket->Parameters.Common.Parameter1 = (ULONG_PTR)BaseAddress;
            ptrBuffer = (PVOID *)BaseAddress;
            for (ULONG Index = 0; Index < MaxThing; ++Index)
            {
                Callback = &PspCreateThreadNotifyRoutine[Index];
                if (Callback->RoutineBlock.Value)
                {
                    CallbackRoutineBlock = (PEX_CALLBACK_ROUTINE_BLOCK)(Callback->RoutineBlock.Value & ~MAX_FAST_REFS);
                    ptrBuffer[Count] = CallbackRoutineBlock->Function;
                    Count++;
                }
            }
            KiPacket->Parameters.Common.Parameter2 = Count;
        }
        break;
    }
    case IOCTL_ENUM_LEGO_NOTIFY:
    {
        PEX_CALLBACK Callback;
        PEX_CALLBACK_ROUTINE_BLOCK CallbackRoutineBlock;
        PVOID *ptrBuffer;
        ULONG Count = 0;

        if (!MmIsAddressValid(PspLegoNotifyRoutine))
        {
            Status = STATUS_UNSUCCESSFUL;
            break;
        }
        RegionSize = sizeof(PVOID) * 1;
        BaseAddress = NULL;
        Status = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
        if (NT_SUCCESS(Status))
        {
            KiPacket->Parameters.Common.Parameter1 = (ULONG_PTR)BaseAddress;
            ptrBuffer = (PVOID *)BaseAddress;
            Callback = PspLegoNotifyRoutine;
            if (Callback->RoutineBlock.Value)
            {
                CallbackRoutineBlock = (PEX_CALLBACK_ROUTINE_BLOCK)(Callback->RoutineBlock.Value & ~MAX_FAST_REFS);
                ptrBuffer[Count] = CallbackRoutineBlock->Function;
                Count++;
            }
            KiPacket->Parameters.Common.Parameter2 = Count;
        }
        break;
    }
    case IOCTL_ENUM_BUGCHECK:
    {
        PBUGCHECK_CALLBACK ptrBuffer;
        ULONG Count = 0;

        if (KeBugCheckCallbackListHead)
        {
            ptrBuffer = KiScanBugCheckCallbackList(Count);
            if (ptrBuffer)
            {
                RegionSize = sizeof(BUGCHECK_CALLBACK) * Count;
                BaseAddress = NULL;
                Status = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
                if (NT_SUCCESS(Status))
                {
                    KiPacket->Parameters.Common.Parameter1 = (ULONG_PTR)BaseAddress;
                    KiPacket->Parameters.Common.Parameter2 = Count;
                    RtlCopyMemory(BaseAddress, ptrBuffer, RegionSize);
                }
                MmFree(ptrBuffer);
            }
            else
            {
                Status = STATUS_UNSUCCESSFUL;
            }
        }
        else
        {
            Status = STATUS_UNSUCCESSFUL;
        }
        break;
    }
    case IOCTL_ENUM_BUGCHECK_REASON:
    {
        PBUGCHECK_CALLBACK ptrBuffer;
        ULONG Count = 0;

        if (KeBugCheckReasonCallbackListHead && MmIsAddressValid(KdDeregisterBugCheckReasonCallback))
        {
            ptrBuffer = KiScanBugCheckReasonCallbackList(Count);
            if (ptrBuffer)
            {
                RegionSize = sizeof(BUGCHECK_CALLBACK) * Count;
                BaseAddress = NULL;
                Status = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
                if (NT_SUCCESS(Status))
                {
                    KiPacket->Parameters.Common.Parameter1 = (ULONG_PTR)BaseAddress;
                    KiPacket->Parameters.Common.Parameter2 = Count;
                    RtlCopyMemory(BaseAddress, ptrBuffer, RegionSize);
                }
                MmFree(ptrBuffer);
            }
            else
            {
                Status = STATUS_UNSUCCESSFUL;
            }
        }
        else
        {
            Status = STATUS_UNSUCCESSFUL;
        }
        break;
    }
    case IOCTL_ENUM_CM_NOTIFY:
    {
        PVOID *ptrBuffer;
        ULONG Count = 0;

        ptrBuffer = EnumCmNotifyRoutines(Count);
        if (ptrBuffer)
        {
            RegionSize = sizeof(PVOID) * Count;
            BaseAddress = NULL;
            Status = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
            if (NT_SUCCESS(Status))
            {
                KiPacket->Parameters.Common.Parameter1 = (ULONG_PTR)BaseAddress;
                KiPacket->Parameters.Common.Parameter2 = Count;
                RtlCopyMemory(BaseAddress, ptrBuffer, RegionSize);
            }
            MmFree(ptrBuffer);
        }
        else
        {
            Status = STATUS_UNSUCCESSFUL;
        }
        break;
    }
    case IOCTL_DELETE_NOTIFY:
    {
        PVOID Function = (PVOID)KiPacket->Parameters.Common.Parameter1;
        ULONG Type = KiPacket->Parameters.Common.Parameter2;

        switch (Type)
        {
        case 1: // ImageLoad
            Status = PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)Function);
            break;
        case 2: // CreateProcess
            Status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)Function, TRUE);
            if (!NT_SUCCESS(Status))
            {
                PEX_CALLBACK Callback;
                PEX_CALLBACK_ROUTINE_BLOCK CallbackRoutineBlock;
                for (ULONG Index = 0; Index < MaxCreateProcess; ++Index)
                {
                    Callback = &PspCreateProcessNotifyRoutine[Index];
                    if (Callback->RoutineBlock.Value)
                    {
                        CallbackRoutineBlock = (PEX_CALLBACK_ROUTINE_BLOCK)(Callback->RoutineBlock.Value & ~MAX_FAST_REFS);
                        if (Function == CallbackRoutineBlock->Function)
                        {
                            PspCreateProcessNotifyRoutine[Index].RoutineBlock.Object = NULL;
                            Status = STATUS_SUCCESS;
                        }
                    }
                }
            }
            break;
        case 3: // CreateThread
            Status = PsRemoveCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)Function);
            break;
        case 4: // Lego
            PsSetLegoNotifyRoutine(NULL);
            break;
        case 5: // Cm
            Status = STATUS_INVALID_PARAMETER;
            if (IsXp)
            {
                PEX_CALLBACK Callback;
                PEX_CALLBACK_ROUTINE_BLOCK CallbackRoutineBlock;
                for (ULONG Index = 0; Index < CM_MAX_CALLBACKS; ++Index)
                {
                    Callback = &CmpCallBackVector[Index];
                    if (Callback->RoutineBlock.Value)
                    {
                        CallbackRoutineBlock = (PEX_CALLBACK_ROUTINE_BLOCK)(Callback->RoutineBlock.Value & ~MAX_FAST_REFS);
                        if (CallbackRoutineBlock->Function == Function)
                        {
                            PCM_CALLBACK_CONTEXT_BLOCK Context = (PCM_CALLBACK_CONTEXT_BLOCK)CallbackRoutineBlock->Context;
                            Status = CmUnRegisterCallback(Context->Cookie);
                            break;
                        }
                    }
                }
            }
            else
            {
                PLIST_ENTRY ListEntry;
                PCM_VISTA_CALLBACK_BLOCK CallbackRoutineBlock;

                ListEntry = CmCallbackListHead->Flink;
                while (ListEntry != CmCallbackListHead)
                {
                    CallbackRoutineBlock = CONTAINING_RECORD(ListEntry, CM_VISTA_CALLBACK_BLOCK, CallbackListHead);
                    if (CallbackRoutineBlock->Function == Function)
                    {
                        Status = CmUnRegisterCallback(CallbackRoutineBlock->Cookie);
                        break;
                    }
                    ListEntry = ListEntry->Flink;
                }
            }
            break;
        case 6: // Bugcheck
        {
            ULONG Count = 0;
            PBUGCHECK_CALLBACK ptrBugcheck = KiScanBugCheckCallbackList(Count);
            if (ptrBugcheck)
            {
                for (ULONG i = 0; i < Count; i++)
                {
                    if (ptrBugcheck[i].Routine == Function)
                    {
                        Status = KeDeregisterBugCheckCallback((PKBUGCHECK_CALLBACK_RECORD)ptrBugcheck[i].Record) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
                        break;
                    }
                }
                MmFree(ptrBugcheck);
            }
            else
            {
                Status = STATUS_UNSUCCESSFUL;
            }
            break;
        }
        case 7: // BugcheckReason
        {
            ULONG Count = 0;
            if (MmIsAddressValid(KdDeregisterBugCheckReasonCallback))
            {
                PBUGCHECK_CALLBACK ptrBugcheck = KiScanBugCheckReasonCallbackList(Count);
                if (ptrBugcheck)
                {
                    for (ULONG i = 0; i < Count; i++)
                    {
                        if (ptrBugcheck[i].Routine == Function)
                        {
                            Status = KdDeregisterBugCheckReasonCallback((PKBUGCHECK_REASON_CALLBACK_RECORD)ptrBugcheck[i].Record) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
                            break;
                        }
                    }
                    MmFree(ptrBugcheck);
                }
                else
                {
                    Status = STATUS_UNSUCCESSFUL;
                }
            }
            else
            {
                Status = STATUS_UNSUCCESSFUL;
            }
            break;
        }
        default:
            Status = STATUS_UNSUCCESSFUL;
        }
        break;
    }
    case IOCTL_DELETE_FILE:
    {
        Status = DeleteFile(KiPacket->Parameters.FileDelete.FilePath, KiPacket->Parameters.FileDelete.ForceDelete);
        break;
    }
    case IOCTL_COPY_FILE:
    {
        Status = CopyFile(KiPacket->Parameters.FileCopy.SourceFilePath, KiPacket->Parameters.FileCopy.DestinationFilePath);
        break;
    }
    case IOCTL_ENUM_THREAD_TRACE:
    {
        PKTHREAD Thread = (PKTHREAD)KiPacket->Parameters.ThreadCaptureStack.ThreadObject;
        PCONTEXT Context = KiPacket->Parameters.ThreadCaptureStack.Context;
        Context->ContextFlags = CONTEXT_CONTROL;
        if (Thread == KeGetCurrentThread())
        {
            __asm
            {
                mov eax, Context;
                mov dword ptr [eax + 0xC4], esp;
                mov dword ptr [eax + 0xB4], ebp;
                push Ecx;
                call $+5;
                pop ecx;
                mov dword ptr [eax + 0xB8], ecx; // eip
                pop ecx;
            }
        }
        else
        {
            //Status = KeSuspendThread(Thread);
            //if (NT_SUCCESS(Status))
            {
                PULONG KernelStack;
                if (IsXp)
                    KernelStack = (PULONG)Thread->KernelStack;
                else
                    KernelStack = *(PULONG *)((ULONG_PTR)Thread + 0x30);
                if (MmIsAddressValid(KernelStack))
                {
                    Context->Esp = (ULONG)&KernelStack[3];
                    Context->Ebp = KernelStack[3];
                    Context->Eip = KernelStack[2];
                }
                //KeResumeThread(Thread);
            }
        }
        break;
    }
    case IOCTL_THREAD_CONTEXT:
    {
        PETHREAD Thread = (PETHREAD)KiPacket->Parameters.ThreadContext.ThreadObject;
        PCONTEXT Context = KiPacket->Parameters.ThreadContext.Context;
        if (!KiPacket->Parameters.ThreadContext.Set)
        {
            *(PVOID *)&KdGetContextThread = KdGetSystemRoutineAddress(L"PsGetContextThread");
            if (KdGetContextThread && !PsIsSystemThread(Thread))
            {
                __asm
                {
                    push UserMode;
                    push Context;
                    push Thread;
                    call KdGetContextThread;
                    mov Status, eax
                }
            }
            else
            {
                Status = STATUS_UNSUCCESSFUL;
            }
        }
        else
        {
            *(PVOID *)&KdSetContextThread = KdGetSystemRoutineAddress(L"PsSetContextThread");
            if (KdSetContextThread && !PsIsSystemThread(Thread))
            {
                __asm
                {
                    push UserMode;
                    push Context;
                    push Thread;
                    call KdSetContextThread;
                    mov Status, eax
                }
            }
            else
            {
                Status = STATUS_UNSUCCESSFUL;
            }
        }
        break;
    }
    case IOCTL_GET_MEMORY_INFO:
    {
        KiPacket->Parameters.SystemInformation.LowestPhysicalPage = *(PULONG)KdVersionBlock->MmLowestPhysicalPage;
        KiPacket->Parameters.SystemInformation.HighestPhysicalPage = *(PULONG)KdVersionBlock->MmHighestPhysicalPage;
        KiPacket->Parameters.SystemInformation.NumberOfPhysicalPages = *(PULONG)KdVersionBlock->MmNumberOfPhysicalPages;
        KiPacket->Parameters.SystemInformation.HighestUserAddress = *(PULONG)KdVersionBlock->MmHighestUserAddress;
        KiPacket->Parameters.SystemInformation.SystemRangeStart = *(PULONG)KdVersionBlock->MmSystemRangeStart;
        KiPacket->Parameters.SystemInformation.UserProbeAddress = *(PULONG)KdVersionBlock->MmUserProbeAddress;
        break;
    }
    case IOCTL_ALLOC_NONPAGED_POOL:
    {
        KiPacket->Parameters.Common.Parameter2 = (ULONG_PTR)MmAlloc(KiPacket->Parameters.Common.Parameter1);
        break;
    }
    case IOCTL_FREE_NONPAGED_POOL:
    {
        MmFree((PVOID)KiPacket->Parameters.Common.Parameter1);
        break;
    }
    case IOCTL_PHYSICAL_PAGE_READ:
    {
        Status = MmReadPhysicalPages(KiPacket->Parameters.PhysicalRead.PhysicalAddress, KiPacket->Parameters.PhysicalRead.Buffer, KiPacket->Parameters.PhysicalRead.Size);
        break;
    }
    case IOCTL_PHYSICAL_PAGE_WRITE:
    {
        Status = MmWritePhysicalPages(KiPacket->Parameters.PhysicalWrite.PhysicalAddress, KiPacket->Parameters.PhysicalWrite.Buffer, KiPacket->Parameters.PhysicalWrite.Size);
        break;
    }
    case IOCTL_GET_FILENAME_BY_OBJECT:
    {
        if (GetFileName((PFILE_OBJECT)KiPacket->Parameters.Common.Parameter1, (PWCHAR)KiPacket->Parameters.Common.Parameter2, KiPacket->Parameters.Common.Parameter3))
            Status = STATUS_SUCCESS;
        else
            Status = STATUS_UNSUCCESSFUL;
        break;
    }
    case IOCTL_GET_FILENAME_BY_HANDLE:
    {
        PFILE_OBJECT FileObject;
        HANDLE hFile = (HANDLE)KiPacket->Parameters.Common.Parameter1;

        Status = KdReferenceObjectByHandle(hFile, SYNCHRONIZE, *IoFileObjectType, KernelMode, (PVOID *)&FileObject, NULL);
        if (NT_SUCCESS(Status))
        {
            if (GetFileName(FileObject, (PWCHAR)KiPacket->Parameters.Common.Parameter2, KiPacket->Parameters.Common.Parameter3))
                Status = STATUS_SUCCESS;
            else
                Status = STATUS_UNSUCCESSFUL;

            ObDereferenceObject(FileObject);
        }
        break;
    }
    case IOCTL_READ_FILE_BY_HANDLE:
    {
        Status = IoReadFile((HANDLE)KiPacket->Parameters.Common.Parameter1, (PVOID)KiPacket->Parameters.Common.Parameter2, KiPacket->Parameters.Common.Parameter3, (PLARGE_INTEGER)KiPacket->Parameters.Common.Parameter4);
        break;
    }
    case IOCTL_WRITE_FILE_BY_HANDLE:
    {
        Status = IoWriteFile((HANDLE)KiPacket->Parameters.Common.Parameter1, (PVOID)KiPacket->Parameters.Common.Parameter2, KiPacket->Parameters.Common.Parameter3, (PLARGE_INTEGER)KiPacket->Parameters.Common.Parameter4);
        break;
    }
    case IOCTL_READ_FILE_BY_NAME:
    {
        PWCHAR FileName = (PWCHAR)KiPacket->Parameters.Common.Parameter1;
        HANDLE hFile;
        Status = IoOpenFile(&hFile, FileName, SYNCHRONIZE, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, FILE_OPEN);
        if (NT_SUCCESS(Status))
        {
            Status = IoReadFile(hFile, (PVOID)KiPacket->Parameters.Common.Parameter2, KiPacket->Parameters.Common.Parameter3, (PLARGE_INTEGER)KiPacket->Parameters.Common.Parameter4);
            ZwClose(hFile);
        }
        break;
    }
    case IOCTL_WRITE_FILE_BY_NAME:
    {
        PWCHAR FileName = (PWCHAR)KiPacket->Parameters.Common.Parameter1;
        HANDLE hFile;
        Status = IoOpenFile(&hFile, FileName, SYNCHRONIZE, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, FILE_OPEN);
        if (NT_SUCCESS(Status))
        {
            Status = IoWriteFile(hFile, (PVOID)KiPacket->Parameters.Common.Parameter2, KiPacket->Parameters.Common.Parameter3, (PLARGE_INTEGER)KiPacket->Parameters.Common.Parameter4);
            ZwClose(hFile);
        }
        break;
    }
    case IOCTL_OPEN_FILE:
    {
        HANDLE hFile;
        Status = IoOpenFile(&hFile, (PWCHAR)KiPacket->Parameters.Common.Parameter1, SYNCHRONIZE, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, FILE_OPEN);
        if (NT_SUCCESS(Status))
        {
            KiPacket->Parameters.Common.Parameter2 = (ULONG_PTR)hFile;
        }
        break;
    }
    case IOCTL_GET_DRIVER_INFO:
    {
        PKLDR_DATA_TABLE_ENTRY dte = NULL;
        PDRIVER_OBJECT DriverObject = (PDRIVER_OBJECT)KiPacket->Parameters.DriversQueryInformation.DriverObject;
        DRIVER_ENTRY *DriverInfo = KiPacket->Parameters.DriversQueryInformation.DriverInformation;

        if (MmIsAddressValid(DriverObject))
        {
            CDRIVER_OBJECT cdo;
            cdo.DriverObject = DriverObject;
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
            }
            cdo.LdrEntry = dte;
            cdo.DriverObject = DriverObject;
            cdo.EntryPoint = DriverObject->DriverInit;
            cdo.ImageBase = DriverObject->DriverStart;
            cdo.ImageSize = DriverObject->DriverSize;
            cdo.Unload = DriverObject->DriverUnload;
            GetDriverInfo(&cdo, DriverInfo);
        }
        else
        {
            Status = STATUS_UNSUCCESSFUL;
        }
        break;
    }
    case IOCTL_GET_OBJECT_NAME:
    {
        PVOID Object = KiPacket->Parameters.ObjectQueryName.Object;
        PWCHAR Buffer = KiPacket->Parameters.ObjectQueryName.ObjectName;
        ULONG dwRetLength = 0;
        POBJECT_NAME_INFORMATION ObjectName;

        Status = ObQueryNameString(Object, NULL, 0, &dwRetLength);
        if (dwRetLength > 0)
        {
            ObjectName = (POBJECT_NAME_INFORMATION)MmAlloc(dwRetLength);
            if (ObjectName)
            {
                Status = ObQueryNameString(Object, ObjectName, dwRetLength, &dwRetLength);
                CopyUnicodeStringFile(Buffer, &ObjectName->Name, MAX_PATH);
                MmFree(ObjectName);
            }
            else
            {
                Status = STATUS_UNSUCCESSFUL;
            }
        }
        break;
    }
    case IOCTL_GET_CONTROL_REG:
    {
        ULONG Crx = KiPacket->Parameters.Common.Parameter1;

        switch (Crx)
        {
        case 0:
        {
            __asm mov eax, cr0;
            __asm mov Crx, eax;
            KiPacket->Parameters.Common.Parameter2 = Crx;
            break;
        }
        case 4:
        {
            __asm __emit 0x0F; // mov eax, cr4
            __asm __emit 0x20;
            __asm __emit 0xE0;
            __asm mov Crx, eax;
            KiPacket->Parameters.Common.Parameter2 = Crx;
            break;
        }
        default:
            Status = STATUS_UNSUCCESSFUL;
        }
        break;
    }
    case IOCTL_SET_CONTROL_REG:
    {
        ULONG Crx = KiPacket->Parameters.Common.Parameter1;
        ULONG Value = KiPacket->Parameters.Common.Parameter2;

        switch (Crx)
        {
        case 0:
        {
            __asm mov eax, Value;
            __asm mov cr0, eax;
            break;
        }
        case 4:
        {
            __asm mov eax, Value;
            __asm __emit 0x0F; // mov cr4, eax
            __asm __emit 0x22;
            __asm __emit 0xE0;
            break;
        }
        default:
            Status = STATUS_UNSUCCESSFUL;
        }
        break;
    }
    case IOCTL_CALL_BIOS:
    {
        if (Kd386CallBios == NULL)
        {
            Status = STATUS_NOT_IMPLEMENTED;
            break;
        }

        if (IsXp)
        {
            if (CsrProcess)
            {
                KAPC_STATE ApcState;
                CONTEXT Context;
                ULONG BiosCommand;

                RtlZeroMemory(&Context, sizeof(Context));
                Context.Eax = KiPacket->Parameters.BiosCall.BiosArguments->Eax;
                Context.Ecx = KiPacket->Parameters.BiosCall.BiosArguments->Ecx;
                Context.Edx = KiPacket->Parameters.BiosCall.BiosArguments->Edx;
                Context.Ebx = KiPacket->Parameters.BiosCall.BiosArguments->Ebx;
                Context.Ebp = KiPacket->Parameters.BiosCall.BiosArguments->Ebp;
                Context.Esi = KiPacket->Parameters.BiosCall.BiosArguments->Esi;
                Context.Edi = KiPacket->Parameters.BiosCall.BiosArguments->Edi;
                Context.SegDs = KiPacket->Parameters.BiosCall.BiosArguments->SegDs;
                Context.SegEs = KiPacket->Parameters.BiosCall.BiosArguments->SegEs;
                BiosCommand = KiPacket->Parameters.BiosCall.BiosCommand;
                KdStackAttachProcess(&CsrProcess->Pcb, &ApcState);
                Status = Kd386CallBios(BiosCommand, &Context);
                KdUnstackDetachProcess(&ApcState);
                KiPacket->Parameters.BiosCall.BiosArguments->Eax = Context.Eax;
                KiPacket->Parameters.BiosCall.BiosArguments->Ecx = Context.Ecx;
                KiPacket->Parameters.BiosCall.BiosArguments->Edx = Context.Edx;
                KiPacket->Parameters.BiosCall.BiosArguments->Ebx = Context.Ebx;
                KiPacket->Parameters.BiosCall.BiosArguments->Ebp = Context.Ebp;
                KiPacket->Parameters.BiosCall.BiosArguments->Esi = Context.Esi;
                KiPacket->Parameters.BiosCall.BiosArguments->Edi = Context.Edi;
                KiPacket->Parameters.BiosCall.BiosArguments->SegDs = (USHORT)Context.SegDs;
                KiPacket->Parameters.BiosCall.BiosArguments->SegEs = (USHORT)Context.SegEs;
                KiPacket->Parameters.BiosCall.BiosArguments->EFlags = Context.EFlags;
            }
            else
            {
                Status = STATUS_UNSUCCESSFUL;
            }
        }
        else
        {
            BIOS_REGISTERS Context;
            ULONG BiosCommand;

            Context = *KiPacket->Parameters.BiosCall.BiosArguments;
            BiosCommand = KiPacket->Parameters.BiosCall.BiosCommand;
            Status = Kd386CallBios(BiosCommand, (PCONTEXT)&Context) == FALSE ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
            *KiPacket->Parameters.BiosCall.BiosArguments = Context;
        }
        Print("CALL_BIOS = %p", Status);
        break;
    }
    case IOCTL_GET_KERNEL_INFO:
    {
        KiPacket->Parameters.KernelInformation.KernelBase = KernelBase;
        KiPacket->Parameters.KernelInformation.KernelSize = KernelSize;
        KiPacket->Parameters.KernelInformation.PsLoadedModuleList = *(PVOID *)KdVersionBlock->PsLoadedModuleList;
        KiPacket->Parameters.KernelInformation.MmLoadedUserImageList = *(PVOID *)KdVersionBlock->MmLoadedUserImageList;
        KiPacket->Parameters.KernelInformation.PspCidTable = *(PVOID *)KdVersionBlock->PspCidTable;
        break;   
    }
    case IOCTL_DISK_READWRITE:
    {
        Status = ReadWriteSector(KiPacket->Parameters.DiskReadWrite.Disk,
                                 KiPacket->Parameters.DiskReadWrite.SectorNumber,
                                 KiPacket->Parameters.DiskReadWrite.SectorCount,
                                 KiPacket->Parameters.DiskReadWrite.IsWrite,
                                 KiPacket->Parameters.DiskReadWrite.Buffer);
        break;
    }
    case IOCTL_PORT_READ:
    {
        USHORT PortNumber = KiPacket->Parameters.Common.Parameter2 & 0xFFFF;
        PVOID PortBuffer = (PVOID)KiPacket->Parameters.Common.Parameter3;
        ULONG PortCount = KiPacket->Parameters.Common.Parameter4;
        switch (KiPacket->Parameters.Common.Parameter1)
        {
        case 0:
            KiPacket->Parameters.Common.Parameter3 = __inbyte(PortNumber);
            break;
        case 1:
            KiPacket->Parameters.Common.Parameter3 = __inword(PortNumber);
            break;
        case 2:
            KiPacket->Parameters.Common.Parameter3 = __indword(PortNumber);
            break;
        case 3:
            __inbytestring(PortNumber, (PUCHAR)PortBuffer, PortCount);
            break;
        case 4:
            __inwordstring(PortNumber, (PUSHORT)PortBuffer, PortCount);
            break;
        case 5:
            __indwordstring(PortNumber, (PULONG)PortBuffer, PortCount);
            break;
        }
        break;
    }
    case IOCTL_PORT_WRITE:
    {
        USHORT PortNumber = KiPacket->Parameters.Common.Parameter2 & 0xFFFF;
        PVOID PortBuffer = (PVOID)KiPacket->Parameters.Common.Parameter3;
        ULONG PortCount = KiPacket->Parameters.Common.Parameter4;
        switch (KiPacket->Parameters.Common.Parameter1)
        {
        case 0:
            __outbyte(PortNumber, (UCHAR)PortBuffer);
            break;
        case 1:
            __outword(PortNumber, (USHORT)PortBuffer);
            break;
        case 2:
            __outdword(PortNumber, (ULONG)PortBuffer);
            break;
        case 3:
            __outbytestring(PortNumber, (PUCHAR)PortBuffer, PortCount);
            break;
        case 4:
            __outwordstring(PortNumber, (PUSHORT)PortBuffer, PortCount);
            break;
        case 5:
            __outdwordstring(PortNumber, (PULONG)PortBuffer, PortCount);
            break;
        }
        break;
    }
    case IOCTL_MSR:
        {
            if (!KiPacket->Parameters.Msr.Write)
            {
                KiPacket->Parameters.Msr.Value = __readmsr(KiPacket->Parameters.Msr.Register);
            }
            else
            {
                __writemsr(KiPacket->Parameters.Msr.Register, KiPacket->Parameters.Msr.Value);
            }
            break;
        }
    case IOCTL_IO_PACKET:
        {
            Status = SendIoPacket(&KiPacket->Parameters.IoPacket.Packet);
            break;
        }
    case IOCTL_GET_OBJECT_BY_HANDLE:
        {
            HANDLE Handle = (HANDLE)KiPacket->Parameters.Common.Parameter1;
            PVOID Object = NULL;

            Status = KdReferenceObjectByHandle(Handle, SYNCHRONIZE, NULL, KernelMode, &Object, NULL);
            if (NT_SUCCESS(Status))
            {
                ObDereferenceObject(Object);
            }
            KiPacket->Parameters.Common.Parameter2 = (ULONG_PTR)Object;
            break;
        }
	case IOCTL_CREATE_THREAD:
		{
			HANDLE Handle;
            PNULL_THREAD_CONTEXT Context = (PNULL_THREAD_CONTEXT)MmAlloc(sizeof(NULL_THREAD_CONTEXT));
            
            Context->Process = KiPacket->Parameters.CreateThread.Process;
            Context->Context = KiPacket->Parameters.CreateThread.Context;
            Context->StartAddress = KiPacket->Parameters.CreateThread.StartAddress;
            Status = PsCreateSystemThread(&Handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, NullSystemThread, Context);
			if(NT_SUCCESS(Status))
			{
                LARGE_INTEGER TimeOut;
                TimeOut.QuadPart = -100000000;
                ZwWaitForSingleObject(Handle, FALSE, &TimeOut);
				ZwClose(Handle);
			}
			break;
		}
    default:
        Status = STATUS_NOT_IMPLEMENTED;
    }

    VMProtectEnd;
    return Status;
}


NTSTATUS
DrvDispatch(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
)
{
    VMProtectBegin;

    PIO_STACK_LOCATION irpStack;
    NTSTATUS Status = STATUS_SUCCESS;


    irpStack = IoGetCurrentIrpStackLocation(Irp);
    switch (irpStack->MajorFunction)
    {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
    {
        break;
    }
    case IRP_MJ_DEVICE_CONTROL:
    {
        PIO_INPUT_BUFFER IoBuffer = (PIO_INPUT_BUFFER)Irp->UserBuffer;
        ULONG ControlCode = IoBuffer->ControlCode[IoBuffer->Index] ^ IoBuffer->Key;
        PVOID InputBuffer = (PVOID)((ULONG_PTR)IoBuffer->InputBuffer[IoBuffer->Index] ^ IoBuffer->Key);
        KeEnterCriticalRegion();
        ExAcquireResourceExclusiveLite(&DispatchResourceObject, TRUE);
        Status = IoDispatchHandler(ControlCode, (PKI_PACKET)InputBuffer);
        ExReleaseResourceLite(&DispatchResourceObject);
        KeLeaveCriticalRegion();
        break;
    }
    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
    }
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    VMProtectEnd;
    return Status;
}


VOID
DrvUnload(
    IN PDRIVER_OBJECT DriverObject
)
{
    VMProtectBegin;
    UNICODE_STRING		deviceLinkUnicodeString = RTL_CONSTANT_STRING(dos_DeviceName);

    IoDeleteSymbolicLink(&deviceLinkUnicodeString);
    IoDeleteDevice(DriverObject->DeviceObject);
    ExDeleteResourceLite(&DispatchResourceObject);
    MmFree(DbgBuffer);
    MmFree(ntoskrnl);
    MmFree(w32k);
    MmFree(FsdFastFat.MappedImage);
    MmFree(FsdNtfs.MappedImage);
    if (gDrivers)
    {
        delete gDrivers;
    }
    if (IsHookDebugService) 
        ExecuteOnAllProcessors(UnhookKiDebugService, TRUE);
#ifdef _REPORT_
    Print("%d -> %I64x", MemoryRef.Counter, MemoryRef.Mount);
#endif
    VMProtectEnd;
}


PVOID GetMmCopyVirtualMemory(PUCHAR ReadVirtualMemory)
{
    PUCHAR cptr;

    __try
    {
        if (MmIsAddressValid(ReadVirtualMemory))
        {
            for (cptr = ReadVirtualMemory; cptr < ReadVirtualMemory + PAGE_SIZE; ++cptr)
            {
                if ((*cptr == 0xe8) && ((cptr + *(PULONG)(cptr + 1) + 5) == KdGetSystemRoutineAddress(L"ObReferenceObjectByHandle")))
                {
                    ++cptr;
                    ++cptr;
                    for (; cptr < ReadVirtualMemory + PAGE_SIZE; ++cptr)
                    {
                        if (*cptr == 0xe8 && MmIsAddressValid((cptr + *(PULONG)(cptr + 1) + 5)))
                        {
                            if ((cptr + *(PULONG)(cptr + 1) + 5) == KdGetSystemRoutineAddress(L"ObfDereferenceObject"))
                            {
                                return NULL;
                            }
                            else if (*(cptr - 3) == 0xff && *(cptr - 2) == 0x75)
                            {
                                return (cptr + *(PULONG)(cptr + 1) + 5);
                            }
                        }
                    }
                    break;
                }
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
    }

    return NULL;
}


PVOID GetPsSuspendThread(PUCHAR lpNtSuspendThread)
{
    PUCHAR cptr;

    VMProtectBegin;

    __try
    {
        if (MmIsAddressValid(lpNtSuspendThread))
        {
            for (cptr = lpNtSuspendThread; cptr < lpNtSuspendThread + PAGE_SIZE; ++cptr)
            {
                if ((*cptr == 0xe8) && ((cptr + *(PULONG)(cptr + 1) + 5) == KdGetSystemRoutineAddress(L"ObReferenceObjectByHandle")))
                {
                    ++cptr;
                    ++cptr;
                    for (; cptr < lpNtSuspendThread + PAGE_SIZE; ++cptr)
                    {
                        if (*cptr == 0xe8 && MmIsAddressValid((cptr + *(PULONG)(cptr + 1) + 5)))
                        {
                            if ((cptr + *(PULONG)(cptr + 1) + 5) == KdGetSystemRoutineAddress(L"ObfDereferenceObject"))
                            {
                                return NULL;
                            }
                            else if (*(cptr - 3) == 0xff && *(cptr - 2) == 0x75)
                            {
                                return (cptr + *(PULONG)(cptr + 1) + 5);
                            }
                        }
                    }
                    break;
                }
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
    }

    VMProtectEnd;

    return NULL;
}

PVOID GetAlertThread(PUCHAR lpNtAlertThread)
{
    PUCHAR cptr;

    VMProtectBegin;
    __try
    {
        if (MmIsAddressValid(lpNtAlertThread))
        {
            for (cptr = lpNtAlertThread; cptr < lpNtAlertThread + PAGE_SIZE; ++cptr)
            {
                if ((*cptr == 0xe8) && ((cptr + *(PULONG)(cptr + 1) + 5) == KdGetSystemRoutineAddress(L"ObReferenceObjectByHandle")))
                {
                    ++cptr;
                    ++cptr;
                    for (; cptr < lpNtAlertThread + PAGE_SIZE; ++cptr)
                    {
                        if (*cptr == 0xe8 && MmIsAddressValid((cptr + *(PULONG)(cptr + 1) + 5)))
                        {
                            if ((cptr + *(PULONG)(cptr + 1) + 5) == KdGetSystemRoutineAddress(L"ObfDereferenceObject"))
                            {
                                return NULL;
                            }
                            else if (*(cptr - 3) == 0xff && *(cptr - 2) == 0x75)
                            {
                                return (cptr + *(PULONG)(cptr + 1) + 5);
                            }
                        }
                    }
                    break;
                }
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
    }

    VMProtectEnd;
    return NULL;
}


VOID EnumKdRoutines()
{
    VMProtectBegin;
    *(PVOID*)&KdQuerySystemInformation = KdGetSystemRoutineAddress(L"NtQuerySystemInformation");
    *(PVOID*)&KdStackAttachProcess = KdGetSystemRoutineAddress(L"KeStackAttachProcess");
    *(PVOID*)&KdUnstackDetachProcess = KdGetSystemRoutineAddress(L"KeUnstackDetachProcess");
    *(PVOID*)&KdLookupProcessByProcessId = KdGetSystemRoutineAddress(L"PsLookupProcessByProcessId");
    *(PVOID*)&KdLookupThreadByThreadId = KdGetSystemRoutineAddress(L"PsLookupThreadByThreadId");
    *(PVOID*)&KdOpenObjectByPointer = KdGetSystemRoutineAddress(L"ObOpenObjectByPointer");
    *(PVOID*)&KdReferenceObjectByHandle = KdGetSystemRoutineAddress(L"ObReferenceObjectByHandle");
    *(PVOID*)&KdClose = KdGetSystemRoutineAddress(L"NtClose");
    *(PVOID*)&KdOpenFile = KdGetSystemRoutineAddress(L"NtOpenFile");
    *(PVOID*)&KdGetPhysicalAddress = KdGetSystemRoutineAddress(L"MmGetPhysicalAddress");
    *(PVOID*)&KdGetVirtualForPhysical = KdGetSystemRoutineAddress(L"MmGetVirtualForPhysical");
    *(PVOID*)&KdOpenProcess = KdGetSystemRoutineAddress(L"NtOpenProcess");
    *(PVOID*)&KdOpenThread = KdGetSystemRoutineAddress(L"NtOpenThread");
    *(PVOID*)&KdDuplicateObject = KdGetSystemRoutineAddress(L"NtDuplicateObject");
    *(PVOID*)&KdEnumHandleTable = KdGetSystemRoutineAddress(L"ExEnumHandleTable");
    *(PVOID*)&KdInsertQueueApc = KdGetSystemRoutineAddress(L"KeInsertQueueApc");
    *(PVOID*)&KdTerminateSystemThread = KdGetSystemRoutineAddress(L"PsTerminateSystemThread");
    *(PVOID*)&KdMapViewOfSection = KdGetSystemRoutineAddress(L"MmMapViewOfSection");
    *(PVOID*)&KdUnmapViewOfSection = KdGetSystemRoutineAddress(L"MmUnmapViewOfSection");
    *(PVOID*)&KdOpenObjectByName = KdGetSystemRoutineAddress(L"ObOpenObjectByName");
    *(PVOID*)&KdDeregisterBugCheckReasonCallback = KdGetSystemRoutineAddress(L"KeDeregisterBugCheckReasonCallback");

    KLDR_DATA_TABLE_ENTRY *NtDllEntry = CONTAINING_RECORD(MmLoadedUserImageList->Flink, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    PVOID NtDll = LoadSystemFile("Ntdll.dll", NtDllEntry->DllBase, FALSE);
    if (NtDll)
    {
        *(PVOID*)&KdTerminateThread = (PVOID)((ULONG)info.SDT[SYSCALL_INDEX(GetProcAddress(NtDll, "ZwTerminateThread"))] + KernelDelta);
        *(PVOID*)&KdReadVirtualMemory = (PVOID)((ULONG)info.SDT[SYSCALL_INDEX(GetProcAddress(NtDll, "ZwReadVirtualMemory"))] + KernelDelta);
        *(PVOID*)&KdWriteVirtualMemory = (PVOID)((ULONG)info.SDT[SYSCALL_INDEX(GetProcAddress(NtDll, "ZwWriteVirtualMemory"))] + KernelDelta);
        *(PVOID*)&KdProtectVirtualMemory = (PVOID)((ULONG)info.SDT[SYSCALL_INDEX(GetProcAddress(NtDll, "ZwProtectVirtualMemory"))] + KernelDelta);
        *(PVOID*)&KdQueryVirtualMemory = (PVOID)((ULONG)info.SDT[SYSCALL_INDEX(GetProcAddress(NtDll, "ZwQueryVirtualMemory"))] + KernelDelta);
        *(PVOID*)&KdResumeThread = (PVOID)((ULONG)info.SDT[SYSCALL_INDEX(GetProcAddress(NtDll, "ZwResumeThread"))] + KernelDelta);
        *(PVOID*)&KdTerminateProcess = (PVOID)((ULONG)info.SDT[SYSCALL_INDEX(GetProcAddress(NtDll, "ZwTerminateProcess"))] + KernelDelta);
        *(PVOID*)&KdFlushInstructionCache = (PVOID)((ULONG)info.SDT[SYSCALL_INDEX(GetProcAddress(NtDll, "ZwFlushInstructionCache"))] + KernelDelta);
        *(PVOID*)&KdAllocateVirtualMemory = (PVOID)((ULONG)info.SDT[SYSCALL_INDEX(GetProcAddress(NtDll, "ZwAllocateVirtualMemory"))] + KernelDelta);
        *(PVOID*)&KdFreeVirtualMemory = (PVOID)((ULONG)info.SDT[SYSCALL_INDEX(GetProcAddress(NtDll, "ZwFreeVirtualMemory"))] + KernelDelta);
        *(PVOID*)&KdOpenDirectoryObject = (PVOID)((ULONG)info.SDT[SYSCALL_INDEX(GetProcAddress(NtDll, "ZwOpenDirectoryObject"))] + KernelDelta);
        *(PVOID*)&KdUnloadDriver = (PVOID)((ULONG)info.SDT[SYSCALL_INDEX(GetProcAddress(NtDll, "ZwUnloadDriver"))] + KernelDelta);
        *(PVOID*)&KdSuspendThread = (PVOID)((ULONG)info.SDT[SYSCALL_INDEX(GetProcAddress(NtDll, "ZwSuspendThread"))] + KernelDelta);
        *(PVOID*)&KdSuspendThread = GetPsSuspendThread((PUCHAR)KdSuspendThread);
        *(PVOID*)&KdAlertThread = (PVOID)((ULONG)info.SDT[SYSCALL_INDEX(GetProcAddress(NtDll, "ZwAlertThread"))] + KernelDelta);
        *(PVOID*)&KdAlertThread = GetAlertThread((PUCHAR)KdAlertThread);
        
        MmFree(NtDll);
    }

    if (IsXp)
    {
        *(PVOID*)&MmCopyVirtualMemory = GetMmCopyVirtualMemory((PUCHAR)KdReadVirtualMemory);
        *(PVOID*)&Kd386CallBios = KdGetSystemRoutineAddress(L"Ke386CallBios");
    }
    else if (IsVista || IsWin7)
    {
        UNICODE_STRING BiosCall_UNC = RTL_CONSTANT_STRING(L"x86BiosCall");
        *(PVOID*)&MmCopyVirtualMemory = KdGetSystemRoutineAddress(L"MmCopyVirtualMemory");
        *(PVOID*)&Kd386CallBios = MmGetSystemRoutineAddress(&BiosCall_UNC);
    }
    VMProtectEnd;
}


VOID
DpcRoutine(
    PKDPC Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
)
{
    PDPC_PARAMS Params = (PDPC_PARAMS)DeferredContext;
    Params->Proc(Params->Param);
    if (Params->Syncronous) KeSetEvent(Params->SyncEvent, IO_NO_INCREMENT, FALSE);
    MmFree(Params);
}


VOID
ExecuteOnProcessor(
    CCHAR Cpu,
    PCALLBACK_PROC Proc,
    ULONG Param,
    BOOLEAN Syncronous
)
{

    KEVENT	  SyncEvent;
    PDPC_PARAMS DpcParams;
    DpcParams = (PDPC_PARAMS)MmAlloc(sizeof(DPC_PARAMS));
    if (DpcParams)
    {
        KeInitializeEvent(&SyncEvent, NotificationEvent, FALSE);
        DpcParams->Syncronous	= Syncronous;
        DpcParams->Param		= Param;
        DpcParams->Proc			= Proc;
        DpcParams->SyncEvent	= &SyncEvent;

        KeInitializeDpc(&DpcParams->Dpc, DpcRoutine, DpcParams);
        KeSetTargetProcessorDpc(&DpcParams->Dpc, Cpu);
        KeInsertQueueDpc(&DpcParams->Dpc, NULL, NULL);
        if (Syncronous) KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
    }
}


VOID
ExecuteOnAllProcessors(
    PCALLBACK_PROC Proc,
    BOOLEAN Syncronous
)
{
    KIRQL	   OldIrql;

    if (KeNumberProcessors == 1)
    {
        OldIrql = KeRaiseIrqlToDpcLevel();
        Proc(0);
        KeLowerIrql(OldIrql);
    }
    else
    {
        for (int j = 0; j < KeNumberProcessors; ++j)
        {
            ExecuteOnProcessor((CCHAR)j, Proc, j, Syncronous);
        }
    }
}


bool __declspec(naked) IsPAEenabled()
{
    __asm __emit 0x0F; // mov eax, cr4
    __asm __emit 0x20;
    __asm __emit 0xE0;
    __asm shr eax, 5;
    __asm and eax, 1;
    __asm ret;
}


#define INIT_SUCCESS				0
#define INIT_UNSUPPORTED_OS			1
#define INIT_CANNOT_LOCATE_ITEMS	2
#define INIT_CANNOT_LOCATE_KERNEL	3
#define INIT_CANNOT_LOAD_KERNEL		4


LONG SetOSVariables()
{
    VMProtectBegin;
    RTL_OSVERSIONINFOEXW VersionInformation;

    VersionInformation.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
    RtlGetVersion((PRTL_OSVERSIONINFOW)&VersionInformation);
    if (IsXp)
    {
        PsIdleProcess = *(PEPROCESS*)(KdVersionBlock->PsActiveProcessHead - 4);
        info.Max_ServiceID						= 0x11c;
        if (VersionInformation.wServicePackMajor)
            info.Max_ShadowServiceID			= 0x29B;
        else
            info.Max_ShadowServiceID			= 0x29A;
        info.PsSizeofProcess					= 0x260;
        info.PsSizeofThread						= 0x258;
        info.PsActiveProcessLinks				= 0x088;
        info.PsExceptionPort					= 0x0c0;
        info.PsServiceTable						= 0x0e0;
        info.PsProcessRundown					= 0x080;
        info.PsThreadRundown					= 0x234;
        info.PsStartAddress						= 0x224;
        info.PsDeviceMap						= 0x15c;
        info.PsThreadListHead					= 0x190;
        info.PsKiThreadListEntry				= 0x1b0;
        info.PsKeThreadListEntry				= 0x22c;
        info.PsVirtualSize						= 0x0b0;
        info.PsSeAuditProcessCreationInfo		= 0x1f4;
        info.PsThreadFlags						= 0x248;
        info.PsProcessFlags						= 0x248;
        info.PsPreviousMode						= 0x140;
        info.PsObjectListHead					= 0x038;
        info.PsObjectTypeName					= 0x040;
        info.PsFreezeCount						= 0x1b8;
        info.PsSuspendSemaphore					= 0x19c;
        MaxCreateProcess						= 8;
    }
    else if (IsVista)
    {
        PsIdleProcess = *(PEPROCESS*)((ULONG)&PsInitialSystemProcess + 4);
        if (KdBuildNumber == 6000)
        {
            info.Max_ServiceID					= 0x18E;
        }
        else
        {
            info.Max_ServiceID					= 0x187;
        }
        info.Max_ShadowServiceID				= 0x304;
        info.PsSizeofProcess					= 0x270;
        info.PsSizeofThread						= 0x288;
        info.PsActiveProcessLinks				= 0x0a0;
        info.PsExceptionPort					= 0x0d8;
        info.PsServiceTable						= 0x12c;
        info.PsProcessRundown					= 0x098;
        info.PsThreadRundown					= 0x250;
        info.PsStartAddress						= 0x1f8;
        info.PsDeviceMap						= 0x134;
        info.PsThreadListHead					= 0x168;
        info.PsKiThreadListEntry				= 0x1c4;
        info.PsKeThreadListEntry				= 0x248;
        info.PsVirtualSize						= 0x0c8;
        info.PsSeAuditProcessCreationInfo		= 0x1cc;
        info.PsThreadFlags						= 0x260;
        info.PsProcessFlags						= 0x228;
        info.PsPreviousMode						= 0x0e7;
        info.PsObjectListHead					= 0x038;
        info.PsObjectTypeName					= 0x040;
        MaxCreateProcess						= 12;
        if (KdBuildNumber >= 6001)
        {
            MaxCreateProcess					= 64;
            info.PsObjectListHead				= 0x000;
            info.PsObjectTypeName				= 0x008;
        }
        info.PsFreezeCount						= 0x16b;
        info.PsSuspendSemaphore					= 0x1ac;
    }
    else if (IsWin7)
    {
        PsIdleProcess = *(PEPROCESS*)((ULONG)&PsInitialSystemProcess + 4);
        info.Max_ServiceID						= 0x191;
        info.Max_ShadowServiceID				= 0x339;
        info.PsSizeofProcess					= 0x2C0;
        info.PsSizeofThread						= 0x2B8;
        info.PsActiveProcessLinks				= 0x0b8;
        info.PsExceptionPort					= 0x0f0;
        info.PsServiceTable						= 0x0bc;
        info.PsProcessRundown					= 0x0B0;
        info.PsThreadRundown					= 0x270;
        info.PsStartAddress						= 0x218;
        info.PsDeviceMap						= 0x150;
        info.PsThreadListHead					= 0x188;
        info.PsKiThreadListEntry				= 0x1E0;
        info.PsKeThreadListEntry				= 0x268;
        info.PsVirtualSize						= 0x0E0;
        info.PsSeAuditProcessCreationInfo		= 0x1EC;
        info.PsThreadFlags						= 0x280;
        info.PsProcessFlags						= 0x270;
        info.PsPreviousMode						= 0x13A;
        info.PsObjectListHead					= 0x000;
        info.PsObjectTypeName					= 0x008;
        info.PsFreezeCount						= 0x140;
        info.PsSuspendSemaphore					= 0x1C8;
        MaxCreateProcess						= 64;
    }
    else
    {
        return INIT_UNSUPPORTED_OS;
    }

    VMProtectEnd;

    return INIT_SUCCESS;
}


VOID GetKernelBase()
{
    PKLDR_DATA_TABLE_ENTRY LdrDataTableEntry;
    PLIST_ENTRY Next;
    WCHAR buffer[MAX_PATH];

    Next = PsLoadedModuleList->Flink;
    while (Next != PsLoadedModuleList)
    {
        if (!MmIsAddressValid(Next)) return;
        LdrDataTableEntry = CONTAINING_RECORD(Next, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (MmIsAddressValid(LdrDataTableEntry))
        {
            RtlZeroMemory(buffer, sizeof(buffer));
            CopyUnicodeString(buffer, &LdrDataTableEntry->FullDllName, MAX_PATH);
            PWCHAR FileName = wExtractFileName(buffer);
            
            if (_wcsicmp(FileName, CurrentKernel) == 0)
            {
                KernelBase = LdrDataTableEntry->DllBase;
                KernelSize = LdrDataTableEntry->SizeOfImage;
            }
            if (_wcsicmp(FileName, L"win32k.sys") == 0)
            {
                w32kBase = LdrDataTableEntry->DllBase;
                w32kSize = LdrDataTableEntry->SizeOfImage;
            }
        }
        Next = Next->Flink;
    }
}


VOID EnumObjectTypes()
{
    UNICODE_STRING DirectoryName = RTL_CONSTANT_STRING(L"\\ObjectTypes");
    OBJECT_ATTRIBUTES ObjectAttributes = RTL_INIT_OBJECT_ATTRIBUTES(&DirectoryName, OBJ_CASE_INSENSITIVE);;
    NTSTATUS Status;
    HANDLE Handle;
    POBJECT_DIRECTORY Directory = NULL;
    POBJECT_DIRECTORY_ENTRY DirectoryEntry;
    POBJECT_DIRECTORY_ENTRY DirectoryEntryNext;
    ULONG Bucket;
    KPROCESSOR_MODE PreviousMode;


    PreviousMode = KeSetPreviousMode(KernelMode);
    Status = KdOpenDirectoryObject(&Handle, DIRECTORY_QUERY, &ObjectAttributes);
    KeSetPreviousMode(PreviousMode);
    if (NT_SUCCESS (Status))
    {
        Status = KdReferenceObjectByHandle(Handle, SYNCHRONIZE, NULL, KernelMode, (PVOID *)&Directory, NULL);
        if (NT_SUCCESS (Status))
        {
            for (Bucket = 0; Bucket < NUMBER_HASH_BUCKETS; Bucket++)
            {
                DirectoryEntry = DirectoryEntryNext = Directory->HashBuckets[Bucket];
                while (MmIsAddressValid(DirectoryEntryNext))
                {
                    POBJECT_TYPE Object = (POBJECT_TYPE)DirectoryEntryNext->Object;
                    ULONG Index;
                    if (KdBuildNumber >= 6001)
                    {
                        Index = *((PUCHAR)Object + 0x14);
                    }
                    else
                    {
                        Index = Object->ObjectTypeIndex;
                    }
                    if (Index < 256)
                        TypesArray[Index] = Object;
                    DirectoryEntryNext = DirectoryEntryNext->ChainLink;
                }
            }
            ObDereferenceObject(Directory);
        }
        ZwClose(Handle);
    }

    for (ULONG n = 0; n < 256; ++n)
    {
        if (TypesArray[n])
        {
            Print("#%u %wZ", n, parseobject(TypesArray[n], ObjectTypeName, UNICODE_STRING));
        }
    }
}


POBJECT_TYPE TypeFromObject(POBJECT_HEADER ObjectHeader)
{
    if (MmIsAddressValid(ObjectHeader))
    {
        if (IsWin7)
        {
            return TypesArray[ObjectHeader->Flags.NameInfoOffset];
        }
        else
        {
            return ObjectHeader->ObjectType;
        }
    }
    else
    {
        return NULL;
    }
}


LONG Initialize(PKI_PACKET KiPacket)
{
    KdBuildNumber = KiPacket->Parameters.Initialize.NtBuildNumber;
    switch (KdBuildNumber)
    {
    case 2600:
    case 6000:
    case 6001:
    case 6002:
    case 7600:
    case 7601:
        break;
    default:
        return INIT_UNSUPPORTED_OS;
    }

    info.PsObjectListHead			= 0x038;
    info.PsObjectTypeName			= 0x040;
    if (KdBuildNumber >= 6001)
    {
        info.PsObjectListHead		= 0x000;
        info.PsObjectTypeName		= 0x008;
    }

    IsHookDebugService = KiPacket->Parameters.Initialize.CaptureDbgMode;
    if (IsHookDebugService)
        ExecuteOnAllProcessors(HookKiDebugService, TRUE);

    KAFFINITY Affinity = 1 << 0;
    KeSetAffinityThread(KeGetCurrentThread(), Affinity);

    __asm nop;
    __asm mov eax, _PCR KPCR.KdVersionBlock;
    __asm mov KdVersionBlock, eax;

    Affinity = KeQueryActiveProcessors();
    KeSetAffinityThread(KeGetCurrentThread(), Affinity);


    if (KdVersionBlock == 0)
        return INIT_CANNOT_LOCATE_ITEMS;

    if (MmIsAddressValid(KdVersionBlock) == 0)
        return INIT_CANNOT_LOCATE_ITEMS;

    PsLoadedModuleList = (PLIST_ENTRY)KdVersionBlock->PsLoadedModuleList;
    MmLoadedUserImageList = (PLIST_ENTRY)KdVersionBlock->MmLoadedUserImageList;
    if (PsLoadedModuleList == 0)
        return INIT_CANNOT_LOCATE_ITEMS;

    Print("PsLoadedModuleList -> %p", PsLoadedModuleList);
    Print("Debug %p", KdVersionBlock);
    Print("Debug->Pae %s", KdVersionBlock->PaeEnabled ? "enabled" : "disabled");
    Print("Debug->Base %p", KdVersionBlock->KernBase);
    Print("Debug->MmUnloadedDrivers %p", KdVersionBlock->MmUnloadedDrivers);
    Print("Debug->ObpRootDirectoryObject %p", *(PVOID *)KdVersionBlock->ObpRootDirectoryObject);


    wcscpy(SystemrootPath, KiPacket->Parameters.Initialize.SystemrootPath);
    WCHAR Buffer[260] = L"";
    KLDR_DATA_TABLE_ENTRY *LdrDataTableEntry = CONTAINING_RECORD(PsLoadedModuleList->Flink, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    Print("%wZ", &LdrDataTableEntry->FullDllName);
    CopyUnicodeString(Buffer, &LdrDataTableEntry->FullDllName, COF(Buffer));
    wcscpy(CurrentKernel, wExtractFileName(Buffer));
    wcscpy(KiPacket->Parameters.Initialize.KernelFileName, wExtractFileName(Buffer));
    Print("Kernel Module :: %ls", CurrentKernel);
    Print("%ls", SystemPath);
    GetKernelBase();
    Print("KernelBase :: %p -> %p", KernelBase, KernelSize);
    Print("w32kBase :: %p -> %p", w32kBase, w32kSize);
    if (!KernelBase || !KernelSize || !w32kBase || !w32kSize) return INIT_CANNOT_LOCATE_KERNEL;
    CHAR krnl[260] = "";
    sprintf(krnl, "%S", CurrentKernel);

    VMProtectBegin;

    UNICODE_STRING uFileSystemName;
    RtlInitUnicodeString(&uFileSystemName, L"\\FileSystem\\Fastfat");
    ObReferenceObjectByName(&uFileSystemName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID *)&FsdFastFat.DriverObject);
    if (FsdFastFat.DriverObject)
    {
        Print("FsdFastFat.DriverObject = %p", FsdFastFat.DriverObject);
        FsdFastFat.MappedImage = LoadSystemFile("Fastfat.sys", FsdFastFat.DriverObject->DriverStart, FALSE);
        if (FsdFastFat.MappedImage)
        {
            FsdFastFat.MajorFunction[IRP_MJ_CREATE] = GetFileSystemMajorFunction(&FsdFastFat, IRP_MJ_CREATE);
            FsdFastFat.MajorFunction[IRP_MJ_READ] = GetFileSystemMajorFunction(&FsdFastFat, IRP_MJ_READ);
            FsdFastFat.MajorFunction[IRP_MJ_WRITE] = GetFileSystemMajorFunction(&FsdFastFat, IRP_MJ_WRITE);
            FsdFastFat.MajorFunction[IRP_MJ_SET_INFORMATION] = GetFileSystemMajorFunction(&FsdFastFat, IRP_MJ_SET_INFORMATION);
            FsdFastFat.MajorFunction[IRP_MJ_QUERY_INFORMATION] = GetFileSystemMajorFunction(&FsdFastFat, IRP_MJ_QUERY_INFORMATION);
            FsdFastFat.MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = GetFileSystemMajorFunction(&FsdFastFat, IRP_MJ_DIRECTORY_CONTROL);
        }
        ObDereferenceObject(FsdFastFat.DriverObject);
    }

    RtlInitUnicodeString(&uFileSystemName, L"\\FileSystem\\Ntfs");
    ObReferenceObjectByName(&uFileSystemName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID *)&FsdNtfs.DriverObject);
    if (FsdNtfs.DriverObject)
    {
        Print("FsdNtfs.DriverObject = %p", FsdNtfs.DriverObject);
        FsdNtfs.MappedImage = LoadSystemFile("Ntfs.sys", FsdNtfs.DriverObject->DriverStart, FALSE);
        if (FsdNtfs.MappedImage)
        {
            FsdNtfs.MajorFunction[IRP_MJ_CREATE] = GetFileSystemMajorFunction(&FsdNtfs, IRP_MJ_CREATE);
            FsdNtfs.MajorFunction[IRP_MJ_READ] = GetFileSystemMajorFunction(&FsdNtfs, IRP_MJ_READ);
            FsdNtfs.MajorFunction[IRP_MJ_WRITE] = GetFileSystemMajorFunction(&FsdNtfs, IRP_MJ_WRITE);
            FsdNtfs.MajorFunction[IRP_MJ_SET_INFORMATION] = GetFileSystemMajorFunction(&FsdNtfs, IRP_MJ_SET_INFORMATION);
            FsdNtfs.MajorFunction[IRP_MJ_QUERY_INFORMATION] = GetFileSystemMajorFunction(&FsdNtfs, IRP_MJ_QUERY_INFORMATION);
            FsdNtfs.MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = GetFileSystemMajorFunction(&FsdNtfs, IRP_MJ_DIRECTORY_CONTROL);
        }
        ObDereferenceObject(FsdNtfs.DriverObject);
    }


    if (ntoskrnl = LoadSystemFile(krnl, KernelBase, FALSE))
    {
        KdBuildNumber = *(PSHORT)KdGetSystemRoutineAddress(L"NtBuildNumber");
        KdServiceDescriptorTable = GetAddrssofServiceTable();
        Print("ntoskrnl --> 0x%08x", ntoskrnl);
        info.SDT = GetRealServiceTable(ntoskrnl, KernelSize);
        Print("SSDT :: %08X", info.SDT);
        KernelDelta = (ULONG)ntoskrnl - (ULONG)KernelBase;
        EnumKdRoutines();
        KiWaitListHead = GetKiWaitListHead();
        Print("KiWaitListHead = %p", KiWaitListHead);
        if (INIT_SUCCESS != SetOSVariables()) return INIT_UNSUPPORTED_OS;
        if (!MmIsAddressValid(PsIdleProcess)) return INIT_CANNOT_LOCATE_ITEMS;
        // Enumerate Object types
        EnumObjectTypes();
        gDrivers = new CDriver();
        gDrivers->Scan();
        gDrivers->ScanPhysicalMemory();
        PULONG idt = GetRealIDT(ntoskrnl, KernelDelta);
        RtlZeroMemory(KiPacket->Parameters.Initialize.InterruptServiceRoutines, sizeof(ULONG_PTR) * 256);
        if (idt)
        {
            for (ULONG c = 0; c < 256; ++c)
            {
                KiPacket->Parameters.Initialize.InterruptServiceRoutines[c] = idt[c*2];
            }
        }
        if (info.SDT)
        {
            for (ULONG c = 0; c < info.Max_ServiceID; ++c)
            {
                KiPacket->Parameters.Initialize.Ssdt[c] = (ULONG)info.SDT[c];
            }
        }
        if (w32k = LoadSystemFile("win32k.sys", w32kBase, FALSE))
        {
            Print("win32k --> 0x%08x", w32k);
            KeServiceDescriptorTableShadow = GetAddrssofShadowTable();
            Print("KeServiceDescriptorTableShadow :: %p", KeServiceDescriptorTableShadow);
            info.ShadowSDT = GetRealShadowServiceTable(w32k, w32kBase, w32kSize);
            Print("ShadowSDT :: %08X", info.ShadowSDT);
            w32kDelta = (ULONG)w32k - (ULONG)w32kBase;
            if (info.ShadowSDT)
            {
                for (ULONG c = 0; c < info.Max_ShadowServiceID; ++c)
                {
                    KiPacket->Parameters.Initialize.ShadowSsdt[c] = (ULONG)info.ShadowSDT[c];
                }
            }
        }
    }
    VMProtectEnd;
    if (!ntoskrnl || !w32k) return INIT_CANNOT_LOAD_KERNEL;

    if (!GetNotifyRoutinesHeadLists())
        Print("Cannot Get PsXxxNotifyRoutines");

    CProcess Prc;
    DispatchLock lock;
    UNICODE_STRING ApiPortName = RTL_CONSTANT_STRING(L"\\Windows\\ApiPort");

    lock.Lock();
    Prc.GrabProcess(PsIdleProcess);
    Prc.ScanCidTable();
    Prc.ScanTypeList();
    Prc.ScanSessionList();
    lock.Unlock();
    for (ULONG n = 0; n < Prc.ProcessCount; n++)
    {
        PCHAR ProcName = PsGetProcessImageFileName(Prc.ProcessArray[n]);
        if (!_strnicmp(ProcName, "CSRSS.EXE", 16))
        {
            ULONG nHandles = 0;
            PHANDLE_INFORMATION_LITE CsrHandles = (PHANDLE_INFORMATION_LITE)GetProcessHandles(Prc.ProcessArray[n], nHandles, FALSE);
            if (CsrHandles != NULL)
            {
                for (ULONG m = 0; m < nHandles; m++)
                {
                    POBJECT_NAME_INFORMATION ObjectNameInfo = (POBJECT_NAME_INFORMATION)MmAlloc(PAGE_SIZE);
                    if (ObjectNameInfo)
                    {
                        ULONG RetLength = 0;
                        if (NT_SUCCESS(ObQueryNameString(CsrHandles[m].Object, ObjectNameInfo, PAGE_SIZE, &RetLength)))
                        {
                            if (!RtlCompareUnicodeString(&ApiPortName, &ObjectNameInfo->Name, FALSE))
                            {
                                CsrProcess = Prc.ProcessArray[n];
                            }
                        }
                        MmFree(ObjectNameInfo);
                    }
                    if (CsrProcess && (KiPacket->Parameters.Initialize.CsrProcessId == 0 || KiPacket->Parameters.Initialize.CsrProcessId == PsGetProcessId(CsrProcess)))
                        break;
                }
                MmFree(CsrHandles);
            }
        }
        if (CsrProcess && (KiPacket->Parameters.Initialize.CsrProcessId == 0 || KiPacket->Parameters.Initialize.CsrProcessId == PsGetProcessId(CsrProcess)))
            break;
    }

    KiPacket->Parameters.Initialize.KiKdProcess = PsGetCurrentProcess();
    KiPacket->Parameters.Initialize.KiCsrProcess = CsrProcess;
    KiPacket->Parameters.Initialize.KiSystemProcess = PsInitialSystemProcess;
    KiPacket->Parameters.Initialize.KiIdleProcess = PsIdleProcess;
    Print("CsrProcess = %d|%p", KiPacket->Parameters.Initialize.CsrProcessId, CsrProcess);

    if (CsrProcess == NULL || !MmIsAddressValid(CsrProcess))
        return INIT_CANNOT_LOCATE_ITEMS;


    Print("MmLoadedUserImageList = %p", KdVersionBlock->MmLoadedUserImageList);
    return INIT_SUCCESS;
}


extern "C"
    NTSTATUS
    DriverEntry(
        IN PDRIVER_OBJECT DriverObject,
        IN PUNICODE_STRING RegistryPath
    )
{
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status;
    UNICODE_STRING deviceNameUnicodeString;
    UNICODE_STRING deviceLinkUnicodeString;
    WCHAR Buffer[MAX_PATH];


#ifdef _REPORT_
    if (InitializeReport(L"\\??\\c:\\kd.log") == 0)
        Print("can't create log file");
#endif


    KdDriverObject = DriverObject;
    CopyUnicodeString(Buffer, RegistryPath, MAX_PATH);
    _snwprintf(nt_DeviceName, MAX_PATH, L"\\Device\\%s", wExtractFileName(Buffer));
    _snwprintf(dos_DeviceName, MAX_PATH, L"\\DosDevices\\%s", wExtractFileName(Buffer));

    RtlInitUnicodeString(&deviceNameUnicodeString, nt_DeviceName);
    RtlInitUnicodeString(&deviceLinkUnicodeString, dos_DeviceName);
    IoDeleteSymbolicLink(&deviceLinkUnicodeString);
    status = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), &deviceNameUnicodeString, FILE_DEVICE_CORE, 0, TRUE, &deviceObject);
    if (NT_SUCCESS(status))
    {
        InitSpinLock();
        ExInitializeResourceLite(&DispatchResourceObject);
        status = IoCreateSymbolicLink(&deviceLinkUnicodeString, &deviceNameUnicodeString);
        DriverObject->MajorFunction[IRP_MJ_CREATE]			=
        DriverObject->MajorFunction[IRP_MJ_CLOSE]			=
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]	= DrvDispatch;
        DriverObject->DriverUnload							= DrvUnload;
    }
    if (!NT_SUCCESS(status))
    {
        if (deviceObject) IoDeleteDevice(deviceObject);
    }
    
    return status;
}
