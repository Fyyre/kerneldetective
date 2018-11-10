
#include "DispatchLock.h"



DispatchLock::DispatchLock() 
{ 
	Dpc = (PKDPC)ExAllocatePoolWithTag(NonPagedPool, KeNumberProcessors * sizeof(KDPC), 'abiS');
	CurrentCpu = KeGetCurrentProcessorNumber();
}


DispatchLock::~DispatchLock() 
{
	if (Dpc) 
	{
		ExFreePoolWithTag(Dpc, 'abiS');
		Dpc = NULL;
	}
	NumberOfRaisedCPU = AllCPURaised = 0;
}


VOID DispatchLock::Lock()
{
	CCHAR Count;

	NumberOfRaisedCPU = AllCPURaised = 0;
    Irql = KeRaiseIrqlToDpcLevel();

    if (Dpc == NULL)
        return;

    for (Count = 0; Count < KeNumberProcessors; ++Count)
    {
        // Make sure we don't schedule a DPC on the current
        // processor. This would cause a deadlock.
		if (Count != CurrentCpu)
        {
            KeInitializeDpc(&Dpc[Count], LockCurrentProcessor, this);
            // Set the target processor for the DPC; otherwise,
            // it will be queued on the current processor when
            // we call KeInsertQueueDpc.
            KeSetTargetProcessorDpc(&Dpc[Count], Count);
            KeInsertQueueDpc(&Dpc[Count], NULL, NULL);
        }
    }

    while (InterlockedCompareExchange(&NumberOfRaisedCPU, KeNumberProcessors - 1, KeNumberProcessors - 1) != KeNumberProcessors - 1)
    {
        __asm nop;
    }
}


VOID DispatchLock::LockCurrentProcessor(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	DispatchLock *ptr_this = (DispatchLock *)DeferredContext;
    InterlockedIncrement(&ptr_this->NumberOfRaisedCPU);
    while (!InterlockedCompareExchange(&ptr_this->AllCPURaised, 1, 1))
    {
        __asm nop;
    }
    InterlockedDecrement(&ptr_this->NumberOfRaisedCPU);
}


VOID DispatchLock::Unlock()
{
    InterlockedIncrement(&AllCPURaised); // Each DPC will decrement
    // the count now and exit.
    // We need to free the memory allocated for the DPCs.
    while (InterlockedCompareExchange(&NumberOfRaisedCPU, 0, 0))
    {
        __asm nop;
    }
	KeLowerIrql(Irql);
}