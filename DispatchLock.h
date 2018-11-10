#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>


class DispatchLock
{
public :
	DispatchLock();
	~DispatchLock();
	VOID Lock();
	VOID Unlock();

private :
	VOID static LockCurrentProcessor(PKDPC, PVOID, PVOID, PVOID);

private :
	volatile LONG NumberOfRaisedCPU, AllCPURaised;
	PKDPC Dpc;
	KIRQL Irql;
	ULONG CurrentCpu;

};



#ifdef __cplusplus
}
#endif