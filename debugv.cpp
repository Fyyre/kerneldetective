/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		debugv.c
 *
 * Abstract:
 *
 *		This module implements various routines used to hook debug messages.
 *
 * Author:
 *
 *		GamingMasteR
 *
 */








#include "KeDetective.h"
#include "debugv.h"
#include "interrupt.h"





PVOID KiDebugService[2];
PCHAR DbgBuffer;
ULONG DbgCount;
BOOL  IsHookDebugService = 0;
BOOL  bServicing = FALSE;


VOID DbgMsg(PCHAR String, SIZE_T Length)
{
	LPDBGMSG		tmp;
	LARGE_INTEGER	CurrentTime;
	LARGE_INTEGER	LocalTime;


    while (bServicing == TRUE)
        __asm nop;

    bServicing = TRUE;

    Length = min(Length, 512);
    Length = GetSystemBufferSize(String, Length);

    if (Length == 0)
        goto __exit;

	__try
	{
        
		DbgBuffer = (PCHAR)MmRealloc(DbgBuffer, (DbgCount + 1) * sizeof(DBGMSG));
		if (DbgBuffer)
		{
			tmp = &(((LPDBGMSG)DbgBuffer)[DbgCount]);
			tmp->Cid.UniqueProcess = PsGetCurrentProcessId();
			tmp->Cid.UniqueThread = PsGetCurrentThreadId();
			_snwprintf(tmp->process, 16, L"%S", PsGetProcessImageFileName(IoGetCurrentProcess()));
			KeQuerySystemTime( &CurrentTime );
			ExSystemTimeToLocalTime( &CurrentTime, &LocalTime );
			tmp->time = LocalTime;
			_snwprintf(tmp->Msg, Length, L"%S", String);
			DbgCount += 1;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
    {
    }

__exit:
	bServicing = FALSE;
}


VOID 
__declspec(naked) 
KiDebugServiceHandler(
	)
{
	__asm	pushad;
	__asm	pushfd;
    __asm   cmp eax, 1;
    __asm   jne __finish;
	__asm	mov bx, 0x30;
	__asm	mov fs, bx;
	__asm	mov bx, 0x23;
	__asm	mov ds, bx;
    __asm	mov es, bx;
	__asm	mov gs, bx;
	__asm	push edx;
	__asm	push ecx;
	__asm	call DbgMsg;
__finish:
	__asm	popfd;
	__asm	popad;
	__asm	jmp KiDebugService;
};


VOID 
HookKiDebugService(
	ULONG Cpu
	)
{
	KiDebugService[Cpu] = (PVOID)HookInterrup(0x2d, (ULONG_PTR)KiDebugServiceHandler);
};


VOID
UnhookKiDebugService(
	ULONG Cpu
	)
{
	HookInterrup(0x2d, (ULONG_PTR)KiDebugService[Cpu]);
};