/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		interrupt.h
 *
 * Abstract:
 *
 *		This module defines various routines used to deal with Interrupts.
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


#pragma pack(1)
typedef struct _IDT {    
    USHORT		wLimit;
	PKIDT_ENTRY	Base;
}IDT, *PIDT;


typedef struct _GDT {
    USHORT		wLimit;
	PKGDTENTRY	Base;
}GDT, *PGDT;
#pragma pack()


PULONG
GetRealIDT(
	PVOID file,
	ULONG delta
	);


VOID
HackIDT(
	PVOID* lpBuffer
	);


ULONG_PTR
HookInterrup(
	int interrupt,
	ULONG_PTR Address
	);


USHORT
HookInterrupSel(
	int interrupt,
	USHORT Selector
	);






#ifdef __cplusplus
	}
#endif