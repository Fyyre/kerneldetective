/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		debugv.h
 *
 * Abstract:
 *
 *		This module defines various routines used to hook debug messages.
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



VOID
DbgMsg(
	IN PCHAR String,
	IN SIZE_T cb
	);


VOID
KiDebugServiceHandler(
	);


VOID
HookKiDebugService(
	ULONG Cpu
	);


VOID
UnhookKiDebugService(
	ULONG Cpu
	);



extern PCHAR DbgBuffer;
extern ULONG DbgCount;
extern BOOL	IsHookDebugService;

#ifdef __cplusplus
	}
#endif