/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		unhook.c
 *
 * Abstract:
 *
 *		This module defines various routines used to detect code hooks .
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




ULONG
ScanModule(
	PHOOK_ENTRY *lpBuffer,
	ULONG file,
	ULONG Base,
	ULONG Flags
	);


ULONG
AnalyzeHook(
	PUCHAR Current,
	PUCHAR Origin,
	ULONG cb,
	ULONG *Destination
	);


VOID
UnhookCode(
	PVOID Address,
	ULONG cb 
	);


#ifdef __cplusplus
	}
#endif