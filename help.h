/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		help.h
 *
 * Abstract:
 *
 *		This module defines various miscellaneous routines.
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
InitSpinLock(
	);


KIRQL
LockSpin(
	VOID
	);


VOID
UnlockSpin(
	KIRQL OldIrql
	);


LPSTR
ExtractFileName(
	LPSTR str
	);


PWCHAR
wExtractFileName(
	PWCHAR str
	);

VOID 
CopyUnicodeString(
    PWSTR DestinationString,
    PUNICODE_STRING SourceString, 
    SIZE_T Size
    );

VOID 
CopyUnicodeStringFile(
    PWSTR DestinationString,
    PUNICODE_STRING SourceString, 
    SIZE_T Size
    );

LPWSTR
wExtractPath(
	LPWSTR str
	);


void
InterlockedExchange16(
	volatile unsigned short *Target, 
	unsigned short Value);


KPROCESSOR_MODE
KeSetPreviousMode(
	KPROCESSOR_MODE mode
	);


#ifdef __cplusplus
	}
#endif