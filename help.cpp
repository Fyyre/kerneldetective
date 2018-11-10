/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		help.c
 *
 * Abstract:
 *
 *		This module implements various miscellaneous routines.
 *
 * Author:
 *
 *		GamingMasteR
 *
 */








#include "KeDetective.h"


KSPIN_LOCK  MsgSpinLock;




VOID
InitSpinLock(
	)
{
	KeInitializeSpinLock(&MsgSpinLock);
};

KIRQL
LockSpin(
	VOID
	)
{
	KIRQL OldIrql = KeGetCurrentIrql();
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
	{
		KeAcquireSpinLock(&MsgSpinLock, &OldIrql);
	}
	return OldIrql;
}


VOID
UnlockSpin(
	KIRQL OldIrql
	)
{
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
	{
		KeReleaseSpinLock(&MsgSpinLock, OldIrql);
	};
};


LPSTR
ExtractFileName(
	LPSTR Str
	)
{
	for	(unsigned long i = strlen(Str) - 1; i > 0; --i)
    {
		if (Str[i] == '\\')
        {
			return Str+i+1;
        }
    }
	return Str;
};


PWCHAR
wExtractFileName(
	PWCHAR Str
	)
{
	for	(unsigned long i = wcslen(Str) - 1; i > 0; --i)
    {
		if (Str[i] == '\\')
        {
			return Str+i+1;
        }
    }
	return Str;
}


LPWSTR
wExtractPath(
	LPWSTR str
	)
{
	int i;
	for	(i = wcslen(str);i>0;i--)
		if (str[i] == *L"\\")
		{
			str[i+1] = 0;
			return str;
		}
	return str;
};


VOID CopyUnicodeStringFile(PWSTR DestinationString, PUNICODE_STRING SourceString, SIZE_T Size)
{
    PWSTR Buffer;

    if (DestinationString)
    {
        if (SourceString && MmIsAddressValid(SourceString))
        {
            if (SourceString->Buffer && SourceString->Length && MmIsAddressValid(SourceString->Buffer))
            {
                if (SourceString->Length >= 256 * 2)
                {
                    Buffer = (PWSTR)MmAlloc(0x8200 * 2);
                    CopyUnicodeString(Buffer, SourceString, 0x8200);
                    wcsncpy(DestinationString, wExtractFileName(Buffer), Size);
                    MmFree(Buffer);
                }
                else
                {
                    CopyUnicodeString(DestinationString, SourceString, Size);
                }
            }
            else
            {
                wcsncpy(DestinationString, L"(null)", Size);
            }
        }
        else
        {
            wcsncpy(DestinationString, L"(null)", Size);
        }
    }
}


VOID CopyUnicodeString(PWSTR DestinationString, PUNICODE_STRING SourceString, SIZE_T Size)
{
    SIZE_T Count;

    if (DestinationString)
    {
        RtlZeroMemory(DestinationString, Size * sizeof(WCHAR));
        if (SourceString && MmIsAddressValid(SourceString))
        {
            if (SourceString->Buffer && SourceString->Length && MmIsAddressValid(SourceString->Buffer))
            {
                Count = min((USHORT)Size, SourceString->Length / 2);
                wcsncpy(DestinationString, SourceString->Buffer, Count);
            }
            else
            {
                wcsncpy(DestinationString, L"(null)", Size);
            }
        }
        else
        {
            wcsncpy(DestinationString, L"(null)", Size);
        }
    }
}


void 
InterlockedExchange16(
	volatile unsigned short *Target, 
	unsigned short Value)
{
	__asm push edx;
	__asm push ecx;
	__asm mov ecx, Target;
	__asm mov dx, Value;
	__asm xchg word ptr [ecx], dx;
	__asm pop ecx;
	__asm pop edx;
};


KPROCESSOR_MODE
KeSetPreviousMode(
	KPROCESSOR_MODE mode
	)
{
	ULONG			eThread;
	KPROCESSOR_MODE	rc;
	eThread = (ULONG)PsGetCurrentThread();
	rc = *parseobject(eThread, PreviousMode, KPROCESSOR_MODE);
	*parseobject(eThread, PreviousMode, KPROCESSOR_MODE) = mode;
	return rc;
};