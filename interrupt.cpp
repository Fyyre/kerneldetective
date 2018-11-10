/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		interrupt.c
 *
 * Abstract:
 *
 *		This module implements various routines used to deal with Interrupts.
 *
 * Author:
 *
 *		GamingMasteR
 *
 */








#include "KeDetective.h"
#include "interrupt.h"


PULONG
GetRealIDT(
	PVOID file,
	ULONG delta
	)
{
	VMProtectBegin;

	PUCHAR EntryPoint = (PUCHAR)file + 
		((PIMAGE_NT_HEADERS)((PCHAR)file + ((PIMAGE_DOS_HEADER)file)->e_lfanew))->OptionalHeader.AddressOfEntryPoint;
	PUCHAR cptr = EntryPoint;
	
	if (0 == MmIsAddressValid(cptr)) return 0;
	for (; cptr < EntryPoint + PAGE_SIZE; ++cptr)
	{
		if ((*cptr == 0xbe)&&
			(0 == memcmp(cptr + 5, "\xB9\x00\x08\x00\x00\xC1\xE9\x02\xF3\xA5", 10))&&
			(*(PUSHORT)(cptr + 15) == 0x408F)&&
			(*(PUSHORT)(cptr + 18) == 0x408F)&&
			(*(PUSHORT)(cptr + 21) == 0x408F)&&
			(*(PUSHORT)(cptr + 24) == 0x408F))
			return (PULONG)(*(PULONG)(cptr+1) + delta);
	};

	VMProtectEnd;
	return 0;
};



VOID
HackIDT(
	PVOID* lpBuffer
	)
{
	IDT			Idt;
	USHORT		n;
	PVOID		BaseAddress;
	SIZE_T		RegionSize;
	NTSTATUS	NtStatus = STATUS_SUCCESS;

	__try
	{
		__asm sidt	Idt;
		RegionSize = n = Idt.wLimit + 1;
		BaseAddress = 0;
		*lpBuffer = 0;
		NtStatus = MmCommitUserBuffer((HANDLE)-1, &BaseAddress, RegionSize);
		if ( NtStatus == STATUS_SUCCESS )
		{
			*(PULONG)lpBuffer = (ULONG)BaseAddress;
			memcpy( BaseAddress, Idt.Base, n );
		};
	}
	__except(1)
	{};
};


ULONG_PTR
HookInterrup(
	int interrupt,
	ULONG_PTR Address
	)
{
	IDT		idt;
	ULONG_PTR	old = 0;
	// save old stuff
	__asm sidt	idt;
	old = idt.Base[interrupt].Offset + (idt.Base[interrupt].ExtendedOffset << 16);
	// change interrupt address
	MemOpen();
	InterlockedExchange16(&idt.Base[interrupt].Offset, (USHORT)Address);
	InterlockedExchange16(&idt.Base[interrupt].ExtendedOffset, (USHORT)((ULONG)Address >> 16));
	//idt.Base[interrupt].Offset  = (WORD)Address;
	//idt.Base[interrupt].ExtendedOffset = (WORD)((DWORD)Address >> 16);
	MemClose();
	return old;
};


USHORT 
HookInterrupSel(
	int interrupt,
	USHORT Selector
	)
{
	IDT		idt;
	USHORT	old = 0;
	// save old stuff
	__asm sidt	idt;
	old = idt.Base[interrupt].Selector;
	// change interrupt address
	__asm cli;
	MemOpen();
	InterlockedExchange16(&idt.Base[interrupt].Selector, (USHORT)Selector);
	//idt.Base[interrupt].Selector = (USHORT)Selector;
	MemClose();
	__asm sti;
	return old;
};