/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		ssdt.h
 *
 * Abstract:
 *
 *		This module defines various routines used to deal with SSDT.
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



PSDT_ENTRY
HackSSDT(
	PVOID* lpBuffer
	);


PVOID*
GetRealServiceTable(
	PVOID file,
	ULONG Size
	);


PSERVICE_DESCRIPTOR_TABLE
GetAddrssofShadowTable(
	);


PSERVICE_DESCRIPTOR_TABLE
GetAddrssofServiceTable(
	);


PVOID*
GetRealShadowServiceTable(
	PVOID file,
	PVOID Base,
	ULONG Size
	);


PSDT_ENTRY
HackShadowSSDT(
	PVOID* lpBuffer
	);


extern PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTableShadow;
extern PSERVICE_DESCRIPTOR_TABLE KdServiceDescriptorTable;

#ifdef __cplusplus
	}
#endif