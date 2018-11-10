/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		handle.h
 *
 * Abstract:
 *
 *		This module implements a set of functions for detecting executive handles.
 *
 * Author:
 *
 *		GamingMasteR
 *
 */

#include "KeDetective.h" 


#define TABLE_LEVEL_MASK              3
#define XP_TABLE_ENTRY_LOCK_BIT       1

typedef struct _HANDLE_TABLE {
	ULONG			TableCode;
	PEPROCESS		QuotaProcess;
	PVOID			UniqueProcessId;
} HANDLE_TABLE, *PHANDLE_TABLE;

typedef struct _EXHANDLE {
	union {
		struct {
			ULONG TagBits : 2;
			ULONG Index : 30;
		};
		ULONG GenericHandleOverlay;
	};
} EXHANDLE, *PEXHANDLE;

typedef BOOLEAN (*EX_ENUMERATE_HANDLE_ROUTINE)(
    IN PHANDLE_TABLE_ENTRY HandleTableEntry,
    IN HANDLE Handle,
    IN PVOID EnumParameter
    );

typedef struct _HANDLE_INFORMATION_LITE {
    PVOID		QuotaProcess;
    PVOID		Object;
} HANDLE_INFORMATION_LITE, *PHANDLE_INFORMATION_LITE;

#ifdef __cplusplus
	extern "C" {
#endif



// ExEnumHandleTable
extern BOOLEAN
(NTAPI *KdEnumHandleTable)(PHANDLE_TABLE HandleTable, EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure, PVOID EnumParameter, PHANDLE Handle OPTIONAL);


PVOID
GetProcessHandles(
	PEPROCESS Process,
	ULONG &HandlesCount,
	BOOLEAN Extended = FALSE
	);


NTSTATUS
CloseHandle(
	HANDLE Handle,
	PEPROCESS Process
	);

#ifdef __cplusplus
	}
#endif