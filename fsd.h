/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		fsd.c
 *
 * Abstract:
 *
 *		This module defines various routines used to relocate image files.
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



#define RVATOVA(base, offset) ((PVOID)((DWORD)(base) + (DWORD)(offset)))


typedef struct _FSD_OBJECT {
	PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
	PDRIVER_OBJECT DriverObject;
	PVOID MappedImage;
} FSD_OBJECT, *PFSD_OBJECT;

		
/* generic relocation types */
#define IMAGE_REL_BASED_ABSOLUTE				0
#define IMAGE_REL_BASED_HIGH					1
#define IMAGE_REL_BASED_LOW						2
#define IMAGE_REL_BASED_HIGHLOW					3
#define IMAGE_REL_BASED_HIGHADJ					4
#define IMAGE_REL_BASED_MIPS_JMPADDR			5
#define IMAGE_REL_BASED_SECTION					6
#define IMAGE_REL_BASED_REL						7
#define IMAGE_REL_BASED_MIPS_JMPADDR16			9
#define IMAGE_REL_BASED_IA64_IMM64				9
#define IMAGE_REL_BASED_DIR64					10
#define IMAGE_REL_BASED_HIGH3ADJ				11


NTSTATUS
ResolveImageReferences (
    PVOID ImageBase,
    IN PUNICODE_STRING ImageFileDirectory
    );


PVOID
LoadFile(
	LPWSTR FileName,
	PVOID ImageBase,
	BOOLEAN FixIAT
	);


PVOID
LoadSystemFile(
	LPSTR FileName,
	PVOID ImageBase,
	BOOLEAN FixIAT
	);


ULONG
LdrRelocateImage(
    IN PVOID BaseAddress,
	IN PVOID NewBase,
    IN ULONG Success,
    IN ULONG Conflict,
    IN ULONG Invalid
);


BOOLEAN
GetFileName(
	PFILE_OBJECT FileObject, 
	PWCHAR FileName, 
	ULONG FileNameLength
	);


PDRIVER_DISPATCH
GetFileSystemMajorFunction(
	PFSD_OBJECT Fsd,
	ULONG MajorFunctionIndex
);


NTSTATUS
DeleteFile(
	PWCHAR FileName,
	LONG ForceDelete
);

NTSTATUS 
CopyFile(
	PWCHAR lpSource,
	PWCHAR lpDest
);

NTSTATUS
FsCallDriver(
    PDRIVER_OBJECT DriverObject,
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
);

NTSTATUS
ReadWriteDisk(
	PDRIVER_OBJECT DriverObject,
	PDEVICE_OBJECT DeviceObject,
    ULONG SectorNumber,
    USHORT SectorCount,
    BOOL IsWrite,
	PVOID Buffer
	);


NTSTATUS
IoOpenFile(
	HANDLE *Handle,
	LPWSTR FileName,
	ACCESS_MASK DesiredAccess,
	ULONG ShareAccess,
	ULONG CreateOptions,
	ULONG CreateDisposition
);

NTSTATUS
IoReadFile(
	HANDLE Handle,
	PVOID Buffer,
	ULONG FileSize,
	PLARGE_INTEGER FileOffset
);

NTSTATUS
IoWriteFile(
	HANDLE Handle,
	PVOID Buffer,
	ULONG FileSize,
	PLARGE_INTEGER FileOffset
);



extern FSD_OBJECT FsdFastFat, FsdNtfs;

#ifdef __cplusplus
	}
#endif