/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		module.c
 *
 * Abstract:
 *
 *		This module defines various routines used to deal with kernel-mode drivers.
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




#define MI_UNLOADED_DRIVERS 50

typedef struct _UNLOADED_DRIVERS {
    UNICODE_STRING Name;
    PVOID StartAddress;
    PVOID EndAddress;
    LARGE_INTEGER CurrentTime;
} UNLOADED_DRIVERS, *PUNLOADED_DRIVERS;


typedef struct _CDRIVER_OBJECT {
	PVOID ImageBase;
	PVOID DriverObject;
    struct _KLDR_DATA_TABLE_ENTRY *LdrEntry;
	PVOID Unload;
	PVOID EntryPoint;
	ULONG ImageSize;
    UNICODE_STRING ImagePath;
} CDRIVER_OBJECT, *PCDRIVER_OBJECT;


//
// Loader Data Table Entry Flags
//
#define LDRP_STATIC_LINK                        0x00000002
#define LDRP_IMAGE_DLL                          0x00000004
#define LDRP_LOAD_IN_PROGRESS                   0x00001000
#define LDRP_UNLOAD_IN_PROGRESS                 0x00002000
#define LDRP_ENTRY_PROCESSED                    0x00004000
#define LDRP_ENTRY_INSERTED                     0x00008000
#define LDRP_CURRENT_LOAD                       0x00010000
#define LDRP_FAILED_BUILTIN_LOAD                0x00020000
#define LDRP_DONT_CALL_FOR_THREADS              0x00040000
#define LDRP_PROCESS_ATTACH_CALLED              0x00080000
#define LDRP_DEBUG_SYMBOLS_LOADED               0x00100000
#define LDRP_IMAGE_NOT_AT_BASE                  0x00200000
#define LDRP_COR_IMAGE                          0x00400000
#define LDR_COR_OWNS_UNMAP                      0x00800000
#define LDRP_SYSTEM_MAPPED                      0x01000000
#define LDRP_IMAGE_VERIFYING                    0x02000000
#define LDRP_DRIVER_DEPENDENT_DLL               0x04000000
#define LDRP_ENTRY_NATIVE                       0x08800000
#define LDRP_REDIRECTED                         0x10000000
#define LDRP_NON_PAGED_DEBUG_INFO               0x20000000
#define LDRP_MM_LOADED                          0x40000000
#define LDRP_COMPAT_DATABASE_PROCESSED          0x80000000


//
// Loader Data Table Entry
//
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        PVOID SectionPointer;
    };
    ULONG CheckSum;
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    // ULONG padding on IA64
    PVOID GpValue;
    PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Unused5;
    PVOID SectionPointer;
    ULONG CheckSum;
    // ULONG padding on IA64
    PVOID LoadedImports;
    PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;


#define NUMBER_HASH_BUCKETS 37

typedef struct _OBJECT_DIRECTORY_ENTRY {
    struct _OBJECT_DIRECTORY_ENTRY *ChainLink;
    PVOID Object;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY {
    struct _OBJECT_DIRECTORY_ENTRY *HashBuckets[ NUMBER_HASH_BUCKETS ];
    struct _OBJECT_DIRECTORY_ENTRY **LookupBucket;
    BOOLEAN LookupFound;
    USHORT SymbolicLinkUsageCount;
    struct _DEVICE_MAP *DeviceMap;
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;




VOID 
GetDriverInfo(
	PCDRIVER_OBJECT DriverObject,
    PDRIVER_ENTRY lpBuffer
);



VOID
GetModuleRange(
	PVOID* Base,
	ULONG* Size,
	PCWSTR FileName
);


PWCHAR
ModuleFromAddress(
	PVOID Addr,
	BOOL GetSymbol,
	BOOL GetExport,
    PWCHAR Module,
    SIZE_T Size
	);


PVOID
GetModuleHandle(
	LPSTR lpModuleName
	);

PVOID
GetModuleHandleW(PWCHAR lpModuleName);


PVOID
KdGetSystemRoutineAddress(
	PCWSTR SystemRoutineName
	);


PVOID
GetSystemRoutineAddress( 
	PCWSTR SystemRoutineName
	);


PVOID
GetProcAddress(
    PVOID DllBase,
    PCHAR RoutineName
    );


PCHAR
GetAddressProc(
	PVOID DllBase,
	PVOID RoutineAddress
	);


PIMAGE_SECTION_HEADER
ImageRvaToSection(
	PVOID Base,
	ULONG Rva
	);


PIMAGE_SECTION_HEADER
ImageVaToSection(
	PVOID Base,
	ULONG Va
	);


PVOID
GetRealProcAddress(
	PVOID hModule,
	PVOID file,
	LPSTR lpProcName
	);


VOID
WalkDirectory(
	POBJECT_DIRECTORY Directory,
	POBJECT_TYPE Type,
	PVOID **ObjectArray
	);


PIMAGE_SECTION_HEADER RtlImageRvaToSection(PVOID, ULONG);


ULONG EnumUnloadedDrivers(PDRIVER_ENTRY *);



class CDriver
{
public:
	CDriver() {
		this->Objects = 0;
		this->DriverCount = 0;
	};
	~CDriver() {
		MmFree(this->Objects);
	};
	VOID ScanModuleList();
	VOID ScanDriverType();
	VOID ScanDeviceType();
	VOID ScanDriverDirectory();
	VOID ScanDeviceDirectory();
	VOID ScanPhysicalMemory();
	VOID GrabDriver(PKLDR_DATA_TABLE_ENTRY Driver);
    VOID GrabDriver(PDRIVER_OBJECT DriverObject);
	VOID Scan() {
		this->ScanDriverType();
		this->ScanDeviceType();
		this->ScanDriverDirectory();
		this->ScanDeviceDirectory();
        this->ScanModuleList();
		//this->ScanPhysicalMemory();
	};

	void * __cdecl operator new(unsigned int count)
	{
		return MmAlloc(count);
	};

	void __cdecl operator delete(void * ptr)
	{
		MmFree(ptr);
	};

private:
	

public:
	PCDRIVER_OBJECT Objects;
	ULONG DriverCount;
};


class CDevice
{
public:
	CDevice() {
		this->DeviceArray = 0;
		this->DeviceCount = 0;
	};
	~CDevice() {
		MmFree(this->DeviceArray);
	};
	VOID ScanDeviceType();
	VOID ScanDeviceDirectory();
	VOID GrabDevice(PDEVICE_OBJECT DeviceObject);
	VOID Scan() {
		this->ScanDeviceType();
		this->ScanDeviceDirectory();
	};

	void * __cdecl operator new(unsigned int count)
	{
		return MmAlloc(count);
	};

	void __cdecl operator delete(void * ptr)
	{
		MmFree(ptr);
	};

private:
	BOOLEAN IsFound(PDEVICE_OBJECT DeviceObject);

public:
	PDEVICE_OBJECT *DeviceArray;
	ULONG DeviceCount;
};


extern PLIST_ENTRY PsLoadedModuleList;
extern PLIST_ENTRY MmLoadedUserImageList;
extern CDriver *gDrivers;



#ifdef __cplusplus
	}
#endif