/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		dbg.cpp
 *
 * Abstract:
 *
 *		This module implements various routines used to save reports for debugging purpose.
 *
 * Author:
 *
 *		GamingMasteR
 *
 */








#include "KeDetective.h"



#ifdef _REPORT_

OBJECT_ATTRIBUTES	LogFileObj;
UNICODE_STRING		LogFileName;

BOOLEAN InitializeReport(PWSTR logpath)
{
	BOOLEAN				rc = 0;
	HANDLE				hFile = 0;
	IO_STATUS_BLOCK		IoStatus;
	NTSTATUS			NtStatus = STATUS_SUCCESS;

	RtlInitUnicodeString(&LogFileName, logpath);
	InitializeObjectAttributes(&LogFileObj, &LogFileName, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);
	NtStatus = ZwCreateFile(&hFile, FILE_WRITE_DATA|SYNCHRONIZE, &LogFileObj, &IoStatus, 0, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
	if (NtStatus == STATUS_SUCCESS)
	{
		rc++;
		ZwClose(hFile);
	};
	return rc;
};


VOID Report(char *format, ...)
{
	char buffer[512] = "";
	va_list arglist = va_start(format);
	HANDLE				hFile = 0;
	IO_STATUS_BLOCK		IoStatus;
	NTSTATUS			NtStatus;

	_vsnprintf(buffer, 512, format, arglist);
	DbgPrint(buffer);
	if (KeGetCurrentIrql() == PASSIVE_LEVEL) 
	{
		NtStatus = ZwOpenFile(&hFile, FILE_APPEND_DATA|SYNCHRONIZE, &LogFileObj, &IoStatus, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
		if (NtStatus == STATUS_SUCCESS)
		{
			ZwWriteFile(hFile, 0, 0, 0, &IoStatus, buffer, strlen(buffer), 0, 0);
			//ZwFlushBuffersFile(hFile, &IoStatus);
			ZwClose(hFile);
		}
	}
};

#endif