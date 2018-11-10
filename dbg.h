/*
 * Copyright (c) 2008 Arab Team 4 Reverse Engineering. All rights reserved.
 *
 * Module Name:
 *
 *		dbg.h
 *
 * Abstract:
 *
 *		This module defines various routines used to save reports for debugging purpose.
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

#ifdef _REPORT_
	#define	Print(format, ...) \
	{\
	Report("[%s] :: " format "\r\n", __FUNCTION__, ##__VA_ARGS__);\
	}
#else
	#define	Print NOTHING
#endif



#undef va_start
#define va_start(name) (va_list)((void *)((char *)&name + \
	((sizeof(name) + (sizeof(int) - 1)) & ~(sizeof(int) - 1))))


BOOLEAN InitializeReport(PWSTR logpath);

VOID Report(char *format, ...);




#ifdef __cplusplus
	}
#endif