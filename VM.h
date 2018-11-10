#ifndef _VMPROTECTDDK_H_
#define _VMPROTECTDDK_H_

#ifdef _WIN64
	extern "C" 
	{
		__declspec(dllimport) void __stdcall VMProtectBegin(void);
		__declspec(dllimport) void __stdcall VMProtectEnd(void);
	}
	#define VMProtectBegin VMProtectBegin();
	#define VMProtectEnd VMProtectEnd();
#endif


	#define VMProtectBegin \
		__asm _emit 0xEB \
		__asm _emit 0x10 \
		__asm _emit 0x56 \
		__asm _emit 0x4D \
		__asm _emit 0x50 \
		__asm _emit 0x72 \
		__asm _emit 0x6F \
		__asm _emit 0x74 \
		__asm _emit 0x65 \
		__asm _emit 0x63 \
		__asm _emit 0x74 \
		__asm _emit 0x20 \
		__asm _emit 0x62 \
		__asm _emit 0x65 \
		__asm _emit 0x67 \
		__asm _emit 0x69 \
		__asm _emit 0x6E \
		__asm _emit 0x00 

	#define VMProtectEnd \
		__asm _emit 0xEB \
		__asm _emit 0x0E \
		__asm _emit 0x56 \
		__asm _emit 0x4D \
		__asm _emit 0x50 \
		__asm _emit 0x72 \
		__asm _emit 0x6F \
		__asm _emit 0x74 \
		__asm _emit 0x65 \
		__asm _emit 0x63 \
		__asm _emit 0x74 \
		__asm _emit 0x20 \
		__asm _emit 0x65 \
		__asm _emit 0x6E \
		__asm _emit 0x64 \
		__asm _emit 0x00 

#endif /*_VMPROTECTDDK_H_*/