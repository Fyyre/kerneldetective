#ifndef _LDASM_
#define _LDASM_

#ifdef __cplusplus
extern "C" {
#endif

unsigned long SizeOfCode(void *Code, unsigned char **pOpcode);

char IsRelativeCmd(unsigned char *pOpcode);

#ifdef __cplusplus
}
#endif

#endif