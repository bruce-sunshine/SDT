#ifndef _UTIL_H_
#define _UTIL_H_

#ifdef __cplusplus
	extern "C"{
#endif


#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include <termios.h>
//#include "swsds.h"

#define OPT_EXIT        -1
#define OPT_RETURN      -2
#define OPT_PREVIOUS    -3
#define OPT_NEXT		-4
#define OPT_YES 		-5
#define OPT_CANCEL		-6

#define PUTCH(ch)
#define GETANYKEY() getchar()
#define GETCH() getchar()
#define SLEEP(msec) usleep(msec*1000)
#define	THREAD_EXIT() pthread_exit(NULL)
#define GETCURRENTTHREADID (int)pthread_self

	int FileRead(char *filename, char *mode, unsigned char *buffer, size_t size);
	int FileReadValue(char *filename, char *value);
	int FileWrite(char *filename, char *mode, unsigned char *buffer, size_t size);
	void GetAnyKey();
	int GetInputIndexZone(int *pIndex1, int *pIndex2, int nMin, int nMax);
	int GetInputLength(int nDefaultLength, int nMin, int nMax);
	int GetPasswd(char *buf,int maxSize);
	int GetSelect(int nDefaultSelect, int nMaxSelect);
	int GetString(char *str, int maxSize);
	int PrintData(char *itemName, unsigned char *sourceData, unsigned int dataLength, unsigned int rowCount);

#ifdef __cplusplus
}
#endif

#endif
