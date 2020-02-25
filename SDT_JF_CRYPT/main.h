/*
 * main.h
 *
 *  Created on: Nov 19, 2019
 *      Author: root
 */

#ifndef MAIN_H_
#define MAIN_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <mcheck.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pthread.h>
#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
extern "C"
{
#include "srtp2/auth.h"
#include "srtp2/cipher.h"
#include "srtp2/crypto_types.h"
#include "srtp2/srtp.h"
}

#define MAXEPOLLSIZE 10000

#define  SIGNAL_RECV_PORT 	1700
#define  AUDIO_RECV_PORT 	6000
#define  VIDEO_RECV_PORT 	6002

#define  SIGNAL_SEND_PORT 	1300
#define  AUDIO_SEND_PORT 	9000
#define  VIDEO_SEND_PORT 	9002


typedef struct Recv_Event
{
	int fdRecv;
	int id;
} Recv_Event;

enum {
	SIGNAL = 1,
	AUDIO,
	VIDEO
};

typedef enum
{
	NALU_NON_IDR = 1,
	NALU_IDR = 5,
	NALU_SEI,
	NALU_SPS,
	NALU_PPS,
	STAP_A = 24,
	FU_A = 28
} NALU_TYPE;

typedef struct stMeg{
	int msgID;			//meg type
	int param1;
	int param2;
	int dateLen;		//meg length
	int data[2000];		//meg data
}stMeg;

#endif /* MAIN_H_ */
