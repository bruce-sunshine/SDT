/*
 * null-cipher.h
 *
 * header file for the null cipher
 *
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */

/*
 *
 * Copyright (c) 2001-2017, Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef SDT_SDF_CIPHER_H
#define SDT_SDF_CIPHER_H

#include "datatypes.h"
#include "cipher.h"

////////added for JMK///////////
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

//#include "pthread.h"
//#include "openssl/rsa.h"
//#include "openssl/crypto.h"
//#include "openssl/x509.h"
//#include "openssl/pem.h"
//#include "openssl/ssl.h"
//#include "openssl/err.h"
//#include "openssl/engine.h"
//#include "openssl/modes.h"

#define EVP_MAX_IV_LENGTH 				(16)
#define EVP_MAX_BLOCK_LENGTH            (32)

//typedef struct {
//	uint32_t rk[32];
//} sms4_key_t;

#define RN 32
#define rotl(x,n)   (((x) << (n)) | ((x) >> (32 - (n))))

#define uint8_t_uint32_t(x,y)	\
	y[0]=((uint32_t)x[0]<<24)|((uint32_t)x[1]<<16)|((uint32_t)x[2]<<8)|(uint32_t)x[3];	\
	y[1]=((uint32_t)x[4]<<24)|((uint32_t)x[5]<<16)|((uint32_t)x[6]<<8)|(uint32_t)x[7];	\
	y[2]=((uint32_t)x[8]<<24)|((uint32_t)x[9]<<16)|((uint32_t)x[10]<<8)|(uint32_t)x[11];	\
	y[3]=((uint32_t)x[12]<<24)|((uint32_t)x[13]<<16)|((uint32_t)x[14]<<8)|(uint32_t)x[15]

#define uint32_t_uint8_t(x,y)	\
	y[0]=(uint8_t)(x[0]>>24); y[1]=(uint8_t)(x[0]>>16); y[2]=(uint8_t)(x[0]>>8); y[3]=(uint8_t)x[0];	\
	y[4]=(uint8_t)(x[1]>>24); y[5]=(uint8_t)(x[1]>>16); y[6]=(uint8_t)(x[1]>>8); y[7]=(uint8_t)x[1];	\
	y[8]=(uint8_t)(x[2]>>24); y[9]=(uint8_t)(x[2]>>16); y[10]=(uint8_t)(x[2]>>8); y[11]=(uint8_t)x[2];	\
	y[12]=(uint8_t)(x[3]>>24); y[13]=(uint8_t)(x[3]>>16); y[14]=(uint8_t)(x[3]>>8); y[15]=(uint8_t)x[3]



const uint32_t S[256]={
0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48};

const uint32_t CK[32]={
0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279};

const uint32_t FK[4]={0xA3B1BAC6,0x56AA3350,0x677D9197,0xB27022DC};

void SMS4_key_schedule(uint32_t *key,uint32_t *ESK,uint32_t *DSK);
void SMS4_crypt(uint32_t in_blk[4], uint32_t out_blk[4], uint32_t *skey);


// CBC 模式，加密
int SMS4_EncCBC_SM100(unsigned char *key, unsigned int key_len,unsigned char *pt,
				 unsigned int pt_len,unsigned char *ct,unsigned char *iv,unsigned int flag);
//参数描述：
//输入：  key，			密钥首地址
//        key_len，		密钥长度,16字节
//        pt，			待加密明文数据首地址
//        pt_len，		待加密明文数据长度,为16的倍数
//        iv，			初始向量首地址（长度与分组长度相同）
//        flag=0，		一次调用
//        flag=1，		分段调用
//输出：  ct，			加密后的密文首地址（输出长度与明文长度相同）
//返回值：
//0，			运算成功
//-1，			输入非法

// CBC 模式，解密
int SMS4_DecCBC_SM100(unsigned char *key, unsigned int key_len,unsigned char *ct,
				 unsigned int ct_len,unsigned char *pt,unsigned char *iv,unsigned int flag);
//参数描述：
//输入：  key，			密钥首地址
//        key_len，		密钥长度,16字节
//        ct，			待解密密文数据首地址
//        ct_len，		待解密密文数据长度,为16的倍数
//        iv，			初始向量首地址（长度与分组长度相同）
//        flag=0，		一次调用
//        flag=1，		分段调用
//输出：  ct，			加密后的密文首地址（输出长度与明文长度相同）
//返回值：
//0，			运算成功
//-1，			输入非法


typedef struct {

	uint8_t sm4_key[SRTP_SDT_SM4_KEY_LEN];
//	sms4_key_t* ks;
    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
    unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
    int num;                    /* used by cfb/ofb/ctr mode */
	unsigned long int encrypt_count;
	unsigned long int decrypt_count;
} srtp_sdt_soft_sm4_ctx;

//typedef void (*block128_f) (const unsigned char in[16],
//                            unsigned char out[16], const void *key);

//basic func of sm4 soft algothrim
#if 0
static uint32_t FK[4] = {
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
};

static uint32_t CK[32] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

uint8_t SBOX[256] = {
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};

#define ROT32(x,i)					\
	(((x) << i) | ((x) >> (32-i)))

#define L32_(x)					\
	((x) ^ 					\
	ROT32((x), 13) ^			\
	ROT32((x), 23))

#define L32(x)						\
	((x) ^						\
	ROT32((x),  2) ^				\
	ROT32((x), 10) ^				\
	ROT32((x), 18) ^				\
	ROT32((x), 24))

#define S32(A)						\
	((SBOX[((A) >> 24)       ] << 24) ^		\
	 (SBOX[((A) >> 16) & 0xff] << 16) ^		\
	 (SBOX[((A) >>  8) & 0xff] <<  8) ^		\
	 (SBOX[((A))       & 0xff]))

#define GET32(pc)  (					\
	((uint32_t)(pc)[0] << 24) ^			\
	((uint32_t)(pc)[1] << 16) ^			\
	((uint32_t)(pc)[2] <<  8) ^			\
	((uint32_t)(pc)[3]))

#define PUT32(st, ct)					\
	(ct)[0] = (uint8_t)((st) >> 24);		\
	(ct)[1] = (uint8_t)((st) >> 16);		\
	(ct)[2] = (uint8_t)((st) >>  8);		\
	(ct)[3] = (uint8_t)(st)


#define ROUND(x0, x1, x2, x3, x4, i)			\
	x4 = x1 ^ x2 ^ x3 ^ *(rk + i);			\
	x4 = S32(x4);					\
	x4 = x0 ^ L32(x4)


#define ROUNDS(x0, x1, x2, x3, x4)		\
	ROUND(x0, x1, x2, x3, x4, 0);		\
	ROUND(x1, x2, x3, x4, x0, 1);		\
	ROUND(x2, x3, x4, x0, x1, 2);		\
	ROUND(x3, x4, x0, x1, x2, 3);		\
	ROUND(x4, x0, x1, x2, x3, 4);		\
	ROUND(x0, x1, x2, x3, x4, 5);		\
	ROUND(x1, x2, x3, x4, x0, 6);		\
	ROUND(x2, x3, x4, x0, x1, 7);		\
	ROUND(x3, x4, x0, x1, x2, 8);		\
	ROUND(x4, x0, x1, x2, x3, 9);		\
	ROUND(x0, x1, x2, x3, x4, 10);		\
	ROUND(x1, x2, x3, x4, x0, 11);		\
	ROUND(x2, x3, x4, x0, x1, 12);		\
	ROUND(x3, x4, x0, x1, x2, 13);		\
	ROUND(x4, x0, x1, x2, x3, 14);		\
	ROUND(x0, x1, x2, x3, x4, 15);		\
	ROUND(x1, x2, x3, x4, x0, 16);		\
	ROUND(x2, x3, x4, x0, x1, 17);		\
	ROUND(x3, x4, x0, x1, x2, 18);		\
	ROUND(x4, x0, x1, x2, x3, 19);		\
	ROUND(x0, x1, x2, x3, x4, 20);		\
	ROUND(x1, x2, x3, x4, x0, 21);		\
	ROUND(x2, x3, x4, x0, x1, 22);		\
	ROUND(x3, x4, x0, x1, x2, 23);		\
	ROUND(x4, x0, x1, x2, x3, 24);		\
	ROUND(x0, x1, x2, x3, x4, 25);		\
	ROUND(x1, x2, x3, x4, x0, 26);		\
	ROUND(x2, x3, x4, x0, x1, 27);		\
	ROUND(x3, x4, x0, x1, x2, 28);		\
	ROUND(x4, x0, x1, x2, x3, 29);		\
	ROUND(x0, x1, x2, x3, x4, 30);		\
	ROUND(x1, x2, x3, x4, x0, 31)


#define ENC_ROUND(x0, x1, x2, x3, x4, i)	\
	x4 = x1 ^ x2 ^ x3 ^ *(CK + i);		\
	x4 = S32(x4);				\
	x4 = x0 ^ L32_(x4);			\
	*(rk + i) = x4



#define ROUNDS_enc(x0, x1, x2, x3, x4)		\
		ENC_ROUND(x0, x1, x2, x3, x4, 0);		\
		ENC_ROUND(x1, x2, x3, x4, x0, 1);		\
		ENC_ROUND(x2, x3, x4, x0, x1, 2);		\
		ENC_ROUND(x3, x4, x0, x1, x2, 3);		\
		ENC_ROUND(x4, x0, x1, x2, x3, 4);		\
		ENC_ROUND(x0, x1, x2, x3, x4, 5);		\
		ENC_ROUND(x1, x2, x3, x4, x0, 6);		\
		ENC_ROUND(x2, x3, x4, x0, x1, 7);		\
		ENC_ROUND(x3, x4, x0, x1, x2, 8);		\
		ENC_ROUND(x4, x0, x1, x2, x3, 9);		\
		ENC_ROUND(x0, x1, x2, x3, x4, 10);		\
		ENC_ROUND(x1, x2, x3, x4, x0, 11);		\
		ENC_ROUND(x2, x3, x4, x0, x1, 12);		\
		ENC_ROUND(x3, x4, x0, x1, x2, 13);		\
		ENC_ROUND(x4, x0, x1, x2, x3, 14);		\
		ENC_ROUND(x0, x1, x2, x3, x4, 15);		\
		ENC_ROUND(x1, x2, x3, x4, x0, 16);		\
		ENC_ROUND(x2, x3, x4, x0, x1, 17);		\
		ENC_ROUND(x3, x4, x0, x1, x2, 18);		\
		ENC_ROUND(x4, x0, x1, x2, x3, 19);		\
		ENC_ROUND(x0, x1, x2, x3, x4, 20);		\
		ENC_ROUND(x1, x2, x3, x4, x0, 21);		\
		ENC_ROUND(x2, x3, x4, x0, x1, 22);		\
		ENC_ROUND(x3, x4, x0, x1, x2, 23);		\
		ENC_ROUND(x4, x0, x1, x2, x3, 24);		\
		ENC_ROUND(x0, x1, x2, x3, x4, 25);		\
		ENC_ROUND(x1, x2, x3, x4, x0, 26);		\
		ENC_ROUND(x2, x3, x4, x0, x1, 27);		\
		ENC_ROUND(x3, x4, x0, x1, x2, 28);		\
		ENC_ROUND(x4, x0, x1, x2, x3, 29);		\
		ENC_ROUND(x0, x1, x2, x3, x4, 30);		\
		ENC_ROUND(x1, x2, x3, x4, x0, 31)

#define DEC_ROUND(x0, x1, x2, x3, x4, i)	\
	x4 = x1 ^ x2 ^ x3 ^ *(CK + i);		\
	x4 = S32(x4);				\
	x4 = x0 ^ L32_(x4);			\
	*(rk + 31 - i) = x4

#define ROUNDS_dec(x0, x1, x2, x3, x4)		\
		DEC_ROUND(x0, x1, x2, x3, x4, 0);		\
		DEC_ROUND(x1, x2, x3, x4, x0, 1);		\
		DEC_ROUND(x2, x3, x4, x0, x1, 2);		\
		DEC_ROUND(x3, x4, x0, x1, x2, 3);		\
		DEC_ROUND(x4, x0, x1, x2, x3, 4);		\
		DEC_ROUND(x0, x1, x2, x3, x4, 5);		\
		DEC_ROUND(x1, x2, x3, x4, x0, 6);		\
		DEC_ROUND(x2, x3, x4, x0, x1, 7);		\
		DEC_ROUND(x3, x4, x0, x1, x2, 8);		\
		DEC_ROUND(x4, x0, x1, x2, x3, 9);		\
		DEC_ROUND(x0, x1, x2, x3, x4, 10);		\
		DEC_ROUND(x1, x2, x3, x4, x0, 11);		\
		DEC_ROUND(x2, x3, x4, x0, x1, 12);		\
		DEC_ROUND(x3, x4, x0, x1, x2, 13);		\
		DEC_ROUND(x4, x0, x1, x2, x3, 14);		\
		DEC_ROUND(x0, x1, x2, x3, x4, 15);		\
		DEC_ROUND(x1, x2, x3, x4, x0, 16);		\
		DEC_ROUND(x2, x3, x4, x0, x1, 17);		\
		DEC_ROUND(x3, x4, x0, x1, x2, 18);		\
		DEC_ROUND(x4, x0, x1, x2, x3, 19);		\
		DEC_ROUND(x0, x1, x2, x3, x4, 20);		\
		DEC_ROUND(x1, x2, x3, x4, x0, 21);		\
		DEC_ROUND(x2, x3, x4, x0, x1, 22);		\
		DEC_ROUND(x3, x4, x0, x1, x2, 23);		\
		DEC_ROUND(x4, x0, x1, x2, x3, 24);		\
		DEC_ROUND(x0, x1, x2, x3, x4, 25);		\
		DEC_ROUND(x1, x2, x3, x4, x0, 26);		\
		DEC_ROUND(x2, x3, x4, x0, x1, 27);		\
		DEC_ROUND(x3, x4, x0, x1, x2, 28);		\
		DEC_ROUND(x4, x0, x1, x2, x3, 29);		\
		DEC_ROUND(x0, x1, x2, x3, x4, 30);		\
		DEC_ROUND(x1, x2, x3, x4, x0, 31)


void sms4_encrypt(const unsigned char *in, unsigned char *out, const sms4_key_t *key)
{
	const uint32_t *rk = key->rk;
	uint32_t x0, x1, x2, x3, x4;

	x0 = GET32(in     );
	x1 = GET32(in +  4);
	x2 = GET32(in +  8);
	x3 = GET32(in + 12);

	ROUNDS(x0, x1, x2, x3, x4);

	PUT32(x0, out     );
	PUT32(x4, out +  4);
	PUT32(x3, out +  8);
	PUT32(x2, out + 12);

	x0 = x1 = x2 = x3 = x4 = 0;
}

void sms4_set_encrypt_key(sms4_key_t *key, const unsigned char *user_key)
{
	uint32_t *rk = key->rk;
	uint32_t x0, x1, x2, x3, x4;

	x0 = GET32(user_key     ) ^ FK[0];
	x1 = GET32(user_key  + 4) ^ FK[1];
	x2 = GET32(user_key  + 8) ^ FK[2];
	x3 = GET32(user_key + 12) ^ FK[3];

	ROUNDS_enc(x0, x1, x2, x3, x4);

	x0 = x1 = x2 = x3 = x4 = 0;
}


void sms4_set_decrypt_key(sms4_key_t *key, const unsigned char *user_key)
{
	uint32_t *rk = key->rk;
	uint32_t x0, x1, x2, x3, x4;

	x0 = GET32(user_key     ) ^ FK[0];
	x1 = GET32(user_key  + 4) ^ FK[1];
	x2 = GET32(user_key  + 8) ^ FK[2];
	x3 = GET32(user_key + 12) ^ FK[3];

	ROUNDS_dec(x0, x1, x2, x3, x4);

	x0 = x1 = x2 = x3 = x4 = 0;
}




#if !defined(STRICT_ALIGNMENT) && !defined(PEDANTIC)
# define STRICT_ALIGNMENT 0
#endif

void CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], block128_f block)
{
    size_t n;
    const unsigned char *iv = ivec;

#if !defined(OPENSSL_SMALL_FOOTPRINT)
    if (STRICT_ALIGNMENT &&
        ((size_t)in | (size_t)out | (size_t)ivec) % sizeof(size_t) != 0) {
        while (len >= 16) {
            for (n = 0; n < 16; ++n)
                out[n] = in[n] ^ iv[n];
            (*block) (out, out, key);
            iv = out;
            len -= 16;
            in += 16;
            out += 16;
        }
    } else {
        while (len >= 16) {
            for (n = 0; n < 16; n += sizeof(size_t))
                *(size_t *)(out + n) =
                    *(size_t *)(in + n) ^ *(size_t *)(iv + n);
            (*block) (out, out, key);
            iv = out;
            len -= 16;
            in += 16;
            out += 16;
        }
    }
#endif
    while (len) {
        for (n = 0; n < 16 && n < len; ++n)
            out[n] = in[n] ^ iv[n];
        for (; n < 16; ++n)
            out[n] = iv[n];
        (*block) (out, out, key);
        iv = out;
        if (len <= 16)
            break;
        len -= 16;
        in += 16;
        out += 16;
    }
    memcpy(ivec, iv, 16);
}

void CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], block128_f block)
{
    size_t n;
    union {
        size_t t[16 / sizeof(size_t)];
        unsigned char c[16];
    } tmp;

#if !defined(OPENSSL_SMALL_FOOTPRINT)
    if (in != out) {
        const unsigned char *iv = ivec;

        if (STRICT_ALIGNMENT &&
            ((size_t)in | (size_t)out | (size_t)ivec) % sizeof(size_t) != 0) {
            while (len >= 16) {
                (*block) (in, out, key);
                for (n = 0; n < 16; ++n)
                    out[n] ^= iv[n];
                iv = in;
                len -= 16;
                in += 16;
                out += 16;
            }
        } else if (16 % sizeof(size_t) == 0) { /* always true */
            while (len >= 16) {
                size_t *out_t = (size_t *)out, *iv_t = (size_t *)iv;

                (*block) (in, out, key);
                for (n = 0; n < 16 / sizeof(size_t); n++)
                    out_t[n] ^= iv_t[n];
                iv = in;
                len -= 16;
                in += 16;
                out += 16;
            }
        }
        memcpy(ivec, iv, 16);
    } else {
        if (STRICT_ALIGNMENT &&
            ((size_t)in | (size_t)out | (size_t)ivec) % sizeof(size_t) != 0) {
            unsigned char c;
            while (len >= 16) {
                (*block) (in, tmp.c, key);
                for (n = 0; n < 16; ++n) {
                    c = in[n];
                    out[n] = tmp.c[n] ^ ivec[n];
                    ivec[n] = c;
                }
                len -= 16;
                in += 16;
                out += 16;
            }
        } else if (16 % sizeof(size_t) == 0) { /* always true */
            while (len >= 16) {
                size_t c, *out_t = (size_t *)out, *ivec_t = (size_t *)ivec;
                const size_t *in_t = (const size_t *)in;

                (*block) (in, tmp.c, key);
                for (n = 0; n < 16 / sizeof(size_t); n++) {
                    c = in_t[n];
                    out_t[n] = tmp.t[n] ^ ivec_t[n];
                    ivec_t[n] = c;
                }
                len -= 16;
                in += 16;
                out += 16;
            }
        }
    }
#endif
    while (len) {
        unsigned char c;
        (*block) (in, tmp.c, key);
        for (n = 0; n < 16 && n < len; ++n) {
            c = in[n];
            out[n] = tmp.c[n] ^ ivec[n];
            ivec[n] = c;
        }
        if (len <= 16) {
            for (; n < 16; ++n)
                ivec[n] = in[n];
            break;
        }
        len -= 16;
        in += 16;
        out += 16;
    }
}

#endif

//

#endif /* NULL_CIPHER_H */
