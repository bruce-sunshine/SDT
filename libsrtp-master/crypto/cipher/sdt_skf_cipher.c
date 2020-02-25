/*
 * null_cipher.c
 *
 * A null cipher implementation.  This cipher leaves the plaintext
 * unchanged.
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */

/*
 *
 * Copyright (c) 2001-2017 Cisco Systems, Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include "datatypes.h"
#include "sdt_skf_cipher.h"
#include "err.h"                /* for srtp_debug */
#include "alloc.h"
#include "skf.h"
#define check_hash 					0
#define sm3_hard					1
#define INIT_APP_NAME             "SJW07A_SDT"
#define INIT_USER_PIN   		  "12345678"
#define PIN_MAX_RETRY_TIMES       (8)

/* the sdt_cipher uses the cipher debug module  */
extern srtp_debug_module_t srtp_mod_cipher;

extern const srtp_cipher_type_t srtp_sdt_skf_SM4_ECB_cipher;
extern const srtp_cipher_type_t srtp_sdt_skf_SM4_ECB_DEC_cipher;
extern const srtp_cipher_type_t srtp_sdt_skf_SM4_ECB_AUDIO_ENC_cipher;
extern const srtp_cipher_type_t srtp_sdt_skf_SM4_ECB_AUDIO_DEC_cipher;
extern const srtp_cipher_type_t srtp_sdt_skf_SM4_CBC_cipher;
/*-----------------------------------------------------------------------------------------------------*/
#if 0
#define SM3_BLOCK_SIZE		64
#define SM3_DIGEST_LENGTH	32
#define cpu_to_be32(v) (((v)>>24) | (((v)>>8)&0xff00) | (((v)<<8)&0xff0000) | ((v)<<24))

#define ROTATELEFT(X,n)  (((X)<<(n)) | ((X)>>(32-(n))))

#define P0(x) ((x) ^  ROTATELEFT((x),9)  ^ ROTATELEFT((x),17))
#define P1(x) ((x) ^  ROTATELEFT((x),15) ^ ROTATELEFT((x),23))

#define FF0(x,y,z) ( (x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )

typedef struct {
	uint32_t digest[8];
	int nblocks;
	unsigned char block[64];
	int num;
} sm3_ctx_t;

void sm3_init(sm3_ctx_t *ctx)
{
	ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x4914B2B9;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;

	ctx->nblocks = 0;
	ctx->num = 0;
}

void sm3_update(sm3_ctx_t *ctx, const unsigned char* data, size_t data_len)
{
	if (ctx->num) {
		unsigned int left = SM3_BLOCK_SIZE - ctx->num;
		if (data_len < left) {
			memcpy(ctx->block + ctx->num, data, data_len);
			ctx->num += data_len;
			return;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			sm3_compress(ctx->digest, ctx->block);
			ctx->nblocks++;
			data += left;
			data_len -= left;
		}
	}
	while (data_len >= SM3_BLOCK_SIZE) {
		sm3_compress(ctx->digest, data);
		ctx->nblocks++;
		data += SM3_BLOCK_SIZE;
		data_len -= SM3_BLOCK_SIZE;
	}
	ctx->num = data_len;
	if (data_len) {
		memcpy(ctx->block, data, data_len);
	}
}

void sm3_final(sm3_ctx_t *ctx, unsigned char *digest)
{
	int i;
	uint32_t *pdigest = (uint32_t *)digest;
	uint32_t *count = (uint32_t *)(ctx->block + SM3_BLOCK_SIZE - 8);

	ctx->block[ctx->num] = 0x80;

	if (ctx->num + 9 <= SM3_BLOCK_SIZE) {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
	} else {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
		sm3_compress(ctx->digest, ctx->block);
		memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
	}

	count[0] = cpu_to_be32((ctx->nblocks) >> 23);
	count[1] = cpu_to_be32((ctx->nblocks << 9) + (ctx->num << 3));

	sm3_compress(ctx->digest, ctx->block);
	for (i = 0; i < sizeof(ctx->digest)/sizeof(ctx->digest[0]); i++) {
		pdigest[i] = cpu_to_be32(ctx->digest[i]);
	}
}




void sm3_compress(uint32_t digest[8], const unsigned char block[64])
{
	int j;
	uint32_t W[68], W1[64];
	const uint32_t *pblock = (const uint32_t *)block;

	uint32_t A = digest[0];
	uint32_t B = digest[1];
	uint32_t C = digest[2];
	uint32_t D = digest[3];
	uint32_t E = digest[4];
	uint32_t F = digest[5];
	uint32_t G = digest[6];
	uint32_t H = digest[7];
	uint32_t SS1,SS2,TT1,TT2,T[64];

	for (j = 0; j < 16; j++) {
		W[j] = cpu_to_be32(pblock[j]);
	}
	for (j = 16; j < 68; j++) {
		W[j] = P1( W[j-16] ^ W[j-9] ^ ROTATELEFT(W[j-3],15)) ^ ROTATELEFT(W[j - 13],7 ) ^ W[j-6];;
	}
	for( j = 0; j < 64; j++) {
		W1[j] = W[j] ^ W[j+4];
	}

	for(j =0; j < 16; j++) {

		T[j] = 0x79CC4519;
		SS1 = ROTATELEFT((ROTATELEFT(A,12) + E + ROTATELEFT(T[j],j)), 7);
		SS2 = SS1 ^ ROTATELEFT(A,12);
		TT1 = FF0(A,B,C) + D + SS2 + W1[j];
		TT2 = GG0(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F,19);
		F = E;
		E = P0(TT2);
	}

	for(j =16; j < 64; j++) {

		T[j] = 0x7A879D8A;
		SS1 = ROTATELEFT((ROTATELEFT(A,12) + E + ROTATELEFT(T[j],j)), 7);
		SS2 = SS1 ^ ROTATELEFT(A,12);
		TT1 = FF1(A,B,C) + D + SS2 + W1[j];
		TT2 = GG1(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F,19);
		F = E;
		E = P0(TT2);
	}

	digest[0] ^= A;
	digest[1] ^= B;
	digest[2] ^= C;
	digest[3] ^= D;
	digest[4] ^= E;
	digest[5] ^= F;
	digest[6] ^= G;
	digest[7] ^= H;
}

void sm3(const unsigned char *msg, size_t msglen,
	unsigned char dgst[SM3_DIGEST_LENGTH])
{
	sm3_ctx_t ctx;

	sm3_init(&ctx);
	sm3_update(&ctx, msg, msglen);
	sm3_final(&ctx, dgst);

	memset(&ctx, 0, sizeof(sm3_ctx_t));
}
#endif
/*-----------------------------------------------------------------------------------------------------*/

static srtp_err_status_t srtp_sdt_skf_cipher_sm4_ecb_alloc (srtp_cipher_t **c, int key_len, int tlen)
{

    srtp_sdt_skf_sm4_ctx_t* sdt_skf_ctx;
    debug_print(srtp_mod_cipher,
                "allocating cipher with key length %d", key_len);


    if (key_len != SRTP_SDT_SM4_KEY_LEN) {
        return srtp_err_status_bad_param;
    }

    /* allocate memory a cipher of type null_cipher */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return srtp_err_status_alloc_fail;
    }
    memset(*c, 0x0, sizeof(srtp_cipher_t));

    sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)srtp_crypto_alloc(sizeof(srtp_sdt_skf_sm4_ctx_t));
    if (sdt_skf_ctx == NULL)
    {
    	srtp_crypto_free(*c);
        return srtp_err_status_alloc_fail;
    }
    memset(sdt_skf_ctx, 0x0, sizeof(srtp_sdt_skf_sm4_ctx_t));
    sdt_skf_ctx->mode = SMS4_ECB;

    (*c)->state = sdt_skf_ctx;
    /* set pointers */
    (*c)->algorithm = SRTP_SDT_SKF_SM4_ECB;
    (*c)->type = &srtp_sdt_skf_SM4_ECB_cipher;
//    (*c)->state = (void *) 0x1; /* The null cipher does not maintain state */

    /* set key size */
    (*c)->key_len = key_len;

    //added huashen ukey init //
	ULONG skf_rv;
#if 0
	char *name_list;
	ULONG name_list_size;
	skf_rv = SKF_EnumDev(TRUE, 0, &name_list_size);
	printf("ecb name_list_size = %d\n", name_list_size);
	if (skf_rv != SAR_OK)
	{
		printf("SKF_EnumDev error, error = 0x%02x\n", skf_rv);
		return srtp_err_status_alloc_fail;
	}
	if (name_list_size == 0)
	{
		printf("SKF get name_list_size = 0\n");
		return srtp_err_status_alloc_fail;
	}
	name_list = (char *)malloc (name_list_size);
	if(name_list == NULL)
	{
		printf("name list, malloc error\n");
		return srtp_err_status_alloc_fail;
	}
#endif
	ULONG name_list_size;
	skf_rv = SKF_EnumDev(TRUE, 0, &name_list_size);
//	printf("ecb name_list_size = %d\n", name_list_size);
	if (skf_rv != SAR_OK)
	{
		printf("SKF_EnumDev error, error = 0x%02x\n", skf_rv);
		return srtp_err_status_alloc_fail;
	}
	char name_list[100];

	skf_rv = SKF_EnumDev(TRUE, name_list, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		free (name_list);
		printf("SKF_EnumDev enc error\n");
		return srtp_err_status_alloc_fail;
	}

//	printf("ecb name_list = %s\n", name_list);

	skf_rv = SKF_ConnectDev(name_list, &(sdt_skf_ctx->hd));
//	free(name_list);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_ConnectDev enc error\n");
		return srtp_err_status_alloc_fail;
	}
	printf("SDT_SKF ukey enc init ok\n");
//	printf("SDT_SKF ukey init ok, choose SM4 mode is %d OK\n", SMS4_ECB);
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_sdt_skf_cipher_sm4_ecb_dec_alloc (srtp_cipher_t **c, int key_len, int tlen)
{

    srtp_sdt_skf_sm4_ctx_t* sdt_skf_ctx;
    debug_print(srtp_mod_cipher,
                "allocating cipher with key length %d", key_len);


    if (key_len != SRTP_SDT_SM4_KEY_LEN) {
        return srtp_err_status_bad_param;
    }

    /* allocate memory a cipher of type null_cipher */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return srtp_err_status_alloc_fail;
    }
    memset(*c, 0x0, sizeof(srtp_cipher_t));

    sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)srtp_crypto_alloc(sizeof(srtp_sdt_skf_sm4_ctx_t));
    if (sdt_skf_ctx == NULL)
    {
    	srtp_crypto_free(*c);
        return srtp_err_status_alloc_fail;
    }
    memset(sdt_skf_ctx, 0x0, sizeof(srtp_sdt_skf_sm4_ctx_t));
    sdt_skf_ctx->mode = SMS4_ECB;

    (*c)->state = sdt_skf_ctx;
    /* set pointers */
    (*c)->algorithm = SRTP_SDT_SKF_SM4_ECB_DEC;
    (*c)->type = &srtp_sdt_skf_SM4_ECB_DEC_cipher;
//    (*c)->state = (void *) 0x1; /* The null cipher does not maintain state */

    /* set key size */
    (*c)->key_len = key_len;

    //added huashen ukey init //
	ULONG skf_rv;
#if 0
	char *name_list;
	ULONG name_list_size;
	skf_rv = SKF_EnumDev(TRUE, 0, &name_list_size);
	printf("ecb name_list_size = %d\n", name_list_size);
	if (skf_rv != SAR_OK)
	{
		printf("SKF_EnumDev error, error = 0x%02x\n", skf_rv);
		return srtp_err_status_alloc_fail;
	}
	if (name_list_size == 0)
	{
		printf("SKF get name_list_size = 0\n");
		return srtp_err_status_alloc_fail;
	}
	name_list = (char *)malloc (name_list_size);
	if(name_list == NULL)
	{
		printf("name list, malloc error\n");
		return srtp_err_status_alloc_fail;
	}
#endif
	ULONG name_list_size;
	skf_rv = SKF_EnumDev(TRUE, 0, &name_list_size);
//	printf("ecb_dec name_list_size = %d\n", name_list_size);
	if (skf_rv != SAR_OK)
	{
		printf("SKF_EnumDev error, error = 0x%02x\n", skf_rv);
		return srtp_err_status_alloc_fail;
	}
	char name_list[100];
	skf_rv = SKF_EnumDev(TRUE, name_list, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		free (name_list);
		printf("SKF_EnumDev dec error\n");
		return srtp_err_status_alloc_fail;
	}
	int ukeynum_first = 0;
	char name_first[30];
	char name_prefix[30];

	memset(name_first, 0, sizeof(name_first));
	memcpy(name_first, name_list, strlen(name_list));
	memset(name_prefix, 0, sizeof(name_prefix));
	memcpy(name_prefix, name_list, 15);
	ukeynum_first = atoi(name_list + 15);
//	printf("ecb_dec name_first = %s\n", name_first);
//	printf("ecb_dec name_prefix = %s\n", name_prefix);
//	printf("ecb_dec ukeynum_first = %d\n", ukeynum_first);

	++ukeynum_first;
	memset(name_list, 0 , sizeof(name_list));
	memcpy(name_list, name_prefix, strlen(name_prefix));
	char str[10];
	sprintf(str, "%d", ukeynum_first);
	strcat(name_list, str);

//	char name[] = "hs-1d99-0001-2-4";
//	memset(name_list, 0 , sizeof(name_list));
//	memcpy(name_list, name, strlen(name));

//	printf("ecb_dec name_list = %s\n", name_list);
	skf_rv = SKF_ConnectDev(name_list, &(sdt_skf_ctx->hd));
//	free(name_list);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_ConnectDev dec error\n");
		return srtp_err_status_alloc_fail;
	}
	printf("SDT_SKF ukey dec init ok\n");
//	printf("SDT_SKF ukey init ok, choose SM4 mode is %d OK\n", SMS4_ECB);
    return srtp_err_status_ok;
}


static srtp_err_status_t srtp_sdt_skf_cipher_sm4_ecb_audio_enc_alloc (srtp_cipher_t **c, int key_len, int tlen)
{

    srtp_sdt_skf_sm4_ctx_t* sdt_skf_ctx;
    debug_print(srtp_mod_cipher,
                "allocating cipher with key length %d", key_len);


    if (key_len != SRTP_SDT_SM4_KEY_LEN) {
        return srtp_err_status_bad_param;
    }

    /* allocate memory a cipher of type null_cipher */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return srtp_err_status_alloc_fail;
    }
    memset(*c, 0x0, sizeof(srtp_cipher_t));

    sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)srtp_crypto_alloc(sizeof(srtp_sdt_skf_sm4_ctx_t));
    if (sdt_skf_ctx == NULL)
    {
    	srtp_crypto_free(*c);
        return srtp_err_status_alloc_fail;
    }
    memset(sdt_skf_ctx, 0x0, sizeof(srtp_sdt_skf_sm4_ctx_t));
    sdt_skf_ctx->mode = SMS4_ECB;

    (*c)->state = sdt_skf_ctx;
    /* set pointers */
    (*c)->algorithm = SRTP_SDT_SKF_SM4_ECB_AUDIO_ENC;
    (*c)->type = &srtp_sdt_skf_SM4_ECB_AUDIO_ENC_cipher;
//    (*c)->state = (void *) 0x1; /* The null cipher does not maintain state */

    /* set key size */
    (*c)->key_len = key_len;

    //added huashen ukey init //
	ULONG skf_rv;
	ULONG name_list_size;
	skf_rv = SKF_EnumDev(TRUE, 0, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		printf("SKF_EnumDev error, error = 0x%02x\n", skf_rv);
		return srtp_err_status_alloc_fail;
	}
	char name_list[100];
	skf_rv = SKF_EnumDev(TRUE, name_list, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		free (name_list);
		printf("SKF_EnumDev dec error\n");
		return srtp_err_status_alloc_fail;
	}
	int ukeynum_first = 0;
	char name_first[30];
	char name_prefix[30];

	memset(name_first, 0, sizeof(name_first));
	memcpy(name_first, name_list, strlen(name_list));
	memset(name_prefix, 0, sizeof(name_prefix));
	memcpy(name_prefix, name_list, 15);
	ukeynum_first = atoi(name_list + 15);
	ukeynum_first += 2;

	memset(name_list, 0 , sizeof(name_list));
	memcpy(name_list, name_prefix, strlen(name_prefix));
	char str[10];
	sprintf(str, "%d", ukeynum_first);
	strcat(name_list, str);

	skf_rv = SKF_ConnectDev(name_list, &(sdt_skf_ctx->hd));

	if(skf_rv != SAR_OK)
	{
		printf("SKF_ConnectDev dec error\n");
		return srtp_err_status_alloc_fail;
	}
	printf("SDT_SKF ukey audio enc init ok\n");
    return srtp_err_status_ok;
}


static srtp_err_status_t srtp_sdt_skf_cipher_sm4_ecb_audio_dec_alloc (srtp_cipher_t **c, int key_len, int tlen)
{

    srtp_sdt_skf_sm4_ctx_t* sdt_skf_ctx;
    debug_print(srtp_mod_cipher,
                "allocating cipher with key length %d", key_len);


    if (key_len != SRTP_SDT_SM4_KEY_LEN) {
        return srtp_err_status_bad_param;
    }

    /* allocate memory a cipher of type null_cipher */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return srtp_err_status_alloc_fail;
    }
    memset(*c, 0x0, sizeof(srtp_cipher_t));

    sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)srtp_crypto_alloc(sizeof(srtp_sdt_skf_sm4_ctx_t));
    if (sdt_skf_ctx == NULL)
    {
    	srtp_crypto_free(*c);
        return srtp_err_status_alloc_fail;
    }
    memset(sdt_skf_ctx, 0x0, sizeof(srtp_sdt_skf_sm4_ctx_t));
    sdt_skf_ctx->mode = SMS4_ECB;

    (*c)->state = sdt_skf_ctx;
    /* set pointers */
    (*c)->algorithm = SRTP_SDT_SKF_SM4_ECB_AUDIO_DEC;
    (*c)->type = &srtp_sdt_skf_SM4_ECB_AUDIO_DEC_cipher;
//    (*c)->state = (void *) 0x1; /* The null cipher does not maintain state */

    /* set key size */
    (*c)->key_len = key_len;

    //added huashen ukey init //
	ULONG skf_rv;
	ULONG name_list_size;
	skf_rv = SKF_EnumDev(TRUE, 0, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		printf("SKF_EnumDev error, error = 0x%02x\n", skf_rv);
		return srtp_err_status_alloc_fail;
	}
	char name_list[100];
	skf_rv = SKF_EnumDev(TRUE, name_list, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		free (name_list);
		printf("SKF_EnumDev dec error\n");
		return srtp_err_status_alloc_fail;
	}
	int ukeynum_first = 0;
	char name_first[30];
	char name_prefix[30];

	memset(name_first, 0, sizeof(name_first));
	memcpy(name_first, name_list, strlen(name_list));
	memset(name_prefix, 0, sizeof(name_prefix));
	memcpy(name_prefix, name_list, 15);
	ukeynum_first = atoi(name_list + 15);
	ukeynum_first += 3;

	memset(name_list, 0 , sizeof(name_list));
	memcpy(name_list, name_prefix, strlen(name_prefix));
	char str[10];
	sprintf(str, "%d", ukeynum_first);
	strcat(name_list, str);

	skf_rv = SKF_ConnectDev(name_list, &(sdt_skf_ctx->hd));

	if(skf_rv != SAR_OK)
	{
		printf("SKF_ConnectDev dec error\n");
		return srtp_err_status_alloc_fail;
	}
	printf("SDT_SKF ukey audio dec init ok\n");
    return srtp_err_status_ok;
}


static srtp_err_status_t srtp_sdt_skf_cipher_sm4_cbc_alloc (srtp_cipher_t **c, int key_len, int tlen)
{

	srtp_sdt_skf_sm4_ctx_t* sdt_skf_ctx;
    debug_print(srtp_mod_cipher,
                "allocating cipher with key length %d", key_len);


    if (key_len != SRTP_SDT_SM4_KEY_LEN) {
        return srtp_err_status_bad_param;
    }

    /* allocate memory a cipher of type null_cipher */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return srtp_err_status_alloc_fail;
    }
    memset(*c, 0x0, sizeof(srtp_cipher_t));

    //allocate memory for sdt cipher
    sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)srtp_crypto_alloc(sizeof(srtp_sdt_skf_sm4_ctx_t));
    if (sdt_skf_ctx == NULL)
    {
    	srtp_crypto_free(*c);
        return srtp_err_status_alloc_fail;
    }
    memset(sdt_skf_ctx, 0x0, sizeof(srtp_sdt_skf_sm4_ctx_t));
    sdt_skf_ctx->mode = SMS4_CBC;

    (*c)->state = sdt_skf_ctx;
    /* set pointers */
    (*c)->algorithm = SRTP_SDT_SKF_SM4_CBC;
    (*c)->type = &srtp_sdt_skf_SM4_CBC_cipher;
//    (*c)->state = (void *) 0x1; /* The null cipher does not maintain state */

    /* set key size */
    (*c)->key_len = key_len;

    //added huashen ukey init //
	ULONG skf_rv;
	char *name_list;
	ULONG name_list_size;
	skf_rv = SKF_EnumDev(TRUE, 0, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		printf("SKF_EnumDev error\n");
		return srtp_err_status_alloc_fail;
	}
	printf("cbc name_list_size = %d\n", name_list_size);
	if (name_list_size == 0)
	{
		printf("SKF get name_list_size = 0\n");
		return srtp_err_status_alloc_fail;
	}
	name_list = (char *)malloc (name_list_size);
	if(name_list == NULL)
	{
		printf("name list, malloc error\n");
		return srtp_err_status_alloc_fail;
	}

	skf_rv = SKF_EnumDev(TRUE, name_list, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		free (name_list);
		printf("SKF_EnumDev_2 error\n");
		return srtp_err_status_alloc_fail;
	}

	skf_rv = SKF_ConnectDev(name_list, &(sdt_skf_ctx->hd));
	free(name_list);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_ConnectDev error\n");
		return srtp_err_status_alloc_fail;
	}

//	printf("SDT_SKF ukey init ok, choose SM4 mode is %d OK\n", SMS4_CBC);

    return srtp_err_status_ok;

}

static srtp_err_status_t srtp_sdt_skf_cipher_dealloc (srtp_cipher_t *c)
{
	srtp_sdt_skf_sm4_ctx_t* sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)c->state;
//////////////////close JMK ////////////////////////////////////////
	ULONG skf_rv;
#if 0
	skf_rv = SKF_CloseApplication(sdt_skf_ctx->app);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_CloseApplication error\n");
		return srtp_err_status_dealloc_fail;
	}
#endif
	skf_rv = SKF_CloseHandle(sdt_skf_ctx->hKeyHandle);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_CloseHandle hKeyHandle error\n");
		return srtp_err_status_dealloc_fail;
	}
	skf_rv = SKF_DisConnectDev(sdt_skf_ctx->hd);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_DisConnectDev error\n");
		return srtp_err_status_dealloc_fail;
	}
//	printf("Ukey close OK\n");
//////////////////close JMK ////////////////////////////////////////

    if (sdt_skf_ctx) {
        /* zeroize the key material */
        octet_string_set_to_zero(sdt_skf_ctx, sizeof(srtp_sdt_skf_sm4_ctx_t));
        srtp_crypto_free(sdt_skf_ctx);
    }

    /* zeroize entire state*/
    octet_string_set_to_zero(c, sizeof(srtp_cipher_t));

    /* free memory of type null_cipher */
    srtp_crypto_free(c);

    return srtp_err_status_ok;

}

static srtp_err_status_t srtp_sdt_skf_cipher_init (void *cv, const uint8_t *key)
{
	srtp_sdt_skf_sm4_ctx_t* sdt_skf_ctx;
	ULONG skf_rv;
	ULONG ulAlgID;
	ULONG UserRetryCount = PIN_MAX_RETRY_TIMES;
	sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)cv;
	/* srtp_sdt_cipher_ctx_t *c = (srtp_sdt_cipher_ctx_t *)cv; */

    debug_print(srtp_mod_cipher, "initializing sdt cipher", NULL);

//    printf("input key is: ");
//    for(i=0; i < 16; i++)
//    {
//    	printf("%02x ",key[i]);
//    }
//    printf("\n");

//	unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

#if 0
	skf_rv=SKF_OpenApplication(sdt_skf_ctx->hd, INIT_APP_NAME, &(sdt_skf_ctx->app));
	if(skf_rv != SAR_OK)
	{
		printf("sm4, SKF_OpenApplication(%s) error(0x%X)\r\n", INIT_APP_NAME, skf_rv);
		return srtp_err_status_init_fail;
	}

	skf_rv = SKF_VerifyPIN(sdt_skf_ctx->app, 1, INIT_USER_PIN, &UserRetryCount);	//1, user pin; 2, admin pin
 	if (skf_rv != SAR_OK)
	{
		printf("sm4, SKF_VerifyPIN error(0x%X),UserRetryCount=%d\r\n", skf_rv, UserRetryCount);
		SKF_CloseApplication(sdt_skf_ctx->app);
		return srtp_err_status_init_fail;
	}
#endif
// 	printf("libsrtp, ukey sm4, VerifyPIN ok\n");

	switch(sdt_skf_ctx->mode)
	{
	case SMS4_CBC:
		ulAlgID = SGD_SMS4_CBC;
		break;
	default:
		ulAlgID = SGD_SMS4_ECB;
	}

  	skf_rv = SKF_SetSymmKey(sdt_skf_ctx->hd, (BYTE*)key, ulAlgID, &(sdt_skf_ctx->hKeyHandle));
	if(skf_rv != SAR_OK)
	{
		printf("skf, Import sm4 key error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_init_fail;
	}
#if 0
	memset(&(sdt_skf_ctx->Param), 0, sizeof(BLOCKCIPHERPARAM));
	sdt_skf_ctx->Param.IVLen = 32;
	sdt_skf_ctx->Param.PaddingType = 0;
	memcpy(sdt_skf_ctx->Param.IV, iv, sdt_skf_ctx->Param.IVLen);

	skf_rv = SKF_EncryptInit(sdt_skf_ctx->hKeyHandle, sdt_skf_ctx->Param);
	if(skf_rv != SAR_OK)
	{
		printf("skf, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
		return 0;
	}
#endif
//	printf("sdt skf sm4 init key success\n");

	sdt_skf_ctx->encrypt_count = 0;
	sdt_skf_ctx->decrypt_count = 0;

    return srtp_err_status_ok;
}


static srtp_err_status_t srtp_sdt_skf_cipher_set_iv (void *cv, uint8_t *iv, srtp_cipher_direction_t dir)
{

	srtp_sdt_skf_sm4_ctx_t *sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)cv;
	//added sanweixinan JMK key //

	if(dir == srtp_direction_encrypt)
	{
		memset(&(sdt_skf_ctx->Param_in), 0, sizeof(BLOCKCIPHERPARAM));
		sdt_skf_ctx->Param_in.IVLen = 16;
		sdt_skf_ctx->Param_in.PaddingType = 0;
	}
	else if(dir == srtp_direction_decrypt)
	{
		memset(&(sdt_skf_ctx->Param_out), 0, sizeof(BLOCKCIPHERPARAM));
		sdt_skf_ctx->Param_out.IVLen = 16;
		sdt_skf_ctx->Param_out.PaddingType = 0;
	}
	else{
		memset(&(sdt_skf_ctx->Param_in), 0, sizeof(BLOCKCIPHERPARAM));
		sdt_skf_ctx->Param_in.IVLen = 16;
		sdt_skf_ctx->Param_in.PaddingType = 0;

		memset(&(sdt_skf_ctx->Param_out), 0, sizeof(BLOCKCIPHERPARAM));
		sdt_skf_ctx->Param_out.IVLen = 16;
		sdt_skf_ctx->Param_out.PaddingType = 0;
	}

    return srtp_err_status_ok;
}
//unsigned long int encrypt_count = 0;
static srtp_err_status_t srtp_sdt_skf_cipher_encrypt (void *cv,
                                            unsigned char *buf, unsigned int *bytes_to_encr)
{

	srtp_sdt_skf_sm4_ctx_t *sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)cv;
	//added sanweixinan JMK encrypt //
	int skf_rv;
	unsigned char pbTempData[2048] = {0};
	ULONG ulTempDataLen;
	if(*bytes_to_encr > 2048)
		return srtp_err_status_bad_param;

//	printf("to be encrypt len=%d\n", *bytes_to_encr);
	if(*bytes_to_encr % 16 !=0)
	{
		printf("enc_len = %d, encrypt len error\n", *bytes_to_encr);
		return srtp_err_status_bad_param;
	}

	ULONG ulAlgID;
	switch(sdt_skf_ctx->mode)
	{
	case SMS4_CBC:
		ulAlgID = SGD_SMS4_CBC;
		break;
	default:
		ulAlgID = SGD_SMS4_ECB;
	}

#if check_hash
//  get the sm3 hash of plaintext, added by bruce, begin
//	unsigned char HashData[32];
#if sm3_hard
	unsigned long int hash_len=0;
	int i;
//	HANDLE phHash;
	skf_rv = SKF_DigestInit(sdt_skf_ctx->hd, SGD_SM3, NULL, NULL, 0, &(sdt_skf_ctx->phHash));
	if(skf_rv != SAR_OK)
	{
		printf("skf encrypt, SKF_DigestInit error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
	skf_rv = SKF_DigestUpdate(sdt_skf_ctx->phHash, buf, *bytes_to_encr);
	if(skf_rv != SAR_OK)
	{
		printf("skf encrypt, SKF_DigestUpdate error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
	memset(sdt_skf_ctx->HashData_enc,0,32);
	skf_rv = SKF_DigestFinal(sdt_skf_ctx->phHash, sdt_skf_ctx->HashData_enc, &hash_len);
	if(skf_rv != SAR_OK)
	{
		printf("skf encrypt, SKF_DigestFinal error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
	skf_rv = SKF_CloseHandle(sdt_skf_ctx->phHash);
	if(skf_rv != SAR_OK)
	{
		printf("skf encrypt, SKF_CloseHandle error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
#else

	unsigned char dgst[SM3_DIGEST_LENGTH];
	memset(dgst, 0 , sizeof(dgst));
	sm3(buf, *bytes_to_encr, dgst);

#endif
//	printf("\nencrypt palin hash is:\n");
//	for(i = 0; i < hash_len; i++)
//	{
//		printf("0x%02x,", sdt_skf_ctx->HashData_enc[i]);
//	}
//	printf("\n");
//  get the sm3 hash of plaintext, added by bruce, end
#endif

	skf_rv = SKF_EncryptInit(sdt_skf_ctx->hKeyHandle, sdt_skf_ctx->Param_in);
	if(skf_rv != SAR_OK)
	{
		printf("skf encrypt, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}

	skf_rv = SKF_EncryptUpdate(sdt_skf_ctx->hKeyHandle, buf, *bytes_to_encr, pbTempData, &ulTempDataLen);
	if(skf_rv != SAR_OK)
	{
		printf("encrypt error，error[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}

#if check_hash
	memcpy(buf, pbTempData, ulTempDataLen);
#if sm3_hard
	memcpy(buf + ulTempDataLen, sdt_skf_ctx->HashData_enc, 32);
	*bytes_to_encr = ulTempDataLen + 32;
#else
	memcpy(buf + ulTempDataLen, dgst, SM3_DIGEST_LENGTH);
	*bytes_to_encr = ulTempDataLen + SM3_DIGEST_LENGTH;
#endif
//	printf("encrypt, output len = %d\n", *bytes_to_encr);
#else
	memcpy(buf, pbTempData, ulTempDataLen);
	*bytes_to_encr = ulTempDataLen;
#endif

	if(sdt_skf_ctx->encrypt_count == 65535)
		sdt_skf_ctx->encrypt_count = 0;
	++(sdt_skf_ctx->encrypt_count);
	if(sdt_skf_ctx->encrypt_count % 5000 == 0)
		printf("skf sm4 encrypt %ld packets success\n", sdt_skf_ctx->encrypt_count);

//	printf("skf sm4 encrypt success\n");
    return srtp_err_status_ok;
}
//unsigned long int decrypt_count = 0;
static srtp_err_status_t srtp_sdt_skf_cipher_decrypt (void *cv,
                                            unsigned char *buf, unsigned int *bytes_to_encr)
{

	srtp_sdt_skf_sm4_ctx_t *sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)cv;

	unsigned char pbOutData[2048] = {0};
	ULONG  ulOutDataLen;
	int skf_rv;

	if(*bytes_to_encr > 2048)
		return srtp_err_status_bad_param;

//	printf("to be decrypt len=%d\n", *bytes_to_encr);

#if check_hash
//get the hash of plaintext, begin
	int i;
//	HANDLE phHash;
//	unsigned char HashData_old[32];
//	unsigned char HashData_new[32];
	unsigned long int hash_len=32;
	memset(sdt_skf_ctx->HashData_enc,0,32);
	memcpy(sdt_skf_ctx->HashData_enc, buf+(*bytes_to_encr)-32, 32);

//	printf("decrypt, get old plain hash is:\n");
//	for(i = 0; i < hash_len; i++)
//	{
//		printf("0x%02x,", HashData_old[i]);
//	}
//	printf("\n");
//check the hash of ciphertext, end
#endif

#if check_hash
	*bytes_to_encr = *bytes_to_encr - 32;
#endif
	if((*bytes_to_encr) % 16 !=0)
	{
		printf("dec_len = %d, decrypt length error\n", *bytes_to_encr);
		return srtp_err_status_bad_param;
	}

	ULONG ulAlgID;
	switch(sdt_skf_ctx->mode)
	{
	case SMS4_CBC:
		ulAlgID = SGD_SMS4_CBC;
		break;
	default:
		ulAlgID = SGD_SMS4_ECB;
	}

	skf_rv = SKF_EncryptInit(sdt_skf_ctx->hKeyHandle, sdt_skf_ctx->Param_out);
	if(skf_rv != SAR_OK)
	{
		printf("skf, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}

	skf_rv = SKF_DecryptUpdate(sdt_skf_ctx->hKeyHandle, buf, *bytes_to_encr, pbOutData, &ulOutDataLen);
	if(skf_rv != SAR_OK)
	{
		printf("decrypt error，error[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}

#if check_hash
#if sm3_hard
	skf_rv = SKF_DigestInit(sdt_skf_ctx->hd, SGD_SM3, NULL, NULL, 0, &(sdt_skf_ctx->phHash));
	if(skf_rv != SAR_OK)
	{
		printf("skf decrypt, SKF_DigestInit error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
	skf_rv = SKF_DigestUpdate(sdt_skf_ctx->phHash, pbOutData, ulOutDataLen);
	if(skf_rv != SAR_OK)
	{
		printf("skf decrypt, SKF_DigestUpdate error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
	memset(sdt_skf_ctx->HashData_dec,0,32);
	skf_rv = SKF_DigestFinal(sdt_skf_ctx->phHash, sdt_skf_ctx->HashData_dec, &hash_len);
	if(skf_rv != SAR_OK)
	{
		printf("skf decrypt, SKF_DigestFinal error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
	skf_rv = SKF_CloseHandle(sdt_skf_ctx->phHash);
	if(skf_rv != SAR_OK)
	{
		printf("skf decrypt, SKF_CloseHandle error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
//	printf("decrypt, get new plain hash is:\n");
//	for(i = 0; i < hash_len; i++)
//	{
//		printf("0x%02x,", sdt_skf_ctx->HashData_dec[i]);
//	}
//	printf("\n");
//check two hash
	if(strncmp(sdt_skf_ctx->HashData_enc, sdt_skf_ctx->HashData_dec, 32) != 0)
	{
		printf("check plain hash error, decrypt success num = %ld\n", sdt_skf_ctx->decrypt_count);
		return srtp_err_status_cipher_fail;
	}
#else
	unsigned char dgst[SM3_DIGEST_LENGTH];
	memset(dgst, 0 , sizeof(dgst));
	sm3(pbOutData, ulOutDataLen, dgst);

	if(strncmp(dgst, sdt_skf_ctx->HashData_enc, 32) != 0)
	{
		printf("check plain hash error, decrypt success num = %ld\n", sdt_skf_ctx->decrypt_count);
		return srtp_err_status_cipher_fail;
	}
#endif

#endif
	memcpy(buf, pbOutData, ulOutDataLen);
	*bytes_to_encr = ulOutDataLen;

	if(sdt_skf_ctx->decrypt_count == 65535)
		sdt_skf_ctx->decrypt_count = 0;
	++(sdt_skf_ctx->decrypt_count);
	if(sdt_skf_ctx->decrypt_count % 5000 == 0)
		printf("skf sm4 decrypt %ld packets success\n", sdt_skf_ctx->decrypt_count);
//	printf("skf sm4 decrypt success\n");
    return srtp_err_status_ok;
}

static const char srtp_sdt_skf_cipher_sm4_ecb_description[] = "sdt ukey cipher sm4_ecb";
static const char srtp_sdt_skf_cipher_sm4_ecb_dec_description[] = "sdt ukey cipher sm4_ecb_dec";
static const char srtp_sdt_skf_cipher_sm4_ecb_audio_enc_description[] = "sdt ukey cipher sm4_ecb_audio_enc";
static const char srtp_sdt_skf_cipher_sm4_ecb_audio_dec_description[] = "sdt ukey cipher sm4_ecb_audio_dec";
static const char srtp_sdt_skf_cipher_sm4_cbc_description[] = "sdt ukey cipher sm4_cbc";

static const uint8_t srtp_sdt_skf_sm4_test_case_0_key[SRTP_SDT_SM4_KEY_LEN] =  {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

static uint8_t srtp_sdt_skf_sm4_test_case_0_nonce[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t srtp_sdt_skf_sm4_test_case_0_plaintext[16]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

static const uint8_t srtp_sdt_skf_sm4_ecb_test_case_0_ciphertext[16]={0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};
static const uint8_t srtp_sdt_skf_sm4_ecb_test_case_0_ciphertext_hash[16+32]={0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46,
		0x13,0xbc,0xec,0x3a,0x7b,0xc6,0xae,0xc8,0x9e,0x6e,0x26,0xe9,0x5a,0x01,0xb1,0xed,0xee,0xb3,0x6c,0x06,0x22,0xdb,0xba,0x84,0x78,0x2f,0xd5,0xd8,0x3f,0x9a,0x1b,0xc6};

static const uint8_t srtp_sdt_skf_sm4_cbc_test_case_0_ciphertext[16]={0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};

static const srtp_cipher_test_case_t srtp_sdt_cipher_sm4_ecb_test_0 = {
		SRTP_SDT_SM4_KEY_LEN,
		srtp_sdt_skf_sm4_test_case_0_key,
		srtp_sdt_skf_sm4_test_case_0_nonce,
		16,
		srtp_sdt_skf_sm4_test_case_0_plaintext,
#if check_hash
		16+32,
		srtp_sdt_skf_sm4_ecb_test_case_0_ciphertext_hash,
#else
		16,
		srtp_sdt_skf_sm4_ecb_test_case_0_ciphertext,
#endif
		0,
		NULL,
		0,
		NULL
};


static const srtp_cipher_test_case_t srtp_sdt_cipher_sm4_cbc_test_0 = {
		SRTP_SDT_SM4_KEY_LEN,
		srtp_sdt_skf_sm4_test_case_0_key,
		srtp_sdt_skf_sm4_test_case_0_nonce,
		16,
		srtp_sdt_skf_sm4_test_case_0_plaintext,
		16,
		srtp_sdt_skf_sm4_cbc_test_case_0_ciphertext,
		0,
		NULL,
		0,
		NULL
};

/*
 * note: the decrypt function is idential to the encrypt function
 */

const srtp_cipher_type_t srtp_sdt_skf_SM4_ECB_cipher = {
	srtp_sdt_skf_cipher_sm4_ecb_alloc,
    srtp_sdt_skf_cipher_dealloc,
    srtp_sdt_skf_cipher_init,
    0,                     /* set_aad */
    srtp_sdt_skf_cipher_encrypt,
    srtp_sdt_skf_cipher_decrypt,
    srtp_sdt_skf_cipher_set_iv,
    0,                     /* get_tag */
    srtp_sdt_skf_cipher_sm4_ecb_description,
    &srtp_sdt_cipher_sm4_ecb_test_0,
    SRTP_SDT_SKF_SM4_ECB
};

const srtp_cipher_type_t srtp_sdt_skf_SM4_ECB_DEC_cipher = {
	srtp_sdt_skf_cipher_sm4_ecb_dec_alloc,
    srtp_sdt_skf_cipher_dealloc,
    srtp_sdt_skf_cipher_init,
    0,                     /* set_aad */
    srtp_sdt_skf_cipher_encrypt,
    srtp_sdt_skf_cipher_decrypt,
    srtp_sdt_skf_cipher_set_iv,
    0,                     /* get_tag */
    srtp_sdt_skf_cipher_sm4_ecb_dec_description,
    &srtp_sdt_cipher_sm4_ecb_test_0,
    SRTP_SDT_SKF_SM4_ECB_DEC
};

const srtp_cipher_type_t srtp_sdt_skf_SM4_ECB_AUDIO_ENC_cipher = {
	srtp_sdt_skf_cipher_sm4_ecb_audio_enc_alloc,
    srtp_sdt_skf_cipher_dealloc,
    srtp_sdt_skf_cipher_init,
    0,                     /* set_aad */
    srtp_sdt_skf_cipher_encrypt,
    srtp_sdt_skf_cipher_decrypt,
    srtp_sdt_skf_cipher_set_iv,
    0,                     /* get_tag */
    srtp_sdt_skf_cipher_sm4_ecb_audio_enc_description,
    &srtp_sdt_cipher_sm4_ecb_test_0,
    SRTP_SDT_SKF_SM4_ECB_AUDIO_ENC
};

const srtp_cipher_type_t srtp_sdt_skf_SM4_ECB_AUDIO_DEC_cipher = {
	srtp_sdt_skf_cipher_sm4_ecb_audio_dec_alloc,
    srtp_sdt_skf_cipher_dealloc,
    srtp_sdt_skf_cipher_init,
    0,                     /* set_aad */
    srtp_sdt_skf_cipher_encrypt,
    srtp_sdt_skf_cipher_decrypt,
    srtp_sdt_skf_cipher_set_iv,
    0,                     /* get_tag */
    srtp_sdt_skf_cipher_sm4_ecb_audio_dec_description,
    &srtp_sdt_cipher_sm4_ecb_test_0,
    SRTP_SDT_SKF_SM4_ECB_AUDIO_DEC
};


const srtp_cipher_type_t srtp_sdt_skf_SM4_CBC_cipher = {
	srtp_sdt_skf_cipher_sm4_cbc_alloc,
    srtp_sdt_skf_cipher_dealloc,
    srtp_sdt_skf_cipher_init,
    0,                     /* set_aad */
    srtp_sdt_skf_cipher_encrypt,
    srtp_sdt_skf_cipher_decrypt,
    srtp_sdt_skf_cipher_set_iv,
    0,                     /* get_tag */
    srtp_sdt_skf_cipher_sm4_cbc_description,
    &srtp_sdt_cipher_sm4_cbc_test_0,
    SRTP_SDT_SKF_SM4_CBC
};
