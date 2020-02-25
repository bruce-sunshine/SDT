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

#include "datatypes.h"
#include "sdt_soft_sm4_cipher.h"
#include "err.h"                /* for srtp_debug */
#include "alloc.h"

/* the sdt_cipher uses the cipher debug module  */
extern srtp_debug_module_t srtp_mod_cipher;

//extern const srtp_cipher_type_t srtp_sdt_SOFT_SM4_ECB_cipher;
extern const srtp_cipher_type_t srtp_sdt_SOFT_SM4_CBC_cipher;
//

void SMS4_key_schedule(uint32_t *key, uint32_t *ESK, uint32_t *DSK)
{
    int i;
    uint32_t K[4],t,y;

	K[0]=FK[0]^key[0];	K[1]=FK[1]^key[1];	K[2]=FK[2]^key[2];	K[3]=FK[3]^key[3];

	for(i=0;i<RN;i++)
	{
		t=K[1]^K[2]^K[3]^CK[i];

		y=(S[t>>24]<<24)|(S[(t>>16)&0xff]<<16)|
			(S[(t>>8)&0xff]<<8)|(S[t&0xff]);

		t=y^rotl(y,13)^rotl(y,23);

		K[0]^=t;

		DSK[RN-i-1]=ESK[i]=K[0];

		t=K[0];	K[0]=K[1];	K[1]=K[2];	K[2]=K[3];	K[3]=t;
	}
}

void SMS4_crypt(uint32_t in_blk[4], uint32_t out_blk[4], uint32_t *skey)
{
	int i;
	uint32_t x[4],y,t;

	x[0]=in_blk[0];	x[1]=in_blk[1];	x[2]=in_blk[2];	x[3]=in_blk[3];

	for(i=0;i<RN;i++)
	{
		t=x[1]^x[2]^x[3]^skey[i];

		y=(S[t>>24]<<24)|(S[(t>>16)&0xff]<<16)|
			(S[(t>>8)&0xff]<<8)|(S[t&0xff]);

		t=y^rotl(y,2)^rotl(y,10)^rotl(y,18)^rotl(y,24);

		x[0]^=t;

		t=x[0];	x[0]=x[1];	x[1]=x[2];	x[2]=x[3];	x[3]=t;
	}

	out_blk[0]=x[3];	out_blk[1]=x[2];	out_blk[2]=x[1];	out_blk[3]=x[0];
}

// CBC 模式，加密
int SMS4_EncCBC_SM100(unsigned char *key, unsigned int key_len,unsigned char *pt,
				 unsigned int pt_len,unsigned char *ct,unsigned char *iv,unsigned int flag)
{
	int i;
	uint32_t x[32],y[32],k[4];
	uint32_t esk[32],dsk[32];
    if (pt_len % 16)
	{
		return -1;
	}

	if (key_len != 16)
	{
		return -1;
	}

	uint8_t_uint32_t(key,k);
	SMS4_key_schedule(k,esk,dsk);

	uint8_t_uint32_t(iv,y);
	for(i=0;i<(int)pt_len;i+=16)
	{
		uint8_t_uint32_t((pt+i),x);
		y[0]^=x[0];		y[1]^=x[1];		y[2]^=x[2];		y[3]^=x[3];
		SMS4_crypt(y,y,esk);
		uint32_t_uint8_t(y,(ct+i));
	}
	if(flag==1)
	{
		uint32_t_uint8_t(y,iv);
	}
	return 0;

}

// CBC 模式，解密
int SMS4_DecCBC_SM100(unsigned char *key, unsigned int key_len,unsigned char *ct,
				 unsigned int ct_len,unsigned char *pt,unsigned char *iv,unsigned int flag)
{
	int i;
	uint32_t x[4],y[4],z[4],k[4];
	uint32_t esk[32],dsk[32];

	if (ct_len % 16)
	{
		return -1;
	}

	if (key_len != 16)
	{
		return -1;
	}

	uint8_t_uint32_t(key,k);
	SMS4_key_schedule(k,esk,dsk);

	uint8_t_uint32_t(iv,y);
	for(i=0;i<(int)ct_len;i+=16)
	{
		uint8_t_uint32_t((ct+i),z);
		SMS4_crypt(z,x,dsk);
		x[0]^=y[0];		x[1]^=y[1];		x[2]^=y[2];		x[3]^=y[3];
		uint32_t_uint8_t(x,(pt+i));
		y[0]=z[0];	y[1]=z[1];	y[2]=z[2];	y[3]=z[3];
	}
	if(flag==1)
	{
		uint32_t_uint8_t(y,iv);
	}
	return 0;
}

//
static srtp_err_status_t srtp_sdt_cipher_soft_sm4_cbc_alloc (srtp_cipher_t **c, int key_len, int tlen)
{

	srtp_sdt_soft_sm4_ctx* sdt_ctx;
    debug_print(srtp_mod_cipher,
                "allocating cipher with key length %d", key_len);


    if (key_len != SRTP_SDT_SM4_KEY_LEN) {

	printf("key_len != SRTP_SDT_SM4_KEY_LEN, key_len = %d \n", key_len);
        return srtp_err_status_bad_param;
    }

    /* allocate memory a cipher of type null_cipher */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return srtp_err_status_alloc_fail;
    }
    memset(*c, 0x0, sizeof(srtp_cipher_t));

    //allocate memory for sdt cipher
    sdt_ctx = (srtp_sdt_soft_sm4_ctx *)srtp_crypto_alloc(sizeof(srtp_sdt_soft_sm4_ctx));
    if (sdt_ctx == NULL)
    {
    	srtp_crypto_free(*c);
        return srtp_err_status_alloc_fail;
    }
    memset(sdt_ctx, 0x0, sizeof(srtp_sdt_soft_sm4_ctx));
    sdt_ctx->num = SMS4_CBC;

    (*c)->state = sdt_ctx;
    /* set pointers */
    (*c)->algorithm = SRTP_SDT_SOFT_SM4_CBC;
    (*c)->type = &srtp_sdt_SOFT_SM4_CBC_cipher;
//    (*c)->state = (void *) 0x1; /* The null cipher does not maintain state */

    /* set key size */
    (*c)->key_len = key_len;

//    printf("sdt_cipher_soft_sm4_cbc init ok\n");
    return srtp_err_status_ok;

}


static srtp_err_status_t srtp_sdt_soft_sm4_cipher_dealloc (srtp_cipher_t *c)
{
	srtp_sdt_soft_sm4_ctx* sdt_ctx = (srtp_sdt_soft_sm4_ctx *)c->state;
//////////////////close JMK ////////////////////////////////////////
//	printf("sdt_cipher_soft_sm4 close\n");
//////////////////close JMK ////////////////////////////////////////

    if (sdt_ctx) {
        /* zeroize the key material */
        octet_string_set_to_zero(sdt_ctx, sizeof(srtp_sdt_soft_sm4_ctx));
        srtp_crypto_free(sdt_ctx);
    }

    /* zeroize entire state*/
    octet_string_set_to_zero(c, sizeof(srtp_cipher_t));

    /* free memory of type null_cipher */
    srtp_crypto_free(c);

    return srtp_err_status_ok;

}

static srtp_err_status_t srtp_sdt_soft_sm4_cipher_init (void *cv, const uint8_t *key)
{
	srtp_sdt_soft_sm4_ctx* sdt_ctx;
	int rv,i;

	sdt_ctx = (srtp_sdt_soft_sm4_ctx *)cv;
    debug_print(srtp_mod_cipher, "initializing sdt cipher", NULL);

//    printf("input key is: ");
//    for(i=0; i < 16; i++)
//    {
//    	printf("%02x ",key[i]);
//    }
//    printf("\n");

//	unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    memset(sdt_ctx->sm4_key, 0, sizeof(sdt_ctx->sm4_key));
    memcpy(sdt_ctx->sm4_key, key, sizeof(sdt_ctx->sm4_key));


    sdt_ctx->encrypt_count = 0;
    sdt_ctx->decrypt_count = 0;

    return srtp_err_status_ok;
}


static srtp_err_status_t srtp_sdt_soft_sm4_cipher_set_iv (void *cv, uint8_t *iv, srtp_cipher_direction_t dir)
{

	srtp_sdt_soft_sm4_ctx *sdt_ctx = (srtp_sdt_soft_sm4_ctx *)cv;
	//added sanweixinan JMK key //

	if(dir == srtp_direction_encrypt)
		memset(sdt_ctx->iv, 0, 16);
	else if(dir == srtp_direction_decrypt)
		memset(sdt_ctx->oiv, 0, 16);
	else
	{
		memset(sdt_ctx->iv, 0, 16);
		memset(sdt_ctx->oiv, 0, 16);
	}
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_sdt_soft_sm4_cbc_cipher_encrypt (void *cv,
                                            unsigned char *buf, unsigned int *bytes_to_encr)
{
	srtp_sdt_soft_sm4_ctx *sdt_ctx = (srtp_sdt_soft_sm4_ctx *)cv;
	unsigned char outData[2048] = {0};
	if(*bytes_to_encr > 2048)
	{
		printf("*bytes_to_encr > 2048, *bytes_to_encr = %d \n", *bytes_to_encr);
		return srtp_err_status_bad_param;
	}
	if(*bytes_to_encr % 16 !=0)
	{
		printf("*bytes_to_encr % 16 !=0 , *bytes_to_encr = %d \n", *bytes_to_encr);
		return srtp_err_status_bad_param;
	}
	SMS4_EncCBC_SM100(sdt_ctx->sm4_key, SRTP_SDT_SM4_KEY_LEN, buf, *bytes_to_encr, outData, sdt_ctx->iv, 1);

	memcpy(buf, outData, *bytes_to_encr);


	if(sdt_ctx->encrypt_count == 65535)
		sdt_ctx->encrypt_count = 0;
	++(sdt_ctx->encrypt_count);
	if(sdt_ctx->encrypt_count % 5000 == 0)
		printf("sdt soft sm4 encrypt %ld packets success\n", sdt_ctx->encrypt_count);

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_sdt_soft_sm4_cbc_cipher_decrypt (void *cv,
                                            unsigned char *buf, unsigned int *bytes_to_encr)
{

	srtp_sdt_soft_sm4_ctx *sdt_ctx = (srtp_sdt_soft_sm4_ctx *)cv;
	unsigned char outData[2048] = {0};
	if(*bytes_to_encr > 2048)
	{
		printf("*bytes_to_encr > 2048, *bytes_to_encr = %d \n", *bytes_to_encr);
		return srtp_err_status_bad_param;
	}
	if(*bytes_to_encr % 16 !=0)
	{
		printf("*bytes_to_encr % 16 !=0, *bytes_to_encr = %d\n", *bytes_to_encr);
		return srtp_err_status_bad_param;
	}
	SMS4_DecCBC_SM100(sdt_ctx->sm4_key, SRTP_SDT_SM4_KEY_LEN, buf, *bytes_to_encr, outData, sdt_ctx->oiv, 1);
	memcpy(buf, outData, *bytes_to_encr);

	if(sdt_ctx->decrypt_count == 65535)
		sdt_ctx->decrypt_count = 0;
	++(sdt_ctx->decrypt_count);
	if(sdt_ctx->decrypt_count % 5000 == 0)
		printf("sdt soft sm4 decrypt %ld packets success\n", sdt_ctx->decrypt_count);

    return srtp_err_status_ok;
}


static const char srtp_sdt_soft_cipher_sm4_cbc_description[] = "sdt soft cipher sm4_cbc";

static const uint8_t srtp_sdt_sm4_test_case_0_key[SRTP_SDT_SM4_KEY_LEN] =  {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

static uint8_t srtp_sdt_sm4_test_case_0_nonce[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t srtp_sdt_sm4_test_case_0_plaintext[16]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};


static const uint8_t srtp_sdt_sm4_cbc_test_case_0_ciphertext[16]={0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};

static const srtp_cipher_test_case_t srtp_sdt_cipher_sm4_soft_cbc_test_0 = {
		SRTP_SDT_SM4_KEY_LEN,
		srtp_sdt_sm4_test_case_0_key,
		srtp_sdt_sm4_test_case_0_nonce,
		16,
		srtp_sdt_sm4_test_case_0_plaintext,
		16,
		srtp_sdt_sm4_cbc_test_case_0_ciphertext,
		0,
		NULL,
		0,
		NULL
};


/*
 * note: the decrypt function is idential to the encrypt function
 */

const srtp_cipher_type_t srtp_sdt_SOFT_SM4_CBC_cipher = {
	srtp_sdt_cipher_soft_sm4_cbc_alloc,
    srtp_sdt_soft_sm4_cipher_dealloc,
    srtp_sdt_soft_sm4_cipher_init,
    0,                     /* set_aad */
    srtp_sdt_soft_sm4_cbc_cipher_encrypt,
    srtp_sdt_soft_sm4_cbc_cipher_decrypt,
    srtp_sdt_soft_sm4_cipher_set_iv,
    0,                     /* get_tag */
    srtp_sdt_soft_cipher_sm4_cbc_description,
    &srtp_sdt_cipher_sm4_soft_cbc_test_0,
    SRTP_SDT_SOFT_SM4_CBC
};



