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
#include "sdt_sdf_cipher.h"
#include "err.h"                /* for srtp_debug */
#include "alloc.h"


/* the sdt_cipher uses the cipher debug module  */
extern srtp_debug_module_t srtp_mod_cipher;

extern const srtp_cipher_type_t srtp_sdt_SM4_ECB_cipher;
extern const srtp_cipher_type_t srtp_sdt_SM4_CBC_cipher;
extern const srtp_cipher_type_t srtp_sdt_SM4_OFB_cipher;

static srtp_err_status_t srtp_sdt_cipher_sm4_ecb_alloc (srtp_cipher_t **c, int key_len, int tlen)
{

    srtp_sdt_sm4_ctx_t* sdt_ctx;
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
    sdt_ctx = (srtp_sdt_sm4_ctx_t *)srtp_crypto_alloc(sizeof(srtp_sdt_sm4_ctx_t));
    if (sdt_ctx == NULL)
    {
    	srtp_crypto_free(*c);
        return srtp_err_status_alloc_fail;
    }
    memset(sdt_ctx, 0x0, sizeof(srtp_sdt_sm4_ctx_t));
    sdt_ctx->mode = SMS4_ECB;

    (*c)->state = sdt_ctx;
    /* set pointers */
    (*c)->algorithm = SRTP_SDT_SM4_ECB;
    (*c)->type = &srtp_sdt_SM4_ECB_cipher;
//    (*c)->state = (void *) 0x1; /* The null cipher does not maintain state */

    /* set key size */
    (*c)->key_len = key_len;

    //added sanweixinan JMK init //
    int rv;
  	if(SDR_OK!=(rv=SDF_OpenDevice(&(sdt_ctx->device_handle))))
  	{
  		printf("open device failed, error code=[0x%08x]\n",rv);
  		return srtp_err_status_alloc_fail;
  	}
  	if(SDR_OK!=(rv=SDF_OpenSession(sdt_ctx->device_handle, &(sdt_ctx->session_handle))))
  	{
  		printf("open session failed, error code=[0x%08x]\n",rv);
  		return srtp_err_status_alloc_fail;
  	}

  	if(SDR_OK!=(rv=SDF_GetDeviceInfo(sdt_ctx->session_handle, &(sdt_ctx->dev_info))))
  	{
  		printf("get dev_info failed, error code=[0x%08x]\n",rv);
  		return srtp_err_status_alloc_fail;
  	}

  	printf( "IssuerName= %s\n, DeviceName=%s\n, DeviceSerial=%d\n,DeviceVersion=%d\n" ,
  			sdt_ctx->dev_info.IssuerName,
  			sdt_ctx->dev_info.DeviceName,
  			sdt_ctx->dev_info.DeviceSerial,
  			sdt_ctx->dev_info.DeviceVersion );

	printf("JMK init, choose SM4 mode is %d OK\n", SMS4_ECB);

    return srtp_err_status_ok;

}


static srtp_err_status_t srtp_sdt_cipher_sm4_cbc_alloc (srtp_cipher_t **c, int key_len, int tlen)
{

    srtp_sdt_sm4_ctx_t* sdt_ctx;
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
    sdt_ctx = (srtp_sdt_sm4_ctx_t *)srtp_crypto_alloc(sizeof(srtp_sdt_sm4_ctx_t));
    if (sdt_ctx == NULL)
    {
    	srtp_crypto_free(*c);
        return srtp_err_status_alloc_fail;
    }
    memset(sdt_ctx, 0x0, sizeof(srtp_sdt_sm4_ctx_t));
    sdt_ctx->mode = SMS4_CBC;

    (*c)->state = sdt_ctx;
    /* set pointers */
    (*c)->algorithm = SRTP_SDT_SM4_CBC;
    (*c)->type = &srtp_sdt_SM4_CBC_cipher;
//    (*c)->state = (void *) 0x1; /* The null cipher does not maintain state */

    /* set key size */
    (*c)->key_len = key_len;

    //added sanweixinan JMK init //
    int rv;
  	if(SDR_OK!=(rv=SDF_OpenDevice(&(sdt_ctx->device_handle))))
  	{
  		printf("open device failed, error code=[0x%08x]\n",rv);
  		return srtp_err_status_alloc_fail;
  	}
  	if(SDR_OK!=(rv=SDF_OpenSession(sdt_ctx->device_handle, &(sdt_ctx->session_handle))))
  	{
  		printf("open session failed, error code=[0x%08x]\n",rv);
  		return srtp_err_status_alloc_fail;
  	}

  	if(SDR_OK!=(rv=SDF_GetDeviceInfo(sdt_ctx->session_handle, &(sdt_ctx->dev_info))))
  	{
  		printf("get dev_info failed, error code=[0x%08x]\n",rv);
  		return srtp_err_status_alloc_fail;
  	}

  	printf( "IssuerName= %s\n, DeviceName=%s\n, DeviceSerial=%d\n,DeviceVersion=%d\n" ,
  			sdt_ctx->dev_info.IssuerName,
  			sdt_ctx->dev_info.DeviceName,
  			sdt_ctx->dev_info.DeviceSerial,
  			sdt_ctx->dev_info.DeviceVersion );

	printf("JMK init, choose SM4 mode is %d OK\n", SMS4_CBC);

    return srtp_err_status_ok;

}

static srtp_err_status_t srtp_sdt_cipher_sm4_ofb_alloc (srtp_cipher_t **c, int key_len, int tlen)
{

    srtp_sdt_sm4_ctx_t* sdt_ctx;
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
    sdt_ctx = (srtp_sdt_sm4_ctx_t *)srtp_crypto_alloc(sizeof(srtp_sdt_sm4_ctx_t));
    if (sdt_ctx == NULL)
    {
    	srtp_crypto_free(*c);
        return srtp_err_status_alloc_fail;
    }
    memset(sdt_ctx, 0x0, sizeof(srtp_sdt_sm4_ctx_t));
    sdt_ctx->mode = SMS4_OFB;

    (*c)->state = sdt_ctx;
    /* set pointers */
    (*c)->algorithm = SRTP_SDT_SM4_OFB;
    (*c)->type = &srtp_sdt_SM4_OFB_cipher;
//    (*c)->state = (void *) 0x1; /* The null cipher does not maintain state */

    /* set key size */
    (*c)->key_len = key_len;

    //added sanweixinan JMK init //
    int rv;
  	if(SDR_OK!=(rv=SDF_OpenDevice(&(sdt_ctx->device_handle))))
  	{
  		printf("open device failed, error code=[0x%08x]\n",rv);
  		return srtp_err_status_alloc_fail;
  	}
  	if(SDR_OK!=(rv=SDF_OpenSession(sdt_ctx->device_handle, &(sdt_ctx->session_handle))))
  	{
  		printf("open session failed, error code=[0x%08x]\n",rv);
  		return srtp_err_status_alloc_fail;
  	}

  	if(SDR_OK!=(rv=SDF_GetDeviceInfo(sdt_ctx->session_handle, &(sdt_ctx->dev_info))))
  	{
  		printf("get dev_info failed, error code=[0x%08x]\n",rv);
  		return srtp_err_status_alloc_fail;
  	}

  	printf( "IssuerName= %s\n, DeviceName=%s\n, DeviceSerial=%d\n,DeviceVersion=%d\n" ,
  			sdt_ctx->dev_info.IssuerName,
  			sdt_ctx->dev_info.DeviceName,
  			sdt_ctx->dev_info.DeviceSerial,
  			sdt_ctx->dev_info.DeviceVersion );

	printf("JMK init, choose SM4 mode is %d OK\n", SMS4_OFB);

    return srtp_err_status_ok;

}


static srtp_err_status_t srtp_sdt_cipher_dealloc (srtp_cipher_t *c)
{
	srtp_sdt_sm4_ctx_t* sdt_ctx = (srtp_sdt_sm4_ctx_t *)c->state;
//////////////////close JMK ////////////////////////////////////////
	int rv;

	if(SDR_OK!=(rv=SDF_DestroyKey(sdt_ctx->session_handle, sdt_ctx->hKeyHandle)))
	{
		printf("DestroyKey failed, error code=[0x%08x]\n",rv);
		return srtp_err_status_dealloc_fail;
	}

	if(SDR_OK!=(rv=SDF_CloseSession(sdt_ctx->session_handle)))
	{
		printf("CloseSession failed, error code=[0x%08x]\n",rv);
		return srtp_err_status_dealloc_fail;
	}

	if(SDR_OK!=(rv=SDF_CloseDevice(sdt_ctx->device_handle)))
	{
		printf("CloseDevice failed, error code=[0x%08x]\n",rv);
		return srtp_err_status_dealloc_fail;
	}

	printf("JMK close OK\n");
//////////////////close JMK ////////////////////////////////////////

    if (sdt_ctx) {
        /* zeroize the key material */
        octet_string_set_to_zero(sdt_ctx, sizeof(srtp_sdt_sm4_ctx_t));
        srtp_crypto_free(sdt_ctx);
    }

    /* zeroize entire state*/
    octet_string_set_to_zero(c, sizeof(srtp_cipher_t));

    /* free memory of type null_cipher */
    srtp_crypto_free(c);

    return srtp_err_status_ok;

}

static srtp_err_status_t srtp_sdt_cipher_init (void *cv, const uint8_t *key)
{
	srtp_sdt_sm4_ctx_t* sdt_ctx;
	int rv,i;

	sdt_ctx = (srtp_sdt_sm4_ctx_t *)cv;
	/* srtp_sdt_cipher_ctx_t *c = (srtp_sdt_cipher_ctx_t *)cv; */

    debug_print(srtp_mod_cipher, "initializing sdt cipher", NULL);

//    printf("input key is: ");
//    for(i=0; i < 16; i++)
//    {
//    	printf("%02x ",key[i]);
//    }
//    printf("\n");

//	unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	rv = SDF_ImportKey(sdt_ctx->session_handle, key, 16, &(sdt_ctx->hKeyHandle));
	if(rv != SDR_OK)
	{
		printf("Import ket error, errorcode=[0x%08x]\n", rv);
		return srtp_err_status_init_fail;
	}

    return srtp_err_status_ok;
}


static srtp_err_status_t srtp_sdt_cipher_set_iv (void *cv, uint8_t *iv, srtp_cipher_direction_t dir)
{

	srtp_sdt_sm4_ctx_t *sdt_ctx = (srtp_sdt_sm4_ctx_t *)cv;
	//added sanweixinan JMK key //

	if(dir == srtp_direction_encrypt)
		memset(sdt_ctx->in_Iv, 0, 16);
	else if(dir == srtp_direction_decrypt)
		memset(sdt_ctx->out_Iv, 0, 16);
	else{
		memset(sdt_ctx->in_Iv, 0, 16);
		memset(sdt_ctx->out_Iv, 0, 16);
	}

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_sdt_cipher_encrypt (void *cv,
                                            unsigned char *buf, unsigned int *bytes_to_encr)
{

	srtp_sdt_sm4_ctx_t *sdt_ctx = (srtp_sdt_sm4_ctx_t *)cv;
	//added sanweixinan JMK encrypt //
	int rv;
	unsigned char pbTempData[2048] = {0};
	unsigned int  ulTempDataLen;

	if(*bytes_to_encr > 2048)
		return srtp_err_status_bad_param;

//	printf("to be encrypt is %02x, len=%d\n",buf,*bytes_to_encr);
	if(*bytes_to_encr % 16 !=0)
		return srtp_err_status_bad_param;

	unsigned int AlgID;
	switch(sdt_ctx->mode)
	{
	case SMS4_CBC:
		AlgID = SGD_SMS4_CBC;
		break;
	case SMS4_OFB:
		AlgID = SGD_SMS4_OFB;
		break;
	default:
		AlgID = SGD_SMS4_ECB;
	}


	rv = SDF_Encrypt(sdt_ctx->session_handle, sdt_ctx->hKeyHandle, AlgID, sdt_ctx->in_Iv, buf, *bytes_to_encr, pbTempData, &ulTempDataLen);
	if(rv != SDR_OK)
	{
		printf("encrypto error，error[0x%08x]\n", rv);
		return srtp_err_status_cipher_fail;
	}
	memcpy(buf, pbTempData, ulTempDataLen);
	*bytes_to_encr = ulTempDataLen;

//	printf("sm4 encrypt success\n");
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_sdt_cipher_decrypt (void *cv,
                                            unsigned char *buf, unsigned int *bytes_to_encr)
{

	srtp_sdt_sm4_ctx_t *sdt_ctx = (srtp_sdt_sm4_ctx_t *)cv;

	unsigned char pbOutData[2048] = {0};
	unsigned int  ulOutDataLen;
	int rv;

	if(*bytes_to_encr > 2048)
		return srtp_err_status_bad_param;

//	printf("to be decrypt is %02x, len=%d\n",buf,*bytes_to_encr);
	if(*bytes_to_encr % 16 !=0)
		return srtp_err_status_bad_param;


	unsigned int AlgID;
	switch(sdt_ctx->mode)
	{
	case SMS4_CBC:
		AlgID = SGD_SMS4_CBC;
		break;
	case SMS4_OFB:
		AlgID = SGD_SMS4_OFB;
		break;
	default:
		AlgID = SGD_SMS4_ECB;
	}

	rv = SDF_Decrypt(sdt_ctx->session_handle, sdt_ctx->hKeyHandle, AlgID, sdt_ctx->out_Iv, buf, *bytes_to_encr, pbOutData, &ulOutDataLen);
	if(rv != SDR_OK)
	{
		printf("decrypto error，error[0x%08x]\n", rv);
		return srtp_err_status_cipher_fail;
	}

	memcpy(buf, pbOutData, ulOutDataLen);
	*bytes_to_encr = ulOutDataLen;

//	printf("sm4 decrypt success\n");
    return srtp_err_status_ok;
}

static const char srtp_sdt_cipher_sm4_ecb_description[] = "sdt cipher sm4_ecb";
static const char srtp_sdt_cipher_sm4_cbc_description[] = "sdt cipher sm4_cbc";
static const char srtp_sdt_cipher_sm4_ofb_description[] = "sdt cipher sm4_ofb";

static const uint8_t srtp_sdt_sm4_test_case_0_key[SRTP_SDT_SM4_KEY_LEN] =  {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

static uint8_t srtp_sdt_sm4_test_case_0_nonce[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t srtp_sdt_sm4_test_case_0_plaintext[16]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

static const uint8_t srtp_sdt_sm4_ecb_test_case_0_ciphertext[16]={0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};

static const uint8_t srtp_sdt_sm4_cbc_test_case_0_ciphertext[16]={0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};

static const uint8_t srtp_sdt_sm4_ofb_test_case_0_ciphertext[16]={0x27,0x54,0xb1,0x0c,0x80,0x6a,0xef,0x23,0x69,0x89,0x89,0x88,0x2d,0x80,0x90,0x3a};


static const srtp_cipher_test_case_t srtp_sdt_cipher_sm4_ecb_test_0 = {
		SRTP_SDT_SM4_KEY_LEN,
		srtp_sdt_sm4_test_case_0_key,
		srtp_sdt_sm4_test_case_0_nonce,
		16,
		srtp_sdt_sm4_test_case_0_plaintext,
		16,
		srtp_sdt_sm4_ecb_test_case_0_ciphertext,
		0,
		NULL,
		0,
		NULL
};


static const srtp_cipher_test_case_t srtp_sdt_cipher_sm4_cbc_test_0 = {
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


static const srtp_cipher_test_case_t srtp_sdt_cipher_sm4_ofb_test_0 = {
		SRTP_SDT_SM4_KEY_LEN,
		srtp_sdt_sm4_test_case_0_key,
		srtp_sdt_sm4_test_case_0_nonce,
		16,
		srtp_sdt_sm4_test_case_0_plaintext,
		16,
		srtp_sdt_sm4_ofb_test_case_0_ciphertext,
		0,
		NULL,
		0,
		NULL
};

/*
 * note: the decrypt function is idential to the encrypt function
 */

const srtp_cipher_type_t srtp_sdt_SM4_ECB_cipher = {
		srtp_sdt_cipher_sm4_ecb_alloc,
    srtp_sdt_cipher_dealloc,
    srtp_sdt_cipher_init,
    0,                     /* set_aad */
    srtp_sdt_cipher_encrypt,
    srtp_sdt_cipher_decrypt,
    srtp_sdt_cipher_set_iv,
    0,                     /* get_tag */
    srtp_sdt_cipher_sm4_ecb_description,
    &srtp_sdt_cipher_sm4_ecb_test_0,
    SRTP_SDT_SM4_ECB
};

const srtp_cipher_type_t srtp_sdt_SM4_CBC_cipher = {
	srtp_sdt_cipher_sm4_cbc_alloc,
    srtp_sdt_cipher_dealloc,
    srtp_sdt_cipher_init,
    0,                     /* set_aad */
    srtp_sdt_cipher_encrypt,
    srtp_sdt_cipher_decrypt,
    srtp_sdt_cipher_set_iv,
    0,                     /* get_tag */
    srtp_sdt_cipher_sm4_cbc_description,
    &srtp_sdt_cipher_sm4_cbc_test_0,
    SRTP_SDT_SM4_CBC
};


const srtp_cipher_type_t srtp_sdt_SM4_OFB_cipher = {
	srtp_sdt_cipher_sm4_ofb_alloc,
    srtp_sdt_cipher_dealloc,
    srtp_sdt_cipher_init,
    0,                     /* set_aad */
    srtp_sdt_cipher_encrypt,
    srtp_sdt_cipher_decrypt,
    srtp_sdt_cipher_set_iv,
    0,                     /* get_tag */
    srtp_sdt_cipher_sm4_ofb_description,
    &srtp_sdt_cipher_sm4_ofb_test_0,
    SRTP_SDT_SM4_OFB
};
