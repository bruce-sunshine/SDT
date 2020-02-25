/*
 * sdt_sdf.c
 *
 *  Created on: Aug 31, 2018
 *      Author: bruce
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/sgd.h>
#include <openssl/sdf.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sm3.h>
#include <openssl/ossl_typ.h>
#include <openssl/obj_mac.h>
#include "internal/evp_int.h"
#include "../crypto/evp/evp_locl.h"
#include <openssl/sms4.h>
//#include <openssl/sha.h>
//#include "../crypto/sm2/sm2_lcl.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/rand.h>
#include "../crypto/ec/ec_lcl.h"
#include <openssl/ecies.h>
#include <openssl/gmapi.h>
#include <pthread.h>
#define EC_KEY_METHOD_SM2	0x02
#define SM3_DIGEST_LENGTH 32
#define SDT_SDF_SM2_PKEY 1
/* Engine Id and Name */
static const char *engine_sdt_sdf_id = "sdt_sdf";
static const char *engine_sdt_sdf_name = "sdt_sdf engine by bruce";

static int sdt_sdf_sm3_init(EVP_MD_CTX *ctx);
static int sdt_sdf_sm3_update(EVP_MD_CTX *ctx, const void *in, size_t inlen);
static int sdt_sdf_sm3_final(EVP_MD_CTX *ctx, unsigned char *md);


typedef void*	SGD_HANDLE;
SGD_HANDLE device_handle=NULL;



static int sdt_sdf_engine_init(ENGINE *e)
{

	ERR_load_SDF_strings();
	if(SDR_OK !=SDF_LoadLibrary("/lib64/libswsds.so", NULL))
	{
		printf("load sdf_library error\n");
		return 0;
	}
	int rv;
	SGD_HANDLE session_handle=NULL;
	DEVICEINFO dev_info;
	if(device_handle == NULL)
	{
		printf("init sdf handle\n");
		if(SDR_OK!=(rv=SDF_OpenDevice(&device_handle)))
		{
			printf("open device failed, error code=[0x%08x]\n",rv);
			return 0;
		}
		if(SDR_OK!=SDF_OpenSession(device_handle, &session_handle))
		{
			printf("open session failed\n");
			return 0;
		}

		if(SDR_OK!=SDF_GetDeviceInfo(session_handle, &dev_info))
		{
			printf("get deviceinfo session failed\n");
			return 0;
		}
		SDF_PrintDeviceInfo(&dev_info);
		SDF_CloseSession(session_handle);
	}
    return 1;
}


static int sdt_sdf_finish(ENGINE *e)
{
	printf("sdt_sdf_finish\n");
	if(device_handle !=NULL)
	{
		SDF_CloseDevice(device_handle);
		device_handle = NULL;
	}
    return 1;
}


static int sdt_sdf_destroy(ENGINE *e)
{

	printf("close sdf device\n");
	SDF_UnloadLibrary();
    return 1;
}


/*----------------------------------- sm2, begin ---------------------------------------*/

typedef struct sdt_sdf_sm2_st {
	SGD_HANDLE session_sm2;
	ECCrefPublicKey pubKey;
	ECCrefPrivateKey priKey;
} SDT_SDF_SM2_CTX;


int sdt_sdf_sm2_init(EC_KEY *key)
{
//	int rv;
//	SDT_SDF_SM2_CTX* sm2_ctx = OPENSSL_zalloc(sizeof(SDT_SDF_SM2_CTX));
//    if (sm2_ctx == NULL) {
//        ECerr(EC_F_EC_KEY_NEW_METHOD, ERR_R_MALLOC_FAILURE);
//        return NULL;
//    }
//    key->data = sm2_ctx;
//  	if(SDR_OK!=(rv=SDF_OpenSession(device_handle, &(sm2_ctx->session_sm2))))
//  	{
//  		printf("open session failed, error code=[0x%08x]\n",rv);
//  		return 0;
//  	}
//  	printf("sdt_sdf_sm2_init\n");
  	return 1;
}

void sdt_sdf_sm2_finish(EC_KEY *key)
{
//	int rv;
//	SDT_SDF_SM2_CTX* sm2_ctx = key->data;
//	if(SDR_OK!=(rv=SDF_CloseSession(sm2_ctx->session_sm2)))
//	{
//		printf("CloseSession failed, error code=[0x%08x]\n",rv);
//		return;
//	}
//	printf("sdt_sdf_sm2_finish\n");
//	OPENSSL_free(sm2_ctx);
}

int sdt_sdf_sm2_ec_key_gen(EC_KEY *eckey)
{
//	int res = EC_KEY_GmSSL()->keygen(eckey);
//	printf("gen sdt_skf ecc key pairs\n");
//	return res;

	int rv;
	SGD_HANDLE session_sm2;
	ECCrefPublicKey pubKey;
	ECCrefPrivateKey priKey;
	if(SDR_OK != (rv = SDF_OpenSession(device_handle, &(session_sm2))))
	{
		printf("open session failed, error code=[0x%08x]\n",rv);
		return 0;
	}

	int keyLen = 256;
	rv = SDF_GenerateKeyPair_ECC(session_sm2, SGD_SM2_3, keyLen, &pubKey, &priKey);
	if(rv != SDR_OK)
	{
		printf("产生ECC密钥对错误，错误码[0x%08x]\n", rv);
		return 0;
	}
	printf("using sdt sdf sm2 to gen ecc pair, success\n");

	//added by bruce, 1213, do not need to re new eckey, eckey had been new by EC_KEY_new_by_curve_name(OBJ_sn2nid("sm2p256v1")

//	eckey = EC_KEY_new_from_ECCrefPrivateKey(&priKey);
//	if(eckey == NULL)
//	{
//		printf("EC_KEY_new_from_ECCrefPrivateKey error\n");
//		return 0;
//	}

	if(1 != EC_KEY_set_ECCrefPrivateKey(eckey, &priKey))
	{
		printf("EC_KEY_set_ECCrefPrivateKey error\n");
		return 0;
	}

	if(1 != EC_KEY_set_ECCrefPublicKey(eckey, &pubKey))
	{
		printf("EC_KEY_set_ECCrefPublicKey error\n");
		return 0;
	}

	if(SDR_OK != (rv = SDF_CloseSession(session_sm2)))
	{
		printf("CloseSession failed, error code=[0x%08x]\n",rv);
		return 0;
	}

	return 1;

}


int sdt_sdf_ecdh_compute_key(unsigned char **psec, size_t *pseclen,
                          const EC_POINT *pub_key, const EC_KEY *ecdh)
{
	return EC_KEY_OpenSSL()->compute_key(psec, pseclen, pub_key, ecdh);
}


int sdt_sdf_sm2_set_private(EC_KEY *key, const BIGNUM *priv_key)
{
	return 1;
}

int sdt_sdf_sm2_set_public(EC_KEY *key, const EC_POINT *pub_key)
{
	return 1;
}

ECDSA_SIG* sdt_sdf_sm2_sign_sig(const unsigned char *dgst, int dgst_len,
                       const BIGNUM *in_kinv, const BIGNUM *in_r,
                       EC_KEY *eckey);

int sdt_sdf_sm2_sign(int type, const unsigned char *dgst, int dlen, unsigned char
            *sig, unsigned int *siglen, const BIGNUM *kinv,
            const BIGNUM *r, EC_KEY *eckey)
{
	//	return EC_KEY_GmSSL()->sign( type, dgst, dlen, sig, siglen, kinv, r, eckey);

		ECDSA_SIG *s;
		RAND_seed(dgst, dlen);

		if (!(s = sdt_sdf_sm2_sign_sig(dgst, dlen, kinv, r, eckey))) {
			*siglen = 0;
			return 0;
		}

#if 0
	printf("12345678\n");
	int i;
	printf("sign, dgst is :\n");
	for(i = 0; i < dlen; i++)
	{
		printf("0x%02x,", dgst[i]);
	}
	printf("\n");

	printf("sign, sig is :\n");
	for(i = 0; i < *siglen; i++)
	{
		printf("0x%02x,", *(sig+i));
	}
	printf("\n");
#endif

		*siglen = i2d_ECDSA_SIG(s, &sig);
		ECDSA_SIG_free(s);
		return 1;
}


int sdt_sdf_sm2_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                  BIGNUM **rp)
{
	printf("sdt_sdf_sm2_sign_setup\n");
	return EC_KEY_GmSSL()->sign_setup(eckey, ctx_in, kinvp, rp);
}

ECDSA_SIG* sdt_sdf_sm2_sign_sig(const unsigned char *dgst, int dgst_len,
                       const BIGNUM *in_kinv, const BIGNUM *in_r,
                       EC_KEY *eckey)
{
//	return EC_KEY_GmSSL()->sign_sig(dgst,  dgst_len, in_kinv, in_r, eckey);


	ECCSignature sigref;
	ECDSA_SIG *ret = NULL;
	ECCrefPrivateKey priKey;
	SGD_HANDLE session_sm2;
	int rv;
	if(SDR_OK != (rv = SDF_OpenSession(device_handle, &(session_sm2))))
	{
		printf("open session failed, error code=[0x%08x]\n",rv);
		return 0;
	}

	if(1 != EC_KEY_get_ECCrefPrivateKey(eckey, &(priKey)))
	{
		printf("EC_KEY_get_ECCrefPrivateKey error\n");
		return NULL;
	}
	int sdf_rv;
	sdf_rv = SDF_ExternalSign_ECC(session_sm2, SGD_SM2_1, &(priKey), dgst, dgst_len, &sigref);
	if(sdf_rv != SDR_OK)
	{
		printf("SDF_ExternalSign_ECC error, error = [0x%08x]\n", sdf_rv);
		return NULL;
	}
	else
	{
		printf("SDF_ExternalSign_ECC success\n");
	}

	ret = ECDSA_SIG_new_from_ECCSignature(&sigref);
	if(ret == NULL)
	{
		printf("ECDSA_SIG_new_from_ECCSIGNATUREBLOB error\n");
		return NULL;
	}

	if(SDR_OK != (rv = SDF_CloseSession(session_sm2)))
	{
		printf("CloseSession failed, error code=[0x%08x]\n",rv);
		return 0;
	}

//	ECDSA_SIG *s = EC_KEY_GmSSL()->sign_sig(dgst,  dgst_len, in_kinv, in_r, eckey);
//	ECDSA_SIG_free(s);

	return ret;
}


int sdt_sdf_sm2_verify(int type, const unsigned char *dgst, int dgst_len,
              const unsigned char *sig, int siglen, EC_KEY *eckey)
{
	//	return  EC_KEY_GmSSL()->verify(type, dgst, dgstlen, sig, siglen, ec_key);

		ECDSA_SIG *s;
		const unsigned char *p = sig;
		unsigned char *der = NULL;
		int derlen = -1;
		int ret = -1;

#if 0
	int i;
	printf("verify, dgst is :\n");
	for(i = 0; i < dgst_len; i++)
	{
		printf("0x%02x,", dgst[i]);
	}
	printf("\n");

	printf("verify, sig is :\n");
	for(i = 0; i < siglen; i++)
	{
		printf("0x%02x,", sig[i]);
	}
	printf("\n");
#endif

		if (!(s = ECDSA_SIG_new())) {
			return ret;
		}
		if (!d2i_ECDSA_SIG(&s, &p, siglen)) {
			goto err;
		}
		derlen = i2d_ECDSA_SIG(s, &der);
		if (derlen != siglen || memcmp(sig, der, derlen)) {
			goto err;
		}

		ret = sdt_sdf_sm2_verify_sig(dgst, dgst_len, s, eckey);

	err:
		if (derlen > 0) {
			OPENSSL_cleanse(der, derlen);
			OPENSSL_free(der);
		}

		ECDSA_SIG_free(s);
		return ret;
}


int sdt_sdf_sm2_verify_sig(const unsigned char *dgst, int dgst_len,
                  const ECDSA_SIG *sig, EC_KEY *eckey)
{
	//	return  EC_KEY_GmSSL()->verify_sig(dgst, dgstlen, sig, ec_key);

		ULONG sdf_rv;
		ECCrefPublicKey pubKey;
//		ECCrefPrivateKey priKey;
		ECCSignature sigref;
		SGD_HANDLE session_sm2;
		int rv;
		if(SDR_OK != (rv = SDF_OpenSession(device_handle, &(session_sm2))))
		{
			printf("open session failed, error code=[0x%08x]\n",rv);
			return 0;
		}


		if(1 != ECDSA_SIG_get_ECCSignature(sig, &sigref))
		{
			printf("ECDSA_SIG_get_ECCSignature error\n");
			return 0;
		}

		if(1 != EC_KEY_get_ECCrefPublicKey(eckey, &(pubKey)))
		{
			printf("EC_KEY_get_ECCrefPublicKey error\n");
			return 0;
		}

		sdf_rv = SDF_ExternalVerify_ECC(session_sm2, SGD_SM2_1, &pubKey, dgst, dgst_len, &sigref);
		if(sdf_rv != SAR_OK)
		{
			printf("SDF_ExternalVerify_ECC error，eroor = [0x%08x]\n", sdf_rv);
			return 0;
		}
		else
		{
			printf("SDF_ExternalVerify_ECC success\n");
		}

		if(SDR_OK != (rv = SDF_CloseSession(session_sm2)))
		{
			printf("CloseSession failed, error code=[0x%08x]\n",rv);
			return 0;
		}
#if 0
		int i;
		printf("verify sigref = \n");
		printf("sigref.s = \n");
		for(i =0; i < 64; i++)
		{
			printf("0x%02x ", sigref.s[i]);
		}
		printf("\n");
		printf("sigref.r  = \n");
		for(i =0; i < 64; i++)
		{
			printf("0x%02x ", sigref.r[i]);
		}
		printf("\n");
#endif
		return 1;
}

int sdt_sdf_sm2_encrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int rv;
	SGD_HANDLE session_sm2;
	ECCrefPublicKey pubKey;

	if(SDR_OK != (rv = SDF_OpenSession(device_handle, &(session_sm2))))
	{
		printf("open session failed, error code=[0x%08x]\n",rv);
		return 0;
	}

	if(1 != EC_KEY_get_ECCrefPublicKey(ec_key, &(pubKey)))
	{
		printf("EC_KEY_get_ECCrefPublicKey error\n");
		return 0;
	}

	rv = SDF_ExternalEncrypt_ECC(session_sm2, SGD_SM2_3, &(pubKey), in, inlen, (ECCCipher *)out);
	if(rv != SDR_OK)
	{
		printf("pubkey encrypt error，错误码[0x%08x]\n", rv);
		return 0;
	}
	*outlen = inlen;

	//need to transfer

	if(SDR_OK != (rv = SDF_CloseSession(session_sm2)))
	{
		printf("CloseSession failed, error code=[0x%08x]\n",rv);
		return 0;
	}
	printf("sdt_sdf_sm2_encrypt success\n");
	return 1;
}

int sdt_sdf_sm2_decrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int rv;
	SGD_HANDLE session_sm2;
	ECCrefPrivateKey priKey;

	if(SDR_OK != (rv = SDF_OpenSession(device_handle, &(session_sm2))))
	{
		printf("open session failed, error code=[0x%08x]\n",rv);
		return 0;
	}

	if(1 != EC_KEY_get_ECCrefPrivateKey(ec_key, &(priKey)))
	{
		printf("EC_KEY_get_ECCrefPrivateKey error\n");
		return 0;
	}
	//need to transfer
	rv = SDF_ExternalDecrypt_ECC(session_sm2, SGD_SM2_3, &priKey, (ECCCipher *)in, out, outlen);
	if(rv != SDR_OK)
	{
		printf("privkey decrypt error，错误码[0x%08x]\n", rv);
		return 0;
	}

	if(SDR_OK != (rv = SDF_CloseSession(session_sm2)))
	{
		printf("CloseSession failed, error code=[0x%08x]\n",rv);
		return 0;
	}

	printf("sdt_sdf_sm2_decrypt success\n");
	return 1;
}

static const EC_KEY_METHOD sdt_sdf_ec_key_method = {
	"SDT_SDF EC_KEY method",
	EC_KEY_METHOD_SM2,
	sdt_sdf_sm2_init,
	sdt_sdf_sm2_finish,
	0,
	0,
//	sdt_sdf_sm2_set_private,
//	sdt_sdf_sm2_set_public,
	0,
	0,
	sdt_sdf_sm2_ec_key_gen,
	sdt_sdf_ecdh_compute_key,
	sdt_sdf_sm2_sign,
	sdt_sdf_sm2_sign_setup,
	sdt_sdf_sm2_sign_sig,
	sdt_sdf_sm2_verify,
	sdt_sdf_sm2_verify_sig,
	sdt_sdf_sm2_encrypt,
	NULL,
	sdt_sdf_sm2_decrypt,
	NULL,
};

const EC_KEY_METHOD *EC_KEY_GmSSL_SDT_SDF(void)
{
	return &sdt_sdf_ec_key_method;
}


/*---------------------------------pkey method---------------------------------------------*/
#if 1

typedef struct {
    /* Key and paramgen group */
    EC_GROUP *gen_group;
    /* message digest */
    const EVP_MD *md;
    /* Duplicate key if custom cofactor needed */
    EC_KEY *co_key;
    /* Cofactor mode */
    signed char cofactor_mode;
    /* KDF (if any) to use for ECDH */
    char kdf_type;
    /* Message digest to use for key derivation */
    const EVP_MD *kdf_md;
    /* User key material */
    unsigned char *kdf_ukm;
    size_t kdf_ukmlen;
    /* KDF output length */
    size_t kdf_outlen;
#ifndef OPENSSL_NO_SM2
    int ec_scheme;
    char *signer_id;
    unsigned char *signer_zid;
    int ec_encrypt_param;
#endif
#if   0

    SDT_SDF_SM2_CTX* sm2_ctx;

#endif
} SDT_SDF_EC_PKEY_CTX;



static int sdt_sdf_pkey_ec_init(EVP_PKEY_CTX *ctx)
{
//	printf("sdt_sdf_pkey_ec_init\n");

	SDT_SDF_EC_PKEY_CTX *dctx;

    dctx = OPENSSL_zalloc(sizeof(*dctx));
    if (dctx == NULL)
        return 0;

    dctx->cofactor_mode = -1;
    dctx->kdf_type = EVP_PKEY_ECDH_KDF_NONE;
#ifndef OPENSSL_NO_SM2
    dctx->ec_scheme = NID_secg_scheme;
    dctx->signer_id = NULL;
    dctx->signer_zid = NULL;
    dctx->ec_encrypt_param = NID_undef;
#endif

    ctx->data = dctx;
    return 1;
}

static int sdt_sdf_pkey_ec_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{

	SDT_SDF_EC_PKEY_CTX *dctx, *sctx;
    if (!sdt_sdf_pkey_ec_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    if (sctx->gen_group) {
        dctx->gen_group = EC_GROUP_dup(sctx->gen_group);
        if (!dctx->gen_group)
            return 0;
    }
    dctx->md = sctx->md;

    if (sctx->co_key) {
        dctx->co_key = EC_KEY_dup(sctx->co_key);
        if (!dctx->co_key)
            return 0;
    }
    dctx->kdf_type = sctx->kdf_type;
    dctx->kdf_md = sctx->kdf_md;
    dctx->kdf_outlen = sctx->kdf_outlen;
    if (sctx->kdf_ukm) {
        dctx->kdf_ukm = OPENSSL_memdup(sctx->kdf_ukm, sctx->kdf_ukmlen);
        if (!dctx->kdf_ukm)
            return 0;
    } else
        dctx->kdf_ukm = NULL;
    dctx->kdf_ukmlen = sctx->kdf_ukmlen;
#ifndef OPENSSL_NO_SM2
    dctx->ec_scheme = sctx->ec_scheme;
    if (sctx->signer_id) {
        dctx->signer_id = OPENSSL_strdup(sctx->signer_id);
        if (!dctx->signer_id)
            return 0;
    }
    dctx->signer_zid = NULL;
    dctx->ec_encrypt_param = sctx->ec_encrypt_param;

#endif
    return 1;
}

static void sdt_sdf_pkey_ec_cleanup(EVP_PKEY_CTX *ctx)
{
	SDT_SDF_EC_PKEY_CTX *dctx = ctx->data;
    if (dctx) {
        EC_GROUP_free(dctx->gen_group);
        EC_KEY_free(dctx->co_key);
        OPENSSL_free(dctx->kdf_ukm);
#ifndef OPENSSL_NO_SM2
        OPENSSL_free(dctx->signer_id);
        OPENSSL_free(dctx->signer_zid);
#endif
        OPENSSL_free(dctx);
    }
}

static int sdt_sdf_pkey_ec_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec = NULL;
    SDT_SDF_EC_PKEY_CTX *dctx = ctx->data;
    int ret = 0;
    if (dctx->gen_group == NULL) {
        ECerr(EC_F_PKEY_EC_PARAMGEN, EC_R_NO_PARAMETERS_SET);
        return 0;
    }
    ec = EC_KEY_new();
    if (ec == NULL)
        return 0;
    ret = EC_KEY_set_group(ec, dctx->gen_group);
    if (ret)
        EVP_PKEY_assign_EC_KEY(pkey, ec);
    else
        EC_KEY_free(ec);
    return ret;

}


static int sdt_sdf_pkey_ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec = NULL;
    SDT_SDF_EC_PKEY_CTX *dctx = ctx->data;
    if (ctx->pkey == NULL && dctx->gen_group == NULL) {
        ECerr(EC_F_PKEY_EC_KEYGEN, EC_R_NO_PARAMETERS_SET);
        return 0;
    }
    ec = EC_KEY_new();
    if (!ec)
        return 0;
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    if (ctx->pkey) {
        /* Note: if error return, pkey is freed by parent routine */
        if (!EVP_PKEY_copy_parameters(pkey, ctx->pkey))
            return 0;
    } else {
        if (!EC_KEY_set_group(ec, dctx->gen_group))
            return 0;
    }

    return EC_KEY_generate_key(pkey->pkey.ec);
}

static int sdt_sdf_pkey_ec_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    int ret, type;
    unsigned int sltmp;
    SDT_SDF_EC_PKEY_CTX *dctx = ctx->data;
    EC_KEY *ec = ctx->pkey->pkey.ec;

    if (!sig) {
        *siglen = ECDSA_size(ec);
        return 1;
    } else if (*siglen < (size_t)ECDSA_size(ec)) {
        ECerr(EC_F_PKEY_EC_SIGN, EC_R_BUFFER_TOO_SMALL);
        return 0;
    }

    if (dctx->md)
        type = EVP_MD_type(dctx->md);
    else
        type = NID_sha1;
    printf("pkey_ec_sign, dctx->ec_scheme = %d\n", dctx->ec_scheme);
#ifndef OPENSSL_NO_SM2
    if (dctx->ec_scheme == NID_sm_scheme)
//    	       ret = SM2_sign(NID_undef, tbs, tbslen, sig, &sltmp, ec);
//    	ret = ec->meth->sign(NID_undef, tbs, tbslen, sig, &sltmp, NULL, NULL, ec);    //changed by bruce, 1130

#ifdef SDT_SDF_SM2_PKEY
//    	ret = ec->meth->sign(NID_undef, tbs, tbslen, sig, &sltmp, NULL, NULL, ec);    //changed by bruce, 1130
    	ret = sdt_sdf_sm2_sign(NID_undef, tbs, tbslen, sig, &sltmp, NULL, NULL, ec);    //changed by bruce, 1210
#else
    	ret = SM2_sign(NID_undef, tbs, tbslen, sig, &sltmp, ec);
#endif

    else
#endif

    ret = ECDSA_sign(type, tbs, tbslen, sig, &sltmp, ec);
#if 0
    int i;
    printf("sign in data is:\n");
    for(i = 0; i < *siglen; i++)
    {
    	printf("0x%02x ", sig[i]);
    }
    printf("\n");

    printf("sign out data is:\n");
    for(i = 0; i < tbslen; i++)
    {
    	printf("0x%02x ", tbs[i]);
    }
    printf("\n");
#endif
    if (ret <= 0)
        return ret;
    *siglen = (size_t)sltmp;
    return 1;
}

static int sdt_sdf_pkey_ec_verify(EVP_PKEY_CTX *ctx,
                          const unsigned char *sig, size_t siglen,
                          const unsigned char *tbs, size_t tbslen)
{
	int ret, type;
	SDT_SDF_EC_PKEY_CTX *dctx = ctx->data;
	EC_KEY *ec = ctx->pkey->pkey.ec;

	if (dctx->md)
		type = EVP_MD_type(dctx->md);
	else
		type = NID_sha1;
	printf("pkey_ec_verify, dctx->ec_scheme = %d\n", dctx->ec_scheme);
#ifndef OPENSSL_NO_SM2
	if (dctx->ec_scheme == NID_sm_scheme)
//		ret = SM2_verify(NID_undef, tbs, tbslen, sig, siglen, ec);
//		ret = ec->meth->verify(NID_undef, tbs, tbslen, sig, siglen, ec);    //changed by bruce, 1130
#ifdef SDT_SDF_SM2_PKEY
//	ret = ec->meth->verify(NID_undef, tbs, tbslen, sig, siglen, ec);    //changed by bruce, 1130
	ret = sdt_sdf_sm2_verify(NID_undef, tbs, tbslen, sig, siglen, ec);    //changed by bruce, 1210
#else
	ret = SM2_verify(NID_undef, tbs, tbslen, sig, siglen, ec);
#endif
	else
#endif
		ret = ECDSA_verify(type, tbs, tbslen, sig, siglen, ec);
#if 0
    int i;
    printf("verify in data is:\n");
    for(i = 0; i < siglen; i++)
    {
    	printf("0x%02x ", sig[i]);
    }
    printf("\n");

    printf("verify out data is:\n");
    for(i = 0; i < tbslen; i++)
    {
    	printf("0x%02x ", tbs[i]);
    }
    printf("\n");
#endif
	return ret;
}

static int sdt_sdf_pkey_ec_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen)
{

    SDT_SDF_EC_PKEY_CTX *dctx = ctx->data;
    EC_KEY *ec_key = ctx->pkey->pkey.ec;
    printf("pkey_ec_encrypt, dctx->ec_scheme = %d\n", dctx->ec_scheme);
    switch (dctx->ec_scheme) {
    case NID_sm_scheme:
        if (!SM2_encrypt(dctx->ec_encrypt_param, in, inlen, out, outlen, ec_key)) {
            ECerr(EC_F_PKEY_EC_ENCRYPT, EC_R_SM2_ENCRYPT_FAILED);
            return 0;
        }
        break;
    case NID_secg_scheme:
        if (!ECIES_encrypt(dctx->ec_encrypt_param, in, inlen, out, outlen, ec_key)) {
            ECerr(EC_F_PKEY_EC_ENCRYPT, EC_R_ECIES_ENCRYPT_FAILED);
            return 0;
        }
        break;
    default:
        ECerr(EC_F_PKEY_EC_ENCRYPT, EC_R_INVALID_ENC_TYPE);
        return 0;
    }

    return 1;
}

static int sdt_sdf_pkey_ec_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen)
{
    SDT_SDF_EC_PKEY_CTX *dctx = ctx->data;
    EC_KEY *ec_key = ctx->pkey->pkey.ec;
    printf("pkey_ec_decrypt, dctx->ec_scheme = %d\n", dctx->ec_scheme);
    switch (dctx->ec_scheme) {
    case  NID_sm_scheme:
        if (!SM2_decrypt(dctx->ec_encrypt_param, in, inlen, out, outlen, ec_key)) {
            ECerr(EC_F_PKEY_EC_DECRYPT, EC_R_SM2_DECRYPT_FAILED);
            return 0;
        }
        break;
    case NID_secg_scheme:
        if (!ECIES_decrypt(dctx->ec_encrypt_param, in, inlen, out, outlen, ec_key)) {
            ECerr(EC_F_PKEY_EC_DECRYPT, EC_R_ECIES_DECRYPT_FAILED);
            return 0;
        }
        break;

    default:
        ECerr(EC_F_PKEY_EC_DECRYPT, EC_R_INVALID_ENC_TYPE);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_EC
static int sdt_sdf_pkey_ec_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                          size_t *keylen)
{
    int ret;
    size_t outlen;
    const EC_POINT *pubkey = NULL;
    EC_KEY *eckey;
    SDT_SDF_EC_PKEY_CTX *dctx = ctx->data;
    if (!ctx->pkey || !ctx->peerkey) {
        ECerr(EC_F_PKEY_EC_DERIVE, EC_R_KEYS_NOT_SET);
        return 0;
    }

    eckey = dctx->co_key ? dctx->co_key : ctx->pkey->pkey.ec;

    if (!key) {
        const EC_GROUP *group;
        group = EC_KEY_get0_group(eckey);
        *keylen = (EC_GROUP_get_degree(group) + 7) / 8;
        return 1;
    }
    pubkey = EC_KEY_get0_public_key(ctx->peerkey->pkey.ec);

    /*
     * NB: unlike PKCS#3 DH, if *outlen is less than maximum size this is not
     * an error, the result is truncated.
     */

    outlen = *keylen;

#ifndef OPENSSL_NO_SM2

/*
    if (dctx->ec_scheme == NID_sm_scheme)
        ret = SM2_compute_key(key, outlen, pubkey, eckey, 0);
    else
*/
#endif

    ret = ECDH_compute_key(key, outlen, pubkey, eckey, 0);	//note, KDF = 0; added by bruce
    if (ret <= 0)
        return 0;
    *keylen = ret;
    return 1;
}

static int sdt_sdf_pkey_ec_kdf_derive(EVP_PKEY_CTX *ctx,
                              unsigned char *key, size_t *keylen)
{
    SDT_SDF_EC_PKEY_CTX *dctx = ctx->data;
    unsigned char *ktmp = NULL;
    size_t ktmplen;
    int rv = 0;
    if (dctx->kdf_type == EVP_PKEY_ECDH_KDF_NONE)
        return sdt_sdf_pkey_ec_derive(ctx, key, keylen);
    if (!key) {
        *keylen = dctx->kdf_outlen;
        return 1;
    }
    if (*keylen != dctx->kdf_outlen)
        return 0;
    if (!sdt_sdf_pkey_ec_derive(ctx, NULL, &ktmplen))
        return 0;
    ktmp = OPENSSL_malloc(ktmplen);
    if (ktmp == NULL)
        return 0;
    if (!sdt_sdf_pkey_ec_derive(ctx, ktmp, &ktmplen))
        goto err;
    /* Do KDF stuff */
    if (!ECDH_KDF_X9_62(key, *keylen, ktmp, ktmplen,
                        dctx->kdf_ukm, dctx->kdf_ukmlen, dctx->kdf_md))
        goto err;
    rv = 1;

 err:
    OPENSSL_clear_free(ktmp, ktmplen);
    return rv;
}
#endif

static int sdt_sdf_pkey_ec_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    SDT_SDF_EC_PKEY_CTX *dctx = ctx->data;
    EC_GROUP *group;
    switch (type) {
    case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
        group = EC_GROUP_new_by_curve_name(p1);
        if (group == NULL) {
            ECerr(EC_F_PKEY_EC_CTRL, EC_R_INVALID_CURVE);
            return 0;
        }
        EC_GROUP_free(dctx->gen_group);
        dctx->gen_group = group;
        return 1;

    case EVP_PKEY_CTRL_EC_PARAM_ENC:
        if (!dctx->gen_group) {
            ECerr(EC_F_PKEY_EC_CTRL, EC_R_NO_PARAMETERS_SET);
            return 0;
        }
        EC_GROUP_set_asn1_flag(dctx->gen_group, p1);
        return 1;

#ifndef OPENSSL_NO_EC
    case EVP_PKEY_CTRL_EC_ECDH_COFACTOR:
        if (p1 == -2) {
            if (dctx->cofactor_mode != -1)
                return dctx->cofactor_mode;
            else {
                EC_KEY *ec_key = ctx->pkey->pkey.ec;
                return EC_KEY_get_flags(ec_key) & EC_FLAG_COFACTOR_ECDH ? 1 :
                    0;
            }
        } else if (p1 < -1 || p1 > 1)
            return -2;
        dctx->cofactor_mode = p1;
        if (p1 != -1) {
            EC_KEY *ec_key = ctx->pkey->pkey.ec;
            if (!ec_key->group)
                return -2;
            /* If cofactor is 1 cofactor mode does nothing */
            if (BN_is_one(ec_key->group->cofactor))
                return 1;
            if (!dctx->co_key) {
                dctx->co_key = EC_KEY_dup(ec_key);
                if (!dctx->co_key)
                    return 0;
            }
            if (p1)
                EC_KEY_set_flags(dctx->co_key, EC_FLAG_COFACTOR_ECDH);
            else
                EC_KEY_clear_flags(dctx->co_key, EC_FLAG_COFACTOR_ECDH);
        } else {
            EC_KEY_free(dctx->co_key);
            dctx->co_key = NULL;
        }
        return 1;
#endif

    case EVP_PKEY_CTRL_EC_KDF_TYPE:
        if (p1 == -2)
            return dctx->kdf_type;
        if (p1 != EVP_PKEY_ECDH_KDF_NONE && p1 != EVP_PKEY_ECDH_KDF_X9_62)
            return -2;
        dctx->kdf_type = p1;
        return 1;

#ifndef OPENSSL_NO_SM2
    case EVP_PKEY_CTRL_EC_SCHEME:
        if (p1 == -2) {
            return dctx->ec_scheme;
        }
        if (p1 != NID_secg_scheme && p1 != NID_sm_scheme) {
            ECerr(EC_F_PKEY_EC_CTRL, EC_R_INVALID_EC_SCHEME);
            return 0;
        }
        dctx->ec_scheme = p1;
# ifdef SM2_DEBUG
        fprintf(stderr, "[SM2_DEBUG] EVP_PKEY_CTX_set_ec_scheme(%s)\n",
            p1 == NID_secg_scheme ? "NID_secg_scheme" : "NID_sm_scheme");
# endif
        return 1;

    case EVP_PKEY_CTRL_SIGNER_ID:
        if (!p2 || !strlen((char *)p2) || strlen((char *)p2) > SM2_MAX_ID_LENGTH) {
            ECerr(EC_F_PKEY_EC_CTRL, EC_R_INVALID_SIGNER_ID);
            return 0;
        } else {
            char *id = NULL;
            if (!(id = OPENSSL_strdup((char *)p2))) {
                ECerr(EC_F_PKEY_EC_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            if (dctx->signer_id)
                OPENSSL_free(dctx->signer_id);
            dctx->signer_id = id;
            if (dctx->ec_scheme == NID_sm_scheme) {
                EC_KEY *ec_key = ctx->pkey->pkey.ec;
                unsigned char zid[SM3_DIGEST_LENGTH];
                size_t zidlen = SM3_DIGEST_LENGTH;
                if (!SM2_compute_id_digest(EVP_sm3(), dctx->signer_id,
                    strlen(dctx->signer_id), zid, &zidlen, ec_key)) {
                    ECerr(EC_F_PKEY_EC_CTRL, ERR_R_SM2_LIB);
                    return 0;
                }
                if (!dctx->signer_zid) {
                    if (!(dctx->signer_zid = OPENSSL_malloc(zidlen))) {
                        ECerr(EC_F_PKEY_EC_CTRL, ERR_R_MALLOC_FAILURE);
                        return 0;
                    }
                }
                memcpy(dctx->signer_zid, zid, zidlen);
# ifdef SM2_DEBUG
                fprintf(stderr, "[SM2_DEBUG] EVP_PKEY_CTX_set_signer_id(\"%s\")\n", id);
# endif
            }
        }
        return 1;

    case EVP_PKEY_CTRL_GET_SIGNER_ID:
        *(const char **)p2 = dctx->signer_id;
        return 1;

    case EVP_PKEY_CTRL_GET_SIGNER_ZID:
        if (dctx->ec_scheme != NID_sm_scheme) {
            *(const unsigned char **)p2 = NULL;
            return -2;
        }
        if (!dctx->signer_zid) {
            EC_KEY *ec_key = ctx->pkey->pkey.ec;
            unsigned char *zid;
            size_t zidlen = SM3_DIGEST_LENGTH;
            if (!(zid = OPENSSL_malloc(zidlen))) {
                ECerr(EC_F_PKEY_EC_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            if (!SM2_compute_id_digest(EVP_sm3(), SM2_DEFAULT_ID,
                SM2_DEFAULT_ID_LENGTH, zid, &zidlen, ec_key)) {
                ECerr(EC_F_PKEY_EC_CTRL, ERR_R_SM2_LIB);
                OPENSSL_free(zid);
                return 0;
            }
            dctx->signer_zid = zid;
# ifdef SM2_DEBUG
            fprintf(stderr, "[SM2_DEBUG] EVP_PKEY_CTX_get_signer_zid() "
                "init zid with default id\n");
# endif
        }
        *(const unsigned char **)p2 = dctx->signer_zid;
        return 1;

    case EVP_PKEY_CTRL_EC_ENCRYPT_PARAM:
        if (p1 == -2) {
            return dctx->ec_encrypt_param;
        }
        dctx->ec_encrypt_param = p1;
        return 1;
#endif

    case EVP_PKEY_CTRL_EC_KDF_MD:
        dctx->kdf_md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_EC_KDF_MD:
        *(const EVP_MD **)p2 = dctx->kdf_md;
        return 1;

    case EVP_PKEY_CTRL_EC_KDF_OUTLEN:
        if (p1 <= 0)
            return -2;
        dctx->kdf_outlen = (size_t)p1;
        return 1;

    case EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN:
        *(int *)p2 = dctx->kdf_outlen;
        return 1;

    case EVP_PKEY_CTRL_EC_KDF_UKM:
        OPENSSL_free(dctx->kdf_ukm);
        dctx->kdf_ukm = p2;
        if (p2)
            dctx->kdf_ukmlen = p1;
        else
            dctx->kdf_ukmlen = 0;
        return 1;

    case EVP_PKEY_CTRL_GET_EC_KDF_UKM:
        *(unsigned char **)p2 = dctx->kdf_ukm;
        return dctx->kdf_ukmlen;

    case EVP_PKEY_CTRL_MD:
        if (EVP_MD_type((const EVP_MD *)p2) != NID_sha1 &&
#ifndef OPENSSL_NO_SM3
            EVP_MD_type((const EVP_MD *)p2) != NID_sm3 &&
#endif
            EVP_MD_type((const EVP_MD *)p2) != NID_ecdsa_with_SHA1 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha224 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha256 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha384 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha512) {
            ECerr(EC_F_PKEY_EC_CTRL, EC_R_INVALID_DIGEST_TYPE);
            return 0;
        }
        dctx->md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_MD:
        *(const EVP_MD **)p2 = dctx->md;
        return 1;

    case EVP_PKEY_CTRL_PEER_KEY:
        /* Default behaviour is OK */
    case EVP_PKEY_CTRL_DIGESTINIT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
    case EVP_PKEY_CTRL_CMS_SIGN:
        return 1;

    default:
        return -2;

    }

}

static int sdt_sdf_pkey_ec_ctrl_str(EVP_PKEY_CTX *ctx,
                            const char *type, const char *value)
{
    if (strcmp(type, "ec_paramgen_curve") == 0) {
        int nid;
        nid = EC_curve_nist2nid(value);
        if (nid == NID_undef)
            nid = OBJ_sn2nid(value);
        if (nid == NID_undef)
            nid = OBJ_ln2nid(value);
        if (nid == NID_undef) {
            ECerr(EC_F_PKEY_EC_CTRL_STR, EC_R_INVALID_CURVE);
            return 0;
        }
        return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
#ifndef OPENSSL_NO_SM2
    } else if (!strcmp(type, "ec_scheme")) {
        int scheme;
        if (!strcmp(value, "secg"))
            scheme = NID_secg_scheme;
        else if (!strcmp(value, "sm2"))
            scheme = NID_sm_scheme;
        else
            return -2;
        return EVP_PKEY_CTX_set_ec_scheme(ctx, scheme);
    } else if (!strcmp(type, "signer_id")) {
        return EVP_PKEY_CTX_set_signer_id(ctx, value);
    } else if (!strcmp(type, "ec_encrypt_param")) {
        int encrypt_param;
        if (!(encrypt_param = OBJ_txt2nid(value))) {
            ECerr(EC_F_PKEY_EC_CTRL_STR, EC_R_INVALID_EC_ENCRYPT_PARAM);
            return 0;
        }
        return EVP_PKEY_CTX_set_ec_encrypt_param(ctx, encrypt_param);
#endif
    } else if (strcmp(type, "ec_param_enc") == 0) {
        int param_enc;
        if (strcmp(value, "explicit") == 0)
            param_enc = 0;
        else if (strcmp(value, "named_curve") == 0)
            param_enc = OPENSSL_EC_NAMED_CURVE;
        else
            return -2;
        return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
    } else if (strcmp(type, "ecdh_kdf_md") == 0) {
        const EVP_MD *md;
        if ((md = EVP_get_digestbyname(value)) == NULL) {
            ECerr(EC_F_PKEY_EC_CTRL_STR, EC_R_INVALID_DIGEST);
            return 0;
        }
        return EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md);
    } else if (strcmp(type, "ecdh_cofactor_mode") == 0) {
        int co_mode;
        co_mode = atoi(value);
        return EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, co_mode);
    }

    return -2;
}

const EVP_PKEY_METHOD sdt_sdf_ec_pkey_meth = {
    EVP_PKEY_EC,
    0,
    sdt_sdf_pkey_ec_init,
    sdt_sdf_pkey_ec_copy,
    sdt_sdf_pkey_ec_cleanup,

    0,
    sdt_sdf_pkey_ec_paramgen,

    0,
    sdt_sdf_pkey_ec_keygen,

    0,
    sdt_sdf_pkey_ec_sign,

    0,
    sdt_sdf_pkey_ec_verify,

    0, 0,

    0, 0, 0, 0,

    0,
    sdt_sdf_pkey_ec_encrypt,

    0,
    sdt_sdf_pkey_ec_decrypt,

    0,
    sdt_sdf_pkey_ec_kdf_derive,

    sdt_sdf_pkey_ec_ctrl,
    sdt_sdf_pkey_ec_ctrl_str
};

static int sdt_sdf_pkey_meths(ENGINE * e, EVP_PKEY_METHOD ** pmeth,
                                      const int **nids, int nid)
{
    static int sdt_sdf_pkey_nids[] = {
    	EVP_PKEY_EC,
        0
    };
    if (!pmeth) {
        *nids = sdt_sdf_pkey_nids;
        return 1;
    }

    if (nid == EVP_PKEY_EC) {
        *pmeth = &sdt_sdf_ec_pkey_meth;
        return 1;
    }

    *pmeth = NULL;
    return 0;
}

#endif

/*----------------------------------- sm2, end ---------------------------------------*/


/*----------------------------------- sm3, begin ---------------------------------------*/

typedef struct sdt_sdf_sm3_st {
	SGD_HANDLE session_sm3;
} SDT_SDF_SM3_CTX;

static int sdt_sdf_sm3_init(EVP_MD_CTX *ctx)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx)) {
		return 0;
	}
	SDT_SDF_SM3_CTX* sm3_ctx = (SDT_SDF_SM3_CTX *)EVP_MD_CTX_md_data(ctx);
	if(SDR_OK!=SDF_OpenSession(device_handle, &(sm3_ctx->session_sm3)))
	{
		printf("open session failed\n");
		return 0;
	}
	if(SDR_OK!=SDF_HashInit(sm3_ctx->session_sm3, SGD_SM3, NULL, NULL, 0))
	{
		printf("hash init failed\n");
		return 0;
	}

	return 1;
}

static int sdt_sdf_sm3_update(EVP_MD_CTX *ctx, const void *in, size_t inlen)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx) || !in) {
		return 0;
	}

	SDT_SDF_SM3_CTX* sm3_ctx = (SDT_SDF_SM3_CTX *)EVP_MD_CTX_md_data(ctx);
	if(SDR_OK!=SDF_HashUpdate(sm3_ctx->session_sm3, (unsigned char *)in, inlen))
	{
		printf("hash update failed\n");
		return 0;
	}

	return 1;
}

static int sdt_sdf_sm3_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx) || !md) {
		return 0;
	}

	SDT_SDF_SM3_CTX* sm3_ctx = (SDT_SDF_SM3_CTX *)EVP_MD_CTX_md_data(ctx);
	unsigned int nOutlen;
	if(SDR_OK!= SDF_HashFinal(sm3_ctx->session_sm3, md, &nOutlen))
	{
		printf("hash update failed\n");
		return 0;
	}
	if(nOutlen != SM3_DIGEST_LENGTH)
	{
		printf("hash update len do not match SM3_DIGEST_LENGTH\n");
		return 0;
	}

	SDF_CloseSession(sm3_ctx->session_sm3);
	sm3_ctx->session_sm3 = NULL;
	return 1;
}


static const EVP_MD sdt_sdf_sm3_md = {
		NID_sm3,
		NID_sm2sign_with_sm3,
		SM3_DIGEST_LENGTH,
		EVP_MD_FLAG_ONESHOT,
		sdt_sdf_sm3_init,
		sdt_sdf_sm3_update,
		sdt_sdf_sm3_final,
		NULL,
		NULL,
		SM3_BLOCK_SIZE,
		sizeof(EVP_MD *) + sizeof(SDT_SDF_SM3_CTX),
};

#if 0
static int sdt_sdf_sha256_init(EVP_MD_CTX *ctx)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx)) {
		return 0;
	}
//	sm3_init(EVP_MD_CTX_md_data(ctx));
	SDT_SDF_SM3_CTX* sm3_ctx = (SDT_SDF_SM3_CTX *)EVP_MD_CTX_md_data(ctx);
	printf("sdt_sdf_sha256_init,flags=0x%0x\n", EVP_MD_CTX_test_flags(ctx, 0xffff));
	if(SDR_OK!=SDF_OpenSession(device_handle, &(sm3_ctx->session_sm3)))
	{
		printf("open session failed\n");
		sm3_ctx->init_ok = 0;
		return 0;
	}
	if(SDR_OK!=SDF_HashInit(sm3_ctx->session_sm3, SGD_SHA256, NULL, NULL, 0))
	{
		printf("hash init failed\n");
		sm3_ctx->init_ok = 0;
		return 0;
	}
	return 1;
}

static int sdt_sdf_sha256_update(EVP_MD_CTX *ctx, const void *in, size_t inlen)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx) || !in) {
		return 0;
	}
//	sm3_update(EVP_MD_CTX_md_data(ctx), in, inlen);
	SDT_SDF_SM3_CTX* sm3_ctx = (SDT_SDF_SM3_CTX *)EVP_MD_CTX_md_data(ctx);
	printf("sdt_sdf_sha256_update,flags=0x%0x\n", EVP_MD_CTX_test_flags(ctx, 0xffff));

	if(SDR_OK!=SDF_HashUpdate(sm3_ctx->session_sm3, (unsigned char *)in, inlen))
	{
		printf("hash update failed\n");
		return 0;
	}

//	EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_UPDATED);
	return 1;
}

static int sdt_sdf_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx) || !md) {
		return 0;
	}
//	sm3_final(EVP_MD_CTX_md_data(ctx), md);
	SDT_SDF_SM3_CTX* sm3_ctx = (SDT_SDF_SM3_CTX *)EVP_MD_CTX_md_data(ctx);
	unsigned int nOutlen;
	printf("sdt_sdf_sha256_final,flags=0x%0x\n", EVP_MD_CTX_test_flags(ctx, 0xffff));
	if(SDR_OK!= SDF_HashFinal(sm3_ctx->session_sm3, md, &nOutlen))
	{
		printf("hash update failed\n");
		return 0;
	}
	if(nOutlen != SM3_DIGEST_LENGTH)
	{
		printf("hash update len do not match sha256_DIGEST_LENGTH\n");
		return 0;
	}

	SDF_CloseSession(sm3_ctx->session_sm3);

	sm3_ctx->session_sm3 = NULL;
	return 1;
}


static const EVP_MD sdt_sdf_sha256_md = {
    NID_sha256,
    NID_sha256WithRSAEncryption,
    SHA256_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
	sdt_sdf_sha256_init,
	sdt_sdf_sha256_update,
	sdt_sdf_sha256_final,
    NULL,
    NULL,
    SHA256_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SDT_SDF_SM3_CTX),
};
#endif

static const int sdt_sdf_digest_nids[] = {
    NID_sm3,
//    NID_sha256,
    0
};
static int sdt_sdf_sm3_engine_digest(ENGINE *e, const EVP_MD **digest,
		const int **nids, int nid) {
	int ok = 1;
	if (!digest) {
		*nids = sdt_sdf_digest_nids;
		return (sizeof(sdt_sdf_digest_nids)) / sizeof(sdt_sdf_digest_nids[0]);
	}
	if (nid == NID_sm3) {
		*digest = &sdt_sdf_sm3_md;
	}
//	if (nid == NID_sha256) {
//		*digest = &sdt_sdf_sha256_md;
//	}
	else {
		ok = 0;
		*digest = NULL;
	}
	return ok;
}
/*----------------------------------- sm3, end ---------------------------------------*/


/*----------------------------------- sm4, begin ---------------------------------------*/
typedef struct {
	SGD_HANDLE session_sm4;
	SGD_HANDLE hKeyHandle;
	int mode;
	int enc;
	unsigned char* Iv;
} EVP_SDT_SDF_SMS4_KEY;


static int sdt_sdf_sms4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	int i, mode,rv;
//	unsigned char sdt_sdf_key[SMS4_KEY_LENGTH] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
	EVP_SDT_SDF_SMS4_KEY *sm4_ctx = EVP_C_DATA(EVP_SDT_SDF_SMS4_KEY, ctx);
	sm4_ctx->enc = enc;

  	if(SDR_OK!=(rv=SDF_OpenSession(device_handle, &(sm4_ctx->session_sm4))))
  	{
  		printf("open session failed, error code=[0x%08x]\n",rv);
  		return 0;
  	}
  	OPENSSL_buf2hexstr(key, SMS4_KEY_LENGTH);
//  	for(i = 0; i < SMS4_KEY_LENGTH; i++)
//  	{
//  		printf("0x%02x ", key[i]);
//  	}
//  	printf("\nkey len = %d\n", strlen(key));

//  	memset(sdt_sdf_key, 0, sizeof(sdt_sdf_key));
//  	memcpy(sdt_sdf_key, key, SMS4_KEY_LENGTH);

	rv = SDF_ImportKey(sm4_ctx->session_sm4, key, SMS4_KEY_LENGTH, &(sm4_ctx->hKeyHandle));
	if(rv != SDR_OK)
	{
		printf("Import key error, errorcode=[0x%08x]\n", rv);
		return 0;
	}
//	printf("sdt sdf sm4 init key success\n");
	return 1;
}

static int sdt_sdf_sms4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	int rv;
	unsigned int  outDataLen;
	EVP_SDT_SDF_SMS4_KEY *sm4_ctx = (EVP_SDT_SDF_SMS4_KEY *)ctx->cipher_data;
	sm4_ctx->Iv = (unsigned char *)EVP_CIPHER_CTX_iv(ctx);
	printf("sm4_ecb input len = %d\n", len);
	if(sm4_ctx->enc)
	{
		rv = SDF_Encrypt(sm4_ctx->session_sm4, sm4_ctx->hKeyHandle, SGD_SM4_ECB, sm4_ctx->Iv, (unsigned char *)in, len, out, &outDataLen);
		if(rv != SDR_OK)
		{
			printf("encrypt error，error[0x%08x]\n", rv);
			return 0;
		}
		printf("encrypt success\n");
	}
	else
	{
		rv = SDF_Decrypt(sm4_ctx->session_sm4, sm4_ctx->hKeyHandle, SGD_SM4_ECB, sm4_ctx->Iv, (unsigned char *)in, len, out, &outDataLen);
		if(rv != SDR_OK)
		{
			printf("encrypt/decypt error，error[0x%08x]\n", rv);
			return 0;
		}
		printf("decrypt success\n");
	}

	return 1;
}

static int sdt_sdf_sms4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	int rv;
	unsigned int  outDataLen;
	EVP_SDT_SDF_SMS4_KEY *sm4_ctx = (EVP_SDT_SDF_SMS4_KEY *)ctx->cipher_data;
	sm4_ctx->Iv = (unsigned char *)EVP_CIPHER_CTX_iv(ctx);
//	printf("sm4_cbc input len = %d\n", len);
	if(sm4_ctx->enc)
	{
		rv = SDF_Encrypt(sm4_ctx->session_sm4, sm4_ctx->hKeyHandle, SGD_SM4_CBC, sm4_ctx->Iv, (unsigned char *)in, len, out, &outDataLen);
		if(rv != SDR_OK)
		{
			printf("encrypt error，error[0x%08x]\n", rv);
			return 0;
		}
//		printf("encrypt success\n");
	}
	else
	{
		rv = SDF_Decrypt(sm4_ctx->session_sm4, sm4_ctx->hKeyHandle, SGD_SM4_CBC, sm4_ctx->Iv, (unsigned char *)in, len, out, &outDataLen);
		if(rv != SDR_OK)
		{
			printf("encrypt/decypt error，error[0x%08x]\n", rv);
			return 0;
		}
//		printf("decrypt success\n");
	}

	return 1;
}

static int sdt_sdf_sms4_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	int rv;
	unsigned int  outDataLen;
	EVP_SDT_SDF_SMS4_KEY *sm4_ctx = (EVP_SDT_SDF_SMS4_KEY *)ctx->cipher_data;
	sm4_ctx->Iv = (unsigned char *)EVP_CIPHER_CTX_iv(ctx);
	printf("sm4_ofb input len = %d\n", len);
	if(sm4_ctx->enc)
	{
		rv = SDF_Encrypt(sm4_ctx->session_sm4, sm4_ctx->hKeyHandle, SGD_SM4_OFB, sm4_ctx->Iv, (unsigned char *)in, len, out, &outDataLen);
		if(rv != SDR_OK)
		{
			printf("encrypt error，error[0x%08x]\n", rv);
			return 0;
		}
		printf("encrypt success\n");
	}
	else
	{
		rv = SDF_Decrypt(sm4_ctx->session_sm4, sm4_ctx->hKeyHandle, SGD_SM4_OFB, sm4_ctx->Iv, (unsigned char *)in, len, out, &outDataLen);
		if(rv != SDR_OK)
		{
			printf("encrypt/decypt error，error[0x%08x]\n", rv);
			return 0;
		}
		printf("decrypt success\n");
	}

	return 1;
}



static int sdt_sdf_sms4_cleanup(EVP_CIPHER_CTX *ctx)
{
	int rv;
	EVP_SDT_SDF_SMS4_KEY *sm4_ctx = (EVP_SDT_SDF_SMS4_KEY *)ctx->cipher_data;
	if(SDR_OK!=(rv=SDF_DestroyKey(sm4_ctx->session_sm4, sm4_ctx->hKeyHandle)))
	{
		printf("DestroyKey failed, error code=[0x%08x]\n",rv);
		return 0;
	}

	if(SDR_OK!=(rv=SDF_CloseSession(sm4_ctx->session_sm4)))
	{
		printf("CloseSession failed, error code=[0x%08x]\n",rv);
		return 0;
	}
//	printf("sdt_sdf_sms4 cleanup\n");
	return 1;
}

const EVP_CIPHER sdt_sdf_sms4_ecb = {
	NID_sms4_ecb,
	16,
	SMS4_KEY_LENGTH,
	SMS4_IV_LENGTH,
	EVP_CIPH_ECB_MODE,
	sdt_sdf_sms4_init_key,
	sdt_sdf_sms4_ecb_cipher,
	sdt_sdf_sms4_cleanup,
	sizeof(EVP_SDT_SDF_SMS4_KEY),
	NULL,NULL,NULL,NULL,
};

const EVP_CIPHER sdt_sdf_sms4_cbc = {
	NID_sms4_cbc,
	16,
	SMS4_KEY_LENGTH,
	SMS4_IV_LENGTH,
	EVP_CIPH_CBC_MODE,
	sdt_sdf_sms4_init_key,
	sdt_sdf_sms4_cbc_cipher,
	sdt_sdf_sms4_cleanup,
	sizeof(EVP_SDT_SDF_SMS4_KEY),
	NULL,NULL,NULL,NULL,
};

const EVP_CIPHER sdt_sdf_sms4_ofb = {
	NID_sms4_ofb128,
	16,
	SMS4_KEY_LENGTH,
	SMS4_IV_LENGTH,
	EVP_CIPH_OFB_MODE,
	sdt_sdf_sms4_init_key,
	sdt_sdf_sms4_ofb_cipher,
	sdt_sdf_sms4_cleanup,
	sizeof(EVP_SDT_SDF_SMS4_KEY),
	NULL,NULL,NULL,NULL,
};


static const int gmi_cipher_nids[] = {
    NID_sms4_ecb,
    NID_sms4_cbc,
    NID_sms4_ofb128,
    0
};


static int sdt_sdf_sm4_cipher_nids_num = ((sizeof(gmi_cipher_nids) - 1)  /
                                      sizeof(gmi_cipher_nids[0]));

static int sdt_sdf_sm4_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    /* No specific cipher => return a list of supported nids ... */
    if (!cipher) {
        *nids = gmi_cipher_nids;
        return sdt_sdf_sm4_cipher_nids_num;
    }

    /* ... or the requested "cipher" otherwise */
    switch (nid)
    {
    case NID_sms4_ecb:
        *cipher = &sdt_sdf_sms4_ecb;
        break;
    case NID_sms4_cbc:
        *cipher = &sdt_sdf_sms4_cbc;
        break;
    case NID_sms4_ofb128:
        *cipher = &sdt_sdf_sms4_ofb;
        break;
    default:
        /* Sorry, we don't support this NID */
        *cipher = NULL;
        return 0;
    }
    return 1;
}
/*----------------------------------- sm4, end ---------------------------------------*/

/*----------------------------------- random, begin ---------------------------------------*/

static int sdt_sdf_rand_bytes(unsigned char *buf, int num)
{
	int rv;
	SGD_HANDLE session_rand;

	if(SDR_OK != (rv = SDF_OpenSession(device_handle, &(session_rand))))
	{
		printf("open session failed, error code=[0x%08x]\n",rv);
		return 0;
	}

	rv = SDF_GenerateRandom(session_rand, num, buf);
	if(rv != SDR_OK)
	{
		printf("SDF_GenerateRandom, error code=[0x%08x]\n",rv);
		return 0;
	}

	if(SDR_OK != (rv = SDF_CloseSession(session_rand)))
	{
		printf("CloseSession failed, error code=[0x%08x]\n",rv);
		return 0;
	}

//	printf("using sdt sdf rand\n");
	return 1;
}

static int sdt_sdf_rand_status(void)
{
    return 1;
}

static RAND_METHOD sdt_sdf_rand = {
    /* "CHIL RAND method", */
    NULL,
    sdt_sdf_rand_bytes,
    NULL,
    NULL,
    sdt_sdf_rand_bytes,
    sdt_sdf_rand_status,
};
/*----------------------------------- random, end ---------------------------------------*/
static int bind_helper(ENGINE * e, const char *id)
{
	ERR_load_SDF_strings();

    if (!ENGINE_set_id(e, engine_sdt_sdf_id)
        || !ENGINE_set_name(e, engine_sdt_sdf_name)
        || !ENGINE_set_init_function(e, sdt_sdf_engine_init)
        || !ENGINE_set_RAND(e, &sdt_sdf_rand)
        || !ENGINE_set_EC(e, EC_KEY_GmSSL_SDT_SDF())
        || !ENGINE_set_pkey_meths(e, sdt_sdf_pkey_meths)
        || !ENGINE_set_digests(e, sdt_sdf_sm3_engine_digest)
        || !ENGINE_set_ciphers(e, sdt_sdf_sm4_ciphers)
        || !ENGINE_set_finish_function(e, sdt_sdf_finish)
        || !ENGINE_set_destroy_function(e, sdt_sdf_destroy)){

       printf("sdt_sdf engine bind and init failed\n");
        return 0;
    }


    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper);
