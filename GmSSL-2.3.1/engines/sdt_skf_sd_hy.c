/*
 * sdt_skf.c
 *
 *  Created on: Aug 31, 2018
 *      Author: bruce
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/sgd.h>
#include <openssl/skf.h>
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
#include <openssl/crypto.h>
#include <pthread.h>

#define SDT_SKF_SM2_PKEY			1

/* SMS4算法ECB加密模式 */
#define SGD_SMS4_ECB 0x00000401

/* SMS4算法CBC加密模式 */
#define SGD_SMS4_CBC 0x00000402

#define EC_KEY_METHOD_SM2	0x02
/* Engine Id and Name */
static const char *engine_sdt_skf_sd_hy_id = "sdt_skf_sd_hy";
static const char *engine_sdt_skf_sd_hy_name = "sdt_skf_sd_hy engine by bruce";

#if 1
DEVHANDLE hd_sd_hy_ssl = NULL;
int get_hd_ssl = 0;
#else
extern DEVHANDLE hd_sd_hy_ssl;
extern int get_hd_ssl;
#endif
int Init_SDkey_ssl()
{
    CHAR szName[255] = "/media/mmcblk0/.stc08";
	ULONG skf_rv;
	BOOL bPresent = 1;
//	char szDevNameList[256] = {0};
	unsigned int pulSize = 0;
	DEVINFO dev_info;
//	skf_rv = SDT_Set_AndroidPath(szName);
//	if(skf_rv)
//	{
//		printf("==%s-%d===[ SDT_Set_AndroidPath err: %x.]===\n", __func__, __LINE__, skf_rv);
//		return skf_rv;
//	}
//
//	//枚举设备
//	skf_rv = SKF_EnumDev(bPresent, NULL, &pulSize);
//	if(skf_rv)
//	{
//		printf("==%s-%d===[ SKF_EnumDev err: %x.]===\n", __func__, __LINE__, skf_rv);
//		return skf_rv;
//	}
//	if(pulSize<=0)
//	{
//		printf("==%s-%d===[ SKF_EnumDev err: %x.]===\n", __func__, __LINE__, skf_rv);
//		return skf_rv;
//
//	}
//	skf_rv = SKF_EnumDev(bPresent, szDevNameList, &pulSize);
//	if(skf_rv)
//	{
//		printf("==%s-%d===[ SKF_EnumDev err: %x.]===\n", __func__, __LINE__, skf_rv);
//		return skf_rv;
//	}
//	printf("Dev Name List : %s\n",szDevNameList);

	char szDevNameList[256] = "/media/mmcblk0/.stc08";
	//连接设备
	skf_rv = SKF_ConnectDev(szDevNameList, &(hd_sd_hy_ssl));
	if(skf_rv)
	{
		printf("==%s-%d===[ SKF_ConnectDev err: %x.]===\n", __func__, __LINE__, skf_rv);
		return skf_rv;
	}

	//获取设备信息
//	skf_rv = SKF_GetDevInfo(hd_sd_hy_ssl,  &(dev_info));
//	if(skf_rv)
//	{
//		printf("==%s-%d===[ SKF_GetDevInfo err: %x.]===\n", __func__, __LINE__, skf_rv);
//		return skf_rv;
//	}
//
//	printf("Version:%c.%c\n",dev_info.Version.major,dev_info.Version.minor);
//	printf("Manufacturer:%s\n",dev_info.Manufacturer);
//	printf("Issuer:%s\n",dev_info.Issuer);
//	printf("Label:%s\n",dev_info.Label);
//	printf("SerialNumber:%s\n",dev_info.SerialNumber);
//	printf("HWVersion:%c.%c\n",dev_info.HWVersion.major,dev_info.HWVersion.minor);
//	printf("FirmwareVersion:%c.%c\n",dev_info.FirmwareVersion.major,dev_info.FirmwareVersion.minor);
//	printf("AlgSymCap:%0x\n",dev_info.AlgSymCap);
//	printf("AlgAsymCap:%0x\n",dev_info.AlgAsymCap);
//	printf("AlgHashCap:%0x\n",dev_info.AlgHashCap);
//	printf("DevAuthAlgId:%0x\n",dev_info.DevAuthAlgId);
//	printf("TotalSpace:%0x\n",dev_info.TotalSpace);
//	printf("FreeSpace:%0x\n",dev_info.FreeSpace);
//	printf("MaxECCBufferSize:%0x\n",dev_info.MaxECCBufferSize);
//	printf("MaxBufferSize:%0x\n",dev_info.MaxBufferSize);

	printf("--sdt skf sd_hy get handle ok--\n");
	get_hd_ssl = 1;
	return 0;
}

static int sdt_skf_sd_hy_engine_init(ENGINE *e)
{

	ERR_load_SKF_strings();
	if(SAR_OK !=SKF_LoadLibrary("/lib/libStcSkf.so", NULL))
	{
		printf("load sd_hy skf_library error\n");
		return 0;
	}
    if(get_hd_ssl == 0)
    {
		if(Init_SDkey_ssl() != 0)
		{
			printf("sdt skf sd_hy ssl handle init failed\n");
			return 0;
		}
    }
    else
    {
    	printf("sdt skf sd_hy ssl handle has already init ok\n");
    }
    ENGINE_set_ex_data(e, 1, (void*)(&get_hd_ssl));
    printf("get index 1 = %d\n", *((int*)(ENGINE_get_ex_data(e, 1))));
    ENGINE_set_ex_data(e, 2, (void*)hd_sd_hy_ssl);
    printf("get index 2 = 0x%08x\n", ENGINE_get_ex_data(e, 2));

	printf("SDT_SKF SD_hy engine init ok\n");
    return 1;
}


static int sdt_skf_sd_hy_finish(ENGINE *e)
{
	ENGINE_set_ex_data(e, 1, NULL);
	ENGINE_set_ex_data(e, 2, NULL);

	if(get_hd_ssl == 1 && hd_sd_hy_ssl != NULL)
	{
		SKF_DisConnectDev(hd_sd_hy_ssl);		//do not close hd_sd_hy_ssl, for reuse
		get_hd_ssl = 0;
		hd_sd_hy_ssl = NULL;
		printf("--close sdt skf hy handle--\n");
	}
	printf("close sdt skf hy SD_key device\n");
	SKF_UnloadLibrary();
	printf("sdt_skf_finish\n");
    return 1;
}


static int sdt_skf_sd_hy_destroy(ENGINE *e)
{
//	if(ENGINE_get_ex_data(e, 2) != NULL)
//		ENGINE_set_ex_data(e, 2, NULL);
//	if(ENGINE_get_ex_data(e, 1) != NULL)
//		ENGINE_set_ex_data(e, 1, NULL);

//	if(get_hd_ssl == 1 && hd_sd_hy_ssl != NULL)
//	{
//		SKF_DisConnectDev(hd_sd_hy_ssl);		//do not close hd_sd_hy_ssl, for reuse
//		get_hd_ssl = 0;
//		hd_sd_hy_ssl = NULL;
//		printf("--close sdt skf hy handle--\n");
//	}
//	printf("close sdt skf hy SD_key device\n");
//	SKF_UnloadLibrary();
	printf("sdt_skf_sd_hy_destroy\n");
    return 1;
}

#if 1
/*----------------------------------- sm2, begin ---------------------------------------*/
#if 1
//huashen skf sm2
typedef struct sdt_skf_sd_hy_sm2_st {
	HAPPLICATION app;
	HCONTAINER	con;
	ECCPUBLICKEYBLOB pubKey;
	ECCPRIVATEKEYBLOB priKey;
} SDT_SKF_SD_HY_SM2_CTX;


int sdt_skf_sd_hy_sm2_init(EC_KEY *key)
{
  	printf("sdt_skf_sd_hy_sm2_init\n");
  	return 1;
}

void sdt_skf_sd_hy_sm2_finish(EC_KEY *key)
{
	return;
}

#if 1
int sdt_skf_sd_hy_sm2_ec_key_gen(EC_KEY *eckey)
{

	int res = EC_KEY_GmSSL()->keygen(eckey);
	printf("gen sdt_skf ecc key pairs\n");
	return res;

//	int skf_rv;
//	SDT_SKF_SM2_CTX* sm2_ctx = eckey->data;
//
//	sm2_ctx->pubKey.BitLen=0;
//	memset(sm2_ctx->pubKey.XCoordinate,0,sizeof(sm2_ctx->pubKey.XCoordinate));
//	memset(sm2_ctx->pubKey.YCoordinate,0,sizeof(sm2_ctx->pubKey.YCoordinate));
//	skf_rv = SKF_GenECCKeyPair(sm2_ctx->con, SGD_SM2_1, &(sm2_ctx->pubKey));
//	if(skf_rv != SAR_OK)
//	{
//		printf("SKF_GenECCKeyPair error(0x%X)\r\n", skf_rv);
//		return 0;
//	}
//	printf("sm2 skf gen ecc pair success\n");
//	eckey = EC_KEY_new_from_ECCPUBLICKEYBLOB(&(sm2_ctx->pubKey));
//
////note, usbkey could not export the private key
////	ECCPRIVATEKEYBLOB_set_private_key(sm2_ctx->priKey, eckey->priv_key);
//	return 1;

}

int sdt_skf_sd_hy_ecdh_compute_key(unsigned char **psec, size_t *pseclen,
                          const EC_POINT *pub_key, const EC_KEY *ecdh)
{
	return EC_KEY_OpenSSL()->compute_key(psec, pseclen, pub_key, ecdh);
}

int sdt_skf_sd_hy_sm2_encrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{

//	return EC_KEY_GmSSL()->encrypt(type, in, inlen, out, outlen, ec_key);
	int skf_rv;
	SDT_SKF_SD_HY_SM2_CTX* sm2_ctx = ec_key->data;
	PECCCIPHERBLOB pCipherText;
	SM2CiphertextValue *cv;
	EC_KEY_get_ECCPUBLICKEYBLOB(ec_key, &(sm2_ctx->pubKey));
	skf_rv = SKF_ExtECCEncrypt(hd_sd_hy_ssl, &(sm2_ctx->pubKey), in, inlen, pCipherText);
	if(skf_rv != SAR_OK)
	{
		printf("pubkey encrypt error，错误码[0x%08x]\n", skf_rv);
		return 0;
	}

	cv = SM2CiphertextValue_new_from_ECCCIPHERBLOB(&pCipherText);
	*outlen = i2d_SM2CiphertextValue(cv, &out);
	SM2CiphertextValue_free(cv);

	printf("pubkey encrypt success--------------------------------------------\n");
	return 1;
}

int sdt_skf_sd_hy_sm2_decrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
//	return EC_KEY_GmSSL()->decrypt(type, in, inlen, out, outlen, ec_key);
	int skf_rv;
	SDT_SKF_SD_HY_SM2_CTX* sm2_ctx = ec_key->data;
	EC_KEY_get_ECCPRIVATEKEYBLOB(ec_key, &(sm2_ctx->priKey));

	PECCCIPHERBLOB pCipherText;
	SM2CiphertextValue *cv = d2i_SM2CiphertextValue(NULL, in, inlen);

	SM2CiphertextValue_get_ECCCIPHERBLOB(cv, &pCipherText);
	skf_rv = SKF_ExtECCDecrypt(hd_sd_hy_ssl, &(sm2_ctx->priKey), pCipherText, out, outlen);
	if(skf_rv != SDR_OK)
	{
		printf("privkey decrypt error，错误码[0x%08x]\n", skf_rv);
		return 0;
	}
	SM2CiphertextValue_free(cv);
	printf("privkey decrypt success-------------------------------------------\n");
	return 1;
}


int sdt_skf_sd_hy_sm2_set_private(EC_KEY *key, const BIGNUM *priv_key)
{
	return 1;
}

int sdt_skf_sd_hy_sm2_set_public(EC_KEY *key, const EC_POINT *pub_key)
{
	return 1;
}

ECDSA_SIG* sdt_skf_sd_hy_sm2_sign_sig(const unsigned char *dgst, int dlen,
                       const BIGNUM *in_kinv, const BIGNUM *in_r,
                       EC_KEY *eckey);

int sdt_skf_sd_hy_sm2_sign(int type, const unsigned char *dgst, int dlen, unsigned char
            *sig, unsigned int *siglen, const BIGNUM *kinv,
            const BIGNUM *r, EC_KEY *eckey)
{
//	return EC_KEY_GmSSL()->sign( type, dgst, dlen, sig, siglen, kinv, r, eckey);

	ECDSA_SIG *s;
	RAND_seed(dgst, dlen);

	if (!(s = sdt_skf_sd_hy_sm2_sign_sig(dgst, dlen, kinv, r, eckey))) {
		*siglen = 0;
		return 0;
	}
	*siglen = i2d_ECDSA_SIG(s, &sig);
	ECDSA_SIG_free(s);
	return 1;
}


int sdt_skf_sd_hy_sm2_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                  BIGNUM **rp)
{
	printf("sdt_skf_sm2_sign_setup\n");
	return EC_KEY_GmSSL()->sign_setup(eckey, ctx_in, kinvp, rp);
}

ECDSA_SIG* sdt_skf_sd_hy_sm2_sign_sig(const unsigned char *dgst, int dlen,
                       const BIGNUM *in_kinv, const BIGNUM *in_r,
                       EC_KEY *eckey)
{
	ECCSIGNATUREBLOB sigref;
	ECDSA_SIG *ret = NULL;
	ECCPRIVATEKEYBLOB priKey;
	ECCPUBLICKEYBLOB pubKey;

#if 0
	return EC_KEY_GmSSL()->sign_sig(dgst,  dlen, in_kinv, in_r, eckey);
#endif

	if(1 != EC_KEY_get_ECCPUBLICKEYBLOB(eckey, &pubKey))
	{
		printf("EC_KEY_get_ECCPUBLICKEYBLOB error\n");
		return 0;
	}
//	printf("sign get pubKey BitLen = %ld\n", pubKey.BitLen);
//	int i;
//	printf("pubKey.XCoordinate = \n");
//	for(i =0; i < 64; i++)
//	{
//		printf("0x%02x,",pubKey.XCoordinate[i]);
//	}
//	printf("\n");
//	printf("pubKey.YCoordinate = \n");
//	for(i =0; i < 64; i++)
//	{
//		printf("0x%02x,",pubKey.YCoordinate[i]);
//	}
//	printf("\n");


	if(1 != EC_KEY_get_ECCPRIVATEKEYBLOB(eckey, &priKey))
	{
		printf("EC_KEY_get_ECCPRIVATEKEYBLOB error\n");
		return NULL;
	}

//	printf("sign get priKey BitLen = %ld\n", priKey.BitLen);
//	printf("PrivateKey = \n");
//	for(i =0; i < 64; i++)
//	{
//		printf("0x%02x,",priKey.PrivateKey[i]);
//	}
//	printf("\n");

	int skf_rv;
	memset(&sigref, 0 , sizeof(ECCSIGNATUREBLOB));
	skf_rv = SKF_ExtECCSign(hd_sd_hy_ssl, &priKey, dgst, dlen, &sigref);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_ExtECCSign error, error = [0x%08x]\n", skf_rv);
		return NULL;
	}
	else
	{
		printf("SKF_ExtECCSign success\n");
//		int i;
//		printf("sign sigref = \n");
//		printf("sigref.r  = \n");
//		for(i =0; i < 64; i++)
//		{
//			printf("0x%02x ", sigref.r[i]);
//		}
//		printf("\n");
//		printf("sigref.s = \n");
//		for(i =0; i < 64; i++)
//		{
//			printf("0x%02x ", sigref.s[i]);
//		}
//		printf("\n");
//
		skf_rv = SKF_ExtECCVerify(hd_sd_hy_ssl, &pubKey, dgst, dlen, &sigref);
		if(skf_rv != SAR_OK)
		{
			printf("SKF_ExtECCSign and verify self test, error = [0x%08x]\n", skf_rv);
		}
		else
			printf("SKF_ExtECCSign and verify self test ok\n");
	}

	ret = ECDSA_SIG_new_from_ECCSIGNATUREBLOB(&sigref);
	if(ret == NULL)
	{
		printf("ECDSA_SIG_new_from_ECCSIGNATUREBLOB error\n");
		return NULL;
	}

	return ret;
}

int sdt_skf_sd_hy_sm2_verify(int type, const unsigned char *dgst, int dgstlen,
              const unsigned char *sig, int siglen, EC_KEY *ec_key)
{
//	return  EC_KEY_GmSSL()->verify(type, dgst, dgstlen, sig, siglen, ec_key);
//

	ECDSA_SIG *s;
	const unsigned char *p = sig;
	unsigned char *der = NULL;
	int derlen = -1;
	int ret = -1;

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

	ret = sdt_skf_sd_hy_sm2_verify_sig(dgst, dgstlen, s, ec_key);

err:
	if (derlen > 0) {
		OPENSSL_cleanse(der, derlen);
		OPENSSL_free(der);
	}

	ECDSA_SIG_free(s);
	return ret;
}


int sdt_skf_sd_hy_sm2_verify_sig(const unsigned char *dgst, int dgstlen,
                  const ECDSA_SIG *sig, EC_KEY *ec_key)
{

	ULONG skf_rv;
	ECCPUBLICKEYBLOB pubKey;
	ECCPRIVATEKEYBLOB priKey;
	ECCSIGNATUREBLOB sigref;
	int i;

#if 0
	return  EC_KEY_GmSSL()->verify_sig(dgst, dgstlen, sig, ec_key);
#endif


	if(1 != ECDSA_SIG_get_ECCSIGNATUREBLOB(sig, &sigref))
	{
		printf("ECDSA_SIG_get_ECCSIGNATUREBLOB error\n");
		return 0;
	}

//	printf("verify sigref = \n");
//	printf("sigref.s = \n");
//	for(i =0; i < 64; i++)
//	{
//		printf("0x%02x ", sigref.s[i]);
//	}
//	printf("\n");
//	printf("sigref.r  = \n");
//	for(i =0; i < 64; i++)
//	{
//		printf("0x%02x ", sigref.r[i]);
//	}
//	printf("\n");

	if(1 != EC_KEY_get_ECCPUBLICKEYBLOB(ec_key, &pubKey))
	{
		printf("EC_KEY_get_ECCPUBLICKEYBLOB error\n");
		return 0;
	}

//	printf("get pubKey BitLen = %ld\n", pubKey.BitLen);
////	int i;
//	printf("pubKey.XCoordinate = \n");
//	for(i =0; i < 64; i++)
//	{
//		printf("0x%02x ",pubKey.XCoordinate[i]);
//	}
//	printf("\n");
//	printf("pubKey.YCoordinate = \n");
//	for(i =0; i < 64; i++)
//	{
//		printf("0x%02x ",pubKey.YCoordinate[i]);
//	}
//	printf("\n");

	skf_rv = SKF_ExtECCVerify(hd_sd_hy_ssl, &pubKey, dgst, dgstlen, &sigref);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_ExtECCVerify error，eroor = [0x%08x]\n", skf_rv);
		return 0;
	}
	else
	{
		printf("SKF_ExtECCVerify success\n");
	}

	return 1;
}
#endif
static const EC_KEY_METHOD sdt_skf_sd_hy_ec_key_method = {
	"SDT_SKF EC_KEY method",
	0,
	sdt_skf_sd_hy_sm2_init,
	sdt_skf_sd_hy_sm2_finish,
	0,
	0,
//	sdt_skf_sd_hy_sm2_set_private,
//	sdt_skf_sd_hy_sm2_set_public,
	0,
	0,
	sdt_skf_sd_hy_sm2_ec_key_gen,
	sdt_skf_sd_hy_ecdh_compute_key,
	sdt_skf_sd_hy_sm2_sign,
	sdt_skf_sd_hy_sm2_sign_setup,
	sdt_skf_sd_hy_sm2_sign_sig,
	sdt_skf_sd_hy_sm2_verify,
	sdt_skf_sd_hy_sm2_verify_sig,
	sdt_skf_sd_hy_sm2_encrypt,
	NULL,
	sdt_skf_sd_hy_sm2_decrypt,
	NULL,
};

const EC_KEY_METHOD *EC_KEY_GmSSL_SDT_SKF_SD_HY(void)
{
//	return EC_KEY_GmSSL();
//	return EC_KEY_OpenSSL();
	return &sdt_skf_sd_hy_ec_key_method;
}

/*---------------------------------pkey method---------------------------------------------*/


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

    SDT_SKF_SM2_CTX* sm2_ctx;

#endif
} SDT_SKF_SD_HY_EC_PKEY_CTX;



static int sdt_skf_sd_hy_pkey_ec_init(EVP_PKEY_CTX *ctx)
{
	printf("sdt_skf_pkey_ec_init\n");

	SDT_SKF_SD_HY_EC_PKEY_CTX *dctx;

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

static int sdt_skf_sd_hy_pkey_ec_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{

	SDT_SKF_SD_HY_EC_PKEY_CTX *dctx, *sctx;
    if (!sdt_skf_sd_hy_pkey_ec_init(dst))
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

static void sdt_skf_sd_hy_pkey_ec_cleanup(EVP_PKEY_CTX *ctx)
{
	SDT_SKF_SD_HY_EC_PKEY_CTX *dctx = ctx->data;
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

static int sdt_skf_sd_hy_pkey_ec_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
//	return 1;
    EC_KEY *ec = NULL;
    SDT_SKF_SD_HY_EC_PKEY_CTX *dctx = ctx->data;
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


static int sdt_skf_sd_hy_pkey_ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec = NULL;
    SDT_SKF_SD_HY_EC_PKEY_CTX *dctx = ctx->data;
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

static int sdt_skf_sd_hy_pkey_ec_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    int ret, type;
    unsigned int sltmp;
    SDT_SKF_SD_HY_EC_PKEY_CTX *dctx = ctx->data;
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

#ifdef SDT_SKF_SM2_PKEY
//    	ret = ec->meth->sign(NID_undef, tbs, tbslen, sig, &sltmp, NULL, NULL, ec);    //changed by bruce, 1130
    	ret = sdt_skf_sd_hy_sm2_sign(NID_undef, tbs, tbslen, sig, &sltmp, NULL, NULL, ec);    //changed by bruce, 1210
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

static int sdt_skf_sd_hy_pkey_ec_verify(EVP_PKEY_CTX *ctx,
                          const unsigned char *sig, size_t siglen,
                          const unsigned char *tbs, size_t tbslen)
{
	int ret, type;
	SDT_SKF_SD_HY_EC_PKEY_CTX *dctx = ctx->data;
	EC_KEY *ec = ctx->pkey->pkey.ec;

	if (dctx->md)
		type = EVP_MD_type(dctx->md);
	else
		type = NID_sha1;
	printf("pkey_ec_verify, dctx->ec_scheme = %d\n", dctx->ec_scheme);
#ifndef OPENSSL_NO_SM2
	if (dctx->ec_scheme == NID_sm_scheme)
//		ret = SM2_verify(NID_undef, tbs, tbslen, sig, siglen, ec);
//		ret = ec->meth->verify(NID_undef, tbs, tbslen, sig, siglen, ec);    	//changed by bruce, 1130
#ifdef SDT_SKF_SM2_PKEY
//	ret = ec->meth->verify(NID_undef, tbs, tbslen, sig, siglen, ec);    		//changed by bruce, 1130
	ret = sdt_skf_sd_hy_sm2_verify(NID_undef, tbs, tbslen, sig, siglen, ec);    //changed by bruce, 1210
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

static int sdt_skf_sd_hy_pkey_ec_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen)
{
	SDT_SKF_SD_HY_EC_PKEY_CTX *dctx = ctx->data;
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

static int sdt_skf_sd_hy_pkey_ec_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen)
{
	SDT_SKF_SD_HY_EC_PKEY_CTX *dctx = ctx->data;
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
static int sdt_skf_sd_hy_pkey_ec_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                          size_t *keylen)
{
    int ret;
    size_t outlen;
    const EC_POINT *pubkey = NULL;
    EC_KEY *eckey;
    SDT_SKF_SD_HY_EC_PKEY_CTX *dctx = ctx->data;
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

    ret = ECDH_compute_key(key, outlen, pubkey, eckey, 0);
    if (ret <= 0)
        return 0;
    *keylen = ret;
    return 1;
}

static int sdt_skf_sd_hy_pkey_ec_kdf_derive(EVP_PKEY_CTX *ctx,
                              unsigned char *key, size_t *keylen)
{
	SDT_SKF_SD_HY_EC_PKEY_CTX *dctx = ctx->data;
    unsigned char *ktmp = NULL;
    size_t ktmplen;
    int rv = 0;
    if (dctx->kdf_type == EVP_PKEY_ECDH_KDF_NONE)
        return sdt_skf_sd_hy_pkey_ec_derive(ctx, key, keylen);
    if (!key) {
        *keylen = dctx->kdf_outlen;
        return 1;
    }
    if (*keylen != dctx->kdf_outlen)
        return 0;
    if (!sdt_skf_sd_hy_pkey_ec_derive(ctx, NULL, &ktmplen))
        return 0;
    ktmp = OPENSSL_malloc(ktmplen);
    if (ktmp == NULL)
        return 0;
    if (!sdt_skf_sd_hy_pkey_ec_derive(ctx, ktmp, &ktmplen))
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

static int sdt_skf_sd_hy_pkey_ec_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	SDT_SKF_SD_HY_EC_PKEY_CTX *dctx = ctx->data;
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

static int sdt_skf_sd_hy_pkey_ec_ctrl_str(EVP_PKEY_CTX *ctx,
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

const EVP_PKEY_METHOD sdt_skf_sd_hy_ec_pkey_meth = {
    EVP_PKEY_EC,
    0,
    sdt_skf_sd_hy_pkey_ec_init,
    sdt_skf_sd_hy_pkey_ec_copy,
    sdt_skf_sd_hy_pkey_ec_cleanup,

    0,
    sdt_skf_sd_hy_pkey_ec_paramgen,

    0,
    sdt_skf_sd_hy_pkey_ec_keygen,

    0,
    sdt_skf_sd_hy_pkey_ec_sign,

    0,
    sdt_skf_sd_hy_pkey_ec_verify,

    0, 0,

    0, 0, 0, 0,

    0,
    sdt_skf_sd_hy_pkey_ec_encrypt,

    0,
    sdt_skf_sd_hy_pkey_ec_decrypt,

    0,
    sdt_skf_sd_hy_pkey_ec_kdf_derive,

    sdt_skf_sd_hy_pkey_ec_ctrl,
    sdt_skf_sd_hy_pkey_ec_ctrl_str
};

static int sdt_skf_sd_hy_pkey_meths(ENGINE * e, EVP_PKEY_METHOD ** pmeth,
                                      const int **nids, int nid)
{
    static int sdt_skf_sd_hy_pkey_nids[] = {
    	EVP_PKEY_EC,
        0
    };
    if (!pmeth) {
        *nids = sdt_skf_sd_hy_pkey_nids;
        return 1;
    }

    if (nid == EVP_PKEY_EC) {
        *pmeth = &sdt_skf_sd_hy_ec_pkey_meth;
        return 1;
    }

    *pmeth = NULL;
    return 0;
}

#endif

/*----------------------------------- sm2, end ---------------------------------------*/


/*----------------------------------- sm3, begin ---------------------------------------*/

typedef struct sdt_skf_sd_hy_sm3_st {
	HANDLE phHash;
} sdt_skf_SD_HY_SM3_CTX;

static int sdt_skf_sd_hy_sm3_init(EVP_MD_CTX *ctx)
{
	ULONG skf_rv;
	if (!ctx || !EVP_MD_CTX_md_data(ctx))
	{
		return 0;
	}
	sdt_skf_SD_HY_SM3_CTX* sm3_ctx = (sdt_skf_SD_HY_SM3_CTX *)EVP_MD_CTX_md_data(ctx);

 	skf_rv = SKF_DigestInit(hd_sd_hy_ssl, SGD_SM3, NULL, NULL, 0, &(sm3_ctx->phHash));
	if(skf_rv != SAR_OK)
	{
		printf("SM3_HASH init error(0x%08x).\n",skf_rv);
		SKF_CloseHandle(sm3_ctx->phHash);
		return 0;
	}

	return 1;
}

static int sdt_skf_sd_hy_sm3_update(EVP_MD_CTX *ctx, const void *in, size_t inlen)
{
	ULONG skf_rv;
	if (!ctx || !EVP_MD_CTX_md_data(ctx) || !in) {
		return 0;
	}

	sdt_skf_SD_HY_SM3_CTX* sm3_ctx = (sdt_skf_SD_HY_SM3_CTX *)EVP_MD_CTX_md_data(ctx);

	skf_rv = SKF_DigestUpdate(sm3_ctx->phHash, (BYTE*)in, inlen);
	if(skf_rv != SAR_OK)
	{
		printf("SM3_HASH update error(0x%08x), inlen = %d\n", skf_rv, inlen);
		SKF_CloseHandle(sm3_ctx->phHash);
		return 0;
	}

	return 1;
}

static int sdt_skf_sm3_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	ULONG skf_rv;
	if (!ctx || !EVP_MD_CTX_md_data(ctx) || !md) {
		return 0;
	}

	sdt_skf_SD_HY_SM3_CTX* sm3_ctx = (sdt_skf_SD_HY_SM3_CTX *)EVP_MD_CTX_md_data(ctx);
	unsigned int nOutlen;

	unsigned char OutData[SM3_DIGEST_LENGTH];
	memset(OutData, 0, sizeof(OutData));
	skf_rv = SKF_DigestFinal(sm3_ctx->phHash, OutData, &nOutlen);
	if(skf_rv != SAR_OK)
	{
		printf("SM3_HASH final error(%0x%08x).\n",skf_rv);
		SKF_CloseHandle(sm3_ctx->phHash);

		return 0;
	}
	if(nOutlen != SM3_DIGEST_LENGTH)
	{
		printf("hash update len do not match SM3_DIGEST_LENGTH\n");
		return 0;
	}
	memcpy(md, OutData, nOutlen);
	skf_rv = SKF_CloseHandle(sm3_ctx->phHash);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_CloseHandle sm3 final error(%0x%08x).\n",skf_rv);
		return 0;
	}

	return 1;
}


static const EVP_MD sdt_skf_sd_hy_sm3_md = {
		NID_sm3,
		NID_sm2sign_with_sm3,
		SM3_DIGEST_LENGTH,
		0,
		sdt_skf_sd_hy_sm3_init,
		sdt_skf_sd_hy_sm3_update,
		sdt_skf_sm3_final,
		NULL,
		NULL,
		SM3_BLOCK_SIZE,
		sizeof(EVP_MD *) + sizeof(sdt_skf_SD_HY_SM3_CTX),
};


static const int sdt_skf_sd_hy_digest_nids[] = {
    NID_sm3,
    0
};
static int sdt_skf_sd_hy_sm3_engine_digest(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
	int ok = 1;
	if (!digest) {
		*nids = sdt_skf_sd_hy_digest_nids;
		return (sizeof(sdt_skf_sd_hy_digest_nids)) / sizeof(sdt_skf_sd_hy_digest_nids[0]);
	}
	if (nid == NID_sm3) {
		*digest = &sdt_skf_sd_hy_sm3_md;
	}
	else
	{
		ok = 0;
		*digest = NULL;
	}
	return ok;
}
/*----------------------------------- sm3, end ---------------------------------------*/


/*----------------------------------- sm4, begin ---------------------------------------*/
#if 1
typedef struct {
	HANDLE hKeyHandle;
	int mode;
	int enc;
	BLOCKCIPHERPARAM Param;
} EVP_SDT_SKF_SD_HY_SMS4_KEY;


static int sdt_skf_sd_hy_sms4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	int i, skf_rv;
	BYTE sdt_skf_key[16];

	ULONG ulAlgID;
//	unsigned char sdt_skf_key[SMS4_KEY_LENGTH] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
	EVP_SDT_SKF_SD_HY_SMS4_KEY *sm4_ctx = EVP_C_DATA(EVP_SDT_SKF_SD_HY_SMS4_KEY, ctx);
	sm4_ctx->enc = enc;
	sm4_ctx->mode = EVP_CIPHER_CTX_num(ctx);
//	printf("mode = %d\n", sm4_ctx->mode);
	if(sm4_ctx->mode == 1)
		ulAlgID = SGD_SMS4_ECB;
	else
		ulAlgID = SGD_SMS4_CBC;

//	skf_rv=SKF_OpenApplication(hd_sd_hy_ssl, INIT_APP_NAME, &(sm4_ctx->app));
//	if(skf_rv != SAR_OK)
//	{
//		printf("sm4, SKF_OpenApplication(%s) error(0x%X)\r\n", INIT_APP_NAME, skf_rv);
//		return 0;
//	}
//
//	skf_rv = SKF_VerifyPIN(sm4_ctx->app, 1, INIT_USER_PIN, &UserRetryCount);	//1, user pin; 2, admin pin
// 	if (skf_rv != SAR_OK)
//	{
//		printf("sm4, SKF_VerifyPIN error(0x%X),UserRetryCount=%d\r\n", skf_rv, UserRetryCount);
//		SKF_CloseApplication(sm4_ctx->app);
//		return 0;
//	}
// 	printf("sm4, VerifyPIN ok\n");

  	OPENSSL_buf2hexstr(key, SMS4_KEY_LENGTH);

//  	for(i = 0; i < SMS4_KEY_LENGTH; i++)
//  	{
//  		printf("0x%02x ", key[i]);
//  	}
//  	printf("\nskf key len = %d\n", strlen(key));

  	memset(sdt_skf_key, 0, sizeof(sdt_skf_key));
  	memcpy(sdt_skf_key, key, sizeof(sdt_skf_key));

  	skf_rv = SKF_SetSymmKey(hd_sd_hy_ssl, (BYTE*)sdt_skf_key, ulAlgID, &(sm4_ctx->hKeyHandle));
	if(skf_rv != SAR_OK)
	{
		printf("skf, Import sm4 key error, errorcode=[0x%08x]\n", skf_rv);
		return 0;
	}
	memset(&(sm4_ctx->Param), 0, sizeof(BLOCKCIPHERPARAM));
	sm4_ctx->Param.IVLen = 16;
	sm4_ctx->Param.PaddingType = 0;
	memcpy(sm4_ctx->Param.IV, iv, sm4_ctx->Param.IVLen);

//	if(enc)
//	{
//		skf_rv = SKF_EncryptInit(sm4_ctx->hKeyHandle, sm4_ctx->Param);
//		if(skf_rv != SAR_OK)
//		{
//			printf("skf, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
//			return 0;
//		}
//		printf("skf, SKF_EncryptInit ok\n");
//	}
//	else
//	{
//		skf_rv = SKF_DecryptInit(sm4_ctx->hKeyHandle, sm4_ctx->Param);
//		if(skf_rv != SAR_OK)
//		{
//			printf("skf, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
//			return 0;
//		}
//		printf("skf, SKF_DecryptInit ok\n");
//	}

	printf("sdt skf sm4 init key success\n");
	return 1;
}

static int sdt_skf_sd_hy_sms4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	int skf_rv;
	unsigned int  outDataLen;
	EVP_SDT_SKF_SD_HY_SMS4_KEY *sm4_ctx = (EVP_SDT_SKF_SD_HY_SMS4_KEY *)ctx->cipher_data;

//	printf("sm4_ecb input len = %d\n", len);
	if(len % 16 != 0)
	{
		printf("ecb mode input len is not align of 16 bytes, len = %d\n", len);
	}
//	printf("sm4 ecb encrypt/decrypt len = %d\n", len);
	if(sm4_ctx->enc)
	{

		skf_rv = SKF_EncryptInit(sm4_ctx->hKeyHandle, sm4_ctx->Param);
		if(skf_rv != SAR_OK)
		{
			printf("skf, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
			return 0;
		}
//		printf("skf, ecb SKF_EncryptInit ok\n");

		skf_rv = SKF_Encrypt(sm4_ctx->hKeyHandle, (unsigned char *)in, len, NULL, &outDataLen);
		if(skf_rv != SAR_OK)
		{
			printf("encrypt error 1，error[0x%08x]\n", skf_rv);
			return 0;
		}

		skf_rv = SKF_Encrypt(sm4_ctx->hKeyHandle, (unsigned char *)in, len, out, &outDataLen);
		if(skf_rv != SAR_OK)
		{
			printf("encrypt error 2，error[0x%08x]\n", skf_rv);
			return 0;
		}
//		printf("skf ecb encrypt success\n");
	}
	else
	{
		skf_rv = SKF_DecryptInit(sm4_ctx->hKeyHandle, sm4_ctx->Param);
		if(skf_rv != SAR_OK)
		{
			printf("skf, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
			return 0;
		}
//		printf("skf, ecb SKF_DecryptInit ok\n");

		skf_rv = SKF_Decrypt(sm4_ctx->hKeyHandle, (unsigned char *)in, len, NULL, &outDataLen);
		if(skf_rv != SAR_OK)
		{
			printf("encrypt/decypt error 1，error[0x%08x]\n", skf_rv);
			return 0;
		}

		skf_rv = SKF_Decrypt(sm4_ctx->hKeyHandle, (unsigned char *)in, len, out, &outDataLen);
		if(skf_rv != SAR_OK)
		{
			printf("encrypt/decypt error 2，error[0x%08x]\n", skf_rv);
			return 0;
		}
//		printf("skf ecb decrypt success\n");
	}

	return 1;
}

static int sdt_skf_sd_hy_sms4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	int skf_rv;
	unsigned int  outDataLen;
	EVP_SDT_SKF_SD_HY_SMS4_KEY *sm4_ctx = (EVP_SDT_SKF_SD_HY_SMS4_KEY *)ctx->cipher_data;

//	printf("sm4_cbc input len = %d\n", len);
	if(len % 16 != 0)
	{
		printf("cbc mode input len is not align of 16 bytes, len = %d\n", len);
	}
//	printf("sm4 cbc encrypt/decrypt len = %d\n", len);
	if(sm4_ctx->enc)
	{

		skf_rv = SKF_EncryptInit(sm4_ctx->hKeyHandle, sm4_ctx->Param);
		if(skf_rv != SAR_OK)
		{
			printf("skf, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
			return 0;
		}
//		printf("skf, cbc SKF_EncryptInit ok\n");

		skf_rv = SKF_Encrypt(sm4_ctx->hKeyHandle, (unsigned char *)in, len, NULL, &outDataLen);
		if(skf_rv != SAR_OK)
		{
			printf("encrypt error 1，error[0x%08x]\n", skf_rv);
			return 0;
		}
		skf_rv = SKF_Encrypt(sm4_ctx->hKeyHandle, (unsigned char *)in, len, out, &outDataLen);
		if(skf_rv != SAR_OK)
		{
			printf("encrypt error 2，error[0x%08x]\n", skf_rv);
			return 0;
		}
//		printf("skf cbc encrypt success\n");
	}
	else
	{

		skf_rv = SKF_DecryptInit(sm4_ctx->hKeyHandle, sm4_ctx->Param);
		if(skf_rv != SAR_OK)
		{
			printf("skf, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
			return 0;
		}
//		printf("skf, cbc SKF_DecryptInit ok\n");

		skf_rv = SKF_Decrypt(sm4_ctx->hKeyHandle, (unsigned char *)in, len, NULL, &outDataLen);
		if(skf_rv != SAR_OK)
		{
			printf("decypt error 1，error[0x%08x]\n", skf_rv);
			return 0;
		}
		skf_rv = SKF_Decrypt(sm4_ctx->hKeyHandle, (unsigned char *)in, len, out, &outDataLen);
		if(skf_rv != SAR_OK)
		{
			printf("decypt error 2，error[0x%08x]\n", skf_rv);
			return 0;
		}
//		printf("skf cbc decrypt success\n");
	}

	return 1;
}


static int sdt_skf_sd_hy_sms4_cleanup(EVP_CIPHER_CTX *ctx)
{
	int skf_rv;
	EVP_SDT_SKF_SD_HY_SMS4_KEY *sm4_ctx = (EVP_SDT_SKF_SD_HY_SMS4_KEY *)ctx->cipher_data;

	skf_rv = SKF_CloseHandle(sm4_ctx->hKeyHandle);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_CloseHandle sm4 error，error[0x%08x]\n", skf_rv);
		return 0;
	}

//	printf("sdt_skf_sms4 cleanup\n");
	return 1;
}

const EVP_CIPHER sdt_skf_sd_hy_sms4_ecb = {
	NID_sms4_ecb,
	16,
	SMS4_KEY_LENGTH,
	SMS4_IV_LENGTH,
	EVP_CIPH_ECB_MODE,
	sdt_skf_sd_hy_sms4_init_key,
	sdt_skf_sd_hy_sms4_ecb_cipher,
	sdt_skf_sd_hy_sms4_cleanup,
	sizeof(EVP_SDT_SKF_SD_HY_SMS4_KEY),
	NULL, NULL, NULL, NULL,
};

const EVP_CIPHER sdt_skf_sd_hy_sms4_cbc = {
	NID_sms4_cbc,
	16,
	SMS4_KEY_LENGTH,
	SMS4_IV_LENGTH,
	EVP_CIPH_CBC_MODE,
	sdt_skf_sd_hy_sms4_init_key,
	sdt_skf_sd_hy_sms4_cbc_cipher,
	sdt_skf_sd_hy_sms4_cleanup,
	sizeof(EVP_SDT_SKF_SD_HY_SMS4_KEY),
	NULL, NULL, NULL, NULL,
};



static const int sd_hy_gmi_cipher_nids[] = {
    NID_sms4_ecb,
    NID_sms4_cbc,
    0
};


static int sdt_skf_sd_hy_sm4_cipher_nids_num = ((sizeof(sd_hy_gmi_cipher_nids) - 1)  /
                                      sizeof(sd_hy_gmi_cipher_nids[0]));

static int sdt_skf_sd_hy_sm4_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    /* No specific cipher => return a list of supported nids ... */
    if (!cipher) {
        *nids = sd_hy_gmi_cipher_nids;
        return sdt_skf_sd_hy_sm4_cipher_nids_num;
    }

    /* ... or the requested "cipher" otherwise */
    switch (nid)
    {
    case NID_sms4_ecb:
        *cipher = &sdt_skf_sd_hy_sms4_ecb;
        break;
    case NID_sms4_cbc:
        *cipher = &sdt_skf_sd_hy_sms4_cbc;
        break;
    default:
        /* Sorry, we don't support this NID */
        *cipher = NULL;
        return 0;
    }
    return 1;
}
#endif
/*----------------------------------- sm4, end ---------------------------------------*/
#endif
/*----------------------------------- random, begin ---------------------------------------*/

static int sdt_skf_sd_hy_rand_bytes(unsigned char *buf, int num)
{
	int rv;

	rv = SKF_GenRandom(hd_sd_hy_ssl, buf, num);
	if(rv != SDR_OK)
	{
		printf("SKF_GenRandom, error code=[0x%08x]\n",rv);
		return 0;
	}

//	printf("using sdt skf rand\n");
	return 1;
}

static int sdt_skf_sd_hy_rand_status(void)
{
    return 1;
}

static RAND_METHOD sdt_skf_sd_hy_rand = {
    /* "CHIL RAND method", */
    NULL,
    sdt_skf_sd_hy_rand_bytes,
    NULL,
    NULL,
    sdt_skf_sd_hy_rand_bytes,
    sdt_skf_sd_hy_rand_status,
};
/*----------------------------------- random, end ---------------------------------------*/




static int bind_helper(ENGINE * e, const char *id)
{
	ERR_load_SDF_strings();

    if (!ENGINE_set_id(e, engine_sdt_skf_sd_hy_id)
        || !ENGINE_set_name(e, engine_sdt_skf_sd_hy_name)
        || !ENGINE_set_init_function(e, sdt_skf_sd_hy_engine_init)
        || !ENGINE_set_RAND(e, &sdt_skf_sd_hy_rand)
        || !ENGINE_set_EC(e, EC_KEY_GmSSL_SDT_SKF_SD_HY())
        || !ENGINE_set_pkey_meths(e, sdt_skf_sd_hy_pkey_meths)
        || !ENGINE_set_digests(e, sdt_skf_sd_hy_sm3_engine_digest)
        || !ENGINE_set_ciphers(e, sdt_skf_sd_hy_sm4_ciphers)
        || !ENGINE_set_finish_function(e, sdt_skf_sd_hy_finish)
        || !ENGINE_set_destroy_function(e, sdt_skf_sd_hy_destroy)){

       printf("sdt_skf_sd_hy engine bind and init failed\n");
        return 0;
    }

    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper);
