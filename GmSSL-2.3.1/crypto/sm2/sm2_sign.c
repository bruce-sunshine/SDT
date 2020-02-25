/* ====================================================================
 * Copyright (c) 2015 - 2016 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include "../ec/ec_lcl.h"

#include <openssl/sgd.h>		//added by bruce, 0918
#include <openssl/sdf.h>		//added by bruce, 0918
#include <openssl/skf.h>		//added by bruce, 0918
#include <openssl/gmapi.h>		//added by bruce, 0918
#define PIN_MAX_RETRY_TIMES       (8)
#define INIT_APP_NAME             "SJW07A_SDT"
#define INIT_USER_PIN   		  "12345678"
//#include <openssl/swsds.h>

static int sm2_sign_setup(EC_KEY *ec_key, BN_CTX *ctx_in, BIGNUM **kp, BIGNUM **xp)
{
	int ret = 0;
	const EC_GROUP *ec_group;
	BN_CTX *ctx = NULL;
	BIGNUM *k = NULL;
	BIGNUM *x = NULL;
	BIGNUM *order = NULL;
	EC_POINT *point = NULL;

	if (ec_key == NULL || (ec_group = EC_KEY_get0_group(ec_key)) == NULL) {
		SM2err(SM2_F_SM2_SIGN_SETUP, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (ctx_in == NULL)  {
		if ((ctx = BN_CTX_new()) == NULL) {
			SM2err(SM2_F_SM2_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
			return 0;
		}
	}
	else {
		ctx = ctx_in;
	}

	k = BN_new();
	x = BN_new();
	order = BN_new();
	if (!k || !x || !order) {
		SM2err(SM2_F_SM2_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (!EC_GROUP_get_order(ec_group, order, ctx)) {
		SM2err(SM2_F_SM2_SIGN_SETUP, ERR_R_EC_LIB);
		goto end;
	}

	if ((point = EC_POINT_new(ec_group)) == NULL) {
		SM2err(SM2_F_SM2_SIGN_SETUP, ERR_R_EC_LIB);
		goto end;
	}

	do {
		/* get random k */
		do {
			if (!BN_rand_range(k, order)) {
				SM2err(SM2_F_SM2_SIGN_SETUP,
					SM2_R_RANDOM_NUMBER_GENERATION_FAILED);
				goto end;
			}

		} while (BN_is_zero(k));

		/* compute r the x-coordinate of generator * k */
		if (!EC_POINT_mul(ec_group, point, k, NULL, NULL, ctx)) {
			SM2err(SM2_F_SM2_SIGN_SETUP, ERR_R_EC_LIB);
			goto end;
		}

		if (EC_METHOD_get_field_type(EC_GROUP_method_of(ec_group)) == NID_X9_62_prime_field) {
			if (!EC_POINT_get_affine_coordinates_GFp(ec_group, point, x, NULL, ctx)) {
				SM2err(SM2_F_SM2_SIGN_SETUP, ERR_R_EC_LIB);
				goto end;
			}
		} else /* NID_X9_62_characteristic_two_field */ {
			if (!EC_POINT_get_affine_coordinates_GF2m(ec_group, point, x, NULL, ctx)) {
				SM2err(SM2_F_SM2_SIGN_SETUP, ERR_R_EC_LIB);
				goto end;
			}
		}

		if (!BN_nnmod(x, x, order, ctx)) {
			SM2err(SM2_F_SM2_SIGN_SETUP, ERR_R_BN_LIB);
			goto end;
		}

	} while (BN_is_zero(x));

	/* clear old values if necessary */
	BN_clear_free(*kp);
	BN_clear_free(*xp);

	/* save the pre-computed values  */
	*kp = k;
	*xp = x;
	ret = 1;

end:
	if (!ret) {
		BN_clear_free(k);
		BN_clear_free(x);
	}
	if (!ctx_in) {
		BN_CTX_free(ctx);
	}
	BN_free(order);
	EC_POINT_free(point);

	return(ret);
}

static ECDSA_SIG *sm2_do_sign(const unsigned char *dgst, int dgstlen,
	const BIGNUM *in_k, const BIGNUM *in_x, EC_KEY *ec_key)
{
	int ok = 0;
	ECDSA_SIG *ret = NULL;
	const EC_GROUP *ec_group;
	const BIGNUM *priv_key;
	const BIGNUM *ck;
	BIGNUM *k = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *order = NULL;
	BIGNUM *e = NULL;
	BIGNUM *bn = NULL;
	int i;

	ec_group = EC_KEY_get0_group(ec_key);
	priv_key = EC_KEY_get0_private_key(ec_key);
	if (!ec_group || !priv_key) {
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	if (!(ret = ECDSA_SIG_new())) {
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	ret->r = BN_new();
	ret->s = BN_new();
	ctx = BN_CTX_new();
	order = BN_new();
	e = BN_new();
	bn = BN_new();
	if (!ret->r || !ret->s || !ctx || !order || !e || !bn) {
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EC_GROUP_get_order(ec_group, order, ctx)) {
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_EC_LIB);
		goto end;
	}

	/* convert dgst to e */
	i = BN_num_bits(order);
#if 0
	if (8 * dgstlen > i) {
		dgstlen = (i + 7)/8;
	}
#endif
	if (!BN_bin2bn(dgst, dgstlen, e)) {
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
		goto end;
	}

#if 0
	if ((8 * dgstlen > i) && !BN_rshift(e, e, 8 - (i & 0x7))) {
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
		goto end;
	}
#endif

	do {
		/* use or compute k and (kG).x */
		if (!in_k || !in_x) {
			if (!sm2_sign_setup(ec_key, ctx, &k, &ret->r)) {
				SM2err(SM2_F_SM2_DO_SIGN, ERR_R_ECDSA_LIB);
				goto end;
			}
			ck = k;
		} else {
			ck = in_k;
			if (!BN_copy(ret->r, in_x)) {
				SM2err(SM2_F_SM2_DO_SIGN, ERR_R_MALLOC_FAILURE);
				goto end;
			}
		}

		/* r = e + x (mod n) */
		if (!BN_mod_add(ret->r, ret->r, e, order, ctx)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}

		if (!BN_mod_add(bn, ret->r, ck, order, ctx)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}

		/* check r != 0 && r + k != n */
		if (BN_is_zero(ret->r) || BN_is_zero(bn)) {
			if (in_k && in_x) {
				SM2err(SM2_F_SM2_DO_SIGN, SM2_R_NEED_NEW_SETUP_VALUES);
				goto end;
			} else
				continue;
		}

		/* s = ((1 + d)^-1 * (k - rd)) mod n */
		if (!BN_one(bn)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}

		if (!BN_mod_add(ret->s, priv_key, bn, order, ctx)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}
		if (!BN_mod_inverse(ret->s, ret->s, order, ctx)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}

		if (!BN_mod_mul(bn, ret->r, priv_key, order, ctx)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}
		if (!BN_mod_sub(bn, ck, bn, order, ctx)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}
		if (!BN_mod_mul(ret->s, ret->s, bn, order, ctx)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}

		/* check s != 0 */
		if (BN_is_zero(ret->s)) {
			if (in_k && in_x) {
				SM2err(SM2_F_SM2_DO_SIGN, SM2_R_NEED_NEW_SETUP_VALUES);
				goto end;
			}
		} else {
			break;
		}

	} while (1);

#if 0
	if (!BN_rshift1(bn, order)) {
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
		goto end;
	}
	if (BN_cmp(ret->r, bn) <= 0) {
		if (!BN_sub(ret->r, order, ret->r)
			|| !BN_sub(ret->s, order, ret->s)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}
	}

#endif

	ok = 1;

end:
	if (!ok) {
		ECDSA_SIG_free(ret);
		ret = NULL;
	}
	BN_free(k);
	BN_CTX_free(ctx);
	BN_free(order);
	BN_free(e);
	BN_free(bn);

	return ret;
}

int sm2_do_verify(const unsigned char *dgst, int dgstlen,
	const ECDSA_SIG *sig, EC_KEY *ec_key)
{
	int ret = -1;
	const EC_GROUP *ec_group;
	const EC_POINT *pub_key;
	EC_POINT *point = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *order = NULL;
	BIGNUM *e = NULL;
	BIGNUM *t = NULL;
	int i;

	if (!sig || !ec_key ||
		!(ec_group = EC_KEY_get0_group(ec_key)) ||
		!(pub_key  = EC_KEY_get0_public_key(ec_key))) {

		SM2err(SM2_F_SM2_DO_VERIFY, SM2_R_MISSING_PARAMETERS);
		return -1;
	}

	ctx = BN_CTX_new();
	order = BN_new();
	e = BN_new();
	t = BN_new();
	if (!ctx || !order || !e || !t) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EC_GROUP_get_order(ec_group, order, ctx)) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
		goto end;
	}

#if 0
	if (!BN_rshift1(t, order)) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		goto end;
	}
	if (BN_cmp(sig->r, t) <= 0) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB); //FIXME: error code
		goto end;
	}
#endif

	/* check r, s in [1, n-1] and r + s != 0 (mod n) */
	if (BN_is_zero(sig->r) ||
		BN_is_negative(sig->r) ||
		BN_ucmp(sig->r, order) >= 0 ||
		BN_is_zero(sig->s) ||
		BN_is_negative(sig->s) ||
		BN_ucmp(sig->s, order) >= 0) {

		SM2err(SM2_F_SM2_DO_VERIFY, SM2_R_BAD_SIGNATURE);
		ret = 0;
		goto end;
	}

	/* check t = r + s != 0 */
	if (!BN_mod_add(t, sig->r, sig->s, order, ctx)) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		goto end;
	}
	if (BN_is_zero(t)) {
		ret = 0;
		goto end;
	}

	/* convert digest to e */
	i = BN_num_bits(order);
#if 0
	if (8 * dgstlen > i) {
		dgstlen = (i + 7)/8;
	}
#endif
	if (!BN_bin2bn(dgst, dgstlen, e)) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		goto end;
	}
#if 0
	if ((8 * dgstlen > i) && !BN_rshift(e, e, 8 - (i & 0x7))) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		goto end;
	}
#endif

	/* compute (x, y) = sG + tP, P is pub_key */
	if (!(point = EC_POINT_new(ec_group))) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EC_POINT_mul(ec_group, point, sig->s, pub_key, t, ctx)) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
		goto end;
	}
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(ec_group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(ec_group, point, t, NULL, ctx)) {
			SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
			goto end;
		}
	} else /* NID_X9_62_characteristic_two_field */ {
		if (!EC_POINT_get_affine_coordinates_GF2m(ec_group, point, t, NULL, ctx)) {
			SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
			goto end;
		}
	}
	if (!BN_nnmod(t, t, order, ctx)) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		goto end;
	}

	/* check (sG + tP).x + e  == sig.r */
	if (!BN_mod_add(t, t, e, order, ctx)) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		goto end;
	}
	if (BN_ucmp(t, sig->r) == 0) {
		ret = 1;
	} else {
		ret = 0;
	}

end:
	EC_POINT_free(point);
	BN_free(order);
	BN_free(e);
	BN_free(t);
	BN_CTX_free(ctx);
	return ret;
}

int SM2_sign_setup(EC_KEY *ec_key, BN_CTX *ctx_in, BIGNUM **kp, BIGNUM **xp)
{
	return sm2_sign_setup(ec_key, ctx_in, kp, xp);
}

ECDSA_SIG *SM2_do_sign_ex(const unsigned char *dgst, int dgstlen,
	const BIGNUM *kp, const BIGNUM *xp, EC_KEY *ec_key)
{
//	printf("using SM2_do_sign_ex_old\n");
	return sm2_do_sign(dgst, dgstlen, kp, xp, ec_key);
}

ECDSA_SIG *SM2_do_sign(const unsigned char *dgst, int dgstlen, EC_KEY *ec_key)
{
	return SM2_do_sign_ex(dgst, dgstlen, NULL, NULL, ec_key);
}

int SM2_do_verify(const unsigned char *dgst, int dgstlen,
	const ECDSA_SIG *sig, EC_KEY *ec_key)
{
	return sm2_do_verify(dgst, dgstlen, sig, ec_key);
}

int SM2_sign_ex(int type, const unsigned char *dgst, int dgstlen,
	unsigned char *sig, unsigned int *siglen,
	const BIGNUM *k, const BIGNUM *x, EC_KEY *ec_key)
{
	ECDSA_SIG *s;

	RAND_seed(dgst, dgstlen);

	if (!(s = SM2_do_sign_ex(dgst, dgstlen, k, x, ec_key))) {	//changed by bruce, because of bug of ECDSA_SIG_new_from_ECCSIGNATUREBLOB, 0927
		*siglen = 0;
		return 0;
	}

	*siglen = i2d_ECDSA_SIG(s, &sig);
	ECDSA_SIG_free(s);

	return 1;
}

int SM2_sign(int type, const unsigned char *dgst, int dgstlen,
	unsigned char *sig, unsigned int *siglen, EC_KEY *ec_key)
{
	return SM2_sign_ex(type, dgst, dgstlen, sig, siglen, NULL, NULL, ec_key);
}

int SM2_verify(int type, const unsigned char *dgst, int dgstlen,		//note, bruce, 0918
	const unsigned char *sig, int siglen, EC_KEY *ec_key)
{
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

	ret = SM2_do_verify(dgst, dgstlen, s, ec_key);

err:
	if (derlen > 0) {
		OPENSSL_cleanse(der, derlen);
		OPENSSL_free(der);
	}

	ECDSA_SIG_free(s);
	return ret;
}
////////////////////////////////////////////////////added by bruce , for sanweixinan JMK SM2 sign and verify//////////////////////
#if 0
typedef void*	SGD_HANDLE;
ECDSA_SIG *SM2_do_sign_ex_sdt_sdf(const unsigned char *dgst, int dgstlen,
	const BIGNUM *kp, const BIGNUM *xp, EC_KEY *ec_key)
{

	SGD_HANDLE device_handle=NULL;
	SGD_HANDLE session_handle=NULL;
	int rv;
	ECCrefPrivateKey priKey;
	ECCSignature sigref;
	ECDSA_SIG *ret = NULL;

	if(SDR_OK!=(rv=SDF_OpenDevice(&device_handle)))
	{
		printf("open device sign failed, error code=[0x%08x]\n",rv);
		return 0;
	}
	if(SDR_OK!=SDF_OpenSession(device_handle, &session_handle))
	{
		printf("open session sign failed\n");
		return 0;
	}

	if(1 != EC_KEY_get_ECCrefPrivateKey(ec_key, &priKey))
	{
		printf("EC_KEY_get_ECCrefPrivateKey error\n");
		return 0;
	}

	rv = SDF_ExternalSign_ECC(session_handle, SGD_SM2_1, &priKey, dgst, dgstlen, &sigref);
	if(rv != SDR_OK)
	{
		printf("SDF_ExternalSign_ECC error, error = [0x%08x]\n", rv);
		return 0;
	}
	else
	{
		printf("SDF_ExternalSign_ECC success\n");
	}

	ret = ECDSA_SIG_new_from_ECCSignature(&sigref);
	if(ret == NULL)
		printf("ECDSA_SIG_new_from_ECCSignature error\n");

	if(SDR_OK!=(rv=SDF_CloseSession(session_handle)))
	{
		printf("CloseSession failed, error code=[0x%08x]\n",rv);
		return 0;
	}
	printf("close sm2 sign session\n");

	if(device_handle != NULL)
	{
		SDF_CloseDevice(device_handle);
		device_handle = NULL;
	}
	printf("close sdf sign device\n");
	return ret;
}

int SM2_do_verify_sdt_sdf(const unsigned char *dgst, int dgstlen,
	const ECDSA_SIG *sig, EC_KEY *ec_key)
{
//	return sm2_do_verify(dgst, dgstlen, sig, ec_key);
	SGD_HANDLE device_handle=NULL;
	SGD_HANDLE session_handle=NULL;
	int rv;
	if(SDR_OK!=(rv=SDF_OpenDevice(&device_handle)))
	{
		printf("open device verify failed, error code=[0x%08x]\n",rv);
		return 0;
	}
	if(SDR_OK!=SDF_OpenSession(device_handle, &session_handle))
	{
		printf("open session verify failed\n");
		return 0;
	}
	ECCrefPublicKey pubKey;
//	ECCrefPrivateKey priKey;
	ECCSignature sigref;
	if(1 != ECDSA_SIG_get_ECCSignature(sig, &sigref))
	{
		printf("ECDSA_SIG_get_ECCSignature error\n");
		return 0;
	}

//	EC_POINT * pub_key  = EC_KEY_get0_public_key(ec_key);

//	int keyLen = 256;
//	rv = SDF_GenerateKeyPair_ECC(session_handle, SGD_SM2_3, keyLen, &pubKey, &priKey);
//	if(rv != SDR_OK)
//	{
//		printf("产生ECC密钥对错误，错误码[0x%08x]\n", rv);
//		return 0;
//	}
//	printf("sm2 gen ecc pair success\n");


//	if(1 != EC_KEY_set_ECCrefPublicKey(ec_key, &pubKey))
//	{
//		printf("EC_KEY_set_ECCrefPublicKey error\n");
//		return 0;
//	}

//	if(1 != EC_KEY_set_ECCrefPrivateKey(ec_key, &priKey))
//	{
//		printf("EC_KEY_set_ECCrefPrivateKey error\n");
//		return 0;
//	}
//
	if(1 != EC_KEY_get_ECCrefPublicKey(ec_key, &pubKey))
	{
		printf("EC_KEY_get_ECCrefPublicKey error\n");
		return 0;
	}

	SDF_PrintECCPublicKey(&pubKey);
	printf("\n");
	SDF_PrintECCSignature(&sigref);

#if 0
	ECCrefPublicKey ECC_PubKey;
	ECCSignature ECC_SignatureValue;
	unsigned char xa[32] = {0x5C,0xA4,0xE4,0x40,0xC5,0x08,0xC4,0x5F,0xE7,0xD7,0x58,0xAB,0x10,0xC4,0x5D,0x82,0x37,0xC4,0xF9,0x55,0x9F,0x7D,0x46,0x61,0x85,0xF2,0x95,0x39,0x9F,0x0A,0xA3,0x7D};
	unsigned char ya[32] = {0x59,0xAD,0x8A,0x3C,0xD1,0x79,0x03,0x28,0x76,0x81,0xBF,0x9D,0x21,0xDA,0x2E,0xB3,0x16,0xA0,0xCE,0x8F,0xD4,0x1C,0x89,0xCE,0x1E,0x2B,0x3F,0x1B,0x8E,0x04,0x1A,0xBA};

	//标准数据
	unsigned char e[32] = {0x38,0x54,0xC4,0x63,0xFA,0x3F,0x73,0x78,0x36,0x21,0xB1,0xCE,0x4E,0xF8,0x3F,0x7C,0x78,0x04,0x8A,0xAC,0x79,0xB2,0x21,0xFC,0xDD,0x29,0x08,0x66,0xCC,0x13,0x11,0x74};

	//标准签名数据
	unsigned char r[32] = {0x6E,0x5D,0xB4,0x9D,0xBD,0x09,0x92,0xB9,0x70,0x40,0x08,0x0A,0x96,0x00,0x3C,0x72,0x1C,0xDB,0x9C,0xF6,0x4C,0x88,0xD7,0x43,0x21,0xFC,0x2F,0x63,0x0A,0xDF,0x37,0x74};
	unsigned char s[32] = {0x2F,0x6D,0xFF,0x45,0x3D,0xFC,0x8D,0x7A,0x50,0x6D,0x3F,0x52,0x30,0x1B,0xEE,0x52,0x9E,0x62,0xFD,0xDD,0x38,0x94,0x8F,0x0D,0x5D,0x2C,0xBC,0xBC,0x55,0x90,0x0C,0xFA};


	memset(&ECC_PubKey, 0, sizeof(ECCrefPublicKey));
	memcpy(ECC_PubKey.x, xa, 32);
	memcpy(ECC_PubKey.y, ya, 32);
	ECC_PubKey.bits = 256;

	memset(&ECC_SignatureValue, 0, sizeof(ECCSignature));
	memcpy(ECC_SignatureValue.r, r, 32);
	memcpy(ECC_SignatureValue.s, s, 32);
	rv = SDF_ExternalVerify_ECC(session_handle, SGD_SM2_1, &ECC_PubKey, e, 32, &ECC_SignatureValue);
	if(rv != SDR_OK)
	{
		printf("ECC标准数据验证错误，错误码[0x%08x]\n", rv);
	}
	else
	{
		printf("ECC标准数据验证成功\n");
	}
#endif
	rv = SDF_ExternalVerify_ECC(session_handle, SGD_SM2_1, &pubKey, dgst, dgstlen, &sigref);
	if(rv != SDR_OK)
	{
		printf("签名运算错误，错误码[0x%08x]\n", rv);
		return 0;
	}
	else
	{
		printf("SDF_ExternalVerify_ECC success\n");
	}

	if(SDR_OK!=(rv=SDF_CloseSession(session_handle)))
	{
		printf("CloseSession failed, error code=[0x%08x]\n",rv);
		return 0;
	}
	printf("close sm2 verify session\n");

	if(device_handle !=NULL)
	{
		SDF_CloseDevice(device_handle);
		device_handle = NULL;
	}
	printf("close sdf verify device\n");

}

#else
////////////////////////////////////////////////////added by bruce , for huashen ukey SM2 sign and verify//////////////////////
ECDSA_SIG *SM2_do_sign_ex_sdt_skf(const unsigned char *dgst, int dgstlen,
	const BIGNUM *kp, const BIGNUM *xp, EC_KEY *ec_key)
{
	printf("using SM2_do_sign_ex\n");
	DEVHANDLE hd;
	HAPPLICATION app;
	char *name_list;
	ULONG name_list_size;
	DEVINFO DevInfo;
	ULONG skf_rv;
	ULONG UserRetryCount = PIN_MAX_RETRY_TIMES;
	ECCPRIVATEKEYBLOB priKey;
	ECCSIGNATUREBLOB sigref;
	ECDSA_SIG *ret = NULL;
	skf_rv = SKF_EnumDev(TRUE, 0, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		printf("SKF_EnumDev error\n");
		return 0;
	}
	printf("name_list_size = %d\n", name_list_size);
	if (name_list_size == 0)
	{
		printf("SKF get name_list_size = 0\n");
		return 0;
	}
	name_list = (char *)malloc (name_list_size);
	if(name_list == NULL)
	{
		printf("name list, malloc error\n");
		return 0;
	}

	skf_rv = SKF_EnumDev(TRUE, name_list, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		free (name_list);
		printf("SKF_EnumDev_2 error\n");
		return 0;
	}

	skf_rv = SKF_ConnectDev(name_list, &hd);
	free(name_list);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_ConnectDev error\n");
		return 0;
	}

	skf_rv=SKF_OpenApplication(hd, INIT_APP_NAME, &(app));
	if(skf_rv != SAR_OK)
	{
		printf("SKF_OpenApplication(%s) error(0x%X)\r\n", INIT_APP_NAME, skf_rv);
		return 0;
	}

	skf_rv = SKF_VerifyPIN(app, 1, INIT_USER_PIN, &UserRetryCount);	//1, user pin; 2, admin pin
 	if (skf_rv != SAR_OK)
	{
		printf("SKF_VerifyPIN error(0x%X),UserRetryCount=%d\r\n", skf_rv, UserRetryCount);
		SKF_CloseApplication(app);
		return 0;
	}
 	printf("sign VerifyPIN ok\n");

	if(1 != EC_KEY_get_ECCPRIVATEKEYBLOB(ec_key, &priKey))
	{
		printf("EC_KEY_get_ECCPRIVATEKEYBLOB error\n");
		return 0;
	}

	skf_rv = SKF_ExtECCSign(hd, &priKey, dgst, dgstlen, &sigref);
	if(skf_rv != SDR_OK)
	{
		printf("SKF_ExtECCSign error, error = [0x%08x]\n", skf_rv);
		return 0;
	}
	else
	{
		printf("SKF_ExtECCSign success\n");
	}

	ret = ECDSA_SIG_new_from_ECCSIGNATUREBLOB(&sigref);				//need to check, added by bruce, 0921
	if(ret == NULL)
		printf("ECDSA_SIG_new_from_ECCSIGNATUREBLOB error\n");

	SKF_CloseApplication(app);
	SKF_DisConnectDev(hd);
	printf("close sm2 ukey skf sign device\n");
	return ret;
}


int SM2_do_verify_bruce_sdt_skf(const unsigned char *dgst, int dgstlen,
	const ECDSA_SIG *sig, EC_KEY *ec_key)
{
	DEVHANDLE hd;
	HAPPLICATION app;
	char *name_list;
	ULONG name_list_size;
	ULONG skf_rv;
	ULONG UserRetryCount = PIN_MAX_RETRY_TIMES;
	ECCPUBLICKEYBLOB pubKey;
	ECCSIGNATUREBLOB sigref;
	skf_rv = SKF_EnumDev(TRUE, 0, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		printf("SKF_EnumDev error\n");
		return 0;
	}
	printf("name_list_size = %d\n", name_list_size);
	if (name_list_size == 0)
	{
		printf("SKF get name_list_size = 0\n");
		return 0;
	}
	name_list = (char *)malloc (name_list_size);
	if(name_list == NULL)
	{
		printf("name list, malloc error\n");
		return 0;
	}

	skf_rv = SKF_EnumDev(TRUE, name_list, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		free (name_list);
		printf("SKF_EnumDev_2 error\n");
		return 0;
	}

	skf_rv = SKF_ConnectDev(name_list, &hd);
	free(name_list);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_ConnectDev error\n");
		return 0;
	}

	skf_rv=SKF_OpenApplication(hd, INIT_APP_NAME, &(app));
	if(skf_rv != SAR_OK)
	{
		printf("SKF_OpenApplication(%s) error(0x%X)\r\n", INIT_APP_NAME, skf_rv);
		return 0;
	}

	skf_rv = SKF_VerifyPIN(app, 1, INIT_USER_PIN, &UserRetryCount);	//1, user pin; 2, admin pin
 	if (skf_rv != SAR_OK)
	{
		printf("SKF_VerifyPIN error(0x%X),UserRetryCount=%d\r\n", skf_rv, UserRetryCount);
		SKF_CloseApplication(app);
		return 0;
	}
 	printf("verify VerifyPIN ok\n");

	if(1 != ECDSA_SIG_get_ECCSIGNATUREBLOB(sig, &sigref))
	{
		printf("ECDSA_SIG_get_ECCSIGNATUREBLOB error\n");
		return 0;
	}

	if(1 != EC_KEY_get_ECCPUBLICKEYBLOB(ec_key, &pubKey))
	{
		printf("EC_KEY_get_ECCPUBLICKEYBLOB error\n");
		return 0;
	}

	skf_rv = SKF_ExtECCVerify(hd, &pubKey, dgst, dgstlen, &sigref);
	if(skf_rv != SAR_OK)
	{
		printf("签名运算错误，错误码[0x%08x]\n", skf_rv);
		return 0;
	}
	else
	{
		printf("SKF_ExtECCVerify success\n");
	}

	SKF_CloseApplication(app);
	SKF_DisConnectDev(hd);
	printf("close sm2 ukey skf verify device\n");
	return 1;
}

#endif
