#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "hmac_sm3.h"
#include "alloc.h"

/* the debug module for authentiation */

srtp_debug_module_t srtp_mod_hmac_sm3 = {
    0,                /* debugging is off by default */
    "hmac sm3"      /* printable name for module   */
};


static srtp_err_status_t srtp_hmac_sm3_alloc (srtp_auth_t **a, int key_len, int out_len)
{
    extern const srtp_auth_type_t srtp_hmac_sm3;
    uint8_t *pointer;

    debug_print(srtp_mod_hmac_sm3, "allocating auth func with key length %d", key_len);
    debug_print(srtp_mod_hmac_sm3, "                          tag length %d", out_len);

    /*
     * check key length - note that we don't support keys larger
     * than 20 bytes yet
     */
    if (key_len > 32) {
        return srtp_err_status_bad_param;
    }

    /* check output length - should be less than 20 bytes */
    if (out_len > 32) {
        return srtp_err_status_bad_param;
    }

    /* allocate memory for auth and srtp_hmac_sm3_ctx_t structures */
    pointer = (uint8_t*)srtp_crypto_alloc(sizeof(srtp_hmac_sm3_ctx_t) + sizeof(srtp_auth_t));
    if (pointer == NULL) {
        return srtp_err_status_alloc_fail;
    }

    /* set pointers */
    *a = (srtp_auth_t*)pointer;
    (*a)->type = &srtp_hmac_sm3;
    (*a)->state = pointer + sizeof(srtp_auth_t);
    (*a)->out_len = out_len;
    (*a)->key_len = key_len;
    (*a)->prefix_len = 0;

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_sm3_dealloc (srtp_auth_t *a)
{
    /* zeroize entire state*/
    octet_string_set_to_zero(a, sizeof(srtp_hmac_sm3_ctx_t) + sizeof(srtp_auth_t));

    /* free memory */
    srtp_crypto_free(a);

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_sm3_init (void *statev, const uint8_t *key, int key_len)
{
    srtp_hmac_sm3_ctx_t *ctx = (srtp_hmac_sm3_ctx_t *)statev;
    int i;
    uint8_t ipad[64];

    /*
     * check key length - note that we don't support keys larger
     * than 20 bytes yet
     */
    if (key_len > 32) {
        return srtp_err_status_bad_param;
    }

	if (key_len <= SM3_BLOCK_SIZE) {
		memcpy(ctx->key, key, key_len);
		memset(ctx->key + key_len, 0, SM3_BLOCK_SIZE - key_len);
	} else
	{
		sm3_init(&ctx->sm3_init_ctx);
		sm3_update(&ctx->sm3_init_ctx, key, key_len);
		sm3_final(&ctx->sm3_init_ctx, ctx->key);
		memset(ctx->key + SM3_DIGEST_LENGTH, 0, SM3_BLOCK_SIZE - SM3_DIGEST_LENGTH);
	}

    /*
     * set values of ipad and opad by exoring the key into the
     * appropriate constant values
     */
    for (i = 0; i < key_len; i++) {
        ipad[i] = key[i] ^ 0x36;
        ctx->opad[i] = key[i] ^ 0x5c;
    }
    /* set the rest of ipad, opad to constant values */
    for (; i < 64; i++) {
        ipad[i] = 0x36;
        ((uint8_t*)ctx->opad)[i] = 0x5c;
    }

    debug_print(srtp_mod_hmac_sm3, "ipad: %s", srtp_octet_string_hex_string(ipad, 64));

    /* initialize sha1 context */
    sm3_init(&ctx->sm3_init_ctx);

    /* hash ipad ^ key */
    sm3_update(&ctx->sm3_init_ctx, ipad, 64);
    memcpy(&ctx->sm3_ctx, &ctx->sm3_init_ctx, sizeof(sm3_ctx_t));

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_sm3_start (void *statev)
{
    srtp_hmac_sm3_ctx_t *ctx = (srtp_hmac_sm3_ctx_t *)statev;

    memcpy(&ctx->sm3_ctx, &ctx->sm3_init_ctx, sizeof(sm3_ctx_t));

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_sm3_update (void *statev, const uint8_t *message, int msg_octets)
{
    srtp_hmac_sm3_ctx_t *ctx = (srtp_hmac_sm3_ctx_t *)statev;

    debug_print(srtp_mod_hmac_sm3, "input: %s",
                srtp_octet_string_hex_string(message, msg_octets));

    /* hash message into sha1 context */
    sm3_update(&ctx->sm3_ctx, message, msg_octets);

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_sm3_compute (void *statev, const uint8_t *message,
                                            int msg_octets, int tag_len, uint8_t *result)
{
    srtp_hmac_sm3_ctx_t *ctx = (srtp_hmac_sm3_ctx_t *)statev;
    uint32_t hash_value[8];
    uint32_t H[8];
    int i;

    /* check tag length, return error if we can't provide the value expected */
    if (tag_len > 32) {
        return srtp_err_status_bad_param;
    }

    /* hash message, copy output into H */
    srtp_hmac_sm3_update(ctx, message, msg_octets);
    sm3_final(&ctx->sm3_ctx, H);

    /*
     * note that we don't need to debug_print() the input, since the
     * function hmac_update() already did that for us
     */
    debug_print(srtp_mod_hmac_sm3, "intermediate state: %s",
                srtp_octet_string_hex_string((uint8_t*)H, 32));

    /* re-initialize hash context */
    sm3_init(&ctx->sm3_ctx);

    /* hash opad ^ key  */
    sm3_update(&ctx->sm3_ctx, (uint8_t*)ctx->opad, 64);

    /* hash the result of the inner hash */
    sm3_update(&ctx->sm3_ctx, (uint8_t*)H, 32);

    /* the result is returned in the array hash_value[] */
    sm3_final(&ctx->sm3_ctx, hash_value);

    /* copy hash_value to *result */
    for (i = 0; i < tag_len; i++) {
        result[i] = ((uint8_t*)hash_value)[i];
    }

    debug_print(srtp_mod_hmac_sm3, "output: %s",
                srtp_octet_string_hex_string((uint8_t*)hash_value, tag_len));

    return srtp_err_status_ok;
}


/* begin test case 0 */

static const uint8_t srtp_hmac_sm3_test_case_0_key[32] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

static const uint8_t srtp_hmac_sm3_test_case_0_data[8] = {
    0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65 /* "Hi There" */
};

static const uint8_t srtp_hmac_sm3_test_case_0_tag[32] = {
	0xc0, 0xba, 0x18, 0xc6, 0x8b, 0x90, 0xc8, 0x8b,
	0xc0, 0x7d, 0xe7, 0x94, 0xbf, 0xc7, 0xd2, 0xc8,
	0xd1, 0x9e, 0xc3, 0x1e, 0xd8, 0x77, 0x3b, 0xc2,
	0xb3, 0x90, 0xc9, 0x60, 0x4e, 0x0b, 0xe1, 0x1e
};

static const srtp_auth_test_case_t srtp_hmac_sm3_test_case_0 = {
    32,                         /* octets in key            */
    srtp_hmac_sm3_test_case_0_key,  /* key                      */
    8,                          /* octets in data           */
    srtp_hmac_sm3_test_case_0_data, /* data                     */
    32,                         /* octets in tag            */
    srtp_hmac_sm3_test_case_0_tag,  /* tag                      */
    NULL                        /* pointer to next testcase */
};

/* end test case 0 */

static const char srtp_hmac_sm3_description[] = "hmac sm3 authentication function";

/*
 * srtp_auth_type_t hmac is the hmac metaobject
 */

const srtp_auth_type_t srtp_hmac_sm3  = {
    srtp_hmac_sm3_alloc,
    srtp_hmac_sm3_dealloc,
    srtp_hmac_sm3_init,
    srtp_hmac_sm3_compute,
    srtp_hmac_sm3_update,
    srtp_hmac_sm3_start,
    srtp_hmac_sm3_description,
    &srtp_hmac_sm3_test_case_0,
    SRTP_HMAC_SM3
};

