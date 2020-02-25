#ifndef HMAC_SM3_H
#define HMAC_SM3_H

#include "auth.h"
#include "sm3.h"

//typedef struct {
//    uint8_t opad[64];
//    sm3_ctx_t ctx;
//    sm3_ctx_t init_ctx;
//} srtp_hmac_sm3_ctx_t;

typedef struct {
	uint8_t opad[64];
	sm3_ctx_t sm3_ctx;
	sm3_ctx_t sm3_init_ctx;
	unsigned char key[SM3_BLOCK_SIZE];
} srtp_hmac_sm3_ctx_t;

#endif /* HMAC_SM3_H */

