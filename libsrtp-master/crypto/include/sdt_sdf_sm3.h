/*
 * sha1.h
 *
 * interface to the Secure Hash Algorithm v.1 (SHA-1), specified in
 * FIPS 180-1
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

#ifndef SDT_SDF_SM3_H
#define SDT_SDF_SM3_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "err.h"
#ifdef OPENSSL
#include <openssl/evp.h>
#include <stdint.h>
#else
#include "datatypes.h"
#endif

#include "swsds.h"
#ifdef __cplusplus
extern "C" {
#endif

#define SDT_SDF_SM3_DIGEST_LENGTH 32

typedef struct sdt_sdf_sm3_st {
	SGD_HANDLE device_handle;
	SGD_HANDLE session_sm3;
} srtp_sdt_sdf_sm3_ctx;


/*
 * srtp_sha1_init(&ctx) initializes the SHA1 context ctx
 *
 * srtp_sha1_update(&ctx, msg, len) hashes the len octets starting at msg
 * into the SHA1 context
 *
 * srtp_sha1_final(&ctx, output) performs the final processing of the SHA1
 * context and writes the result to the 20 octets at output
 *
 */
void srtp_sdt_sdf_sm3_init(srtp_sdt_sdf_sm3_ctx *ctx);

void srtp_sdt_sdf_sm3_update(srtp_sdt_sdf_sm3_ctx *ctx, const uint8_t *M, int octets_in_msg);

void srtp_sdt_sdf_sm3_final(srtp_sdt_sdf_sm3_ctx * ctx, uint32_t output[8]);


#ifdef __cplusplus
}
#endif

#endif /* SDT_SDF_SM3_H */
