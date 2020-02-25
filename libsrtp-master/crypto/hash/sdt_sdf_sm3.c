/*
 * sha1.c
 *
 * an implementation of the Secure Hash Algorithm v.1 (SHA-1),
 * specified in FIPS 180-1
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "sdt_sdf_sm3.h"

srtp_debug_module_t srtp_mod_sdt_sdf_sm3 = {
    0,               /* debugging is off by default */
    "sdt_sdf_sm3"          /* printable module name       */
};

void srtp_sdt_sdf_sm3 (const uint8_t *msg,  int octets_in_msg, uint32_t hash_value[8])
{
	srtp_sdt_sdf_sm3_ctx ctx;

	srtp_sdt_sdf_sm3_init(&ctx);
	srtp_sdt_sdf_sm3_update(&ctx, msg, octets_in_msg);
	srtp_sdt_sdf_sm3_final(&ctx, hash_value);

}

void srtp_sdt_sdf_sm3_init (srtp_sdt_sdf_sm3_ctx *ctx)
{
	if(SDR_OK!=SDF_OpenSession(ctx->device_handle, &(ctx->session_sm3)))
	{
		printf("sdt_sdf_sm3, open session failed\n");
		return;
	}
	if(SDR_OK!=SDF_HashInit(ctx->session_sm3, SGD_SM3, NULL, NULL, 0))
	{
		printf("sdt_sdf_sm3, hash init failed\n");
		return;
	}
}

void srtp_sdt_sdf_sm3_update (srtp_sdt_sdf_sm3_ctx *ctx, const uint8_t *msg, int octets_in_msg)
{
	if(SDR_OK!=SDF_HashUpdate(ctx->session_sm3, (unsigned char *)msg, octets_in_msg))
	{
		printf("sdt_sdf_sm3, hash update failed\n");
		return;
	}
}

void srtp_sdt_sdf_sm3_final (srtp_sdt_sdf_sm3_ctx *ctx, uint32_t *output)
{
	unsigned int nOutlen;
	if(SDR_OK!= SDF_HashFinal(ctx->session_sm3, output, &nOutlen))
	{
		printf("sdt_sdf_sm3, hash final failed\n");
		return ;
	}
	if(nOutlen != SDT_SDF_SM3_DIGEST_LENGTH)
	{
		printf("sdt_sdf_sm3, hash final len do not match SDT_SDF_SM3_DIGEST_LENGTH\n");
		return ;
	}

	SDF_CloseSession(ctx->session_sm3);
	ctx->session_sm3 = NULL;

	if(ctx->device_handle !=NULL)
	{
		SDF_CloseDevice(ctx->device_handle);
		ctx->device_handle = NULL;
	}

    return;
}



