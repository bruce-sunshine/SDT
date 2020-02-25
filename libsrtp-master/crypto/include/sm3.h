#ifndef SM3_H
#define SM3_H

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

#ifdef __cplusplus
extern "C" {
#endif

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

void sm3_compress(uint32_t digest[8], const unsigned char block[64]);
void sm3_init(sm3_ctx_t *ctx);
void sm3_update(sm3_ctx_t *ctx, const unsigned char* data, size_t data_len);
void sm3_final(sm3_ctx_t *ctx, unsigned char *digest);
void sm3(const unsigned char *msg, size_t msglen, unsigned char dgst[SM3_DIGEST_LENGTH]);


#ifdef __cplusplus
}
#endif

#endif
