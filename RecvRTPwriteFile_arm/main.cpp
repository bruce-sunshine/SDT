#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include "H264Decoder.h"
#include <mcheck.h>
extern "C"
{
#include "srtp2/auth.h"
#include "srtp2/cipher.h"
#include "srtp2/crypto_types.h"
#include "srtp2/srtp.h"
}

unsigned char pKey[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
#define  BASEPORT 9000


void set_Enc_pad(unsigned char* buf, unsigned int enc_len, unsigned char *pad_len)
{
	int i;
	*pad_len = 16 - (enc_len % 16);
	for(i = 0; i < *pad_len - 1; i++)
		*(buf + enc_len + i) = 0xaf;
	*(buf + enc_len + i) = (*pad_len) & 0x1f;
}

bool check_Dec_pad(unsigned char* buf, unsigned int enc_len, unsigned char *pad_len)
{
	int i;
	*pad_len = *(buf + enc_len - 1) & 0x1f;
	i = 0;
	while(i < *pad_len - 1)
	{
		if(*(buf + enc_len - 2 - i) != 0xaf)
		{
			*pad_len = 0;
			return false;
		}
		i++;
	}
	return true;
}


int main(int argc,char* argv[])
{
//	setenv("MALLOC_TRACE", "mtrace_dec", 1);
//	mtrace();

	int portIndex =0;

	if (argc >1)
	{
		portIndex = atoi(argv[1]);
	}
	H264Decoder h264Decoder(BASEPORT+2*portIndex);

	int sockSrv = socket(AF_INET,SOCK_DGRAM, 0);

	struct sockaddr_in addrServ;

	int value =0;
	socklen_t valSize = sizeof(value);


//	addrServ.sin_addr.s_addr = htonl(INADDR_ANY);
	addrServ.sin_addr.s_addr = inet_addr(argv[1]);
	addrServ.sin_family = AF_INET;
	addrServ.sin_port = htons(atoi(argv[2]));
	bind(sockSrv,(struct sockaddr *)&addrServ,sizeof(struct sockaddr_in));
	getsockopt(sockSrv, SOL_SOCKET, SO_RCVBUF,(char *)&value, &valSize);
	value = 16384*4;
	setsockopt(sockSrv, SOL_SOCKET, SO_RCVBUF,(char *)&value, sizeof(value));
	value =0;
	getsockopt(sockSrv, SOL_SOCKET, SO_RCVBUF,(char *)&value, &valSize);
	printf("socket size: %d\n",value);

	int length = sizeof(struct sockaddr);

	unsigned char*  recvBuf;
	unsigned flags = 0;
	int recvBufLength = 0;
	int len =10000;
	recvBuf=(unsigned char*)malloc(len); 
	//DWORD fionbio =1;
	//ioctlsocket(sockSrv, FIONBIO, &fionbio);

	//	init srtp
		srtp_err_status_t err;
		srtp_policy_t policyIn;
		srtp_ctx_t	*ctxIn;
		/* initialize srtp library */
		err = srtp_init();
		if (err)
		{
			printf("error: srtp init failed with error code %d\n", err);
			exit(1);
		}

		memset(&policyIn, 0, sizeof(srtp_policy_t));
//		srtp_crypto_policy_set_soft_sm4_cbc(&policyIn.rtp);
		srtp_crypto_policy_set_soft_sm4_cbc_hmac_sm3(&policyIn.rtp);
//		srtp_crypto_policy_set_sdt_skf_hy_sm4_ecb(&policyIn.rtp);
//		srtp_crypto_policy_set_sdt_skf_sm4_cbc(&policyIn.rtp);
//		srtp_crypto_policy_set_null_cipher_hmac_null(&policyIn.rtp);
//		srtp_crypto_policy_set_rtp_default(&policyIn.rtp);
//		srtp_crypto_policy_set_rtcp_default(&policyIn.rtcp);
		bool created_in = false;
		unsigned char pad_len_out;
		int recv_count=0;
	while (1)
	{
		flags = 0;
		//memset(recvBuf,0,len);



		memset(recvBuf,0,len);
		recvBufLength = recvfrom(sockSrv, (char*)recvBuf, len, 0, (struct sockaddr*)(&addrServ), (socklen_t *)&length);
//		++recv_count;
//		if(recv_count == 50050)
//			break;
//		printf("recvBufLength = %d\n", recvBufLength);
		if (recvBufLength < 0)
		{
			printf("*****recvBufLength < 0");
			continue;

		}

		if(!created_in)
		{
			RTPFrame getRTP((unsigned char*)recvBuf, recvBufLength);
			policyIn.ssrc.type = ssrc_any_inbound;
			policyIn.ssrc.value = getRTP.GetSSRC();
			policyIn.key = (unsigned char*)pKey;
			policyIn.ekt = NULL;
			policyIn.next = NULL;
			policyIn.window_size = 128;
			policyIn.allow_repeat_tx = 0;
			policyIn.rtp.sec_serv =(srtp_sec_serv_t)(sec_serv_conf_and_auth);
//			policyIn.rtcp.sec_serv = sec_serv_conf_and_auth;

			err = srtp_create(&ctxIn, &policyIn);
			if(err != srtp_err_status_ok)
			{
				printf("\nsrtp created failed %d\n", err);
			}else
			{
				printf("\n\nsrtp created ok\n");
			}
			created_in = true;
			printf("ssrc = %ld\n",getRTP.GetSSRC());
		}
		//pad the payload to align 16 bytes

		if(created_in)
		{
//			int before_len = recvBufLength;
//			printf("recvBufLength = %d\n", recvBufLength);
			err = ::srtp_unprotect(ctxIn, recvBuf, &recvBufLength);
			if (err != srtp_err_status_ok)
			{
				printf("\nsrtp unprotected failed Out, err= %d\n", err);
				continue;
			}
//			int after_len = recvBufLength;
//			printf("srtp_unprotect, before_len = %d, after_len = %d\n", before_len, after_len);
			pad_len_out= 0;
			if(check_Dec_pad(recvBuf, recvBufLength, &pad_len_out) == true)
			{
				if(pad_len_out > 16)
				{
					printf("check_Dec_pad len > 16 \n");
					exit(-1);

				}
//				if(pad_len_out == 16)
//					printf("check_Dec_pad len = 16 \n");
				recvBufLength -= pad_len_out;
			}
			else
			{
//				printf("check_Dec_pad error----\n");
			}

			h264Decoder.Transcode(recvBuf,recvBufLength,flags);
		}
		/*RTPFrame recvRTP(recvBuf, recvBufLength);*/

		/*
		need to add decrypto code

		*/


	}
	srtp_dealloc(ctxIn);
	err = srtp_shutdown();
	if (err) {
		printf("error: srtp shutdown failed with error code %d\n", err);
		exit(1);
	}

	free(recvBuf);

	close(sockSrv);

	return 0;
}
