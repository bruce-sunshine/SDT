#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <list>
#include <numeric>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include "H264Encoder.h"
#include <mcheck.h>
//#include "swsds.h"
//#include "util.h"
#include "memwatch.h"



extern "C"
{
#include "srtp2/auth.h"
#include "srtp2/cipher.h"
#include "srtp2/crypto_types.h"
#include "srtp2/srtp.h"
}
#define new mwNew
#define delete mwDelete

unsigned char pKey[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

using namespace std;

#define socketNum 1
#define packetNum 200
#define basePort 9000
enum PluginCodec_CoderFlags {
	PluginCodec_CoderSilenceFrame      = 1,    // request audio codec to create silence frame
	PluginCodec_CoderForceIFrame       = 2     // request video codec to force I frame
};

H264Encoder h264Encoder;
int m_totalFrames =0;
list<RTPFrame> rtpFrameList;
int sockClient;
int seqNum = 0;

//info about JMK
//SGD_HANDLE device_handle; /*全局设备句柄*/

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

bool getRTPList(RTPFrame dstRTP)
{
	unsigned flags;
	unsigned int toLen = dstRTP.GetFrameLen();
	flags = forceIFrame || m_totalFrames == 0 ? PluginCodec_CoderForceIFrame : 0;
	h264Encoder.Transcode(dstRTP.GetFrame(), toLen, flags);
	dstRTP.SetFrameLen (toLen) ;
//	dstRTP.SetPadding(1);
	dstRTP.SetVersion(2);
	dstRTP.SetPayloadType(96);
	dstRTP.SetSequenceNumber(htons(seqNum));
	dstRTP.SetSSRC(1);
	rtpFrameList.push_back(dstRTP);
	seqNum=(seqNum+1)%65536;

	return dstRTP.GetMarker();
}

int main(int argc,char* argv[])
{
//	setenv("MALLOC_TRACE", "mtrace_enc", 1);
//	mtrace();

	fprintf(stderr, "pid=%d\n", getpid());//新添加
	int portIndex =0;
	if (argc >1)
	{
		portIndex = atoi(argv[2]);
	}
#if 0
//api about JMK
	SGD_HANDLE session_handle;
	DEVICEINFO dev_info;
	SGD_HANDLE hKeyHandle;
	SGD_UINT32 uiKeyIndex = 1;
	int rv;
	if(SDR_OK!=(rv=SDF_OpenDevice(&device_handle)))
	{
		printf("open device failed, error code=[0x%08x]\n",rv);
		return -1;
	}
	if(SDR_OK!=(rv=SDF_OpenSession(device_handle, &session_handle)))
	{
		printf("open session failed, error code=[0x%08x]\n",rv);
		return -1;
	}

	if(SDR_OK!=(rv=SDF_GetDeviceInfo(session_handle, &dev_info)))
	{
		printf("get dev_info failed, error code=[0x%08x]\n",rv);
		return -1;
	}
//
	cout<< "IssuerName=" << dev_info.IssuerName <<"\n"
		<< "DeviceName=" << dev_info.DeviceName <<"\n"
		<< "DeviceSerial=" << dev_info.DeviceSerial <<"\n"
		<< "DeviceVersion=" << dev_info.DeviceVersion <<endl;
//end


	if(SDR_OK!=(rv=SDF_GetSymmKeyHandle(session_handle, 1, &hKeyHandle)))
	{
		printf("GetSymmKeyHandle_1 failed, error code=[0x%08x]\n",rv);
		return -1;
	}

	if(SDR_OK!=(rv=SDF_DestroyKey(session_handle, hKeyHandle)))
	{
		printf("DestroyKey failed, error code=[0x%08x]\n",rv);
		return -1;
	}

	if(SDR_OK!=(rv=SDF_GetSymmKeyHandle(session_handle, 1, &hKeyHandle)))
	{
		printf("GetSymmKeyHandle_2 failed, error code=[0x%08x]\n",rv);
		return -1;
	}

	unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	if(SDR_OK!=(rv=SDF_ImportKey(session_handle, pbKeyValue, 16, &hKeyHandle)))
	{
		printf("ImportKey failed, error code=[0x%08x]\n",rv);
		return -1;
	}

#endif


	struct sockaddr_in  addrServ;
	sockClient = socket(AF_INET,SOCK_DGRAM, 0);
	addrServ.sin_addr.s_addr = inet_addr(argv[1]);
	addrServ.sin_family = AF_INET;
	addrServ.sin_port = htons(atoi(argv[2]));

	unsigned char* dst[packetNum];
	int packetCount = 0;
	list<RTPFrame>::iterator interFrame;

	for (int i = 0;i < packetNum;i++)
	{
		dst[i] =(unsigned char*)malloc(1500);
	}
#if 0
// api about JMK, test the correctness of symcrypto
	unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	unsigned char pbPlainText[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	unsigned char pbCipherText[16] = {0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};
	unsigned char pbTempData[128] = {0};
	unsigned int  ulTempDataLen;
	unsigned char pbOutData[128] = {0};
	unsigned int  ulOutDataLen;

	rv = SDF_ImportKey(session_handle, pbKeyValue, 16, &hKeyHandle);
	if(rv != SDR_OK)
	{
		printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
	}

	unsigned char pIv[16];
	memset(pIv, 0, 16);
	unsigned int  nInlen = 16;

	memset(pbTempData, 0, sizeof(pbTempData));
	ulTempDataLen = sizeof(pbTempData);

	rv = SDF_Encrypt(session_handle, hKeyHandle, SGD_SMS4_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);

	for(int i=0; i < ulTempDataLen; i++)
	{
		printf("0x%02x,", pbTempData[i]);
	}
	printf("\n");

	if(rv == 0)
	{
		if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
		{
			;
		}
		else
		{
			SDF_DestroyKey(session_handle, hKeyHandle);

			printf("运算结果：加密密文与标准密文数据比较失败。\n");
			printf("\n按任意键继续...");
		}

		memset(pIv, 0, 16);
		memset(pbOutData, 0, sizeof(pbOutData));
		ulOutDataLen = sizeof(pbOutData);
		rv = SDF_Decrypt(session_handle, hKeyHandle, SGD_SMS4_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
		if(rv == 0)
		{
			if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
			{
				printf("标准数据加密、解密及结果比较均正确。\n");
				SDF_DestroyKey(session_handle, hKeyHandle);
			}
			else
			{
				SDF_DestroyKey(session_handle, hKeyHandle);

				printf("运算结果：解密后结果与标准明文数据比较失败。\n");
				printf("\n按任意键继续...");
			}
		}
		else
		{
			SDF_DestroyKey(session_handle, hKeyHandle);

			printf("运算结果：解密错误，[%08x]\n", rv);
			printf("\n按任意键继续...");
		}
	}
	else
	{
		SDF_DestroyKey(session_handle, hKeyHandle);

		printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
	}
#endif
	unsigned char e_Iv[16], d_Iv[16];
	memset(e_Iv, 0, 16);
	memset(d_Iv, 0, 16);

	unsigned char inputData[1500] = {0};
	int  inputDataLen;
	unsigned char encyrpt_Data[1500] = {0};
	int  encyrpt_DataLen;
	unsigned char outputData[1500] = {0};
	unsigned int  outputDataLen;
//end
	int payload_len;
	unsigned char pad_len_in= 0;
	unsigned char pad_len_out=0;

	int enc_err_count = 0;
	int dec_err_count = 0;

	int send_count=0;
//	init srtp
	srtp_err_status_t err;
	srtp_policy_t policyOut;
	srtp_ctx_t	*ctxOut;

//	initialize srtp library
	err = srtp_init();
	if (err)
	{
		printf("error: srtp init failed with error code %d\n", err);
		exit(1);
	}

	memset(&policyOut, 0, sizeof(srtp_policy_t));
//	srtp_crypto_policy_set_sdt_skf_hy_sm4_ecb(&policyOut.rtp);

	srtp_crypto_policy_set_soft_sm4_cbc_hmac_sm3(&policyOut.rtp);
//	srtp_crypto_policy_set_sdt_skf_sm4_cbc(&policyOut.rtp);
//	srtp_crypto_policy_set_rtp_default(&policyOut.rtp);
//	srtp_crypto_policy_set_rtcp_default(&policyOut.rtcp);

	bool created_out = false;
	while (1)
	{
		memset(dst[packetCount], 0, 1500);
		RTPFrame dstRTP(dst[packetCount], 1300);
		packetCount++;
		if(getRTPList(dstRTP))
		{
			packetCount =0;
			for (interFrame = rtpFrameList.begin(); interFrame != rtpFrameList.end(); ++interFrame)
			{
				if(!created_out)
				{
					policyOut.ssrc.type = ssrc_any_outbound;
					policyOut.ssrc.value = interFrame->GetSSRC();
					policyOut.key = (unsigned char*)pKey;
					policyOut.ekt = NULL;
					policyOut.next = NULL;
					policyOut.window_size = 128;
					policyOut.allow_repeat_tx = 0;
					policyOut.rtp.sec_serv =(srtp_sec_serv_t)( sec_serv_conf_and_auth);
//					policyOut.rtcp.sec_serv = sec_serv_conf_and_auth;
					err = srtp_create(&ctxOut, &policyOut);
					if(err != srtp_err_status_ok)
					{
						printf("\nsrtp created failed %d\n", err);
					}else
					{
						printf("\n\nsrtp created ok \n");
					}
					created_out = true;
					printf("ssrc = %ld\n",interFrame->GetSSRC());
				}
				//pad the payload to align 16 bytes

				if(created_out)
				{
					inputDataLen = interFrame->GetPayloadSize();
//					printf("inputDataLen = %d\n", inputDataLen);
					pad_len_in = 0;
//					if(inputDataLen % 16 != 0)
//					{
						set_Enc_pad(interFrame->GetPayloadPtr(), inputDataLen, &pad_len_in);
						inputDataLen += pad_len_in;
//					}
					interFrame->SetPayloadSize(inputDataLen);
					encyrpt_DataLen = interFrame->GetFrameLen();
//					int before_len = encyrpt_DataLen;
//					printf("encyrpt_DataLen = %d\n", encyrpt_DataLen);
					err = ::srtp_protect(ctxOut, interFrame->GetFrame(), &encyrpt_DataLen);
					if(encyrpt_DataLen < 30)
					{
						printf("encyrpt_DataLen = %d, inputDataLen = %d, pad_len_in = %d\n", encyrpt_DataLen, inputDataLen, pad_len_in);
//						exit(0);
					}
//					int after_len = encyrpt_DataLen;
//					if(before_len != after_len)
//						printf("srtp_protect, before_len = %d, after_len = %d\n", before_len, after_len);
					if (err != srtp_err_status_ok)
					{
						printf("\nsrtp protected failed Out, err= %d\n", err);
						continue;
					}

					//				memset(inputData, 0, sizeof(inputData));
					//				inputDataLen = sizeof(inputData);
					//				memcpy(inputData, interFrame->GetPayloadPtr(),interFrame->GetPayloadSize());
					//				inputDataLen = interFrame->GetPayloadSize();
					//				//encrypto the frame before send out
					//
					//				pad_len_in = 0;
					//				if(inputDataLen % 16 != 0)
					//				{
					//					set_Enc_pad(inputData, inputDataLen, &pad_len_in);
					//					inputDataLen += pad_len_in;
					//				}
					//
					////				printf("inputDataLen = %d, pad_len_in = %d\n", inputDataLen, pad_len_in);
					//
					//
					//				memset(encyrpt_Data, 0, sizeof(encyrpt_Data));
					//				encyrpt_DataLen = sizeof(encyrpt_Data);
					//				rv = SDF_Encrypt(session_handle, hKeyHandle, SGD_SMS4_ECB, e_Iv, inputData, inputDataLen, encyrpt_Data, &encyrpt_DataLen);
					//				if(SDR_OK != rv)
					//				{
					//					printf("encrypto frame error，错误码[0x%08x], enc_err_count = %d\n", rv, ++enc_err_count);
					//					// if occur error, drop it
					//					continue;
					////					SDF_DestroyKey(session_handle, hKeyHandle);
					////
					//				}
					//
					//				memset(outputData, 0, sizeof(outputData));
					//				outputDataLen = sizeof(outputData);
					//				rv = SDF_Decrypt(session_handle, hKeyHandle, SGD_SMS4_ECB, d_Iv, encyrpt_Data, encyrpt_DataLen, outputData, &outputDataLen);
					//				if(SDR_OK != rv)
					//				{
					//					printf("decrypto frame error，错误码[0x%08x], dec_err_count = %d\n", rv, ++dec_err_count);
					//					continue;
					////					SDF_DestroyKey(session_handle, hKeyHandle);
					//
					//				}
					//
					//				pad_len_out= 0;
					//				if(check_Dec_pad(outputData, outputDataLen, &pad_len_out) == true)
					//				{
					//					outputDataLen -= pad_len_out;
					//				}
					////				printf("outputDataLen = %d, pad_len_in = %d\n", outputDataLen+pad_len_out, pad_len_out);
					//				//end
					//				if(pad_len_in != pad_len_out)
					//				{
					//					printf("check pad error\n");
					//					return -1;
					//				}
					////				printf("encrypt_DataLen = %d, decrypt_DataLen = %d\n", encyrpt_DataLen, outputDataLen);
					////				sendto(sockClient, (char *)outputData, outputDataLen, 0 , (struct sockaddr*)(&addrServ), sizeof(addrServ));
					//				memcpy(interFrame->GetPayloadPtr(),outputData,outputDataLen);

					sendto(sockClient,(char *)interFrame->GetFrame(),encyrpt_DataLen, 0 , (struct sockaddr*)(&addrServ), sizeof(addrServ));
					//				printf("send len = %d\n", interFrame->GetFrameLen());
					//				usleep(100000);
//					++send_count;
//					if(send_count == 50050)
//						break;
				}
			}
			usleep(16666);
//			if(send_count == 50050)
//				break;
			rtpFrameList.clear();

		}
	}
	for (int i = 0;i < packetNum;i++)
	{
		free(dst[i]);
	}
	srtp_dealloc(ctxOut);
	err = srtp_shutdown();
	if (err) {
		printf("error: srtp shutdown failed with error code %d\n", err);
		exit(1);
	}
#if 0
	SDF_CloseSession(session_handle);
	SDF_CloseDevice(device_handle);
#endif
	return 1;

}
