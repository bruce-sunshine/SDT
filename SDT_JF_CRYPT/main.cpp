#include <pthread.h>
#include "ShMemRWInterface.h"
#include "main.h"

unsigned char pKey[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

static int signal_sock, audio_sock, video_sock, kdpfd;
static struct sockaddr_in signal_recv_addr, audio_recv_addr, video_recv_addr;
static struct sockaddr_in signal_send_addr, audio_send_addr, video_send_addr;
static uint32_t audio_send_Seq = 0;
static uint32_t audio_recv_Seq = 0;
static uint32_t video_send_Seq = 0;
static uint32_t video_recv_Seq = 0;
static FILE *fp = NULL;
pthread_t thread_audio, thread_video;
pthread_attr_t attr_audio, attr_video;
ENGINE* sdt_engine = NULL;
struct epoll_event ev_signal, ev_accept, ev_audio, ev_video;
struct epoll_event events[MAXEPOLLSIZE];

bool srtp_init_ok = false;
srtp_policy_t audio_policyIn, audio_policyOut, video_policyIn, video_policyOut, video_aux_policyIn, video_aux_policyOut;
srtp_ctx_t *audio_ctxIn, *audio_ctxOut, *video_ctxIn, *video_ctxOut, *video_aux_ctxIn, *video_aux_ctxOut;
bool createIn_audio  = false;
bool createOut_audio = false;
bool createIn_video  = false;
bool createOut_video = false;
bool createauxIn_video = false;
bool createauxOut_video = false;

void set_Enc_pad( char* buf, unsigned int enc_len, unsigned char *pad_len)
{
	int i;
	*pad_len = 16 - (enc_len % 16);
	for(i = 0; i < *pad_len - 1; i++)
		*(buf + enc_len + i) = 0xaf;
	*(buf + enc_len + i) = (*pad_len) & 0x1f;
}

bool check_Dec_pad( char* buf, unsigned int enc_len, unsigned char *pad_len)
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

void tarnsferRtpheader_to_jf(JfRtpHeadDef* jf_header)
{
	JfRtpHeadDef jfhead;
	RtpHeadDef* header = (RtpHeadDef*)jf_header;
	jfhead.ulSeq  		= header->seq;
	jfhead.bit7PT		= header->payload;
	jfhead.bit1M  		= header->marker;
	jfhead.bit4CC 		= header->csrc_len;
	jfhead.bit1X  		= header->extension;
	jfhead.bit1P  		= header->padding;
	jfhead.bit2V  		= header->version;
	jfhead.ulTimeStamp 	= header->timestamp;
	jfhead.ulSSRC 		= header->ssrc;
	memcpy(jf_header, &jfhead, sizeof(JfRtpHeadDef));
}

void tarnsferjfRtpheader_to_normal(JfRtpHeadDef* jf_header)
{
	RtpHeadDef head;
	head.seq 		= jf_header->ulSeq;
	head.payload 	= jf_header->bit7PT;
	head.marker  	= jf_header->bit1M;
	head.csrc_len 	= jf_header->bit4CC;
	head.extension 	= jf_header->bit1X;
	head.padding 	= jf_header->bit1P;
	head.version 	= jf_header->bit2V;
	head.timestamp 	= jf_header->ulTimeStamp;
	head.ssrc 		= jf_header->ulSSRC;
	memcpy(jf_header, &head, sizeof(RtpHeadDef));
}


int Init_sdt_engine()
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	ENGINE_load_dynamic();

	sdt_engine = ENGINE_by_id("sdt_skf_sd_hy_engine");	//use huashen usbkey for ssl hard encrypt/decrypt

	if( sdt_engine == NULL )
	{
		printf("SSL Could not Load sdt_skf_engine, use soft algorithm !\n");
		return -1;
	}
	else
	{
		printf("SSL sdt_skf_engine successfully loaded\n");
		int er;
		er = ENGINE_init(sdt_engine);
		if(!er)
		{
			printf("Engine init failed\n");
			sdt_engine = NULL;
			return -1;
		}
		printf("Engine name: %s init result : %d \n", ENGINE_get_name(sdt_engine), er);

		printf("hd_sd_hy_ssl = 0x%08x, get_hd_ssl = %d\n",
				ENGINE_get_ex_data(sdt_engine, 2), *((int*)(ENGINE_get_ex_data(sdt_engine, 1))));

//		set_hy_sd_handle(ENGINE_get_ex_data(sdt_engine, 2), (int*)(ENGINE_get_ex_data(sdt_engine, 1)));

		er = ENGINE_set_default_digests(sdt_engine);
		if(!er)
		{
			printf("ENGINE_set_default_digests failed\n");
			sdt_engine = NULL;
			return -1;
		}
//		printf("ENGINE SETTING DEFAULT DIGESTS %d\n",er);

		er = ENGINE_set_default_ciphers(sdt_engine);
		if(!er)
		{
			printf("ENGINE_set_default_ciphers failed\n");
			sdt_engine = NULL;
			return -1;
		}
//		printf("ENGINE SETTING DEFAULT ciphers %d\n",er);

		er = ENGINE_set_default_EC(sdt_engine);
		if(!er)
		{
			printf("ENGINE_set_default_EC failed\n");
			sdt_engine = NULL;
			return -1;
		}
//		printf("ENGINE SETTING DEFAULT EC %d\n",er);

		er = ENGINE_set_default_pkey_meths(sdt_engine);
		if(!er)
		{
			printf("ENGINE_set_default_pkey_meths failed\n");
			sdt_engine = NULL;
			return -1;
		}
//		printf("ENGINE SETTING DEFAULT PKEY METHOD %d\n",er);

		er = ENGINE_set_default_RAND(sdt_engine);
		if(!er)
		{
			printf("ENGINE_set_default_RAND failed\n");
			sdt_engine = NULL;
			return -1;
		}
//		printf("ENGINE SETTING DEFAULT RAND %d\n",er);
	}
	printf("Init_sdt_engine ok\n");
	return 0;
}

void Close_sdt_engine()
{
	if(sdt_engine != NULL)
	{
		printf("Close_sdt_engine begin\n");
		ENGINE_finish(sdt_engine);
		ENGINE_free(sdt_engine);
		sdt_engine = NULL;
//		OPENSSL_cleanup();
	}
	printf("Close_sdt_engine ok\n");
}

/*
  setnonblocking – 设置句柄为非阻塞方式
  */
int setnonblocking(int sockfd)
{
	if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0)|O_NONBLOCK) == -1)
	{
		return -1;
	}
	return 0;
}

int Init_Recv_Socket(int* sock_fd, sockaddr_in* addr, int port, int mode)
{
	if ((*sock_fd = socket(AF_INET, mode, 0)) == -1)
	{
		perror("sock create failed ！ \n");
		return -1;
	}
	else
	{
		printf("sock create success ! \n");
	}
	/*设置socket属性，端口可以重用*/
	int opt=SO_REUSEADDR;
	setsockopt(*sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	setnonblocking(*sock_fd);
	bzero(addr, sizeof(*addr));
	(*addr).sin_family = AF_INET;
	(*addr).sin_port = htons(port);
	(*addr).sin_addr.s_addr = inet_addr("127.0.0.1");//INADDR_ANY;
	if (bind(*sock_fd, (struct sockaddr *) addr, sizeof(struct sockaddr)) == -1)
	{
		perror("bind");
		return -1;
	}
	else
	{
		printf(" IP and port %d bind success \n", port);
	}
    if (listen(*sock_fd, 10) == -1)
    {
        perror("listen");
        exit(1);
    }
    else
    	printf("signal 开启 listen 服务成功,！\n");
	return 0;
}

void Close_Recv_Socket(int* sock_fd)
{
	if(*sock_fd != 0)
	{
		shutdown(*sock_fd, SHUT_RD);
		close(*sock_fd);
		*sock_fd = 0;
	}
}

int handle_message(int new_fd)
{
    char buf[2000];
    int len;
    /* 开始处理每个新连接上的数据收发 */
    bzero(buf, sizeof(buf));
    /* 接收客户端的消息 */

    len = recv(new_fd, buf, sizeof(buf), 0);

    if (len > 0)
    {
    	stMeg* meg = (stMeg*)buf;
    	switch(meg->msgID)
    	{
    	case SIGNAL:
    		break;
    	case AUDIO:
    		if(meg->param1)
    		{
    			//encrypt
    		}
    		else
    		{
    			//decrypt
    		}
    		break;
    	case VIDEO:
    		if(meg->param1)
    		{
    			//encrypt
    		}
    		else
    		{
    			//decrypt
    		}
    		break;
    	default:
    		printf("Unknown meg id\n");
    		break;
    	}
    }
    else
    {
        if (len < 0)
            printf("消息接收失败！错误代码是%d，错误信息是'%s'\n",errno, strerror(errno));
        else
            printf("客户端%d退出!\n",new_fd);
        return -1;
    }

	return len;
}

/*
  pthread_handle_message – 线程处理 socket 上的消息收发
  */

int Init_audio_srtp()
 {

	 srtp_err_status_t err;

	 if(srtp_init_ok && !createIn_audio)
	 {
		 memset(&audio_policyIn, 0, sizeof(srtp_policy_t));
		 srtp_crypto_policy_set_soft_sm4_cbc(&audio_policyIn.rtp);
		 audio_policyIn.ssrc.type = ssrc_any_inbound;
		 audio_policyIn.ssrc.value = 10;
		 audio_policyIn.key = (unsigned char*)pKey;
		 audio_policyIn.ekt = NULL;
		 audio_policyIn.next = NULL;
		 audio_policyIn.window_size = 128;
		 audio_policyIn.allow_repeat_tx = 0;
		 audio_policyIn.rtp.sec_serv =(srtp_sec_serv_t)( sec_serv_conf);

		 err = srtp_create(&audio_ctxIn, &audio_policyIn);
		 if(err != srtp_err_status_ok)
		 {
			 printf("\nsrtp audio created In failed %d\n", err);
			 createIn_audio = false;
		 }else
		 {
			 printf("\nsrtp audio created In ok\n");
			 createIn_audio = true;
		 }
		 printf("audio dec ssrc = %d\n", audio_policyIn.ssrc.value);
	 }

	 if(srtp_init_ok && !createOut_audio)
	 {
		 memset(&audio_policyOut, 0, sizeof(srtp_policy_t));
		 srtp_crypto_policy_set_soft_sm4_cbc(&audio_policyOut.rtp);
		 audio_policyOut.ssrc.type = ssrc_any_outbound;
		 audio_policyOut.ssrc.value = 10;
		 audio_policyOut.key = (unsigned char*)pKey;
		 audio_policyOut.ekt = NULL;
		 audio_policyOut.next = NULL;
		 audio_policyOut.window_size = 128;
		 audio_policyOut.allow_repeat_tx = 0;
		 audio_policyOut.rtp.sec_serv =(srtp_sec_serv_t)( sec_serv_conf);

		 err = srtp_create(&audio_ctxOut, &audio_policyOut);
		 if(err != srtp_err_status_ok)
		 {
			 printf("\nsrtp audio created Out failed %d\n", err);
			 createOut_audio = false;
		 }else
		 {
			 printf("\nsrtp audio created Out ok\n");
			 createOut_audio = true;
		 }
		 printf("audio enc ssrc = %d\n", audio_policyOut.ssrc.value);
	 }

	 return 0;
 }

int Init_video_srtp()
 {
	 srtp_err_status_t err;

	 if(srtp_init_ok && !createIn_video)
	 {
		 memset(&video_policyIn, 0, sizeof(srtp_policy_t));
		 srtp_crypto_policy_set_soft_sm4_cbc(&video_policyIn.rtp);
		 video_policyIn.ssrc.type = ssrc_any_inbound;
		 video_policyIn.ssrc.value = 10;
		 video_policyIn.key = (unsigned char*)pKey;
		 video_policyIn.ekt = NULL;
		 video_policyIn.next = NULL;
		 video_policyIn.window_size = 128;
		 video_policyIn.allow_repeat_tx = 0;
		 video_policyIn.rtp.sec_serv =(srtp_sec_serv_t)( sec_serv_conf);

		 err = srtp_create(&video_ctxIn, &video_policyIn);
		 if(err != srtp_err_status_ok)
		 {
			 printf("\nsrtp video created In failed %d\n", err);
			 createIn_video = false;
		 }else
		 {
			 printf("\nsrtp video created In ok\n");
			 createIn_video = true;
		 }
		 printf("video dec ssrc = %d\n", video_policyIn.ssrc.value);
	 }

	 if(srtp_init_ok && !createOut_video)
	 {
		 memset(&video_policyOut, 0, sizeof(srtp_policy_t));
		 srtp_crypto_policy_set_soft_sm4_cbc(&video_policyOut.rtp);
		 video_policyOut.ssrc.type = ssrc_any_outbound;
		 video_policyOut.ssrc.value = 10;
		 video_policyOut.key = (unsigned char*)pKey;
		 video_policyOut.ekt = NULL;
		 video_policyOut.next = NULL;
		 video_policyOut.window_size = 128;
		 video_policyOut.allow_repeat_tx = 0;
		 video_policyOut.rtp.sec_serv =(srtp_sec_serv_t)( sec_serv_conf);

		 err = srtp_create(&video_ctxOut, &video_policyOut);
		 if(err != srtp_err_status_ok)
		 {
			 printf("\nsrtp video created Out failed %d\n", err);
			 createOut_video = false;
		 }else
		 {
			 printf("\nsrtp video created Out ok\n");
			 createOut_video = true;
		 }
		 printf("video enc ssrc = %d\n", video_policyOut.ssrc.value);
	 }
	 return 0;
 }

int Init_aux_video_srtp()
 {
	 srtp_err_status_t err;

	 if(srtp_init_ok && !createauxIn_video)
	 {
		 memset(&video_aux_policyIn, 0, sizeof(srtp_policy_t));
		 srtp_crypto_policy_set_soft_sm4_cbc(&video_aux_policyIn.rtp);
		 video_aux_policyIn.ssrc.type = ssrc_any_inbound;
		 video_aux_policyIn.key = (unsigned char*)pKey;
		 video_aux_policyIn.ekt = NULL;
		 video_aux_policyIn.next = NULL;
		 video_aux_policyIn.window_size = 20480;
		 video_aux_policyIn.allow_repeat_tx = 0;
		 video_aux_policyIn.rtp.sec_serv =(srtp_sec_serv_t)( sec_serv_conf);

		 err = srtp_create(&video_aux_ctxIn, &video_aux_policyIn);
		 if(err != srtp_err_status_ok)
		 {
			 printf("\nsrtp aux video created In failed %d\n", err);
			 createauxIn_video = false;
		 }else
		 {
			 printf("\nsrtp aux video created In ok\n");
			 createauxIn_video = true;
		 }
		 printf("video aux dec ssrc = %d\n", video_aux_policyIn.ssrc.value);
	 }

	 if(srtp_init_ok && !createauxOut_video)
	 {
		 memset(&video_aux_policyOut, 0, sizeof(srtp_policy_t));
		 srtp_crypto_policy_set_soft_sm4_cbc(&video_aux_policyOut.rtp);
		 video_aux_policyOut.ssrc.type = ssrc_any_outbound;
		 video_aux_policyOut.key = (unsigned char*)pKey;
		 video_aux_policyOut.ekt = NULL;
		 video_aux_policyOut.next = NULL;
		 video_aux_policyOut.window_size = 20480;
		 video_aux_policyOut.allow_repeat_tx = 0;
		 video_aux_policyOut.rtp.sec_serv =(srtp_sec_serv_t)( sec_serv_conf);

		 err = srtp_create(&video_aux_ctxOut, &video_aux_policyOut);
		 if(err != srtp_err_status_ok)
		 {
			 printf("\nsrtp aux video created Out failed %d\n", err);
			 createauxOut_video = false;
		 }else
		 {
			 printf("\nsrtp aux video created Out ok\n");
			 createauxOut_video = true;
		 }
		 printf("video aux enc ssrc = %d\n", video_aux_policyOut.ssrc.value);
	 }
	 return 0;
 }

void sdt_srtp_dealloc()
{
//audio
	if(createIn_audio)
	{
		srtp_dealloc(audio_ctxIn);
		audio_ctxIn = NULL;
	}
	if(createOut_audio)
	{
		srtp_dealloc(audio_ctxOut);
		audio_ctxOut = NULL;
	}
	createIn_audio = false;
	createOut_audio = false;

//video
	if(createIn_video)
	{
		srtp_dealloc(video_ctxIn);
		video_ctxIn = NULL;
	}
	if(createOut_video)
	{
		srtp_dealloc(video_ctxOut);
		video_ctxOut = NULL;
	}
	createIn_video = false;
	createOut_video = false;
//aux video
	if(createauxIn_video)
	{
		srtp_dealloc(video_aux_ctxIn);
		video_aux_ctxIn = NULL;
	}
	if(createOut_video)
	{
		srtp_dealloc(video_aux_ctxOut);
		video_aux_ctxOut = NULL;
	}
	createauxIn_video = false;
	createauxOut_video = false;

}

void Write_recv_video(unsigned char *rtp_payload, int rtp_payload_len)
{
	char startcode[4] = { 0, 0, 0, 1 };
	unsigned char nal_ty = *rtp_payload & 0x1f;

	switch (nal_ty)
	{
		case NALU_IDR:
			fwrite(&startcode, 4, 1, fp);
			fwrite(rtp_payload, rtp_payload_len, 1, fp);
			fflush(fp);

			break;
		case NALU_SPS:
		case NALU_NON_IDR:
		case NALU_SEI:
		case NALU_PPS:
			fwrite(&startcode, 4, 1, fp);
			fwrite(rtp_payload, rtp_payload_len, 1, fp);
			fflush(fp);
			break;
		case STAP_A:
		{
			printf("bruce, recv STAP_A packet\n");
			unsigned char *stapA_payload = rtp_payload+1;
			int stapA_payload_len = rtp_payload_len-1;
			char nalu_header;
			char nalu_type;
			unsigned char *data_payload;
			unsigned short int *nalu_len;
			unsigned char nalu_len_seq[2];
			nalu_len = (unsigned short int *)&nalu_len_seq;
			int totallen=0;
			while(stapA_payload_len>0)
			{
				nalu_len_seq[0] = *(stapA_payload+1);
				nalu_len_seq[1] = *(stapA_payload);
				nalu_header = *(stapA_payload+2);
				data_payload = stapA_payload+2;
				nalu_type = nalu_header & 0x1f;

				fwrite(&startcode, 4, 1, fp);
				fwrite(data_payload, *nalu_len, 1, fp);
				fflush(fp);
				totallen += *nalu_len+4;
				stapA_payload += *nalu_len +2 ;
				stapA_payload_len -= (*nalu_len + 2);
			}
		}
		break;
		case FU_A:
		{
			char fuA_identifier = *rtp_payload;
			char fuA_Header = *(rtp_payload+1);
			unsigned char *fuA_data = rtp_payload +2;
			int fuA_len = rtp_payload_len-2;
			char isfuA_firstPacket = fuA_Header & 0x80;
			char nalu_header = (fuA_identifier & 0x60) | (fuA_Header & 0x1f);
			if (isfuA_firstPacket == 0x80)
			{
				fwrite(&startcode, 4, 1, fp);
				fwrite(&nalu_header, 1, 1, fp);
				fflush(fp);
			}
			fwrite(fuA_data, fuA_len, 1, fp);
			fflush(fp);
		}
		break;
		default:
		{
//			printf("unknown write recv video, nal_ty = %d \n", nal_ty);
		}
		break;
	}
}

int media_srtp_handle(SM_DataElem* elem, int mode)
{
	unsigned char pad_len_in = 0;
	unsigned char pad_len_out = 0;
	srtp_err_status_t err;
	char* pl = (char*)(elem + 1);
	int plLen = elem->len - sizeof(SM_DataElem);
//	if((plLen-12) % 16 != 0)
//	{
//		printf("encrypt/decrypt len do not align 16 bytes, plLen = %d\n", plLen-12);
//		return -1;
//	}
	switch(mode)
	{
	case SM_ShMemKey_VidRecv_BefCipher:
		if(createIn_video)
		{
			err = srtp_unprotect(video_ctxIn, pl, &plLen);
			if (err != srtp_err_status_ok)
			{
				printf("\nsrtp video unprotected failed In, err= %d\n", err);
				return -1;
			}
			if(check_Dec_pad(pl + 12, plLen - 12, &pad_len_out) == 1)
			{
				plLen -= pad_len_out;
			}
			elem->len = plLen + sizeof(SM_DataElem);
			Write_recv_video((unsigned char *)(pl + 12), plLen-12);
		}
		break;
	case SM_ShMemKey_VidSend_BefCipher:
		if(createOut_video)
		{
			set_Enc_pad(pl + 12 , plLen - 12, &pad_len_in);
			plLen += pad_len_in;
			err = srtp_protect(video_ctxOut, pl, &plLen);
			if (err != srtp_err_status_ok)
			{
				printf("\nsrtp video protected failed Out, err= %d\n", err);
				return -1;
			}
			elem->len = plLen + sizeof(SM_DataElem);
//			unsigned char nal_ty = pl[12] & 0x1f;
//			if(nal_ty >= 30)
//				printf("Send video nal_ty = %d", nal_ty);
		}
		break;
	case SM_ShMemKey_AudRecv_BefCipher:
		if(createIn_audio)
		{
			if((plLen - 12) % 16 != 0)
			{
				printf("---------------------------------------decrypt len do not align 16 bytes\n");
			}
			err = srtp_unprotect(audio_ctxIn, pl, &plLen);
			if (err != srtp_err_status_ok)
			{
//				printf("\nsrtp audio unprotected failed In, err= %d\n", err);
				return -1;
			}
			if(check_Dec_pad(pl + 12, plLen - 12, &pad_len_out) == 1)
			{
				plLen -= pad_len_out;
			}
			elem->len = plLen + sizeof(SM_DataElem);
		}
		break;
	case SM_ShMemKey_AudSend_BefCipher:
		if(createOut_audio)
		{
			set_Enc_pad(pl + 12 , plLen - 12, &pad_len_in);
			plLen += pad_len_in;
			err = srtp_protect(audio_ctxOut, pl, &plLen);
			if (err != srtp_err_status_ok)
			{
				printf("\nsrtp audio protected failed Out, err= %d\n", err);
				return -1;
			}
			if((plLen - 12) % 16 != 0)
			{
				printf("encrypt len do not align 16 bytes---------------------------------------\n");
			}
			elem->len = plLen + sizeof(SM_DataElem);
		}
		break;

	case SM_ShMemKey_AuxRecv_BefCipher:
		if(createauxIn_video)
		{
			err = srtp_unprotect(video_aux_ctxIn, pl, &plLen);
			if (err != srtp_err_status_ok)
			{
				printf("\nsrtp aux video unprotected failed In, err= %d\n", err);
				return -1;
			}
			if(check_Dec_pad(pl + 12, plLen - 12, &pad_len_out) == 1)
			{
				plLen -= pad_len_out;
			}
			elem->len = plLen + sizeof(SM_DataElem);
		}
		break;
	case SM_ShMemKey_AuxSend_BefCipher:
		if(createauxOut_video)
		{
			set_Enc_pad(pl + 12 , plLen - 12, &pad_len_in);
			plLen += pad_len_in;
			err = srtp_protect(video_aux_ctxOut, pl, &plLen);
			if (err != srtp_err_status_ok)
			{
				printf("\nsrtp aux video protected failed Out, err= %d\n", err);
				return -1;
			}
			elem->len = plLen + sizeof(SM_DataElem);
		}
		break;
	default:
		printf("unknown handle mesg\n");
		break;
	}

	return 0;
}

int main(int argc,char* argv[])
{
	srtp_err_status_t err;
	int ret;
	int rlt = 0;
	JfRtpHeadDef* jfrtpHead;
	uint32_t seq1 = 0;
	uint32_t seq2 = 0;
	fp = fopen("recv.h264", "wb");
	SM_Init();
	SM_DataElem *elem = (SM_DataElem *)new char[_SM_BigBlockSize]();
	memset(elem, 0x66, _SM_BigBlockSize);

//init signal sock
	ret = Init_Recv_Socket(&signal_sock, &signal_recv_addr, SIGNAL_RECV_PORT, SOCK_STREAM);
	if(ret != 0)
	{
		printf("Init_Recv_Socket signal error\n");
		return -1;
	}

//init srtp
	srtp_err_status_t err_video = srtp_init();
	if (err_video)
	{
		printf("error: srtp video init failed with error code %d\n", err_video);
		srtp_init_ok = false;
		return -1;
	}
	else
	{
		printf("srtp video init ok\n");
		srtp_init_ok = true;
	}

	Init_audio_srtp();
	Init_video_srtp();
	Init_aux_video_srtp();
#if 1
	while(1)
	{
//video
        if (0 == SM_ReadOneElem(SM_ShMemKey_VidRecv_BefCipher, elem))
        {
        	jfrtpHead = (JfRtpHeadDef*)(elem + 1);
        	seq1 = jfrtpHead->ulSeq;
        	tarnsferjfRtpheader_to_normal(jfrtpHead);
            media_srtp_handle(elem, SM_ShMemKey_VidRecv_BefCipher);
            tarnsferRtpheader_to_jf(jfrtpHead);
            seq2 = jfrtpHead->ulSeq;
            if(seq1 != seq2 )
            {
            	printf("recv video seq change\n");
            	break;
            }
            rlt = SM_WriteOneElem(SM_ShMemKey_VidRecv_AftCipher, elem);
            if (rlt != 0)
            	printf("write video back to shm failed:%d\n", rlt);
        }

        if (0 == SM_ReadOneElem(SM_ShMemKey_VidSend_BefCipher, elem))
        {

            jfrtpHead = (JfRtpHeadDef*)(elem + 1);
            seq1 = jfrtpHead->ulSeq;
        	tarnsferjfRtpheader_to_normal(jfrtpHead);
            media_srtp_handle(elem, SM_ShMemKey_VidSend_BefCipher);
            tarnsferRtpheader_to_jf(jfrtpHead);
            seq2 = jfrtpHead->ulSeq;
            if(seq1 != seq2 )
            {
            	printf("send video seq change\n");
            	break;
            }
            rlt = SM_WriteOneElem(SM_ShMemKey_VidSend_AftCipher, elem);
            if (rlt != 0)
                printf("write back send video to shm failed:%d\n", rlt);
        }
//audio
        if (0 == SM_ReadOneElem(SM_ShMemKey_AudRecv_BefCipher, elem))
        {

        	jfrtpHead = (JfRtpHeadDef*)(elem + 1);
        	seq1 = jfrtpHead->ulSeq;
        	tarnsferjfRtpheader_to_normal(jfrtpHead);
            media_srtp_handle(elem, SM_ShMemKey_AudRecv_BefCipher);
            tarnsferRtpheader_to_jf(jfrtpHead);
            seq2 = jfrtpHead->ulSeq;
            if(seq1 != seq2 )
            {
            	printf("recv audio seq change\n");
            	break;
            }
            SM_WriteOneElem(SM_ShMemKey_AudRecv_AftCipher, elem);
            if (rlt != 0)
            	printf("write recv audio back to shm failed:%d\n", rlt);
        }
        if (0 == SM_ReadOneElem(SM_ShMemKey_AudSend_BefCipher, elem))
        {
        	jfrtpHead = (JfRtpHeadDef*)(elem + 1);
        	seq1 = jfrtpHead->ulSeq;
        	tarnsferjfRtpheader_to_normal(jfrtpHead);
            media_srtp_handle(elem, SM_ShMemKey_AudSend_BefCipher);
            tarnsferRtpheader_to_jf(jfrtpHead);
            seq2 = jfrtpHead->ulSeq;
            if(seq1 != seq2 )
            {
            	printf("send audio seq change\n");
            	break;
            }
            SM_WriteOneElem(SM_ShMemKey_AudSend_AftCipher, elem);
            if (rlt != 0)
                printf("write back send audio to shm failed:%d\n", rlt);
        }
//aux video
        if (0 == SM_ReadOneElem(SM_ShMemKey_AuxRecv_BefCipher, elem))
        {
            jfrtpHead = (JfRtpHeadDef*)(elem + 1);
        	tarnsferjfRtpheader_to_normal(jfrtpHead);
            media_srtp_handle(elem, SM_ShMemKey_AuxRecv_BefCipher);
            tarnsferRtpheader_to_jf(jfrtpHead);

            SM_WriteOneElem(SM_ShMemKey_AuxRecv_AftCipher, elem);
            if (rlt != 0)
            	printf("write recv aux video back to shm failed:%d\n", rlt);
        }
        if (0 == SM_ReadOneElem(SM_ShMemKey_AuxSend_BefCipher, elem))
        {
        	jfrtpHead = (JfRtpHeadDef*)(elem + 1);
        	tarnsferjfRtpheader_to_normal(jfrtpHead);
        	media_srtp_handle(elem, SM_ShMemKey_AuxSend_BefCipher);
        	tarnsferRtpheader_to_jf(jfrtpHead);

            SM_WriteOneElem(SM_ShMemKey_AuxSend_AftCipher, elem);
            if (rlt != 0)
                printf("write back send aux video to shm failed:%d\n", rlt);
        }

        usleep(1000);

	}
#endif
	Close_Recv_Socket(&signal_sock);

	err = srtp_shutdown();
	if (err) {
		printf("error: srtp shutdown failed with error code %d\n", err);
		exit(1);
	}
	fclose(fp);
	delete elem;
	SM_DeInit();
	return 0;
}
