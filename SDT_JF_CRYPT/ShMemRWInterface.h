#ifndef __SHMEMRWINTERFACE_H__
#define __SHMEMRWINTERFACE_H__

//#ifdef __cplusplus
//	extern "C" {
//#endif

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef struct _RTP_HEADER_DEF {
	/**//* byte 0 */
	unsigned char csrc_len :4; /**//* expect 0 */
	unsigned char extension :1; /**//* expect 1, see RTP_OP below */
	unsigned char padding :1; /**//* expect 0 */
	unsigned char version :2; /**//* expect 2 */
	/**//* byte 1 */
	unsigned char payload :7; /**//* RTP_PAYLOAD_RTSP */
	unsigned char marker :1; /**//* expect 1 */
	/**//* bytes 2, 3 */
	unsigned short seq;
	/**//* bytes 4-7 */
	unsigned int timestamp;	//changed long-->int, for ti8168 unsigned long = 4 bytes, for hisi unsigned long = 8bytes;
	/**//* bytes 8-11 */
	unsigned int ssrc; /**//* stream number is used here. */
} RtpHeadDef;

#if 1
typedef struct _JF_RTP_HEADER_DEF {
	uint32_t ulSeq 	:16;
	uint32_t bit7PT	:7;
	uint32_t bit1M	:1;
	uint32_t bit4CC	:4;
	uint32_t bit1X	:1;
	uint32_t bit1P	:1;
	uint32_t bit2V	:2;
	uint32_t ulTimeStamp;
	uint32_t ulSSRC;
} JfRtpHeadDef;

#endif
struct SM_CheckHead {
    unsigned char flag1;
    unsigned char flag2;
    unsigned char flag3;
    unsigned char flag4;
};

struct SM_ChannelInfo {
    int confId;
    int siteId;
    int channelId;
    int direction;
    int position;
};

#pragma pack(2)
struct SM_DataElem {
    SM_CheckHead   checkValue;
    SM_ChannelInfo chan;
    unsigned long long    ts;
    //unsigned    sessionFlag;
    unsigned    len;
    char        placeHolder[160];
};
#pragma pack()

enum SM_ShMemKey {
    SM_ShMemKey_Begin = 1234,
    SM_ShMemKey_VidRecv_BefCipher = SM_ShMemKey_Begin,
    SM_ShMemKey_VidRecv_AftCipher,
    SM_ShMemKey_VidSend_BefCipher,
    SM_ShMemKey_VidSend_AftCipher,
    SM_ShMemKey_AudRecv_BefCipher,
    SM_ShMemKey_AudRecv_AftCipher,
    SM_ShMemKey_AudSend_BefCipher,
    SM_ShMemKey_AudSend_AftCipher,
    SM_ShMemKey_AuxRecv_BefCipher,
    SM_ShMemKey_AuxRecv_AftCipher,
    SM_ShMemKey_AuxSend_BefCipher,
    SM_ShMemKey_AuxSend_AftCipher,
    SM_ShMemKey_End,
};

static const unsigned _SM_BigBlockSize = 1800;

/*
初始化共享内存
*/
int SM_Init();

/*
读取一个包的缓存，然后进行加密\解密
dataElem必须为外部创建好的缓存，大小为_SM_BigBlockSize
*/
int SM_ReadOneElem(const SM_ShMemKey shKey, void* dataElem);

/*
将已经处理的加密\解密的包写入到共享存储区
dataElem必须为外部创建好的缓存，大小为_SM_BigBlockSize
*/
int SM_WriteOneElem(const SM_ShMemKey shKey, void* dataElem);

/*
程序退出前资源回收
*/
int SM_DeInit();

/*
模拟加解密
*/
static int SimulateDoCipher(SM_DataElem* elem)
{
    if (elem->len > sizeof(SM_DataElem) + 12 && elem->len < _SM_BigBlockSize) {
        char* pl = (char*)(elem + 1) + 12;
        int plLen = elem->len - sizeof(SM_DataElem) - 12;
        for (int i = 0; i < plLen; ++i) {
            pl[i] ^= 0x12;
        }
//        elem->len = elem->len; // 注意：解密\解密后，需要根据实际改变长度参数
        return 0;
    } else {
        return -1;
    }
}

//#ifdef __cplusplus
//}
//#endif /** __cplusplus */

#endif
