#include "H264Encoder.h"
/*
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include <map>
#include <string>

*/
#include <string.h>
char readfile_name[] = "ys_1080P60.264";
#define H264_PAYLOAD_SIZE      1300
H264Encoder::H264Encoder()
{
	count=0;
	_txH264Frame = new H264Frame();
	_txH264Frame->SetMaxPayloadSize(H264_PAYLOAD_SIZE);

//	snprintf(ssName, sizeof(ssName), "ys_1080P60.264");
	strncpy(ssName, readfile_name, sizeof(readfile_name)/sizeof(char));
	printf("ssName=%s\n",ssName);
	fp = fopen(ssName,"rb");

	buf=(unsigned char *)malloc((sizeof(char)*1024*1024*4));
	memset(buf,0,(sizeof(char)*1024*1024*4));
	nal = (x264_nal_t *)malloc(sizeof(x264_nal_t));
	memset(nal,0,sizeof(x264_nal_t));
}

H264Encoder::~H264Encoder()
{
	if (buf)
	{
		free(buf);
		buf=NULL;
	}
	if (nal)
	{
		free(nal);
		nal=NULL;
	}
	if (databuf)
	{
		free(databuf);
		databuf=NULL;
	}
	
	delete(_txH264Frame);
	fclose(fp);
}
bool H264Encoder::Transcode(
					   unsigned char * toPtr,
					   unsigned & toLen,
					   unsigned & flags)
{
	/*unsigned a = m_frameRate;
	unsigned b = m_height;
	unsigned c = m_width;
	unsigned d = m_maxBitRate;*/

	unsigned int headerLen;
	RTPFrame dstRTP((unsigned char *)toPtr, toLen);
	toLen = 0;
	//dong trace
	//PTRACE(1,m_codecString, "testPlugin _txH264Frame");
	if (!_txH264Frame)
	{
		return false;
	}
	if  (_txH264Frame->HasRTPFrames())
	{
		_txH264Frame->GetRTPFrame(dstRTP, flags);
		toLen = dstRTP.GetFrameLen();
		if (/*_txH264Frame->GetToFreeFrame()||*/(flags&0x01)==1)
		{
			free(_txH264Frame->GetFramePtr());
			_txH264Frame->SetFramePtr();//lastFrame to free memory
		}		
		return true;
	}

	_txH264Frame->BeginNewFrame();
	int numberOfNALs=1;

	//ck to instead with 8168
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	while(getdata())
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	{

		_txH264Frame->SetFromFrame(nal, numberOfNALs);
		if (_txH264Frame->HasRTPFrames())
		{
			_txH264Frame->GetRTPFrame(dstRTP, flags);
			/*dstRTP.SetCount(0);*/
			dstRTP.SetExtension(0);
			dstRTP.SetPadding(0);
			dstRTP.SetVersion(2);
			dstRTP.SetPayloadType(96);
			/*dstRTP.SetMarker(0);
			dstRTP.SetSequenceNumber(0);
			dstRTP.SetTimeStamp(0);*/
			dstRTP.SetSSRC(1);
			toLen = dstRTP.GetFrameLen();
			return true;
		}
	}
	return true;
}

//H264 ��ʼ����
char H264Encoder::checkend(unsigned char *p)
{
	if((*(p+0)==0x00)&&(*(p+1)==0x00)&&(*(p+2)==0x00)&&(*(p+3)==0x01))
		return 1;
	else if((*(p+1)==0x00)&&(*(p+2)==0x00)&&(*(p+3)==0x01))
	{

		return 2;
	}else
		return 0;
}

//ѹ���¶�ȡ���ֽ�
void H264Encoder::puttochar(unsigned char *tempbuff,unsigned char c)
{
	*(tempbuff+0)=*(tempbuff+1);
	*(tempbuff+1)=*(tempbuff+2);
	*(tempbuff+2)=*(tempbuff+3);
	*(tempbuff+3)=c;
}

//��ȡH264 ���
bool H264Encoder::getdata()
{
	if(feof(fp)!=0)
		rewind(fp);
	unsigned int len=0;
	unsigned char tempbuff[4];
	unsigned char c;
	unsigned int i=0;

	//����ļ�ͷ�Ŀ�ʼ��
	if(ftell(fp)==0)
		fread(tempbuff,sizeof(char),4,fp);

	//�״ζ�ȡ��ݣ�����temp������
	fread(tempbuff,sizeof(char),4,fp);

	//��ʼ����
	while(!checkend(tempbuff))
	{
		//����ݻ�����ѹ�����
		*(buf+i)=tempbuff[0];
		len+=fread(&c,sizeof(char),1,fp);

		//����һ���ֽ�ѹ�뻺����
		puttochar(tempbuff,c);
		i++;
		if(feof(fp)!=0)
		{
			memcpy((buf+i),tempbuff,sizeof(tempbuff));
			len+=4;
			rewind(fp);
			break;
		}
	}
	if (checkend(tempbuff) ==2)//the last data if eof counts 3
	{
		*(buf+i)=tempbuff[0];
		if(feof(fp)!=0)
		{
			memcpy((buf+i),tempbuff,sizeof(char));
			len++;
			rewind(fp);
		}else
		{
			len++;
		}
	}

	databuf=(unsigned char *)malloc(len);
	memcpy(databuf,buf,len);
	memset(buf,0,(sizeof(char)*1024*1024*4));

	//rtp_data�ṹ���������
	uint8_t header ;
	memcpy(&header,databuf,1);
	nal->i_ref_idc = (header&60)>>5;
	nal->i_type = header&0x1f;

	nal->i_payload=len;
	nal->p_payload=databuf;
	databuf=NULL;
	return true;
}
