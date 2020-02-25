#ifndef _H264CODEC_H__
#define _H264CODEC_H__ 1
#include "h264frame.h"
#include <malloc.h>
#include <stdio.h>

class H264Encoder
{
public:
	H264Encoder();
	~H264Encoder();

	bool Transcode(unsigned char * toPtr,
		unsigned & toLen,
		unsigned & flags);
	char checkend(unsigned char *p);
	void puttochar(unsigned char *tempbuff,unsigned char c);
	bool getdata();

private:
	H264Frame* _txH264Frame;
	int count;
	char ssName [512];
	FILE * fp;

	unsigned char *buf;
	unsigned char *databuf;
	x264_nal_t* nal;

};
#endif /* _H264CODEC_H__ */
