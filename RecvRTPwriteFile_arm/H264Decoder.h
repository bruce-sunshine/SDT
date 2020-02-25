#ifndef _H264DECODER_H__
#define _H264DECODER_H__ 1
#include "h264frame.h"
#include <malloc.h>
#include <stdio.h>
#define socketNum 1
class H264Decoder
{
public:
	H264Decoder(int portIndex);
	~H264Decoder();
	bool Transcode(const void * fromPtr,
		int & toLen,
		unsigned & flags);

private:
	char ssName [512];
	FILE * fp;
	H264Frame* _rxH264Frame;
	bool _gotIFrame;
	bool _gotAGoodFrame;
	int _frameCounter;
	int _skippedFrameCounter;
};
#endif /* _H264DECODER_H__ */
