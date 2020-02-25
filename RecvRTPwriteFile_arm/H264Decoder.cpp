#include "H264Decoder.h"
#include <string.h>
enum PluginCodec_ReturnCoderFlags {
	PluginCodec_ReturnCoderLastFrame      = 1,    // indicates when video codec returns last data for frame
	PluginCodec_ReturnCoderIFrame         = 2,    // indicates when video returns I frame
	PluginCodec_ReturnCoderRequestIFrame  = 4,    // indicates when video decoder request I frame for resync
	PluginCodec_ReturnCoderBufferTooSmall = 8     // indicates when output buffer is not large enough to receive
	// the data, another call to get_output_data_size is required
};
// #define snprintf  _snprintf
char h264_name[] = "1920_1080.h264";
H264Decoder::H264Decoder(int portIndex)
{
//	snprintf(ssName, sizeof(ssName),
//				"main_decode_%d_%d_%d.264", GetCurrentProcessId(),GetCurrentThreadId(),portIndex);
	strncpy(ssName, h264_name, sizeof(h264_name)/sizeof(char));
		fp = fopen(ssName,"wb+");
	
	_gotIFrame = false;
	_gotAGoodFrame = false;
	_frameCounter = 0; 
	_skippedFrameCounter = 0;
	_rxH264Frame = new H264Frame();
	//dong trace
	//PTRACE(1,NULL, "H264Decoder");
}

H264Decoder::~H264Decoder()
{
	delete(_rxH264Frame);
	fflush(fp);
	fclose(fp);

}

bool H264Decoder::Transcode(const void * fromPtr,
						  int & fromLen,
						  unsigned & flags)
{
	RTPFrame srcRTP((unsigned char*)fromPtr, fromLen);
	if (!_rxH264Frame->SetFromRTPFrame(srcRTP, flags)) {
		_rxH264Frame->BeginNewFrame();
		flags = (_gotAGoodFrame ? requestIFrame : 0);
		_gotAGoodFrame = false;
		return true;
	}
	if (srcRTP.GetMarker()==0)
	{
		return true;
	} 
	if (_rxH264Frame->GetFrameSize()==0)
	{
		_rxH264Frame->BeginNewFrame();
		/*TRACE(4, "H264\tDecoder\tGot an empty frame - skipping");*/
		_skippedFrameCounter++;
		flags = (_gotAGoodFrame ? requestIFrame : 0);
		_gotAGoodFrame = false;
		return true;
	}
	// look and see if we have read an I frame.
	if (_gotIFrame == 0)
	{
		if (!_rxH264Frame->IsSync())
		{
			/*TRACE(1, "H264\tDecoder\tWaiting for an I-Frame");*/
			_rxH264Frame->BeginNewFrame();
			flags = (_gotAGoodFrame ? requestIFrame : 0);
			_gotAGoodFrame = false;
			return true;
		}
		_gotIFrame = 1;
	}

	uint32_t bytesUsed = 0;  

	//ck to instead with 8168
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	if(_rxH264Frame->Isgoodframe())
	{
		fwrite(_rxH264Frame->GetFramePtr() + bytesUsed,_rxH264Frame->GetFrameSize() - bytesUsed,1,fp);
		fflush(fp);
	}	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////

	_rxH264Frame->BeginNewFrame();
	int gotPicture = 1;
	/*gotPicture used to show the decoder's status*/
	if (!gotPicture) 
	{
		/*TRACE(1, "H264\tDecoder\tDecoded "<< bytesDecoded << " bytes without getting a Picture..."); */
		_skippedFrameCounter++;
		flags = (_gotAGoodFrame ? requestIFrame : 0);
		_gotAGoodFrame = false;
		return true;
	}

	flags = PluginCodec_ReturnCoderLastFrame;
	_frameCounter++;
	_gotAGoodFrame = true;
	return true;
}
