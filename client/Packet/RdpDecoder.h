
#ifndef FREERDP_PACKET_DECODER_H
#define FREERDP_PACKET_DECODER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <windows.h>

typedef int (WINAPI * fnFrameCallback)(void* frameParam,
	BYTE* frameData, int frameStep, int frameWidth, int frameHeight,
	int changeX, int changeY, int changeWidth, int changeHeight,
	UINT64 frameTime, int frameIndex);


typedef struct rdp_decoder RdpDecoder;


#ifdef __cplusplus
extern "C"
{
#endif

__declspec(dllexport) RdpDecoder* RdpDecoder_New();
__declspec(dllexport) bool RdpDecoder_Open(RdpDecoder* ctx, const char* filename);
__declspec(dllexport) bool RdpDecoder_Args(RdpDecoder* ctx, int argc, char** argv);
__declspec(dllexport) void RdpDecoder_Close(RdpDecoder* ctx);
__declspec(dllexport) bool RdpDecoder_Start(RdpDecoder* ctx);
__declspec(dllexport) bool RdpDecoder_Stop(RdpDecoder* ctx);
__declspec(dllexport) void RdpDecoder_SetFinishEvent(RdpDecoder* ctx, HANDLE finishEvent);
__declspec(dllexport) void RdpDecoder_SetFrameCallback(RdpDecoder* ctx, fnFrameCallback func, void* param);
__declspec(dllexport) int RdpDecoder_WriteBitmap(RdpDecoder* ctx, const char* filename, BYTE* data,
                                                 int step,
                                                 int width, int height);
__declspec(dllexport) void RdpDecoder_Free(RdpDecoder* ctx);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_PACKET_DECODER_H */