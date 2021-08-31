
#include "RdpDecoder.h"

int WINAPI PacketFrameCallback(void* frameParam,
	BYTE* frameData, int frameStep, int frameWidth, int frameHeight,
	int changeX, int changeY, int changeWidth, int changeHeight,
	UINT64 frameTime, int frameIndex)
{
	char filename[256];
	RdpDecoder* dec = (RdpDecoder*) frameParam;

	sprintf_s(filename, sizeof(filename) - 1, "rdp_%04d.bmp", frameIndex);
	RdpDecoder_WriteBitmap(dec, filename, frameData, frameStep, frameWidth, frameHeight);

	return 1;
}

int main(int argc, char** argv)
{
	RdpDecoder* dec = RdpDecoder_New();
	HANDLE finishEvent;

	finishEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	RdpDecoder_SetFinishEvent(dec, finishEvent);
	RdpDecoder_SetFrameCallback(dec, PacketFrameCallback, dec);

	if ((argc == 2) && (argv[1][0] != '/'))
	{
		/* use filename only */
		RdpDecoder_Open(dec, argv[1]);
	}
	else
	{
		/* use FreeRDP arguments */
		RdpDecoder_Args(dec, argc, argv);
		RdpDecoder_Open(dec, NULL);
	}

	RdpDecoder_Start(dec);

	WaitForSingleObject(finishEvent, INFINITE);

	RdpDecoder_Stop(dec);
	RdpDecoder_Close(dec);

	CloseHandle(finishEvent);
	RdpDecoder_Free(dec);

	return 0;
}