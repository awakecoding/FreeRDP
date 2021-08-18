
#include "RdpDecoder.h"

int WINAPI PacketFrameCallback(void* frameParam,
	BYTE* frameData, int frameStep, int frameWidth, int frameHeight,
	int changeX, int changeY, int changeWidth, int changeHeight,
	UINT64 frameTime, int frameIndex)
{
	char filename[256];
	RdpDecoder* dec = (RdpDecoder*) frameParam;

	sprintf_s(filename, sizeof(filename) - 1, "rdp_%04d.bmp", frameIndex);
	dec->writeBitmap(filename, frameData, frameStep, frameWidth, frameHeight);

	return 1;
}

int main(int argc, char** argv)
{
	RdpDecoder* dec;
	HANDLE finishEvent;

	dec = new RdpDecoder();
	finishEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	dec->setFinishEvent(finishEvent);
	dec->setFrameCallback(PacketFrameCallback, dec);

	if ((argc == 2) && (argv[1][0] != '/'))
	{
		/* use filename only */
		dec->open(argv[1]);
	}
	else
	{
		/* use FreeRDP arguments */
		dec->args(argc, argv);
		dec->open(NULL);
	}

	dec->start();

	WaitForSingleObject(finishEvent, INFINITE);

	dec->stop();
	dec->close();

	CloseHandle(finishEvent);
	delete dec;

	return 0;
}