
#ifndef FREERDP_PACKET_DECODER_H
#define FREERDP_PACKET_DECODER_H

#include <stdio.h>
#include <stdlib.h>

#include <windows.h>

typedef int (WINAPI * fnFrameCallback)(void* frameParam,
	BYTE* frameData, int frameStep, int frameWidth, int frameHeight,
	int changeX, int changeY, int changeWidth, int changeHeight,
	UINT64 frameTime, int frameIndex);

class __declspec(dllexport) RdpDecoder
{
public:
	RdpDecoder();
	~RdpDecoder();

	bool open(const char* filename);
	bool args(int argc, char** argv);

	void close();

	bool start();
	bool stop();

	void setFinishEvent(HANDLE finishEvent);
	void setFrameCallback(fnFrameCallback func, void* param);

	int writeBitmap(const char* filename, BYTE* data, int step, int width, int height);

private:
	void* m_context;
	void* m_settings;
	char* m_filename;
	void* m_frameParam;
	fnFrameCallback m_frameFunc;
	HANDLE m_finishEvent;
};

#endif /* FREERDP_PACKET_DECODER_H */