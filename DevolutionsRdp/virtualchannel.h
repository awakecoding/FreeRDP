#ifndef CS_VIRTUALCHANNEL_H_
#define CS_VIRTUALCHANNEL_H_

#include <freerdp/svc.h>
#include <freerdp/addin.h>
#include <freerdp/channels/log.h>

typedef void (*fnOnChannelReceivedData)(void* context, char* channelName, BYTE* text, UINT32 length);

typedef struct _virtchan_context
{
	void* handle;
	void* custom;

	rdpContext* rdpcontext;
} VirtChanContext;

typedef struct virtchan_plugin
{
	CHANNEL_DEF channelDef;
	CHANNEL_ENTRY_POINTS_FREERDP_EX channelEntryPoints;

	VirtChanContext* context;
	fnOnChannelReceivedData onChannelReceivedData;

	wStream* data_in;
	void* InitHandle;
	DWORD OpenHandle;
	rdpContext* rdpcontext;
} virtchanPlugin;

PVIRTUALCHANNELENTRY cs_channels_load_static_addin_entry(LPCSTR pszName, LPSTR pszSubsystem, LPSTR pszType, DWORD dwFlags);
UINT cs_channel_write(VirtChanContext* context, BSTR message, int size);
char* cs_channel_get_name(VirtChanContext* context);
void cs_channel_set_on_received_data(VirtChanContext* context, fnOnChannelReceivedData fn);

#endif /* CS_VIRTUALCHANNEL_H_ */