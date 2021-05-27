#include "virtualchannel.h"
#include <freerdp/client/channels.h>

#define TAG CHANNELS_TAG("virtual.channel")

static UINT virtchan_virtual_channel_event_data_received(virtchanPlugin* virtchan,
    void* pData, UINT32 dataLength, UINT32 totalLength, UINT32 dataFlags)
{
    wStream* data_in;

    if ((dataFlags & CHANNEL_FLAG_SUSPEND) || (dataFlags & CHANNEL_FLAG_RESUME))
        return CHANNEL_RC_OK;

    if (dataFlags & CHANNEL_FLAG_FIRST)
    {
        if (virtchan->data_in)
            Stream_Free(virtchan->data_in, TRUE);

        virtchan->data_in = Stream_New(NULL, totalLength);

        if (!virtchan->data_in)
        {
            WLog_ERR(TAG, "Stream_New failed!");
            return CHANNEL_RC_NO_MEMORY;
        }
    }

    data_in = virtchan->data_in;

    if (!Stream_EnsureRemainingCapacity(data_in, (int)dataLength))
    {
        WLog_ERR(TAG, "Stream_EnsureRemainingCapacity failed!");
        return ERROR_INTERNAL_ERROR;
    }

    Stream_Write(data_in, pData, dataLength);

    if (dataFlags & CHANNEL_FLAG_LAST)
    {
        if (Stream_Capacity(data_in) != Stream_GetPosition(data_in))
        {
            WLog_ERR(TAG, "virtchan_plugin_process_received: read error");
            return ERROR_INVALID_DATA;
        }

        virtchan->data_in = NULL;
        Stream_SealLength(data_in);
        Stream_SetPosition(data_in, 0);

		if(virtchan->onChannelReceivedData)
		{
			virtchan->onChannelReceivedData(virtchan->context->custom, virtchan->channelDef.name, data_in->buffer, data_in->length);
		}
    }

    return CHANNEL_RC_OK;
}

static VOID VCAPITYPE virtchan_virtual_channel_open_event_ex(LPVOID lpUserParam, DWORD openHandle,
        UINT event,
        LPVOID pData, UINT32 dataLength, UINT32 totalLength, UINT32 dataFlags)
{
	UINT error = CHANNEL_RC_OK;
	virtchanPlugin* virtchan = (virtchanPlugin*) lpUserParam;

	if (!virtchan || (virtchan->OpenHandle != openHandle))
	{
		WLog_ERR(TAG,  "error no match");
		return;
	}

	 switch (event)
	 {
	 	case CHANNEL_EVENT_DATA_RECEIVED:
	 		if ((error = virtchan_virtual_channel_event_data_received(virtchan, pData,
	 		             dataLength, totalLength, dataFlags)))
	 			WLog_ERR(TAG, "virtchan_virtual_channel_event_data_received failed with error %"PRIu32"", error);

	 		break;

	 	case CHANNEL_EVENT_WRITE_COMPLETE:
	 		break;

	 	case CHANNEL_EVENT_USER:
	 		break;
	 }

	if (error && virtchan->rdpcontext)
		setChannelError(virtchan->rdpcontext, error, "virtchan_virtual_channel_open_event reported an error");

	return;
}

static UINT virtchan_virtual_channel_event_connected(virtchanPlugin* virtchan,
        LPVOID pData, UINT32 dataLength)
{
	UINT32 status;
	status = virtchan->channelEntryPoints.pVirtualChannelOpenEx(virtchan->InitHandle,
	         &virtchan->OpenHandle, virtchan->channelDef.name,
	         virtchan_virtual_channel_open_event_ex);

	if (status != CHANNEL_RC_OK)
	{
		WLog_ERR(TAG, "pVirtualChannelOpen failed with %s [%08"PRIX32"]",
		         WTSErrorToString(status), status);
		return status;
	}

	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT virtchan_virtual_channel_event_disconnected(virtchanPlugin* virtchan)
{
	UINT rc;

	if (virtchan->OpenHandle == 0)
		return CHANNEL_RC_OK;

	rc = virtchan->channelEntryPoints.pVirtualChannelCloseEx(virtchan->InitHandle, virtchan->OpenHandle);

	if (CHANNEL_RC_OK != rc)
	{
		WLog_ERR(TAG, "pVirtualChannelClose failed with %s [%08"PRIX32"]",
		         WTSErrorToString(rc), rc);
		return rc;
	}

	virtchan->OpenHandle = 0;

	if (virtchan->data_in)
	{
		Stream_Free(virtchan->data_in, TRUE);
		virtchan->data_in = NULL;
	}

	return CHANNEL_RC_OK;
}


/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT virtchan_virtual_channel_event_terminated(virtchanPlugin* virtchan)
{
	virtchan->InitHandle = 0;
	free(virtchan->context);
	free(virtchan);
	return CHANNEL_RC_OK;
}

static VOID VCAPITYPE virtchan_virtual_channel_init_event_ex(LPVOID lpUserParam, LPVOID pInitHandle,
        UINT event, LPVOID pData, UINT dataLength)
{
	UINT error = CHANNEL_RC_OK;
	virtchanPlugin* virtchan = (virtchanPlugin*) lpUserParam;

	if (!virtchan || (virtchan->InitHandle != pInitHandle))
	{
		WLog_ERR(TAG,  "error no match");
		return;
	}

	switch (event)
	{
		case CHANNEL_EVENT_CONNECTED:
			if ((error = virtchan_virtual_channel_event_connected(virtchan, pData,
			             dataLength)))
				WLog_ERR(TAG, "virtchan_virtual_channel_event_connected failed with error %"PRIu32"",
				         error);

			break;

		case CHANNEL_EVENT_DISCONNECTED:
			if ((error = virtchan_virtual_channel_event_disconnected(virtchan)))
				WLog_ERR(TAG,
				         "virtchan_virtual_channel_event_disconnected failed with error %"PRIu32"", error);

			break;

		case CHANNEL_EVENT_TERMINATED:
			virtchan_virtual_channel_event_terminated(virtchan);
			break;

		default:
			WLog_ERR(TAG, "Unhandled event type %"PRIu32"", event);
	}

	if (error && virtchan->rdpcontext)
		setChannelError(virtchan->rdpcontext, error, "virtchan_virtual_channel_init_event reported an error");
}

BOOL VCAPITYPE rdpvirt_VirtualChannelEntryEx(PCHANNEL_ENTRY_POINTS pEntryPoints, PVOID pInitHandle, LPCSTR pszName)
{
    UINT rc;
	virtchanPlugin* virtchan;
	VirtChanContext* context = NULL;
	CHANNEL_ENTRY_POINTS_FREERDP_EX* pEntryPointsEx;
	BOOL isFreerdp = FALSE;
	virtchan = (virtchanPlugin*) calloc(1, sizeof(virtchanPlugin));

	if (!virtchan)
	{
		WLog_ERR(TAG, "calloc failed!");
		return FALSE;
	}

	virtchan->channelDef.options =
	    CHANNEL_OPTION_INITIALIZED |
	    CHANNEL_OPTION_ENCRYPT_RDP |
	    CHANNEL_OPTION_COMPRESS_RDP;
	sprintf_s(virtchan->channelDef.name, ARRAYSIZE(virtchan->channelDef.name), "%s", pszName);
	pEntryPointsEx = (CHANNEL_ENTRY_POINTS_FREERDP_EX*) pEntryPoints;

	if ((pEntryPointsEx->cbSize >= sizeof(CHANNEL_ENTRY_POINTS_FREERDP_EX)) &&
	    (pEntryPointsEx->MagicNumber == FREERDP_CHANNEL_MAGIC_NUMBER))
	{
		context = (VirtChanContext*) calloc(1, sizeof(VirtChanContext));

		if (!context)
		{
			WLog_ERR(TAG, "calloc failed!");
			goto error_out;
		}

		context->handle = (void*) virtchan;
		virtchan->context = context;
		virtchan->rdpcontext = pEntryPointsEx->context;
		isFreerdp = TRUE;
	}

	CopyMemory(&(virtchan->channelEntryPoints), pEntryPoints,
	           sizeof(CHANNEL_ENTRY_POINTS_FREERDP_EX));
	virtchan->InitHandle = pInitHandle;
	rc = virtchan->channelEntryPoints.pVirtualChannelInitEx(virtchan, context, pInitHandle,
	        &virtchan->channelDef, 1, VIRTUAL_CHANNEL_VERSION_WIN2000,
	        virtchan_virtual_channel_init_event_ex);

	if (CHANNEL_RC_OK != rc)
	{
		WLog_ERR(TAG, "failed with %s [%08"PRIX32"]",
		         WTSErrorToString(rc), rc);
		goto error_out;
	}

	virtchan->channelEntryPoints.pInterface = context;
	return TRUE;
error_out:

	if (isFreerdp)
		free(virtchan->context);

	free(virtchan);
	return FALSE;
}

BOOL VCAPITYPE rdpvirt_jump_VirtualChannelEntryEx(PCHANNEL_ENTRY_POINTS pEntryPoints, PVOID pInitHandle)
{
	return rdpvirt_VirtualChannelEntryEx(pEntryPoints, pInitHandle, "RDMJump");
}

BOOL VCAPITYPE rdpvirt_cmd_VirtualChannelEntryEx(PCHANNEL_ENTRY_POINTS pEntryPoints, PVOID pInitHandle)
{
	return rdpvirt_VirtualChannelEntryEx(pEntryPoints, pInitHandle, "RDMCmd");
}

BOOL VCAPITYPE rdpvirt_log_VirtualChannelEntryEx(PCHANNEL_ENTRY_POINTS pEntryPoints, PVOID pInitHandle)
{
	return rdpvirt_VirtualChannelEntryEx(pEntryPoints, pInitHandle, "RDMLog");
}

PVIRTUALCHANNELENTRY cs_channels_load_static_addin_entry(LPCSTR pszName, LPSTR pszSubsystem, LPSTR pszType, DWORD dwFlags)
{
    PVIRTUALCHANNELENTRY entry = NULL;

	entry = freerdp_channels_load_static_addin_entry(pszName, pszSubsystem, pszType, dwFlags);
    if(entry)
        return entry;

	if (strcmp(pszName, "RDMJump") == 0)
	{
		return rdpvirt_jump_VirtualChannelEntryEx;
	}
	else if (strcmp(pszName, "RDMCmd") == 0)
	{
		return rdpvirt_cmd_VirtualChannelEntryEx;
	}
	else if (strcmp(pszName, "RDMLog") == 0)
	{
		return rdpvirt_log_VirtualChannelEntryEx;
	}

	return NULL;
}

UINT cs_channel_write(VirtChanContext* context, BSTR message, int size)
{
	wStream* s;
	virtchanPlugin* virtchan;
	UINT status;
	virtchan = (virtchanPlugin*) context->handle;
	s = Stream_New(NULL, size);

	if (!s)
	{
		WLog_ERR(TAG, "Stream_New failed!");
		return CHANNEL_RC_NO_MEMORY;
	}

	Stream_Write(s, (void*)message, size);
	Stream_SealLength(s);

	status = virtchan->channelEntryPoints.pVirtualChannelWriteEx(virtchan->InitHandle,
	         virtchan->OpenHandle,
	         Stream_Buffer(s), (UINT32) Stream_Length(s), s);

	if (status != CHANNEL_RC_OK)
		WLog_ERR(TAG,  "VirtualChannelWriteEx failed with %s [%08"PRIX32"]",
		         WTSErrorToString(status), status);

	return status;
}

char* cs_channel_get_name(VirtChanContext* context)
{
	virtchanPlugin* virtchan = (virtchanPlugin*) context->handle;

	return virtchan->channelDef.name;
}

void cs_channel_set_on_received_data(VirtChanContext* context, fnOnChannelReceivedData fn)
{
	virtchanPlugin* virtchan = (virtchanPlugin*) context->handle;
	virtchan->onChannelReceivedData = fn;
}