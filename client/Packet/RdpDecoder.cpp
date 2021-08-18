/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Windows Client
 *
 * Copyright 2009-2011 Jay Sorg
 * Copyright 2010-2011 Vic Lee
 * Copyright 2010-2011 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <winpr/windows.h>

#include <winpr/crt.h>
#include <winpr/image.h>

#include <freerdp/log.h>
#include <freerdp/freerdp.h>
#include <freerdp/gdi/gfx.h>
#include <freerdp/gdi/region.h>
#include <freerdp/primitives.h>
#include <freerdp/codec/region.h>
#include <freerdp/client/cmdline.h>
#include <freerdp/client/channels.h>
#include <libfreerdp/core/client.h>

#include "RdpDecoder.h"

typedef struct pf_context pfContext;

struct pf_context
{
	rdpContext context;
	DEFINE_RDP_CLIENT_COMMON();

	int frameIndex;
	HANDLE stopEvent;
	HANDLE finishEvent;
	freerdp* instance;
	rdpSettings* settings;

	void* frameParam;
	fnFrameCallback frameFunc;
};

#define TAG CLIENT_TAG("packet")

void pf_OnChannelConnectedEventHandler(rdpContext* context, ChannelConnectedEventArgs* e)
{
	WLog_WARN(TAG, "OnChannelConnectedEventHandler: %s", e->name);

	if (!strcmp(e->name, RDPGFX_DVC_CHANNEL_NAME))
	{
		gdi_graphics_pipeline_init(context->gdi, (RdpgfxClientContext*) e->pInterface);
	}
}

void pf_OnChannelDisconnectedEventHandler(rdpContext* context, ChannelDisconnectedEventArgs* e)
{
	WLog_WARN(TAG, "OnChannelDisconnectedEventHandler: %s", e->name);

	if (!strcmp(e->name, RDPGFX_DVC_CHANNEL_NAME))
	{
		gdi_graphics_pipeline_uninit(context->gdi, (RdpgfxClientContext*) e->pInterface);
	}
}

BOOL pf_begin_paint(pfContext* pfc)
{
	WLog_WARN(TAG, "pf_begin_paint");
	rdpGdi* gdi = ((rdpContext*) pfc)->gdi;
	gdi->primary->hdc->hwnd->invalid->null = TRUE;
	gdi->primary->hdc->hwnd->ninvalid = 0;
	return TRUE;
}

BOOL pf_end_paint(pfContext* pfc)
{
	rdpGdi* gdi;
	HGDI_RGN invalid;
	UINT64 frameTime;
	rdpContext* context = (rdpContext*) pfc;

	gdi = context->gdi;
	invalid = gdi->primary->hdc->hwnd->invalid;

    if (gdi->primary->hdc->hwnd->ninvalid < 0) 
        return TRUE;

	if (invalid->null)
		return TRUE;

	frameTime = metrics_get_session_time(context->metrics);

	if (pfc->frameFunc)
	{
		pfc->frameFunc(pfc->frameParam, gdi->primary_buffer, gdi->width * 4, gdi->width, gdi->height,
			invalid->x, invalid->y, invalid->w, invalid->h, frameTime, pfc->frameIndex);
	}

	pfc->frameIndex++;

	return TRUE;
}

BOOL pf_desktop_resize(pfContext* pfc)
{
	rdpContext* context = (rdpContext*) pfc;
	rdpSettings* settings = context->settings;

	if (!gdi_resize(context->gdi, settings->DesktopWidth, settings->DesktopHeight))
		return FALSE;

	freerdp_client_codecs_reset(context->codecs, FREERDP_CODEC_ALL,
		settings->DesktopWidth, settings->DesktopHeight);

	return TRUE;
}

BOOL pf_pre_connect(freerdp* instance)
{
	rdpContext* context = instance->context;
	rdpSettings* settings = context->settings;
	rdpChannels* channels = context->channels;

	settings->AsyncInput = FALSE;
	settings->AsyncUpdate = FALSE;
	settings->AsyncChannels = FALSE;

	settings->OsMajorType = OSMAJORTYPE_WINDOWS;
	settings->OsMinorType = OSMINORTYPE_WINDOWS_NT;
	settings->OrderSupport[NEG_DSTBLT_INDEX] = TRUE;
	settings->OrderSupport[NEG_PATBLT_INDEX] = TRUE;
	settings->OrderSupport[NEG_SCRBLT_INDEX] = TRUE;
	settings->OrderSupport[NEG_OPAQUE_RECT_INDEX] = TRUE;
	settings->OrderSupport[NEG_DRAWNINEGRID_INDEX] = FALSE;
	settings->OrderSupport[NEG_MULTIDSTBLT_INDEX] = FALSE;
	settings->OrderSupport[NEG_MULTIPATBLT_INDEX] = FALSE;
	settings->OrderSupport[NEG_MULTISCRBLT_INDEX] = FALSE;
	settings->OrderSupport[NEG_MULTIOPAQUERECT_INDEX] = TRUE;
	settings->OrderSupport[NEG_MULTI_DRAWNINEGRID_INDEX] = FALSE;
	settings->OrderSupport[NEG_LINETO_INDEX] = TRUE;
	settings->OrderSupport[NEG_POLYLINE_INDEX] = TRUE;
	settings->OrderSupport[NEG_MEMBLT_INDEX] = TRUE;
	settings->OrderSupport[NEG_MEM3BLT_INDEX] = FALSE;
	settings->OrderSupport[NEG_SAVEBITMAP_INDEX] = FALSE;
	settings->OrderSupport[NEG_GLYPH_INDEX_INDEX] = FALSE;
	settings->OrderSupport[NEG_FAST_INDEX_INDEX] = FALSE;
	settings->OrderSupport[NEG_FAST_GLYPH_INDEX] = FALSE;
	settings->OrderSupport[NEG_POLYGON_SC_INDEX] = FALSE;
	settings->OrderSupport[NEG_POLYGON_CB_INDEX] = FALSE;
	settings->OrderSupport[NEG_ELLIPSE_SC_INDEX] = FALSE;
	settings->OrderSupport[NEG_ELLIPSE_CB_INDEX] = FALSE;
	settings->AllowUnanouncedOrdersFromServer = true;

	settings->GlyphSupportLevel = GLYPH_SUPPORT_FULL;

	settings->ColorDepth = 32;
	settings->RemoteFxCodec = TRUE;
	settings->SurfaceFrameMarkerEnabled = TRUE;
	settings->FrameMarkerCommandEnabled = TRUE;
	settings->AutoReconnectionEnabled = FALSE;
	settings->NetworkAutoDetect = FALSE;
	settings->SupportHeartbeatPdu = FALSE;

	settings->ReplayMode = TRUE;
	settings->ExternalTransport = TRUE;
	settings->ExternalSecurity = TRUE;
	settings->CompressionEnabled = FALSE;
	settings->IgnoreCertificate = TRUE;
	settings->ExternalCertificateManagement = TRUE;

	settings->DeviceRedirection = FALSE;
	settings->SupportDynamicChannels = FALSE;
	settings->SupportGraphicsPipeline = TRUE;
    settings->BitmapCacheEnabled = TRUE;
	settings->OffscreenSupportLevel = TRUE;

	PubSub_SubscribeChannelConnected(context->pubSub,
		(pChannelConnectedEventHandler) pf_OnChannelConnectedEventHandler);

	PubSub_SubscribeChannelDisconnected(context->pubSub,
		(pChannelDisconnectedEventHandler) pf_OnChannelDisconnectedEventHandler);

	return TRUE;
}

BOOL pf_post_connect(freerdp* instance)
{
	rdpContext* context = instance->context;
	rdpSettings* settings = context->settings;
	rdpChannels* channels = context->channels;
	rdpUpdate* update = context->update;

	if (!gdi_init(instance, PIXEL_FORMAT_RGBX32))
		return FALSE;

	update->BeginPaint = (pBeginPaint) pf_begin_paint;
	update->EndPaint = (pEndPaint) pf_end_paint;
	update->DesktopResize = (pDesktopResize) pf_desktop_resize;

	return TRUE;
}

void pf_post_disconnect(freerdp* instance)
{
	
}

static BOOL pf_authenticate(freerdp* instance, char** username, char** password, char** domain)
{
	return TRUE;
}

static BOOL pf_gw_authenticate(freerdp* instance, char** username, char** password, char** domain)
{
	return TRUE;
}

int pf_verify_x509_certificate(freerdp* instance, const BYTE* data, size_t length, const char* hostname, UINT16 port, DWORD flags)
{
	return 1;
}

int pf_logon_error_info(freerdp* instance, UINT32 data, UINT32 type)
{
	return 1;
}

DWORD WINAPI pf_client_thread(LPVOID lpParam)
{
	DWORD nCount;
	DWORD waitStatus;
	HANDLE handles[64];
	pfContext* pfc;
	freerdp* instance;
	rdpContext* context;

	context = (rdpContext*) lpParam;
	pfc = (pfContext*) context;
	instance = context->instance;

	while (1)
	{
		nCount = 0;
		handles[nCount++] = pfc->stopEvent;

		nCount += freerdp_get_event_handles(context, &handles[nCount], 64 - nCount);

		waitStatus = WaitForMultipleObjects(nCount, handles, FALSE, INFINITE);

		if (waitStatus == WAIT_FAILED)
			break;

		if (waitStatus == WAIT_OBJECT_0)
			break;

		if (!freerdp_check_event_handles(context))
			break;
	}

	freerdp_disconnect(instance);

	if (pfc->finishEvent)
		SetEvent(pfc->finishEvent);

	ExitThread(0);
	return 0;
}

BOOL pfreerdp_client_global_init(void)
{
	return TRUE;
}

void pfreerdp_client_global_uninit(void)
{

}

BOOL pfreerdp_client_new(freerdp* instance, rdpContext* context)
{
	pfContext* pfc = (pfContext*) context;

	context->channels = freerdp_channels_new(instance);

	if (!context->channels)
		return FALSE;

	instance->PreConnect = pf_pre_connect;
	instance->PostConnect = pf_post_connect;
	instance->PostDisconnect = pf_post_disconnect;
	instance->Authenticate = pf_authenticate;
	instance->GatewayAuthenticate = pf_gw_authenticate;
	instance->VerifyX509Certificate = pf_verify_x509_certificate;
	instance->LogonErrorInfo = pf_logon_error_info;

	pfc->instance = instance;
	pfc->settings = instance->settings;

	pfc->stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	return TRUE;
}

void pfreerdp_client_free(freerdp* instance, rdpContext* context)
{
	pfContext* pfc = (pfContext*) context;

	if (!context)
		return;

	if (context->gdi)
	{
		gdi_free(instance);
		context->gdi = NULL;
	}

	if (context->channels)
	{
		freerdp_channels_disconnect(context->channels, instance);
		freerdp_channels_close(context->channels, instance);
		freerdp_channels_free(context->channels);
		context->channels = NULL;
	}

	if (context->cache)
	{
		cache_free(context->cache);
		context->cache = NULL;
	}

	if (pfc->stopEvent)
	{
		CloseHandle(pfc->stopEvent);
		pfc->stopEvent = NULL;
	}
}

int pfreerdp_client_start(rdpContext* context)
{
	pfContext* pfc = (pfContext*) context;

	ResetEvent(pfc->stopEvent);
	
	if (pfc->finishEvent)
		ResetEvent(pfc->finishEvent);


	rdpSettings* settings = context->settings;
	rdpChannels* channels = context->channels;
	freerdp_client_load_addins(channels, settings);

	if (!freerdp_connect(context->instance))
		return -1;

	pfc->thread = CreateThread(NULL, 0, pf_client_thread, (void*) context, 0, NULL);

	if (!pfc->thread)
		return -1;

	return 0;
}

int pfreerdp_client_stop(rdpContext* context)
{
	pfContext* pfc = (pfContext*) context;

	if (pfc->thread)
	{
		SetEvent(pfc->stopEvent);
		WaitForSingleObject(pfc->thread, INFINITE);
		CloseHandle(pfc->thread);
		pfc->thread = NULL;
	}

	return 0;
}

int RdpClientEntry(RDP_CLIENT_ENTRY_POINTS* pEntryPoints)
{
	pEntryPoints->Version = 1;
	pEntryPoints->Size = sizeof(RDP_CLIENT_ENTRY_POINTS_V1);

	pEntryPoints->GlobalInit = pfreerdp_client_global_init;
	pEntryPoints->GlobalUninit = pfreerdp_client_global_uninit;

	pEntryPoints->ContextSize = sizeof(pfContext);
	pEntryPoints->ClientNew = pfreerdp_client_new;
	pEntryPoints->ClientFree = pfreerdp_client_free;

	pEntryPoints->ClientStart = pfreerdp_client_start;
	pEntryPoints->ClientStop = pfreerdp_client_stop;

	return 0;
}

/**
 * C++ Wrapper Class
 */

bool RdpDecoder::open(const char* filename)
{
	int argc;
	char* argv[4];
	HANDLE thread;
	DWORD dwExitCode;
	pfContext* pfc;
	rdpContext* context;
	rdpSettings* settings;
	RDP_CLIENT_ENTRY_POINTS clientEntryPoints;

	if (filename)
	{
		m_filename = _strdup(filename);

		if (!m_filename)
			return false;
	}

	if (!m_filename)
		return false;

	ZeroMemory(&clientEntryPoints, sizeof(RDP_CLIENT_ENTRY_POINTS));
	clientEntryPoints.Size = sizeof(RDP_CLIENT_ENTRY_POINTS);
	clientEntryPoints.Version = RDP_CLIENT_INTERFACE_VERSION;

	settings = (rdpSettings*) m_settings;
	clientEntryPoints.settings = settings;

	RdpClientEntry(&clientEntryPoints);

	context = freerdp_client_context_new(&clientEntryPoints);
	m_context = (void*) context;

	pfc = (pfContext*) context;
	settings = context->settings;
	m_settings = (rdpSettings*) settings;

    freerdp_settings_set_string(settings, FreeRDP_ServerHostname, m_filename);

	return true;
}

bool RdpDecoder::args(int argc, char** argv)
{
	int status;
	const char* filename;
	rdpContext* context;
	rdpSettings* settings;

	context = (rdpContext*) m_context;
	settings = (rdpSettings*) m_settings;

	if (context)
		settings = context->settings;
	else
		settings = freerdp_settings_new(0);

	if (!settings)
		return false;

	m_settings = settings;

	status = freerdp_client_settings_parse_command_line(settings, argc, argv, TRUE);

	if (status < 0)
		return false;

	filename = freerdp_settings_get_string(settings, FreeRDP_ServerHostname);

	m_filename = _strdup(filename);

	return true;
}

void RdpDecoder::close()
{
	if (m_context)
	{
		freerdp_client_context_free((rdpContext*) m_context);
		m_context = NULL;
	}

	if (m_filename)
	{
		free(m_filename);
		m_filename = NULL;
	}
}

void RdpDecoder::setFinishEvent(HANDLE finishEvent)
{
	m_finishEvent = finishEvent;
}

void RdpDecoder::setFrameCallback(fnFrameCallback func, void* param)
{
	m_frameFunc = func;
	m_frameParam = param;
}

int RdpDecoder::writeBitmap(const char* filename, BYTE* data, int step, int width, int height)
{
	int status;
	wImage img;

	ZeroMemory(&img, sizeof(wImage));
	img.type = WINPR_IMAGE_BITMAP;
	img.width = width;
	img.height = height;
	img.data = data;
	img.scanline = step;
	img.bitsPerPixel = 32;
	img.bytesPerPixel = 4;

	status = winpr_image_write(&img, filename);

	return status;
}

bool RdpDecoder::start()
{
	int status;
	pfContext* pfc;
	rdpContext* context;
	
	context = (rdpContext*) m_context;
	pfc = (pfContext*) m_context;

	if (!pfc)
		return false;

	if (!m_frameFunc)
		return false;

	pfc->frameFunc = m_frameFunc;
	pfc->frameParam = m_frameParam;

	pfc->finishEvent = m_finishEvent;

	status = freerdp_client_start(context);

	if (status < 0)
		return false;

	return true;
}

bool RdpDecoder::stop()
{
	int status;
	pfContext* pfc;
	rdpContext* context;

	context = (rdpContext*) m_context;
	pfc = (pfContext*) m_context;

	status = freerdp_client_stop(context);

	if (status < 0)
		return false;

	return true;
}

static int g_RefCount = 0;

RdpDecoder::RdpDecoder():
	m_context(NULL), m_settings(NULL), m_filename(NULL),
	m_frameParam(NULL), m_frameFunc(NULL), m_finishEvent(NULL)
{
}

RdpDecoder::~RdpDecoder()
{
	close();
}
