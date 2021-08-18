/**
* FreeRDP: A Remote Desktop Protocol Implementation
* Packet Capture & Replay API
*
* Copyright 2016 Marc-Andre Moreau <marcandre.moreau@gmail.com>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
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

#include <freerdp/log.h>
#include <freerdp/packet.h>
#include <freerdp/crypto/per.h>
#include <freerdp/channels/rdpgfx.h>

#include <winpr/crt.h>
#include <winpr/print.h>
#include <winpr/stream.h>
#include <winpr/winsock.h>

#include "tcp.h"
#include "rdp.h"
#include "client.h"
#include "server.h"

#define TAG FREERDP_TAG("core")

/* PCAP BIO */

struct _WINPR_BIO_PCAP
{
	rdpContext* context;
	HANDLE event;
	rdpPcap* pcap;
	char* filename;
	UINT32 poffset;
	UINT32 plength;
	UINT32 srcAddress;
	UINT32 dstAddress;
	pcap_record record;
	rdpEthHeader eth;
	rdpIPv4Header ipv4;
	rdpTcpHeader tcp;
	wStream* cs;
	BOOL firstPass;
	BOOL mcsDone;
	wStream* mcsPkt;
	UINT64 timestamp;
	UINT32 packetIndex;
};
typedef struct _WINPR_BIO_PCAP WINPR_BIO_PCAP;

int freerdp_packet_client_recv_channel_data(freerdp* instance, UINT16 channelId, BYTE* data, int dataSize, int flags, int totalSize)
{
	UINT32 index;
	rdpMcs* mcs;
	rdpChannels* channels;
	rdpMcsChannel* channel = NULL;
	CHANNEL_OPEN_DATA* pChannelOpenData;
	rdpContext* context = instance->context;
	rdpSettings* settings = context->settings;

	mcs = instance->context->rdp->mcs;
	channels = instance->context->channels;

	if (!channels || !mcs)
		return 1;

	for (index = 0; index < mcs->channelCount; index++)
	{
		if (mcs->channels[index].ChannelId == channelId)
		{
			channel = &mcs->channels[index];
			break;
		}
	}

	if (flags & CHANNEL_PACKET_COMPRESSED)
	{
		BYTE* pDstData = NULL;
		UINT32 DstSize = 0;
		UINT32 size = dataSize;
		UINT32 compressionFlags = (flags & 0x00FF0000) >> 16;

		int bulkStatus = bulk_decompress(context->rdp->bulk, data, size, &pDstData, &DstSize, compressionFlags);

		if (bulkStatus < 0 || (totalSize != DstSize))
		{
			WLog_ERR(TAG, "bulk_decompress() failed");
			return -1;
		}
	}

	if (!channel)
		return 1;

	if (!strcmp(channel->Name, "drdynvc"))
	{
		pChannelOpenData = freerdp_channels_find_channel_open_data_by_name(channels, channel->Name);

		if (!pChannelOpenData)
			return 1;

		if (pChannelOpenData->pChannelOpenEventProc)
		{
			pChannelOpenData->pChannelOpenEventProc(pChannelOpenData->OpenHandle,
				CHANNEL_EVENT_DATA_RECEIVED, data, dataSize, totalSize, flags);
		}
	}

	return 0;
}

static const char* RDPGFX_CMDID_STRINGS[] =
{
	"RDPGFX_CMDID_UNUSED_0000",
	"RDPGFX_CMDID_WIRETOSURFACE_1",
	"RDPGFX_CMDID_WIRETOSURFACE_2",
	"RDPGFX_CMDID_DELETEENCODINGCONTEXT",
	"RDPGFX_CMDID_SOLIDFILL",
	"RDPGFX_CMDID_SURFACETOSURFACE",
	"RDPGFX_CMDID_SURFACETOCACHE",
	"RDPGFX_CMDID_CACHETOSURFACE",
	"RDPGFX_CMDID_EVICTCACHEENTRY",
	"RDPGFX_CMDID_CREATESURFACE",
	"RDPGFX_CMDID_DELETESURFACE",
	"RDPGFX_CMDID_STARTFRAME",
	"RDPGFX_CMDID_ENDFRAME",
	"RDPGFX_CMDID_FRAMEACKNOWLEDGE",
	"RDPGFX_CMDID_RESETGRAPHICS",
	"RDPGFX_CMDID_MAPSURFACETOOUTPUT",
	"RDPGFX_CMDID_CACHEIMPORTOFFER",
	"RDPGFX_CMDID_CACHEIMPORTREPLY",
	"RDPGFX_CMDID_CAPSADVERTISE",
	"RDPGFX_CMDID_CAPSCONFIRM",
	"RDPGFX_CMDID_UNUSED_0014",
	"RDPGFX_CMDID_MAPSURFACETOWINDOW"
};

static const char* rdpgfx_get_cmd_id_string(UINT16 cmdId)
{
	if (cmdId <= RDPGFX_CMDID_MAPSURFACETOWINDOW)
		return RDPGFX_CMDID_STRINGS[cmdId];
	else
		return "RDPGFX_CMDID_UNKNOWN";
}

int freerdp_packet_server_recv_rdpgfx_data(rdpContext* context, wStream* s)
{
	RDPGFX_HEADER header;

	if (Stream_GetRemainingLength(s) < 8)
		return -1;

	Stream_Read_UINT16(s, header.cmdId); /* cmdId (2 bytes) */
	Stream_Read_UINT16(s, header.flags); /* flags (2 bytes) */
	Stream_Read_UINT32(s, header.pduLength); /* pduLength (4 bytes) */

	if (header.cmdId == RDPGFX_CMDID_FRAMEACKNOWLEDGE)
	{
		if (Stream_GetRemainingLength(s) < 12)
			return -1;

		Stream_Seek_UINT32(s); /* queueDepth (4 bytes) */
		Stream_Seek_UINT32(s); /* frameId (4 bytes) */
		Stream_Seek_UINT32(s); /* totalFramesDecoded (4 bytes) */
	}

	WLog_WARN(TAG, "EGFX cmdId: %s (0x%04X) flags: 0x%04X pduLength: %d",
		rdpgfx_get_cmd_id_string(header.cmdId), header.cmdId, header.flags, header.pduLength);

	return 1;
}

struct DRDYNVC_PCAP
{
	wStream* staticData;
	UINT32 staticLength;
	wStream* dynamicData;
	UINT32 dynamicLength;
};
typedef struct DRDYNVC_PCAP DRDYNVC_PCAP;

static DRDYNVC_PCAP g_DrDynVC = { NULL, 0, NULL, 0 };

int freerdp_packet_server_recv_dynamic_data(rdpContext* context, wStream* s, UINT32 channelId)
{
	const char* channelName;
	rdpChannels* channels = context->channels;

	if (!channels->drdynvc)
		return 1;

	channelName = channels->drdynvc->GetChannelName(channels->drdynvc, channelId);

	if (!strcmp(channelName, RDPGFX_DVC_CHANNEL_NAME))
	{
		freerdp_packet_server_recv_rdpgfx_data(context, s);
	}

	return 1;
}

static UINT32 drdynvc_read_variable_uint(wStream* s, int cbLen)
{
	UINT32 val = 0;

	if (cbLen == 0)
		Stream_Read_UINT8(s, val);
	else if (cbLen == 1)
		Stream_Read_UINT16(s, val);
	else
		Stream_Read_UINT32(s, val);

	return val;
}

UINT freerdp_packet_server_recv_drdynvc_data(rdpContext* context, BYTE* data, UINT32 dataLength, UINT32 totalLength, UINT32 dataFlags)
{
	DRDYNVC_PCAP* drdynvc = &g_DrDynVC;

	if ((dataFlags & CHANNEL_FLAG_SUSPEND) || (dataFlags & CHANNEL_FLAG_RESUME))
		return CHANNEL_RC_OK;

	if (dataFlags & CHANNEL_FLAG_FIRST)
	{
		drdynvc->staticLength = totalLength;

		if (!drdynvc->staticData)
			drdynvc->staticData = Stream_New(NULL, totalLength);

		Stream_SetPosition(drdynvc->staticData, 0);
		Stream_EnsureCapacity(drdynvc->staticData, totalLength);
	}

	if (!drdynvc->staticData)
		return CHANNEL_RC_NO_MEMORY;

	if (!Stream_EnsureRemainingCapacity(drdynvc->staticData, (size_t) dataLength))
	{
		Stream_Free(drdynvc->staticData, TRUE);
		drdynvc->staticData = NULL;
		return ERROR_INTERNAL_ERROR;
	}

	Stream_Write(drdynvc->staticData, data, dataLength);

	if (dataFlags & CHANNEL_FLAG_LAST)
	{
		int cmd;
		int sp;
		int cbChId;
		BYTE value;
		UINT32 channelId;
		UINT32 dataSize;

		Stream_SealLength(drdynvc->staticData);
		Stream_SetPosition(drdynvc->staticData, 0);

		{
			if (Stream_GetRemainingLength(drdynvc->staticData) < 1)
				return ERROR_INVALID_DATA;

			Stream_Read_UINT8(drdynvc->staticData, value);

			cmd = (value & 0xF0) >> 4;
			sp = (value & 0x0C) >> 2;
			cbChId = (value & 0x03);

			if ((cmd == DATA_FIRST_PDU) || (cmd == DATA_PDU))
			{
				channelId = drdynvc_read_variable_uint(drdynvc->staticData, cbChId);

				dataSize = (UINT32) Stream_GetRemainingLength(drdynvc->staticData);

				if (cmd == DATA_FIRST_PDU)
				{
					drdynvc->dynamicLength = drdynvc_read_variable_uint(drdynvc->staticData, sp);

					if (!drdynvc->dynamicData)
						drdynvc->dynamicData = Stream_New(NULL, drdynvc->dynamicLength);

					Stream_SetPosition(drdynvc->dynamicData, 0);
					Stream_EnsureCapacity(drdynvc->dynamicData, drdynvc->dynamicLength);
				}
				else if (cmd == DATA_PDU)
				{
					if (!drdynvc->dynamicLength)
						drdynvc->dynamicLength = dataSize;

					if (!drdynvc->dynamicData)
						drdynvc->dynamicData = Stream_New(NULL, drdynvc->dynamicLength);

					Stream_SetPosition(drdynvc->dynamicData, 0);
					Stream_EnsureCapacity(drdynvc->dynamicData, drdynvc->dynamicLength);
				}

				if (!drdynvc->dynamicData)
					return ERROR_INTERNAL_ERROR;

				if ((Stream_GetPosition(drdynvc->dynamicData) + dataSize) > drdynvc->dynamicLength)
					return ERROR_INVALID_DATA;

				if (!Stream_EnsureRemainingCapacity(drdynvc->dynamicData, dataSize))
					return ERROR_INTERNAL_ERROR;

				Stream_Copy(drdynvc->dynamicData, drdynvc->staticData, dataSize);

				if (((UINT32) Stream_GetPosition(drdynvc->dynamicData)) >= drdynvc->dynamicLength)
				{
					Stream_SealLength(drdynvc->dynamicData);
					Stream_SetPosition(drdynvc->dynamicData, 0);

					freerdp_packet_server_recv_dynamic_data(context, drdynvc->dynamicData, channelId);

					drdynvc->dynamicLength = 0;
				}
			}
			else if (cmd == CAPABILITY_REQUEST_PDU)
			{
				UINT16 version;

				if (Stream_GetRemainingLength(drdynvc->staticData) < 3)
					return ERROR_INVALID_DATA;

				Stream_Seek_UINT8(drdynvc->staticData); /* pad */
				Stream_Read_UINT16(drdynvc->staticData, version); /* version */

				if ((version == 2) || (version == 3))
				{
					if (Stream_GetRemainingLength(drdynvc->staticData) < 8)
						return ERROR_INVALID_DATA;

					Stream_Seek_UINT16(drdynvc->staticData); /* PriorityCharge0 */
					Stream_Seek_UINT16(drdynvc->staticData); /* PriorityCharge1 */
					Stream_Seek_UINT16(drdynvc->staticData); /* PriorityCharge2 */
					Stream_Seek_UINT16(drdynvc->staticData); /* PriorityCharge3 */
				}
			}

			Stream_SetPosition(drdynvc->staticData, 0);
			Stream_SetLength(drdynvc->staticData, 0);
		}
	}

	return CHANNEL_RC_OK;
}

int freerdp_packet_server_recv_channel_data(freerdp* instance, UINT16 channelId, BYTE* data, int dataSize, int flags, int totalSize)
{
	UINT32 index;
	rdpMcs* mcs;
	rdpChannels* channels;
	rdpMcsChannel* channel = NULL;
	CHANNEL_OPEN_DATA* pChannelOpenData;
	rdpContext* context = instance->context;
	rdpSettings* settings = context->settings;

	mcs = instance->context->rdp->mcs;
	channels = instance->context->channels;

	if (!channels || !mcs)
		return 1;

	for (index = 0; index < mcs->channelCount; index++)
	{
		if (mcs->channels[index].ChannelId == channelId)
		{
			channel = &mcs->channels[index];
			break;
		}
	}

	if (!channel)
		return 1;

	if (!strcmp(channel->Name, "drdynvc") && 0)
	{
		UINT error;

		pChannelOpenData = freerdp_channels_find_channel_open_data_by_name(channels, channel->Name);

		if (!pChannelOpenData)
			return 1;

		error = freerdp_packet_server_recv_drdynvc_data(context, data, dataSize, totalSize, flags);

		if (error)
			WLog_WARN(TAG, "freerdp_packet_server_recv_drdynvc_data: 0x%04X", error);
	}

	return 0;
}

BOOL freerdp_packet_read_header(wStream* s, UINT16* length, UINT16* channelId)
{
	BYTE li;
	BYTE byte;
	BYTE code;
	BYTE choice;
	UINT16 initiator;
	enum DomainMCSPDU MCSPDU;
	enum DomainMCSPDU domainMCSPDU;

	MCSPDU = DomainMCSPDU_SendDataRequest;

	tpkt_read_header(s, length);

	if (!tpdu_read_header(s, &code, &li, *length))
		return FALSE;

	if (code != X224_TPDU_DATA)
	{
		if (code == X224_TPDU_DISCONNECT_REQUEST)
			return TRUE;

		return FALSE;
	}

	if (!per_read_choice(s, &choice))
		return FALSE;

	domainMCSPDU = (enum DomainMCSPDU) (choice >> 2);

	if (domainMCSPDU != MCSPDU)
	{
		if (domainMCSPDU != DomainMCSPDU_DisconnectProviderUltimatum)
			return FALSE;
	}

	MCSPDU = domainMCSPDU;

	if ((size_t) (*length - 8) > Stream_GetRemainingLength(s))
		return FALSE;

	if (Stream_GetRemainingLength(s) < 5)
		return FALSE;

	per_read_integer16(s, &initiator, MCS_BASE_CHANNEL_ID); /* initiator (UserId) */
	per_read_integer16(s, channelId, 0); /* channelId */
	Stream_Read_UINT8(s, byte); /* dataPriority + Segmentation (0x70) */

	if (!per_read_length(s, length)) /* userData (OCTET_STRING) */
		return FALSE;

	if (*length > Stream_GetRemainingLength(s))
		return FALSE;

	return TRUE;
}

int freerdp_packet_client_to_server(BIO* bio, rdpContext* context, wStream* s, UINT32 timestamp)
{
	size_t pos;
	UINT32 index;
	rdpRdp* rdp = context->rdp;
	rdpMcs* mcs = rdp->mcs;
	BOOL tpktDataPdu = FALSE;
	rdpSettings* settings = context->settings;
	WINPR_BIO_PCAP* ptr = (WINPR_BIO_PCAP*) BIO_get_data(bio);
	UINT16 tlength;

	if (!ptr->firstPass)
	{
		UINT16 li;
		int length;

		pos = Stream_GetPosition(s);

		if (tpkt_read_header(s, &tlength) && tpdu_read_data(s, &li, tlength) &&
			ber_read_application_tag(s, MCS_TYPE_CONNECT_INITIAL, &length))
		{
			Stream_SetPosition(s, pos);
			ptr->mcsPkt = Stream_New(NULL, Stream_GetRemainingLength(s));
			Stream_Copy(s, ptr->mcsPkt, Stream_GetRemainingLength(s));
			Stream_SetPosition(ptr->mcsPkt, 0);
		}

		Stream_SetPosition(s, pos);

		if (ptr->mcsPkt)
			ptr->firstPass = TRUE;

		return 1;
	}
	else
	{
		UINT16 length;
		UINT16 channelId = 0;

		pos = Stream_GetPosition(s);

		if (freerdp_packet_read_header(s, &length, &channelId))
			tpktDataPdu = TRUE;

		Stream_SetPosition(s, pos);
	}

	if (!ptr->mcsDone)
	{
		UINT32 options;
		const char* name;

		ptr->mcsDone = TRUE;

		mcs_recv_connect_initial(mcs, ptr->mcsPkt);

		settings->NetworkAutoDetect = FALSE;
		settings->SupportHeartbeatPdu = FALSE;
		settings->SupportMultitransport = FALSE;

		settings->ChannelCount = mcs->channelCount;

		settings->DeviceRedirection = FALSE;
		settings->EncomspVirtualChannel = FALSE;
		settings->RemdeskVirtualChannel = FALSE;

		settings->DynamicChannelCount = 0;
		settings->SupportDynamicChannels = FALSE;

		for (index = 0; index < mcs->channelCount; index++)
		{
			name = mcs->channels[index].Name;
			options = mcs->channels[index].options;

			CopyMemory(settings->ChannelDefArray[index].name, name, 8);
			settings->ChannelDefArray[index].options = options;

			WLog_INFO(TAG, " %s", name);

			if (!strcmp(name, "drdynvc"))
				settings->SupportDynamicChannels = TRUE;
			else if (!strcmp(name, "encomsp"))
				settings->EncomspVirtualChannel = TRUE;
			else if (!strcmp(name, "remdesk"))
				settings->RemdeskVirtualChannel = TRUE;
			else if (!strcmp(name, "rdpdr"))
				settings->DeviceRedirection = TRUE;
		}

		mcs_initialize_client_channels(mcs, settings);

		if (settings->SupportDynamicChannels)
		{
			settings->SupportGraphicsPipeline = TRUE;
		}
		else
		{
			settings->SupportGraphicsPipeline = FALSE;
			settings->RemoteFxCodec = TRUE;
		}

		if (settings->EncomspVirtualChannel && settings->RemdeskVirtualChannel)
			settings->LyncRdpMode = TRUE;
	}
	
	if (tpktDataPdu)
	{
		UINT16 length;
		UINT16 channelId = 0;

		if (!freerdp_packet_read_header(s, &length, &channelId))
			return 1;

		if (channelId != MCS_GLOBAL_CHANNEL_ID)
		{
			UINT32 length;
			UINT32 flags;
			int chunkLength;

			if (Stream_GetRemainingLength(s) < 8)
				return FALSE;

			Stream_Read_UINT32(s, length);
			Stream_Read_UINT32(s, flags);
			chunkLength = (int) Stream_GetRemainingLength(s);

			freerdp_packet_server_recv_channel_data(context->instance,
				channelId, Stream_Pointer(s), chunkLength, flags, length);
		}
	}

	return 1;
}

static int transport_bio_pcap_init(BIO* bio, const char* filename);
static int transport_bio_pcap_uninit(BIO* bio);

static BOOL transport_bio_pcap_read_ethernet_header(FILE* fp, rdpEthHeader* ethernet)
{
	wStream* s;
	BYTE buffer[14];

	if (!fp || !ethernet)
		return FALSE;

	if (fread(buffer, 14, 1, fp) != 1)
		return FALSE;

	s = Stream_New(buffer, 14);

	if (!s)
		return FALSE;
	
	Stream_Read(s, ethernet->Destination, 6);
	Stream_Read(s, ethernet->Source, 6);
	Stream_Read_UINT16_BE(s, ethernet->Type);
	
	Stream_Free(s, FALSE);

	return TRUE;
}

static BOOL transport_bio_pcap_read_ipv4_header(FILE* fp, rdpIPv4Header* ipv4)
{
	wStream* s;
	BYTE bytes8;
	UINT16 bytes16;
	BYTE buffer[20];

	if (!fp || !ipv4)
		return FALSE;

	if (fread(buffer, 20, 1, fp) != 1)
		return FALSE;

	s = Stream_New(buffer, 20);
	
	if (!s)
		return FALSE;

	Stream_Read_UINT8(s, bytes8);
	ipv4->Version = (bytes8 >> 4) & 0x0F;
	ipv4->InternetHeaderLength = bytes8 & 0x0F;

	Stream_Read_UINT8(s, ipv4->TypeOfService);
	Stream_Read_UINT16_BE(s, ipv4->TotalLength);
	Stream_Read_UINT16_BE(s, ipv4->Identification);
	
	Stream_Read_UINT16_BE(s, bytes16);
	ipv4->InternetProtocolFlags = (bytes16 >> 13) & 0x03;
	ipv4->FragmentOffset = bytes16 & 0x1FFF;

	Stream_Read_UINT8(s, ipv4->TimeToLive);
	Stream_Read_UINT8(s, ipv4->Protocol);
	Stream_Read_UINT16(s, ipv4->HeaderChecksum);
	Stream_Read_UINT32_BE(s, ipv4->SourceAddress);
	Stream_Read_UINT32_BE(s, ipv4->DestinationAddress);
	
	Stream_Rewind(s, 10);
	Stream_Read_UINT16(s, ipv4->HeaderChecksum);
	Stream_Seek(s, 8);
	
	Stream_Free(s, FALSE);
	
	return TRUE;
}

static BOOL transport_bio_pcap_read_tcp_header(FILE* fp, rdpTcpHeader* tcp)
{
	wStream* s;
	BYTE bytes8;
	BYTE buffer[20];

	if (!fp || !tcp)
		return FALSE;

	if (fread(buffer, 20, 1, fp) != 1)
		return FALSE;

	s = Stream_New(buffer, 20);
	
	if (!s)
		return FALSE;

	Stream_Read_UINT16_BE(s, tcp->SourcePort);
	Stream_Read_UINT16_BE(s, tcp->DestinationPort);
	Stream_Read_UINT32_BE(s, tcp->SequenceNumber);
	Stream_Read_UINT32_BE(s, tcp->AcknowledgementNumber);
	
	Stream_Read_UINT8(s, bytes8);
	tcp->Offset = (bytes8 >> 4) & 0x0F;
	tcp->Reserved = bytes8 & 0x0F;

	Stream_Read_UINT8(s, tcp->TcpFlags);
	Stream_Read_UINT16_BE(s, tcp->Window);
	Stream_Read_UINT16_BE(s, tcp->Checksum);
	Stream_Read_UINT16_BE(s, tcp->UrgentPointer);

	Stream_Free(s, FALSE);

	return TRUE;
}

BOOL transport_bio_pcap_process_first_packet(BIO* bio)
{
	wStream* s;
	BYTE li = 0;
	BYTE code = 0;
	UINT16 length;
	BOOL client = TRUE;
	UINT32 protocol = PROTOCOL_RDP;
	WINPR_BIO_PCAP* ptr = (WINPR_BIO_PCAP*) BIO_get_data(bio);
	rdpContext* context = ptr->context;
	rdpSettings* settings = context->settings;
	rdpRdp* rdp = context->rdp;
	rdpNego* nego = rdp->nego;

	s = Stream_New(NULL, ptr->plength);

	if (!s)
		return FALSE;

	fread(Stream_Buffer(s), 1, ptr->plength, ptr->pcap->fp);
	fseek(ptr->pcap->fp, -1 * ptr->plength, SEEK_CUR);
	Stream_SetLength(s, ptr->plength);
	Stream_SetPosition(s, 0);

	settings->RdpSecurity = TRUE;
	settings->TlsSecurity = FALSE;
	settings->NlaSecurity = FALSE;

	tpkt_read_header(s, &length);

	if (length && tpdu_read_header(s, &code, &li, length))
	{
		BYTE type;

		if (code == X224_TPDU_CONNECTION_REQUEST)
		{
			if (nego_read_request_token_or_cookie(nego, s))
			{
				if (Stream_GetRemainingLength(s) >= 8)
				{
					Stream_Read_UINT8(s, type); /* Type */

					if (type == TYPE_RDP_NEG_REQ)
					{
						Stream_Seek_UINT8(s); /* flags */
						Stream_Seek_UINT16(s); /* length */
						Stream_Read_UINT32(s, protocol); /* selectedProtocol */
					}
				}
			}

			client = TRUE;
		}
		else if (code == X224_TPDU_CONNECTION_CONFIRM)
		{
			if (li > 6)
			{
				Stream_Read_UINT8(s, type); /* Type */

				if (type == TYPE_RDP_NEG_RSP)
				{
					Stream_Seek_UINT8(s); /* flags */
					Stream_Seek_UINT16(s); /* length */
					Stream_Read_UINT32(s, protocol); /* selectedProtocol */
				}
			}

			client = FALSE;
		}
	}

	settings->RdpSecurity = (protocol == PROTOCOL_RDP) ? TRUE : FALSE;
	settings->TlsSecurity = (protocol & PROTOCOL_SSL) ? TRUE : FALSE;
	settings->NlaSecurity = (protocol & PROTOCOL_HYBRID) ? TRUE : FALSE;

	nego_enable_rdp(nego, settings->RdpSecurity);
	nego_enable_tls(nego, settings->TlsSecurity);
	nego_enable_nla(nego, settings->NlaSecurity);

	Stream_Free(s, TRUE);

	return client;
}

static BOOL transport_bio_pcap_next(BIO* bio)
{
	WINPR_BIO_PCAP* ptr = (WINPR_BIO_PCAP*) BIO_get_data(bio);
	rdpContext* context = ptr->context;
	rdpSettings* settings = context->settings;

	if (!ptr->plength)
	{
		if (!pcap_has_next_record(ptr->pcap))
			return FALSE;

		if (!pcap_get_next_record_header(ptr->pcap, &ptr->record))
			return FALSE;

		ptr->poffset = 0;
		ptr->plength = ptr->record.length;

		ptr->timestamp = (ptr->record.header.ts_sec * 1000) + (ptr->record.header.ts_usec / 1000);
		metrics_set_session_time(context->metrics, ptr->timestamp);

		if (ptr->plength < 54)
			return FALSE;

		if (!transport_bio_pcap_read_ethernet_header(ptr->pcap->fp, &ptr->eth))
			return FALSE;

		if (!transport_bio_pcap_read_ipv4_header(ptr->pcap->fp, &ptr->ipv4))
			return FALSE;

		if (!transport_bio_pcap_read_tcp_header(ptr->pcap->fp, &ptr->tcp))
			return FALSE;

		ptr->poffset = 0;
		ptr->plength -= 54;
		ptr->packetIndex++;

		if (!ptr->srcAddress)
		{
			if (transport_bio_pcap_process_first_packet(bio))
			{
				/* first packet is sent by the client */
				ptr->srcAddress = ptr->ipv4.SourceAddress;
				ptr->dstAddress = ptr->ipv4.DestinationAddress;
			}
			else
			{
				/* first packet is sent by the server */
				ptr->srcAddress = ptr->ipv4.DestinationAddress;
				ptr->dstAddress = ptr->ipv4.SourceAddress;
			}
		}

		if (ptr->srcAddress == ptr->ipv4.SourceAddress)
		{
			Stream_EnsureCapacity(ptr->cs, ptr->plength);
			fread(Stream_Buffer(ptr->cs), 1, ptr->plength, ptr->pcap->fp);
			Stream_SetLength(ptr->cs, ptr->plength);
			Stream_SetPosition(ptr->cs, 0);
			ptr->poffset = 0;
			ptr->plength = 0;

			freerdp_packet_client_to_server(bio, ptr->context, ptr->cs, 0);

			return transport_bio_pcap_next(bio);
		}

		return TRUE;
	}

	return TRUE;
}

static BOOL transport_bio_pcap_first(BIO* bio)
{
	WINPR_BIO_PCAP* ptr = (WINPR_BIO_PCAP*)BIO_get_data(bio);
	rdpContext* context = ptr->context;

	while (transport_bio_pcap_next(bio) && !ptr->firstPass)
	{
		fseek(ptr->pcap->fp, ptr->plength, SEEK_CUR);
		ptr->poffset = 0;
		ptr->plength = 0;
	}

	ptr->poffset = 0;
	ptr->plength = 0;
	ptr->srcAddress = 0;
	ptr->dstAddress = 0;

	pcap_close(ptr->pcap);
	ptr->pcap = pcap_open(ptr->filename, FALSE);

	ptr->packetIndex = 0;

	return ptr->mcsPkt ? TRUE : FALSE;
}

static long transport_bio_pcap_callback(BIO* bio, int mode, const char* argp, int argi, long argl, long ret)
{
	return 1;
}

static int transport_bio_pcap_write(BIO* bio, const char* buf, int size)
{
	int status = 0;
	WINPR_BIO_PCAP* ptr = (WINPR_BIO_PCAP*) BIO_get_data(bio);

	if (!buf)
		return 0;

	BIO_clear_flags(bio, BIO_FLAGS_WRITE);

	status = size;

	BIO_set_flags(bio, (BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY));

	return status;
}

static int transport_bio_pcap_read(BIO* bio, char* buf, int size)
{
	int status = 0;
	WINPR_BIO_PCAP* ptr = (WINPR_BIO_PCAP*) BIO_get_data(bio);

	if (!buf)
		return 0;

	BIO_clear_flags(bio, BIO_FLAGS_READ);

	if (!ptr->firstPass)
		transport_bio_pcap_first(bio);

	if (!transport_bio_pcap_next(bio))
		goto failure;

	status = ptr->plength - ptr->poffset;

	if (status > size)
		status = size;

	status = (int) fread(buf, 1, status, ptr->pcap->fp);

	if (status < 0)
		goto failure;

	ptr->poffset += status;

	if (ptr->poffset == ptr->plength)
	{
		ptr->poffset = 0;
		ptr->plength = 0;
	}

	BIO_set_flags(bio, (BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY));

	return status;

failure:
	BIO_clear_flags(bio, BIO_FLAGS_SHOULD_RETRY);
	ResetEvent(ptr->event);
	return -1;
}

static int transport_bio_pcap_puts(BIO* bio, const char* str)
{
	return 1;
}

static int transport_bio_pcap_gets(BIO* bio, char* str, int size)
{
	return 1;
}

static long transport_bio_pcap_ctrl(BIO* bio, int cmd, long arg1, void* arg2)
{
	int status = -1;
	WINPR_BIO_PCAP* ptr = (WINPR_BIO_PCAP*) BIO_get_data(bio);

	if (cmd == BIO_C_SET_SOCKET)
	{
		return 1;
	}
	else if (cmd == BIO_C_GET_SOCKET)
	{
		return 1;
	}
	else if (cmd == BIO_C_GET_EVENT)
	{
		if (!BIO_get_init(bio) || !arg2)
			return 0;

		*((ULONG_PTR*) arg2) = (ULONG_PTR) ptr->event;

		return 1;
	}
	else if (cmd == BIO_C_SET_NONBLOCK)
	{
		return 1;
	}
	else if (cmd == BIO_C_WAIT_READ)
	{
		return 1;
	}
	else if (cmd == BIO_C_WAIT_WRITE)
	{
		return 1;
	}
	else if (cmd == BIO_C_SET_CONNECT)
	{
		if (arg1 == 0)
		{
			transport_bio_pcap_uninit(bio);
			transport_bio_pcap_init(bio, (char*) arg2);
		}
	}
	else if (cmd == BIO_C_SET_RDP_CONTEXT)
	{
		rdpContext* context = (rdpContext*) arg2;
		freerdp* instance = context->instance;

		ptr->context = context;
		instance->ReceiveChannelData = freerdp_packet_client_recv_channel_data;
	}

	switch (cmd)
	{
		case BIO_C_SET_FD:
			status = 1;
			break;

		case BIO_C_GET_FD:
			status = 1;
			break;

		case BIO_CTRL_GET_CLOSE:
			status = BIO_get_shutdown(bio);
			break;

		case BIO_CTRL_SET_CLOSE:
			BIO_set_shutdown(bio, (int)arg1);
			status = 1;
			break;

		case BIO_CTRL_DUP:
			status = 1;
			break;

		case BIO_CTRL_FLUSH:
			status = 1;
			break;

		default:
			status = 0;
			break;
	}

	return status;
}

static int transport_bio_pcap_init(BIO* bio, const char* filename)
{
	WINPR_BIO_PCAP* ptr = (WINPR_BIO_PCAP*) BIO_get_data(bio);

	ptr->cs = Stream_New(NULL, 1024);

	if (!ptr->cs)
		return 0;

	ptr->filename = _strdup(filename);
	ptr->pcap = pcap_open(ptr->filename, FALSE);

    BIO_set_flags(bio, BIO_FLAGS_SHOULD_RETRY);
	BIO_set_init(bio, 1);

	ptr->event = CreateEvent(NULL, TRUE, FALSE, NULL);

	if (!ptr->event)
		return 0;

	SetEvent(ptr->event);

	return 1;
}

static int transport_bio_pcap_uninit(BIO* bio)
{
	WINPR_BIO_PCAP* ptr = (WINPR_BIO_PCAP*) BIO_get_data(bio);

	if (BIO_get_init(bio))
	{
		pcap_close(ptr->pcap);
		ptr->pcap = NULL;
	}

	if (ptr->event)
	{
		CloseHandle(ptr->event);
		ptr->event = NULL;
	}

	if (ptr->cs)
	{
		Stream_Free(ptr->cs, TRUE);
		ptr->cs = NULL;
	}

	if (ptr->mcsPkt)
	{
		Stream_Free(ptr->mcsPkt, TRUE);
		ptr->mcsPkt = NULL;
	}

	if (ptr->filename)
	{
		free(ptr->filename);
		ptr->filename = NULL;
	}

	BIO_set_init(bio, 0);
	BIO_set_flags(bio, 0);

	return 1;
}

static int transport_bio_pcap_new(BIO* bio)
{
	WINPR_BIO_PCAP* ptr;

	BIO_set_init(bio, 0);
	BIO_set_data(bio, NULL);
	BIO_set_flags(bio, BIO_FLAGS_SHOULD_RETRY);

	ptr = (WINPR_BIO_PCAP*) calloc(1, sizeof(WINPR_BIO_PCAP));

	if (!ptr)
		return 0;

    BIO_set_data(bio, ptr);

	return 1;
}

static int transport_bio_pcap_free(BIO* bio)
{
	if (!bio)
		return 0;

	if (BIO_next(bio))
	{
		BIO_free(BIO_next(bio));
		BIO_set_next(bio, NULL);
	}

	transport_bio_pcap_uninit(bio);

	if (BIO_get_data(bio))
	{
		free(BIO_get_data(bio));
		BIO_set_data(bio, NULL);
	}

	return 1;
}

BIO_METHOD* BIO_s_pcap(void)
{
	BIO_METHOD* meth = BIO_meth_new(BIO_TYPE_PCAP, "PCAP");
	BIO_meth_set_write(meth, transport_bio_pcap_write);
	BIO_meth_set_read(meth, transport_bio_pcap_read);
	BIO_meth_set_puts(meth, transport_bio_pcap_puts);
	BIO_meth_set_gets(meth, transport_bio_pcap_gets);
	BIO_meth_set_ctrl(meth, transport_bio_pcap_ctrl);
	BIO_meth_set_create(meth, transport_bio_pcap_new);
	BIO_meth_set_destroy(meth, transport_bio_pcap_free);
	BIO_meth_set_callback_ctrl(meth, NULL);

	return meth;
}