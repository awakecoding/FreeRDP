/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * MULTITRANSPORT PDUs
 *
 * Copyright 2014 Dell Software <Mike.McDonald@software.dell.com>
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

#include <ctype.h>

#include "multitransport.h"

#define TAG FREERDP_TAG("core.multitransport")

/**
 * Utility Functions
 */
static wStream* multitransport_packet_init()
{
	BYTE* buffer;

	buffer = (BYTE*) malloc(1024);

	return buffer ? Stream_New(buffer, 1024) : NULL;
}

static void multitransport_dump_packet(wStream* s)
{
	BYTE* pduptr = Stream_Buffer(s);
	int pdulen = Stream_Length(s);

	while (pdulen > 0)
	{
		int size = (pdulen < 16 ? pdulen : 16);
		int i;

		for (i = 0; i < 16; i++)
		{
			fprintf(stderr, (i < size) ? "%02X " : "   ", pduptr[i]);
		}
		fprintf(stderr, " ");
		for (i = 0; i < size; i++)
		{
			fprintf(stderr, "%c", isprint(pduptr[i]) ? pduptr[i] : '.');
		}
		fprintf(stderr, "\n");

		pduptr += size;
		pdulen -= size;
	}
}

/**
 * Protocol encoders/decoders
 */
static void multitransport_dump_tunnel_header(RDP_TUNNEL_HEADER* p)
{
	fprintf(stderr, "RDP_TUNNEL_HEADER\n");
	fprintf(stderr, ".action=%u\n", p->action);
	fprintf(stderr, ".flags=%u\n", p->flags);
	fprintf(stderr, ".payloadLength=%u\n", p->payloadLength);
	fprintf(stderr, ".headerLength=%u\n", p->headerLength);

	if (p->headerLength > 4)
	{
		fprintf(stderr, "RDP_TUNNEL_SUBHEADER\n");
		fprintf(stderr, ".subHeaderLength=%u\n", p->subHeaderLength);
		fprintf(stderr, ".subHeaderType=%u\n", p->subHeaderType);
		fprintf(stderr, ".subHeaderData=%p\n", p->subHeaderData);
	}
}

static BOOL multitransport_read_tunnel_header(wStream* s, RDP_TUNNEL_HEADER* p)
{
	UINT8 actionFlags;

	if (Stream_GetRemainingLength(s) < 4)
		return FALSE;

	Stream_Read_UINT8(s, actionFlags);
	p->action = (actionFlags & 0x0F);
	p->flags = ((actionFlags >> 4) & 0x0F);
	Stream_Read_UINT16(s, p->payloadLength);
	Stream_Read_UINT8(s, p->headerLength);

	if (p->headerLength > 4)
	{
		UINT8 subHeaderLength;

		if (Stream_GetRemainingLength(s) < 2)
			return FALSE;

		subHeaderLength = p->headerLength - 4;

		Stream_Read_UINT8(s, p->subHeaderLength);
		Stream_Read_UINT8(s, p->subHeaderType);

		if (p->subHeaderLength != subHeaderLength)
			return FALSE;

		if (Stream_GetRemainingLength(s) < (p->subHeaderLength - 2))
			return FALSE;

		p->subHeaderData = Stream_Pointer(s);
		Stream_Seek(s, p->subHeaderLength - 2);
	}

	multitransport_dump_tunnel_header(p);

	return TRUE;
}

static void multitransport_write_tunnel_header(wStream* s, RDP_TUNNEL_HEADER* p)
{
	UINT8 actionFlags;

	actionFlags = p->action | (p->flags << 4);
	Stream_Write_UINT8(s, actionFlags);
	Stream_Write_UINT16(s, p->payloadLength);
	Stream_Write_UINT8(s, p->headerLength);

	if (p->headerLength > 4)
	{
		Stream_Write_UINT8(s, p->subHeaderLength);
		Stream_Write_UINT8(s, p->subHeaderType);
		Stream_Write(s, p->subHeaderData, p->subHeaderLength - 2);
	}

	multitransport_dump_tunnel_header(p);
}

static void multitransport_dump_tunnel_create_request(RDP_TUNNEL_CREATEREQUEST* p)
{
	BYTE* securityCookie = p->securityCookie;

	fprintf(stderr, "RDP_TUNNEL_CREATEREQUEST\n");
	fprintf(stderr, ".requestID=%u\n", p->requestID);
	fprintf(stderr, ".reserved=%u\n", p->reserved);
	fprintf(stderr, ".securityCookie=%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
		securityCookie[0], securityCookie[1], securityCookie[2], securityCookie[3],
		securityCookie[4], securityCookie[5], securityCookie[6], securityCookie[7],
		securityCookie[8], securityCookie[9], securityCookie[10], securityCookie[11],
		securityCookie[12], securityCookie[13], securityCookie[14], securityCookie[15]);
}

static BOOL multitransport_read_tunnel_create_request(wStream* s, RDP_TUNNEL_CREATEREQUEST* p)
{
	if (Stream_GetRemainingLength(s) < 24)
		return FALSE;

	Stream_Read_UINT32(s, p->requestID);
	Stream_Read_UINT32(s, p->reserved);
	Stream_Read(s, p->securityCookie, 16);

	multitransport_dump_tunnel_create_request(p);

	return TRUE;
}

static void multitransport_write_tunnel_create_request(wStream* s, RDP_TUNNEL_CREATEREQUEST* p)
{
	Stream_Write_UINT32(s, p->requestID);
	Stream_Write_UINT32(s, p->reserved);
	Stream_Write(s, p->securityCookie, 16);

	multitransport_dump_tunnel_create_request(p);
}

static void multitransport_dump_tunnel_create_response(RDP_TUNNEL_CREATERESPONSE* p)
{
	fprintf(stderr, "RDP_TUNNEL_CREATERESPONSE\n");
	fprintf(stderr, ".hrResponse=%u\n", p->hrResponse);
}

static BOOL multitransport_read_tunnel_create_response(wStream* s, RDP_TUNNEL_CREATERESPONSE* p)
{
	if (Stream_GetRemainingLength(s) < 4)
		return FALSE;

	Stream_Read_UINT32(s, p->hrResponse);

	multitransport_dump_tunnel_create_response(p);

	return TRUE;
}

static void multitransport_write_tunnel_create_response(wStream* s, RDP_TUNNEL_CREATERESPONSE* p)
{
	Stream_Write_UINT32(s, p->hrResponse);

	multitransport_dump_tunnel_create_response(p);
}

static void multitransport_dump_tunnel_data(RDP_TUNNEL_DATA* p)
{
	fprintf(stderr, "RDP_TUNNEL_DATA\n");
	fprintf(stderr, ".higherLayerDataPointer=%p\n", p->higherLayerDataPointer);
	fprintf(stderr, ".higherLayerDataLength=%u\n", p->higherLayerDataLength);
}

static BOOL multitransport_read_tunnel_data(wStream* s, RDP_TUNNEL_DATA* p)
{
	p->higherLayerDataPointer = Stream_Pointer(s);
	p->higherLayerDataLength = Stream_GetRemainingLength(s);

	multitransport_dump_tunnel_data(p);

	return TRUE;
}

static void multitransport_write_tunnel_data(wStream* s, RDP_TUNNEL_DATA* p)
{
	Stream_Write(s, p->higherLayerDataPointer, p->higherLayerDataLength);

	multitransport_dump_tunnel_data(p);
}

static BOOL multitransport_decode_pdu(wStream *s, MULTITRANSPORT_PDU* pdu)
{
	RDP_TUNNEL_HEADER tunnelHeader;

	ZeroMemory(pdu, sizeof(MULTITRANSPORT_PDU));

	/* Parse the RDP_TUNNEL_HEADER. */
	if (!multitransport_read_tunnel_header(s, &tunnelHeader))
	{
		WLog_ERR(TAG, "error parsing RDP_TUNNEL_HEADER");
		return FALSE;
	}

	pdu->action = tunnelHeader.action;
	pdu->flags = tunnelHeader.flags;
	pdu->subHeaderLength = tunnelHeader.subHeaderLength;
	pdu->subHeaderType = tunnelHeader.subHeaderType;
	pdu->subHeaderData = tunnelHeader.subHeaderData;

	switch (pdu->action)
	{
		case RDPTUNNEL_ACTION_CREATEREQUEST:
			if (!multitransport_read_tunnel_create_request(s, &pdu->u.tunnelCreateRequest))
			{
				WLog_ERR(TAG, "error parsing RDP_TUNNEL_CREATEREQUEST");
				return FALSE;
			}
			break;

		case RDPTUNNEL_ACTION_CREATERESPONSE:
			if (!multitransport_read_tunnel_create_response(s, &pdu->u.tunnelCreateResponse))
			{
				WLog_ERR(TAG, "error parsing RDP_TUNNEL_CREATERESPONSE");
				return FALSE;
			}
			break;

		case RDPTUNNEL_ACTION_DATA:
			if (!multitransport_read_tunnel_data(s, &pdu->u.tunnelData));
			{
				WLog_ERR(TAG, "error parsing RDP_TUNNEL_DATA");
				return FALSE;
			}
			break;

		default:
			WLog_ERR(TAG, "unrecognized action 0x%x in RDP_TUNNEL_HEADER", pdu->action);
			return FALSE;
	}

	return TRUE;
}

wStream* multitransport_encode_pdu(MULTITRANSPORT_PDU* pdu)
{
	wStream* s;
	RDP_TUNNEL_HEADER tunnelHeader;

	s = multitransport_packet_init();

	if (!s)
		return NULL;

	ZeroMemory(&tunnelHeader, sizeof(tunnelHeader));
	tunnelHeader.action = pdu->action;
	tunnelHeader.flags = pdu->flags;

	switch (pdu->action)
	{
		case RDPTUNNEL_ACTION_CREATEREQUEST:
			tunnelHeader.payloadLength = 24;
			break;

		case RDPTUNNEL_ACTION_CREATERESPONSE:
			tunnelHeader.payloadLength = 4;
			break;

		case RDPTUNNEL_ACTION_DATA:
			tunnelHeader.payloadLength = pdu->u.tunnelData.higherLayerDataLength;
			break;
	}
	tunnelHeader.headerLength = 4;

	if (pdu->subHeaderData && (pdu->subHeaderLength > 0))
	{
		tunnelHeader.subHeaderLength = (pdu->subHeaderLength + 2);
		tunnelHeader.subHeaderType = pdu->subHeaderType;
		tunnelHeader.subHeaderData = pdu->subHeaderData;
		tunnelHeader.headerLength += tunnelHeader.subHeaderLength;
	}

	multitransport_write_tunnel_header(s, &tunnelHeader);

	switch (pdu->action)
	{
		case RDPTUNNEL_ACTION_CREATEREQUEST:
			multitransport_write_tunnel_create_request(s, &pdu->u.tunnelCreateRequest);
			break;

		case RDPTUNNEL_ACTION_CREATERESPONSE:
			multitransport_write_tunnel_create_response(s, &pdu->u.tunnelCreateResponse);
			break;

		case RDPTUNNEL_ACTION_DATA:
			multitransport_write_tunnel_data(s, &pdu->u.tunnelData);
			break;
	}

	return s;
}

/**
 * PDUs sent/received over RDP-UDP
 */
static BOOL multitransport_send_pdu(rdpUdp* rdpudp, MULTITRANSPORT_PDU* pdu)
{
	wStream* s;
	BYTE* pduptr;
	int pdulen;
	int status;

	s = multitransport_encode_pdu(pdu);

	if (!s)
		return FALSE;

	Stream_SealLength(s);

	pduptr = Stream_Buffer(s);
	pdulen = Stream_Length(s);

	status = rdpudp_write(rdpudp, pduptr, pdulen);

	if (status != pdulen)
		return FALSE;

	return TRUE;
}

/*
 * RDP-UDP callbacks
 */
static void multitransport_on_disconnected(rdpUdp* rdpudp)
{
	multitransportTunnel* tunnel;

	tunnel = (multitransportTunnel*) rdpudp->callbackData;

	fprintf(stderr, "multitransport_on_disconnected\n");
}

static void multitransport_on_connecting(rdpUdp* rdpudp)
{
	multitransportTunnel* tunnel;

	tunnel = (multitransportTunnel*) rdpudp->callbackData;

	fprintf(stderr, "multitransport_on_connecting\n");
}

static void multitransport_on_connected(rdpUdp* rdpudp)
{
	multitransportTunnel* tunnel;

	tunnel = (multitransportTunnel*) rdpudp->callbackData;

	fprintf(stderr, "multitransport_on_connected\n");
}

static void multitransport_on_securing(rdpUdp* rdpudp)
{
	multitransportTunnel* tunnel;

	tunnel = (multitransportTunnel*) rdpudp->callbackData;

	fprintf(stderr, "multitransport_on_securing\n");
}

static void multitransport_on_secured(rdpUdp* rdpudp)
{
	multitransportTunnel* tunnel;
	MULTITRANSPORT_PDU pdu;

	tunnel = (multitransportTunnel*) rdpudp->callbackData;

	fprintf(stderr, "multitransport_on_secured\n");

	ZeroMemory(&pdu, sizeof(pdu));
	pdu.action = RDPTUNNEL_ACTION_CREATEREQUEST;
	pdu.u.tunnelCreateRequest.requestID = tunnel->requestId;
	CopyMemory(pdu.u.tunnelCreateRequest.securityCookie, tunnel->securityCookie, 16);

	multitransport_send_pdu(rdpudp, &pdu);
}

static void multitransport_on_data_received(rdpUdp* rdpudp, BYTE* data, int size)
{
	wStream* s;
	MULTITRANSPORT_PDU pdu;
	multitransportTunnel* tunnel;

	tunnel = (multitransportTunnel*) rdpudp->callbackData;

	fprintf(stderr, "multitransport_on_data_received\n");
	fprintf(stderr, "data=%p, size=%d\n", data, size);

	s = Stream_New(data, size);

	if (!s)
	{
		WLog_ERR(TAG, "could not create stream");
		return;
	}

	multitransport_dump_packet(s);

	/* Decode the multitransport PDU. */
	if (!multitransport_decode_pdu(s, &pdu))
	{
		WLog_ERR(TAG, "could not decode PDU");
		return;
	}
}

/**
 * PDUs sent/received over main RDP channel
 */
BOOL multitransport_send_initiate_error(
	rdpMultitransport* multitransport, UINT32 requestId, UINT32 hrResponse)
{
	rdpRdp* rdp;
	wStream* s;

	rdp = multitransport->rdp;

	/* Send the response PDU to the server */
	s = rdp_message_channel_pdu_init(rdp);

	if (!s)
		return FALSE;

	WLog_DBG(TAG, "sending initiate error PDU");

	Stream_Write_UINT32(s, requestId); /* requestId (4 bytes) */
	Stream_Write_UINT32(s, hrResponse); /* hrResponse (4 bytes) */

	return rdp_send_message_channel_pdu(rdp, s, SEC_TRANSPORT_RSP);
}

static BOOL multitransport_recv_initiate_request(
	rdpMultitransport* multitransport, UINT32 requestId,
	UINT16 requestedProtocol, BYTE* securityCookie)
{
	multitransportTunnel* tunnel = NULL;
	rdpUdp* rdpudp = NULL;

	WLog_DBG(TAG, "requestId=%x, requestedProtocol=%x", requestId, requestedProtocol);

	tunnel = (multitransportTunnel*) calloc(1, sizeof(multitransportTunnel));

	if (!tunnel)
		goto EXCEPTION;

	rdpudp = rdpudp_new(multitransport->rdp);

	if (!rdpudp)
		goto EXCEPTION;

	rdpudp->onDisconnected = multitransport_on_disconnected;
	rdpudp->onConnecting = multitransport_on_connecting;
	rdpudp->onConnected = multitransport_on_connected;
	rdpudp->onSecuring = multitransport_on_securing;
	rdpudp->onSecured = multitransport_on_secured;
	rdpudp->onDataReceived = multitransport_on_data_received;

	rdpudp->callbackData = (void*) tunnel;

	if (!rdpudp_init(rdpudp, requestedProtocol))
		goto EXCEPTION;

	tunnel->rdpudp = rdpudp;
	tunnel->requestId = requestId;
	tunnel->protocol = requestedProtocol;
	CopyMemory(tunnel->securityCookie, securityCookie, 16);

	if (tunnel->protocol == RDPUDP_PROTOCOL_UDPFECL)
	{
		multitransport->udpLTunnel = tunnel;
	}
	else
	{
		multitransport->udpRTunnel = tunnel;
	}

	return TRUE;

EXCEPTION:
	if (rdpudp)
	{
		rdpudp_free(rdpudp);
	}

	if (tunnel)
	{
		free(tunnel);
	}

	return FALSE;
}

int rdp_recv_multitransport_packet(rdpRdp* rdp, wStream* s)
{
	UINT32 requestId;
	UINT16 requestedProtocol;
	UINT16 reserved;
	BYTE securityCookie[16];

	if (Stream_GetRemainingLength(s) < 24)
		return -1;

	Stream_Read_UINT32(s, requestId); /* requestId (4 bytes) */
	Stream_Read_UINT16(s, requestedProtocol); /* requestedProtocol (2 bytes) */
	Stream_Read_UINT16(s, reserved); /* reserved (2 bytes) */
	Stream_Read(s, securityCookie, 16); /* securityCookie (16 bytes) */

	multitransport_recv_initiate_request(rdp->multitransport,
			requestId, requestedProtocol, securityCookie);

	return 0;
}

rdpMultitransport* multitransport_new(rdpRdp* rdp)
{
	rdpMultitransport* multitransport;

	multitransport = (rdpMultitransport*) calloc(1, sizeof(rdpMultitransport));

	if (multitransport)
	{
		multitransport->rdp = rdp;
	}
	
	return multitransport;
}

void multitransport_free(rdpMultitransport* multitransport)
{
	multitransportTunnel* tunnel;

	if (!multitransport)
		return;

	if (multitransport->udpLTunnel)
	{
		tunnel = (multitransportTunnel*) multitransport->udpLTunnel;
		rdpudp_free(tunnel->rdpudp);
		free(tunnel);
	}

	if (multitransport->udpRTunnel)
	{
		tunnel = (multitransportTunnel*) multitransport->udpRTunnel;
		rdpudp_free(tunnel->rdpudp);
		free(tunnel);
	}

	free(multitransport);
}
