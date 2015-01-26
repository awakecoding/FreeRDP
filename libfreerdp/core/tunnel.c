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
#include <winpr/print.h>

#include "tunnel.h"

#define TAG FREERDP_TAG("core.tunnel")

/**
 *                             Multitransport Connection Sequence
 *     client                                                                    server
 *        |                                                                         |
 *        |<------------------Initiate Multitransport Request PDU-------------------| [MS-RDPBCGR]
 *        |-------------------------------------------------------------------------|
 *        |<---------------UDP Connection Initiation (UDP-R or UDP-L)-------------->| [MS-RDPUDP]
 *        |-------------------------------------------------------------------------|
 *        |<------------------Security Layer Handshake (TLS or DTLS)--------------->| RFC 2246, 4346, 5246 OR 4347
 *        |-------------------------------------------------------------------------|
 *        |--------------------------Tunnel Create Request PDU--------------------->|
 *        |<-------------------------Tunnel Create Response PDU---------------------| [MS-RDPEMT]
 *        |<-----------------------------Tunnel Data PDUs-------------------------->|
 *        |-------------------------------------------------------------------------|
 */

/**
 * Protocol encoders/decoders
 */
static void multitransport_trace_tunnel_header(RDP_TUNNEL_HEADER* hdr)
{
	WLog_DBG(TAG, "RDP_TUNNEL_HEADER: Action: %d Flags: %d PayloadLength: %d HeaderLength: %d",
			hdr->action, hdr->flags, hdr->payloadLength, hdr->headerLength);

	if (hdr->headerLength > 4)
	{
		WLog_DBG(TAG, "RDP_TUNNEL_SUBHEADER: SubHeaderLength: %d SubHeaderType: %d",
				hdr->subHeaderLength, hdr->subHeaderType);
	}
}

static BOOL multitransport_read_tunnel_header(wStream* s, RDP_TUNNEL_HEADER* p)
{
	UINT8 actionFlags;
	UINT8 subHeaderLength;

	if (Stream_GetRemainingLength(s) < 4)
		return FALSE;

	Stream_Read_UINT8(s, actionFlags); /* ActionFlags (1 byte) */
	p->action = (actionFlags & 0x0F);
	p->flags = ((actionFlags >> 4) & 0x0F);

	Stream_Read_UINT16(s, p->payloadLength); /* PayloadLength (2 bytes) */
	Stream_Read_UINT8(s, p->headerLength); /* HeaderLength (1 byte) */

	if (p->headerLength > 4)
	{
		if (Stream_GetRemainingLength(s) < 2)
			return FALSE;

		subHeaderLength = p->headerLength - 4;

		Stream_Read_UINT8(s, p->subHeaderLength); /* SubHeaderLength (1 byte) */
		Stream_Read_UINT8(s, p->subHeaderType); /* SubHeaderType (1 byte) */

		if (p->subHeaderLength != subHeaderLength)
			return FALSE;

		if (Stream_GetRemainingLength(s) < (p->subHeaderLength - 2))
			return FALSE;

		p->subHeaderData = Stream_Pointer(s);
		Stream_Seek(s, p->subHeaderLength - 2);
	}

	multitransport_trace_tunnel_header(p);

	return TRUE;
}

static void multitransport_write_tunnel_header(wStream* s, RDP_TUNNEL_HEADER* p)
{
	UINT8 actionFlags;

	actionFlags = p->action | (p->flags << 4);
	Stream_Write_UINT8(s, actionFlags); /* ActionFlags (1 byte) */
	Stream_Write_UINT16(s, p->payloadLength); /* PayloadLength (2 bytes) */
	Stream_Write_UINT8(s, p->headerLength); /* HeaderLength (1 byte) */

	if (p->headerLength > 4)
	{
		Stream_Write_UINT8(s, p->subHeaderLength); /* SubHeaderLength (1 byte) */
		Stream_Write_UINT8(s, p->subHeaderType); /* SubHeaderType (1 byte) */
		Stream_Write(s, p->subHeaderData, p->subHeaderLength - 2);
	}

	multitransport_trace_tunnel_header(p);
}

static void multitransport_trace_tunnel_create_request(RDP_TUNNEL_CREATEREQUEST* createRequest)
{
	BYTE* p = createRequest->securityCookie;

	WLog_DBG(TAG, "RDP_TUNNEL_CREATEREQUEST: RequestId: %d SecurityCookie: "
			"%02X %02X %02X %02X %02X %02X %02X %02X "
			"%02X %02X %02X %02X %02X %02X %02X %02X",
			createRequest->requestID,
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
			p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
}

static BOOL multitransport_read_tunnel_create_request(wStream* s, RDP_TUNNEL_CREATEREQUEST* p)
{
	if (Stream_GetRemainingLength(s) < 24)
		return FALSE;

	Stream_Read_UINT32(s, p->requestID); /* RequestId (4 bytes) */
	Stream_Read_UINT32(s, p->reserved); /* Reserved (4 bytes) */
	Stream_Read(s, p->securityCookie, 16); /* SecurityCookie (16 bytes) */

	multitransport_trace_tunnel_create_request(p);

	return TRUE;
}

static void multitransport_write_tunnel_create_request(wStream* s, RDP_TUNNEL_CREATEREQUEST* p)
{
	Stream_Write_UINT32(s, p->requestID); /* RequestId (4 bytes) */
	Stream_Write_UINT32(s, p->reserved); /* Reserved (4 bytes) */
	Stream_Write(s, p->securityCookie, 16); /* SecurityCookie (16 bytes) */

	multitransport_trace_tunnel_create_request(p);
}

static void multitransport_trace_tunnel_create_response(RDP_TUNNEL_CREATERESPONSE* createResponse)
{
	WLog_DBG(TAG, "RDP_TUNNEL_CREATERESPONSE: hrResponse: 0x%04X",
			createResponse->hrResponse);
}

static BOOL multitransport_read_tunnel_create_response(wStream* s, RDP_TUNNEL_CREATERESPONSE* p)
{
	if (Stream_GetRemainingLength(s) < 4)
		return FALSE;

	Stream_Read_UINT32(s, p->hrResponse); /* HrResponse (4 bytes) */

	multitransport_trace_tunnel_create_response(p);

	return TRUE;
}

static void multitransport_write_tunnel_create_response(wStream* s, RDP_TUNNEL_CREATERESPONSE* p)
{
	Stream_Write_UINT32(s, p->hrResponse); /* HrResponse (4 bytes) */

	multitransport_trace_tunnel_create_response(p);
}

static void multitransport_trace_tunnel_data(RDP_TUNNEL_DATA* tunnelData)
{
	WLog_DBG(TAG, "RDP_TUNNEL_DATA: length: %d",
			tunnelData->length);

	winpr_HexDump(TAG, WLOG_DEBUG, tunnelData->data,
			tunnelData->length);
}

static void multitransport_write_tunnel_data(wStream* s, RDP_TUNNEL_DATA* tunnelData)
{
	Stream_Write(s, tunnelData->data, tunnelData->length);

	multitransport_trace_tunnel_data(tunnelData);
}

static BOOL multitransport_recv_tunnel_data(rdpTunnel* tunnel, wStream* s)
{
	BYTE* data;
	UINT32 length;
	UINT32 flags;
	int status;

	data = Stream_Pointer(s);
	length = Stream_GetRemainingLength(s);
	flags = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;

	WLog_DBG(TAG, "RDP_TUNNEL_DATA: length: %d", length);
	//winpr_HexDump(TAG, WLOG_DEBUG, data, length);

	status = freerdp_recv_drdynvc_data(tunnel->context, data, length, length, flags);

	return TRUE;
}

static BOOL multitransport_recv_pdu(rdpTunnel* tunnel, wStream *s, MULTITRANSPORT_PDU* pdu)
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

	if (pdu->action == RDPTUNNEL_ACTION_DATA)
	{
		if (!multitransport_recv_tunnel_data(tunnel, s))
		{
			WLog_ERR(TAG, "error receiving tunnel data");
			return FALSE;
		}
	}
	else if (pdu->action == RDPTUNNEL_ACTION_CREATEREQUEST)
	{
		RDP_TUNNEL_CREATEREQUEST tunnelCreateRequest;

		ZeroMemory(&tunnelCreateRequest, sizeof(RDP_TUNNEL_CREATEREQUEST));

		if (!multitransport_read_tunnel_create_request(s, &tunnelCreateRequest))
		{
			WLog_ERR(TAG, "error parsing RDP_TUNNEL_CREATEREQUEST");
			return FALSE;
		}
	}
	else if (pdu->action == RDPTUNNEL_ACTION_CREATERESPONSE)
	{
		RDP_TUNNEL_CREATERESPONSE tunnelCreateResponse;

		ZeroMemory(&tunnelCreateResponse, sizeof(RDP_TUNNEL_CREATERESPONSE));

		if (!multitransport_read_tunnel_create_response(s, &tunnelCreateResponse))
		{
			WLog_ERR(TAG, "error parsing RDP_TUNNEL_CREATERESPONSE");
			return FALSE;
		}

		freerdp_set_drdynvc_tunnel(tunnel->context, tunnel);
	}
	else
	{
		WLog_ERR(TAG, "unrecognized action %d in RDP_TUNNEL_HEADER", pdu->action);
		return FALSE;
	}

	return TRUE;
}

int multitransport_send_tunnel_data(rdpTunnel* tunnel, const BYTE* data, UINT32 length)
{
	wStream* s;
	int status;
	UINT32 pduLength;
	RDP_TUNNEL_HEADER tunnelHeader;

	s = Stream_New(NULL, length + 4);

	if (!s)
		return -1;

	ZeroMemory(&tunnelHeader, sizeof(tunnelHeader));
	tunnelHeader.action = RDPTUNNEL_ACTION_DATA;
	tunnelHeader.flags = 0;
	tunnelHeader.payloadLength = length;
	tunnelHeader.headerLength = 4;

	multitransport_write_tunnel_header(s, &tunnelHeader);
	Stream_Write(s, data, length);
	Stream_SealLength(s);

	pduLength = Stream_Length(s);
	status = rdp_udp_write(tunnel->udp, Stream_Buffer(s), pduLength);
	Stream_Free(s, TRUE);

	if (status != pduLength)
		return -1;

	return status;
}

wStream* multitransport_encode_pdu(MULTITRANSPORT_PDU* pdu)
{
	wStream* s;
	RDP_TUNNEL_HEADER tunnelHeader;

	s = Stream_New(NULL, 1024);

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
			tunnelHeader.payloadLength = pdu->u.tunnelData.length;
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
static BOOL multitransport_send_pdu(rdpUdp* udp, MULTITRANSPORT_PDU* pdu)
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

	status = rdp_udp_write(udp, pduptr, pdulen);

	if (status != pdulen)
		return FALSE;

	return TRUE;
}

/*
 * RDP-UDP callbacks
 */
static void multitransport_on_disconnected(rdpUdp* udp)
{
	//rdpTunnel* tunnel = (rdpTunnel*) udp->callbackData;
}

static void multitransport_on_connecting(rdpUdp* udp)
{
	//rdpTunnel* tunnel = (rdpTunnel*) udp->callbackData;
}

static void multitransport_on_connected(rdpUdp* udp)
{
	//rdpTunnel* tunnel = (rdpTunnel*) udp->callbackData;
}

static void multitransport_on_securing(rdpUdp* udp)
{
	//rdpTunnel* tunnel = (rdpTunnel*) udp->callbackData;
}

static void multitransport_on_secured(rdpUdp* udp)
{
	MULTITRANSPORT_PDU pdu;
	rdpTunnel* tunnel = (rdpTunnel*) udp->callbackData;

	ZeroMemory(&pdu, sizeof(pdu));
	pdu.action = RDPTUNNEL_ACTION_CREATEREQUEST;
	pdu.u.tunnelCreateRequest.requestID = tunnel->requestId;
	CopyMemory(pdu.u.tunnelCreateRequest.securityCookie, tunnel->securityCookie, 16);

	multitransport_send_pdu(udp, &pdu);
}

static void multitransport_on_data_received(rdpUdp* udp, BYTE* data, int size)
{
	wStream* s;
	MULTITRANSPORT_PDU pdu;
	rdpTunnel* tunnel = (rdpTunnel*) udp->callbackData;

	s = Stream_New(data, size);

	if (!s)
	{
		WLog_ERR(TAG, "could not create stream");
		return;
	}

	if (!multitransport_recv_pdu(tunnel, s, &pdu))
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
	rdpUdp* udp = NULL;
	rdpTunnel* tunnel = NULL;
	BYTE* p = securityCookie;

	WLog_DBG(TAG, "InitiateMultitransportRequest: RequestId: %d "
			"RequestedProtocol: %d SecurityCookie: "
			"%02X %02X %02X %02X %02X %02X %02X %02X "
			"%02X %02X %02X %02X %02X %02X %02X %02X",
			requestId, requestedProtocol,
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
			p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);

	tunnel = (rdpTunnel*) calloc(1, sizeof(rdpTunnel));

	if (!tunnel)
		goto EXCEPTION;

	udp = rdp_udp_new(multitransport->rdp);

	if (!udp)
		goto EXCEPTION;

	udp->onDisconnected = multitransport_on_disconnected;
	udp->onConnecting = multitransport_on_connecting;
	udp->onConnected = multitransport_on_connected;
	udp->onSecuring = multitransport_on_securing;
	udp->onSecured = multitransport_on_secured;
	udp->onDataReceived = multitransport_on_data_received;

	udp->callbackData = (void*) tunnel;

	if (!rdp_udp_init(udp, requestedProtocol))
		goto EXCEPTION;

	tunnel->udp = udp;
	tunnel->context = udp->rdp->context;
	tunnel->requestId = requestId;
	tunnel->protocol = requestedProtocol;
	CopyMemory(tunnel->securityCookie, securityCookie, 16);

	if (tunnel->protocol == RDPUDP_PROTOCOL_UDPFECL)
		multitransport->udpLTunnel = tunnel;
	else
		multitransport->udpRTunnel = tunnel;

	return TRUE;

EXCEPTION:
	rdp_udp_free(udp);
	free(tunnel);

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
	rdpTunnel* tunnel;

	if (!multitransport)
		return;

	if (multitransport->udpLTunnel)
	{
		tunnel = multitransport->udpLTunnel;
		rdp_udp_free(tunnel->udp);
		free(tunnel);
	}

	if (multitransport->udpRTunnel)
	{
		tunnel = multitransport->udpRTunnel;
		rdp_udp_free(tunnel->udp);
		free(tunnel);
	}

	free(multitransport);
}
