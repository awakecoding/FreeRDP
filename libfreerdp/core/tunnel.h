/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Multitransport PDUs
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

#ifndef __MULTITRANSPORT_H
#define __MULTITRANSPORT_H

typedef struct rdp_multitransport rdpMultitransport;

#include "rdp.h"
#include "udp.h"

#include <freerdp/log.h>
#include <freerdp/freerdp.h>

#include <winpr/stream.h>

#define RDPTUNNEL_ACTION_CREATEREQUEST			0x0
#define RDPTUNNEL_ACTION_CREATERESPONSE			0x1
#define RDPTUNNEL_ACTION_DATA				0x2

#define RDPTUNNEL_TYPE_ID_AUTODETECT_REQUEST		0x00
#define RDPTUNNEL_TYPE_ID_AUTODETECT_RESPONSE		0x01

struct _RDP_TUNNEL_HEADER
{
	BYTE action;
	BYTE flags;
	UINT16 payloadLength;
	BYTE headerLength;
	BYTE subHeaderLength;
	BYTE subHeaderType;
	BYTE* subHeaderData;
};
typedef struct _RDP_TUNNEL_HEADER RDP_TUNNEL_HEADER;

struct _RDP_TUNNEL_CREATEREQUEST
{
	UINT32 requestID;
	UINT32 reserved;
	BYTE securityCookie[16];
};
typedef struct _RDP_TUNNEL_CREATEREQUEST RDP_TUNNEL_CREATEREQUEST;

struct _RDP_TUNNEL_CREATERESPONSE
{
	UINT32 hrResponse;
};
typedef struct _RDP_TUNNEL_CREATERESPONSE RDP_TUNNEL_CREATERESPONSE;

struct _RDP_TUNNEL_DATA
{
	BYTE* higherLayerDataPointer;
	UINT16 higherLayerDataLength;
};
typedef struct _RDP_TUNNEL_DATA RDP_TUNNEL_DATA;

struct _MULTITRANSPORT_PDU
{
	BYTE action;
	BYTE flags;
	BYTE subHeaderLength;
	BYTE subHeaderType;
	BYTE* subHeaderData;
	union {
		RDP_TUNNEL_CREATEREQUEST tunnelCreateRequest;
		RDP_TUNNEL_CREATERESPONSE tunnelCreateResponse;
		RDP_TUNNEL_DATA tunnelData;
	} u;
};
typedef struct _MULTITRANSPORT_PDU MULTITRANSPORT_PDU;

/**
 * Tunnel definition
 */
struct rdp_tunnel
{
	rdpUdp* udp;
	UINT32 requestId;
	UINT16 protocol;
	BYTE securityCookie[16];
};
typedef struct rdp_tunnel rdpTunnel;

struct rdp_multitransport
{
	rdpRdp* rdp;
	rdpTunnel* udpRTunnel; /* reliable tunnel */
	rdpTunnel* udpLTunnel; /* lossy tunnel */
};

int rdp_recv_multitransport_packet(rdpRdp* rdp, wStream* s);

rdpMultitransport* multitransport_new(rdpRdp* rdp);
void multitransport_free(rdpMultitransport* multitransport);

#endif /* __MULTITRANSPORT_H */
