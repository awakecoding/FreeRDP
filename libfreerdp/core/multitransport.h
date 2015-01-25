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
#include "rdpudp.h"

#include <freerdp/log.h>
#include <freerdp/freerdp.h>

#include <winpr/stream.h>

#define RDPTUNNEL_ACTION_CREATEREQUEST		0x0
#define RDPTUNNEL_ACTION_CREATERESPONSE		0x1
#define RDPTUNNEL_ACTION_DATA			0x2

typedef struct {
	BYTE action;
	BYTE flags;
	UINT16 payloadLength;
	BYTE headerLength;
	BYTE subHeaderLength;
	BYTE subHeaderType;
	BYTE* subHeaderData;
} RDP_TUNNEL_HEADER;

typedef struct {
	UINT32 requestID;
	UINT32 reserved;
	BYTE securityCookie[16];
} RDP_TUNNEL_CREATEREQUEST;

typedef struct {
	UINT32 hrResponse;
} RDP_TUNNEL_CREATERESPONSE;

typedef struct {
	BYTE* higherLayerDataPointer;
	UINT16 higherLayerDataLength;
} RDP_TUNNEL_DATA;

typedef struct {
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
} MULTITRANSPORT_PDU;

/**
 * Tunnel definition
 */
typedef struct {
	rdpUdp* rdpudp;
	UINT32 requestId;
	UINT16 protocol;
	BYTE securityCookie[16];
} multitransportTunnel;

struct rdp_multitransport
{
	rdpRdp* rdp;

	void* udpRTunnel;	/* reliable tunnel */
	void* udpLTunnel;	/* lossy tunnel */
};

int rdp_recv_multitransport_packet(rdpRdp* rdp, wStream* s);

rdpMultitransport* multitransport_new(rdpRdp* rdp);
void multitransport_free(rdpMultitransport* multitransport);

#endif /* __MULTITRANSPORT_H */
