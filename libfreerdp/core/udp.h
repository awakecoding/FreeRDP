/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * RDP-UDP Implementation
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

#ifndef __RDPUDP_H
#define __RDPUDP_H

typedef struct rdp_udp rdpUdp;

#include "rdp.h"

#include <freerdp/log.h>
#include <freerdp/freerdp.h>

#include <winpr/stream.h>
#include <winpr/winsock.h>

#include "udpl.h"
#include "udpr.h"

#define RDPUDP_PROTOCOL_UDPFECR			0x01
#define RDPUDP_PROTOCOL_UDPFECL			0x02

#define RDPUDP_MTU_SIZE				1232
#define RDPUDP_QUEUE_SIZE			1024
#define RDPUDP_ACKVECTOR_SIZE			1024
#define RDPUDP_RETRANSMIT_COUNT			3
#define RDPUDP_RETRANSMIT_INTERVAL		1000

#define RDPUDP_STATE_DISCONNECTED		0
#define RDPUDP_STATE_CONNECTING			1
#define RDPUDP_STATE_CONNECTED			2
#define RDPUDP_STATE_SECURING			3
#define RDPUDP_STATE_SECURED			4

#define DATAGRAM_RECEIVED			0
#define DATAGRAM_RESERVED_1			1
#define DATAGRAM_RESERVED_2			2
#define DATAGRAM_NOT_YET_RECEIVED		3

#define RDPUDP_FLAG_SYN				0x0001
#define RDPUDP_FLAG_FIN				0x0002
#define RDPUDP_FLAG_ACK				0x0004
#define RDPUDP_FLAG_DATA			0x0008
#define RDPUDP_FLAG_FEC				0x0010
#define RDPUDP_FLAG_CN				0x0020
#define RDPUDP_FLAG_CWR				0x0040
#define RDPUDP_FLAG_SACK_OPTION			0x0080
#define RDPUDP_FLAG_ACK_OF_ACKS			0x0100
#define RDPUDP_FLAG_SYNLOSSY			0x0200
#define RDPUDP_FLAG_ACKDELAYED			0x0400
#define RDPUDP_FLAG_CORRELATION_ID		0x0800

#define E_ABORT					0x80004004

struct _RDPUDP_FEC_HEADER
{
	UINT32 snSourceAck;
	UINT16 uReceiveWindowSize;
	UINT16 uFlags;
};
typedef struct _RDPUDP_FEC_HEADER RDPUDP_FEC_HEADER;

struct _RDPUDP_FEC_PAYLOAD_HEADER
{
	UINT32 snCoded;
	UINT32 snSourceStart;
	BYTE uSourceRange;
	BYTE uFecIndex;
	UINT16 uPadding;
};
typedef struct _RDPUDP_FEC_PAYLOAD_HEADER RDPUDP_FEC_PAYLOAD_HEADER;

struct _RDPUDP_PAYLOAD_PREFIX
{
	UINT16 cbPayloadSize;
};
typedef struct _RDPUDP_PAYLOAD_PREFIX RDPUDP_PAYLOAD_PREFIX;

struct _RDPUDP_SOURCE_PAYLOAD_HEADER
{
	UINT32 snCoded;
	UINT32 snSourceStart;
};
typedef struct _RDPUDP_SOURCE_PAYLOAD_HEADER RDPUDP_SOURCE_PAYLOAD_HEADER;

struct _RDPUDP_SYNDATA_PAYLOAD
{
	UINT32 snInitialSequenceNumber;
	UINT16 uUpStreamMtu;
	UINT16 uDownStreamMtu;
};
typedef struct _RDPUDP_SYNDATA_PAYLOAD RDPUDP_SYNDATA_PAYLOAD;

struct _RDPUDP_ACK_OF_ACKVECTOR_HEADER
{
	UINT32 snAckOfAcksSeqNum;
};
typedef struct _RDPUDP_ACK_OF_ACKVECTOR_HEADER RDPUDP_ACK_OF_ACKVECTOR_HEADER;

struct _RDPUDP_ACK_VECTOR_HEADER
{
	UINT16 uAckVectorSize;
	UINT8 AckVectorElement[RDPUDP_ACKVECTOR_SIZE];
};
typedef struct _RDPUDP_ACK_VECTOR_HEADER RDPUDP_ACK_VECTOR_HEADER;

struct _RDPUDP_CORRELATION_ID_PAYLOAD
{
	BYTE uCorrelationId[16];
	BYTE uReserved[16];
};
typedef struct _RDPUDP_CORRELATION_ID_PAYLOAD RDPUDP_CORRELATION_ID_PAYLOAD;

struct _RDPUDP_PDU
{
	wStream* s;

	RDPUDP_FEC_HEADER fecHeader;
	RDPUDP_SYNDATA_PAYLOAD syndataPayload;
	RDPUDP_ACK_VECTOR_HEADER ackVectorHeader;
	RDPUDP_FEC_PAYLOAD_HEADER fecPayloadHeader;
	RDPUDP_SOURCE_PAYLOAD_HEADER sourcePayloadHeader;
	RDPUDP_CORRELATION_ID_PAYLOAD correlationIdPayload;
	RDPUDP_ACK_OF_ACKVECTOR_HEADER ackOfAckVectorHeader;

	BYTE* payloadData;
	int payloadSize;
};
typedef struct _RDPUDP_PDU RDPUDP_PDU;

struct rdp_udp
{
	rdpRdp* rdp;

	UINT16 protocol;

	int sockfd;
	rdpUdpDtls* dtls;
	rdpUdpTls* tls;
	HANDLE hThread;
	DWORD dwThreadId;

	int state;

	void* callbackData;
	void (*onDisconnected)(rdpUdp* udp);
	void (*onConnecting)(rdpUdp* udp);
	void (*onConnected)(rdpUdp* udp);
	void (*onSecuring)(rdpUdp* udp);
	void (*onSecured)(rdpUdp* udp);
	void (*onDataReceived)(rdpUdp* udp, BYTE* data, int size);

	DWORD retransmitTimer;
	int retransmitCount;

	wStream** recvQueue;
	int recvQueueCapacity;
	int recvQueueSize;
	int recvQueueHead;
	int recvQueueTail;

	wStream** sendQueue;
	int sendQueueCapacity;
	int sendQueueSize;
	int sendQueueHead;
	int sendQueueTail;

	UINT32 clientSequenceNumber;
	UINT16 clientReceiveWindowSize;
	UINT32 serverSequenceNumber;
	UINT16 serverReceiveWindowSize;
};

BOOL rdp_udp_init(rdpUdp* udp, UINT16 protocol);

int rdp_udp_read(rdpUdp* udp, BYTE* data, int size);
int rdp_udp_write(rdpUdp* udp, BYTE* data, int size);

rdpUdp* rdp_udp_new(rdpRdp* rdp);
void rdp_udp_free(rdpUdp* rdpUdp);

#endif /* __RDPUDP_H */
