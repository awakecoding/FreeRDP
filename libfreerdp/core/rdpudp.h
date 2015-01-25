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

#include "rdp.h"

#include <freerdp/log.h>
#include <freerdp/freerdp.h>

#include <winpr/stream.h>

#ifndef _WIN32
#include <netdb.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>

#define closesocket(_fd)	close(_fd)
#else
#define SHUT_RDWR SD_BOTH
#endif

#include "rdpudp_dtls.h"
#include "rdpudp_tls.h"

#define RDPUDP_PROTOCOL_UDPFECR		0x01
#define RDPUDP_PROTOCOL_UDPFECL		0x02

typedef struct rdpudp rdpUdp;

struct rdpudp
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
	void (*onDisconnected)(rdpUdp* rdpudp);
	void (*onConnecting)(rdpUdp* rdpudp);
	void (*onConnected)(rdpUdp* rdpudp);
	void (*onSecuring)(rdpUdp* rdpudp);
	void (*onSecured)(rdpUdp* rdpudp);
	void (*onDataReceived)(rdpUdp* rdpudp, BYTE* data, int size);

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

BOOL rdpudp_init(rdpUdp* rdpudp, UINT16 protocol);

int rdpudp_read(rdpUdp* rdpudp, BYTE* data, int size);
int rdpudp_write(rdpUdp* rdpudp, BYTE* data, int size);

rdpUdp* rdpudp_new(rdpRdp* rdp);
void rdpudp_free(rdpUdp* rdpUdp);

#endif /* __RDPUDP_H */
