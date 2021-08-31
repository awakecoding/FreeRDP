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

#ifndef FREERDP_PACKET_H
#define FREERDP_PACKET_H

#include <freerdp/api.h>
#include <freerdp/freerdp.h>
#include <freerdp/utils/pcap.h>

struct rdp_eth_header
{
	BYTE Destination[6];
	BYTE Source[6];
	UINT16 Type;
};
typedef struct rdp_eth_header rdpEthHeader;

struct rdp_ipv4_header
{
	BYTE Version;
	BYTE InternetHeaderLength;
	BYTE TypeOfService;
	UINT16 TotalLength;
	UINT16 Identification;
	BYTE InternetProtocolFlags;
	UINT16 FragmentOffset;
	BYTE TimeToLive;
	BYTE Protocol;
	UINT16 HeaderChecksum;
	UINT32 SourceAddress;
	UINT32 DestinationAddress;
};
typedef struct rdp_ipv4_header rdpIPv4Header;

struct rdp_tcp_header
{
	UINT16 SourcePort;
	UINT16 DestinationPort;
	UINT32 SequenceNumber;
	UINT32 AcknowledgementNumber;
	BYTE Offset;
	BYTE Reserved;
	BYTE TcpFlags;
	UINT16 Window;
	UINT16 Checksum;
	UINT16 UrgentPointer;
};
typedef struct rdp_tcp_header rdpTcpHeader;

#ifdef	__cplusplus
extern "C" {
#endif



#ifdef	__cplusplus
}
#endif

#endif /* FREERDP_PACKET_H */