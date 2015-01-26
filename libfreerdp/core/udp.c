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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>

#include "tunnel.h"

#define TAG FREERDP_TAG("core.udp")

static BOOL rdp_udp_send_packet(rdpUdp* udp, wStream* s)
{
	int status;
	int pduLen;
	BYTE* pduPtr;

	if (!s)
		return FALSE;

	Stream_SealLength(s);

	pduPtr = Stream_Buffer(s);
	pduLen = Stream_Length(s);

	status = send(udp->sockfd, pduPtr, pduLen, 0);

	return (status == pduLen) ? TRUE : FALSE;
}

/**
 * Protocol encoders/decoders
 */
static int rdp_udp_ack_vector_header_padding(UINT16 uAckVectorSize)
{
	static int padding[] = { 2, 1, 0, 3 };

	return padding[uAckVectorSize & 0x3];
}

static void rdp_udp_trace_fec_header(RDPUDP_FEC_HEADER* fecHeader)
{
	WLog_DBG(TAG, "RDPUDP_FEC_HEADER: snSourceAck: 0x%04X uReceiveWindowSize: %d uFlags: 0x%04X",
			fecHeader->snSourceAck, fecHeader->uReceiveWindowSize, fecHeader->uFlags);
}

static BOOL rdp_udp_read_fec_header(wStream* s, RDPUDP_FEC_HEADER* fecHeader)
{
	if (Stream_GetRemainingLength(s) < 8)
		return FALSE;

	Stream_Read_UINT32_BE(s, fecHeader->snSourceAck); /* snSourceAck (4 bytes) */
	Stream_Read_UINT16_BE(s, fecHeader->uReceiveWindowSize); /* uReceiveWindowSize (2 bytes) */
	Stream_Read_UINT16_BE(s, fecHeader->uFlags); /* uFlags (2 bytes) */

	rdp_udp_trace_fec_header(fecHeader);

	return TRUE;
}

static void rdp_udp_write_fec_header(wStream* s, RDPUDP_FEC_HEADER* fecHeader)
{
	Stream_Write_UINT32_BE(s, fecHeader->snSourceAck); /* snSourceAck (4 bytes) */
	Stream_Write_UINT16_BE(s, fecHeader->uReceiveWindowSize); /* uReceiveWindowSize (2 bytes) */
	Stream_Write_UINT16_BE(s, fecHeader->uFlags); /* uFlags (2 bytes) */

	rdp_udp_trace_fec_header(fecHeader);
}

static void rdp_udp_trace_fec_payload_header(RDPUDP_FEC_PAYLOAD_HEADER* fecPayloadHeader)
{
	WLog_DBG(TAG, "RDPUDP_FEC_PAYLOAD_HEADER: snCoded: 0x%04X snSourceStart: 0x%04X "
			"uSourceRange: %d uFecIndex: %d\n",
			fecPayloadHeader->snCoded, fecPayloadHeader->snSourceStart,
			fecPayloadHeader->uSourceRange, fecPayloadHeader->uFecIndex);
}

static BOOL rdp_udp_read_fec_payload_header(wStream* s, RDPUDP_FEC_PAYLOAD_HEADER* fecPayloadHeader)
{
	if (Stream_GetRemainingLength(s) < 12)
		return FALSE;

	Stream_Read_UINT32_BE(s, fecPayloadHeader->snCoded); /* snCoded (4 bytes) */
	Stream_Read_UINT32_BE(s, fecPayloadHeader->snSourceStart); /* snSourceStart (4 bytes) */
	Stream_Read_UINT8(s, fecPayloadHeader->uSourceRange); /* uSourceRange (1 byte) */
	Stream_Read_UINT8(s, fecPayloadHeader->uFecIndex); /* uFecIndex (1 byte) */
	Stream_Read_UINT16_BE(s, fecPayloadHeader->uPadding); /* uPadding (2 bytes) */

	rdp_udp_trace_fec_payload_header(fecPayloadHeader);

	return TRUE;
}

void rdp_udp_write_fec_payload_header(wStream* s, RDPUDP_FEC_PAYLOAD_HEADER* fecPayloadHeader)
{
	Stream_Write_UINT32_BE(s, fecPayloadHeader->snCoded); /* snCoded (4 bytes) */
	Stream_Write_UINT32_BE(s, fecPayloadHeader->snSourceStart); /* snSourceStart (4 bytes) */
	Stream_Write_UINT8(s, fecPayloadHeader->uSourceRange); /* uSourceRange (1 byte) */
	Stream_Write_UINT8(s, fecPayloadHeader->uFecIndex); /* uFecIndex (1 byte) */
	Stream_Write_UINT16_BE(s, fecPayloadHeader->uPadding); /* uPadding (2 bytes) */

	rdp_udp_trace_fec_payload_header(fecPayloadHeader);
}

static void rdp_udp_trace_source_payload_header(RDPUDP_SOURCE_PAYLOAD_HEADER* sourcePayloadHeader)
{
	WLog_DBG(TAG, "RDPUDP_SOURCE_PAYLOAD_HEADER: snCodec: 0x%04X snSourceStart: 0x%04X",
			sourcePayloadHeader->snCoded, sourcePayloadHeader->snSourceStart);
}

static BOOL rdp_udp_read_source_payload_header(wStream* s, RDPUDP_SOURCE_PAYLOAD_HEADER* sourcePayloadHeader)
{
	if (Stream_GetRemainingLength(s) < 8)
		return FALSE;

	Stream_Read_UINT32_BE(s, sourcePayloadHeader->snCoded); /* snCoded (4 bytes) */
	Stream_Read_UINT32_BE(s, sourcePayloadHeader->snSourceStart); /* snSourceStart (4 bytes) */

	rdp_udp_trace_source_payload_header(sourcePayloadHeader);

	return TRUE;
}

static void rdp_udp_write_source_payload_header(wStream* s, RDPUDP_SOURCE_PAYLOAD_HEADER* sourcePayloadHeader)
{
	Stream_Write_UINT32_BE(s, sourcePayloadHeader->snCoded); /* snCoded (4 bytes) */
	Stream_Write_UINT32_BE(s, sourcePayloadHeader->snSourceStart); /* snSourceStart (4 bytes) */

	rdp_udp_trace_source_payload_header(sourcePayloadHeader);
}

static void rdp_udp_trace_syndata_payload(RDPUDP_SYNDATA_PAYLOAD* syndataPayload)
{
	WLog_DBG(TAG, "RDPUDP_SYNDATA_PAYLOAD: snInitialSequenceNumber: 0x%04X "
			"uUpStreamMtu: %d uDownStreamMtu: %d",
			syndataPayload->snInitialSequenceNumber,
			syndataPayload->uUpStreamMtu, syndataPayload->uDownStreamMtu);
}

static BOOL rdp_udp_read_syndata_payload(wStream* s, RDPUDP_SYNDATA_PAYLOAD* syndataPayload)
{
	if (Stream_GetRemainingLength(s) < 8)
		return FALSE;

	Stream_Read_UINT32_BE(s, syndataPayload->snInitialSequenceNumber); /* snInitialSequenceNumber (4 bytes) */
	Stream_Read_UINT16_BE(s, syndataPayload->uUpStreamMtu); /* uUpStreamMtu (2 bytes) */
	Stream_Read_UINT16_BE(s, syndataPayload->uDownStreamMtu); /* uDownStreamMtu (2 bytes) */

	rdp_udp_trace_syndata_payload(syndataPayload);

	return TRUE;
}

static void rdp_udp_write_syndata_payload(wStream* s, RDPUDP_SYNDATA_PAYLOAD* syndataPayload)
{
	Stream_Write_UINT32_BE(s, syndataPayload->snInitialSequenceNumber); /* snInitialSequenceNumber (4 bytes) */
	Stream_Write_UINT16_BE(s, syndataPayload->uUpStreamMtu); /* uUpStreamMtu (2 bytes) */
	Stream_Write_UINT16_BE(s, syndataPayload->uDownStreamMtu); /* uDownStreamMtu (2 bytes) */

	rdp_udp_trace_syndata_payload(syndataPayload);
}

static void rdp_udp_trace_ack_of_ackvector_header(RDPUDP_ACK_OF_ACKVECTOR_HEADER* ackOfAckVectorHeader)
{
	WLog_DBG(TAG, "RDPUDP_ACK_OF_ACKVECTOR_HEADER: snAckOfAcksSeqNum: 0x%04X",
			ackOfAckVectorHeader->snAckOfAcksSeqNum);
}

static BOOL rdp_udp_read_ack_of_ackvector_header(wStream* s, RDPUDP_ACK_OF_ACKVECTOR_HEADER* ackOfAckVectorHeader)
{
	if (Stream_GetRemainingLength(s) < 4)
		return FALSE;

	Stream_Read_UINT32_BE(s, ackOfAckVectorHeader->snAckOfAcksSeqNum); /* snAckOfAcksSeqNum (4 bytes) */

	rdp_udp_trace_ack_of_ackvector_header(ackOfAckVectorHeader);

	return TRUE;
}

void rdp_udp_write_ack_of_ackvector_header(wStream *s, RDPUDP_ACK_OF_ACKVECTOR_HEADER* ackOfAckVectorHeader)
{
	Stream_Write_UINT32_BE(s, ackOfAckVectorHeader->snAckOfAcksSeqNum); /* snAckOfAcksSeqNum (4 bytes) */

	rdp_udp_trace_ack_of_ackvector_header(ackOfAckVectorHeader);
}

static void rdp_udp_trace_ack_vector_header(RDPUDP_ACK_VECTOR_HEADER* ackVectorHeader)
{
	WLog_DBG(TAG, "RDPUDP_ACK_VECTOR_HEADER: uAckVectorSize: %d",
			ackVectorHeader->uAckVectorSize);
}

static BOOL rdp_udp_read_ack_vector_header(wStream* s, RDPUDP_ACK_VECTOR_HEADER* ackVectorHeader)
{
	int padding;

	if (Stream_GetRemainingLength(s) < 2)
		return FALSE;

	Stream_Read_UINT16_BE(s, ackVectorHeader->uAckVectorSize); /* uAckVectorSize (2 bytes) */

	if (Stream_GetRemainingLength(s) < ackVectorHeader->uAckVectorSize)
		return FALSE;

	Stream_Read(s, ackVectorHeader->AckVectorElement, ackVectorHeader->uAckVectorSize);

	/* Skip over padding to make the structure fall on a DWORD boundary. */
	padding = rdp_udp_ack_vector_header_padding(ackVectorHeader->uAckVectorSize);

	if (padding > 0)
	{
		if (Stream_GetRemainingLength(s) < padding)
			return FALSE;

		Stream_Seek(s, padding);
	}

	rdp_udp_trace_ack_vector_header(ackVectorHeader);

	return TRUE;
}

static void rdp_udp_write_ack_vector_header(wStream* s, RDPUDP_ACK_VECTOR_HEADER* ackVectorHeader)
{
	int padding;

	Stream_Write_UINT16_BE(s, ackVectorHeader->uAckVectorSize); /* uAckVectorSize (2 bytes) */

	Stream_Write(s, ackVectorHeader->AckVectorElement, ackVectorHeader->uAckVectorSize);

	/* Pad the structure on a DWORD boundary. */
	padding = rdp_udp_ack_vector_header_padding(ackVectorHeader->uAckVectorSize);

	if (padding > 0)
		Stream_Zero(s, padding);

	rdp_udp_trace_ack_vector_header(ackVectorHeader);
}

static void rdp_udp_trace_correlation_id_payload(RDPUDP_CORRELATION_ID_PAYLOAD* correlationIdPayload)
{
	BYTE* p = correlationIdPayload->uCorrelationId;

	WLog_DBG(TAG, "RDPUDP_CORRELATION_ID_PAYLOAD: uCorrelationId: ",
			"%02X %02X %02X %02X %02X %02X %02X %02X"
			"%02X %02X %02X %02X %02X %02X %02X %02X",
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
			p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
}

BOOL rdp_udp_read_correlation_id_payload(wStream* s, RDPUDP_CORRELATION_ID_PAYLOAD* correlationIdPayload)
{
	if (Stream_GetRemainingLength(s) < 32)
		return FALSE;

	Stream_Read(s, correlationIdPayload->uCorrelationId, 16); /* uCorrelationId (16 bytes) */
	Stream_Read(s, correlationIdPayload->uReserved, 16); /* uReserved (16 bytes) */

	rdp_udp_trace_correlation_id_payload(correlationIdPayload);

	return TRUE;
}

static void rdp_udp_write_correlation_id_payload(wStream* s, RDPUDP_CORRELATION_ID_PAYLOAD* correlationIdPayload)
{
	ZeroMemory(correlationIdPayload->uReserved, 16);

	Stream_Write(s, correlationIdPayload->uCorrelationId, 16); /* uCorrelationId (16 bytes) */
	Stream_Write(s, correlationIdPayload->uReserved, 16); /* uReserved (16 bytes) */

	rdp_udp_trace_correlation_id_payload(correlationIdPayload);
}

static BOOL rdp_udp_decode_pdu(wStream *s, RDPUDP_PDU* pdu)
{
	ZeroMemory(pdu, sizeof(RDPUDP_PDU));

	/* Parse the RDPUDP_FEC_HEADER. */
	if (!rdp_udp_read_fec_header(s, &pdu->fecHeader))
	{
		WLog_ERR(TAG, "error parsing RDPUDP_FEC_HEADER");
		return FALSE;
	}

	/* If the SYN flag is set... */
	if (pdu->fecHeader.uFlags & RDPUDP_FLAG_SYN)
	{
		/* Parse the RDPUDP_SYNDATA_PAYLOAD. */
		if (!rdp_udp_read_syndata_payload(s, &pdu->syndataPayload))
		{
			WLog_ERR(TAG, "error parsing RDPUDP_SYNDATA_PAYLOAD");
			return FALSE;
		}
	}

	/* If the ACK flag is set... */
	if (pdu->fecHeader.uFlags & RDPUDP_FLAG_ACK)
	{
		/* Parse the RDPUDP_ACK_VECTOR_HEADER. */
		if (!rdp_udp_read_ack_vector_header(s, &pdu->ackVectorHeader))
		{
			WLog_ERR(TAG, "error parsing RDPUDP_ACK_VECTOR_HEADER");
			return FALSE;
		}
	}

	/* If the ACK_OF_ACKS flag is set... */
	if (pdu->fecHeader.uFlags & RDPUDP_FLAG_ACK_OF_ACKS)
	{
		/* Parse the RDPUDP_ACK_OF_ACKVECTOR_HEADER. */
		if (!rdp_udp_read_ack_of_ackvector_header(s, &pdu->ackOfAckVectorHeader))
		{
			WLog_ERR(TAG, "error parsing RDPUDP_ACK_OF_ACKVECTOR_HEADER");
			return FALSE;
		}
	}

	/* If the DATA flag is set... */
	if (pdu->fecHeader.uFlags & RDPUDP_FLAG_DATA)
	{
		/* If the FEC flag is set... */
		if (pdu->fecHeader.uFlags & RDPUDP_FLAG_FEC)
		{
			/* Parse the RDPUDP_FEC_PAYLOAD_HEADER. */
			if (!rdp_udp_read_fec_payload_header(s, &pdu->fecPayloadHeader))
			{
				WLog_ERR(TAG, "error parsing RDPUDP_FEC_PAYLOAD_HEADER");
				return FALSE;
			}
		}
		else
		{
			/* Parse the RDPUDP_SOURCE_PAYLOAD_HEADER. */
			if (!rdp_udp_read_source_payload_header(s, &pdu->sourcePayloadHeader))
			{
				WLog_ERR(TAG, "error parsing RDPUDP_SOURCE_PAYLOAD_HEADER");
				return FALSE;
			}
		}

		/* The remainder should be the payload. */
		pdu->payloadData = Stream_Pointer(s);
		pdu->payloadSize = Stream_GetRemainingLength(s);
	}

	pdu->s = s;

	return TRUE;
}

wStream* rdp_udp_encode_pdu(RDPUDP_PDU* pdu)
{
	wStream* s;

	s = Stream_New(NULL, RDPUDP_MTU_SIZE);

	if (!s)
		return NULL;

	rdp_udp_write_fec_header(s, &pdu->fecHeader);

	if (pdu->fecHeader.uFlags & RDPUDP_FLAG_SYN)
	{
		rdp_udp_write_syndata_payload(s, &pdu->syndataPayload);
	}

	if (pdu->fecHeader.uFlags & RDPUDP_FLAG_CORRELATION_ID)
	{
		rdp_udp_write_correlation_id_payload(s, &pdu->correlationIdPayload);
	}

	if (pdu->fecHeader.uFlags & RDPUDP_FLAG_ACK)
	{
		rdp_udp_write_ack_vector_header(s, &pdu->ackVectorHeader);
	}

	if (pdu->fecHeader.uFlags & RDPUDP_FLAG_DATA)
	{
		rdp_udp_write_source_payload_header(s, &pdu->sourcePayloadHeader);

		if (pdu->payloadData)
		{		
			Stream_Write(s, pdu->payloadData, pdu->payloadSize);
		}
	}

	if (pdu->fecHeader.uFlags & RDPUDP_FLAG_SYN)
	{
		/* Pad the remainder of the PDU. */
		Stream_Zero(s, Stream_GetRemainingLength(s));
	}

	return s;
}

/*
 * Queue Functions
 */

static void rdp_udp_clear_recv_queue(rdpUdp* udp)
{

}

static void rdp_udp_clear_send_queue(rdpUdp* udp)
{
	wStream* pdu;
	int index = udp->sendQueueHead;
	int count = udp->sendQueueSize;

	if (count > 0)
	{
		while (count > 0)
		{
			pdu = udp->sendQueue[index];
			udp->sendQueue[index] = NULL;
			Stream_Free(pdu, TRUE);	
			index = (index + 1) % udp->sendQueueCapacity;
			count--;
		}
		udp->sendQueueHead = index;
		udp->sendQueueSize = 0;
	}
}

static BOOL rdp_udp_append_send_queue(rdpUdp* udp, wStream* s)
{
	if (udp->sendQueueSize >= udp->sendQueueCapacity)
	{
		fprintf(stderr, "send queue overflow\n");
		return FALSE;
	}

	udp->sendQueue[udp->sendQueueTail] = s;
	udp->sendQueueTail = (udp->sendQueueTail + 1) % udp->sendQueueCapacity;
	udp->sendQueueSize++;

	return TRUE;
}

/**
 * Timer Functions
 */
static void rdp_udp_stop_retransmit_timer(rdpUdp* udp)
{
	udp->retransmitTimer = 0;
	udp->retransmitCount = 0;
}

static void rdp_udp_reset_retransmit_timer(rdpUdp* udp)
{
	udp->retransmitTimer = GetTickCount() + RDPUDP_RETRANSMIT_INTERVAL;
}

static void rdp_udp_start_retransmit_timer(rdpUdp* udp)
{
	rdp_udp_reset_retransmit_timer(udp);
	udp->retransmitCount = 0;
}

static void rdp_udp_retransmit(rdpUdp* udp)
{
	wStream* s;
	int index = udp->sendQueueHead;
	int count = udp->sendQueueSize;

	while (count > 0)
	{
		s = udp->sendQueue[index];
		rdp_udp_send_packet(udp, s);
		index = (index + 1) % udp->sendQueueCapacity;
		count--;
	}
}

/**
 * PDU Processing Functions
 */
static BOOL rdp_udp_send_pdu(rdpUdp* udp, RDPUDP_PDU* pdu)
{
	wStream* s;

	s = rdp_udp_encode_pdu(pdu);

	if (!s)
		return FALSE;

	if (!rdp_udp_send_packet(udp, s))
	{
		WLog_ERR(TAG, "error sending PDU\n");
		Stream_Free(s, TRUE);
		return FALSE;
	}

	rdp_udp_append_send_queue(udp, s);
	rdp_udp_start_retransmit_timer(udp);

	return TRUE;
}

static BOOL rdp_udp_send_data(
	rdpUdp* udp, UINT16 flags,
	BYTE* ackVectorElement, UINT16 ackVectorSize,
	BYTE* payloadData, int payloadSize)
{
	RDPUDP_PDU pdu;

	if (flags == 0)
		return FALSE;

	ZeroMemory(&pdu, sizeof(pdu));

	pdu.fecHeader.snSourceAck = udp->serverSequenceNumber;
	pdu.fecHeader.uReceiveWindowSize = udp->clientReceiveWindowSize;
	pdu.fecHeader.uFlags = flags;

	if (flags & RDPUDP_FLAG_SYN)
	{
		pdu.syndataPayload.snInitialSequenceNumber = udp->clientSequenceNumber;
		pdu.syndataPayload.uUpStreamMtu = RDPUDP_MTU_SIZE;
		pdu.syndataPayload.uDownStreamMtu = RDPUDP_MTU_SIZE;
	}

	if (flags & RDPUDP_FLAG_ACK)
	{
		if (ackVectorElement && (ackVectorSize > 0))
		{
			pdu.ackVectorHeader.uAckVectorSize = ackVectorSize;
			CopyMemory(pdu.ackVectorHeader.AckVectorElement, ackVectorElement, ackVectorSize);
		}
	}

	if (flags & RDPUDP_FLAG_DATA)
	{
		udp->clientSequenceNumber++;

		pdu.sourcePayloadHeader.snCoded = udp->clientSequenceNumber;
		pdu.sourcePayloadHeader.snSourceStart = udp->clientSequenceNumber;

		if (payloadData)
		{
			pdu.payloadData = payloadData;
			pdu.payloadSize = payloadSize;
		}
	}

	return rdp_udp_send_pdu(udp, &pdu);
}

static BOOL rdp_udp_process_acks(rdpUdp* udp, RDPUDP_PDU* pdu)
{
	wStream* s;
	int index = udp->sendQueueHead;
	int count = udp->sendQueueSize;

	if ((pdu->fecHeader.uFlags & RDPUDP_FLAG_ACK) == 0)
	{
		fprintf(stderr, "no ACKS to process\n");
		return FALSE;
	}

	if (count > 0)
	{
		while (count > 0)
		{
			s = udp->sendQueue[index];
			udp->sendQueue[index] = NULL;
			Stream_Free(s, TRUE);	
			index = (index + 1) % udp->sendQueueCapacity;
			count--;
		}

		udp->sendQueueHead = index;
		udp->sendQueueSize = 0;

		if (udp->sendQueueSize == 0)
		{
			rdp_udp_stop_retransmit_timer(udp);
		}
	}

	return TRUE;
}

static void rdp_udp_process_data(rdpUdp* udp, RDPUDP_PDU* inputPdu)
{
	int status;
	UINT16 flags;
	UINT16 ackVectorSize;
	BYTE ackVectorElement[1];
	BYTE decryptedData[2048];

	/* If the connection is secured with TLS... */
	if (udp->tls)
	{
		/* Decrypt the payload. */
		status = rdp_udp_tls_write(udp->tls, inputPdu->payloadData, inputPdu->payloadSize);

		if (status < 0)
		{
			WLog_ERR(TAG, "error decrypting data");
			return;
		}

		status = rdp_udp_tls_decrypt(udp->tls, decryptedData, sizeof(decryptedData));

		if (status < 0)
		{
			WLog_ERR(TAG, "error decrypting data");
			return;
		}

		/* Deliver the data. */
		IFCALL(udp->onDataReceived, udp, decryptedData, status);

		/* Send an ACK. */
		flags = RDPUDP_FLAG_ACK;

		/* Update the server sequence number. */
		udp->serverSequenceNumber = inputPdu->sourcePayloadHeader.snSourceStart;
			
		/* Construct the ACK vector. */
		ackVectorSize = 1;
		ackVectorElement[0] = (DATAGRAM_RECEIVED << 6) | 0x01;

		rdp_udp_send_data(udp, flags, ackVectorElement, ackVectorSize, NULL, 0);
	}
}

static void rdp_udp_change_state(rdpUdp* udp, int state)
{
	udp->state = state;

	switch (state)
	{
		case RDPUDP_STATE_DISCONNECTED:
			IFCALL(udp->onDisconnected, udp);
			break;

		case RDPUDP_STATE_CONNECTING:
			IFCALL(udp->onConnecting, udp);
			break;

		case RDPUDP_STATE_CONNECTED:
			IFCALL(udp->onConnected, udp);
			break;

		case RDPUDP_STATE_SECURING:
			IFCALL(udp->onSecuring, udp);
			break;

		case RDPUDP_STATE_SECURED:
			IFCALL(udp->onSecured, udp);
			break;

		default:
			break;
	}
}

static void rdp_udp_secure_connection(rdpUdp* udp, RDPUDP_PDU* inputPdu)
{
	int status;
	UINT16 flags;
	BYTE buffer[2048];
	BYTE ackVectorElement[1];
	UINT16 ackVectorSize = 0;

	if (udp->tls)
	{
		/* If the DATA flag is set... */
		if (inputPdu->fecHeader.uFlags & RDPUDP_FLAG_DATA)
		{
			/* Update the server sequence number. */
			udp->serverSequenceNumber = inputPdu->sourcePayloadHeader.snSourceStart;
			
			/* Construct the ACK vector. */
			ackVectorSize = 1;
			ackVectorElement[0] = (DATAGRAM_RECEIVED << 6) | 0x01;

			/* Process handshake bytes sent by the peer. */
			status = rdp_udp_tls_write(udp->tls, inputPdu->payloadData, inputPdu->payloadSize);
		}

		/* When connect returns TRUE, the connection is secured. */
		if (rdp_udp_tls_connect(udp->tls))
		{
			rdp_udp_change_state(udp, RDPUDP_STATE_SECURED);
		}

		/* Send handshake bytes to the peer. */
		if (rdp_udp_tls_get_last_error(udp->tls) == SSL_ERROR_WANT_READ)
		{
			status = rdp_udp_tls_read(udp->tls, buffer, sizeof(buffer));

			if (status >= 0)
			{
				flags = RDPUDP_FLAG_ACK;

				if (status > 0)
					flags |= RDPUDP_FLAG_DATA;

				rdp_udp_send_data(udp, flags, ackVectorElement, ackVectorSize, buffer, status);
			}
		}
	}
}

/**
 * State machine
 */
static void rdp_udp_connecting_state(rdpUdp* udp, RDPUDP_PDU* inputPdu)
{
	/* If the SYN + ACK flags are set... */
	if ((inputPdu->fecHeader.uFlags & RDPUDP_FLAG_SYN) &&
		(inputPdu->fecHeader.uFlags & RDPUDP_FLAG_ACK))
	{
		rdp_udp_change_state(udp, RDPUDP_STATE_CONNECTED);

		/* Process ACKs. */
		rdp_udp_process_acks(udp, inputPdu);

		/* Save the server's initial sequence number. */
		udp->serverSequenceNumber = inputPdu->syndataPayload.snInitialSequenceNumber;

		/* Begin securing the connection. */
		rdp_udp_change_state(udp, RDPUDP_STATE_SECURING);

		rdp_udp_secure_connection(udp, inputPdu);
	}
}

static void rdp_udp_securing_state(rdpUdp* udp, RDPUDP_PDU* inputPdu)
{
	/* If the ACK flag is set... */
	if (inputPdu->fecHeader.uFlags & RDPUDP_FLAG_ACK)
	{
		rdp_udp_process_acks(udp, inputPdu);
	}

	/* If the DATA flag is set... */
	if (inputPdu->fecHeader.uFlags & RDPUDP_FLAG_DATA)
	{
		/* Continue securing the connection. */
		rdp_udp_secure_connection(udp, inputPdu);
	}
}

static void rdp_udp_secured_state(rdpUdp* udp, RDPUDP_PDU* inputPdu)
{
	/* If the ACK flag is set... */
	if (inputPdu->fecHeader.uFlags & RDPUDP_FLAG_ACK)
	{
		rdp_udp_process_acks(udp, inputPdu);
	}

	/* If the DATA flag is set... */
	if (inputPdu->fecHeader.uFlags & RDPUDP_FLAG_DATA)
	{
		rdp_udp_process_data(udp, inputPdu);
	}
}

static BOOL rdp_udp_recv_pdu(rdpUdp* udp, wStream* s)
{
	RDPUDP_PDU pdu;

	/* Decode the PDU. */
	if (!rdp_udp_decode_pdu(s, &pdu))
	{
		return FALSE;
	}

	switch (udp->state)
	{
		case RDPUDP_STATE_DISCONNECTED:
			break;

		case RDPUDP_STATE_CONNECTING:
			rdp_udp_connecting_state(udp, &pdu);
			break;

		case RDPUDP_STATE_CONNECTED:
			break;

		case RDPUDP_STATE_SECURING:
			rdp_udp_securing_state(udp, &pdu);
			break;

		case RDPUDP_STATE_SECURED:
			rdp_udp_secured_state(udp, &pdu);
			break;

		default:
			break;
	}

	/**
	 * If we got here, it's because we received something
	 * unexpected.  In this case, just retransmit PDUs.
	 */
	//rdp_udp_retransmit(rdpudp);

	return TRUE;
}

static void rdp_udp_timeout(rdpUdp* udp)
{
	switch (udp->state)
	{
		case RDPUDP_STATE_CONNECTING:
		case RDPUDP_STATE_SECURING:
			if (udp->retransmitCount++ < RDPUDP_RETRANSMIT_COUNT)
			{
				rdp_udp_retransmit(udp);
				rdp_udp_reset_retransmit_timer(udp);
			}
			break;

		default:
			break;
	}
}

/**
 * Main thread
 */
static DWORD rdp_udp_thread(LPVOID lpParameter)
{
	int status;
	wStream* s;
	int sockfd;
	fd_set rfds;
	DWORD timeDiff;
	DWORD tickCount;
	struct timeval* tv;
	struct timeval timeval;
	BYTE pdu[RDPUDP_MTU_SIZE];
	rdpUdp* rdpudp = (rdpUdp*) lpParameter;

	sockfd = rdpudp->sockfd;

	while (TRUE)
	{
		FD_ZERO(&rfds);
		FD_SET(sockfd, &rfds);

		tv = NULL;

		if (rdpudp->retransmitTimer)
		{
			tickCount = GetTickCount();

			if (tickCount < rdpudp->retransmitTimer)
			{
				timeDiff = rdpudp->retransmitTimer - tickCount;
				timeval.tv_sec = timeDiff / 1000;
				timeval.tv_usec = (timeDiff % 1000) * 1000;
				tv = &timeval;
			}
		}

		status = select(sockfd + 1, &rfds, NULL, NULL, tv);

		if (status < 0)
		{
			WLog_ERR(TAG, "select error (errno: %d)", errno);
			break;
		}

		if (status > 0)
		{
			status = recv(sockfd, pdu, sizeof(pdu), 0);

			if (status <= 0)
			{
				WLog_ERR(TAG, "recv error (errno: %d)", errno);
				break;
			}

			s = Stream_New(pdu, status);
			rdp_udp_recv_pdu(rdpudp, s);
			Stream_Free(s, FALSE);
		}
		else
		{
			rdp_udp_timeout(rdpudp);
		}
	}

	return 0;
}

/**
 * Initialization
 */
BOOL rdp_udp_init(rdpUdp* udp, UINT16 protocol)
{
	int status;
	int sockfd;
	char* hostname;
	char servname[32];
	UINT16 flags;
	struct addrinfo hints;
	struct addrinfo* ai = NULL;
	struct addrinfo* res = NULL;

	/*
	 * Only focused right now on UDP-R.
	 */
	if (protocol == RDPUDP_PROTOCOL_UDPFECL)
		return FALSE;

	/* Initialize state. */
	udp->protocol = protocol;

	udp->clientSequenceNumber = 0x35B1D982;
	udp->clientReceiveWindowSize = 64;

	udp->serverSequenceNumber = 0xFFFFFFFF;
	udp->serverReceiveWindowSize = 64;

	udp->recvQueueCapacity = RDPUDP_QUEUE_SIZE;
	udp->recvQueue = (wStream**) calloc(udp->recvQueueCapacity, sizeof(wStream*));

	if (!udp->recvQueue)
		return FALSE;

	udp->sendQueueCapacity = RDPUDP_QUEUE_SIZE;
	udp->sendQueue = (wStream**) calloc(udp->sendQueueCapacity, sizeof(wStream*));

	if (!udp->sendQueue)
		return FALSE;

	/* Initialize TLS/DTLS. */
	if (protocol == RDPUDP_PROTOCOL_UDPFECR)
	{
		udp->tls = rdp_udp_tls_new(udp->rdp->settings);
	}
	else
	{
		udp->dtls = rdp_udp_dtls_new(udp->rdp->settings);
	}

	/* Create the UDP socket. */
	ZeroMemory(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	hostname = udp->rdp->settings->ServerHostname;
	sprintf(servname, "%d", udp->rdp->settings->ServerPort);
	status = getaddrinfo(hostname, servname, &hints, &res);

	if (status != 0)
	{
		WLog_DBG(TAG, "getaddrinfo (errno=%s)", gai_strerror(status));
		return FALSE;
	}

	sockfd = -1;

	for (ai = res; ai; ai = ai->ai_next)
	{
		sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

		if (sockfd < 0)
			continue;

		status = connect(sockfd, ai->ai_addr, ai->ai_addrlen);

		if (status != 0)
			continue;

		break;
	}

	freeaddrinfo(res);

	if (sockfd == -1)
	{
		WLog_DBG(TAG, "unable to connect to %s:%s\n", hostname, servname);
		return FALSE;
	}

	udp->sockfd = sockfd;

	/* Send a SYN datagram to the server. */
	flags = RDPUDP_FLAG_SYN;

	if (protocol == RDPUDP_PROTOCOL_UDPFECL)
		flags |= RDPUDP_FLAG_SYNLOSSY;

	if (!rdp_udp_send_data(udp, flags, NULL, 0, NULL, 0))
	{
		WLog_DBG(TAG, "cannot send SYN");
		return FALSE;
	}

	udp->state = RDPUDP_STATE_CONNECTING;

	/* Start the thread. */
	udp->hThread = CreateThread(NULL, 0, rdp_udp_thread,
			(LPVOID) udp, 0, &udp->dwThreadId);

	return TRUE;
}

/**
 * Read/write functions
 */
int rdp_udp_read(rdpUdp* udp, BYTE* data, int size)
{
	return -1;
}

int rdp_udp_write(rdpUdp* udp, BYTE* data, int size)
{
	int status;
	BYTE encryptedData[1024];

	if (udp->state != RDPUDP_STATE_SECURED)
	{
		WLog_DBG(TAG, "state is not secured");
		return -1;
	}

	/* If the connection is secured with TLS... */
	if (udp->tls)
	{
		/* Encrypt the data. */
		status = rdp_udp_tls_encrypt(udp->tls, data, size);

		if (status != size)
		{
			WLog_DBG(TAG, "error encrypting data (status=%d)", status);
			return -1;
		}

		status = rdp_udp_tls_read(udp->tls, encryptedData, sizeof(encryptedData));

		if (status < 0)
		{
			WLog_DBG(TAG, "error encrypting data (status=%d)", status);
			return -1;
		}

		/* Send the encrypted data. */
		if (!rdp_udp_send_data(udp, RDPUDP_FLAG_ACK | RDPUDP_FLAG_DATA, NULL, 0, encryptedData, status))
		{
			WLog_DBG(TAG, "error sending data");
			return -1;
		}
	}

	return size;
}

/**
 * Constructor/destructor
 */
rdpUdp* rdp_udp_new(rdpRdp* rdp)
{
	rdpUdp* udp;

	udp = (rdpUdp*) calloc(1, sizeof(rdpUdp));

	if (udp)
	{
		udp->rdp = rdp;
	}
	
	return udp;
}

void rdp_udp_free(rdpUdp* udp)
{
	if (!udp)
		return;

	if (udp->sockfd && (udp->sockfd != -1))
	{
		closesocket(udp->sockfd);
		udp->sockfd = -1;
	}

	if (udp->hThread)
	{
		WaitForSingleObject(udp->hThread, 250);
		CloseHandle(udp->hThread);
		udp->hThread = NULL;
	}

	rdp_udp_clear_recv_queue(udp);
	rdp_udp_clear_send_queue(udp);

	free(udp->recvQueue);
	udp->recvQueue = NULL;

	free(udp->sendQueue);
	udp->sendQueue = NULL;

	free(udp);
}
