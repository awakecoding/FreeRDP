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

#include "multitransport.h"

#define TAG FREERDP_TAG("core.rdpudp")

/**
 * Utility Functions
 */
static wStream* rdpudp_packet_init()
{
	BYTE* buffer;

	buffer = (BYTE*) malloc(RDPUDP_MTU_SIZE);

	return buffer ? Stream_New(buffer, RDPUDP_MTU_SIZE) : NULL;
}

static void rdpudp_dump_packet(wStream* s)
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

static BOOL rdpudp_send_packet(rdpUdp* rdpudp, wStream* s)
{
	BYTE* pduptr;
	int pdulen;
	int status;

	if (!s)
		return FALSE;

	Stream_SealLength(s);

	pduptr = Stream_Buffer(s);
	pdulen = Stream_Length(s);

	status = send(rdpudp->sockfd, pduptr, pdulen, 0);
	WLog_DBG(TAG, "send pduptr=%p, pdulen=%d, status=%d", pduptr, pdulen, status);

	rdpudp_dump_packet(s);

	return status == pdulen ? TRUE : FALSE;		
}

/**
 * Protocol encoders/decoders
 */
static int rdpudp_ack_vector_header_padding(UINT16 uAckVectorSize)
{
	static int padding[] = { 2, 1, 0, 3 };

	return padding[uAckVectorSize & 0x3];
}

static void rdpudp_dump_fec_header(RDPUDP_FEC_HEADER* fecHeader)
{
	fprintf(stderr, "RDPUDP_FEC_HEADER\n");
	fprintf(stderr, ".snSourceAck=%u\n", fecHeader->snSourceAck);
	fprintf(stderr, ".uReceiveWindowSize=%u\n", fecHeader->uReceiveWindowSize);
	fprintf(stderr, ".uFlags=%u\n", fecHeader->uFlags);
}

static BOOL rdpudp_read_fec_header(wStream* s, RDPUDP_FEC_HEADER* fecHeader)
{
	if (Stream_GetRemainingLength(s) < 8)
		return FALSE;

	Stream_Read_UINT32_BE(s, fecHeader->snSourceAck);
	Stream_Read_UINT16_BE(s, fecHeader->uReceiveWindowSize);
	Stream_Read_UINT16_BE(s, fecHeader->uFlags);

	rdpudp_dump_fec_header(fecHeader);

	return TRUE;
}

static void rdpudp_write_fec_header(wStream* s, RDPUDP_FEC_HEADER* fecHeader)
{
	Stream_Write_UINT32_BE(s, fecHeader->snSourceAck);
	Stream_Write_UINT16_BE(s, fecHeader->uReceiveWindowSize);
	Stream_Write_UINT16_BE(s, fecHeader->uFlags);

	rdpudp_dump_fec_header(fecHeader);
}

static void rdpudp_dump_fec_payload_header(RDPUDP_FEC_PAYLOAD_HEADER* fecPayloadHeader)
{
	fprintf(stderr, "RDPUDP_FEC_PAYLOAD_HEADER\n");
	fprintf(stderr, ".snCoded=%u\n", fecPayloadHeader->snCoded);
	fprintf(stderr, ".snSourceStart=%u\n", fecPayloadHeader->snSourceStart);
	fprintf(stderr, ".uSourceRange=%u\n", fecPayloadHeader->uSourceRange);
	fprintf(stderr, ".uFecIndex=%u\n", fecPayloadHeader->uFecIndex);
	fprintf(stderr, ".uPadding=%u\n", fecPayloadHeader->uPadding);
}

static BOOL rdpudp_read_fec_payload_header(wStream* s, RDPUDP_FEC_PAYLOAD_HEADER* fecPayloadHeader)
{
	if (Stream_GetRemainingLength(s) < 14)
		return FALSE;

	Stream_Read_UINT32_BE(s, fecPayloadHeader->snCoded);
	Stream_Read_UINT32_BE(s, fecPayloadHeader->snSourceStart);
	Stream_Read_UINT16_BE(s, fecPayloadHeader->uSourceRange);
	Stream_Read_UINT16_BE(s, fecPayloadHeader->uFecIndex);
	Stream_Read_UINT16_BE(s, fecPayloadHeader->uPadding);

	rdpudp_dump_fec_payload_header(fecPayloadHeader);

	return TRUE;
}

void rdpudp_write_fec_payload_header(wStream* s, RDPUDP_FEC_PAYLOAD_HEADER* fecPayloadHeader)
{
	Stream_Write_UINT32_BE(s, fecPayloadHeader->snCoded);
	Stream_Write_UINT32_BE(s, fecPayloadHeader->snSourceStart);
	Stream_Write_UINT16_BE(s, fecPayloadHeader->uSourceRange);
	Stream_Write_UINT16_BE(s, fecPayloadHeader->uFecIndex);
	Stream_Write_UINT16_BE(s, fecPayloadHeader->uPadding);

	rdpudp_dump_fec_payload_header(fecPayloadHeader);
}

static void rdpudp_dump_source_payload_header(RDPUDP_SOURCE_PAYLOAD_HEADER* sourcePayloadHeader)
{
	fprintf(stderr, "RDPUDP_SOURCE_PAYLOAD_HEADER\n");
	fprintf(stderr, ".snCoded=%u\n", sourcePayloadHeader->snCoded);
	fprintf(stderr, ".snSourceStart=%u\n", sourcePayloadHeader->snSourceStart);
}

static BOOL rdpudp_read_source_payload_header(wStream* s, RDPUDP_SOURCE_PAYLOAD_HEADER* sourcePayloadHeader)
{
	if (Stream_GetRemainingLength(s) < 8)
		return FALSE;

	Stream_Read_UINT32_BE(s, sourcePayloadHeader->snCoded);
	Stream_Read_UINT32_BE(s, sourcePayloadHeader->snSourceStart);

	rdpudp_dump_source_payload_header(sourcePayloadHeader);

	return TRUE;
}

static void rdpudp_write_source_payload_header(wStream* s, RDPUDP_SOURCE_PAYLOAD_HEADER* sourcePayloadHeader)
{
	Stream_Write_UINT32_BE(s, sourcePayloadHeader->snCoded);
	Stream_Write_UINT32_BE(s, sourcePayloadHeader->snSourceStart);

	rdpudp_dump_source_payload_header(sourcePayloadHeader);
}

static void rdpudp_dump_syndata_payload(RDPUDP_SYNDATA_PAYLOAD* syndataPayload)
{
	fprintf(stderr, "RDPUDP_SYNDATA_PAYLOAD\n");
	fprintf(stderr, ".snInitialSequenceNumber=%u\n", syndataPayload->snInitialSequenceNumber);
	fprintf(stderr, ".uUpStreamMtu=%u\n", syndataPayload->uUpStreamMtu);
	fprintf(stderr, ".uDownStreamMtu=%u\n", syndataPayload->uDownStreamMtu);
}

static BOOL rdpudp_read_syndata_payload(wStream* s, RDPUDP_SYNDATA_PAYLOAD* syndataPayload)
{
	if (Stream_GetRemainingLength(s) < 8)
		return FALSE;

	Stream_Read_UINT32_BE(s, syndataPayload->snInitialSequenceNumber);
	Stream_Read_UINT16_BE(s, syndataPayload->uUpStreamMtu);
	Stream_Read_UINT16_BE(s, syndataPayload->uDownStreamMtu);

	rdpudp_dump_syndata_payload(syndataPayload);

	return TRUE;
}

static void rdpudp_write_syndata_payload(wStream* s, RDPUDP_SYNDATA_PAYLOAD* syndataPayload)
{
	Stream_Write_UINT32_BE(s, syndataPayload->snInitialSequenceNumber);
	Stream_Write_UINT16_BE(s, syndataPayload->uUpStreamMtu);
	Stream_Write_UINT16_BE(s, syndataPayload->uDownStreamMtu);

	rdpudp_dump_syndata_payload(syndataPayload);
}

static void rdpudp_dump_ack_of_ackvector_header(RDPUDP_ACK_OF_ACKVECTOR_HEADER* ackOfAckVectorHeader)
{
	fprintf(stderr, "RDPUDP_ACK_OF_ACKVECTOR_HEADER\n");
	fprintf(stderr, ".snAckOfAcksSequNum=%u\n", ackOfAckVectorHeader->snAckOfAcksSeqNum);
}

static BOOL rdpudp_read_ack_of_ackvector_header(wStream* s, RDPUDP_ACK_OF_ACKVECTOR_HEADER* ackOfAckVectorHeader)
{
	if (Stream_GetRemainingLength(s) < 4)
		return FALSE;

	Stream_Read_UINT32_BE(s, ackOfAckVectorHeader->snAckOfAcksSeqNum);

	rdpudp_dump_ack_of_ackvector_header(ackOfAckVectorHeader);

	return TRUE;
}

void rdpudp_write_ack_of_ackvector_header(wStream *s, RDPUDP_ACK_OF_ACKVECTOR_HEADER* ackOfAckVectorHeader)
{
	Stream_Write_UINT32_BE(s, ackOfAckVectorHeader->snAckOfAcksSeqNum);

	rdpudp_dump_ack_of_ackvector_header(ackOfAckVectorHeader);
}

static void rdpudp_dump_ack_vector_header(RDPUDP_ACK_VECTOR_HEADER* ackVectorHeader)
{
	fprintf(stderr, "RDPUDP_ACK_VECTOR_HEADER\n");
	fprintf(stderr, ".uAckVectorSize=%u\n", ackVectorHeader->uAckVectorSize);
}

static BOOL rdpudp_read_ack_vector_header(wStream* s, RDPUDP_ACK_VECTOR_HEADER* ackVectorHeader)
{
	int padding;

	if (Stream_GetRemainingLength(s) < 2)
		return FALSE;

	Stream_Read_UINT16_BE(s, ackVectorHeader->uAckVectorSize);

	if (Stream_GetRemainingLength(s) < ackVectorHeader->uAckVectorSize)
		return FALSE;

	Stream_Read(s, ackVectorHeader->AckVectorElement, ackVectorHeader->uAckVectorSize);

	/* Skip over padding to make the structure fall on a DWORD boundary. */
	padding = rdpudp_ack_vector_header_padding(ackVectorHeader->uAckVectorSize);

	if (padding > 0)
	{
		if (Stream_GetRemainingLength(s) < padding)
			return FALSE;

		Stream_Seek(s, padding);
	}

	rdpudp_dump_ack_vector_header(ackVectorHeader);

	return TRUE;
}

static void rdpudp_write_ack_vector_header(wStream* s, RDPUDP_ACK_VECTOR_HEADER* ackVectorHeader)
{
	int padding;

	Stream_Write_UINT16_BE(s, ackVectorHeader->uAckVectorSize);
	Stream_Write(s, ackVectorHeader->AckVectorElement, ackVectorHeader->uAckVectorSize);

	/* Pad the structure on a DWORD boundary. */
	padding = rdpudp_ack_vector_header_padding(ackVectorHeader->uAckVectorSize);

	if (padding > 0)
		Stream_Zero(s, padding);

	rdpudp_dump_ack_vector_header(ackVectorHeader);
}

static void rdpudp_dump_correlation_id_payload(RDPUDP_CORRELATION_ID_PAYLOAD* correlationIdPayload)
{
	fprintf(stderr, "RDPUDP_CORRELATION_ID_PAYLOAD\n");
	fprintf(stderr, ".uCorrelationId=xxx\n");
}

BOOL rdpudp_read_correlation_id_payload(wStream* s, RDPUDP_CORRELATION_ID_PAYLOAD* correlationIdPayload)
{
	if (Stream_GetRemainingLength(s) < 16)
		return FALSE;

	Stream_Read(s, correlationIdPayload->uCorrelationId, 16);

	rdpudp_dump_correlation_id_payload(correlationIdPayload);

	return TRUE;
}

static void rdpudp_write_correlation_id_payload(wStream* s, RDPUDP_CORRELATION_ID_PAYLOAD* correlationIdPayload)
{
	Stream_Write(s, correlationIdPayload->uCorrelationId, 16);

	rdpudp_dump_correlation_id_payload(correlationIdPayload);
}

static BOOL rdpudp_decode_pdu(wStream *s, RDPUDP_PDU* pdu)
{
	ZeroMemory(pdu, sizeof(RDPUDP_PDU));

	rdpudp_dump_packet(s);

	/* Parse the RDPUDP_FEC_HEADER. */
	if (!rdpudp_read_fec_header(s, &pdu->fecHeader))
	{
		WLog_ERR(TAG, "error parsing RDPUDP_FEC_HEADER");
		return FALSE;
	}

	/* If the SYN flag is set... */
	if (pdu->fecHeader.uFlags & RDPUDP_FLAG_SYN)
	{
		/* Parse the RDPUDP_SYNDATA_PAYLOAD. */
		if (!rdpudp_read_syndata_payload(s, &pdu->syndataPayload))
		{
			WLog_ERR(TAG, "error parsing RDPUDP_SYNDATA_PAYLOAD");
			return FALSE;
		}
	}

	/* If the ACK flag is set... */
	if (pdu->fecHeader.uFlags & RDPUDP_FLAG_ACK)
	{
		/* Parse the RDPUDP_ACK_VECTOR_HEADER. */
		if (!rdpudp_read_ack_vector_header(s, &pdu->ackVectorHeader))
		{
			WLog_ERR(TAG, "error parsing RDPUDP_ACK_VECTOR_HEADER");
			return FALSE;
		}
	}

	/* If the ACK_OF_ACKS flag is set... */
	if (pdu->fecHeader.uFlags & RDPUDP_FLAG_ACK_OF_ACKS)
	{
		/* Parse the RDPUDP_ACK_OF_ACKVECTOR_HEADER. */
		if (!rdpudp_read_ack_of_ackvector_header(s, &pdu->ackOfAckVectorHeader))
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
			if (!rdpudp_read_fec_payload_header(s, &pdu->fecPayloadHeader))
			{
				WLog_ERR(TAG, "error parsing RDPUDP_FEC_PAYLOAD_HEADER");
				return FALSE;
			}
		}
		else
		{
			/* Parse the RDPUDP_SOURCE_PAYLOAD_HEADER. */
			if (!rdpudp_read_source_payload_header(s, &pdu->sourcePayloadHeader))
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

wStream* rdpudp_encode_pdu(RDPUDP_PDU* pdu)
{
	wStream* s;

	s = rdpudp_packet_init();

	if (!s)
		return NULL;

	rdpudp_write_fec_header(s, &pdu->fecHeader);

	if (pdu->fecHeader.uFlags & RDPUDP_FLAG_SYN)
	{
		rdpudp_write_syndata_payload(s, &pdu->syndataPayload);
	}

	if (pdu->fecHeader.uFlags & RDPUDP_FLAG_CORRELATION_ID)
	{
		rdpudp_write_correlation_id_payload(s, &pdu->correlationIdPayload);
	}

	if (pdu->fecHeader.uFlags & RDPUDP_FLAG_ACK)
	{
		rdpudp_write_ack_vector_header(s, &pdu->ackVectorHeader);
	}

	if (pdu->fecHeader.uFlags & RDPUDP_FLAG_DATA)
	{
		rdpudp_write_source_payload_header(s, &pdu->sourcePayloadHeader);

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
static void rdpudp_clear_recv_queue(rdpUdp* rdpudp)
{
}

static void rdpudp_clear_send_queue(rdpUdp* rdpudp)
{
	int index = rdpudp->sendQueueHead;
	int count = rdpudp->sendQueueSize;

	if (count > 0)
	{
		while (count > 0)
		{
			wStream* pdu = rdpudp->sendQueue[index];
			rdpudp->sendQueue[index] = NULL;
			Stream_Free(pdu, TRUE);	
			index = (index + 1) % rdpudp->sendQueueCapacity;
			count--;
		}
		rdpudp->sendQueueHead = index;
		rdpudp->sendQueueSize = 0;
	}
}

static BOOL rdpudp_append_send_queue(rdpUdp* rdpudp, wStream* s)
{
	if (rdpudp->sendQueueSize >= rdpudp->sendQueueCapacity)
	{
		fprintf(stderr, "send queue overflow\n");
		return FALSE;
	}

	rdpudp->sendQueue[rdpudp->sendQueueTail] = s;
	rdpudp->sendQueueTail = (rdpudp->sendQueueTail + 1) % rdpudp->sendQueueCapacity;
	rdpudp->sendQueueSize++;

	return TRUE;
}

/**
 * Timer Functions
 */
static void rdpudp_stop_retransmit_timer(rdpUdp* rdpudp)
{
	rdpudp->retransmitTimer = 0;
	rdpudp->retransmitCount = 0;
}

static void rdpudp_reset_retransmit_timer(rdpUdp* rdpudp)
{
	rdpudp->retransmitTimer = GetTickCount() + RDPUDP_RETRANSMIT_INTERVAL;
}

static void rdpudp_start_retransmit_timer(rdpUdp* rdpudp)
{
	rdpudp_reset_retransmit_timer(rdpudp);
	rdpudp->retransmitCount = 0;
}

static void rdpudp_retransmit(rdpUdp* rdpudp)
{
	int index = rdpudp->sendQueueHead;
	int count = rdpudp->sendQueueSize;

	while (count > 0)
	{
		wStream* s = rdpudp->sendQueue[index];
		rdpudp_send_packet(rdpudp, s);
		index = (index + 1) % rdpudp->sendQueueCapacity;
		count--;
	}
}

/**
 * PDU Processing Functions
 */
static BOOL rdpudp_send_pdu(rdpUdp* rdpudp, RDPUDP_PDU* pdu)
{
	wStream* s;

	s = rdpudp_encode_pdu(pdu);

	if (!s)
		return FALSE;

	if (!rdpudp_send_packet(rdpudp, s))
	{
		WLog_ERR(TAG, "error sending PDU\n");
		Stream_Free(s, TRUE);
		return FALSE;
	}

	rdpudp_append_send_queue(rdpudp, s);
	rdpudp_start_retransmit_timer(rdpudp);

	return TRUE;
}

static BOOL rdpudp_send_data(
	rdpUdp* rdpudp, UINT16 flags,
	BYTE* ackVectorElement, UINT16 ackVectorSize,
	BYTE* payloadData, int payloadSize)
{
	RDPUDP_PDU pdu;

	if (flags == 0)
		return FALSE;

	ZeroMemory(&pdu, sizeof(pdu));

	pdu.fecHeader.snSourceAck = rdpudp->serverSequenceNumber;
	pdu.fecHeader.uReceiveWindowSize = rdpudp->clientReceiveWindowSize;
	pdu.fecHeader.uFlags = flags;

	if (flags & RDPUDP_FLAG_SYN)
	{
		pdu.syndataPayload.snInitialSequenceNumber = rdpudp->clientSequenceNumber;
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
		rdpudp->clientSequenceNumber++;

		pdu.sourcePayloadHeader.snCoded = rdpudp->clientSequenceNumber;
		pdu.sourcePayloadHeader.snSourceStart = rdpudp->clientSequenceNumber;

		if (payloadData)
		{
			pdu.payloadData = payloadData;
			pdu.payloadSize = payloadSize;
		}
	}

	return rdpudp_send_pdu(rdpudp, &pdu);
}

static BOOL rdpudp_process_acks(rdpUdp* rdpudp, RDPUDP_PDU* pdu)
{
	if ((pdu->fecHeader.uFlags & RDPUDP_FLAG_ACK) == 0)
	{
		fprintf(stderr, "no ACKS to process\n");
		return FALSE;
	}

	int index = rdpudp->sendQueueHead;
	int count = rdpudp->sendQueueSize;

	if (count > 0)
	{
		while (count > 0)
		{
			wStream* s = rdpudp->sendQueue[index];
			rdpudp->sendQueue[index] = NULL;
			Stream_Free(s, TRUE);	
			index = (index + 1) % rdpudp->sendQueueCapacity;
			count--;
		}
		rdpudp->sendQueueHead = index;
		rdpudp->sendQueueSize = 0;

		if (rdpudp->sendQueueSize == 0)
		{
			rdpudp_stop_retransmit_timer(rdpudp);
		}
	}

	return TRUE;
}

static void rdpudp_process_data(rdpUdp* rdpudp, RDPUDP_PDU* inputPdu)
{
	BYTE decryptedData[1024];
	int status;

	fprintf(stderr, "rdpudp_process_data\n");

	/* If the connection is secured with TLS... */
	if (rdpudp->tls)
	{
		/* Decrypt the payload. */
		status = rdpudp_tls_write(rdpudp->tls, inputPdu->payloadData, inputPdu->payloadSize);

		if (status < 0)
		{
			WLog_ERR(TAG, "error decrypting data");
			return;
		}

		status = rdpudp_tls_decrypt(rdpudp->tls, decryptedData, sizeof(decryptedData));

		if (status < 0)
		{
			WLog_ERR(TAG, "error decrypting data");
			return;
		}

		/* Deliver the data. */
		IFCALL(rdpudp->onDataReceived, rdpudp, decryptedData, status);

		/* Send an ACK. */
		UINT16 flags = RDPUDP_FLAG_ACK;
		BYTE ackVectorElement[1];
		UINT16 ackVectorSize = 0;

		/* Update the server sequence number. */
		rdpudp->serverSequenceNumber = inputPdu->sourcePayloadHeader.snSourceStart;
			
		/* Construct the ACK vector. */
		ackVectorSize = 1;
		ackVectorElement[0] = (DATAGRAM_RECEIVED << 6) | 0x01;

		rdpudp_send_data(rdpudp, flags, ackVectorElement, ackVectorSize, NULL, 0);
	}
}

static void rdpudp_change_state(rdpUdp* rdpudp, int state)
{
	rdpudp->state = state;

	switch (state)
	{
		case RDPUDP_STATE_DISCONNECTED:
			IFCALL(rdpudp->onDisconnected, rdpudp);
			break;

		case RDPUDP_STATE_CONNECTING:
			IFCALL(rdpudp->onConnecting, rdpudp);
			break;

		case RDPUDP_STATE_CONNECTED:
			IFCALL(rdpudp->onConnected, rdpudp);
			break;

		case RDPUDP_STATE_SECURING:
			IFCALL(rdpudp->onSecuring, rdpudp);
			break;

		case RDPUDP_STATE_SECURED:
			IFCALL(rdpudp->onSecured, rdpudp);
			break;

		default:
			break;
	}
}

static void rdpudp_secure_connection(rdpUdp* rdpudp, RDPUDP_PDU* inputPdu)
{
	BYTE ackVectorElement[1];
	UINT16 ackVectorSize = 0;

	if (rdpudp->tls)
	{
		WLog_DBG(TAG, "securing with TLS");

		/* If the DATA flag is set... */
		if (inputPdu->fecHeader.uFlags & RDPUDP_FLAG_DATA)
		{
			/* Update the server sequence number. */
			rdpudp->serverSequenceNumber = inputPdu->sourcePayloadHeader.snSourceStart;
			
			/* Construct the ACK vector. */
			ackVectorSize = 1;
			ackVectorElement[0] = (DATAGRAM_RECEIVED << 6) | 0x01;

			/* Process handshake bytes sent by the peer. */
			int status = rdpudp_tls_write(rdpudp->tls, inputPdu->payloadData, inputPdu->payloadSize);
			fprintf(stderr, "rdpudp_tls_write: payload=%p, length=%d, status=%d\n", inputPdu->payloadData, inputPdu->payloadSize, status);
		}

		/* When connect returns TRUE, the connection is secured. */
		if (rdpudp_tls_connect(rdpudp->tls))
		{
			fprintf(stderr, "SECURED!!!\n");
			rdpudp_change_state(rdpudp, RDPUDP_STATE_SECURED);
		}

		/* Send handshake bytes to the peer. */
		if (rdpudp_tls_get_last_error(rdpudp->tls) == SSL_ERROR_WANT_READ)
		{
			BYTE buffer[2048];
			int status;

			status = rdpudp_tls_read(rdpudp->tls, buffer, sizeof(buffer));

			fprintf(stderr, "rdpudp_tls_read: status=%d\n", status);

			if (status >= 0)
			{
				UINT16 flags = RDPUDP_FLAG_ACK;
				if (status > 0)
				{
					flags |= RDPUDP_FLAG_DATA;
				}
				rdpudp_send_data(rdpudp, flags, ackVectorElement, ackVectorSize, buffer, status);
			}
		}
	}
}


/**
 * State machine
 */
static void rdpudp_connecting_state(rdpUdp* rdpudp, RDPUDP_PDU* inputPdu)
{
	/* If the SYN + ACK flags are set... */
	if ((inputPdu->fecHeader.uFlags & RDPUDP_FLAG_SYN) &&
		(inputPdu->fecHeader.uFlags & RDPUDP_FLAG_ACK))
	{
		fprintf(stderr, "SYN + ACK received\n");

		rdpudp_change_state(rdpudp, RDPUDP_STATE_CONNECTED);

		/* Process ACKs. */
		rdpudp_process_acks(rdpudp, inputPdu);

		/* Save the server's initial sequence number. */
		rdpudp->serverSequenceNumber = inputPdu->syndataPayload.snInitialSequenceNumber;

		/* Begin securing the connection. */
		rdpudp_change_state(rdpudp, RDPUDP_STATE_SECURING);

		rdpudp_secure_connection(rdpudp, inputPdu);
	}
}

static void rdpudp_securing_state(rdpUdp* rdpudp, RDPUDP_PDU* inputPdu)
{
	/* If the ACK flag is set... */
	if (inputPdu->fecHeader.uFlags & RDPUDP_FLAG_ACK)
	{
		rdpudp_process_acks(rdpudp, inputPdu);
	}

	/* If the DATA flag is set... */
	if (inputPdu->fecHeader.uFlags & RDPUDP_FLAG_DATA)
	{
		/* Continue securing the connection. */
		rdpudp_secure_connection(rdpudp, inputPdu);
	}
}

static void rdpudp_secured_state(rdpUdp* rdpudp, RDPUDP_PDU* inputPdu)
{
	fprintf(stderr, "rdpudp_secured_state\n");

	/* If the ACK flag is set... */
	if (inputPdu->fecHeader.uFlags & RDPUDP_FLAG_ACK)
	{
		rdpudp_process_acks(rdpudp, inputPdu);
	}

	/* If the DATA flag is set... */
	if (inputPdu->fecHeader.uFlags & RDPUDP_FLAG_DATA)
	{
		rdpudp_process_data(rdpudp, inputPdu);
	}
}

static BOOL rdpudp_recv_pdu(rdpUdp* rdpudp, wStream* s)
{
	RDPUDP_PDU pdu;

	fprintf(stderr, "rdpudp_recv_pdu: tickCount: %d\n", (int) GetTickCount());

	/* Decode the PDU. */
	if (!rdpudp_decode_pdu(s, &pdu))
	{
		return FALSE;
	}

	switch (rdpudp->state)
	{
		case RDPUDP_STATE_DISCONNECTED:
			break;

		case RDPUDP_STATE_CONNECTING:
			rdpudp_connecting_state(rdpudp, &pdu);
			break;

		case RDPUDP_STATE_CONNECTED:
			break;

		case RDPUDP_STATE_SECURING:
			rdpudp_securing_state(rdpudp, &pdu);
			break;

		case RDPUDP_STATE_SECURED:
			rdpudp_secured_state(rdpudp, &pdu);
			break;

		default:
			break;
	}

	/**
	 * If we got here, it's because we received something
	 * unexpected.  In this case, just retransmit PDUs.
	 */
	//rdpudp_retransmit(rdpudp);

	fprintf(stderr, "\n");

	return TRUE;
}

static void rdpudp_timeout(rdpUdp* rdpudp)
{
	fprintf(stderr, "rdpudp_timeout: tickCount: %d\n", (int) GetTickCount());

	switch (rdpudp->state)
	{
		case RDPUDP_STATE_CONNECTING:
		case RDPUDP_STATE_SECURING:
			if (rdpudp->retransmitCount++ < RDPUDP_RETRANSMIT_COUNT)
			{
				rdpudp_retransmit(rdpudp);
				rdpudp_reset_retransmit_timer(rdpudp);
			}
			break;

		default:
			break;
	}

	fprintf(stderr, "\n");
}

/**
 * Main thread
 */
static DWORD rdpudp_thread(LPVOID lpParameter)
{
	rdpUdp* rdpudp = (rdpUdp*) lpParameter;
	int sockfd = rdpudp->sockfd;

	while (TRUE)
	{
		BYTE pdu[RDPUDP_MTU_SIZE];
		struct timeval timeval;
		struct timeval* tv;
		fd_set rfds;
		wStream* s;
		int status;

		FD_ZERO(&rfds);
		FD_SET(sockfd, &rfds);

		tv = NULL;

		if (rdpudp->retransmitTimer)
		{
			DWORD tickCount = GetTickCount();

			if (tickCount < rdpudp->retransmitTimer)
			{
				DWORD timeDiff = rdpudp->retransmitTimer - tickCount;
				timeval.tv_sec = timeDiff / 1000;
				timeval.tv_usec = (timeDiff % 1000) * 1000;
				tv = &timeval;
			}
		}

		status = select(sockfd + 1, &rfds, NULL, NULL, tv);

		if (status < 0)
		{
			WLog_DBG(TAG, "select error (errno=%d)", errno);
			break;
		}

		if (status > 0)
		{
			status = recv(sockfd, pdu, sizeof(pdu), 0);

			if (status <= 0)
			{
				WLog_DBG(TAG, "recv error (errno=%d)", errno);
				break;
			}

			WLog_DBG(TAG, "recv pdulen=%d", status);
			s = Stream_New(pdu, status);
			rdpudp_recv_pdu(rdpudp, s);
			Stream_Free(s, FALSE);
		}
		else
		{
			rdpudp_timeout(rdpudp);
		}
	}

	return 0;
}

/**
 * Initialization
 */
BOOL rdpudp_init(rdpUdp* rdpudp, UINT16 protocol)
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
	rdpudp->protocol = protocol;

	rdpudp->clientSequenceNumber = 0x35B1D982;
	rdpudp->clientReceiveWindowSize = 64;

	rdpudp->serverSequenceNumber = 0xFFFFFFFF;
	rdpudp->serverReceiveWindowSize = 64;

	rdpudp->recvQueue = (wStream**) calloc(RDPUDP_QUEUE_SIZE, sizeof(wStream*));
	if (rdpudp->recvQueue)
	{
		rdpudp->recvQueueCapacity = RDPUDP_QUEUE_SIZE;
	}

	rdpudp->sendQueue = (wStream**) calloc(RDPUDP_QUEUE_SIZE, sizeof(wStream*));
	if (rdpudp->sendQueue)
	{
		rdpudp->sendQueueCapacity = RDPUDP_QUEUE_SIZE;
	}

	/* Initialize TLS/DTLS. */
	if (protocol == RDPUDP_PROTOCOL_UDPFECR)
	{
		rdpudp->tls = rdpudp_tls_new(rdpudp->rdp->settings);
	}
	else
	{
		rdpudp->dtls = rdpudp_dtls_new(rdpudp->rdp->settings);
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

	hostname = rdpudp->rdp->settings->ServerHostname;
	sprintf(servname, "%d", rdpudp->rdp->settings->ServerPort);
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
		if (sockfd < 0) continue;

		status = connect(sockfd, ai->ai_addr, ai->ai_addrlen);
		if (status != 0) continue;

		break;
	}

	freeaddrinfo(res);

	if (sockfd == -1)
	{
		WLog_DBG(TAG, "unable to connect to %s:%s\n", hostname, servname);
		return FALSE;
	}

	rdpudp->sockfd = sockfd;

	/* Send a SYN datagram to the server. */
	flags = RDPUDP_FLAG_SYN;

	if (protocol == RDPUDP_PROTOCOL_UDPFECL)
		flags |= RDPUDP_FLAG_SYNLOSSY;

	if (!rdpudp_send_data(rdpudp, flags, NULL, 0, NULL, 0))
	{
		WLog_DBG(TAG, "cannot send SYN");
		return FALSE;
	}

	rdpudp->state = RDPUDP_STATE_CONNECTING;

	/* Start the thread. */
	rdpudp->hThread = CreateThread(NULL, 0, rdpudp_thread,
			(LPVOID) rdpudp, 0, &rdpudp->dwThreadId);

	return TRUE;
}

/**
 * Read/write functions
 */
int rdpudp_read(rdpUdp* rdpudp, BYTE* data, int size)
{
	return -1;
}

int rdpudp_write(rdpUdp* rdpudp, BYTE* data, int size)
{
	int status;
	BYTE encryptedData[1024];

	if (rdpudp->state != RDPUDP_STATE_SECURED)
	{
		WLog_DBG(TAG, "state is not secured");
		return -1;
	}

	/* If the connection is secured with TLS... */
	if (rdpudp->tls)
	{
		/* Encrypt the data. */
		status = rdpudp_tls_encrypt(rdpudp->tls, data, size);

		if (status != size)
		{
			WLog_DBG(TAG, "error encrypting data (status=%d)", status);
			return -1;
		}

		status = rdpudp_tls_read(rdpudp->tls, encryptedData, sizeof(encryptedData));

		if (status < 0)
		{
			WLog_DBG(TAG, "error encrypting data (status=%d)", status);
			return -1;
		}

		/* Send the encrypted data. */
		if (!rdpudp_send_data(rdpudp, RDPUDP_FLAG_ACK | RDPUDP_FLAG_DATA, NULL, 0, encryptedData, status))
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
rdpUdp* rdpudp_new(rdpRdp* rdp)
{
	rdpUdp* rdpudp;

	rdpudp = (rdpUdp*) calloc(1, sizeof(rdpUdp));

	if (rdpudp)
	{
		rdpudp->rdp = rdp;
	}
	
	return rdpudp;
}

void rdpudp_free(rdpUdp* rdpudp)
{
	if (!rdpudp)
		return;

	WLog_DBG(TAG, "rdpudp_free");

	closesocket(rdpudp->sockfd);
	rdpudp->sockfd = -1;

	WaitForSingleObject(rdpudp->hThread, 250);
	CloseHandle(rdpudp->hThread);

	rdpudp_clear_recv_queue(rdpudp);
	rdpudp_clear_send_queue(rdpudp);

	free(rdpudp->recvQueue);
	free(rdpudp->sendQueue);

	free(rdpudp);
}

