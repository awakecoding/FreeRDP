/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Activation Sequence
 *
 * Copyright 2011 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#include "activation.h"
#include "display.h"

#define TAG FREERDP_TAG("core.activation")

/*
static const char* const CTRLACTION_STRINGS[] =
{
        "",
        "CTRLACTION_REQUEST_CONTROL",
        "CTRLACTION_GRANTED_CONTROL",
        "CTRLACTION_DETACH",
        "CTRLACTION_COOPERATE"
};
*/
static BOOL rdp_recv_server_synchronize_pdu(rdpRdp* rdp, wStream* s);
static BOOL rdp_recv_client_font_list_pdu(wStream* s);
static BOOL rdp_recv_client_persistent_key_list_pdu(wStream* s);
static BOOL rdp_recv_server_font_map_pdu(rdpRdp* rdp, wStream* s);
static BOOL rdp_recv_client_font_map_pdu(rdpRdp* rdp, wStream* s);
static BOOL rdp_send_server_font_map_pdu(rdpRdp* rdp);

static BOOL rdp_write_synchronize_pdu(wStream* s, rdpSettings* settings)
{
	if (Stream_GetRemainingCapacity(s) < 4)
		return FALSE;
	Stream_Write_UINT16(s, SYNCMSGTYPE_SYNC);    /* messageType (2 bytes) */
	Stream_Write_UINT16(s, settings->PduSource); /* targetUser (2 bytes) */
	return TRUE;
}

BOOL rdp_recv_synchronize_pdu(rdpRdp* rdp, wStream* s)
{
	if (rdp->settings->ServerMode)
		return rdp_recv_server_synchronize_pdu(rdp, s);
	else
		return rdp_recv_client_synchronize_pdu(rdp, s);
}

BOOL rdp_recv_server_synchronize_pdu(rdpRdp* rdp, wStream* s)
{
	rdp->finalize_sc_pdus |= FINALIZE_SC_SYNCHRONIZE_PDU;
	return TRUE;
}

BOOL rdp_send_server_synchronize_pdu(rdpRdp* rdp)
{
	wStream* s = rdp_data_pdu_init(rdp);
	if (!s)
		return FALSE;
	if (!rdp_write_synchronize_pdu(s, rdp->settings))
	{
		Stream_Free(s, TRUE);
		return FALSE;
	}
	return rdp_send_data_pdu(rdp, s, DATA_PDU_TYPE_SYNCHRONIZE, rdp->mcs->userId);
}

BOOL rdp_recv_client_synchronize_pdu(rdpRdp* rdp, wStream* s)
{
	UINT16 messageType;
	rdp->finalize_sc_pdus |= FINALIZE_SC_SYNCHRONIZE_PDU;

	if (Stream_GetRemainingLength(s) < 4)
		return FALSE;

	Stream_Read_UINT16(s, messageType); /* messageType (2 bytes) */

	if (messageType != SYNCMSGTYPE_SYNC)
		return FALSE;

	/* targetUser (2 bytes) */
	Stream_Seek_UINT16(s);
	return TRUE;
}

BOOL rdp_send_client_synchronize_pdu(rdpRdp* rdp)
{
	wStream* s = rdp_data_pdu_init(rdp);
	if (!s)
		return FALSE;
	if (!rdp_write_synchronize_pdu(s, rdp->settings))
	{
		Stream_Free(s, TRUE);
		return FALSE;
	}
	return rdp_send_data_pdu(rdp, s, DATA_PDU_TYPE_SYNCHRONIZE, rdp->mcs->userId);
}

static BOOL rdp_recv_control_pdu(wStream* s, UINT16* action)
{
	if (Stream_GetRemainingLength(s) < 8)
		return FALSE;

	Stream_Read_UINT16(s, *action); /* action (2 bytes) */
	Stream_Seek_UINT16(s);          /* grantId (2 bytes) */
	Stream_Seek_UINT32(s);          /* controlId (4 bytes) */
	return TRUE;
}

static BOOL rdp_write_client_control_pdu(wStream* s, UINT16 action)
{
	if (Stream_GetRemainingCapacity(s) < 8)
		return FALSE;
	Stream_Write_UINT16(s, action); /* action (2 bytes) */
	Stream_Write_UINT16(s, 0);      /* grantId (2 bytes) */
	Stream_Write_UINT32(s, 0);      /* controlId (4 bytes) */
	return TRUE;
}

BOOL rdp_recv_server_control_pdu(rdpRdp* rdp, wStream* s)
{
	UINT16 action;

	if (rdp_recv_control_pdu(s, &action) == FALSE)
		return FALSE;

	switch (action)
	{
		case CTRLACTION_COOPERATE:
			rdp->finalize_sc_pdus |= FINALIZE_SC_CONTROL_COOPERATE_PDU;
			break;

		case CTRLACTION_GRANTED_CONTROL:
			rdp->finalize_sc_pdus |= FINALIZE_SC_CONTROL_GRANTED_PDU;
			rdp->resendFocus = TRUE;
			break;
	}

	return TRUE;
}

BOOL rdp_send_server_control_cooperate_pdu(rdpRdp* rdp)
{
	wStream* s = rdp_data_pdu_init(rdp);
	if (!s)
		return FALSE;
	if (Stream_GetRemainingCapacity(s) < 8)
	{
		Stream_Free(s, TRUE);
		return FALSE;
	}
	Stream_Write_UINT16(s, CTRLACTION_COOPERATE); /* action (2 bytes) */
	Stream_Write_UINT16(s, 0);                    /* grantId (2 bytes) */
	Stream_Write_UINT32(s, 0);                    /* controlId (4 bytes) */
	return rdp_send_data_pdu(rdp, s, DATA_PDU_TYPE_CONTROL, rdp->mcs->userId);
}

static BOOL rdp_send_server_control_granted_pdu(rdpRdp* rdp)
{
	wStream* s = rdp_data_pdu_init(rdp);
	if (!s)
		return FALSE;
	if (Stream_GetRemainingCapacity(s) < 8)
	{
		Stream_Free(s, TRUE);
		return FALSE;
	}
	Stream_Write_UINT16(s, CTRLACTION_GRANTED_CONTROL); /* action (2 bytes) */
	Stream_Write_UINT16(s, rdp->mcs->userId);           /* grantId (2 bytes) */
	Stream_Write_UINT32(s, 0x03EA);                     /* controlId (4 bytes) */
	return rdp_send_data_pdu(rdp, s, DATA_PDU_TYPE_CONTROL, rdp->mcs->userId);
}

BOOL rdp_send_client_control_pdu(rdpRdp* rdp, UINT16 action)
{
	wStream* s = rdp_data_pdu_init(rdp);
	if (!s)
		return FALSE;
	if (!rdp_write_client_control_pdu(s, action))
	{
		Stream_Free(s, TRUE);
		return FALSE;
	}
	return rdp_send_data_pdu(rdp, s, DATA_PDU_TYPE_CONTROL, rdp->mcs->userId);
}

static BOOL rdp_write_persistent_list_entry(wStream* s, UINT32 key1, UINT32 key2)
{
	if (Stream_GetRemainingCapacity(s) < 8)
		return FALSE;
	Stream_Write_UINT32(s, key1); /* key1 (4 bytes) */
	Stream_Write_UINT32(s, key2); /* key2 (4 bytes) */
	return TRUE;
}

static BOOL rdp_write_client_persistent_key_list_pdu(wStream* s, RDP_BITMAP_PERSISTENT_INFO* info)
{
	int index;
	UINT32 key1;
	UINT32 key2;

	if (Stream_GetRemainingCapacity(s) < 24)
		return FALSE;
	Stream_Write_UINT16(s, info->numEntriesCache0);              /* numEntriesCache0 (2 bytes) */
	Stream_Write_UINT16(s, info->numEntriesCache1);              /* numEntriesCache1 (2 bytes) */
	Stream_Write_UINT16(s, info->numEntriesCache2);              /* numEntriesCache2 (2 bytes) */
	Stream_Write_UINT16(s, info->numEntriesCache3);              /* numEntriesCache3 (2 bytes) */
	Stream_Write_UINT16(s, info->numEntriesCache4);              /* numEntriesCache4 (2 bytes) */
	Stream_Write_UINT16(s, info->totalEntriesCache0);            /* totalEntriesCache0 (2 bytes) */
	Stream_Write_UINT16(s, info->totalEntriesCache1);            /* totalEntriesCache1 (2 bytes) */
	Stream_Write_UINT16(s, info->totalEntriesCache2);            /* totalEntriesCache2 (2 bytes) */
	Stream_Write_UINT16(s, info->totalEntriesCache3);            /* totalEntriesCache3 (2 bytes) */
	Stream_Write_UINT16(s, info->totalEntriesCache4);            /* totalEntriesCache4 (2 bytes) */
	Stream_Write_UINT8(s, PERSIST_FIRST_PDU | PERSIST_LAST_PDU); /* bBitMask (1 byte) */
	Stream_Write_UINT8(s, 0);                                    /* pad1 (1 byte) */
	Stream_Write_UINT16(s, 0);                                   /* pad3 (2 bytes) */
	                                                             /* entries */

	Stream_EnsureRemainingCapacity(s, info->keyCount * 8);

	for (index = 0; index < info->keyCount; index++)
	{
		key1 = (UINT32)info->keyList[index];
		key2 = (UINT32)(info->keyList[index] >> 32);
		Stream_Write_UINT32(s, key1);
		Stream_Write_UINT32(s, key2);
	}

	return TRUE;
}

UINT32 rdp_load_persistent_key_list(rdpRdp* rdp, UINT64** pKeyList)
{
	int index;
	int count;
	int status;
	UINT32 keyCount;
	UINT64* keyList = NULL;
	rdpPersistentCache* persistent;
	PERSISTENT_CACHE_ENTRY cacheEntry;
	rdpSettings* settings = rdp->settings;

	*pKeyList = NULL;

	if (!settings->BitmapCachePersistEnabled)
		return 0;

	if (!settings->BitmapCachePersistFile)
		return 0;

	persistent = persistent_cache_new();

	if (!persistent)
		return 0;

	status = persistent_cache_open(persistent, settings->BitmapCachePersistFile, FALSE, -1);

	if (status < 1)
		goto error;

	count = persistent_cache_get_count(persistent);

	keyCount = (UINT32)count;
	keyList = (UINT64*)malloc(keyCount * sizeof(UINT64));

	for (index = 0; index < count; index++)
	{
		if (persistent_cache_read_entry(persistent, &cacheEntry) < 1)
			continue;

		keyList[index] = cacheEntry.key64;
	}

	*pKeyList = keyList;

	persistent_cache_free(persistent);
	return keyCount;
error:
	persistent_cache_free(persistent);
	return 0;
}

BOOL rdp_send_client_persistent_key_list_pdu(rdpRdp* rdp)
{
	UINT32 keyCount;
	UINT64* keyList = NULL;
	RDP_BITMAP_PERSISTENT_INFO info;
	rdpSettings* settings = rdp->settings;

	keyCount = rdp_load_persistent_key_list(rdp, &keyList);

	info.totalEntriesCache0 = settings->BitmapCacheV2CellInfo[0].numEntries;
	info.totalEntriesCache1 = settings->BitmapCacheV2CellInfo[1].numEntries;
	info.totalEntriesCache2 = settings->BitmapCacheV2CellInfo[2].numEntries;
	info.totalEntriesCache3 = settings->BitmapCacheV2CellInfo[3].numEntries;
	info.totalEntriesCache4 = settings->BitmapCacheV2CellInfo[4].numEntries;

	info.numEntriesCache0 =
		(keyCount < info.totalEntriesCache0) ? keyCount : info.totalEntriesCache0;
	keyCount -= info.numEntriesCache0;
	info.numEntriesCache1 =
		(keyCount < info.totalEntriesCache1) ? keyCount : info.totalEntriesCache1;
	keyCount -= info.numEntriesCache1;
	info.numEntriesCache2 =
		(keyCount < info.totalEntriesCache2) ? keyCount : info.totalEntriesCache2;
	keyCount -= info.numEntriesCache2;
	info.numEntriesCache3 =
		(keyCount < info.totalEntriesCache3) ? keyCount : info.totalEntriesCache3;
	keyCount -= info.numEntriesCache3;
	info.numEntriesCache4 =
		(keyCount < info.totalEntriesCache4) ? keyCount : info.totalEntriesCache4;
	keyCount -= info.numEntriesCache4;

	info.totalEntriesCache0 = info.numEntriesCache0;
	info.totalEntriesCache1 = info.numEntriesCache1;
	info.totalEntriesCache2 = info.numEntriesCache2;
	info.totalEntriesCache3 = info.numEntriesCache3;
	info.totalEntriesCache4 = info.numEntriesCache4;

	keyCount = info.totalEntriesCache0 + info.totalEntriesCache1 + info.totalEntriesCache2 +
		info.totalEntriesCache3 + info.totalEntriesCache4;

	info.keyCount = keyCount;
	info.keyList = keyList;

	wStream* s = rdp_data_pdu_init(rdp);
	if (!s)
		return FALSE;
	if (!rdp_write_client_persistent_key_list_pdu(s, rdp->settings))
	{
		Stream_Free(s, TRUE);
		return FALSE;
	}

	free(keyList);

	return rdp_send_data_pdu(rdp, s, DATA_PDU_TYPE_BITMAP_CACHE_PERSISTENT_LIST, rdp->mcs->userId);
}

BOOL rdp_recv_client_font_list_pdu(wStream* s)
{
	/* 2.2.1.18 Client Font List PDU */
	return Stream_SafeSeek(s, 8);
}

BOOL rdp_recv_client_persistent_key_list_pdu(wStream* s)
{
	BYTE flags;
	size_t count = 0;
	UINT16 cache, x;
	/* 2.2.1.17.1 Persistent Key List PDU Data (TS_BITMAPCACHE_PERSISTENT_LIST_PDU) */
	if (Stream_GetRemainingLength(s) < 21)
		return FALSE;
	/* Read numEntriesCacheX for variable length data in PDU */
	for (x = 0; x < 5; x++)
	{
		Stream_Read_UINT16(s, cache);
		count += cache;
	}

	/* Skip totalEntriesCacheX */
	if (!Stream_SafeSeek(s, 10))
		return FALSE;

	Stream_Read_UINT8(s, flags);

	/* Skip padding */
	if (!Stream_SafeSeek(s, 3))
		return FALSE;
	/* Skip actual entries sent by client */
	return Stream_SafeSeek(s, count * sizeof(UINT64));
}

static BOOL rdp_write_client_font_list_pdu(wStream* s, UINT16 flags)
{
	if (Stream_GetRemainingCapacity(s) < 8)
		return FALSE;
	Stream_Write_UINT16(s, 0);     /* numberFonts (2 bytes) */
	Stream_Write_UINT16(s, 0);     /* totalNumFonts (2 bytes) */
	Stream_Write_UINT16(s, flags); /* listFlags (2 bytes) */
	Stream_Write_UINT16(s, 50);    /* entrySize (2 bytes) */
	return TRUE;
}

BOOL rdp_send_client_font_list_pdu(rdpRdp* rdp, UINT16 flags)
{
	wStream* s = rdp_data_pdu_init(rdp);
	if (!s)
		return FALSE;
	if (!rdp_write_client_font_list_pdu(s, flags))
	{
		Stream_Free(s, TRUE);
		return FALSE;
	}
	return rdp_send_data_pdu(rdp, s, DATA_PDU_TYPE_FONT_LIST, rdp->mcs->userId);
}

BOOL rdp_recv_font_map_pdu(rdpRdp* rdp, wStream* s)
{
	if (rdp->settings->ServerMode)
		return rdp_recv_server_font_map_pdu(rdp, s);
	else
		return rdp_recv_client_font_map_pdu(rdp, s);
}

BOOL rdp_recv_server_font_map_pdu(rdpRdp* rdp, wStream* s)
{
	rdp->finalize_sc_pdus |= FINALIZE_SC_FONT_MAP_PDU;
	return TRUE;
}

BOOL rdp_recv_client_font_map_pdu(rdpRdp* rdp, wStream* s)
{
	rdp->finalize_sc_pdus |= FINALIZE_SC_FONT_MAP_PDU;

	if (Stream_GetRemainingLength(s) >= 8)
	{
		Stream_Seek_UINT16(s); /* numberEntries (2 bytes) */
		Stream_Seek_UINT16(s); /* totalNumEntries (2 bytes) */
		Stream_Seek_UINT16(s); /* mapFlags (2 bytes) */
		Stream_Seek_UINT16(s); /* entrySize (2 bytes) */
	}

	return TRUE;
}

BOOL rdp_send_server_font_map_pdu(rdpRdp* rdp)
{
	wStream* s = rdp_data_pdu_init(rdp);
	if (!s)
		return FALSE;
	if (Stream_GetRemainingCapacity(s) < 8)
	{
		Stream_Free(s, TRUE);
		return FALSE;
	}
	Stream_Write_UINT16(s, 0);                              /* numberEntries (2 bytes) */
	Stream_Write_UINT16(s, 0);                              /* totalNumEntries (2 bytes) */
	Stream_Write_UINT16(s, FONTLIST_FIRST | FONTLIST_LAST); /* mapFlags (2 bytes) */
	Stream_Write_UINT16(s, 4);                              /* entrySize (2 bytes) */
	return rdp_send_data_pdu(rdp, s, DATA_PDU_TYPE_FONT_MAP, rdp->mcs->userId);
}

BOOL rdp_recv_deactivate_all(rdpRdp* rdp, wStream* s)
{
	UINT16 lengthSourceDescriptor;
	UINT32 timeout;

	if (rdp->state == CONNECTION_STATE_ACTIVE)
		rdp->deactivation_reactivation = TRUE;
	else
		rdp->deactivation_reactivation = FALSE;

	/*
	 * Windows XP can send short DEACTIVATE_ALL PDU that doesn't contain
	 * the following fields.
	 */
	if (Stream_GetRemainingLength(s) > 0)
	{
		do
		{
			if (Stream_GetRemainingLength(s) < 4)
				break;

			Stream_Read_UINT32(s, rdp->settings->ShareId); /* shareId (4 bytes) */

			if (Stream_GetRemainingLength(s) < 2)
				break;

			Stream_Read_UINT16(s, lengthSourceDescriptor); /* lengthSourceDescriptor (2 bytes) */

			if (Stream_GetRemainingLength(s) < lengthSourceDescriptor)
				break;

			Stream_Seek(s, lengthSourceDescriptor); /* sourceDescriptor (should be 0x00) */
		} while (0);
	}

	rdp_client_transition_to_state(rdp, CONNECTION_STATE_CAPABILITIES_EXCHANGE);

	for (timeout = 0; timeout < rdp->settings->TcpAckTimeout; timeout += 100)
	{
		if (rdp_check_fds(rdp) < 0)
			return FALSE;

		if (freerdp_shall_disconnect(rdp->instance))
			return TRUE;

		if (rdp->state == CONNECTION_STATE_ACTIVE)
			return TRUE;

		Sleep(100);
	}

	WLog_ERR(TAG, "Timeout waiting for activation");
	return FALSE;
}

BOOL rdp_send_deactivate_all(rdpRdp* rdp)
{
	wStream* s = rdp_send_stream_pdu_init(rdp);
	BOOL status = FALSE;

	if (!s)
		return FALSE;

	if (Stream_GetRemainingCapacity(s) < 7)
		goto fail;
	Stream_Write_UINT32(s, rdp->settings->ShareId); /* shareId (4 bytes) */
	Stream_Write_UINT16(s, 1);                      /* lengthSourceDescriptor (2 bytes) */
	Stream_Write_UINT8(s, 0);                       /* sourceDescriptor (should be 0x00) */
	status = rdp_send_pdu(rdp, s, PDU_TYPE_DEACTIVATE_ALL, rdp->mcs->userId);
fail:
	Stream_Release(s);
	return status;
}

BOOL rdp_server_accept_client_control_pdu(rdpRdp* rdp, wStream* s)
{
	UINT16 action;

	if (!rdp_recv_control_pdu(s, &action))
		return FALSE;

	if (action == CTRLACTION_REQUEST_CONTROL)
	{
		if (!rdp_send_server_control_granted_pdu(rdp))
			return FALSE;
	}

	return TRUE;
}

BOOL rdp_server_accept_client_font_list_pdu(rdpRdp* rdp, wStream* s)
{
	rdpSettings* settings = rdp->settings;
	freerdp_peer* peer = rdp->context->peer;

	if (!rdp_recv_client_font_list_pdu(s))
		return FALSE;

	if (settings->SupportMonitorLayoutPdu && settings->MonitorCount && peer->AdjustMonitorsLayout &&
	    peer->AdjustMonitorsLayout(peer))
	{
		/* client supports the monitorLayout PDU, let's send him the monitors if any */
		MONITOR_DEF* monitors = (MONITOR_DEF*)calloc(settings->MonitorCount, sizeof(MONITOR_DEF));

		if (!monitors)
			return FALSE;

		if (!display_convert_rdp_monitor_to_monitor_def(settings->MonitorCount,
		                                                settings->MonitorDefArray, &monitors))
		{
			free(monitors);
			return FALSE;
		}

		if (!freerdp_display_send_monitor_layout(rdp->context, settings->MonitorCount, monitors))
		{
			free(monitors);
			return FALSE;
		}

		free(monitors);
	}

	if (!rdp_send_server_font_map_pdu(rdp))
		return FALSE;

	if (rdp_server_transition_to_state(rdp, CONNECTION_STATE_ACTIVE) < 0)
		return FALSE;

	return TRUE;
}

BOOL rdp_server_accept_client_persistent_key_list_pdu(rdpRdp* rdp, wStream* s)
{
	if (!rdp_recv_client_persistent_key_list_pdu(s))
		return FALSE;

	// TODO: Actually do something with this
	return TRUE;
}
