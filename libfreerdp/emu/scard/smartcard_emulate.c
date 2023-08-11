/**
 * WinPR: Windows Portable Runtime
 * Smart Card API emulation
 *
 * Copyright 2021 Armin Novak <armin.novak@thincast.com>
 * Copyright 2021 Thincast Technologies GmbH
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

#include <freerdp/config.h>

#include <winpr/crt.h>
#include <winpr/wlog.h>
#include <winpr/file.h>
#include <winpr/path.h>
#include <winpr/library.h>
#include <winpr/smartcard.h>
#include <winpr/collections.h>
#include <winpr/crypto.h>

#include <freerdp/emulate/scard/smartcard_emulate.h>
#include "FreeRDP.ico.h"

#include "smartcard_virtual_gids.h"

#define MAX_CACHE_ITEM_SIZE 4096
#define MAX_CACHE_ITEM_VALUES 4096

static CHAR g_ReaderNameA[] = { 'F', 'r', 'e', 'e', 'R', 'D', 'P', ' ',  'E',
	                            'm', 'u', 'l', 'a', 't', 'o', 'r', '\0', '\0' };
static WCHAR g_ReaderNameW[] = { 'F', 'r', 'e', 'e', 'R', 'D', 'P', ' ',  'E',
	                             'm', 'u', 'l', 'a', 't', 'o', 'r', '\0', '\0' };

struct smartcard_emulation_context
{
	const rdpSettings* settings;
	DWORD log_default_level;
	wLog* log;
	wHashTable* contexts;
	wHashTable* handles;
	BOOL configured;
	const char* pem;
	const char* key;
	const char* pin;
};

#define MAX_EMULATED_READERS 1
typedef struct
{
	ULONG readerState;
	SCARD_READERSTATEA readerStateA[MAX_EMULATED_READERS];
	SCARD_READERSTATEW readerStateW[MAX_EMULATED_READERS];
	wHashTable* cards;
	wArrayList* strings;
	wHashTable* cacheA;
	wHashTable* cacheW;
	BOOL canceled;
} SCardContext;

typedef struct
{
	union
	{
		void* pv;
		CHAR* pc;
		WCHAR* pw;
	} szReader;
	BOOL unicode;
	BOOL transaction;
	DWORD transmitcount;
	DWORD dwShareMode;
	DWORD dwActiveProtocol;
	SCARDCONTEXT hContext;
	SCARDHANDLE card;
	vgidsContext* vgids;
	size_t referencecount;
} SCardHandle;

typedef struct
{
	DWORD freshness;
	DWORD size;
	char data[MAX_CACHE_ITEM_SIZE];
} SCardCacheItem;

static SCardHandle* find_reader(SmartcardEmulationContext* smartcard, const void* szReader,
                                BOOL unicode);

static const BYTE ATR[] = { 0x3b, 0xf7, 0x18, 0x00, 0x00, 0x80, 0x31, 0xfe, 0x45,
	                        0x73, 0x66, 0x74, 0x65, 0x2d, 0x6e, 0x66, 0xc4 };

static BOOL scard_status_transition(SCardContext* context)
{
	WINPR_ASSERT(context);

	switch (context->readerState)
	{
		default:
		case 0:
		{
			SCARD_READERSTATEA* reader = &context->readerStateA[0];
			reader->szReader = g_ReaderNameA;
			reader->dwEventState = SCARD_STATE_PRESENT;
			reader->cbAtr = sizeof(ATR);
			memcpy(reader->rgbAtr, ATR, sizeof(ATR));
		}
			{
				SCARD_READERSTATEW* reader = &context->readerStateW[0];
				reader->szReader = g_ReaderNameW;
				reader->dwEventState = SCARD_STATE_PRESENT;
				reader->cbAtr = sizeof(ATR);
				memcpy(reader->rgbAtr, ATR, sizeof(ATR));
			}
			context->readerState = 42;
			break;
	}

	return TRUE;
}

static UINT32 scard_copy_strings(SCardContext* ctx, void* dst, UINT32 dstSize, const void* src,
                                 UINT32 srcSize)
{
	WINPR_ASSERT(ctx);
	WINPR_ASSERT(dst);

	if (dstSize == SCARD_AUTOALLOCATE)
	{
		void* tmp = malloc(srcSize);
		memcpy(tmp, src, srcSize);
		ArrayList_Append(ctx->strings, tmp);
		*((void**)dst) = tmp;
		return srcSize;
	}
	else
	{
		UINT32 min = MIN(dstSize, srcSize);
		memcpy(dst, src, min);
		return min;
	}
}

static void scard_context_free(void* context)
{
	SCardContext* ctx = context;
	if (ctx)
	{
		HashTable_Free(ctx->cards);
		ArrayList_Free(ctx->strings);
		HashTable_Free(ctx->cacheA);
		HashTable_Free(ctx->cacheW);
	}
	free(ctx);
}

static BOOL char_compare(const void* a, const void* b)
{
	const CHAR* wa = a;
	const CHAR* wb = b;

	if (!a && !b)
		return TRUE;
	if (!a || !b)
		return FALSE;
	return strcmp(wa, wb) == 0;
}

static BOOL wchar_compare(const void* a, const void* b)
{
	const WCHAR* wa = a;
	const WCHAR* wb = b;

	if (!a && !b)
		return TRUE;
	if (!a || !b)
		return FALSE;
	return _wcscmp(wa, wb) == 0;
}

static SCardContext* scard_context_new(void)
{
	SCardContext* ctx = calloc(1, sizeof(SCardContext));
	if (!ctx)
		return NULL;

	ctx->strings = ArrayList_New(FALSE);
	if (!ctx->strings)
		goto fail;
	else
	{
		wObject* obj = ArrayList_Object(ctx->strings);
		WINPR_ASSERT(obj);
		obj->fnObjectFree = free;
	}

	ctx->cacheA = HashTable_New(FALSE);
	if (!ctx->cacheA)
		goto fail;
	else
	{
		wObject* key = HashTable_KeyObject(ctx->cacheA);
		wObject* val = HashTable_ValueObject(ctx->cacheA);
		WINPR_ASSERT(key);
		WINPR_ASSERT(val);

		key->fnObjectEquals = char_compare;
		key->fnObjectNew = (OBJECT_NEW_FN)_strdup;
		key->fnObjectFree = free;

		val->fnObjectFree = free;
	}

	ctx->cacheW = HashTable_New(FALSE);
	if (!ctx->cacheW)
		goto fail;
	else
	{
		wObject* key = HashTable_KeyObject(ctx->cacheW);
		wObject* val = HashTable_ValueObject(ctx->cacheW);
		WINPR_ASSERT(key);
		WINPR_ASSERT(val);

		key->fnObjectEquals = wchar_compare;
		key->fnObjectNew = (OBJECT_NEW_FN)_wcsdup;
		key->fnObjectFree = free;

		val->fnObjectFree = free;
	}

	scard_status_transition(ctx);
	return ctx;
fail:
	scard_context_free(ctx);
	return NULL;
}

static void scard_handle_free(void* handle)
{
	SCardHandle* hdl = handle;
	if (hdl)
	{
		free(hdl->szReader.pv);
		vgids_free(hdl->vgids);
	}
	free(hdl);
}

static SCardHandle* scard_handle_new(SmartcardEmulationContext* smartcard, SCARDCONTEXT context,
                                     const void* name, BOOL unicode)
{
	SCardHandle* hdl;

	WINPR_ASSERT(smartcard);

	hdl = calloc(1, sizeof(SCardHandle));
	if (!hdl)
		goto fail;

	/* ATTENTION: Do not use _strdup or _wcsdup!
	 * These strings are required to be double NULL terminated!
	 */
	if (unicode)
	{
		size_t s = _wcslen(name);

		hdl->szReader.pw = calloc(s + 2, sizeof(WCHAR));
		if (!hdl->szReader.pw)
			goto fail;
		memcpy(hdl->szReader.pv, name, s * sizeof(WCHAR));
	}
	else
	{
		size_t s = strlen(name);

		hdl->szReader.pw = calloc(s + 2, sizeof(CHAR));
		if (!hdl->szReader.pw)
			goto fail;
		memcpy(hdl->szReader.pv, name, s * sizeof(CHAR));
	}

	if (!hdl->szReader.pv)
		goto fail;

	hdl->vgids = vgids_new();
	if (!hdl->vgids)
		goto fail;

	{
		const char* pem =
		    freerdp_settings_get_string(smartcard->settings, FreeRDP_SmartcardCertificate);
		const char* key =
		    freerdp_settings_get_string(smartcard->settings, FreeRDP_SmartcardPrivateKey);

		const char* pin = freerdp_settings_get_string(smartcard->settings, FreeRDP_Password);

		if (!vgids_init(hdl->vgids, pem, key, pin))
			goto fail;
	}

	hdl->unicode = unicode;
	hdl->hContext = context;
	return hdl;

fail:
	scard_handle_free(hdl);
	return NULL;
}

static LONG scard_handle_valid(SmartcardEmulationContext* smartcard, SCARDHANDLE handle)
{
	SCardHandle* ctx;

	WINPR_ASSERT(smartcard);

	ctx = HashTable_GetItemValue(smartcard->handles, (const void*)handle);
	if (!ctx)
		return SCARD_E_INVALID_HANDLE;

	return SCARD_S_SUCCESS;
}

static LONG scard_reader_name_valid_a(SmartcardEmulationContext* smartcard, SCARDCONTEXT context,
                                      const char* name)
{
	size_t x;
	SCardContext* ctx;

	WINPR_ASSERT(smartcard);
	ctx = HashTable_GetItemValue(smartcard->contexts, (const void*)context);

	WINPR_ASSERT(name);
	WINPR_ASSERT(ctx);

	for (x = 0; x < MAX_EMULATED_READERS; x++)
	{
		const SCARD_READERSTATEA* reader = &ctx->readerStateA[x];
		if (strcmp(reader->szReader, name) == 0)
			return SCARD_S_SUCCESS;
	}

	return SCARD_E_UNKNOWN_READER;
}

static LONG scard_reader_name_valid_w(SmartcardEmulationContext* smartcard, SCARDCONTEXT context,
                                      const WCHAR* name)
{
	size_t x;
	SCardContext* ctx;

	WINPR_ASSERT(smartcard);
	ctx = HashTable_GetItemValue(smartcard->contexts, (const void*)context);

	WINPR_ASSERT(name);
	WINPR_ASSERT(ctx);

	for (x = 0; x < MAX_EMULATED_READERS; x++)
	{
		const SCARD_READERSTATEW* reader = &ctx->readerStateW[x];
		if (_wcscmp(reader->szReader, name) == 0)
			return SCARD_S_SUCCESS;
	}

	return SCARD_E_UNKNOWN_READER;
}

/**
 * Standard Windows Smart Card API
 */

LONG WINAPI Emulate_SCardEstablishContext(SCARDAPICONTEXT hSCardApi, DWORD dwScope,
                                          LPCVOID pvReserved1, LPCVOID pvReserved2,
                                          LPSCARDCONTEXT phContext)
{
	LONG status = SCARD_E_NO_MEMORY;
	SCardContext* ctx;
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;

	WINPR_ASSERT(smartcard);

	ctx = scard_context_new();

	WINPR_UNUSED(pvReserved1);
	WINPR_UNUSED(pvReserved2);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardEstablishContext { dwScope: %s (0x%08" PRIX32 ")",
	           SCardGetScopeString(dwScope), dwScope);

	if (ctx)
	{
		SCARDCONTEXT context = { 0 };

		winpr_RAND(&context, sizeof(SCARDCONTEXT));
		if (HashTable_Insert(smartcard->contexts, (const void*)context, ctx))
		{
			*phContext = context;
			status = SCARD_S_SUCCESS;
		}
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardEstablishContext } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	if (status != SCARD_S_SUCCESS)
		scard_context_free(ctx);
	return status;
}

LONG WINAPI Emulate_SCardReleaseContext(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext)
{
	LONG status;
	SCardContext* value;
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;

	WINPR_ASSERT(smartcard);

	value = HashTable_GetItemValue(smartcard->contexts, (const void*)hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardReleaseContext { hContext: %p",
	           (void*)hContext);

	if (value)
		HashTable_Remove(smartcard->contexts, (const void*)hContext);

	status = SCARD_S_SUCCESS;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardReleaseContext } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardIsValidContext(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext)
{
	LONG status;
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;

	WINPR_ASSERT(smartcard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardIsValidContext { hContext: %p",
	           (void*)hContext);

	status = HashTable_Contains(smartcard->contexts, (const void*)hContext)
	             ? SCARD_S_SUCCESS
	             : SCARD_E_INVALID_HANDLE;
	if (status == SCARD_S_SUCCESS)
	{
		SCardContext* value = HashTable_GetItemValue(smartcard->contexts, (const void*)hContext);
		WINPR_ASSERT(value); /* Must be valid after Emulate_SCardIsValidContext */
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardIsValidContext } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardListReaderGroupsA(SCARDAPICONTEXT hSCardApi,
                                           SCARDCONTEXT hContext, LPSTR mszGroups,
                                           LPDWORD pcchGroups)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardListReaderGroupsA { hContext: %p", (void*)hContext);

	WINPR_UNUSED(mszGroups);
	WINPR_UNUSED(pcchGroups);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardListReaderGroupsA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardListReaderGroupsW(SCARDAPICONTEXT hSCardApi,
                                           SCARDCONTEXT hContext, LPWSTR mszGroups,
                                           LPDWORD pcchGroups)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardListReaderGroupsW { hContext: %p", (void*)hContext);

	WINPR_UNUSED(mszGroups);
	WINPR_UNUSED(pcchGroups);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardListReaderGroupsW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardListReadersA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                      LPCSTR mszGroups, LPSTR mszReaders, LPDWORD pcchReaders)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);
	if (!pcchReaders)
		status = SCARD_E_INVALID_PARAMETER;

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardListReadersA { hContext: %p",
	           (void*)hContext);

	WINPR_UNUSED(mszGroups); /* Not required */

	if (SCARD_S_SUCCESS == status)
	{
		SCardContext* value =
		    (SCardContext*)HashTable_GetItemValue(smartcard->contexts, (const void*)hContext);
		WINPR_ASSERT(value); /* Must be valid after Emulate_SCardIsValidContext */

		// TODO: If emulator not ready return SCARD_E_NO_READERS_AVAILABLE

		// TODO: argument mszGrous

		/* Return length only */
		if (!mszReaders)
			*pcchReaders = ARRAYSIZE(g_ReaderNameA);
		else
		{
			*pcchReaders = scard_copy_strings(value, mszReaders, *pcchReaders, g_ReaderNameA,
			                                  sizeof(g_ReaderNameA));
		}
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardListReadersA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardListReadersW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                      LPCWSTR mszGroups, LPWSTR mszReaders, LPDWORD pcchReaders)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (!pcchReaders)
		status = SCARD_E_INVALID_PARAMETER;

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardListReadersW { hContext: %p",
	           (void*)hContext);

	WINPR_UNUSED(mszGroups); /* Not required */

	if (SCARD_S_SUCCESS == status)
	{
		SCardContext* value = HashTable_GetItemValue(smartcard->contexts, (const void*)hContext);
		WINPR_ASSERT(value); /* Must be valid after Emulate_SCardIsValidContext */

		// TODO: If emulator not ready return SCARD_E_NO_READERS_AVAILABLE

		// TODO: argument mszGrous

		/* Return length only */
		if (!mszReaders)
			*pcchReaders = ARRAYSIZE(g_ReaderNameW);
		else
		{
			*pcchReaders = scard_copy_strings(value, mszReaders, *pcchReaders, g_ReaderNameW,
			                                  sizeof(g_ReaderNameW)) /
			               sizeof(WCHAR);
		}
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardListReadersW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardListCardsA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                    LPCBYTE pbAtr, LPCGUID rgquidInterfaces,
                                    DWORD cguidInterfaceCount, CHAR* mszCards, LPDWORD pcchCards)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardListCardsA { hContext: %p",
	           (void*)hContext);

	WINPR_UNUSED(pbAtr);
	WINPR_UNUSED(rgquidInterfaces);
	WINPR_UNUSED(cguidInterfaceCount);
	WINPR_UNUSED(mszCards);
	WINPR_UNUSED(pcchCards);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardListCardsA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardListCardsW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                    LPCBYTE pbAtr, LPCGUID rgquidInterfaces,
                                    DWORD cguidInterfaceCount, WCHAR* mszCards, LPDWORD pcchCards)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardListCardsW { hContext: %p",
	           (void*)hContext);

	WINPR_UNUSED(pbAtr);
	WINPR_UNUSED(rgquidInterfaces);
	WINPR_UNUSED(cguidInterfaceCount);
	WINPR_UNUSED(mszCards);
	WINPR_UNUSED(pcchCards);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardListCardsW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardListInterfacesA(SCARDAPICONTEXT hSCardApi,
                                         SCARDCONTEXT hContext, LPCSTR szCard,
                                         LPGUID pguidInterfaces, LPDWORD pcguidInterfaces)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardListInterfacesA { hContext: %p",
	           (void*)hContext);

	WINPR_UNUSED(szCard);
	WINPR_UNUSED(pguidInterfaces);
	WINPR_UNUSED(pcguidInterfaces);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardListInterfacesA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardListInterfacesW(SCARDAPICONTEXT hSCardApi,
                                         SCARDCONTEXT hContext, LPCWSTR szCard,
                                         LPGUID pguidInterfaces, LPDWORD pcguidInterfaces)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardListInterfacesW { hContext: %p",
	           (void*)hContext);

	WINPR_UNUSED(szCard);
	WINPR_UNUSED(pguidInterfaces);
	WINPR_UNUSED(pcguidInterfaces);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardListInterfacesW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardGetProviderIdA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                        LPCSTR szCard, LPGUID pguidProviderId)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardGetProviderIdA { hContext: %p",
	           (void*)hContext);

	WINPR_UNUSED(szCard);
	WINPR_UNUSED(pguidProviderId);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetProviderIdA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardGetProviderIdW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                        LPCWSTR szCard, LPGUID pguidProviderId)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardGetProviderIdW { hContext: %p",
	           (void*)hContext);

	WINPR_UNUSED(szCard);
	WINPR_UNUSED(pguidProviderId);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetProviderIdW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardGetCardTypeProviderNameA(SCARDAPICONTEXT hSCardApi,
                                                  SCARDCONTEXT hContext, LPCSTR szCardName,
                                                  DWORD dwProviderId, CHAR* szProvider,
                                                  LPDWORD pcchProvider)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetCardTypeProviderNameA { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szCardName);
	WINPR_UNUSED(dwProviderId);
	WINPR_UNUSED(szProvider);
	WINPR_UNUSED(pcchProvider);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetCardTypeProviderNameA } status: %s (0x%08" PRIX32 ")",
	           SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardGetCardTypeProviderNameW(SCARDAPICONTEXT hSCardApi,
                                                  SCARDCONTEXT hContext, LPCWSTR szCardName,
                                                  DWORD dwProviderId, WCHAR* szProvider,
                                                  LPDWORD pcchProvider)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetCardTypeProviderNameW { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szCardName);
	WINPR_UNUSED(dwProviderId);
	WINPR_UNUSED(szProvider);
	WINPR_UNUSED(pcchProvider);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetCardTypeProviderNameW } status: %s (0x%08" PRIX32 ")",
	           SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardIntroduceReaderGroupA(SCARDAPICONTEXT hSCardApi,
                                               SCARDCONTEXT hContext, LPCSTR szGroupName)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardIntroduceReaderGroupA { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szGroupName);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardIntroduceReaderGroupA } status: %s (0x%08" PRIX32 ")",
	           SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardIntroduceReaderGroupW(SCARDAPICONTEXT hSCardApi,
                                               SCARDCONTEXT hContext, LPCWSTR szGroupName)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardIntroduceReaderGroupW { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szGroupName);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardIntroduceReaderGroupW } status: %s (0x%08" PRIX32 ")",
	           SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardForgetReaderGroupA(SCARDAPICONTEXT hSCardApi,
                                            SCARDCONTEXT hContext, LPCSTR szGroupName)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardForgetReaderGroupA { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szGroupName);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardForgetReaderGroupA } status: %s (0x%08" PRIX32 ")",
	           SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardForgetReaderGroupW(SCARDAPICONTEXT hSCardApi,
                                            SCARDCONTEXT hContext, LPCWSTR szGroupName)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardForgetReaderGroupW { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szGroupName);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardForgetReaderGroupW } status: %s (0x%08" PRIX32 ")",
	           SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardIntroduceReaderA(SCARDAPICONTEXT hSCardApi,
                                          SCARDCONTEXT hContext, LPCSTR szReaderName,
                                          LPCSTR szDeviceName)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (status == SCARD_S_SUCCESS)
		status = scard_reader_name_valid_a(smartcard, hContext, szReaderName);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardIntroduceReaderA { hContext: %p",
	           (void*)hContext);

	WINPR_UNUSED(szDeviceName);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardIntroduceReaderA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardIntroduceReaderW(SCARDAPICONTEXT hSCardApi,
                                          SCARDCONTEXT hContext, LPCWSTR szReaderName,
                                          LPCWSTR szDeviceName)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (status == SCARD_S_SUCCESS)
		status = scard_reader_name_valid_w(smartcard, hContext, szReaderName);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardIntroduceReaderW { hContext: %p",
	           (void*)hContext);

	WINPR_UNUSED(szDeviceName);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardIntroduceReaderW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardForgetReaderA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                       LPCSTR szReaderName)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (status == SCARD_S_SUCCESS)
		status = scard_reader_name_valid_a(smartcard, hContext, szReaderName);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardForgetReaderA { hContext: %p",
	           (void*)hContext);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardForgetReaderA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardForgetReaderW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                       LPCWSTR szReaderName)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (status == SCARD_S_SUCCESS)
		status = scard_reader_name_valid_w(smartcard, hContext, szReaderName);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardForgetReaderW { hContext: %p",
	           (void*)hContext);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardForgetReaderW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardAddReaderToGroupA(SCARDAPICONTEXT hSCardApi,
                                           SCARDCONTEXT hContext, LPCSTR szReaderName,
                                           LPCSTR szGroupName)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (status == SCARD_S_SUCCESS)
		status = scard_reader_name_valid_a(smartcard, hContext, szReaderName);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardAddReaderToGroupA { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szGroupName);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardAddReaderToGroupA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardAddReaderToGroupW(SCARDAPICONTEXT hSCardApi,
                                           SCARDCONTEXT hContext, LPCWSTR szReaderName,
                                           LPCWSTR szGroupName)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (status == SCARD_S_SUCCESS)
		status = scard_reader_name_valid_w(smartcard, hContext, szReaderName);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardAddReaderToGroupW { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szGroupName);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardAddReaderToGroupW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardRemoveReaderFromGroupA(SCARDAPICONTEXT hSCardApi,
                                                SCARDCONTEXT hContext, LPCSTR szReaderName,
                                                LPCSTR szGroupName)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (status == SCARD_S_SUCCESS)
		status = scard_reader_name_valid_a(smartcard, hContext, szReaderName);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardRemoveReaderFromGroupA { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szGroupName);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardRemoveReaderFromGroupA } status: %s (0x%08" PRIX32 ")",
	           SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardRemoveReaderFromGroupW(SCARDAPICONTEXT hSCardApi,
                                                SCARDCONTEXT hContext, LPCWSTR szReaderName,
                                                LPCWSTR szGroupName)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (status == SCARD_S_SUCCESS)
		status = scard_reader_name_valid_w(smartcard, hContext, szReaderName);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardRemoveReaderFromGroupW { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szGroupName);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardRemoveReaderFromGroupW } status: %s (0x%08" PRIX32 ")",
	           SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardIntroduceCardTypeA(SCARDAPICONTEXT hSCardApi,
                                            SCARDCONTEXT hContext, LPCSTR szCardName,
                                            LPCGUID pguidPrimaryProvider, LPCGUID rgguidInterfaces,
                                            DWORD dwInterfaceCount, LPCBYTE pbAtr,
                                            LPCBYTE pbAtrMask, DWORD cbAtrLen)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardIntroduceCardTypeA { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szCardName);
	WINPR_UNUSED(pguidPrimaryProvider);
	WINPR_UNUSED(rgguidInterfaces);
	WINPR_UNUSED(dwInterfaceCount);
	WINPR_UNUSED(pbAtr);
	WINPR_UNUSED(pbAtrMask);
	WINPR_UNUSED(cbAtrLen);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardIntroduceCardTypeA } status: %s (0x%08" PRIX32 ")",
	           SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardIntroduceCardTypeW(SCARDAPICONTEXT hSCardApi,
                                            SCARDCONTEXT hContext, LPCWSTR szCardName,
                                            LPCGUID pguidPrimaryProvider, LPCGUID rgguidInterfaces,
                                            DWORD dwInterfaceCount, LPCBYTE pbAtr,
                                            LPCBYTE pbAtrMask, DWORD cbAtrLen)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardIntroduceCardTypeW { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szCardName);
	WINPR_UNUSED(pguidPrimaryProvider);
	WINPR_UNUSED(rgguidInterfaces);
	WINPR_UNUSED(dwInterfaceCount);
	WINPR_UNUSED(pbAtr);
	WINPR_UNUSED(pbAtrMask);
	WINPR_UNUSED(cbAtrLen);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardIntroduceCardTypeW } status: %s (0x%08" PRIX32 ")",
	           SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardSetCardTypeProviderNameA(SCARDAPICONTEXT hSCardApi,
                                                  SCARDCONTEXT hContext, LPCSTR szCardName,
                                                  DWORD dwProviderId, LPCSTR szProvider)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardSetCardTypeProviderNameA { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szCardName);
	WINPR_UNUSED(dwProviderId);
	WINPR_UNUSED(szProvider);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardSetCardTypeProviderNameA } status: %s (0x%08" PRIX32 ")",
	           SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardSetCardTypeProviderNameW(SCARDAPICONTEXT hSCardApi,
                                                  SCARDCONTEXT hContext, LPCWSTR szCardName,
                                                  DWORD dwProviderId, LPCWSTR szProvider)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardSetCardTypeProviderNameA { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szCardName);
	WINPR_UNUSED(dwProviderId);
	WINPR_UNUSED(szProvider);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardSetCardTypeProviderNameW } status: %s (0x%08" PRIX32 ")",
	           SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardForgetCardTypeA(SCARDAPICONTEXT hSCardApi,
                                         SCARDCONTEXT hContext, LPCSTR szCardName)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardForgetCardTypeA { hContext: %p",
	           (void*)hContext);

	WINPR_UNUSED(szCardName);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardForgetCardTypeA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardForgetCardTypeW(SCARDAPICONTEXT hSCardApi,
                                         SCARDCONTEXT hContext, LPCWSTR szCardName)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardForgetCardTypeW { hContext: %p",
	           (void*)hContext);

	WINPR_UNUSED(szCardName);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardForgetCardTypeW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardFreeMemory(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                    LPVOID pvMem)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardFreeMemory { hContext: %p",
	           (void*)hContext);

	if (status == SCARD_S_SUCCESS)
	{
		SCardContext* value = HashTable_GetItemValue(smartcard->contexts, (const void*)hContext);
		WINPR_ASSERT(value); /* Must be valid after Emulate_SCardIsValidContext */

		ArrayList_Remove(value->strings, pvMem);
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardFreeMemory } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

HANDLE WINAPI Emulate_SCardAccessStartedEvent(SCARDAPICONTEXT hSCardApi)
{
	HANDLE hEvent;
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;

	WINPR_ASSERT(smartcard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardAccessStartedEvent {");

	/* Not required, return random */
	winpr_RAND(&hEvent, sizeof(hEvent));

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardAccessStartedEvent } hEvent: %p",
	           hEvent);

	return hEvent;
}

void WINAPI Emulate_SCardReleaseStartedEvent(SCARDAPICONTEXT hSCardApi)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	WINPR_ASSERT(smartcard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardReleaseStartedEvent {");

	/* Not required, return not supported */

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardReleaseStartedEvent }");
}

LONG WINAPI Emulate_SCardLocateCardsA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                      LPCSTR mszCards, LPSCARD_READERSTATEA rgReaderStates,
                                      DWORD cReaders)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardLocateCardsA { hContext: %p",
	           (void*)hContext);

	WINPR_UNUSED(mszCards);
	WINPR_UNUSED(rgReaderStates);
	WINPR_UNUSED(cReaders);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardLocateCardsA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardLocateCardsW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                      LPCWSTR mszCards, LPSCARD_READERSTATEW rgReaderStates,
                                      DWORD cReaders)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardLocateCardsW { hContext: %p",
	           (void*)hContext);

	WINPR_UNUSED(mszCards);
	WINPR_UNUSED(rgReaderStates);
	WINPR_UNUSED(cReaders);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardLocateCardsW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardLocateCardsByATRA(SCARDAPICONTEXT hSCardApi,
                                           SCARDCONTEXT hContext, LPSCARD_ATRMASK rgAtrMasks,
                                           DWORD cAtrs, LPSCARD_READERSTATEA rgReaderStates,
                                           DWORD cReaders)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardLocateCardsByATRA { hContext: %p", (void*)hContext);

	WINPR_UNUSED(rgAtrMasks);
	WINPR_UNUSED(cAtrs);
	WINPR_UNUSED(rgReaderStates);
	WINPR_UNUSED(cReaders);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardLocateCardsByATRA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardLocateCardsByATRW(SCARDAPICONTEXT hSCardApi,
                                           SCARDCONTEXT hContext, LPSCARD_ATRMASK rgAtrMasks,
                                           DWORD cAtrs, LPSCARD_READERSTATEW rgReaderStates,
                                           DWORD cReaders)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardLocateCardsByATRW { hContext: %p", (void*)hContext);

	WINPR_UNUSED(rgAtrMasks);
	WINPR_UNUSED(cAtrs);
	WINPR_UNUSED(rgReaderStates);
	WINPR_UNUSED(cReaders);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardLocateCardsByATRW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardGetStatusChangeA(SCARDAPICONTEXT hSCardApi,
                                          SCARDCONTEXT hContext, DWORD dwTimeout,
                                          LPSCARD_READERSTATEA rgReaderStates, DWORD cReaders)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardGetStatusChangeA { hContext: %p",
	           (void*)hContext);

	if (dwTimeout == INFINITE)
		dwTimeout = 60000;

	if (status == SCARD_S_SUCCESS)
	{
		const DWORD diff = 100;
		size_t x;
		size_t eventCount = 0;
		SCardContext* value = HashTable_GetItemValue(smartcard->contexts, (const void*)hContext);
		WINPR_ASSERT(value); /* Must be valid after Emulate_SCardIsValidContext */

		status = SCARD_E_TIMEOUT;
		do
		{
			for (x = 0; x < cReaders; x++)
			{
				size_t y;
				LPSCARD_READERSTATEA out = &rgReaderStates[x];

				for (y = 0; y < MAX_EMULATED_READERS; y++)
				{
					const LPSCARD_READERSTATEA in = &value->readerStateA[y];
					if (strcmp(out->szReader, in->szReader) == 0)
					{
						const SCardHandle* hdl = find_reader(smartcard, in->szReader, FALSE);
						out->dwEventState = in->dwEventState;
						if (hdl)
						{
							out->dwEventState |= SCARD_STATE_INUSE;
							if (hdl->dwShareMode == SCARD_SHARE_EXCLUSIVE)
								out->dwEventState |= SCARD_STATE_EXCLUSIVE;
						}

						if ((out->dwEventState & SCARD_STATE_EMPTY) !=
						    (out->dwCurrentState & SCARD_STATE_EMPTY))
							out->dwEventState |= SCARD_STATE_CHANGED;
						if ((out->dwEventState & SCARD_STATE_PRESENT) !=
						    (out->dwCurrentState & SCARD_STATE_PRESENT))
							out->dwEventState |= SCARD_STATE_CHANGED;

						out->cbAtr = in->cbAtr;
						memcpy(out->rgbAtr, in->rgbAtr, out->cbAtr);
						if (out->dwEventState & SCARD_STATE_CHANGED)
							eventCount++;
					}
				}
			}
			if (value->canceled)
			{
				status = SCARD_E_CANCELLED;
				break;
			}
			if (eventCount != 0)
			{
				status = SCARD_S_SUCCESS;
				break;
			}
			Sleep(diff);
			dwTimeout -= MIN(dwTimeout, diff);
		} while (dwTimeout > 0);
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetStatusChangeA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardGetStatusChangeW(SCARDAPICONTEXT hSCardApi,
                                          SCARDCONTEXT hContext, DWORD dwTimeout,
                                          LPSCARD_READERSTATEW rgReaderStates, DWORD cReaders)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardGetStatusChangeW { hContext: %p",
	           (void*)hContext);

	if (dwTimeout == INFINITE)
		dwTimeout = 60000;

	if (status == SCARD_S_SUCCESS)
	{
		const DWORD diff = 100;
		size_t x;
		size_t eventCount = 0;
		SCardContext* value = HashTable_GetItemValue(smartcard->contexts, (const void*)hContext);
		WINPR_ASSERT(value); /* Must be valid after Emulate_SCardIsValidContext */

		status = SCARD_E_TIMEOUT;
		do
		{
			for (x = 0; x < cReaders; x++)
			{
				size_t y;
				LPSCARD_READERSTATEW out = &rgReaderStates[x];

				for (y = 0; y < MAX_EMULATED_READERS; y++)
				{
					const LPSCARD_READERSTATEW in = &value->readerStateW[y];
					if (_wcscmp(out->szReader, in->szReader) == 0)
					{
						const SCardHandle* hdl = find_reader(smartcard, in->szReader, TRUE);
						out->dwEventState = in->dwEventState;
						if (hdl)
						{
							out->dwEventState |= SCARD_STATE_INUSE;
							if (hdl->dwShareMode == SCARD_SHARE_EXCLUSIVE)
								out->dwEventState |= SCARD_STATE_EXCLUSIVE;
						}
						if ((out->dwEventState & SCARD_STATE_EMPTY) !=
						    (out->dwCurrentState & SCARD_STATE_EMPTY))
							out->dwEventState |= SCARD_STATE_CHANGED;
						if ((out->dwEventState & SCARD_STATE_PRESENT) !=
						    (out->dwCurrentState & SCARD_STATE_PRESENT))
							out->dwEventState |= SCARD_STATE_CHANGED;
						out->cbAtr = in->cbAtr;
						memcpy(out->rgbAtr, in->rgbAtr, out->cbAtr);

						if (out->dwEventState & SCARD_STATE_CHANGED)
							eventCount++;
					}
				}
			}
			if (value->canceled)
			{
				status = SCARD_E_CANCELLED;
				break;
			}
			if (eventCount != 0)
			{
				status = SCARD_S_SUCCESS;
				break;
			}
			Sleep(diff);
			dwTimeout -= MIN(dwTimeout, diff);
		} while (dwTimeout > 0);
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetStatusChangeW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardCancel(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardCancel { hContext: %p",
	           (void*)hContext);

	if (status == SCARD_S_SUCCESS)
	{
		SCardContext* value = HashTable_GetItemValue(smartcard->contexts, (const void*)hContext);
		WINPR_ASSERT(value);
		value->canceled = TRUE;
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardCancel } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status), status);

	return status;
}

SCardHandle* find_reader(SmartcardEmulationContext* smartcard, const void* szReader, BOOL unicode)
{
	SCardHandle* hdl = NULL;
	UINT_PTR* keys = NULL;
	size_t x, count;

	WINPR_ASSERT(smartcard);
	count = HashTable_GetKeys(smartcard->handles, &keys);
	for (x = 0; x < count; x++)
	{
		SCardHandle* cur = HashTable_GetItemValue(smartcard->handles, (const void*)keys[x]);
		WINPR_ASSERT(cur);

		if (cur->unicode != unicode)
			continue;
		if (!unicode && (strcmp(cur->szReader.pc, szReader) != 0))
			continue;
		if (unicode && (_wcscmp(cur->szReader.pw, szReader) != 0))
			continue;
		hdl = cur;
		break;
	}
	free(keys);
	return hdl;
}

static SCardHandle* reader2handle(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                  const void* szReader, BOOL unicode, DWORD dwShareMode,
                                  SCARDHANDLE* phCard, DWORD dwPreferredProtocols,
                                  LPDWORD pdwActiveProtocol)
{
	SCardHandle* hdl;
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;

	WINPR_ASSERT(phCard);

	*phCard = 0;
	if (Emulate_SCardIsValidContext(hSCardApi, hContext) != SCARD_S_SUCCESS)
		return NULL;

	hdl = scard_handle_new(smartcard, hContext, szReader, unicode);
	if (hdl)
	{
		winpr_RAND(&hdl->card, sizeof(hdl->card));
		hdl->dwActiveProtocol = SCARD_PROTOCOL_T1;
		hdl->dwShareMode = dwShareMode;

		if (!HashTable_Insert(smartcard->handles, (const void*)hdl->card, hdl))
		{
			scard_handle_free(hdl);
			hdl = NULL;
		}
		else
		{
			if (pdwActiveProtocol)
			{
				if ((hdl->dwActiveProtocol & dwPreferredProtocols) == 0)
				{
					scard_handle_free(hdl);
					hdl = NULL;
				}
				else
					*pdwActiveProtocol = hdl->dwActiveProtocol;
			}
			if (hdl)
			{
				hdl->referencecount++;
				*phCard = hdl->card;
			}
		}
	}
	WLog_Print(smartcard->log, smartcard->log_default_level, "{ %p }", (void*)*phCard);
	return hdl;
}

LONG WINAPI Emulate_SCardConnectA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                  LPCSTR szReader, DWORD dwShareMode, DWORD dwPreferredProtocols,
                                  LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (!phCard || !pdwActiveProtocol)
		status = SCARD_E_INVALID_PARAMETER;

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardConnectA { hContext: %p",
	           (void*)hContext);

	if (status == SCARD_S_SUCCESS)
	{
		if (!reader2handle(hSCardApi, hContext, szReader, FALSE, dwShareMode, phCard,
		                   dwPreferredProtocols, pdwActiveProtocol))
			status = SCARD_E_NO_MEMORY;
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardConnectA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardConnectW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                  LPCWSTR szReader, DWORD dwShareMode, DWORD dwPreferredProtocols,
                                  LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (!phCard || !pdwActiveProtocol)
		status = SCARD_E_INVALID_PARAMETER;

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardConnectW { hContext: %p",
	           (void*)hContext);

	if (status == SCARD_S_SUCCESS)
	{
		if (!reader2handle(hSCardApi, hContext, szReader, TRUE, dwShareMode, phCard,
		                   dwPreferredProtocols, pdwActiveProtocol))
			status = SCARD_E_NO_MEMORY;
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardConnectW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardReconnect(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard,
                                   DWORD dwShareMode, DWORD dwPreferredProtocols,
                                   DWORD dwInitialization, LPDWORD pdwActiveProtocol)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = scard_handle_valid(smartcard, hCard);

	if (!pdwActiveProtocol)
		status = SCARD_E_INVALID_PARAMETER;

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardReconnect { hCard: %p",
	           (void*)hCard);

	if (status == SCARD_S_SUCCESS)
	{
		SCardHandle* hdl = HashTable_GetItemValue(smartcard->handles, (const void*)hCard);
		WINPR_ASSERT(hdl);

		// TODO: Implement
		hdl->dwShareMode = dwShareMode;
		hdl->transaction = FALSE;

		*pdwActiveProtocol = hdl->dwActiveProtocol;
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardReconnect } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardDisconnect(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard,
                                    DWORD dwDisposition)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = scard_handle_valid(smartcard, hCard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardDisconnect { hCard: %p",
	           (void*)hCard);

	WINPR_UNUSED(dwDisposition); /* We just ignore this. All return values are static anyway */

	if (status == SCARD_S_SUCCESS)
	{
		SCardHandle* hdl = HashTable_GetItemValue(smartcard->handles, (const void*)hCard);
		WINPR_ASSERT(hdl);

		hdl->referencecount--;
		if (hdl->referencecount == 0)
			HashTable_Remove(smartcard->handles, (const void*)hCard);
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardDisconnect } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardBeginTransaction(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = scard_handle_valid(smartcard, hCard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardBeginTransaction { hCard: %p",
	           (void*)hCard);

	if (status == SCARD_S_SUCCESS)
	{
		SCardHandle* hdl = HashTable_GetItemValue(smartcard->handles, (const void*)hCard);
		WINPR_ASSERT(hdl);
		if (hdl->transaction)
			status = SCARD_E_INVALID_VALUE;
		else
			hdl->transaction = TRUE;
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardBeginTransaction } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardEndTransaction(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard,
                                        DWORD dwDisposition)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = scard_handle_valid(smartcard, hCard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardEndTransaction { hCard: %p",
	           (void*)hCard);

	WINPR_UNUSED(dwDisposition); /* We just ignore this. All return values are static anyway */

	if (status == SCARD_S_SUCCESS)
	{
		SCardHandle* hdl = HashTable_GetItemValue(smartcard->handles, (const void*)hCard);
		WINPR_ASSERT(hdl);
		if (!hdl->transaction)
			status = SCARD_E_NOT_TRANSACTED;
		else
			hdl->transaction = FALSE;
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardEndTransaction } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardCancelTransaction(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = scard_handle_valid(smartcard, hCard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardCancelTransaction { hCard: %p",
	           (void*)hCard);

	if (status == SCARD_S_SUCCESS)
	{
		SCardHandle* hdl = HashTable_GetItemValue(smartcard->handles, (const void*)hCard);
		WINPR_ASSERT(hdl);
		if (!hdl->transaction)
			status = SCARD_E_NOT_TRANSACTED;
		else
			hdl->transaction = FALSE;
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardCancelTransaction } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardState(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard,
                               LPDWORD pdwState, LPDWORD pdwProtocol, LPBYTE pbAtr,
                               LPDWORD pcbAtrLen)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = scard_handle_valid(smartcard, hCard);

	if (!pdwState || !pdwProtocol)
		status = SCARD_E_INVALID_PARAMETER;

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardState { hCard: %p",
	           (void*)hCard);

	if (status == SCARD_S_SUCCESS)
	{
		SCardHandle* hdl = HashTable_GetItemValue(smartcard->handles, (const void*)hCard);
		WINPR_ASSERT(hdl);

		if (pdwState)
			*pdwState = SCARD_SPECIFIC;
		if (pdwProtocol)
			*pdwProtocol = SCARD_PROTOCOL_T1;

		if (pcbAtrLen)
		{
			size_t x;
			SCardContext* ctx =
			    HashTable_GetItemValue(smartcard->contexts, (const void*)hdl->hContext);
			WINPR_ASSERT(ctx);

			for (x = 0; x < MAX_EMULATED_READERS; x++)
			{
				const SCARD_READERSTATEA* readerA = &ctx->readerStateA[x];
				const SCARD_READERSTATEW* readerW = &ctx->readerStateW[x];
				if (hdl->unicode)
				{
					if (_wcscmp(readerW->szReader, hdl->szReader.pw) == 0)
					{
						*pcbAtrLen = scard_copy_strings(ctx, pbAtr, *pcbAtrLen, readerW->rgbAtr,
						                                readerW->cbAtr);
					}
				}
				else
				{
					if (strcmp(readerA->szReader, hdl->szReader.pc) == 0)
					{
						*pcbAtrLen = scard_copy_strings(ctx, pbAtr, *pcbAtrLen, readerA->rgbAtr,
						                                readerA->cbAtr);
					}
				}
			}
		}
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardState } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardStatusA(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard,
                                 LPSTR mszReaderNames, LPDWORD pcchReaderLen, LPDWORD pdwState,
                                 LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = scard_handle_valid(smartcard, hCard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardStatusA { hCard: %p",
	           (void*)hCard);

	if (status == SCARD_S_SUCCESS)
	{
		SCardContext* ctx;
		SCardHandle* hdl = HashTable_GetItemValue(smartcard->handles, (const void*)hCard);
		WINPR_ASSERT(hdl);

		ctx = HashTable_GetItemValue(smartcard->contexts, (const void*)hdl->hContext);
		WINPR_ASSERT(ctx);

		if (pcchReaderLen)
			*pcchReaderLen =
			    scard_copy_strings(ctx, mszReaderNames, *pcchReaderLen, hdl->szReader.pc,
			                       (UINT32)strlen(hdl->szReader.pc) + 2);

		if (pdwState)
			*pdwState = SCARD_SPECIFIC;
		if (pdwProtocol)
			*pdwProtocol = SCARD_PROTOCOL_T1;

		if (pcbAtrLen)
		{
			size_t x;

			for (x = 0; x < MAX_EMULATED_READERS; x++)
			{
				const SCARD_READERSTATEA* reader = &ctx->readerStateA[x];
				if (strcmp(reader->szReader, hdl->szReader.pc) == 0)
				{
					*pcbAtrLen =
					    scard_copy_strings(ctx, pbAtr, *pcbAtrLen, reader->rgbAtr, reader->cbAtr);
				}
			}
		}
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardStatusA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardStatusW(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard,
                                 LPWSTR mszReaderNames, LPDWORD pcchReaderLen, LPDWORD pdwState,
                                 LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = scard_handle_valid(smartcard, hCard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardStatusW { hCard: %p",
	           (void*)hCard);

	if (status == SCARD_S_SUCCESS)
	{
		SCardContext* ctx;
		SCardHandle* hdl = HashTable_GetItemValue(smartcard->handles, (const void*)hCard);
		WINPR_ASSERT(hdl);

		ctx = HashTable_GetItemValue(smartcard->contexts, (const void*)hdl->hContext);
		WINPR_ASSERT(ctx);

		if (pcchReaderLen)
			*pcchReaderLen =
			    scard_copy_strings(ctx, mszReaderNames, *pcchReaderLen, hdl->szReader.pw,
			                       (UINT32)(_wcslen(hdl->szReader.pw) + 2) * sizeof(WCHAR)) /
			    sizeof(WCHAR);

		if (pdwState)
			*pdwState = SCARD_SPECIFIC;
		if (pdwProtocol)
			*pdwProtocol = SCARD_PROTOCOL_T1;

		if (pcbAtrLen)
		{
			size_t x;

			for (x = 0; x < MAX_EMULATED_READERS; x++)
			{
				const SCARD_READERSTATEW* reader = &ctx->readerStateW[x];
				if (_wcscmp(reader->szReader, hdl->szReader.pw) == 0)
					*pcbAtrLen =
					    scard_copy_strings(ctx, pbAtr, *pcbAtrLen, reader->rgbAtr, reader->cbAtr);
			}
		}
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardStatusW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardTransmit(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard,
                                  LPCSCARD_IO_REQUEST pioSendPci, LPCBYTE pbSendBuffer,
                                  DWORD cbSendLength, LPSCARD_IO_REQUEST pioRecvPci,
                                  LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = scard_handle_valid(smartcard, hCard);

	if (!pioSendPci || !pbSendBuffer || !pbRecvBuffer || !pcbRecvLength)
		status = SCARD_E_INVALID_PARAMETER;

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardTransmit { hCard: %p",
	           (void*)hCard);

	if (status == SCARD_S_SUCCESS)
	{
		BYTE* response = NULL;
		DWORD responseSize = 0;
		SCardHandle* hdl = HashTable_GetItemValue(smartcard->handles, (const void*)hCard);
		WINPR_ASSERT(hdl);

		hdl->transmitcount++;

		if (!vgids_process_apdu(hdl->vgids, pbSendBuffer, cbSendLength, &response, &responseSize))
			status = SCARD_E_NO_SMARTCARD;
		else
		{
			SCardContext* ctx =
			    HashTable_GetItemValue(smartcard->contexts, (const void*)hdl->hContext);
			WINPR_ASSERT(ctx);

			*pcbRecvLength =
			    scard_copy_strings(ctx, pbRecvBuffer, *pcbRecvLength, response, responseSize);
			free(response);

			/* Required */
			if (pioRecvPci)
				pioRecvPci->dwProtocol = hdl->dwActiveProtocol;
		}
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardTransmit } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardGetTransmitCount(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard,
                                          LPDWORD pcTransmitCount)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = scard_handle_valid(smartcard, hCard);

	if (!pcTransmitCount)
		status = SCARD_E_INVALID_PARAMETER;

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardGetTransmitCount { hCard: %p",
	           (void*)hCard);

	if (status == SCARD_S_SUCCESS)
	{
		SCardHandle* hdl = HashTable_GetItemValue(smartcard->handles, (const void*)hCard);
		WINPR_ASSERT(hdl);

		*pcTransmitCount = hdl->transmitcount;
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetTransmitCount } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardControl(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard,
                                 DWORD dwControlCode, LPCVOID lpInBuffer, DWORD cbInBufferSize,
                                 LPVOID lpOutBuffer, DWORD cbOutBufferSize, LPDWORD lpBytesReturned)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = scard_handle_valid(smartcard, hCard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardControl { hCard: %p",
	           (void*)hCard);

	if (status == SCARD_S_SUCCESS)
	{
		WINPR_UNUSED(dwControlCode);
		WINPR_UNUSED(lpInBuffer);
		WINPR_UNUSED(cbInBufferSize);
		WINPR_UNUSED(lpOutBuffer);
		WINPR_UNUSED(cbOutBufferSize);
		WINPR_UNUSED(lpBytesReturned);

		/* Not required, return not supported */
		status = SCARD_E_UNSUPPORTED_FEATURE;
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardControl } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardGetAttrib(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard,
                                   DWORD dwAttrId, LPBYTE pbAttr, LPDWORD pcbAttrLen)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = scard_handle_valid(smartcard, hCard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardGetAttrib { hCard: %p",
	           (void*)hCard);

	WINPR_UNUSED(dwAttrId);
	WINPR_UNUSED(pbAttr);
	WINPR_UNUSED(pcbAttrLen);

	/* Not required, return not supported */
	status = SCARD_F_INTERNAL_ERROR;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetAttrib } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardSetAttrib(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard,
                                   DWORD dwAttrId, LPCBYTE pbAttr, DWORD cbAttrLen)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = scard_handle_valid(smartcard, hCard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardSetAttrib { hCard: %p",
	           (void*)hCard);

	WINPR_UNUSED(dwAttrId);
	WINPR_UNUSED(pbAttr);
	WINPR_UNUSED(cbAttrLen);

	/* Not required, return not supported */
	status = SCARD_F_INTERNAL_ERROR;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardSetAttrib } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardUIDlgSelectCardA(SCARDAPICONTEXT hSCardApi,
                                          LPOPENCARDNAMEA_EX pDlgStruc)
{
	LONG status;
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;

	WINPR_ASSERT(smartcard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardUIDlgSelectCardA {");

	WINPR_UNUSED(pDlgStruc);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardUIDlgSelectCardA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardUIDlgSelectCardW(SCARDAPICONTEXT hSCardApi,
                                          LPOPENCARDNAMEW_EX pDlgStruc)
{
	LONG status;
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;

	WINPR_ASSERT(smartcard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardUIDlgSelectCardW {");

	WINPR_UNUSED(pDlgStruc);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardUIDlgSelectCardW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_GetOpenCardNameA(SCARDAPICONTEXT hSCardApi,
                                     LPOPENCARDNAMEA pDlgStruc)
{
	LONG status;
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;

	WINPR_ASSERT(smartcard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "GetOpenCardNameA {");

	WINPR_UNUSED(pDlgStruc);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "GetOpenCardNameA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_GetOpenCardNameW(SCARDAPICONTEXT hSCardApi,
                                     LPOPENCARDNAMEW pDlgStruc)
{
	LONG status;
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;

	WINPR_ASSERT(smartcard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "GetOpenCardNameW {");

	WINPR_UNUSED(pDlgStruc);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "GetOpenCardNameW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardDlgExtendedError(SCARDAPICONTEXT hSCardApi)
{
	LONG status;
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;

	WINPR_ASSERT(smartcard);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardDlgExtendedError {");

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardDlgExtendedError } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardReadCacheA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                    UUID* CardIdentifier, DWORD FreshnessCounter, LPSTR LookupName,
                                    PBYTE Data, DWORD* DataLen)
{
	DWORD count = 0;
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (!CardIdentifier || !DataLen)
		status = SCARD_E_INVALID_PARAMETER;

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardReadCacheA { hContext: %p",
	           (void*)hContext);

	if (DataLen)
	{
		count = *DataLen;
		*DataLen = 0;
	}

	if (status == SCARD_S_SUCCESS)
	{
		SCardCacheItem* data;
		SCardContext* value = HashTable_GetItemValue(smartcard->contexts, (const void*)hContext);
		WINPR_ASSERT(value); /* Must be valid after Emulate_SCardIsValidContext */

		data = HashTable_GetItemValue(value->cacheA, LookupName);
		if (!data)
			status = SCARD_W_CACHE_ITEM_NOT_FOUND;
		else if (data->freshness != FreshnessCounter)
			status = SCARD_W_CACHE_ITEM_STALE;
		else
			*DataLen = scard_copy_strings(value, Data, count, data->data, data->size);
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardReadCacheA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardReadCacheW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                    UUID* CardIdentifier, DWORD FreshnessCounter, LPWSTR LookupName,
                                    PBYTE Data, DWORD* DataLen)
{
	DWORD count = 0;
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (!CardIdentifier || !DataLen)
		status = SCARD_E_INVALID_PARAMETER;

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardReadCacheW { hContext: %p",
	           (void*)hContext);

	if (DataLen)
	{
		count = *DataLen;
		*DataLen = 0;
	}

	if (status == SCARD_S_SUCCESS)
	{
		SCardCacheItem* data;
		SCardContext* value = HashTable_GetItemValue(smartcard->contexts, (const void*)hContext);
		WINPR_ASSERT(value); /* Must be valid after Emulate_SCardIsValidContext */

		data = HashTable_GetItemValue(value->cacheW, LookupName);
		if (!data)
			status = SCARD_W_CACHE_ITEM_NOT_FOUND;
		else if (data->freshness != FreshnessCounter)
			status = SCARD_W_CACHE_ITEM_STALE;
		else
			*DataLen = scard_copy_strings(value, Data, count, data->data, data->size);
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardReadCacheW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

static BOOL insert_data(wHashTable* table, DWORD FreshnessCounter, const void* key,
                        const PBYTE Data, DWORD DataLen)
{
	BOOL rc;
	SCardCacheItem* item;

	WINPR_ASSERT(table);
	WINPR_ASSERT(key);

	if (DataLen > MAX_CACHE_ITEM_SIZE)
		return SCARD_W_CACHE_ITEM_TOO_BIG;

	if (HashTable_Count(table) > MAX_CACHE_ITEM_VALUES)
		return SCARD_E_WRITE_TOO_MANY;

	item = HashTable_GetItemValue(table, key);
	if (!item)
	{
		item = calloc(1, sizeof(SCardCacheItem));
		if (!item)
			return SCARD_E_NO_MEMORY;

		rc = HashTable_Insert(table, key, item);
		if (!rc)
		{
			free(item);
			return SCARD_E_NO_MEMORY;
		}
	}

	if (item->freshness > FreshnessCounter)
		return SCARD_W_CACHE_ITEM_STALE;
	item->freshness = FreshnessCounter;
	item->size = DataLen;
	memcpy(item->data, Data, DataLen);
	return SCARD_S_SUCCESS;
}

LONG WINAPI Emulate_SCardWriteCacheA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                     UUID* CardIdentifier, DWORD FreshnessCounter, LPSTR LookupName,
                                     PBYTE Data, DWORD DataLen)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (!CardIdentifier)
		status = SCARD_E_INVALID_PARAMETER;

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardWriteCacheA { hContext: %p",
	           (void*)hContext);

	if (status == SCARD_S_SUCCESS)
	{
		SCardContext* value = HashTable_GetItemValue(smartcard->contexts, (const void*)hContext);
		WINPR_ASSERT(value); /* Must be valid after Emulate_SCardIsValidContext */

		status = insert_data(value->cacheA, FreshnessCounter, LookupName, Data, DataLen);
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardWriteCacheA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardWriteCacheW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                     UUID* CardIdentifier, DWORD FreshnessCounter,
                                     LPWSTR LookupName, PBYTE Data, DWORD DataLen)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (!CardIdentifier)
		status = SCARD_E_INVALID_PARAMETER;

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardWriteCacheW { hContext: %p",
	           (void*)hContext);

	if (status == SCARD_S_SUCCESS)
	{
		SCardContext* value = HashTable_GetItemValue(smartcard->contexts, (const void*)hContext);
		WINPR_ASSERT(value); /* Must be valid after Emulate_SCardIsValidContext */

		status = insert_data(value->cacheW, FreshnessCounter, LookupName, Data, DataLen);
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardWriteCacheW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardGetReaderIconA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                        LPCSTR szReaderName, LPBYTE pbIcon, LPDWORD pcbIcon)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (!szReaderName || !pcbIcon)
		status = SCARD_E_INVALID_PARAMETER;

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardGetReaderIconA { hContext: %p",
	           (void*)hContext);

	if (status == SCARD_S_SUCCESS)
		status = scard_reader_name_valid_a(smartcard, hContext, szReaderName);

	if (status == SCARD_S_SUCCESS)
	{
		SCardContext* ctx = HashTable_GetItemValue(smartcard->contexts, (const void*)hContext);
		WINPR_ASSERT(ctx);

		if (pbIcon)
			*pcbIcon = scard_copy_strings(ctx, pbIcon, *pcbIcon, resources_FreeRDP_ico,
			                              resources_FreeRDP_ico_len);
		else
			*pcbIcon = resources_FreeRDP_ico_len;
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetReaderIconA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardGetReaderIconW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                        LPCWSTR szReaderName, LPBYTE pbIcon, LPDWORD pcbIcon)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (!szReaderName || !pcbIcon)
		status = SCARD_E_INVALID_PARAMETER;

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardGetReaderIconW { hContext: %p",
	           (void*)hContext);

	if (status == SCARD_S_SUCCESS)
		status = scard_reader_name_valid_w(smartcard, hContext, szReaderName);

	if (status == SCARD_S_SUCCESS)
	{
		SCardContext* ctx = HashTable_GetItemValue(smartcard->contexts, (const void*)hContext);
		WINPR_ASSERT(ctx);

		if (pbIcon)
			*pcbIcon = scard_copy_strings(ctx, pbIcon, *pcbIcon, resources_FreeRDP_ico,
			                              resources_FreeRDP_ico_len);
		else
			*pcbIcon = resources_FreeRDP_ico_len;
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetReaderIconW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardGetDeviceTypeIdA(SCARDAPICONTEXT hSCardApi,
                                          SCARDCONTEXT hContext, LPCSTR szReaderName,
                                          LPDWORD pdwDeviceTypeId)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (!pdwDeviceTypeId)
		status = SCARD_E_INVALID_PARAMETER;

	if (status == SCARD_S_SUCCESS)
		status = scard_reader_name_valid_a(smartcard, hContext, szReaderName);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardGetDeviceTypeIdA { hContext: %p",
	           (void*)hContext);

	if (status == SCARD_S_SUCCESS)
	{
		*pdwDeviceTypeId = SCARD_READER_TYPE_USB; // SCARD_READER_TYPE_TPM
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetDeviceTypeIdA } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardGetDeviceTypeIdW(SCARDAPICONTEXT hSCardApi,
                                          SCARDCONTEXT hContext, LPCWSTR szReaderName,
                                          LPDWORD pdwDeviceTypeId)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (!pdwDeviceTypeId)
		status = SCARD_E_INVALID_PARAMETER;

	if (status == SCARD_S_SUCCESS)
		status = scard_reader_name_valid_w(smartcard, hContext, szReaderName);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardGetDeviceTypeIdW { hContext: %p",
	           (void*)hContext);

	if (status == SCARD_S_SUCCESS)
	{
		*pdwDeviceTypeId = SCARD_READER_TYPE_USB; // SCARD_READER_TYPE_TPM
	}

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetDeviceTypeIdW } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status),
	           status);

	return status;
}

LONG WINAPI Emulate_SCardGetReaderDeviceInstanceIdA(SCARDAPICONTEXT hSCardApi,
                                                    SCARDCONTEXT hContext, LPCSTR szReaderName,
                                                    LPSTR szDeviceInstanceId,
                                                    LPDWORD pcchDeviceInstanceId)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (status == SCARD_S_SUCCESS)
		status = scard_reader_name_valid_a(smartcard, hContext, szReaderName);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetReaderDeviceInstanceIdA { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szDeviceInstanceId);
	WINPR_UNUSED(pcchDeviceInstanceId);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetReaderDeviceInstanceIdA } status: %s (0x%08" PRIX32 ")",
	           SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardGetReaderDeviceInstanceIdW(SCARDAPICONTEXT hSCardApi,
                                                    SCARDCONTEXT hContext, LPCWSTR szReaderName,
                                                    LPWSTR szDeviceInstanceId,
                                                    LPDWORD pcchDeviceInstanceId)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	if (status == SCARD_S_SUCCESS)
		status = scard_reader_name_valid_w(smartcard, hContext, szReaderName);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetReaderDeviceInstanceIdW { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szDeviceInstanceId);
	WINPR_UNUSED(pcchDeviceInstanceId);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardGetReaderDeviceInstanceIdW } status: %s (0x%08" PRIX32 ")",
	           SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardListReadersWithDeviceInstanceIdA(SCARDAPICONTEXT hSCardApi,
                                                          SCARDCONTEXT hContext,
                                                          LPCSTR szDeviceInstanceId,
                                                          LPSTR mszReaders, LPDWORD pcchReaders)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardListReadersWithDeviceInstanceIdA { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szDeviceInstanceId);
	WINPR_UNUSED(mszReaders);
	WINPR_UNUSED(pcchReaders);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardListReadersWithDeviceInstanceIdA } status: %s (0x%08" PRIX32 ")",
	           SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardListReadersWithDeviceInstanceIdW(SCARDAPICONTEXT hSCardApi,
                                                          SCARDCONTEXT hContext,
                                                          LPCWSTR szDeviceInstanceId,
                                                          LPWSTR mszReaders, LPDWORD pcchReaders)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardListReadersWithDeviceInstanceIdW { hContext: %p", (void*)hContext);

	WINPR_UNUSED(szDeviceInstanceId);
	WINPR_UNUSED(mszReaders);
	WINPR_UNUSED(pcchReaders);

	/* Not required, return not supported */
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardListReadersWithDeviceInstanceIdW } status: %s (0x%08" PRIX32 ")",
	           SCardGetErrorString(status), status);

	return status;
}

LONG WINAPI Emulate_SCardAudit(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                               DWORD dwEvent)
{
    SmartcardEmulationContext* smartcard = (SmartcardEmulationContext*) hSCardApi;
	LONG status = Emulate_SCardIsValidContext(hSCardApi, hContext);

	WINPR_UNUSED(dwEvent);

	WLog_Print(smartcard->log, smartcard->log_default_level, "SCardAudit { hContext: %p",
	           (void*)hContext);

	// TODO: Implement
	status = SCARD_E_UNSUPPORTED_FEATURE;

	WLog_Print(smartcard->log, smartcard->log_default_level,
	           "SCardAudit } status: %s (0x%08" PRIX32 ")", SCardGetErrorString(status), status);

	return status;
}

static BOOL context_equals(const void* pva, const void* pvb)
{
	const SCARDCONTEXT a = (const SCARDCONTEXT)pva;
	const SCARDCONTEXT b = (const SCARDCONTEXT)pvb;
	if (!a && !b)
		return TRUE;
	if (!a || !b)
		return FALSE;

	return a == b;
}

static BOOL handle_equals(const void* pva, const void* pvb)
{
	const SCARDHANDLE a = (const SCARDHANDLE)pva;
	const SCARDHANDLE b = (const SCARDHANDLE)pvb;
	if (!a && !b)
		return TRUE;
	if (!a || !b)
		return FALSE;

	return a == b;
}

SmartcardEmulationContext* Emulate_New(const rdpSettings* settings)
{
	SmartcardEmulationContext* smartcard;

	WINPR_ASSERT(settings);

	smartcard = calloc(1, sizeof(SmartcardEmulationContext));
	if (!smartcard)
		goto fail;

	smartcard->settings = settings;
	smartcard->log = WLog_Get("EmulateSCard");
	if (!smartcard->log)
		goto fail;
	smartcard->log_default_level = WLOG_TRACE;

	smartcard->contexts = HashTable_New(FALSE);
	if (!smartcard->contexts)
		goto fail;
	else
	{
		wObject* obj = HashTable_KeyObject(smartcard->contexts);
		WINPR_ASSERT(obj);
		obj->fnObjectEquals = context_equals;
	}
	if (!smartcard->contexts)
		goto fail;
	else
	{
		wObject* obj = HashTable_ValueObject(smartcard->contexts);
		WINPR_ASSERT(obj);
		obj->fnObjectFree = scard_context_free;
	}

	smartcard->handles = HashTable_New(FALSE);
	if (!smartcard->handles)
		goto fail;
	else
	{
		wObject* obj = HashTable_KeyObject(smartcard->handles);
		WINPR_ASSERT(obj);
		obj->fnObjectEquals = handle_equals;
	}
	if (!smartcard->handles)
		goto fail;
	else
	{
		wObject* obj = HashTable_ValueObject(smartcard->handles);
		WINPR_ASSERT(obj);
		obj->fnObjectFree = scard_handle_free;
	}

	return smartcard;

fail:
	Emulate_Free(smartcard);
	return NULL;
}

void Emulate_Free(SmartcardEmulationContext* context)
{
	if (!context)
		return;

	HashTable_Free(context->handles);
	HashTable_Free(context->contexts);
	free(context);
}

BOOL Emulate_IsConfigured(SmartcardEmulationContext* context)
{
	BOOL rc = FALSE;
	vgidsContext* vgids;
	const char* pem = NULL;
	const char* key = NULL;
	const char* pin = NULL;

	WINPR_ASSERT(context);

	pem = freerdp_settings_get_string(context->settings, FreeRDP_SmartcardCertificate);
	key = freerdp_settings_get_string(context->settings, FreeRDP_SmartcardPrivateKey);
	pin = freerdp_settings_get_string(context->settings, FreeRDP_Password);

	/* Cache result only, if no initialization arguments changed. */
	if ((context->pem == pem) && (context->key == key) && (context->pin == pin))
		return context->configured;

	context->pem = pem;
	context->key = key;
	context->pin = pin;

	vgids = vgids_new();
	if (vgids)
		rc = vgids_init(vgids, context->pem, context->key, context->pin);
	vgids_free(vgids);

	context->configured = rc;
	return rc;
}

static const SCardApiFunctionTableEx Emulate_SCardApiFunctionTableEx = {
	0, /* dwVersion */
	0, /* dwFlags */

	Emulate_SCardEstablishContext,                 /* SCardEstablishContext */
	Emulate_SCardReleaseContext,                   /* SCardReleaseContext */
	Emulate_SCardIsValidContext,                   /* SCardIsValidContext */
	Emulate_SCardListReaderGroupsA,                /* SCardListReaderGroupsA */
	Emulate_SCardListReaderGroupsW,                /* SCardListReaderGroupsW */
	Emulate_SCardListReadersA,                     /* SCardListReadersA */
	Emulate_SCardListReadersW,                     /* SCardListReadersW */
	Emulate_SCardListCardsA,                       /* SCardListCardsA */
	Emulate_SCardListCardsW,                       /* SCardListCardsW */
	Emulate_SCardListInterfacesA,                  /* SCardListInterfacesA */
	Emulate_SCardListInterfacesW,                  /* SCardListInterfacesW */
	Emulate_SCardGetProviderIdA,                   /* SCardGetProviderIdA */
	Emulate_SCardGetProviderIdW,                   /* SCardGetProviderIdW */
	Emulate_SCardGetCardTypeProviderNameA,         /* SCardGetCardTypeProviderNameA */
	Emulate_SCardGetCardTypeProviderNameW,         /* SCardGetCardTypeProviderNameW */
	Emulate_SCardIntroduceReaderGroupA,            /* SCardIntroduceReaderGroupA */
	Emulate_SCardIntroduceReaderGroupW,            /* SCardIntroduceReaderGroupW */
	Emulate_SCardForgetReaderGroupA,               /* SCardForgetReaderGroupA */
	Emulate_SCardForgetReaderGroupW,               /* SCardForgetReaderGroupW */
	Emulate_SCardIntroduceReaderA,                 /* SCardIntroduceReaderA */
	Emulate_SCardIntroduceReaderW,                 /* SCardIntroduceReaderW */
	Emulate_SCardForgetReaderA,                    /* SCardForgetReaderA */
	Emulate_SCardForgetReaderW,                    /* SCardForgetReaderW */
	Emulate_SCardAddReaderToGroupA,                /* SCardAddReaderToGroupA */
	Emulate_SCardAddReaderToGroupW,                /* SCardAddReaderToGroupW */
	Emulate_SCardRemoveReaderFromGroupA,           /* SCardRemoveReaderFromGroupA */
	Emulate_SCardRemoveReaderFromGroupW,           /* SCardRemoveReaderFromGroupW */
	Emulate_SCardIntroduceCardTypeA,               /* SCardIntroduceCardTypeA */
	Emulate_SCardIntroduceCardTypeW,               /* SCardIntroduceCardTypeW */
	Emulate_SCardSetCardTypeProviderNameA,         /* SCardSetCardTypeProviderNameA */
	Emulate_SCardSetCardTypeProviderNameW,         /* SCardSetCardTypeProviderNameW */
	Emulate_SCardForgetCardTypeA,                  /* SCardForgetCardTypeA */
	Emulate_SCardForgetCardTypeW,                  /* SCardForgetCardTypeW */
	Emulate_SCardFreeMemory,                       /* SCardFreeMemory */
	Emulate_SCardAccessStartedEvent,               /* SCardAccessStartedEvent */
	Emulate_SCardReleaseStartedEvent,              /* SCardReleaseStartedEvent */
	Emulate_SCardLocateCardsA,                     /* SCardLocateCardsA */
	Emulate_SCardLocateCardsW,                     /* SCardLocateCardsW */
	Emulate_SCardLocateCardsByATRA,                /* SCardLocateCardsByATRA */
	Emulate_SCardLocateCardsByATRW,                /* SCardLocateCardsByATRW */
	Emulate_SCardGetStatusChangeA,                 /* SCardGetStatusChangeA */
	Emulate_SCardGetStatusChangeW,                 /* SCardGetStatusChangeW */
	Emulate_SCardCancel,                           /* SCardCancel */
	Emulate_SCardConnectA,                         /* SCardConnectA */
	Emulate_SCardConnectW,                         /* SCardConnectW */
	Emulate_SCardReconnect,                        /* SCardReconnect */
	Emulate_SCardDisconnect,                       /* SCardDisconnect */
	Emulate_SCardBeginTransaction,                 /* SCardBeginTransaction */
	Emulate_SCardEndTransaction,                   /* SCardEndTransaction */
	Emulate_SCardCancelTransaction,                /* SCardCancelTransaction */
	Emulate_SCardState,                            /* SCardState */
	Emulate_SCardStatusA,                          /* SCardStatusA */
	Emulate_SCardStatusW,                          /* SCardStatusW */
	Emulate_SCardTransmit,                         /* SCardTransmit */
	Emulate_SCardGetTransmitCount,                 /* SCardGetTransmitCount */
	Emulate_SCardControl,                          /* SCardControl */
	Emulate_SCardGetAttrib,                        /* SCardGetAttrib */
	Emulate_SCardSetAttrib,                        /* SCardSetAttrib */
	Emulate_SCardUIDlgSelectCardA,                 /* SCardUIDlgSelectCardA */
	Emulate_SCardUIDlgSelectCardW,                 /* SCardUIDlgSelectCardW */
	Emulate_GetOpenCardNameA,                      /* GetOpenCardNameA */
	Emulate_GetOpenCardNameW,                      /* GetOpenCardNameW */
	Emulate_SCardDlgExtendedError,                 /* SCardDlgExtendedError */
	Emulate_SCardReadCacheA,                       /* SCardReadCacheA */
	Emulate_SCardReadCacheW,                       /* SCardReadCacheW */
	Emulate_SCardWriteCacheA,                      /* SCardWriteCacheA */
	Emulate_SCardWriteCacheW,                      /* SCardWriteCacheW */
	Emulate_SCardGetReaderIconA,                   /* SCardGetReaderIconA */
	Emulate_SCardGetReaderIconW,                   /* SCardGetReaderIconW */
	Emulate_SCardGetDeviceTypeIdA,                 /* SCardGetDeviceTypeIdA */
	Emulate_SCardGetDeviceTypeIdW,                 /* SCardGetDeviceTypeIdW */
	Emulate_SCardGetReaderDeviceInstanceIdA,       /* SCardGetReaderDeviceInstanceIdA */
	Emulate_SCardGetReaderDeviceInstanceIdW,       /* SCardGetReaderDeviceInstanceIdW */
	Emulate_SCardListReadersWithDeviceInstanceIdA, /* SCardListReadersWithDeviceInstanceIdA */
	Emulate_SCardListReadersWithDeviceInstanceIdW, /* SCardListReadersWithDeviceInstanceIdW */
	Emulate_SCardAudit                             /* SCardAudit */
};

const SCardApiFunctionTableEx* Emulate_GetSCardApiFunctionTableEx(void)
{
	return &Emulate_GetSCardApiFunctionTableEx;
}
