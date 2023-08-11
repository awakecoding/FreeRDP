/**
 * WinPR: Windows Portable Runtime
 * Smart Card Extended API
 *
 * Copyright 2022 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#include <winpr/config.h>

#include <winpr/crt.h>
#include <winpr/library.h>
#include <winpr/smartcard.h>
#include <winpr/synch.h>
#include <winpr/wlog.h>

#include "../log.h"

#include "smartcard.h"

#define TAG WINPR_TAG("smartcard_ex")

#define xstr(s) str(s)
#define str(s) #s

#define SCARDAPI_STUB_CALL_LONG(_name, ...)                                              \
	SCardApiFunctionTable* pSCardApi = (SCardApiFunctionTable*) hSCardApi;              \
	if (!pSCardApi || !pSCardApi->pfn##_name)                                          \
	{                                                                                    \
		WLog_DBG(TAG, "Missing function pointer hSCardApi=%p->" xstr(pfn##_name) "=%p", \
		         pSCardApi, pSCardApi ? pSCardApi->pfn##_name : NULL);                \
		return SCARD_E_NO_SERVICE;                                                       \
	}                                                                                    \
	return pSCardApi->pfn##_name(__VA_ARGS__)

#define SCARDAPI_STUB_CALL_HANDLE(_name, ...)                                            \
	SCardApiFunctionTable* pSCardApi = (SCardApiFunctionTable*) hSCardApi;              \
	if (!hSCardApi || !pSCardApi->pfn##_name)                                          \
	{                                                                                    \
		WLog_DBG(TAG, "Missing function pointer hSCardApi=%p->" xstr(pfn##_name) "=%p", \
		         pSCardApi, pSCardApi ? pSCardApi->pfn##_name : NULL);                \
		return NULL;                                                                     \
	}                                                                                    \
	return pSCardApi->pfn##_name(__VA_ARGS__)

#define SCARDAPI_STUB_CALL_VOID(_name, ...)                                              \
	SCardApiFunctionTable* pSCardApi = (SCardApiFunctionTable*) hSCardApi;              \
	if (!pSCardApi || !pSCardApi->pfn##_name)                                          \
	{                                                                                    \
		WLog_DBG(TAG, "Missing function pointer hSCardApi=%p->" xstr(pfn##_name) "=%p", \
		         pSCardApi, pSCardApi ? pSCardApi->pfn##_name : NULL);                \
		return;                                                                          \
	}                                                                                    \
	pSCardApi->pfn##_name(__VA_ARGS__)

WINSCARDAPI LONG WINAPI SCardEstablishContextEx(SCARDAPICONTEXT hSCardApi, DWORD dwScope, LPCVOID pvReserved1,
                                              LPCVOID pvReserved2, LPSCARDCONTEXT phContext)
{
	SCARDAPI_STUB_CALL_LONG(SCardEstablishContext, dwScope, pvReserved1, pvReserved2, phContext);
}

WINSCARDAPI LONG WINAPI SCardReleaseContextEx(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext)
{
	SCARDAPI_STUB_CALL_LONG(SCardReleaseContext, hContext);
}

WINSCARDAPI LONG WINAPI SCardIsValidContextEx(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext)
{
	SCARDAPI_STUB_CALL_LONG(SCardIsValidContext, hContext);
}

WINSCARDAPI LONG WINAPI SCardListReaderGroupsExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPSTR mszGroups,
                                               LPDWORD pcchGroups)
{
	SCARDAPI_STUB_CALL_LONG(SCardListReaderGroupsA, hContext, mszGroups, pcchGroups);
}

WINSCARDAPI LONG WINAPI SCardListReaderGroupsExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPWSTR mszGroups,
                                               LPDWORD pcchGroups)
{
	SCARDAPI_STUB_CALL_LONG(SCardListReaderGroupsW, hContext, mszGroups, pcchGroups);
}

WINSCARDAPI LONG WINAPI SCardListReadersExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR mszGroups, LPSTR mszReaders,
                                          LPDWORD pcchReaders)
{
	SCARDAPI_STUB_CALL_LONG(SCardListReadersA, hContext, mszGroups, mszReaders, pcchReaders);
}

WINSCARDAPI LONG WINAPI SCardListReadersExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR mszGroups,
                                          LPWSTR mszReaders, LPDWORD pcchReaders)
{
	SCARDAPI_STUB_CALL_LONG(SCardListReadersW, hContext, mszGroups, mszReaders, pcchReaders);
}

WINSCARDAPI LONG WINAPI SCardListCardsExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCBYTE pbAtr,
                                        LPCGUID rgquidInterfaces, DWORD cguidInterfaceCount,
                                        CHAR* mszCards, LPDWORD pcchCards)
{
	SCARDAPI_STUB_CALL_LONG(SCardListCardsA, hContext, pbAtr, rgquidInterfaces, cguidInterfaceCount,
	                        mszCards, pcchCards);
}

WINSCARDAPI LONG WINAPI SCardListCardsExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCBYTE pbAtr,
                                        LPCGUID rgquidInterfaces, DWORD cguidInterfaceCount,
                                        WCHAR* mszCards, LPDWORD pcchCards)
{
	SCARDAPI_STUB_CALL_LONG(SCardListCardsW, hContext, pbAtr, rgquidInterfaces, cguidInterfaceCount,
	                        mszCards, pcchCards);
}

WINSCARDAPI LONG WINAPI SCardListInterfacesExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szCard,
                                             LPGUID pguidInterfaces, LPDWORD pcguidInterfaces)
{
	SCARDAPI_STUB_CALL_LONG(SCardListInterfacesA, hContext, szCard, pguidInterfaces,
	                        pcguidInterfaces);
}

WINSCARDAPI LONG WINAPI SCardListInterfacesExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szCard,
                                             LPGUID pguidInterfaces, LPDWORD pcguidInterfaces)
{
	SCARDAPI_STUB_CALL_LONG(SCardListInterfacesW, hContext, szCard, pguidInterfaces,
	                        pcguidInterfaces);
}

WINSCARDAPI LONG WINAPI SCardGetProviderIdExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szCard,
                                            LPGUID pguidProviderId)
{
	SCARDAPI_STUB_CALL_LONG(SCardGetProviderIdA, hContext, szCard, pguidProviderId);
}

WINSCARDAPI LONG WINAPI SCardGetProviderIdExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szCard,
                                            LPGUID pguidProviderId)
{
	SCARDAPI_STUB_CALL_LONG(SCardGetProviderIdW, hContext, szCard, pguidProviderId);
}

WINSCARDAPI LONG WINAPI SCardGetCardTypeProviderNameExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szCardName,
                                                      DWORD dwProviderId, CHAR* szProvider,
                                                      LPDWORD pcchProvider)
{
	SCARDAPI_STUB_CALL_LONG(SCardGetCardTypeProviderNameA, hContext, szCardName, dwProviderId,
	                        szProvider, pcchProvider);
}

WINSCARDAPI LONG WINAPI SCardGetCardTypeProviderNameExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szCardName,
                                                      DWORD dwProviderId, WCHAR* szProvider,
                                                      LPDWORD pcchProvider)
{
	SCARDAPI_STUB_CALL_LONG(SCardGetCardTypeProviderNameW, hContext, szCardName, dwProviderId,
	                        szProvider, pcchProvider);
}

WINSCARDAPI LONG WINAPI SCardIntroduceReaderGroupExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szGroupName)
{
	SCARDAPI_STUB_CALL_LONG(SCardIntroduceReaderGroupA, hContext, szGroupName);
}

WINSCARDAPI LONG WINAPI SCardIntroduceReaderGroupExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szGroupName)
{
	SCARDAPI_STUB_CALL_LONG(SCardIntroduceReaderGroupW, hContext, szGroupName);
}

WINSCARDAPI LONG WINAPI SCardForgetReaderGroupExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szGroupName)
{
	SCARDAPI_STUB_CALL_LONG(SCardForgetReaderGroupA, hContext, szGroupName);
}

WINSCARDAPI LONG WINAPI SCardForgetReaderGroupExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szGroupName)
{
	SCARDAPI_STUB_CALL_LONG(SCardForgetReaderGroupW, hContext, szGroupName);
}

WINSCARDAPI LONG WINAPI SCardIntroduceReaderExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szReaderName,
                                              LPCSTR szDeviceName)
{
	SCARDAPI_STUB_CALL_LONG(SCardIntroduceReaderA, hContext, szReaderName, szDeviceName);
}

WINSCARDAPI LONG WINAPI SCardIntroduceReaderExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szReaderName,
                                              LPCWSTR szDeviceName)
{
	SCARDAPI_STUB_CALL_LONG(SCardIntroduceReaderW, hContext, szReaderName, szDeviceName);
}

WINSCARDAPI LONG WINAPI SCardForgetReaderExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szReaderName)
{
	SCARDAPI_STUB_CALL_LONG(SCardForgetReaderA, hContext, szReaderName);
}

WINSCARDAPI LONG WINAPI SCardForgetReaderExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szReaderName)
{
	SCARDAPI_STUB_CALL_LONG(SCardForgetReaderW, hContext, szReaderName);
}

WINSCARDAPI LONG WINAPI SCardAddReaderToGroupExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szReaderName,
                                               LPCSTR szGroupName)
{
	SCARDAPI_STUB_CALL_LONG(SCardAddReaderToGroupA, hContext, szReaderName, szGroupName);
}

WINSCARDAPI LONG WINAPI SCardAddReaderToGroupExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szReaderName,
                                               LPCWSTR szGroupName)
{
	SCARDAPI_STUB_CALL_LONG(SCardAddReaderToGroupW, hContext, szReaderName, szGroupName);
}

WINSCARDAPI LONG WINAPI SCardRemoveReaderFromGroupExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szReaderName,
                                                    LPCSTR szGroupName)
{
	SCARDAPI_STUB_CALL_LONG(SCardRemoveReaderFromGroupA, hContext, szReaderName, szGroupName);
}

WINSCARDAPI LONG WINAPI SCardRemoveReaderFromGroupExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szReaderName,
                                                    LPCWSTR szGroupName)
{
	SCARDAPI_STUB_CALL_LONG(SCardRemoveReaderFromGroupW, hContext, szReaderName, szGroupName);
}

WINSCARDAPI LONG WINAPI SCardIntroduceCardTypeExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szCardName,
                                                LPCGUID pguidPrimaryProvider,
                                                LPCGUID rgguidInterfaces, DWORD dwInterfaceCount,
                                                LPCBYTE pbAtr, LPCBYTE pbAtrMask, DWORD cbAtrLen)
{
	SCARDAPI_STUB_CALL_LONG(SCardIntroduceCardTypeA, hContext, szCardName, pguidPrimaryProvider,
	                        rgguidInterfaces, dwInterfaceCount, pbAtr, pbAtrMask, cbAtrLen);
}

WINSCARDAPI LONG WINAPI SCardIntroduceCardTypeExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szCardName,
                                                LPCGUID pguidPrimaryProvider,
                                                LPCGUID rgguidInterfaces, DWORD dwInterfaceCount,
                                                LPCBYTE pbAtr, LPCBYTE pbAtrMask, DWORD cbAtrLen)
{
	SCARDAPI_STUB_CALL_LONG(SCardIntroduceCardTypeW, hContext, szCardName, pguidPrimaryProvider,
	                        rgguidInterfaces, dwInterfaceCount, pbAtr, pbAtrMask, cbAtrLen);
}

WINSCARDAPI LONG WINAPI SCardSetCardTypeProviderNameExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szCardName,
                                                      DWORD dwProviderId, LPCSTR szProvider)
{
	SCARDAPI_STUB_CALL_LONG(SCardSetCardTypeProviderNameA, hContext, szCardName, dwProviderId,
	                        szProvider);
}

WINSCARDAPI LONG WINAPI SCardSetCardTypeProviderNameExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szCardName,
                                                      DWORD dwProviderId, LPCWSTR szProvider)
{
	SCARDAPI_STUB_CALL_LONG(SCardSetCardTypeProviderNameW, hContext, szCardName, dwProviderId,
	                        szProvider);
}

WINSCARDAPI LONG WINAPI SCardForgetCardTypeExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szCardName)
{
	SCARDAPI_STUB_CALL_LONG(SCardForgetCardTypeA, hContext, szCardName);
}

WINSCARDAPI LONG WINAPI SCardForgetCardTypeExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szCardName)
{
	SCARDAPI_STUB_CALL_LONG(SCardForgetCardTypeW, hContext, szCardName);
}

WINSCARDAPI LONG WINAPI SCardFreeMemoryEx(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPVOID pvMem)
{
	SCARDAPI_STUB_CALL_LONG(SCardFreeMemory, hContext, pvMem);
}

WINSCARDAPI HANDLE WINAPI SCardAccessStartedEventEx(SCARDAPICONTEXT hSCardApi)
{
	SCARDAPI_STUB_CALL_HANDLE(SCardAccessStartedEvent);
}

WINSCARDAPI void WINAPI SCardReleaseStartedEventEx(SCARDAPICONTEXT hSCardApi)
{
	SCARDAPI_STUB_CALL_VOID(SCardReleaseStartedEvent);
}

WINSCARDAPI LONG WINAPI SCardLocateCardsExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR mszCards,
                                          LPSCARD_READERSTATEA rgReaderStates, DWORD cReaders)
{
	SCARDAPI_STUB_CALL_LONG(SCardLocateCardsA, hContext, mszCards, rgReaderStates, cReaders);
}

WINSCARDAPI LONG WINAPI SCardLocateCardsExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR mszCards,
                                          LPSCARD_READERSTATEW rgReaderStates, DWORD cReaders)
{
	SCARDAPI_STUB_CALL_LONG(SCardLocateCardsW, hContext, mszCards, rgReaderStates, cReaders);
}

WINSCARDAPI LONG WINAPI SCardLocateCardsByATRExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPSCARD_ATRMASK rgAtrMasks,
                                               DWORD cAtrs, LPSCARD_READERSTATEA rgReaderStates,
                                               DWORD cReaders)
{
	SCARDAPI_STUB_CALL_LONG(SCardLocateCardsByATRA, hContext, rgAtrMasks, cAtrs, rgReaderStates,
	                        cReaders);
}

WINSCARDAPI LONG WINAPI SCardLocateCardsByATRExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPSCARD_ATRMASK rgAtrMasks,
                                               DWORD cAtrs, LPSCARD_READERSTATEW rgReaderStates,
                                               DWORD cReaders)
{
	SCARDAPI_STUB_CALL_LONG(SCardLocateCardsByATRW, hContext, rgAtrMasks, cAtrs, rgReaderStates,
	                        cReaders);
}

WINSCARDAPI LONG WINAPI SCardGetStatusChangeExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, DWORD dwTimeout,
                                              LPSCARD_READERSTATEA rgReaderStates, DWORD cReaders)
{
	SCARDAPI_STUB_CALL_LONG(SCardGetStatusChangeA, hContext, dwTimeout, rgReaderStates, cReaders);
}

WINSCARDAPI LONG WINAPI SCardGetStatusChangeExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, DWORD dwTimeout,
                                              LPSCARD_READERSTATEW rgReaderStates, DWORD cReaders)
{
	SCARDAPI_STUB_CALL_LONG(SCardGetStatusChangeW, hContext, dwTimeout, rgReaderStates, cReaders);
}

WINSCARDAPI LONG WINAPI SCardCancelEx(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext)
{
	SCARDAPI_STUB_CALL_LONG(SCardCancel, hContext);
}

WINSCARDAPI LONG WINAPI SCardConnectExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode,
                                      DWORD dwPreferredProtocols, LPSCARDHANDLE phCard,
                                      LPDWORD pdwActiveProtocol)
{
	SCARDAPI_STUB_CALL_LONG(SCardConnectA, hContext, szReader, dwShareMode, dwPreferredProtocols,
	                        phCard, pdwActiveProtocol);
}

WINSCARDAPI LONG WINAPI SCardConnectExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szReader, DWORD dwShareMode,
                                      DWORD dwPreferredProtocols, LPSCARDHANDLE phCard,
                                      LPDWORD pdwActiveProtocol)
{
	SCARDAPI_STUB_CALL_LONG(SCardConnectW, hContext, szReader, dwShareMode, dwPreferredProtocols,
	                        phCard, pdwActiveProtocol);
}

WINSCARDAPI LONG WINAPI SCardReconnectEx(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard, DWORD dwShareMode,
                                       DWORD dwPreferredProtocols, DWORD dwInitialization,
                                       LPDWORD pdwActiveProtocol)
{
	SCARDAPI_STUB_CALL_LONG(SCardReconnect, hCard, dwShareMode, dwPreferredProtocols,
	                        dwInitialization, pdwActiveProtocol);
}

WINSCARDAPI LONG WINAPI SCardDisconnectEx(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard, DWORD dwDisposition)
{
	SCARDAPI_STUB_CALL_LONG(SCardDisconnect, hCard, dwDisposition);
}

WINSCARDAPI LONG WINAPI SCardBeginTransactionEx(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard)
{
	SCARDAPI_STUB_CALL_LONG(SCardBeginTransaction, hCard);
}

WINSCARDAPI LONG WINAPI SCardEndTransactionEx(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard, DWORD dwDisposition)
{
	SCARDAPI_STUB_CALL_LONG(SCardEndTransaction, hCard, dwDisposition);
}

WINSCARDAPI LONG WINAPI SCardCancelTransactionEx(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard)
{
	SCARDAPI_STUB_CALL_LONG(SCardCancelTransaction, hCard);
}

WINSCARDAPI LONG WINAPI SCardStateEx(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard, LPDWORD pdwState, LPDWORD pdwProtocol,
                                   LPBYTE pbAtr, LPDWORD pcbAtrLen)
{
	SCARDAPI_STUB_CALL_LONG(SCardState, hCard, pdwState, pdwProtocol, pbAtr, pcbAtrLen);
}

WINSCARDAPI LONG WINAPI SCardStatusExA(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard, LPSTR mszReaderNames, LPDWORD pcchReaderLen,
                                     LPDWORD pdwState, LPDWORD pdwProtocol, LPBYTE pbAtr,
                                     LPDWORD pcbAtrLen)
{
	SCARDAPI_STUB_CALL_LONG(SCardStatusA, hCard, mszReaderNames, pcchReaderLen, pdwState,
	                        pdwProtocol, pbAtr, pcbAtrLen);
}

WINSCARDAPI LONG WINAPI SCardStatusExW(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard, LPWSTR mszReaderNames,
                                     LPDWORD pcchReaderLen, LPDWORD pdwState, LPDWORD pdwProtocol,
                                     LPBYTE pbAtr, LPDWORD pcbAtrLen)
{
	SCARDAPI_STUB_CALL_LONG(SCardStatusW, hCard, mszReaderNames, pcchReaderLen, pdwState,
	                        pdwProtocol, pbAtr, pcbAtrLen);
}

WINSCARDAPI LONG WINAPI SCardTransmitEx(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard, LPCSCARD_IO_REQUEST pioSendPci,
                                      LPCBYTE pbSendBuffer, DWORD cbSendLength,
                                      LPSCARD_IO_REQUEST pioRecvPci, LPBYTE pbRecvBuffer,
                                      LPDWORD pcbRecvLength)
{
	SCARDAPI_STUB_CALL_LONG(SCardTransmit, hCard, pioSendPci, pbSendBuffer, cbSendLength,
	                        pioRecvPci, pbRecvBuffer, pcbRecvLength);
}

WINSCARDAPI LONG WINAPI SCardGetTransmitCountEx(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard, LPDWORD pcTransmitCount)
{
	SCARDAPI_STUB_CALL_LONG(SCardGetTransmitCount, hCard, pcTransmitCount);
}

WINSCARDAPI LONG WINAPI SCardControlEx(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard, DWORD dwControlCode, LPCVOID lpInBuffer,
                                     DWORD cbInBufferSize, LPVOID lpOutBuffer,
                                     DWORD cbOutBufferSize, LPDWORD lpBytesReturned)
{
	SCARDAPI_STUB_CALL_LONG(SCardControl, hCard, dwControlCode, lpInBuffer, cbInBufferSize,
	                        lpOutBuffer, cbOutBufferSize, lpBytesReturned);
}

WINSCARDAPI LONG WINAPI SCardGetAttribEx(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr,
                                       LPDWORD pcbAttrLen)
{
	SCARDAPI_STUB_CALL_LONG(SCardGetAttrib, hCard, dwAttrId, pbAttr, pcbAttrLen);
}

WINSCARDAPI LONG WINAPI SCardSetAttribEx(SCARDAPICONTEXT hSCardApi, SCARDHANDLE hCard, DWORD dwAttrId, LPCBYTE pbAttr,
                                       DWORD cbAttrLen)
{
	SCARDAPI_STUB_CALL_LONG(SCardSetAttrib, hCard, dwAttrId, pbAttr, cbAttrLen);
}

WINSCARDAPI LONG WINAPI SCardUIDlgSelectCardExA(SCARDAPICONTEXT hSCardApi, LPOPENCARDNAMEA_EX pDlgStruc)
{
	SCARDAPI_STUB_CALL_LONG(SCardUIDlgSelectCardA, pDlgStruc);
}

WINSCARDAPI LONG WINAPI SCardUIDlgSelectCardExW(SCARDAPICONTEXT hSCardApi, LPOPENCARDNAMEW_EX pDlgStruc)
{
	SCARDAPI_STUB_CALL_LONG(SCardUIDlgSelectCardW, pDlgStruc);
}

WINSCARDAPI LONG WINAPI GetOpenCardNameExA(SCARDAPICONTEXT hSCardApi, LPOPENCARDNAMEA pDlgStruc)
{
	SCARDAPI_STUB_CALL_LONG(GetOpenCardNameA, pDlgStruc);
}

WINSCARDAPI LONG WINAPI GetOpenCardNameExW(SCARDAPICONTEXT hSCardApi, LPOPENCARDNAMEW pDlgStruc)
{
	SCARDAPI_STUB_CALL_LONG(GetOpenCardNameW, pDlgStruc);
}

WINSCARDAPI LONG WINAPI SCardDlgExtendedErrorEx(SCARDAPICONTEXT hSCardApi)
{
	SCARDAPI_STUB_CALL_LONG(SCardDlgExtendedError);
}

WINSCARDAPI LONG WINAPI SCardReadCacheExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, UUID* CardIdentifier,
                                        DWORD FreshnessCounter, LPSTR LookupName, PBYTE Data,
                                        DWORD* DataLen)
{
	SCARDAPI_STUB_CALL_LONG(SCardReadCacheA, hContext, CardIdentifier, FreshnessCounter, LookupName,
	                        Data, DataLen);
}

WINSCARDAPI LONG WINAPI SCardReadCacheExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, UUID* CardIdentifier,
                                        DWORD FreshnessCounter, LPWSTR LookupName, PBYTE Data,
                                        DWORD* DataLen)
{
	SCARDAPI_STUB_CALL_LONG(SCardReadCacheW, hContext, CardIdentifier, FreshnessCounter, LookupName,
	                        Data, DataLen);
}

WINSCARDAPI LONG WINAPI SCardWriteCacheExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, UUID* CardIdentifier,
                                         DWORD FreshnessCounter, LPSTR LookupName, PBYTE Data,
                                         DWORD DataLen)
{
	SCARDAPI_STUB_CALL_LONG(SCardWriteCacheA, hContext, CardIdentifier, FreshnessCounter,
	                        LookupName, Data, DataLen);
}

WINSCARDAPI LONG WINAPI SCardWriteCacheExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, UUID* CardIdentifier,
                                         DWORD FreshnessCounter, LPWSTR LookupName, PBYTE Data,
                                         DWORD DataLen)
{
	SCARDAPI_STUB_CALL_LONG(SCardWriteCacheW, hContext, CardIdentifier, FreshnessCounter,
	                        LookupName, Data, DataLen);
}

WINSCARDAPI LONG WINAPI SCardGetReaderIconExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szReaderName,
                                            LPBYTE pbIcon, LPDWORD pcbIcon)
{
	SCARDAPI_STUB_CALL_LONG(SCardGetReaderIconA, hContext, szReaderName, pbIcon, pcbIcon);
}

WINSCARDAPI LONG WINAPI SCardGetReaderIconExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szReaderName,
                                            LPBYTE pbIcon, LPDWORD pcbIcon)
{
	SCARDAPI_STUB_CALL_LONG(SCardGetReaderIconW, hContext, szReaderName, pbIcon, pcbIcon);
}

WINSCARDAPI LONG WINAPI SCardGetDeviceTypeIdExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szReaderName,
                                              LPDWORD pdwDeviceTypeId)
{
	SCARDAPI_STUB_CALL_LONG(SCardGetDeviceTypeIdA, hContext, szReaderName, pdwDeviceTypeId);
}

WINSCARDAPI LONG WINAPI SCardGetDeviceTypeIdExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szReaderName,
                                              LPDWORD pdwDeviceTypeId)
{
	SCARDAPI_STUB_CALL_LONG(SCardGetDeviceTypeIdW, hContext, szReaderName, pdwDeviceTypeId);
}

WINSCARDAPI LONG WINAPI SCardGetReaderDeviceInstanceIdExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szReaderName,
                                                        LPSTR szDeviceInstanceId,
                                                        LPDWORD pcchDeviceInstanceId)
{
	SCARDAPI_STUB_CALL_LONG(SCardGetReaderDeviceInstanceIdA, hContext, szReaderName,
	                        szDeviceInstanceId, pcchDeviceInstanceId);
}

WINSCARDAPI LONG WINAPI SCardGetReaderDeviceInstanceIdExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szReaderName,
                                                        LPWSTR szDeviceInstanceId,
                                                        LPDWORD pcchDeviceInstanceId)
{
	SCARDAPI_STUB_CALL_LONG(SCardGetReaderDeviceInstanceIdW, hContext, szReaderName,
	                        szDeviceInstanceId, pcchDeviceInstanceId);
}

WINSCARDAPI LONG WINAPI SCardListReadersWithDeviceInstanceIdExA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                                              LPCSTR szDeviceInstanceId,
                                                              LPSTR mszReaders, LPDWORD pcchReaders)
{
	SCARDAPI_STUB_CALL_LONG(SCardListReadersWithDeviceInstanceIdA, hContext, szDeviceInstanceId,
	                        mszReaders, pcchReaders);
}

WINSCARDAPI LONG WINAPI SCardListReadersWithDeviceInstanceIdExW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
                                                              LPCWSTR szDeviceInstanceId,
                                                              LPWSTR mszReaders,
                                                              LPDWORD pcchReaders)
{
	SCARDAPI_STUB_CALL_LONG(SCardListReadersWithDeviceInstanceIdW, hContext, szDeviceInstanceId,
	                        mszReaders, pcchReaders);
}

WINSCARDAPI LONG WINAPI SCardAuditEx(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, DWORD dwEvent)
{
	SCARDAPI_STUB_CALL_LONG(SCardAudit, hContext, dwEvent);
}

static const SCardApiFunctionTableEx Null_SCardApiFunctionTableEx = {
	0, /* dwVersion */
	0, /* dwFlags */

	SCardEstablishContextEx,                 /* SCardEstablishContext */
	SCardReleaseContextEx,                   /* SCardReleaseContext */
	SCardIsValidContextEx,                   /* SCardIsValidContext */
	SCardListReaderGroupsExA,                /* SCardListReaderGroupsA */
	SCardListReaderGroupsExW,                /* SCardListReaderGroupsW */
	SCardListReadersExA,                     /* SCardListReadersA */
	SCardListReadersExW,                     /* SCardListReadersW */
	SCardListCardsExA,                       /* SCardListCardsA */
	SCardListCardsExW,                       /* SCardListCardsW */
	SCardListInterfacesExA,                  /* SCardListInterfacesA */
	SCardListInterfacesExW,                  /* SCardListInterfacesW */
	SCardGetProviderIdExA,                   /* SCardGetProviderIdA */
	SCardGetProviderIdExW,                   /* SCardGetProviderIdW */
	SCardGetCardTypeProviderNameExA,         /* SCardGetCardTypeProviderNameA */
	SCardGetCardTypeProviderNameExW,         /* SCardGetCardTypeProviderNameW */
	SCardIntroduceReaderGroupExA,            /* SCardIntroduceReaderGroupA */
	SCardIntroduceReaderGroupExW,            /* SCardIntroduceReaderGroupW */
	SCardForgetReaderGroupExA,               /* SCardForgetReaderGroupA */
	SCardForgetReaderGroupExW,               /* SCardForgetReaderGroupW */
	SCardIntroduceReaderExA,                 /* SCardIntroduceReaderA */
	SCardIntroduceReaderExW,                 /* SCardIntroduceReaderW */
	SCardForgetReaderExA,                    /* SCardForgetReaderA */
	SCardForgetReaderExW,                    /* SCardForgetReaderW */
	SCardAddReaderToGroupExA,                /* SCardAddReaderToGroupA */
	SCardAddReaderToGroupExW,                /* SCardAddReaderToGroupW */
	SCardRemoveReaderFromGroupExA,           /* SCardRemoveReaderFromGroupA */
	SCardRemoveReaderFromGroupExW,           /* SCardRemoveReaderFromGroupW */
	SCardIntroduceCardTypeExA,               /* SCardIntroduceCardTypeA */
	SCardIntroduceCardTypeExW,               /* SCardIntroduceCardTypeW */
	SCardSetCardTypeProviderNameExA,         /* SCardSetCardTypeProviderNameA */
	SCardSetCardTypeProviderNameExW,         /* SCardSetCardTypeProviderNameW */
	SCardForgetCardTypeExA,                  /* SCardForgetCardTypeA */
	SCardForgetCardTypeExW,                  /* SCardForgetCardTypeW */
	SCardFreeMemoryEx,                       /* SCardFreeMemory */
	SCardAccessStartedEventEx,               /* SCardAccessStartedEvent */
	SCardReleaseStartedEventEx,              /* SCardReleaseStartedEvent */
	SCardLocateCardsExA,                     /* SCardLocateCardsA */
	SCardLocateCardsExW,                     /* SCardLocateCardsW */
	SCardLocateCardsByATRExA,                /* SCardLocateCardsByATRA */
	SCardLocateCardsByATRExW,                /* SCardLocateCardsByATRW */
	SCardGetStatusChangeExA,                 /* SCardGetStatusChangeA */
	SCardGetStatusChangeExW,                 /* SCardGetStatusChangeW */
	SCardCancelEx,                           /* SCardCancel */
	SCardConnectExA,                         /* SCardConnectA */
	SCardConnectExW,                         /* SCardConnectW */
	SCardReconnectEx,                        /* SCardReconnect */
	SCardDisconnectEx,                       /* SCardDisconnect */
	SCardBeginTransactionEx,                 /* SCardBeginTransaction */
	SCardEndTransactionEx,                   /* SCardEndTransaction */
	SCardCancelTransactionEx,                /* SCardCancelTransaction */
	SCardStateEx,                            /* SCardState */
	SCardStatusExA,                          /* SCardStatusA */
	SCardStatusExW,                          /* SCardStatusW */
	SCardTransmitEx,                         /* SCardTransmit */
	SCardGetTransmitCountEx,                 /* SCardGetTransmitCount */
	SCardControlEx,                          /* SCardControl */
	SCardGetAttribEx,                        /* SCardGetAttrib */
	SCardSetAttribEx,                        /* SCardSetAttrib */
	SCardUIDlgSelectCardExA,                 /* SCardUIDlgSelectCardA */
	SCardUIDlgSelectCardExW,                 /* SCardUIDlgSelectCardW */
	GetOpenCardNameExA,                      /* GetOpenCardNameA */
	GetOpenCardNameExW,                      /* GetOpenCardNameW */
	SCardDlgExtendedErrorEx,                 /* SCardDlgExtendedError */
	SCardReadCacheExA,                       /* SCardReadCacheA */
	SCardReadCacheExW,                       /* SCardReadCacheW */
	SCardWriteCacheExA,                      /* SCardWriteCacheA */
	SCardWriteCacheExW,                      /* SCardWriteCacheW */
	SCardGetReaderIconExA,                   /* SCardGetReaderIconA */
	SCardGetReaderIconExW,                   /* SCardGetReaderIconW */
	SCardGetDeviceTypeIdExA,                 /* SCardGetDeviceTypeIdA */
	SCardGetDeviceTypeIdExW,                 /* SCardGetDeviceTypeIdW */
	SCardGetReaderDeviceInstanceIdExA,       /* SCardGetReaderDeviceInstanceIdA */
	SCardGetReaderDeviceInstanceIdExW,       /* SCardGetReaderDeviceInstanceIdW */
	SCardListReadersWithDeviceInstanceIdExA, /* SCardListReadersWithDeviceInstanceIdA */
	SCardListReadersWithDeviceInstanceIdExW, /* SCardListReadersWithDeviceInstanceIdW */
	SCardAuditEx                             /* SCardAudit */
};

const SCardApiFunctionTableEx* Null_GetSCardApiFunctionTableEx(void)
{
	return &Null_GetSCardApiFunctionTableEx;
}
