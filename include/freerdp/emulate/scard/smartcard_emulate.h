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

#ifndef WINPR_SMARTCARD_EMULATE_PRIVATE_H
#define WINPR_SMARTCARD_EMULATE_PRIVATE_H

#include <winpr/platform.h>
#include <winpr/smartcard.h>

#include <freerdp/api.h>
#include <freerdp/settings.h>

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct smartcard_emulation_context SmartcardEmulationContext;

	FREERDP_API SmartcardEmulationContext* Emulate_New(const rdpSettings* settings);
	FREERDP_API void Emulate_Free(SmartcardEmulationContext* context);

	FREERDP_API BOOL Emulate_IsConfigured(SmartcardEmulationContext* context);

	FREERDP_API LONG WINAPI Emulate_SCardEstablishContext(SCARDAPICONTEXT hSCardApi,
	                                                      DWORD dwScope, LPCVOID pvReserved1,
	                                                      LPCVOID pvReserved2,
	                                                      LPSCARDCONTEXT phContext);

	FREERDP_API LONG WINAPI Emulate_SCardReleaseContext(SCARDAPICONTEXT hSCardApi,
	                                                    SCARDCONTEXT hContext);

	FREERDP_API LONG WINAPI Emulate_SCardIsValidContext(SCARDAPICONTEXT hSCardApi,
	                                                    SCARDCONTEXT hContext);

	FREERDP_API LONG WINAPI Emulate_SCardListReaderGroupsA(SCARDAPICONTEXT hSCardApi,
	                                                       SCARDCONTEXT hContext, LPSTR mszGroups,
	                                                       LPDWORD pcchGroups);

	FREERDP_API LONG WINAPI Emulate_SCardListReaderGroupsW(SCARDAPICONTEXT hSCardApi,
	                                                       SCARDCONTEXT hContext, LPWSTR mszGroups,
	                                                       LPDWORD pcchGroups);

	FREERDP_API LONG WINAPI Emulate_SCardListReadersA(SCARDAPICONTEXT hSCardApi,
	                                                  SCARDCONTEXT hContext, LPCSTR mszGroups,
	                                                  LPSTR mszReaders, LPDWORD pcchReaders);

	FREERDP_API LONG WINAPI Emulate_SCardListReadersW(SCARDAPICONTEXT hSCardApi,
	                                                  SCARDCONTEXT hContext, LPCWSTR mszGroups,
	                                                  LPWSTR mszReaders, LPDWORD pcchReaders);

	FREERDP_API LONG WINAPI Emulate_SCardListCardsA(SCARDAPICONTEXT hSCardApi,
	                                                SCARDCONTEXT hContext, LPCBYTE pbAtr,
	                                                LPCGUID rgquidInterfaces,
	                                                DWORD cguidInterfaceCount, CHAR* mszCards,
	                                                LPDWORD pcchCards);

	FREERDP_API LONG WINAPI Emulate_SCardListCardsW(SCARDAPICONTEXT hSCardApi,
	                                                SCARDCONTEXT hContext, LPCBYTE pbAtr,
	                                                LPCGUID rgquidInterfaces,
	                                                DWORD cguidInterfaceCount, WCHAR* mszCards,
	                                                LPDWORD pcchCards);

	FREERDP_API LONG WINAPI Emulate_SCardListInterfacesA(SCARDAPICONTEXT hSCardApi,
	                                                     SCARDCONTEXT hContext, LPCSTR szCard,
	                                                     LPGUID pguidInterfaces,
	                                                     LPDWORD pcguidInterfaces);

	FREERDP_API LONG WINAPI Emulate_SCardListInterfacesW(SCARDAPICONTEXT hSCardApi,
	                                                     SCARDCONTEXT hContext, LPCWSTR szCard,
	                                                     LPGUID pguidInterfaces,
	                                                     LPDWORD pcguidInterfaces);

	FREERDP_API LONG WINAPI Emulate_SCardGetProviderIdA(SCARDAPICONTEXT hSCardApi,
	                                                    SCARDCONTEXT hContext, LPCSTR szCard,
	                                                    LPGUID pguidProviderId);

	FREERDP_API LONG WINAPI Emulate_SCardGetProviderIdW(SCARDAPICONTEXT hSCardApi,
	                                                    SCARDCONTEXT hContext, LPCWSTR szCard,
	                                                    LPGUID pguidProviderId);

	FREERDP_API LONG WINAPI Emulate_SCardGetCardTypeProviderNameA(
	    SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szCardName,
	    DWORD dwProviderId, CHAR* szProvider, LPDWORD pcchProvider);

	FREERDP_API LONG WINAPI Emulate_SCardGetCardTypeProviderNameW(
	    SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szCardName,
	    DWORD dwProviderId, WCHAR* szProvider, LPDWORD pcchProvider);

	FREERDP_API LONG WINAPI Emulate_SCardIntroduceReaderGroupA(SCARDAPICONTEXT hSCardApi,
	                                                           SCARDCONTEXT hContext,
	                                                           LPCSTR szGroupName);

	FREERDP_API LONG WINAPI Emulate_SCardIntroduceReaderGroupW(SCARDAPICONTEXT hSCardApi,
	                                                           SCARDCONTEXT hContext,
	                                                           LPCWSTR szGroupName);

	FREERDP_API LONG WINAPI Emulate_SCardForgetReaderGroupA(SCARDAPICONTEXT hSCardApi,
	                                                        SCARDCONTEXT hContext,
	                                                        LPCSTR szGroupName);

	FREERDP_API LONG WINAPI Emulate_SCardForgetReaderGroupW(SCARDAPICONTEXT hSCardApi,
	                                                        SCARDCONTEXT hContext,
	                                                        LPCWSTR szGroupName);

	FREERDP_API LONG WINAPI Emulate_SCardIntroduceReaderA(SCARDAPICONTEXT hSCardApi,
	                                                      SCARDCONTEXT hContext,
	                                                      LPCSTR szReaderName, LPCSTR szDeviceName);

	FREERDP_API LONG WINAPI Emulate_SCardIntroduceReaderW(SCARDAPICONTEXT hSCardApi,
	                                                      SCARDCONTEXT hContext,
	                                                      LPCWSTR szReaderName,
	                                                      LPCWSTR szDeviceName);

	FREERDP_API LONG WINAPI Emulate_SCardForgetReaderA(SCARDAPICONTEXT hSCardApi,
	                                                   SCARDCONTEXT hContext, LPCSTR szReaderName);

	FREERDP_API LONG WINAPI Emulate_SCardForgetReaderW(SCARDAPICONTEXT hSCardApi,
	                                                   SCARDCONTEXT hContext, LPCWSTR szReaderName);

	FREERDP_API LONG WINAPI Emulate_SCardAddReaderToGroupA(SCARDAPICONTEXT hSCardApi,
	                                                       SCARDCONTEXT hContext,
	                                                       LPCSTR szReaderName, LPCSTR szGroupName);

	FREERDP_API LONG WINAPI Emulate_SCardAddReaderToGroupW(SCARDAPICONTEXT hSCardApi,
	                                                       SCARDCONTEXT hContext,
	                                                       LPCWSTR szReaderName,
	                                                       LPCWSTR szGroupName);

	FREERDP_API LONG WINAPI
	Emulate_SCardRemoveReaderFromGroupA(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
	                                    LPCSTR szReaderName, LPCSTR szGroupName);

	FREERDP_API LONG WINAPI
	Emulate_SCardRemoveReaderFromGroupW(SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext,
	                                    LPCWSTR szReaderName, LPCWSTR szGroupName);

	FREERDP_API LONG WINAPI Emulate_SCardIntroduceCardTypeA(
	    SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szCardName,
	    LPCGUID pguidPrimaryProvider, LPCGUID rgguidInterfaces, DWORD dwInterfaceCount,
	    LPCBYTE pbAtr, LPCBYTE pbAtrMask, DWORD cbAtrLen);

	FREERDP_API LONG WINAPI Emulate_SCardIntroduceCardTypeW(
	    SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szCardName,
	    LPCGUID pguidPrimaryProvider, LPCGUID rgguidInterfaces, DWORD dwInterfaceCount,
	    LPCBYTE pbAtr, LPCBYTE pbAtrMask, DWORD cbAtrLen);

	FREERDP_API LONG WINAPI Emulate_SCardSetCardTypeProviderNameA(
	    SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szCardName,
	    DWORD dwProviderId, LPCSTR szProvider);

	FREERDP_API LONG WINAPI Emulate_SCardSetCardTypeProviderNameW(
	    SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szCardName,
	    DWORD dwProviderId, LPCWSTR szProvider);

	FREERDP_API LONG WINAPI Emulate_SCardForgetCardTypeA(SCARDAPICONTEXT hSCardApi,
	                                                     SCARDCONTEXT hContext, LPCSTR szCardName);

	FREERDP_API LONG WINAPI Emulate_SCardForgetCardTypeW(SCARDAPICONTEXT hSCardApi,
	                                                     SCARDCONTEXT hContext, LPCWSTR szCardName);

	FREERDP_API LONG WINAPI Emulate_SCardFreeMemory(SCARDAPICONTEXT hSCardApi,
	                                                SCARDCONTEXT hContext, LPVOID pvMem);

	FREERDP_API HANDLE WINAPI Emulate_SCardAccessStartedEvent(SCARDAPICONTEXT hSCardApi);

	FREERDP_API void WINAPI Emulate_SCardReleaseStartedEvent(SCARDAPICONTEXT hSCardApi);

	FREERDP_API LONG WINAPI Emulate_SCardLocateCardsA(SCARDAPICONTEXT hSCardApi,
	                                                  SCARDCONTEXT hContext, LPCSTR mszCards,
	                                                  LPSCARD_READERSTATEA rgReaderStates,
	                                                  DWORD cReaders);

	FREERDP_API LONG WINAPI Emulate_SCardLocateCardsW(SCARDAPICONTEXT hSCardApi,
	                                                  SCARDCONTEXT hContext, LPCWSTR mszCards,
	                                                  LPSCARD_READERSTATEW rgReaderStates,
	                                                  DWORD cReaders);

	FREERDP_API LONG WINAPI Emulate_SCardLocateCardsByATRA(SCARDAPICONTEXT hSCardApi,
	                                                       SCARDCONTEXT hContext,
	                                                       LPSCARD_ATRMASK rgAtrMasks, DWORD cAtrs,
	                                                       LPSCARD_READERSTATEA rgReaderStates,
	                                                       DWORD cReaders);

	FREERDP_API LONG WINAPI Emulate_SCardLocateCardsByATRW(SCARDAPICONTEXT hSCardApi,
	                                                       SCARDCONTEXT hContext,
	                                                       LPSCARD_ATRMASK rgAtrMasks, DWORD cAtrs,
	                                                       LPSCARD_READERSTATEW rgReaderStates,
	                                                       DWORD cReaders);

	FREERDP_API LONG WINAPI Emulate_SCardGetStatusChangeA(SCARDAPICONTEXT hSCardApi,
	                                                      SCARDCONTEXT hContext, DWORD dwTimeout,
	                                                      LPSCARD_READERSTATEA rgReaderStates,
	                                                      DWORD cReaders);

	FREERDP_API LONG WINAPI Emulate_SCardGetStatusChangeW(SCARDAPICONTEXT hSCardApi,
	                                                      SCARDCONTEXT hContext, DWORD dwTimeout,
	                                                      LPSCARD_READERSTATEW rgReaderStates,
	                                                      DWORD cReaders);

	FREERDP_API LONG WINAPI Emulate_SCardCancel(SCARDAPICONTEXT hSCardApi,
	                                            SCARDCONTEXT hContext);

	FREERDP_API LONG WINAPI Emulate_SCardConnectA(SCARDAPICONTEXT hSCardApi,
	                                              SCARDCONTEXT hContext, LPCSTR szReader,
	                                              DWORD dwShareMode, DWORD dwPreferredProtocols,
	                                              LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol);

	FREERDP_API LONG WINAPI Emulate_SCardConnectW(SCARDAPICONTEXT hSCardApi,
	                                              SCARDCONTEXT hContext, LPCWSTR szReader,
	                                              DWORD dwShareMode, DWORD dwPreferredProtocols,
	                                              LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol);

	FREERDP_API LONG WINAPI Emulate_SCardReconnect(SCARDAPICONTEXT hSCardApi,
	                                               SCARDHANDLE hCard, DWORD dwShareMode,
	                                               DWORD dwPreferredProtocols,
	                                               DWORD dwInitialization,
	                                               LPDWORD pdwActiveProtocol);

	FREERDP_API LONG WINAPI Emulate_SCardDisconnect(SCARDAPICONTEXT hSCardApi,
	                                                SCARDHANDLE hCard, DWORD dwDisposition);

	FREERDP_API LONG WINAPI Emulate_SCardBeginTransaction(SCARDAPICONTEXT hSCardApi,
	                                                      SCARDHANDLE hCard);

	FREERDP_API LONG WINAPI Emulate_SCardEndTransaction(SCARDAPICONTEXT hSCardApi,
	                                                    SCARDHANDLE hCard, DWORD dwDisposition);

	FREERDP_API LONG WINAPI Emulate_SCardCancelTransaction(SCARDAPICONTEXT hSCardApi,
	                                                       SCARDHANDLE hCard);

	FREERDP_API LONG WINAPI Emulate_SCardState(SCARDAPICONTEXT hSCardApi,
	                                           SCARDHANDLE hCard, LPDWORD pdwState,
	                                           LPDWORD pdwProtocol, LPBYTE pbAtr,
	                                           LPDWORD pcbAtrLen);

	FREERDP_API LONG WINAPI Emulate_SCardStatusA(SCARDAPICONTEXT hSCardApi,
	                                             SCARDHANDLE hCard, LPSTR mszReaderNames,
	                                             LPDWORD pcchReaderLen, LPDWORD pdwState,
	                                             LPDWORD pdwProtocol, LPBYTE pbAtr,
	                                             LPDWORD pcbAtrLen);

	FREERDP_API LONG WINAPI Emulate_SCardStatusW(SCARDAPICONTEXT hSCardApi,
	                                             SCARDHANDLE hCard, LPWSTR mszReaderNames,
	                                             LPDWORD pcchReaderLen, LPDWORD pdwState,
	                                             LPDWORD pdwProtocol, LPBYTE pbAtr,
	                                             LPDWORD pcbAtrLen);

	FREERDP_API LONG WINAPI Emulate_SCardTransmit(SCARDAPICONTEXT hSCardApi,
	                                              SCARDHANDLE hCard, LPCSCARD_IO_REQUEST pioSendPci,
	                                              LPCBYTE pbSendBuffer, DWORD cbSendLength,
	                                              LPSCARD_IO_REQUEST pioRecvPci,
	                                              LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength);

	FREERDP_API LONG WINAPI Emulate_SCardGetTransmitCount(SCARDAPICONTEXT hSCardApi,
	                                                      SCARDHANDLE hCard,
	                                                      LPDWORD pcTransmitCount);

	FREERDP_API LONG WINAPI Emulate_SCardControl(SCARDAPICONTEXT hSCardApi,
	                                             SCARDHANDLE hCard, DWORD dwControlCode,
	                                             LPCVOID lpInBuffer, DWORD cbInBufferSize,
	                                             LPVOID lpOutBuffer, DWORD cbOutBufferSize,
	                                             LPDWORD lpBytesReturned);

	FREERDP_API LONG WINAPI Emulate_SCardGetAttrib(SCARDAPICONTEXT hSCardApi,
	                                               SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr,
	                                               LPDWORD pcbAttrLen);

	FREERDP_API LONG WINAPI Emulate_SCardSetAttrib(SCARDAPICONTEXT hSCardApi,
	                                               SCARDHANDLE hCard, DWORD dwAttrId,
	                                               LPCBYTE pbAttr, DWORD cbAttrLen);

	FREERDP_API LONG WINAPI Emulate_SCardUIDlgSelectCardA(SCARDAPICONTEXT hSCardApi,
	                                                      LPOPENCARDNAMEA_EX pDlgStruc);

	FREERDP_API LONG WINAPI Emulate_SCardUIDlgSelectCardW(SCARDAPICONTEXT hSCardApi,
	                                                      LPOPENCARDNAMEW_EX pDlgStruc);

	FREERDP_API LONG WINAPI Emulate_GetOpenCardNameA(SCARDAPICONTEXT hSCardApi,
	                                                 LPOPENCARDNAMEA pDlgStruc);

	FREERDP_API LONG WINAPI Emulate_GetOpenCardNameW(SCARDAPICONTEXT hSCardApi,
	                                                 LPOPENCARDNAMEW pDlgStruc);

	FREERDP_API LONG WINAPI Emulate_SCardDlgExtendedError(SCARDAPICONTEXT hSCardApi);

	FREERDP_API LONG WINAPI Emulate_SCardReadCacheA(SCARDAPICONTEXT hSCardApi,
	                                                SCARDCONTEXT hContext, UUID* CardIdentifier,
	                                                DWORD FreshnessCounter, LPSTR LookupName,
	                                                PBYTE Data, DWORD* DataLen);

	FREERDP_API LONG WINAPI Emulate_SCardReadCacheW(SCARDAPICONTEXT hSCardApi,
	                                                SCARDCONTEXT hContext, UUID* CardIdentifier,
	                                                DWORD FreshnessCounter, LPWSTR LookupName,
	                                                PBYTE Data, DWORD* DataLen);

	FREERDP_API LONG WINAPI Emulate_SCardWriteCacheA(SCARDAPICONTEXT hSCardApi,
	                                                 SCARDCONTEXT hContext, UUID* CardIdentifier,
	                                                 DWORD FreshnessCounter, LPSTR LookupName,
	                                                 PBYTE Data, DWORD DataLen);

	FREERDP_API LONG WINAPI Emulate_SCardWriteCacheW(SCARDAPICONTEXT hSCardApi,
	                                                 SCARDCONTEXT hContext, UUID* CardIdentifier,
	                                                 DWORD FreshnessCounter, LPWSTR LookupName,
	                                                 PBYTE Data, DWORD DataLen);

	FREERDP_API LONG WINAPI Emulate_SCardGetReaderIconA(SCARDAPICONTEXT hSCardApi,
	                                                    SCARDCONTEXT hContext, LPCSTR szReaderName,
	                                                    LPBYTE pbIcon, LPDWORD pcbIcon);

	FREERDP_API LONG WINAPI Emulate_SCardGetReaderIconW(SCARDAPICONTEXT hSCardApi,
	                                                    SCARDCONTEXT hContext, LPCWSTR szReaderName,
	                                                    LPBYTE pbIcon, LPDWORD pcbIcon);

	FREERDP_API LONG WINAPI Emulate_SCardGetDeviceTypeIdA(SCARDAPICONTEXT hSCardApi,
	                                                      SCARDCONTEXT hContext,
	                                                      LPCSTR szReaderName,
	                                                      LPDWORD pdwDeviceTypeId);
	FREERDP_API LONG WINAPI Emulate_SCardGetDeviceTypeIdW(SCARDAPICONTEXT hSCardApi,
	                                                      SCARDCONTEXT hContext,
	                                                      LPCWSTR szReaderName,
	                                                      LPDWORD pdwDeviceTypeId);

	FREERDP_API LONG WINAPI Emulate_SCardGetReaderDeviceInstanceIdA(
	    SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szReaderName,
	    LPSTR szDeviceInstanceId, LPDWORD pcchDeviceInstanceId);

	FREERDP_API LONG WINAPI Emulate_SCardGetReaderDeviceInstanceIdW(
	    SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szReaderName,
	    LPWSTR szDeviceInstanceId, LPDWORD pcchDeviceInstanceId);
	FREERDP_API LONG WINAPI Emulate_SCardListReadersWithDeviceInstanceIdA(
	    SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCSTR szDeviceInstanceId,
	    LPSTR mszReaders, LPDWORD pcchReaders);
	FREERDP_API LONG WINAPI Emulate_SCardListReadersWithDeviceInstanceIdW(
	    SCARDAPICONTEXT hSCardApi, SCARDCONTEXT hContext, LPCWSTR szDeviceInstanceId,
	    LPWSTR mszReaders, LPDWORD pcchReaders);
	FREERDP_API LONG WINAPI Emulate_SCardAudit(SCARDAPICONTEXT hSCardApi,
	                                           SCARDCONTEXT hContext, DWORD dwEvent);

    FREERDP_API const SCardApiFunctionTableEx* Emulate_GetSCardApiFunctionTableEx(void);

#ifdef __cplusplus
}
#endif

#endif /* WINPR_SMARTCARD_EMULATE_PRIVATE_H */
