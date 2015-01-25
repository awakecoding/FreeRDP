/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * RDPUDP Datagram Transport Layer Security
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

#ifndef __RDPUDP_DTLS_H
#define __RDPUDP_DTLS_H

#include <winpr/crt.h>
#include <winpr/sspi.h>
#include <winpr/stream.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <freerdp/api.h>
#include <freerdp/log.h>
#include <freerdp/types.h>

#include <freerdp/crypto/crypto.h>
#include <freerdp/crypto/certificate.h>

typedef struct rdp_udp_dtls rdpUdpDtls;

struct rdp_udp_dtls
{
	SSL* ssl;
	BIO* bio;
	int sockfd;
	SSL_CTX* ctx;
	BYTE* PublicKey;
	BIO_METHOD* methods;
	DWORD PublicKeyLength;
	rdpSettings* settings;
	SecPkgContext_Bindings* Bindings;
	rdpCertificateStore* certificate_store;
	char* hostname;
	int port;
};

FREERDP_API BOOL rdp_udp_dtls_connect(rdpUdpDtls* dtls);
FREERDP_API BOOL rdp_udp_dtls_disconnect(rdpUdpDtls* dtls);

FREERDP_API int rdp_udp_dtls_read(rdpUdpDtls* dtls, BYTE* data, int length);
FREERDP_API int rdp_udp_dtls_write(rdpUdpDtls* dtls, BYTE* data, int length);

FREERDP_API BOOL rdp_udp_dtls_match_hostname(char* pattern, int pattern_length, char *hostname);
FREERDP_API BOOL rdp_udp_dtls_verify_certificate(rdpUdpDtls* dtls, CryptoCert cert, char* hostname, int port);
FREERDP_API void rdp_udp_dtls_print_certificate_error(char* hostname, char* fingerprint, char* hosts_file);
FREERDP_API void rdp_udp_dtls_print_certificate_name_mismatch_error(char* hostname, char* common_name, char** alt_names, int alt_names_count);

FREERDP_API BOOL rdp_udp_dtls_print_error(char* func, SSL* connection, int value);

rdpUdpDtls* rdp_udp_dtls_new(rdpSettings* settings);
void rdp_udp_dtls_free(rdpUdpDtls* dtls);

#endif /* __RDPUDP_DTLS_H */
