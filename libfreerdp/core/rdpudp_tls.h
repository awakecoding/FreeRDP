/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * RDP-UDP Transport Layer Security
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

#ifndef __RDPUDP_TLS_H
#define __RDPUDP_TLS_H

#include <winpr/crt.h>
#include <winpr/sspi.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <freerdp/api.h>
#include <freerdp/types.h>

#include <freerdp/crypto/crypto.h>
#include <freerdp/crypto/certificate.h>

#include <winpr/stream.h>

#define TLS_ALERT_LEVEL_WARNING				1
#define TLS_ALERT_LEVEL_FATAL				2

#define TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY		0
#define TLS_ALERT_DESCRIPTION_UNEXPECTED_MESSAGE	10
#define TLS_ALERT_DESCRIPTION_BAD_RECORD_MAC		20
#define TLS_ALERT_DESCRIPTION_DECRYPTION_FAILED		21
#define TLS_ALERT_DESCRIPTION_RECORD_OVERFLOW		22
#define TLS_ALERT_DESCRIPTION_DECOMPRESSION_FAILURE	30
#define TLS_ALERT_DESCRIPTION_HANSHAKE_FAILURE		40
#define TLS_ALERT_DESCRIPTION_NO_CERTIFICATE		41
#define TLS_ALERT_DESCRIPTION_BAD_CERTIFICATE		42
#define TLS_ALERT_DESCRIPTION_UNSUPPORTED_CERTIFICATE	43
#define TLS_ALERT_DESCRIPTION_CERTIFICATE_REVOKED	44
#define TLS_ALERT_DESCRIPTION_CERTIFICATE_EXPIRED	45
#define TLS_ALERT_DESCRIPTION_CERTIFICATE_UNKNOWN	46
#define TLS_ALERT_DESCRIPTION_ILLEGAL_PARAMETER		47
#define TLS_ALERT_DESCRIPTION_UNKNOWN_CA		48
#define TLS_ALERT_DESCRIPTION_ACCESS_DENIED		49
#define TLS_ALERT_DESCRIPTION_DECODE_ERROR		50
#define TLS_ALERT_DESCRIPTION_DECRYPT_ERROR		51
#define TLS_ALERT_DESCRIPTION_EXPORT_RESTRICTION	60
#define TLS_ALERT_DESCRIPTION_PROTOCOL_VERSION		70
#define TLS_ALERT_DESCRIPTION_INSUFFICIENT_SECURITY	71
#define TLS_ALERT_DESCRIPTION_INTERNAL_ERROR		80
#define TLS_ALERT_DESCRIPTION_USER_CANCELED		90
#define TLS_ALERT_DESCRIPTION_NO_RENEGOTIATION		100
#define TLS_ALERT_DESCRIPTION_UNSUPPORTED_EXTENSION	110

typedef struct rdpudp_tls rdpUdpTls;

struct rdpudp_tls
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
	int state;
	int lastError;
	BIO* bioRead;
	BIO* bioWrite;
	BYTE* readBuffer;
	BYTE* writeBuffer;
	char* hostname;
	int port;
	int alertLevel;
	int alertDescription;
};

FREERDP_API BOOL rdpudp_tls_connect(rdpUdpTls* tls);
FREERDP_API BOOL rdpudp_tls_accept(rdpUdpTls* tls, const char* cert_file, const char* privatekey_file);
FREERDP_API BOOL rdpudp_tls_disconnect(rdpUdpTls* tls);

FREERDP_API int rdpudp_tls_decrypt(rdpUdpTls* tls, BYTE* data, int length);
FREERDP_API int rdpudp_tls_encrypt(rdpUdpTls* tls, BYTE* data, int length);

FREERDP_API int rdpudp_tls_read(rdpUdpTls* tls, BYTE* data, int length);
FREERDP_API int rdpudp_tls_write(rdpUdpTls* tls, BYTE* data, int length);

FREERDP_API int rdpudp_tls_get_last_error(rdpUdpTls* tls);

FREERDP_API int rdpudp_tls_set_alert_code(rdpUdpTls* tls, int level, int description);

FREERDP_API BOOL rdpudp_tls_match_hostname(char *pattern, int pattern_length, char *hostname);
FREERDP_API BOOL rdpudp_tls_verify_certificate(rdpUdpTls* tls, CryptoCert cert, char* hostname, int port);
FREERDP_API void rdpudp_tls_print_certificate_error(char* hostname, char* fingerprint, char* hosts_file);
FREERDP_API void rdpudp_tls_print_certificate_name_mismatch_error(char* hostname, char* common_name, char** alt_names, int alt_names_count);

FREERDP_API BOOL rdpudp_tls_print_error(char* func, SSL* connection, int value);

FREERDP_API rdpUdpTls* rdpudp_tls_new(rdpSettings* settings);
FREERDP_API void rdpudp_tls_free(rdpUdpTls* tls);

#endif /* __RDPUDP_TLS_H */