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
 *		 http://www.apache.org/licenses/LICENSE-2.0
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

#include <assert.h>

#include <winpr/crt.h>
#include <winpr/ssl.h>
#include <winpr/sspi.h>
#include <winpr/stream.h>
#include <winpr/winsock.h>

#include "udpr.h"

#define TAG FREERDP_TAG("core.udp")

#define TLS_STATE_UNINITIALIZED		0
#define TLS_STATE_INITIALIZED		1
#define TLS_STATE_CONNECTED		2
#define TLS_STATE_DISCONNECTED		3
#define TLS_STATE_ERROR			4

#define TLS_BUFFER_SIZE			1200

static CryptoCert rdp_udp_tls_get_certificate(rdpUdpTls* tls, BOOL peer)
{
	CryptoCert cert;
	X509* server_cert;

	if (peer)
		server_cert = SSL_get_peer_certificate(tls->ssl);
	else
		server_cert = SSL_get_certificate(tls->ssl);

	if (!server_cert)
	{
		fprintf(stderr, "rdp_udp_tls_get_certificate: failed to get the server TLS certificate\n");
		cert = NULL;
	}
	else
	{
		cert = malloc(sizeof(*cert));
		cert->px509 = server_cert;
	}

	return cert;
}

static void rdp_udp_tls_free_certificate(CryptoCert cert)
{
	X509_free(cert->px509);
	free(cert);
}

#define TLS_SERVER_END_POINT	"tls-server-end-point:"

SecPkgContext_Bindings* rdp_udp_tls_get_channel_bindings(X509* cert)
{
	int PrefixLength;
	BYTE CertificateHash[32];
	UINT32 CertificateHashLength;
	BYTE* ChannelBindingToken;
	UINT32 ChannelBindingTokenLength;
	SEC_CHANNEL_BINDINGS* ChannelBindings;
	SecPkgContext_Bindings* ContextBindings;

	ZeroMemory(CertificateHash, sizeof(CertificateHash));
	X509_digest(cert, EVP_sha256(), CertificateHash, &CertificateHashLength);

	PrefixLength = strlen(TLS_SERVER_END_POINT);
	ChannelBindingTokenLength = PrefixLength + CertificateHashLength;

	ContextBindings = (SecPkgContext_Bindings*) calloc(1, sizeof(SecPkgContext_Bindings));

	ContextBindings->BindingsLength = sizeof(SEC_CHANNEL_BINDINGS) + ChannelBindingTokenLength;
	ChannelBindings = (SEC_CHANNEL_BINDINGS*) calloc(1, ContextBindings->BindingsLength);
	ContextBindings->Bindings = ChannelBindings;

	ChannelBindings->cbApplicationDataLength = ChannelBindingTokenLength;
	ChannelBindings->dwApplicationDataOffset = sizeof(SEC_CHANNEL_BINDINGS);
	ChannelBindingToken = &((BYTE*) ChannelBindings)[ChannelBindings->dwApplicationDataOffset];

	strcpy((char*) ChannelBindingToken, TLS_SERVER_END_POINT);
	CopyMemory(&ChannelBindingToken[PrefixLength], CertificateHash, CertificateHashLength);

	return ContextBindings;
}

void rdp_udp_tls_ssl_info_callback(const SSL* ssl, int type, int val)
{
	if (type & SSL_CB_HANDSHAKE_START)
	{

	}
}

static BOOL rdp_udp_tls_init(rdpUdpTls* tls)
{
	int status;
	long options = 0;

	switch (tls->state)
	{
		case TLS_STATE_UNINITIALIZED:
			break;

		case TLS_STATE_ERROR:
			return FALSE;

		default:
			return TRUE;
	}

	tls->ctx = SSL_CTX_new(TLSv1_client_method());

	if (!tls->ctx)
	{
		fprintf(stderr, "SSL_CTX_new failed\n");
		return FALSE;
	}

	//SSL_CTX_set_mode(tls->ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);

	/**
	 * SSL_OP_NO_COMPRESSION:
	 *
	 * The Microsoft RDP server does not advertise support
	 * for TLS compression, but alternative servers may support it.
	 * This was observed between early versions of the FreeRDP server
	 * and the FreeRDP client, and caused major performance issues,
	 * which is why we're disabling it.
	 */
#ifdef SSL_OP_NO_COMPRESSION
	options |= SSL_OP_NO_COMPRESSION;
#endif
	 
	/**
	 * SSL_OP_TLS_BLOCK_PADDING_BUG:
	 *
	 * The Microsoft RDP server does *not* support TLS padding.
	 * It absolutely needs to be disabled otherwise it won't work.
	 */
	options |= SSL_OP_TLS_BLOCK_PADDING_BUG;

	/**
	 * SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS:
	 *
	 * Just like TLS padding, the Microsoft RDP server does not
	 * support empty fragments. This needs to be disabled.
	 */
	options |= SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;

	SSL_CTX_set_options(tls->ctx, options);

	tls->ssl = SSL_new(tls->ctx);

	if (!tls->ssl)
	{
		fprintf(stderr, "SSL_new failed\n");
		return FALSE;
	}

	tls->bioRead = BIO_new(BIO_s_mem());

	if (!tls->bioRead)
	{
		fprintf(stderr, "BIO_new failed\n");
		return FALSE;
	}

	tls->readBuffer = (BYTE*) malloc(TLS_BUFFER_SIZE);

	if (!tls->readBuffer)
	{
		fprintf(stderr, "malloc failed\n");
		return FALSE;
	}

	status = BIO_set_write_buf_size(tls->bioRead, TLS_BUFFER_SIZE);

	tls->bioWrite = BIO_new(BIO_s_mem());

	if (!tls->bioWrite)
	{
		fprintf(stderr, "BIO_new failed\n");
		return FALSE;
	}

	tls->writeBuffer = (BYTE*) malloc(TLS_BUFFER_SIZE);

	if (!tls->writeBuffer)
	{
		fprintf(stderr, "malloc failed\n");
		return FALSE;
	}

	status = BIO_set_write_buf_size(tls->bioWrite, TLS_BUFFER_SIZE);

	BIO_make_bio_pair(tls->bioRead, tls->bioWrite);

	SSL_set_bio(tls->ssl, tls->bioRead, tls->bioWrite);

	tls->state = TLS_STATE_INITIALIZED;

	return TRUE;
}

BOOL rdp_udp_tls_connect(rdpUdpTls* tls)
{
	int status;
	int error;
	CryptoCert cert;

	if (!rdp_udp_tls_init(tls))
	{
		return FALSE;
	}

	status = SSL_connect(tls->ssl);

	if (status <= 0)
	{
		error = SSL_get_error(tls->ssl, status);

		if (error != SSL_ERROR_WANT_READ)
			fprintf(stderr, "rdp_udp_tls_connect: status: %d error: 0x%08X\n", status, error);

		tls->lastError = error;

		return FALSE;
	}

	cert = rdp_udp_tls_get_certificate(tls, TRUE);

	if (!cert)
	{
		fprintf(stderr, "rdp_udp_tls_connect: rdp_udp_tls_get_certificate failed to return the server certificate.\n");
		return FALSE;
	}

	tls->Bindings = rdp_udp_tls_get_channel_bindings(cert->px509);

	if (!crypto_cert_get_public_key(cert, &tls->PublicKey, &tls->PublicKeyLength))
	{
		fprintf(stderr, "rdp_udp_tls_connect: crypto_cert_get_public_key failed to return the server public key.\n");
		rdp_udp_tls_free_certificate(cert);
		return FALSE;
	}

	if (!rdp_udp_tls_verify_certificate(tls, cert, tls->hostname, tls->port))
	{
		fprintf(stderr, "rdp_udp_tls_connect: certificate not trusted, aborting.\n");
		rdp_udp_tls_disconnect(tls);
		rdp_udp_tls_free_certificate(cert);
		return FALSE;
	}

	rdp_udp_tls_free_certificate(cert);

	return TRUE;
}

BOOL rdp_udp_tls_accept(rdpUdpTls* tls, const char* cert_file, const char* privatekey_file)
{
	CryptoCert cert;
	long options = 0;
	int connection_status;

	tls->ctx = SSL_CTX_new(SSLv23_server_method());

	if (!tls->ctx)
	{
		fprintf(stderr, "SSL_CTX_new failed\n");
		return FALSE;
	}

	/*
	 * SSL_OP_NO_SSLv2:
	 *
	 * We only want SSLv3 and TLSv1, so disable SSLv2.
	 * SSLv3 is used by, eg. Microsoft RDC for Mac OS X.
	 */
	options |= SSL_OP_NO_SSLv2;

	/**
	 * SSL_OP_NO_COMPRESSION:
	 *
	 * The Microsoft RDP server does not advertise support
	 * for TLS compression, but alternative servers may support it.
	 * This was observed between early versions of the FreeRDP server
	 * and the FreeRDP client, and caused major performance issues,
	 * which is why we're disabling it.
	 */
#ifdef SSL_OP_NO_COMPRESSION
	options |= SSL_OP_NO_COMPRESSION;
#endif
	 
	/**
	 * SSL_OP_TLS_BLOCK_PADDING_BUG:
	 *
	 * The Microsoft RDP server does *not* support TLS padding.
	 * It absolutely needs to be disabled otherwise it won't work.
	 */
	options |= SSL_OP_TLS_BLOCK_PADDING_BUG;

	/**
	 * SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS:
	 *
	 * Just like TLS padding, the Microsoft RDP server does not
	 * support empty fragments. This needs to be disabled.
	 */
	options |= SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;

	SSL_CTX_set_options(tls->ctx, options);

	if (SSL_CTX_use_RSAPrivateKey_file(tls->ctx, privatekey_file, SSL_FILETYPE_PEM) <= 0)
	{
		fprintf(stderr, "SSL_CTX_use_RSAPrivateKey_file failed\n");
		fprintf(stderr, "PrivateKeyFile: %s\n", privatekey_file);
		return FALSE;
	}

	tls->ssl = SSL_new(tls->ctx);

	if (!tls->ssl)
	{
		fprintf(stderr, "SSL_new failed\n");
		return FALSE;
	}

	if (SSL_use_certificate_file(tls->ssl, cert_file, SSL_FILETYPE_PEM) <= 0)
	{
		fprintf(stderr, "SSL_use_certificate_file failed\n");
		return FALSE;
	}

	if (SSL_set_fd(tls->ssl, tls->sockfd) < 1)
	{
		fprintf(stderr, "SSL_set_fd failed\n");
		return FALSE;
	}

	while (1)
	{
		connection_status = SSL_accept(tls->ssl);

		if (connection_status <= 0)
		{
			switch (SSL_get_error(tls->ssl, connection_status))
			{
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_WRITE:
					break;

				default:
					if (rdp_udp_tls_print_error("SSL_accept", tls->ssl, connection_status))
						return FALSE;
					break;

			}
		}
		else
		{
			break;
		}
	}

	cert = rdp_udp_tls_get_certificate(tls, FALSE);

	if (!cert)
	{
		fprintf(stderr, "rdp_udp_tls_connect: rdp_udp_tls_get_certificate failed to return the server certificate.\n");
		return FALSE;
	}

	if (!crypto_cert_get_public_key(cert, &tls->PublicKey, &tls->PublicKeyLength))
	{
		fprintf(stderr, "rdp_udp_tls_connect: crypto_cert_get_public_key failed to return the server public key.\n");
		rdp_udp_tls_free_certificate(cert);
		return FALSE;
	}

	free(cert);

	fprintf(stderr, "TLS connection accepted\n");

	return TRUE;
}

BOOL rdp_udp_tls_disconnect(rdpUdpTls* tls)
{
	if (!tls)
		return FALSE;

	if (tls->ssl)
	{
		if (tls->alertDescription != TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY)
		{
			/**
			 * OpenSSL doesn't really expose an API for sending a TLS alert manually.
			 *
			 * The following code disables the sending of the default "close notify"
			 * and then proceeds to force sending a custom TLS alert before shutting down.
			 *
			 * Manually sending a TLS alert is necessary in certain cases,
			 * like when server-side NLA results in an authentication failure.
			 */

			SSL_set_quiet_shutdown(tls->ssl, 1);

			if ((tls->alertLevel == TLS_ALERT_LEVEL_FATAL) && (tls->ssl->session))
				SSL_CTX_remove_session(tls->ssl->ctx, tls->ssl->session);

			tls->ssl->s3->alert_dispatch = 1;
			tls->ssl->s3->send_alert[0] = tls->alertLevel;
			tls->ssl->s3->send_alert[1] = tls->alertDescription;

			if (tls->ssl->s3->wbuf.left == 0)
				tls->ssl->method->ssl_dispatch_alert(tls->ssl);

			SSL_shutdown(tls->ssl);
		}
		else
		{
			SSL_shutdown(tls->ssl);
		}
	}

	return TRUE;
}

int rdp_udp_tls_decrypt(rdpUdpTls* tls, BYTE* data, int length)
{
	int error;
	int status;

	if (!tls || !tls->ssl)
		return -1;

	status = SSL_read(tls->ssl, data, length);

	if (status < 0)
	{
		error = SSL_get_error(tls->ssl, status);

		switch (error)
		{
			case SSL_ERROR_NONE:
				status = 0;
				break;

			default:
				status = -1;
				break;
		}
	}

	return status;
}

int rdp_udp_tls_encrypt(rdpUdpTls* tls, BYTE* data, int length)
{
	int error;
	int status;

	if (!tls || !tls->ssl)
		return -1;

	status = SSL_write(tls->ssl, data, length);

	if (status < 0)
	{
		error = SSL_get_error(tls->ssl, status);

		switch (error)
		{
			case SSL_ERROR_NONE:
				status = 0;
				break;

			default:
				status = -1;
				break;
		}
	}

	return status;
}

int rdp_udp_tls_read(rdpUdpTls* tls, BYTE* data, int length)
{
	int error;
	int status;

	if (!tls)
		return -1;

	if (!tls->ssl)
		return -1;

	status = BIO_read(tls->bioWrite, data, length);

	if (status == 0)
	{
		return -1; /* peer disconnected */
	}

	if (status <= 0)
	{
		error = SSL_get_error(tls->ssl, status);

		//fprintf(stderr, "rdp_udp_tls_read: length: %d status: %d error: 0x%08X\n",
		//		length, status, error);

		switch (error)
		{
			case SSL_ERROR_NONE:
				break;

			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				status = 0;
				break;

			case SSL_ERROR_SYSCALL:
				if ((errno == EAGAIN) || (errno == 0))
				{
					status = 0;
				}
				else
				{
					rdp_udp_tls_print_error("SSL_read", tls->ssl, status);
					status = -1;
				}
				break;

			default:
				rdp_udp_tls_print_error("SSL_read", tls->ssl, status);
				status = -1;
				break;
		}
	}

	return status;
}

int rdp_udp_tls_write(rdpUdpTls* tls, BYTE* data, int length)
{
	int error;
	int status;

	if (!tls)
		return -1;

	if (!tls->ssl)
		return -1;

	status = BIO_write(tls->bioRead, data, length);

	if (status <= 0)
	{
		error = SSL_get_error(tls->ssl, status);

		//fprintf(stderr, "rdp_udp_tls_write: length: %d status: %d error: 0x%08X\n", length, status, error);

		switch (error)
		{
			case SSL_ERROR_NONE:
				break;

			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				status = 0;
				break;

			case SSL_ERROR_SYSCALL:
				if (errno == EAGAIN)
				{
					status = 0;
				}
				else
				{
					rdp_udp_tls_print_error("SSL_write", tls->ssl, status);
					status = -1;
				}
				break;

			default:
				rdp_udp_tls_print_error("SSL_write", tls->ssl, status);
				status = -1;
				break;
		}
	}

	return status;
}

int rdp_udp_tls_get_last_error(rdpUdpTls* tls)
{
	return tls->lastError;
}

static void rdp_udp_tls_errors(const char *prefix)
{
	unsigned long error;

	while ((error = ERR_get_error()) != 0)
		fprintf(stderr, "%s: %s\n", prefix, ERR_error_string(error, NULL));
}

BOOL rdp_udp_tls_print_error(char* func, SSL* connection, int value)
{
	switch (SSL_get_error(connection, value))
	{
		case SSL_ERROR_ZERO_RETURN:
			fprintf(stderr, "%s: Server closed TLS connection\n", func);
			return TRUE;

		case SSL_ERROR_WANT_READ:
			fprintf(stderr, "%s: SSL_ERROR_WANT_READ\n", func);
			return FALSE;

		case SSL_ERROR_WANT_WRITE:
			fprintf(stderr, "%s: SSL_ERROR_WANT_WRITE\n", func);
			return FALSE;

		case SSL_ERROR_SYSCALL:
			fprintf(stderr, "%s: I/O error: %s (%d)\n", func, strerror(errno), errno);
			rdp_udp_tls_errors(func);
			return TRUE;

		case SSL_ERROR_SSL:
			fprintf(stderr, "%s: Failure in SSL library (protocol error?)\n", func);
			rdp_udp_tls_errors(func);
			return TRUE;

		default:
			fprintf(stderr, "%s: Unknown error\n", func);
			rdp_udp_tls_errors(func);
			return TRUE;
	}
}

int rdp_udp_tls_set_alert_code(rdpUdpTls* tls, int level, int description)
{
	tls->alertLevel = level;
	tls->alertDescription = description;

	return 0;
}

BOOL rdp_udp_tls_match_hostname(char *pattern, int pattern_length, char *hostname)
{
	if (strlen(hostname) == pattern_length)
	{
		if (memcmp((void*) hostname, (void*) pattern, pattern_length) == 0)
			return TRUE;
	}

	if (pattern_length > 2 && pattern[0] == '*' && pattern[1] == '.' && strlen(hostname) >= pattern_length)
	{
		char *check_hostname = &hostname[ strlen(hostname) - pattern_length+1 ];
		if (memcmp((void*) check_hostname, (void*) &pattern[1], pattern_length - 1) == 0 )
		{
			return TRUE;
		}
	}

	return FALSE;
}

BOOL rdp_udp_tls_verify_certificate(rdpUdpTls* tls, CryptoCert cert, char* hostname, int port)
{
	int match;
	int index;
	char* common_name = NULL;
	int common_name_length = 0;
	char** alt_names = NULL;
	int alt_names_count = 0;
	int* alt_names_lengths = NULL;
	BOOL certificate_status;
	BOOL hostname_match = FALSE;
	BOOL verification_status = FALSE;
	rdpCertificateData* certificate_data;

	if (tls->settings->ExternalCertificateManagement)
	{
		BIO* bio;
		int status;
		int length;
		int offset;
		BYTE* pemCert;
		freerdp* instance = (freerdp*) tls->settings->instance;

		/**
		 * Don't manage certificates internally, leave it up entirely to the external client implementation
		 */

		bio = BIO_new(BIO_s_mem());
		
		if (!bio)
		{
			fprintf(stderr, "rdp_udp_tls_verify_certificate: BIO_new() failure\n");
			return FALSE;
		}

		status = PEM_write_bio_X509(bio, cert->px509);

		if (status < 0)
		{
			fprintf(stderr, "rdp_udp_tls_verify_certificate: PEM_write_bio_X509 failure: %d\n", status);
			return FALSE;
		}
		
		offset = 0;
		length = 2048;
		pemCert = (BYTE*) malloc(length + 1);

		status = BIO_read(bio, pemCert, length);
		
		if (status < 0)
		{
			fprintf(stderr, "rdp_udp_tls_verify_certificate: failed to read certificate\n");
			return FALSE;
		}
		
		offset += status;

		while (offset >= length)
		{
			length *= 2;
			pemCert = (BYTE*) realloc(pemCert, length + 1);

			status = BIO_read(bio, &pemCert[offset], length);

			if (status < 0)
				break;

			offset += status;
		}

		if (status < 0)
		{
			fprintf(stderr, "rdp_udp_tls_verify_certificate: failed to read certificate\n");
			return FALSE;
		}
		
		length = offset;
		pemCert[length] = '\0';

		status = -1;
		
		if (instance->VerifyX509Certificate)
		{
			status = instance->VerifyX509Certificate(instance, pemCert, length, hostname, port, 0);
		}
		
		fprintf(stderr, "VerifyX509Certificate: (length = %d) status: %d\n%s\n",
			length, status, pemCert);

		free(pemCert);
		BIO_free(bio);

		return (status < 0) ? FALSE : TRUE;
	}

	/* ignore certificate verification if user explicitly required it (discouraged) */
	if (tls->settings->IgnoreCertificate)
		return TRUE;  /* success! */

	/* if user explicitly specified a certificate name, use it instead of the hostname */
	if (tls->settings->CertificateName)
		hostname = tls->settings->CertificateName;

	/* attempt verification using OpenSSL and the ~/.freerdp/certs certificate store */
	certificate_status = x509_verify_certificate(cert, tls->certificate_store->path);

	/* verify certificate name match */
	certificate_data = crypto_get_certificate_data(cert->px509, hostname);

	/* extra common name and alternative names */
	common_name = crypto_cert_subject_common_name(cert->px509, &common_name_length);
	alt_names = crypto_cert_subject_alt_name(cert->px509, &alt_names_count, &alt_names_lengths);

	/* compare against common name */

	if (common_name != NULL)
	{
		if (rdp_udp_tls_match_hostname(common_name, common_name_length, hostname))
			hostname_match = TRUE;
	}

	/* compare against alternative names */

	if (alt_names != NULL)
	{
		for (index = 0; index < alt_names_count; index++)
		{
			if (rdp_udp_tls_match_hostname(alt_names[index], alt_names_lengths[index], hostname))
			{
				hostname_match = TRUE;
				break;
			}
		}
	}

	/* if the certificate is valid and the certificate name matches, verification succeeds */
	if (certificate_status && hostname_match)
	{
		if (common_name)
		{
			free(common_name);
			common_name = NULL;
		}

		verification_status = TRUE; /* success! */
	}

	/* if the certificate is valid but the certificate name does not match, warn user, do not accept */
	if (certificate_status && !hostname_match)
		rdp_udp_tls_print_certificate_name_mismatch_error(hostname, common_name, alt_names, alt_names_count);

	/* verification could not succeed with OpenSSL, use known_hosts file and prompt user for manual verification */

	if (!certificate_status)
	{
		char* issuer;
		char* subject;
		char* fingerprint;
		freerdp* instance = (freerdp*) tls->settings->instance;
		BOOL accept_certificate = FALSE;

		issuer = crypto_cert_issuer(cert->px509);
		subject = crypto_cert_subject(cert->px509);
		fingerprint = crypto_cert_fingerprint(cert->px509);

		/* search for matching entry in known_hosts file */
		match = certificate_data_match(tls->certificate_store, certificate_data);

		if (match == 1)
		{
			/* no entry was found in known_hosts file, prompt user for manual verification */
			if (!hostname_match)
				rdp_udp_tls_print_certificate_name_mismatch_error(hostname, common_name, alt_names, alt_names_count);

			if (instance->VerifyCertificate)
				accept_certificate = instance->VerifyCertificate(instance, subject, issuer, fingerprint);

			if (!accept_certificate)
			{
				/* user did not accept, abort and do not add entry in known_hosts file */
				verification_status = FALSE; /* failure! */
			}
			else
			{
				/* user accepted certificate, add entry in known_hosts file */
				certificate_data_print(tls->certificate_store, certificate_data);
				verification_status = TRUE; /* success! */
			}
		}
		else if (match == -1)
		{
			/* entry was found in known_hosts file, but fingerprint does not match. ask user to use it */
			rdp_udp_tls_print_certificate_error(hostname, fingerprint, tls->certificate_store->file);
			
			if (instance->VerifyChangedCertificate)
				accept_certificate = instance->VerifyChangedCertificate(instance, subject, issuer, fingerprint, "");

			if (!accept_certificate)
			{
				/* user did not accept, abort and do not change known_hosts file */
				verification_status = FALSE;  /* failure! */
			}
			else
			{
				/* user accepted new certificate, add replace fingerprint for this host in known_hosts file */
				certificate_data_replace(tls->certificate_store, certificate_data);
				verification_status = TRUE; /* success! */
			}
		}
		else if (match == 0)
		{
			verification_status = TRUE; /* success! */
		}

		free(issuer);
		free(subject);
		free(fingerprint);
	}

	if (certificate_data)
	{
		free(certificate_data->fingerprint);
		free(certificate_data->hostname);
		free(certificate_data);
	}

#ifndef _WIN32
	if (common_name)
		free(common_name);
#endif

	if (alt_names)
		crypto_cert_subject_alt_name_free(alt_names_count, alt_names_lengths,
				alt_names);

	return verification_status;
}

void rdp_udp_tls_print_certificate_error(char* hostname, char* fingerprint, char *hosts_file)
{
	WLog_ERR(TAG,  "The host key for %s has changed", hostname);
	WLog_ERR(TAG,  "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	WLog_ERR(TAG,  "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
	WLog_ERR(TAG,  "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	WLog_ERR(TAG,  "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
	WLog_ERR(TAG,  "Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
	WLog_ERR(TAG,  "It is also possible that a host key has just been changed.");
	WLog_ERR(TAG,  "The fingerprint for the host key sent by the remote host is%s", fingerprint);
	WLog_ERR(TAG,  "Please contact your system administrator.");
	WLog_ERR(TAG,  "Add correct host key in %s to get rid of this message.", hosts_file);
	WLog_ERR(TAG,  "Host key for %s has changed and you have requested strict checking.", hostname);
	WLog_ERR(TAG,  "Host key verification failed.");
}

void rdp_udp_tls_print_certificate_name_mismatch_error(char* hostname, char* common_name, char** alt_names, int alt_names_count)
{
	int index;

	assert(NULL != hostname);
	WLog_ERR(TAG,  "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	WLog_ERR(TAG,  "@           WARNING: CERTIFICATE NAME MISMATCH!           @");
	WLog_ERR(TAG,  "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	WLog_ERR(TAG,  "The hostname used for this connection (%s) ", hostname);
	WLog_ERR(TAG,  "does not match %s given in the certificate:", alt_names_count < 1 ? "the name" : "any of the names");
	WLog_ERR(TAG,  "Common Name (CN):");
	WLog_ERR(TAG,  "\t%s", common_name ? common_name : "no CN found in certificate");

	if (alt_names_count > 0)
	{
		assert(NULL != alt_names);
		WLog_ERR(TAG,  "Alternative names:");
		for (index = 0; index < alt_names_count; index++)
		{
			assert(alt_names[index]);
			WLog_ERR(TAG,  "\t %s", alt_names[index]);
		}
	}
	WLog_ERR(TAG,  "A valid certificate for the wrong name should NOT be trusted!");
}

rdpUdpTls* rdp_udp_tls_new(rdpSettings* settings)
{
	rdpUdpTls* tls;

	tls = (rdpUdpTls*) calloc(1, sizeof(rdpUdpTls));

	if (tls)
	{
		winpr_InitializeSSL(WINPR_SSL_INIT_DEFAULT);

		tls->settings = settings;
		tls->certificate_store = certificate_store_new(settings);

		tls->alertLevel = TLS_ALERT_LEVEL_WARNING;
		tls->alertDescription = TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY;
	}

	return tls;
}

void rdp_udp_tls_free(rdpUdpTls* tls)
{
	if (tls)
	{
		if (tls->ssl)
		{
			SSL_free(tls->ssl);
			tls->ssl = NULL;
		}

		if (tls->ctx)
		{
			SSL_CTX_free(tls->ctx);
			tls->ctx = NULL;
		}

		if (tls->PublicKey)
		{
			free(tls->PublicKey);
			tls->PublicKey = NULL;
		}

		if (tls->Bindings)
		{
			free(tls->Bindings->Bindings);
			free(tls->Bindings);
			tls->Bindings = NULL;
		}

		certificate_store_free(tls->certificate_store);
		tls->certificate_store = NULL;

		free(tls);
	}
}