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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include <winpr/crt.h>
#include <winpr/sspi.h>
#include <winpr/stream.h>
#include <winpr/winsock.h>

#include "rdpudp_dtls.h"

static CryptoCert rdpudp_dtls_get_certificate(rdpUdpDtls* dtls, BOOL peer)
{
	CryptoCert cert;
	X509* server_cert;

	if (peer)
		server_cert = SSL_get_peer_certificate(dtls->ssl);
	else
		server_cert = SSL_get_certificate(dtls->ssl);

	if (!server_cert)
	{
		fprintf(stderr, "rdpudp_dtls_get_certificate: failed to get the server TLS certificate\n");
		cert = NULL;
	}
	else
	{
		cert = malloc(sizeof(*cert));
		cert->px509 = server_cert;
	}

	return cert;
}

static void rdpudp_dtls_free_certificate(CryptoCert cert)
{
	X509_free(cert->px509);
	free(cert);
}

#define DTLS_SERVER_END_POINT	"dtls-server-end-point:"

SecPkgContext_Bindings* rdpudp_dtls_get_channel_bindings(X509* cert)
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

	PrefixLength = strlen(DTLS_SERVER_END_POINT);
	ChannelBindingTokenLength = PrefixLength + CertificateHashLength;

	ContextBindings = (SecPkgContext_Bindings*) calloc(1, sizeof(SecPkgContext_Bindings));

	ContextBindings->BindingsLength = sizeof(SEC_CHANNEL_BINDINGS) + ChannelBindingTokenLength;
	ChannelBindings = (SEC_CHANNEL_BINDINGS*) calloc(1, ContextBindings->BindingsLength);
	ContextBindings->Bindings = ChannelBindings;

	ChannelBindings->cbApplicationDataLength = ChannelBindingTokenLength;
	ChannelBindings->dwApplicationDataOffset = sizeof(SEC_CHANNEL_BINDINGS);
	ChannelBindingToken = &((BYTE*) ChannelBindings)[ChannelBindings->dwApplicationDataOffset];

	strcpy((char*) ChannelBindingToken, DTLS_SERVER_END_POINT);
	CopyMemory(&ChannelBindingToken[PrefixLength], CertificateHash, CertificateHashLength);

	return ContextBindings;
}

BOOL rdpudp_dtls_connect(rdpUdpDtls* dtls)
{
	CryptoCert cert;
	long options = 0;
	int connection_status;

	dtls->ctx = SSL_CTX_new(DTLSv1_client_method());
	if (!dtls->ctx)
	{
		fprintf(stderr, "SSL_CTX_new failed\n");
		return FALSE;
	}

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

	SSL_CTX_set_options(dtls->ctx, options);

	dtls->ssl = SSL_new(dtls->ctx);
	if (!dtls->ssl)
	{
		fprintf(stderr, "SSL_new failed\n");
		return FALSE;
	}

	if (SSL_set_fd(dtls->ssl, dtls->sockfd) < 1)
	{
		fprintf(stderr, "SSL_set_fd failed\n");
		return FALSE;
	}

	connection_status = SSL_connect(dtls->ssl);
	if (connection_status <= 0)
	{
		if (rdpudp_dtls_print_error("SSL_connect", dtls->ssl, connection_status))
		{
			return FALSE;
		}
	}

	cert = rdpudp_dtls_get_certificate(dtls, TRUE);
	if (!cert)
	{
		fprintf(stderr, "rdpudp_dtls_connect: rdpudp_dtls_get_certificate failed to return the server certificate.\n");
		return FALSE;
	}

	dtls->Bindings = rdpudp_dtls_get_channel_bindings(cert->px509);

	if (!crypto_cert_get_public_key(cert, &dtls->PublicKey, &dtls->PublicKeyLength))
	{
		fprintf(stderr, "rdpudp_dtls_connect: crypto_cert_get_public_key failed to return the server public key.\n");
		rdpudp_dtls_free_certificate(cert);
		return FALSE;
	}

	if (!rdpudp_dtls_verify_certificate(dtls, cert, dtls->hostname, dtls->port))
	{
		fprintf(stderr, "rdpudp_dtls_connect: certificate not trusted, aborting.\n");
		rdpudp_dtls_disconnect(dtls);
		rdpudp_dtls_free_certificate(cert);
		return FALSE;
	}

	rdpudp_dtls_free_certificate(cert);

	return TRUE;
}

BOOL rdpudp_dtls_disconnect(rdpUdpDtls* dtls)
{
	if (!dtls)
		return FALSE;

	if (dtls->ssl)
	{
		SSL_shutdown(dtls->ssl);
	}

	return TRUE;
}

static void rdpudp_dtls_errors(const char *prefix)
{
	unsigned long error;

	while ((error = ERR_get_error()) != 0)
		fprintf(stderr, "%s: %s\n", prefix, ERR_error_string(error, NULL));
}

BOOL rdpudp_dtls_print_error(char* func, SSL* connection, int value)
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
			rdpudp_dtls_errors(func);
			return TRUE;

		case SSL_ERROR_SSL:
			fprintf(stderr, "%s: Failure in SSL library (protocol error?)\n", func);
			rdpudp_dtls_errors(func);
			return TRUE;

		default:
			fprintf(stderr, "%s: Unknown error\n", func);
			rdpudp_dtls_errors(func);
			return TRUE;
	}
}

BOOL rdpudp_dtls_match_hostname(char *pattern, int pattern_length, char *hostname)
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

BOOL rdpudp_dtls_verify_certificate(rdpUdpDtls* dtls, CryptoCert cert, char* hostname, int port)
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

	if (dtls->settings->ExternalCertificateManagement)
	{
		BIO* bio;
		int status;
		int length;
		int offset;
		BYTE* pemCert;
		freerdp* instance = (freerdp*) dtls->settings->instance;

		/**
		 * Don't manage certificates internally, leave it up entirely to the external client implementation
		 */

		bio = BIO_new(BIO_s_mem());
		
		if (!bio)
		{
			fprintf(stderr, "rdpudp_dtls_verify_certificate: BIO_new() failure\n");
			return FALSE;
		}

		status = PEM_write_bio_X509(bio, cert->px509);

		if (status < 0)
		{
			fprintf(stderr, "rdpudp_dtls_verify_certificate: PEM_write_bio_X509 failure: %d\n", status);
			return FALSE;
		}
		
		offset = 0;
		length = 2048;
		pemCert = (BYTE*) malloc(length + 1);

		status = BIO_read(bio, pemCert, length);
		
		if (status < 0)
		{
			fprintf(stderr, "rdpudp_dtls_verify_certificate: failed to read certificate\n");
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
			fprintf(stderr, "rdpudp_dtls_verify_certificate: failed to read certificate\n");
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
	if (dtls->settings->IgnoreCertificate)
		return TRUE;  /* success! */

	/* if user explicitly specified a certificate name, use it instead of the hostname */
	if (dtls->settings->CertificateName)
		hostname = dtls->settings->CertificateName;

	/* attempt verification using OpenSSL and the ~/.freerdp/certs certificate store */
	certificate_status = x509_verify_certificate(cert, dtls->certificate_store->path);

	/* verify certificate name match */
	certificate_data = crypto_get_certificate_data(cert->px509, hostname);

	/* extra common name and alternative names */
	common_name = crypto_cert_subject_common_name(cert->px509, &common_name_length);
	alt_names = crypto_cert_subject_alt_name(cert->px509, &alt_names_count, &alt_names_lengths);

	/* compare against common name */

	if (common_name != NULL)
	{
		if (rdpudp_dtls_match_hostname(common_name, common_name_length, hostname))
			hostname_match = TRUE;
	}

	/* compare against alternative names */

	if (alt_names != NULL)
	{
		for (index = 0; index < alt_names_count; index++)
		{
			if (rdpudp_dtls_match_hostname(alt_names[index], alt_names_lengths[index], hostname))
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
		rdpudp_dtls_print_certificate_name_mismatch_error(hostname, common_name, alt_names, alt_names_count);

	/* verification could not succeed with OpenSSL, use known_hosts file and prompt user for manual verification */

	if (!certificate_status)
	{
		char* issuer;
		char* subject;
		char* fingerprint;
		freerdp* instance = (freerdp*) dtls->settings->instance;
		BOOL accept_certificate = FALSE;

		issuer = crypto_cert_issuer(cert->px509);
		subject = crypto_cert_subject(cert->px509);
		fingerprint = crypto_cert_fingerprint(cert->px509);

		/* search for matching entry in known_hosts file */
		match = certificate_data_match(dtls->certificate_store, certificate_data);

		if (match == 1)
		{
			/* no entry was found in known_hosts file, prompt user for manual verification */
			if (!hostname_match)
				rdpudp_dtls_print_certificate_name_mismatch_error(hostname, common_name, alt_names, alt_names_count);

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
				certificate_data_print(dtls->certificate_store, certificate_data);
				verification_status = TRUE; /* success! */
			}
		}
		else if (match == -1)
		{
			/* entry was found in known_hosts file, but fingerprint does not match. ask user to use it */
			rdpudp_dtls_print_certificate_error(hostname, fingerprint, dtls->certificate_store->file);
			
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
				certificate_data_replace(dtls->certificate_store, certificate_data);
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

void rdpudp_dtls_print_certificate_error(char* hostname, char* fingerprint, char *hosts_file)
{
	fprintf(stderr, "The host key for %s has changed\n", hostname);
	fprintf(stderr, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	fprintf(stderr, "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n");
	fprintf(stderr, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	fprintf(stderr, "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n");
	fprintf(stderr, "Someone could be eavesdropping on you right now (man-in-the-middle attack)!\n");
	fprintf(stderr, "It is also possible that a host key has just been changed.\n");
	fprintf(stderr, "The fingerprint for the host key sent by the remote host is\n%s\n", fingerprint);
	fprintf(stderr, "Please contact your system administrator.\n");
	fprintf(stderr, "Add correct host key in %s to get rid of this message.\n", hosts_file);
	fprintf(stderr, "Host key for %s has changed and you have requested strict checking.\n", hostname);
	fprintf(stderr, "Host key verification failed.\n");
}

void rdpudp_dtls_print_certificate_name_mismatch_error(char* hostname, char* common_name, char** alt_names, int alt_names_count)
{
	int index;

	assert(NULL != hostname);
	assert(NULL != common_name);
	
	fprintf(stderr, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	fprintf(stderr, "@           WARNING: CERTIFICATE NAME MISMATCH!           @\n");
	fprintf(stderr, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	fprintf(stderr, "The hostname used for this connection (%s) \n", hostname);
	fprintf(stderr, "does not match %s given in the certificate:\n", alt_names_count < 1 ? "the name" : "any of the names");
	fprintf(stderr, "Common Name (CN):\n");
	fprintf(stderr, "\t%s\n", common_name ? common_name : "no CN found in certificate");
	if (alt_names_count > 1)
	{
		assert(NULL != alt_names);
		fprintf(stderr, "Alternative names:\n");
		if (alt_names_count > 1)
		{
			for (index = 0; index < alt_names_count; index++)
			{
				assert(alt_names[index]);
				fprintf(stderr, "\t %s\n", alt_names[index]);
			}
		}
	}
	fprintf(stderr, "A valid certificate for the wrong name should NOT be trusted!\n");
}

rdpUdpDtls* rdpudp_dtls_new(rdpSettings* settings)
{
	rdpUdpDtls* dtls;

	dtls = (rdpUdpDtls*) calloc(1, sizeof(rdpUdpDtls));

	if (dtls)
	{
		SSL_load_error_strings();
		SSL_library_init();

		dtls->settings = settings;
		dtls->certificate_store = certificate_store_new(settings);
	}
	
	return dtls;
}

void rdpudp_dtls_free(rdpUdpDtls* dtls)
{
	if (dtls)
	{
		if (dtls->ssl)
		{
			SSL_free(dtls->ssl);
			dtls->ssl = NULL;
		}

		if (dtls->ctx)
		{
			SSL_CTX_free(dtls->ctx);
			dtls->ctx = NULL;
		}

		if (dtls->PublicKey)
		{
			free(dtls->PublicKey);
			dtls->PublicKey = NULL;
		}

		if (dtls->Bindings)
		{
			free(dtls->Bindings->Bindings);
			free(dtls->Bindings);
			dtls->Bindings = NULL;
		}

		certificate_store_free(dtls->certificate_store);
		dtls->certificate_store = NULL;

		free(dtls);
	}
}
