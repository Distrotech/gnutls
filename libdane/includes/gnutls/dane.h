/* -*- c -*-
 * Copyright (C) 2012 KU Leuven
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of libdane.
 *
 * libdane is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */


#include <gnutls/gnutls.h> /* for gnutls_datum_t */

/**
 * dane_cert_usage_t:
 * @DANE_CERT_USAGE_CA: CA constraint. The certificate/key
 *   presented must have signed the verified key.
 * @DANE_CERT_USAGE_EE: The key or the certificate of the end
 *   entity.
 * @DANE_CERT_USAGE_LOCAL_CA: The remote CA is local and possibly
 *   untrusted by the verifier.
 * @DANE_CERT_USAGE_LOCAL_EE: The remote end-entity key is local
 *   and possibly untrusted by the verifier (not signed by a CA).
 *
 * Enumeration of different certificate usage types.
 */
typedef enum dane_cert_usage_t
{
  DANE_CERT_USAGE_CA = 0,
  DANE_CERT_USAGE_EE = 1,
  DANE_CERT_USAGE_LOCAL_CA = 2,
  DANE_CERT_USAGE_LOCAL_EE = 3
} dane_cert_usage_t;

/**
 * dane_cert_type_t:
 * @DANE_CERT_X509: An X.509 certificate.
 * @DANE_CERT_PK: A public key.
 *
 * Enumeration of different certificate types.
 */
typedef enum dane_cert_type_t 
{
  DANE_CERT_X509 = 0,
  DANE_CERT_PK = 1
} dane_cert_type_t;

/**
 * dane_match_type_t:
 * @DANE_MATCH_EXACT: The full content.
 * @DANE_MATCH_SHA2_256: A SHA-256 hash of the content.
 * @DANE_MATCH_SHA2_512: A SHA-512 hash of the content.
 *
 * Enumeration of different content matching types.
 */
typedef enum dane_match_type_t 
{
  DANE_MATCH_EXACT = 0,
  DANE_MATCH_SHA2_256 = 1,
  DANE_MATCH_SHA2_512 = 2
} dane_match_type_t;

/**
 * dane_query_status_t:
 * @DANE_QUERY_UNKNOWN: There was no query.
 * @DANE_QUERY_DNSSEC_VERIFIED: The query was verified using DNSSEC.
 * @DANE_QUERY_BOGUS: The query has wrong DNSSEC signature.
 * @DANE_QUERY_NO_DNSSEC: The query has no DNSSEC data.
 *
 * Enumeration of different certificate types.
 */
typedef enum dane_query_status_t 
{
  DANE_QUERY_UNKNOWN = 0,
  DANE_QUERY_DNSSEC_VERIFIED,
  DANE_QUERY_BOGUS,
  DANE_QUERY_NO_DNSSEC
} dane_query_status_t;

typedef struct dane_query_st *dane_query_t;


int dane_query_init (dane_query_t* q, unsigned int flags);
void dane_query_deinit (dane_query_t q);
int dane_query_resolve_tlsa (dane_query_t q, const char* host, const char* proto, unsigned int port);
int dane_query_data(dane_query_t q, unsigned int idx,
					unsigned int *usage, unsigned int *type,
					unsigned int *match, gnutls_datum_t * data);
dane_query_status_t dane_query_status(dane_query_t q);
unsigned int dane_query_entries(dane_query_t q);


/**
 * dane_verify_status_t:
 * @DANE_VERIFY_CA_CONSTRAINS_VIOLATED: The CA constrains was violated.
 * @DANE_VERIFY_CERT_DIFFERS: The certificate obtained via DNS differs.
 * @DANE_VERIFY_NO_DANE_INFO: No DANE data were found in the DNS record.
 *
 * Enumeration of different verification status flags.
 */
typedef enum dane_verify_status_t 
{
  DANE_VERIFY_CA_CONSTRAINS_VIOLATED = 1,
  DANE_VERIFY_CERT_DIFFERS = 1<<1,
  DANE_VERIFY_NO_DANE_INFO = 1<<2,
} dane_verify_status_t;

/**
 * dane_verify_flags_t:
 * @DANE_F_REQUIRE_DNSSEC: Require DNSSEC for verification.
 * @DANE_F_IGNORE_LOCAL_RESOLVER: Many systems are not DNSSEC-ready. In that case the local resolver is ignored, and a direct recursive resolve occurs.
 *
 * Enumeration of different verification flags.
 */
typedef enum dane_verify_flags_t 
{
  DANE_F_IGNORE_LOCAL_RESOLVER = 1,
} dane_verify_flags_t;

int dane_verify_crt (
	const gnutls_datum_t *chain, unsigned chain_size,
	gnutls_certificate_type_t chain_type,
	const char * hostname, const char* proto, unsigned int port,
	unsigned int flags, unsigned int *verify);

int dane_verify_session_crt (
	gnutls_session_t session,
	const char * hostname, const char* proto, unsigned int port,
	unsigned int flags, unsigned int *verify);

const char * dane_strerror (int error);

#define DANE_E_SUCCESS 0
#define DANE_E_INITIALIZATION_ERROR -1
#define DANE_E_RESOLVING_ERROR -2
#define DANE_E_NO_DANE_DATA -3
#define DANE_E_RECEIVED_CORRUPT_DATA -4
#define DANE_E_INVALID_DNSSEC_SIG -5
#define DANE_E_NO_DNSSEC_SIG -6
#define DANE_E_MEMORY_ERROR -7
#define DANE_E_REQUESTED_DATA_NOT_AVAILABLE -8
#define DANE_E_INVALID_REQUEST -9
#define DANE_E_PUBKEY_ERROR -10
#define DANE_E_NO_CERT -11
