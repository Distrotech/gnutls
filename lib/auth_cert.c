/*
 *      Copyright (C) 2001,2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <gnutls_int.h>
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include <gnutls_cert.h>
#include <auth_cert.h>
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "x509_asn1.h"
#include "x509_der.h"
#include "gnutls_datum.h"
#include <gnutls_random.h>
#include <gnutls_pk.h>
#include <gnutls_algorithms.h>
#include <gnutls_global.h>
#include <gnutls_record.h>
#include <x509_verify.h>
#include <gnutls_sig.h>
#include <x509_extensions.h>
#include <gnutls_state.h>
#include <gnutls_pk.h>
#include <gnutls_x509.h>
#include <gnutls_openpgp.h>
#include "debug.h"

/* Copies data from a internal certificate struct (gnutls_cert) to 
 * exported certificate struct (CERTIFICATE_AUTH_INFO)
 */
static
int _gnutls_copy_certificate_auth_info(CERTIFICATE_AUTH_INFO info,
				       gnutls_cert * cert, int ncerts)
{
	/* Copy peer's information to AUTH_INFO
	 */
	int ret, i, j;

	if (ncerts == 0) {
		info->raw_certificate_list = NULL;
		info->ncerts = 0;
		return 0;
	}

	info->raw_certificate_list =
	    gnutls_calloc(1, sizeof(gnutls_datum) * ncerts);
	if (info->raw_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	for (i = 0; i < ncerts; i++) {
		if (cert->raw.size > 0) {
			ret =
			    gnutls_set_datum(&info->
					     raw_certificate_list[i],
					     cert[i].raw.data,
					     cert[i].raw.size);
			if (ret < 0) {
				gnutls_assert();
				goto clear;
			}
		}
	}
	info->ncerts = ncerts;

	return 0;

      clear:

	for (j = 0; j < i; j++)
		gnutls_free_datum(&info->raw_certificate_list[j]);

	gnutls_free(info->raw_certificate_list);
	info->raw_certificate_list = NULL;

	return ret;
}


/* Returns the issuer's Distinguished name in odn, of the certificate 
 * specified in cert.
 */
int _gnutls_find_dn(gnutls_datum * odn, gnutls_cert * cert)
{
	node_asn *dn;
	int len, result;
	int start, end;

	if ((result=asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1.Certificate", &dn,
	     "dn")) != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_get_der(dn, cert->raw.data, cert->raw.size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure(dn);
		return _gnutls_asn2err(result);
	}

	result = asn1_get_start_end_der(dn, cert->raw.data, cert->raw.size,
					"dn.tbsCertificate.issuer", &start,
					&end);

	if (result != ASN_OK) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure(dn);
		return _gnutls_asn2err(result);
	}
	asn1_delete_structure(dn);

	len = end - start + 1;

	odn->size = len;
	odn->data = &cert->raw.data[start];

	return 0;
}


/* returns 0 if the algo_to-check exists in the pk_algos list,
 * -1 otherwise.
 */
inline
    static int _gnutls_check_pk_algo_in_list(PKAlgorithm * pk_algos,
					     int pk_algos_length,
					     PKAlgorithm algo_to_check)
{
	int i;
	for (i = 0; i < pk_algos_length; i++) {
		if (algo_to_check == pk_algos[i]) {
			return 0;
		}
	}
	return -1;
}

/* Locates the most appropriate x509 certificate using the
 * given DN. If indx == -1 then no certificate was found.
 */
static int _find_x509_cert(const GNUTLS_CERTIFICATE_CREDENTIALS cred,
			   opaque * _data, int _data_size,
			   PKAlgorithm * pk_algos, int pk_algos_length,
			   int *indx)
{
	int size;
	gnutls_datum odn;
	opaque *data = _data;
	int data_size = _data_size, i, j;
	int result;

	*indx = -1;

	do {

		DECR_LENGTH_RET(data_size, 2, 0);
		size = READuint16(data);
		DECR_LENGTH_RET(data_size, size, 0);
		data += 2;

		for (i = 0; i < cred->ncerts; i++) {
			for (j = 0; j < cred->cert_list_length[i]; j++) {
				if ((result =
				     _gnutls_find_dn(&odn,
						     &cred->cert_list[i]
						     [j])) < 0) {
					gnutls_assert();
					return result;
				}

				if (odn.size != size)
					continue;

				/* If the DN matches and
				 * the *_SIGN algorithm matches
				 * the cert is our cert!
				 */
				if ((memcmp(odn.data,
					    data, size) == 0) &&
				    (_gnutls_check_pk_algo_in_list
				     (pk_algos, pk_algos_length,
				      cred->cert_list[i][0].
				      subject_pk_algorithm) == 0)
				    && (cred->cert_list[i][0].cert_type ==
					GNUTLS_CRT_X509)) {
					*indx = i;
					break;
				}
			}
			if (*indx != -1)
				break;
		}

		if (*indx != -1)
			break;

		/* move to next record */
		if (data_size <= 0)
			break;

		data += size;

	} while (1);

	return 0;

}

/* Locates the most appropriate openpgp cert
 */
static int _find_openpgp_cert(const GNUTLS_CERTIFICATE_CREDENTIALS cred,
			      PKAlgorithm * pk_algos, int pk_algos_length,
			      int *indx)
{
	int i, j;

	*indx = -1;

	for (i = 0; i < cred->ncerts; i++) {
		for (j = 0; j < cred->cert_list_length[i]; j++) {

			/* If the *_SIGN algorithm matches
			 * the cert is our cert!
			 */
			if ((_gnutls_check_pk_algo_in_list
			     (pk_algos, pk_algos_length,
			      cred->cert_list[i][0].
			      subject_pk_algorithm) == 0)
			    && (cred->cert_list[i][0].cert_type ==
				GNUTLS_CRT_OPENPGP)) {
				*indx = i;
				break;
			}
		}
		if (*indx != -1)
			break;
	}

	return 0;
}

/* Finds the appropriate certificate depending on the cA Distinguished name
 * advertized by the server. If none matches then returns 0 and -1 as index.
 * In case of an error a negative value, is returned.
 *
 * 20020128: added ability to select a certificate depending on the SIGN
 * algorithm (only in automatic mode).
 */
static int _gnutls_find_acceptable_client_cert(GNUTLS_STATE state,
					       opaque * _data,
					       int _data_size, int *ind,
					       PKAlgorithm * pk_algos,
					       int pk_algos_length)
{
	int result, size;
	int indx = -1;
	int i, j, try = 0, *ij_map = NULL;
	const GNUTLS_CERTIFICATE_CREDENTIALS cred;
	opaque *data = _data;
	int data_size = _data_size;

	cred =
	    _gnutls_get_cred(state->gnutls_key, GNUTLS_CRD_CERTIFICATE,
			     NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	if (state->gnutls_internals.client_cert_callback != NULL) {
		/* if try>=0 then the client wants automatic
		 * choose of certificate, otherwise (-1), he
		 * will be prompted to choose one.
		 */
		try =
		    state->gnutls_internals.client_cert_callback(state,
								 NULL, 0,
								 NULL, 0);
	}


	if (try >= 0) {
		result = 0;

		if (state->security_parameters.cert_type ==
		    GNUTLS_CRT_X509)
			result =
			    _find_x509_cert(cred, _data, _data_size,
					    pk_algos, pk_algos_length,
					    &indx);

		if (state->security_parameters.cert_type ==
		    GNUTLS_CRT_OPENPGP)
			result =
			    _find_openpgp_cert(cred, pk_algos,
					       pk_algos_length, &indx);


		if (result < 0) {
			gnutls_assert();
			return result;
		}
	}


	/* use the callback 
	 */
	if (indx == -1 && state->gnutls_internals.client_cert_callback != NULL && cred->ncerts > 0) {	/* use a callback to get certificate */
		gnutls_datum *my_certs = NULL;
		gnutls_datum *issuers_dn = NULL;
		int count;
		int issuers_dn_len = 0;
		opaque* dataptr = data;
		int dataptr_size = data_size;

		/* Count the number of the given issuers;
		 * This is used to allocate the issuers_dn without
		 * using realloc().
		 */
		do {
			dataptr_size -= 2;
			if (dataptr_size <= 0)
				goto clear;
			size = READuint16(data);

			dataptr_size -= size;
			if (dataptr_size < 0)
				goto clear;

			dataptr += 2;

			issuers_dn_len++;

			dataptr += size;

			if (dataptr_size == 0)
				break;

		} while (1);


		my_certs =
		    gnutls_alloca(cred->ncerts * sizeof(gnutls_datum));
		if (my_certs == NULL)
			goto clear;

		/* put the requested DNs to req_dn, only in case
		 * of X509 certificates.
		 */
		if (gnutls_cert_type_get(state) == GNUTLS_CRT_X509) {
			data = _data;
			data_size = _data_size;

			issuers_dn = gnutls_alloca( issuers_dn_len * sizeof(gnutls_datum));

			for (i=0;i<issuers_dn_len;i++) {
				/* The checks here for the buffer boundaries
				 * are not needed since the buffer has been
				 * parsed above.
				 */
				data_size -= 2;

				size = READuint16(data);

				data += 2;

				issuers_dn[count].data = data;
				issuers_dn[count].size = size;

				data += size;

			}

		} else {	/* Other certificate types */
			issuers_dn_len = 0;
			issuers_dn = NULL;
		}

		/* maps j -> i */
		ij_map = gnutls_alloca(sizeof(int) * cred->ncerts);
		if (ij_map==NULL) {
			gnutls_assert();
			goto clear;
		}

		/* put our certificate's issuer and dn into cdn, idn
		 */
		for (j = i = 0; i < cred->ncerts; i++) {
			if ((cred->cert_list[i][0].cert_type ==
			     gnutls_cert_type_get(state)) &&
			    (_gnutls_check_pk_algo_in_list(pk_algos,
							   pk_algos_length,
							   cred->
							   cert_list[i][0].
							   subject_pk_algorithm)
			     == 0)) {
				/* Add a certificate ONLY if it is allowed
				 * by the peer.
				 */
				ij_map[j] = i;
				my_certs[j++] = cred->cert_list[i][0].raw;
			}
		}

		indx =
		    state->gnutls_internals.client_cert_callback(state,
								 my_certs,
								 j,
								 issuers_dn,
								 issuers_dn_len);

		/* the indx returned by the user is relative
		 * to the certificates we provided him.
		 * This will make it relative to the certificates
		 * we've got.
		 */
		indx = ij_map[indx];

	      clear:
		gnutls_afree(my_certs);
		gnutls_afree(ij_map);
		gnutls_afree(issuers_dn);
	}

	*ind = indx;
	return 0;
}

/* Generate client certificate
 */

int _gnutls_gen_x509_certificate(GNUTLS_STATE state, opaque ** data)
{
	int ret, i;
	opaque *pdata;
	gnutls_cert *apr_cert_list;
	gnutls_private_key *apr_pkey;
	int apr_cert_list_length;

	/* find the appropriate certificate */
	if ((ret =
	     _gnutls_find_apr_cert(state, &apr_cert_list,
				   &apr_cert_list_length,
				   &apr_pkey)) < 0) {
		gnutls_assert();
		return ret;
	}

	ret = 3;
	for (i = 0; i < apr_cert_list_length; i++) {
		ret += apr_cert_list[i].raw.size + 3;
		/* hold size
		 * for uint24 */
	}

	/* if no certificates were found then send:
	 * 0B 00 00 03 00 00 00    // Certificate with no certs
	 * instead of:
	 * 0B 00 00 00          // empty certificate handshake
	 *
	 * ( the above is the whole handshake message, not 
	 * the one produced here )
	 */

	(*data) = gnutls_malloc(ret);
	pdata = (*data);

	if (pdata == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	WRITEuint24(ret - 3, pdata);
	pdata += 3;
	for (i = 0; i < apr_cert_list_length; i++) {
		WRITEdatum24(pdata, apr_cert_list[i].raw);
		pdata += (3 + apr_cert_list[i].raw.size);
	}

	return ret;
}

enum PGPKeyDescriptorType { PGP_KEY_FINGERPRINT, PGP_KEY };

int _gnutls_gen_openpgp_certificate(GNUTLS_STATE state,
					   opaque ** data)
{
	int ret;
	opaque *pdata;
	gnutls_cert *apr_cert_list;
	gnutls_private_key *apr_pkey;
	int apr_cert_list_length;

	/* find the appropriate certificate */
	if ((ret =
	     _gnutls_find_apr_cert(state, &apr_cert_list,
				   &apr_cert_list_length,
				   &apr_pkey)) < 0) {
		gnutls_assert();
		return ret;
	}

	ret = 3 + 1 + 3;

	if (apr_cert_list_length > 0)
		ret += apr_cert_list[0].raw.size;

	(*data) = gnutls_malloc(ret);
	pdata = (*data);

	if (pdata == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	WRITEuint24(ret - 3, pdata);
	pdata += 3;

	*pdata = PGP_KEY;	/* whole key */
	pdata++;

	if (apr_cert_list_length > 0) {
		WRITEdatum24(pdata, apr_cert_list[0].raw);
		pdata += (3 + apr_cert_list[0].raw.size);
	} else			/* empty - no certificate */
		WRITEuint24(0, pdata);

	return ret;
}

int _gnutls_gen_openpgp_certificate_fpr(GNUTLS_STATE state,
					       opaque ** data)
{
	int ret, fpr_size, packet_size;
	opaque *pdata;
	gnutls_cert *apr_cert_list;
	gnutls_private_key *apr_pkey;
	int apr_cert_list_length;

	/* find the appropriate certificate */
	if ((ret =
	     _gnutls_find_apr_cert(state, &apr_cert_list,
				   &apr_cert_list_length,
				   &apr_pkey)) < 0) {
		gnutls_assert();
		return ret;
	}

	packet_size = 3 + 1;

	/* Only v4 fingerprints are sent 
	 */
	if (apr_cert_list_length > 0 && apr_cert_list[0].version == 4)
		packet_size += 20 + 1;
	else			/* empty certificate case */
		return _gnutls_gen_openpgp_certificate(state, data);

	(*data) = gnutls_malloc(packet_size);
	pdata = (*data);

	if (pdata == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	WRITEuint24(packet_size - 3, pdata);
	pdata += 3;

	*pdata = PGP_KEY_FINGERPRINT;	/* key fingerprint */
	pdata++;

	*pdata = 20;
	pdata++;

	fpr_size = 20;
	if ( (ret=gnutls_openpgp_fingerprint( &apr_cert_list[0].raw, pdata, &fpr_size)) < 0) {
		gnutls_assert();
		return ret;
	}

	return packet_size;
}



int _gnutls_gen_cert_client_certificate(GNUTLS_STATE state, opaque ** data)
{
	switch (state->security_parameters.cert_type) {
	case GNUTLS_CRT_OPENPGP:
		if (_gnutls_openpgp_send_fingerprint(state) == 0)
			return
			    _gnutls_gen_openpgp_certificate(state,
								   data);
		else
			return
			    _gnutls_gen_openpgp_certificate_fpr
			    (state, data);

	case GNUTLS_CRT_X509:
		return _gnutls_gen_x509_certificate(state, data);

	default:
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}
}

int _gnutls_gen_cert_server_certificate(GNUTLS_STATE state, opaque ** data)
{
	switch (state->security_parameters.cert_type) {
	case GNUTLS_CRT_OPENPGP:
		return _gnutls_gen_openpgp_certificate(state, data);
	case GNUTLS_CRT_X509:
		return _gnutls_gen_x509_certificate(state, data);
	default:
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}
}

/* Process server certificate
 */

#define CLEAR_CERTS for(x=0;x<peer_certificate_list_size;x++) _gnutls_free_cert(peer_certificate_list[x])
int _gnutls_proc_x509_server_certificate(GNUTLS_STATE state, opaque * data,
					 int data_size)
{
	int size, len, ret;
	opaque *p = data;
	CERTIFICATE_AUTH_INFO info;
	const GNUTLS_CERTIFICATE_CREDENTIALS cred;
	int dsize = data_size;
	int i, j, x;
	gnutls_cert *peer_certificate_list;
	int peer_certificate_list_size = 0;
	gnutls_datum tmp;

	cred =
	    _gnutls_get_cred(state->gnutls_key, GNUTLS_CRD_CERTIFICATE,
			     NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}


	if ((ret =
	     _gnutls_auth_info_set(state, GNUTLS_CRD_CERTIFICATE,
				   sizeof(CERTIFICATE_AUTH_INFO_INT), 1)) <
	    0) {
		gnutls_assert();
		return ret;
	}

	info = _gnutls_get_auth_info(state);

	if (data == NULL || data_size == 0) {
		gnutls_assert();
		/* no certificate was sent */
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}

	DECR_LEN(dsize, 3);
	size = READuint24(p);
	p += 3;

	if (size == 0) {
		gnutls_assert();
		/* no certificate was sent */
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}

	i = dsize;
	while(i > 0) {
		DECR_LEN(dsize, 3);
		len = READuint24(p);
		p += 3;
		DECR_LEN(dsize, len);
		peer_certificate_list_size++;
		p += len;
		i -= len + 3;
	}

	if (peer_certificate_list_size == 0) {
		gnutls_assert();
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}

	/* Ok we now allocate the memory to hold the
	 * certificate list 
	 */

	peer_certificate_list =
	    gnutls_alloca( sizeof(gnutls_cert) *
			  (peer_certificate_list_size));

	if (peer_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	memset( peer_certificate_list, 0, sizeof(gnutls_cert)*
					peer_certificate_list_size);

	p = data + 3;

	/* Now we start parsing the list (again).
	 * We don't use DECR_LEN since the list has
	 * been parsed before.
	 */

	for (j=0;j<peer_certificate_list_size;j++) {
		len = READuint24(p);
		p += 3;

		tmp.size = len;
		tmp.data = p;

		if ((ret =
		     _gnutls_x509_cert2gnutls_cert(&peer_certificate_list
						   [j], tmp)) < 0) {
			gnutls_assert();
			CLEAR_CERTS;
			gnutls_afree(peer_certificate_list);
			return ret;
		}

		p += len;
	}


	if ((ret =
	     _gnutls_copy_certificate_auth_info(info,
						peer_certificate_list,
						peer_certificate_list_size))
	    < 0) {
		gnutls_assert();
		CLEAR_CERTS;
		gnutls_afree(peer_certificate_list);
		return ret;
	}

	if ((ret =
	     _gnutls_check_x509_key_usage(&peer_certificate_list[0],
					  gnutls_kx_get(state)))
	    < 0) {
		gnutls_assert();
		CLEAR_CERTS;
		gnutls_afree(peer_certificate_list);
		return ret;
	}

	CLEAR_CERTS;
	gnutls_afree(peer_certificate_list);

	return 0;
}

#define CLEAR_CERTS for(x=0;x<peer_certificate_list_size;x++) _gnutls_free_cert(peer_certificate_list[x])
int _gnutls_proc_openpgp_server_certificate(GNUTLS_STATE state,
					    opaque * data, int data_size)
{
	int size, ret, len;
	opaque *p = data;
	CERTIFICATE_AUTH_INFO info;
	const GNUTLS_CERTIFICATE_CREDENTIALS cred;
	int dsize = data_size;
	int i, x;
	gnutls_cert *peer_certificate_list;
	int peer_certificate_list_size = 0;
	gnutls_datum tmp, akey = { NULL, 0 };

	cred =
	    _gnutls_get_cred(state->gnutls_key, GNUTLS_CRD_CERTIFICATE,
			     NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	if ((ret =
	     _gnutls_auth_info_set(state, GNUTLS_CRD_CERTIFICATE,
				   sizeof(CERTIFICATE_AUTH_INFO_INT), 1)) <
	    0) {
		gnutls_assert();
		return ret;
	}

	info = _gnutls_get_auth_info(state);

	if (data == NULL || data_size == 0) {
		gnutls_assert();
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}

	DECR_LEN(dsize, 3);
	size = READuint24(p);
	p += 3;

	if (size == 0) {
		gnutls_assert();
		/* no certificate was sent */
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}
	i = dsize;

	/* Read PGPKeyDescriptor */
	DECR_LEN(dsize, 1);
	if (*p == PGP_KEY_FINGERPRINT) { /* the fingerprint */
		p++;
		
		DECR_LEN(dsize, 1);
		len = (uint8) *p;
		
		if (len != 20) {
			gnutls_assert();
			return GNUTLS_E_UNIMPLEMENTED_FEATURE;
		}
		
		DECR_LEN( dsize, 20);

		/* request the actual key from our database, or
		 * a key server or anything.
		 */
		if ( (ret=_gnutls_openpgp_request_key( &akey, cred, p, 20)) < 0) {
			gnutls_assert();
			return ret;
		}
		tmp = akey;
		peer_certificate_list_size++;

	} else if (*p == PGP_KEY) { /* the whole key */

		p++;

		/* Read the actual certificate */
		DECR_LEN(dsize, 3);
		len = READuint24(p);
		p += 3;

		if (size == 0) {
			gnutls_assert();
			/* no certificate was sent */
			return GNUTLS_E_NO_CERTIFICATE_FOUND;
		}

		DECR_LEN(dsize, len);
		peer_certificate_list_size++;

		tmp.size = len;
		tmp.data = p;

	} else {
		gnutls_assert();
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}

	/* ok we now have the peer's key in tmp datum
	 */

	if (peer_certificate_list_size == 0) {
		gnutls_assert();
		gnutls_free_datum( &akey);
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	peer_certificate_list =
	    gnutls_alloca( sizeof(gnutls_cert) *
			  (peer_certificate_list_size));
		if (peer_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	memset( peer_certificate_list, 0, sizeof(gnutls_cert)*
			peer_certificate_list_size);


	if ((ret =
	     _gnutls_openpgp_cert2gnutls_cert(&peer_certificate_list[0],
					      tmp)) < 0) {
		gnutls_assert();
		gnutls_free_datum( &akey);
		CLEAR_CERTS;
		gnutls_afree(peer_certificate_list);
		return ret;
	}
	gnutls_free_datum( &akey);

	if ((ret =
	     _gnutls_copy_certificate_auth_info(info,
						peer_certificate_list,
						peer_certificate_list_size))
	    < 0) {
		gnutls_assert();
		CLEAR_CERTS;
		gnutls_afree(peer_certificate_list);
		return ret;
	}

	if ((ret =
	     _gnutls_check_x509_key_usage(&peer_certificate_list[0],
					  gnutls_kx_get(state)))
	    < 0) {
		gnutls_assert();
		CLEAR_CERTS;
		gnutls_afree(peer_certificate_list);
		return ret;
	}

	CLEAR_CERTS;
	gnutls_afree(peer_certificate_list);

	return 0;
}

int _gnutls_proc_cert_server_certificate(GNUTLS_STATE state, opaque * data,
					 int data_size)
{
	switch (state->security_parameters.cert_type) {
	case GNUTLS_CRT_OPENPGP:
		return _gnutls_proc_openpgp_server_certificate(state, data,
							       data_size);
	case GNUTLS_CRT_X509:
		return _gnutls_proc_x509_server_certificate(state, data,
							    data_size);
	default:
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}
}

#define MAX_SIGN_ALGOS 2
typedef enum CertificateSigType { RSA_SIGN = 1, DSA_SIGN
} CertificateSigType;

/* Checks if we support the given signature algorithm 
 * (RSA or DSA). Returns the corresponding PKAlgorithm
 * if true;
 */
inline static
int _gnutls_check_supported_sign_algo(CertificateSigType algo)
{
	switch (algo) {
	case RSA_SIGN:
		return GNUTLS_PK_RSA;
	case DSA_SIGN:
		return GNUTLS_PK_DSA;
	}

	return -1;
}

int _gnutls_proc_cert_cert_req(GNUTLS_STATE state, opaque * data,
			       int data_size)
{
	int size, ret;
	opaque *p = data;
	const GNUTLS_CERTIFICATE_CREDENTIALS cred;
	CERTIFICATE_AUTH_INFO info;
	int dsize = data_size;
	int i, j, ind;
	PKAlgorithm pk_algos[MAX_SIGN_ALGOS];
	int pk_algos_length;

	cred =
	    _gnutls_get_cred(state->gnutls_key, GNUTLS_CRD_CERTIFICATE,
			     NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	if ((ret =
	     _gnutls_auth_info_set(state, GNUTLS_CRD_CERTIFICATE,
				   sizeof(CERTIFICATE_AUTH_INFO_INT), 0)) <
	    0) {
		gnutls_assert();
		return ret;
	}

	info = _gnutls_get_auth_info(state);

	DECR_LEN(dsize, 1);
	size = p[0];
	p++;
	/* check if the sign algorithm is supported.
	 */
	pk_algos_length = j = 0;
	for (i = 0; i < size; i++, p++) {
		DECR_LEN(dsize, 1);
		if ((ret = _gnutls_check_supported_sign_algo(*p)) > 0) {
			if (j < MAX_SIGN_ALGOS) {
				pk_algos[j++] = ret;
				pk_algos_length++;
			}
		}
	}

	if (pk_algos_length == 0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_KX_ALGORITHM;
	}

	if (state->security_parameters.cert_type == GNUTLS_CRT_X509) {
		DECR_LEN(dsize, 2);
		size = READuint16(p);
		p += 2;
	} else {
		p = NULL;
		size = 0;
	}

	DECR_LEN(dsize, size);

	/* now we ask the user to tell which one
	 * he wants to use.
	 */
	if ((ret =
	     _gnutls_find_acceptable_client_cert(state, p, size,
						 &ind, pk_algos,
						 pk_algos_length)) < 0) {
		gnutls_assert();
		return ret;
	}
	/* put the index of the client certificate to use
	 */
	state->gnutls_internals.selected_cert_index = ind;

	if (ind >= 0)
		state->gnutls_key->certificate_requested = 1;

	return 0;
}

int _gnutls_gen_cert_client_cert_vrfy(GNUTLS_STATE state, opaque ** data)
{
	int ret;
	gnutls_cert *apr_cert_list;
	gnutls_private_key *apr_pkey;
	int apr_cert_list_length, size;
	gnutls_datum signature;

	*data = NULL;

	/* find the appropriate certificate */
	if ((ret =
	     _gnutls_find_apr_cert(state, &apr_cert_list,
				   &apr_cert_list_length,
				   &apr_pkey)) < 0) {
		gnutls_assert();
		return ret;
	}

	if (apr_pkey != NULL) {
		if ((ret =
		     _gnutls_generate_sig_from_hdata(state,
						     &apr_cert_list[0],
						     apr_pkey,
						     &signature)) < 0) {
			gnutls_assert();
			return ret;
		}
	} else {
		gnutls_assert();
		return 0;
	}

	*data = gnutls_malloc(signature.size + 2);
	if (*data == NULL) {
		gnutls_free_datum(&signature);
		return GNUTLS_E_MEMORY_ERROR;
	}
	size = signature.size;
	WRITEuint16(size, *data);

	memcpy(&(*data)[2], signature.data, size);

	gnutls_free_datum(&signature);

	return size + 2;
}

int _gnutls_proc_cert_client_cert_vrfy(GNUTLS_STATE state, opaque * data,
				       int data_size)
{
	int size, ret;
	int dsize = data_size;
	opaque *pdata = data;
	gnutls_datum sig;
	CERTIFICATE_AUTH_INFO info = _gnutls_get_auth_info(state);
	gnutls_cert peer_cert;

	if (info == NULL || info->ncerts == 0) {
		gnutls_assert();
		/* we need this in order to get peer's certificate */
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	DECR_LEN(dsize, 2);
	size = READuint16(pdata);
	pdata += 2;

	DECR_LEN(dsize, size);

	sig.data = pdata;
	sig.size = size;

	switch (state->security_parameters.cert_type) {
	case GNUTLS_CRT_X509:
		ret =
		    _gnutls_x509_cert2gnutls_cert(&peer_cert,
						  info->
						  raw_certificate_list[0]);
		break;
	case GNUTLS_CRT_OPENPGP:
		ret =
		    _gnutls_openpgp_cert2gnutls_cert(&peer_cert,
						     info->
						     raw_certificate_list
						     [0]);
		break;
	default:
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	if ((ret =
	     _gnutls_verify_sig_hdata(state, &peer_cert, &sig,
				      data_size + HANDSHAKE_HEADER_SIZE)) <
	    0) {
		gnutls_assert();
		_gnutls_free_cert(peer_cert);
		return ret;
	}
	_gnutls_free_cert(peer_cert);

	return 0;
}

#define CERTTYPE_SIZE 3
int _gnutls_gen_cert_server_cert_req(GNUTLS_STATE state, opaque ** data)
{
	const GNUTLS_CERTIFICATE_CREDENTIALS cred;
	int size;
	opaque *pdata;

	/* Now we need to generate the RDN sequence. This is
	 * already in the CERTIFICATE_CRED structure, to improve
	 * performance.
	 */

	cred =
	    _gnutls_get_cred(state->gnutls_key, GNUTLS_CRD_CERTIFICATE,
			     NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	size = CERTTYPE_SIZE + 2;	/* 2 for CertificateType + 2 for size of rdn_seq 
					 */

	if (state->security_parameters.cert_type == GNUTLS_CRT_X509)
		size += cred->x509_rdn_sequence.size;

	(*data) = gnutls_malloc(size);
	pdata = (*data);

	if (pdata == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	pdata[0] = CERTTYPE_SIZE - 1;

	pdata[1] = RSA_SIGN;
	pdata[2] = DSA_SIGN;	/* only these for now */
	pdata += CERTTYPE_SIZE;

	if (state->security_parameters.cert_type == GNUTLS_CRT_X509) {
		WRITEdatum16(pdata, cred->x509_rdn_sequence);
		pdata += cred->x509_rdn_sequence.size + 2;
	}

	return size;
}


/* This function will return the appropriate certificate to use. The return
 * value depends on the side (client or server).
 */
int _gnutls_find_apr_cert(GNUTLS_STATE state, gnutls_cert ** apr_cert_list,
			  int *apr_cert_list_length,
			  gnutls_private_key ** apr_pkey)
{
	const GNUTLS_CERTIFICATE_CREDENTIALS cred;
	int ind;

	cred =
	    _gnutls_get_kx_cred(state->gnutls_key, GNUTLS_CRD_CERTIFICATE,
				NULL);

	if (cred == NULL) {
		gnutls_assert();
		*apr_cert_list = NULL;
		*apr_pkey = NULL;
		*apr_cert_list_length = 0;
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	if (state->security_parameters.entity == GNUTLS_SERVER) {

		if (cred->ncerts == 0) {
			*apr_cert_list = NULL;
			*apr_cert_list_length = 0;
			*apr_pkey = NULL;
			gnutls_assert();	/* this is not allowed */
			return GNUTLS_E_INSUFICIENT_CRED;
		} else {
			/* find_cert_list_index() has been called before.
			 */
			ind = state->gnutls_internals.selected_cert_index;

			if (ind < 0) {
				*apr_cert_list = NULL;
				*apr_cert_list_length = 0;
				*apr_pkey = NULL;
				gnutls_assert();
				return GNUTLS_E_INSUFICIENT_CRED;
			} else {
				*apr_cert_list = cred->cert_list[ind];
				*apr_cert_list_length =
				    cred->cert_list_length[ind];
				*apr_pkey = &cred->pkey[ind];
			}
		}
	} else {		/* CLIENT SIDE */
		if (cred->ncerts == 0) {
			*apr_cert_list = NULL;
			*apr_cert_list_length = 0;
			*apr_pkey = NULL;
			/* it is allowed not to have a certificate 
			 */
		} else {
			/* we had already decided which certificate
			 * to send.
			 */
			ind = state->gnutls_internals.selected_cert_index;

			if (ind < 0) {
				*apr_cert_list = NULL;
				*apr_cert_list_length = 0;
				*apr_pkey = NULL;
			} else {
				*apr_cert_list = cred->cert_list[ind];
				*apr_cert_list_length =
				    cred->cert_list_length[ind];
				*apr_pkey = &cred->pkey[ind];
			}
		}

	}

	return 0;
}

/* finds the most appropriate certificate in the cert list.
 * The 'appropriate' is defined by the user. 
 * (frontend to _gnutls_server_find_cert_index())
 */
const gnutls_cert *_gnutls_server_find_cert(GNUTLS_STATE state,
					    PKAlgorithm requested_algo)
{
	int i;
	const GNUTLS_CERTIFICATE_CREDENTIALS x509_cred;

	x509_cred =
	    _gnutls_get_cred(state->gnutls_key, GNUTLS_CRD_CERTIFICATE,
			     NULL);

	if (x509_cred == NULL)
		return NULL;

	i = _gnutls_server_find_cert_list_index(state,
						x509_cred->cert_list,
						x509_cred->ncerts,
						requested_algo);

	if (i < 0)
		return NULL;

	return &x509_cred->cert_list[i][0];
}

/* finds the most appropriate certificate in the cert list.
 * The 'appropriate' is defined by the user.
 *
 * requested_algo holds the parameters required by the peer (RSA, DSA
 * or -1 for any).
 */
int _gnutls_server_find_cert_list_index(GNUTLS_STATE state,
					gnutls_cert ** cert_list,
					int cert_list_length,
					PKAlgorithm requested_algo)
{
	int i, index = -1, j;
	const GNUTLS_CERTIFICATE_CREDENTIALS cred;
	int my_certs_length;
	int *ij_map = NULL;

	cred =
	    _gnutls_get_cred(state->gnutls_key, GNUTLS_CRD_CERTIFICATE,
			     NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	index = -1;		/* default is use no certificate */

	for (i = 0; i < cred->ncerts; i++) {
		/* find one compatible certificate */
		if (requested_algo == -1 ||
		    requested_algo ==
		    cred->cert_list[i][0].subject_pk_algorithm) {
			/* if cert type matches */
			if (state->security_parameters.cert_type ==
			    cred->cert_list[i][0].cert_type) {
				index = i;
				break;
			}
		}

	}

	if (state->gnutls_internals.server_cert_callback != NULL && cred->ncerts > 0) {	/* use the callback to get certificate */
		gnutls_datum *my_certs = NULL;

		my_certs =
		    gnutls_malloc(cred->ncerts * sizeof(gnutls_datum));
		if (my_certs == NULL)
			goto clear;
		my_certs_length = cred->ncerts;

		/* put our certificate's issuer and dn into cdn, idn
		 */
		ij_map = gnutls_malloc(sizeof(int) * cred->ncerts);

		j = 0;
		for (i = 0; i < cred->ncerts; i++) {
			/* Add compatible certificates */
			if (requested_algo == -1 ||
			    requested_algo ==
			    cred->cert_list[i][0].subject_pk_algorithm) {

				/* if cert type matches */
				if (state->security_parameters.cert_type ==
				    cred->cert_list[i][0].cert_type) {

					ij_map[j] = i;
					my_certs[j++] =
					    cred->cert_list[i][0].raw;
				}
			}
		}
		my_certs_length = j;

		index =
		    state->gnutls_internals.server_cert_callback(state,
								 my_certs,
								 my_certs_length);

		index = ij_map[index];

	      clear:
		gnutls_free(my_certs);
		gnutls_free(ij_map);
	}

	/* store the index for future use, in the handshake.
	 * (This will allow not calling this callback again.)
	 */
	state->gnutls_internals.selected_cert_index = index;
	return index;
}
