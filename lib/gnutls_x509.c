/*
 *      Copyright (C) 2002 Nikos Mavroyanopoulos
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
#include <gnutls_str.h>
#include <debug.h>
#include <x509_b64.h>
#include <gnutls_privkey.h>
#include <gnutls_x509.h>

/*
 * some x509 certificate parsing functions.
 */

int gnutls_x509_pkcs7_extract_certificate(const gnutls_datum * pkcs7_struct, int indx, char* certificate, int* certificate_size);
int gnutls_x509_pkcs7_extract_certificate_count(const gnutls_datum * pkcs7_struct);


#define _READ(a, aa, b, c, d, e, res, f) \
	result = _IREAD(a, aa, sizeof(aa), b, c, d, e, res, sizeof(res)-1, f); \
	if (result<0) return result; \
	if (result==1) continue


static int _IREAD(node_asn * rasn, char *name3, int name3_size, char *rstr, char *OID,
	   char *ANAME, char *TYPE, char *res, int res_size, int CHOICE)
{
	char name2[256];
	int result, len;
	char str[1024];
	node_asn *tmpasn;

	if (strcmp(rstr, OID) == 0) {

		_gnutls_str_cpy(str, sizeof(str), "PKIX1."); 
		_gnutls_str_cat(str, sizeof(str), ANAME); 
		_gnutls_str_cpy(name2, sizeof(name2), "temp-structure-"); 
		_gnutls_str_cat(name2, sizeof(name2), TYPE); 

		if ((result =
		     asn1_create_structure(_gnutls_get_pkix(), str,
					   &tmpasn, name2)) != ASN_OK) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}

		len = sizeof(str) -1;
		if ((result =
		     asn1_read_value(rasn, name3, str, &len)) != ASN_OK) {
			asn1_delete_structure(tmpasn);
			return 1;
		}

		if ((result = asn1_get_der(tmpasn, str, len)) != ASN_OK) {
			asn1_delete_structure(tmpasn);
			return 1;
		}
		_gnutls_str_cpy(name3, name3_size, name2);

		len = sizeof(str) - 1;
		if ((result = asn1_read_value(tmpasn, name3, str, &len)) != ASN_OK) {	/* CHOICE */
			asn1_delete_structure(tmpasn);
			return 1;
		}

		if (CHOICE == 0) {
			str[len] = 0;
			/* strlen(str) < res_size, checked above */
			_gnutls_str_cpy(res, res_size, str); 
			
		} else {	/* CHOICE */
			str[len] = 0;
			_gnutls_str_cat(name3, name3_size, "."); 
			_gnutls_str_cat(name3, name3_size, str); 
			len = sizeof(str) - 1;

			if ((result =
			     asn1_read_value(tmpasn, name3, str,
					     &len)) != ASN_OK) {
				asn1_delete_structure(tmpasn);
				return 1;
			}
			str[len] = 0;
			if ( len < res_size)
				_gnutls_str_cpy(res, res_size, str); 
		}
		asn1_delete_structure(tmpasn);

	}
	return 0;
}

/* this function will convert up to 3 digit
 * numbers to characters.
 */
void _gnutls_int2str(int k, char *data)
{
	if (k > 999)
		data[0] = 0;
	else
		sprintf(data, "%d", k); 
}

/* This function will attempt to read a Name
 * ASN.1 structure. (Taken from Fabio's samples!)
 *
 * FIXME: These functions need carefull auditing
 * (they're complex enough)
 * --nmav
 */
int _gnutls_x509_get_name_type(node_asn * rasn, char *root, gnutls_DN * dn)
{
	int k, k2, result, len;
	char name[128], str[1024], name2[128], counter[MAX_INT_DIGITS],
	    name3[128];

	k = 0;
	do {
		k++;

		_gnutls_str_cpy(name, sizeof(name), root); 
		_gnutls_str_cat(name, sizeof(name), ".rdnSequence.?"); 
		_gnutls_int2str(k, counter);
		_gnutls_str_cat(name, sizeof(name), counter); 

		len = sizeof(str) - 1;

		result = asn1_read_value(rasn, name, str, &len);

		/* move to next
		 */
		if (result == ASN_ELEMENT_NOT_FOUND)
			break;
		if (result != ASN_VALUE_NOT_FOUND) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}

		k2 = 0;
		do {
			k2++;

			_gnutls_str_cpy(name2, sizeof(name2), name); 
			_gnutls_str_cat(name2, sizeof(name2), ".?"); 
			_gnutls_int2str(k2, counter);
			_gnutls_str_cat(name2, sizeof(name2), counter); 

			len = sizeof(str) - 1;
			result = asn1_read_value(rasn, name2, str, &len);

			if (result == ASN_ELEMENT_NOT_FOUND)
				break;
			if (result != ASN_VALUE_NOT_FOUND) {
				gnutls_assert();
				return _gnutls_asn2err(result);
			}

			_gnutls_str_cpy(name3, sizeof(name3), name2);
			_gnutls_str_cat(name3, sizeof(name3), ".type"); 

			len = sizeof(str) - 1;
			result = asn1_read_value(rasn, name3, str, &len);

			if (result == ASN_ELEMENT_NOT_FOUND)
				break;
			else if (result != ASN_OK) {
				gnutls_assert();
				return _gnutls_asn2err(result);
			}

			_gnutls_str_cpy(name3, sizeof(name3), name2);
			_gnutls_str_cat(name3, sizeof(name3), ".value"); 

			if (result == ASN_OK) {
#ifdef DEBUG
# warning " FIX COUNTRY HERE"
#endif
				_READ(rasn, name3, str, "2 5 4 6",
				      "X520OrganizationName",
				      "countryName", dn->country, 1);
				_READ(rasn, name3, str, "2 5 4 10",
				      "X520OrganizationName",
				      "OrganizationName", dn->organization,
				      1);
				_READ(rasn, name3, str, "2 5 4 11",
				      "X520OrganizationalUnitName",
				      "OrganizationalUnitName",
				      dn->organizational_unit_name, 1);
				_READ(rasn, name3, str, "2 5 4 3",
				      "X520CommonName", "CommonName",
				      dn->common_name, 1);
				_READ(rasn, name3, str, "2 5 4 7",
				      "X520LocalityName", "LocalityName",
				      dn->locality_name, 1);
				_READ(rasn, name3, str, "2 5 4 8",
				      "X520StateOrProvinceName",
				      "StateOrProvinceName",
				      dn->state_or_province_name, 1);
				_READ(rasn, name3, str,
				      "1 2 840 113549 1 9 1", "Pkcs9email",
				      "emailAddress", dn->email, 0);
			}
		} while (1);
	} while (1);

	if (result == ASN_ELEMENT_NOT_FOUND)
		return 0;
	else
		return _gnutls_asn2err(result);
}



#define MAX_TIME 1024
time_t _gnutls_x509_get_time(node_asn * c2, char *root, char *when)
{
	opaque ttime[MAX_TIME];
	char name[1024];
	time_t ctime;
	int len, result;

	_gnutls_str_cpy(name, sizeof(name), root);
	_gnutls_str_cat(name, sizeof(name), ".tbsCertificate.validity."); 
	_gnutls_str_cat(name, sizeof(name), when);

	len = sizeof(ttime) - 1;
	if ((result = asn1_read_value(c2, name, ttime, &len)) < 0) {
		gnutls_assert();
		return (time_t) (-1);
	}

	/* CHOICE */
	_gnutls_str_cpy(name, sizeof(name), root);

	if (strcmp(ttime, "GeneralizedTime") == 0) {

		_gnutls_str_cat(name, sizeof(name), ".tbsCertificate.validity."); 
		_gnutls_str_cat(name, sizeof(name), when);
		_gnutls_str_cat(name, sizeof(name), ".generalTime"); 
		len = sizeof(ttime) - 1;
		result = asn1_read_value(c2, name, ttime, &len);
		if (result == ASN_OK)
			ctime = _gnutls_generalTime2gtime(ttime);
	} else {		/* UTCTIME */

		_gnutls_str_cat(name, sizeof(name), ".tbsCertificate.validity."); 
		_gnutls_str_cat(name, sizeof(name), when);
		_gnutls_str_cat(name, sizeof(name), ".utcTime"); 
		len = sizeof(ttime) - 1;
		result = asn1_read_value(c2, name, ttime, &len);
		if (result == ASN_OK)
			ctime = _gnutls_utcTime2gtime(ttime);
	}

	/* We cannot handle dates after 2031 in 32 bit machines.
	 * a time_t of 64bits has to be used.
	 */
	 	
	if (result != ASN_OK) {
		gnutls_assert();
		return (time_t) (-1);
	}
	return ctime;
}

int _gnutls_x509_get_version(node_asn * c2, char *root)
{
	opaque gversion[5];
	char name[1024];
	int len, result;

	_gnutls_str_cpy(name, sizeof(name), root);
	_gnutls_str_cat(name, sizeof(name), ".tbsCertificate.version"); 

	len = sizeof(gversion) - 1;
	if ((result = asn1_read_value(c2, name, gversion, &len)) < 0) {
		gnutls_assert();
		return result;
	}
	return (int) gversion[0] + 1;
}





/**
  * gnutls_x509_extract_dn - This function parses an RDN sequence
  * @idn: should contain a DER encoded RDN sequence
  * @rdn: a pointer to a structure to hold the name
  *
  * This function will return the name of the given RDN sequence.
  * The name will be returned as a gnutls_x509_dn structure.
  * Returns a negative error code in case of an error.
  *
  **/
int gnutls_x509_extract_dn(const gnutls_datum * idn, gnutls_x509_dn * rdn)
{
	node_asn *dn;
	int result;

	if ((result =
	     asn1_create_structure(_gnutls_get_pkix(),
				   "PKIX1.Name", &dn,
				   "dn")) != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_get_der(dn, idn->data, idn->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure(dn);
		return _gnutls_asn2err(result);
	}

	result = _gnutls_x509_get_name_type(dn, "dn", rdn);
	asn1_delete_structure(dn);

	if (result < 0) {
		/* couldn't decode DER */
		gnutls_assert();
		return result;
	}

	return 0;
}

/**
  * gnutls_x509_extract_certificate_dn - This function returns the certificate's distinguished name
  * @cert: should contain an X.509 DER encoded certificate
  * @ret: a pointer to a structure to hold the peer's name
  *
  * This function will return the name of the certificate holder. The name is gnutls_x509_dn structure and 
  * is a obtained by the peer's certificate. If the certificate send by the
  * peer is invalid, or in any other failure this function returns error.
  * Returns a negative error code in case of an error.
  *
  **/
int gnutls_x509_extract_certificate_dn(const gnutls_datum * cert,
					  gnutls_x509_dn * ret)
{
	node_asn *c2;
	int result;

	memset(ret, 0, sizeof(gnutls_x509_dn));

	if ((result=asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1.Certificate", &c2,
	     "certificate2"))
	    != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}


	result = asn1_get_der(c2, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("X509_auth: Decoding error %d\n", result);

		gnutls_assert();
		asn1_delete_structure(c2);
		return _gnutls_asn2err(result);
	}
	if ((result =
	     _gnutls_x509_get_name_type(c2,
				   "certificate2.tbsCertificate.subject",
				   ret)) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return result;
	}

	asn1_delete_structure(c2);

	return 0;
}

/**
  * gnutls_x509_extract_certificate_issuer_dn - This function returns the certificate's issuer distinguished name
  * @cert: should contain an X.509 DER encoded certificate
  * @ret: a pointer to a structure to hold the issuer's name
  *
  * This function will return the name of the issuer stated in the certificate. The name is a gnutls_x509_dn structure and 
  * is a obtained by the peer's certificate. If the certificate send by the
  * peer is invalid, or in any other failure this function returns error.
  * Returns a negative error code in case of an error.
  *
  **/
int gnutls_x509_extract_certificate_issuer_dn(const gnutls_datum * cert,
						 gnutls_x509_dn * ret)
{
	node_asn *c2;
	int result;

	memset(ret, 0, sizeof(gnutls_x509_dn));

	if ((result=asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1.Certificate", &c2,
	     "certificate2"))
	    != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_get_der(c2, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("X509_auth: Decoding error %d\n", result);

		gnutls_assert();
		asn1_delete_structure(c2);
		return _gnutls_asn2err(result);
	}
	if ((result =
	     _gnutls_x509_get_name_type(c2,
				   "certificate2.tbsCertificate.issuer",
				   ret)) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return result;
	}

	asn1_delete_structure(c2);

	return 0;
}

static GNUTLS_X509_SUBJECT_ALT_NAME _find_type( char* str_type) {
	if (strcmp( str_type, "dNSName")==0) return GNUTLS_SAN_DNSNAME;
	if (strcmp( str_type, "rfc822Name")==0) return GNUTLS_SAN_RFC822NAME;
	if (strcmp( str_type, "uniformResourceIdentifier")==0) return GNUTLS_SAN_URI;
	if (strcmp( str_type, "iPAddress")==0) return GNUTLS_SAN_IPADDRESS;
	return -1;
}

/**
  * gnutls_x509_extract_subject_alt_name - This function returns the peer's alt name, if any
  * @cert: should contain an X.509 DER encoded certificate
  * @seq: specifies the sequence number of the alt name (0 for the first one, 1 for the second etc.)
  * @ret: is the place where dns name will be copied to
  * @ret_size: holds the size of ret.
  *
  * This function will return the alternative name (the dns part of it), contained in the
  * given certificate.
  * 
  * This is specified in X509v3 Certificate Extensions. 
  * GNUTLS will return the Alternative name, or a negative
  * error code.
  * Returns GNUTLS_E_INVALID_REQUEST if ret_size is not enough to hold the alternative name,
  * or the type of alternative name if everything was ok. The type is one of the
  * enumerated GNUTLS_X509_SUBJECT_ALT_NAME.
  *
  * If the certificate does not have an Alternative name with the specified sequence number
  * then returns GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  *
  **/
int gnutls_x509_extract_subject_alt_name(const gnutls_datum * cert, int seq, char *ret, int *ret_size)
{
	int result;
	gnutls_datum dnsname;
	node_asn *c2;
	char nptr[128];
	char ext_data[256];
	int len;
	char num[MAX_INT_DIGITS];
	GNUTLS_X509_SUBJECT_ALT_NAME type;

	memset(ret, 0, *ret_size);

	if ((result =
	     _gnutls_get_extension(cert, "2 5 29 17", &dnsname)) < 0) {
	     	gnutls_assert();
		return result;
	}

	if (dnsname.size == 0 || dnsname.data==NULL) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	if ((result=asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1.SubjectAltName", &c2, "san"))
	    != ASN_OK) {
		gnutls_assert();
		gnutls_free_datum( &dnsname);
		return _gnutls_asn2err(result);
	}

	result = asn1_get_der(c2, dnsname.data, dnsname.size);
	gnutls_free_datum( &dnsname);

	if (result != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("X509_auth: Decoding error %d\n", result);
		gnutls_assert();
		asn1_delete_structure(c2);
		return _gnutls_asn2err(result);
	}

	seq++; /* 0->1, 1->2 etc */
	_gnutls_int2str( seq, num);
	_gnutls_str_cpy( nptr, sizeof(nptr), "san.?");
	_gnutls_str_cat( nptr, sizeof(nptr), num);

	len = sizeof(ext_data);
	result =
	     asn1_read_value(c2, nptr, ext_data, &len);

	if (result == ASN_VALUE_NOT_FOUND) {
		asn1_delete_structure(c2);
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return _gnutls_asn2err(result);
	}


	type = _find_type( ext_data);
	if (type == -1) {
		gnutls_assert();
		return GNUTLS_E_X509_UNKNOWN_SAN;
	}

	_gnutls_str_cat( nptr, sizeof(nptr), ".");
	_gnutls_str_cat( nptr, sizeof(nptr), ext_data);

	len = sizeof(ext_data);

	result =
	     asn1_read_value(c2, nptr, ret, ret_size);
	asn1_delete_structure(c2);
	
	if (result==ASN_MEM_ERROR)
		return GNUTLS_E_INVALID_REQUEST;
	
	if (result != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	return type;
}

/**
  * gnutls_x509_extract_certificate_activation_time - This function returns the peer's certificate activation time
  * @cert: should contain an X.509 DER encoded certificate
  *
  * This function will return the certificate's activation time in UNIX time 
  * (ie seconds since 00:00:00 UTC January 1, 1970).
  * Returns a (time_t) -1 in case of an error.
  *
  **/
time_t gnutls_x509_extract_certificate_activation_time(const
							  gnutls_datum *
							  cert)
{
	node_asn *c2;
	int result;
	time_t ret;

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1.Certificate", &c2,
	     "certificate2")
	    != ASN_OK) {
		gnutls_assert();
		return (time_t)-1;
	}

	result = asn1_get_der(c2, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("X509_auth: Decoding error %d\n", result);

		gnutls_assert();
		return (time_t)-1;
	}

	ret = _gnutls_x509_get_time(c2, "certificate2", "notBefore");

	asn1_delete_structure(c2);

	return ret;
}

/**
  * gnutls_x509_extract_certificate_expiration_time - This function returns the certificate's expiration time
  * @cert: should contain an X.509 DER encoded certificate
  *
  * This function will return the certificate's expiration time in UNIX time 
  * (ie seconds since 00:00:00 UTC January 1, 1970).
  * Returns a (time_t) -1 in case of an error.
  *
  **/
time_t gnutls_x509_extract_certificate_expiration_time(const
							  gnutls_datum *
							  cert)
{
	node_asn *c2;
	int result;
	time_t ret;

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1.Certificate", &c2,
	     "certificate2")
	    != ASN_OK) {
		gnutls_assert();
		return (time_t)-1;
	}

	result = asn1_get_der(c2, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("X509_auth: Decoding error %d\n", result);

		gnutls_assert();
		return (time_t)-1;
	}

	ret = _gnutls_x509_get_time(c2, "certificate2", "notAfter");

	asn1_delete_structure(c2);

	return ret;
}

/**
  * gnutls_x509_extract_certificate_version - This function returns the certificate's version
  * @cert: is an X.509 DER encoded certificate
  *
  * This function will return the X.509 certificate's version (1, 2, 3). This is obtained by the X509 Certificate
  * Version field. Returns a negative value in case of an error.
  *
  **/
int gnutls_x509_extract_certificate_version(const gnutls_datum * cert)
{
	node_asn *c2;
	int result;

	if ((result=asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1.Certificate", &c2,
	     "certificate2"))
	    != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_get_der(c2, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("X509_auth: Decoding error %d\n", result);

		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = _gnutls_x509_get_version(c2, "certificate2");

	asn1_delete_structure(c2);

	return result;

}

#define CLEAR_CERTS for(x=0;x<peer_certificate_list_size;x++) _gnutls_free_cert(peer_certificate_list[x])

/*-
  * _gnutls_x509_cert_verify_peers - This function returns the peer's certificate status
  * @state: is a gnutls state
  *
  * This function will try to verify the peer's certificate and return it's status (TRUSTED, EXPIRED etc.). 
  * The return value (status) should be one of the CertificateStatus enumerated elements.
  * However you must also check the peer's name in order to check if the verified certificate belongs to the 
  * actual peer. Returns a negative error code in case of an error, or GNUTLS_E_NO_CERTIFICATE_FOUND if no certificate was sent.
  *
  -*/
int _gnutls_x509_cert_verify_peers(GNUTLS_STATE state)
{
	CERTIFICATE_AUTH_INFO info;
	const GNUTLS_CERTIFICATE_CREDENTIALS cred;
	CertificateStatus verify;
	gnutls_cert *peer_certificate_list;
	int peer_certificate_list_size, i, x, ret;

	CHECK_AUTH(GNUTLS_CRD_CERTIFICATE, GNUTLS_E_INVALID_REQUEST);

	info = _gnutls_get_auth_info(state);
	if (info == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}
	
	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_CRD_CERTIFICATE, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	if (info->raw_certificate_list == NULL || info->ncerts == 0)
		return GNUTLS_E_NO_CERTIFICATE_FOUND;

	/* generate a list of gnutls_certs based on the auth info
	 * raw certs.
	 */
	peer_certificate_list_size = info->ncerts;
	peer_certificate_list =
	    gnutls_calloc(1,
			  peer_certificate_list_size *
			  sizeof(gnutls_cert));
	if (peer_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	for (i = 0; i < peer_certificate_list_size; i++) {
		if ((ret =
		     _gnutls_x509_cert2gnutls_cert(&peer_certificate_list[i],
					     info->
					     raw_certificate_list[i])) <
		    0) {
			gnutls_assert();
			CLEAR_CERTS;
			gnutls_free(peer_certificate_list);
			return ret;
		}
	}

	/* Verify certificate 
	 */
	verify =
	    _gnutls_x509_verify_certificate(peer_certificate_list,
				      peer_certificate_list_size,
				      cred->x509_ca_list, cred->x509_ncas, NULL, 0);

	CLEAR_CERTS;
	gnutls_free(peer_certificate_list);

	if (verify < 0) {
		gnutls_assert();
		return verify;
	}


	return verify;
}

#define CLEAR_CERTS_CA for(x=0;x<peer_certificate_list_size;x++) _gnutls_free_cert(peer_certificate_list[x]); \
		for(x=0;x<ca_certificate_list_size;x++) _gnutls_free_cert(ca_certificate_list[x])
/**
  * gnutls_x509_verify_certificate - This function verifies given certificate list
  * @cert_list: is the certificate list to be verified
  * @cert_list_length: holds the number of certificate in cert_list
  * @CA_list: is the CA list which will be used in verification
  * @CA_list_length: holds the number of CA certificate in CA_list
  * @CRL_list: not used
  * @CRL_list_length: not used
  *
  * This function will try to verify the given certificate list and return it's status (TRUSTED, EXPIRED etc.). 
  * The return value (status) should be one or more of the CertificateStatus 
  * enumerated elements bitwise or'd.
  *
  * However you must also check the peer's name in order to check if the verified certificate belongs to the 
  * actual peer. 
  *
  * Returns a negative error code in case of an error.
  *
  **/
int gnutls_x509_verify_certificate( const gnutls_datum* cert_list, int cert_list_length, const gnutls_datum * CA_list, int CA_list_length, const gnutls_datum* CRL_list, int CRL_list_length)
{
	CertificateStatus verify;
	gnutls_cert *peer_certificate_list;
	gnutls_cert *ca_certificate_list;
	int peer_certificate_list_size, i, x, ret, ca_certificate_list_size;

	if (cert_list == NULL || cert_list_length == 0)
		return GNUTLS_E_NO_CERTIFICATE_FOUND;

	/* generate a list of gnutls_certs based on the auth info
	 * raw certs.
	 */
	peer_certificate_list_size = cert_list_length;
	peer_certificate_list =
	    gnutls_calloc(1,
			  peer_certificate_list_size *
			  sizeof(gnutls_cert));
	if (peer_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	ca_certificate_list_size = CA_list_length;
	ca_certificate_list =
	    gnutls_calloc(1,
			  ca_certificate_list_size *
			  sizeof(gnutls_cert));
	if (ca_certificate_list == NULL) {
		gnutls_assert();
		gnutls_free( peer_certificate_list);
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* convert certA_list to gnutls_cert* list
	 */
	for (i = 0; i < peer_certificate_list_size; i++) {
		if ((ret =
		     _gnutls_x509_cert2gnutls_cert(&peer_certificate_list[i],
					     cert_list[i])) < 0) {
			gnutls_assert();
			CLEAR_CERTS_CA;
			gnutls_free( peer_certificate_list);
			gnutls_free( ca_certificate_list);
			return ret;
		}
	}

	/* convert CA_list to gnutls_cert* list
	 */
	for (i = 0; i < ca_certificate_list_size; i++) {
		if ((ret =
		     _gnutls_x509_cert2gnutls_cert(&ca_certificate_list[i],
					     CA_list[i])) < 0) {
			gnutls_assert();
			CLEAR_CERTS_CA;
			gnutls_free( peer_certificate_list);
			gnutls_free( ca_certificate_list);
			return ret;
		}
	}

	/* Verify certificate 
	 */
	verify =
	    _gnutls_x509_verify_certificate(peer_certificate_list,
				      peer_certificate_list_size,
				      ca_certificate_list, ca_certificate_list_size, NULL, 0);

	CLEAR_CERTS_CA;
	gnutls_free( peer_certificate_list);
	gnutls_free( ca_certificate_list);

	if (verify < 0) {
		gnutls_assert();
		return verify;
	}

	return verify;
}

/**
  * gnutls_x509_extract_certificate_serial - This function returns the certificate's serial number
  * @cert: is an X.509 DER encoded certificate
  * @result: The place where the serial number will be copied
  * @result_size: Holds the size of the result field.
  *
  * This function will return the X.509 certificate's serial number. 
  * This is obtained by the X509 Certificate serialNumber
  * field. Serial is not always a 32 or 64bit number. Some CAs use
  * large serial numbers, thus it may be wise to handle it as something
  * opaque. 
  * Returns a negative value in case of an error.
  *
  **/
int gnutls_x509_extract_certificate_serial(const gnutls_datum * cert, char* result, int* result_size)
{
	node_asn *c2;
	int ret;

	if ((ret=asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1.Certificate", &c2,
	     "certificate2"))
	    != ASN_OK) {
		gnutls_assert();
		return ret;
	}

	ret = asn1_get_der(c2, cert->data, cert->size);
	if (ret != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("X509_auth: Decoding error %d\n", result);

		gnutls_assert();
		return ret;
	}

	if ((ret = asn1_read_value(c2, "certificate2.tbsCertificate.serialNumber", result, result_size)) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return ret;
	}

	asn1_delete_structure(c2);

	return 0;

}


/*
 * Read certificates and private keys, from files, memory etc.
 */

/* returns error if the certificate has different algorithm than
 * the given key parameters.
 */
static int _gnutls_check_key_cert_match( GNUTLS_CERTIFICATE_CREDENTIALS res) {
	
	if (res->pkey[res->ncerts-1].pk_algorithm != res->cert_list[res->ncerts-1][0].subject_pk_algorithm) {
		gnutls_assert();
		return GNUTLS_E_CERTIFICATE_KEY_MISMATCH;
	}
	return 0;
}

#define MAX_FILE_SIZE 100*1024
#define CERT_SEP "-----BEGIN"

/* Reads a DER encoded certificate list from memory and stores it to
 * a gnutls_cert structure. This is only called if PKCS7 read fails.
 * returns the number of certificates parsed (1)
 */
static int parse_der_cert_mem( gnutls_cert** cert_list, int* ncerts, 
	const char *input_cert, int input_cert_size)
{
	int i;
	gnutls_datum tmp;
	int ret;

	i = *ncerts + 1;

	*cert_list =
	    (gnutls_cert *) gnutls_realloc( *cert_list,
					   i *
					   sizeof(gnutls_cert));

	if ( *cert_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	tmp.data = (opaque*) input_cert;
	tmp.size = input_cert_size;

	if ((ret =
	     _gnutls_x509_cert2gnutls_cert(
				     &cert_list[0][i - 1],
				     tmp)) < 0) {
		gnutls_assert();
		return ret;
	}

	*ncerts = i;

	return 1; /* one certificate parsed */
}


/* Reads a PKCS7 base64 encoded certificate list from memory and stores it to
 * a gnutls_cert structure.
 * returns the number of certificate parsed
 */
static int parse_pkcs7_cert_mem( gnutls_cert** cert_list, int* ncerts, 
	const char *input_cert, int input_cert_size)
{
	int i, j, count;
	gnutls_datum tmp, tmp2;
	int ret;
	opaque pcert[MAX_X509_CERT_SIZE];
	int pcert_size;

	i = *ncerts + 1;

	/* tmp now contains the decoded certificate list */
	tmp.data = (opaque*)input_cert;
	tmp.size = input_cert_size;

	count = gnutls_x509_pkcs7_extract_certificate_count( &tmp);

	if (count < 0) {
		gnutls_assert();
		/* if we failed to read the count,
		 * then just try to decode a plain DER
		 * certificate.
		 */
		return parse_der_cert_mem( cert_list, ncerts,
			input_cert, input_cert_size);
	}
	
	
	j = count - 1;
	do {
		pcert_size = sizeof(pcert);
		ret = gnutls_x509_pkcs7_extract_certificate( &tmp, j, pcert, &pcert_size);
		j--;

		/* if the current certificate is too long, just ignore
		 * it. */
		if (ret==GNUTLS_E_MEMORY_ERROR) {
			count--;
			continue;
		}
		
		if (ret >= 0) {
			*cert_list =
			    (gnutls_cert *) gnutls_realloc( *cert_list,
					   i * sizeof(gnutls_cert));

			if ( *cert_list == NULL) {
				gnutls_assert();
				return GNUTLS_E_MEMORY_ERROR;
			}

			tmp2.data = pcert;
			tmp2.size = pcert_size;

			if ((ret =
			     _gnutls_x509_cert2gnutls_cert(
						     &cert_list[0][i - 1],
						     tmp2)) < 0) {
				gnutls_assert();
				return ret;
			}
			
			i++;
		}

	} while (ret >= 0 && j >= 0);
	
	*ncerts = i - 1;

	return count;
}


/* Reads a base64 encoded certificate list from memory and stores it to
 * a gnutls_cert structure. Returns the number of certificate parsed.
 */
static int parse_pem_cert_mem( gnutls_cert** cert_list, int* ncerts, 
	const char *input_cert, int input_cert_size)
{
	int siz, i, siz2;
	opaque *b64;
	const char *ptr;
	gnutls_datum tmp;
	int ret, count;

	if (strstr( input_cert, "-----BEGIN PKCS7")!=NULL) {
		siz2 = _gnutls_fbase64_decode(ptr, siz, &b64);

		ret = parse_pkcs7_cert_mem( cert_list, ncerts, b64,
			siz2);

		gnutls_free(b64);
		
		return ret;
	}

	
	ptr = input_cert;
	siz = input_cert_size;
	i = *ncerts + 1;
	count = 0;

	do {
		siz2 = _gnutls_fbase64_decode(ptr, siz, &b64);
		siz -= siz2;	/* FIXME: this is not enough
				 */

		if (siz2 < 0) {
			gnutls_assert();
			return GNUTLS_E_PARSING_ERROR;
		}


		*cert_list =
		    (gnutls_cert *) gnutls_realloc( *cert_list,
						   i *
						   sizeof(gnutls_cert));

		if ( *cert_list == NULL) {
			gnutls_assert();
			gnutls_free(b64);
			return GNUTLS_E_MEMORY_ERROR;
		}

		tmp.data = b64;
		tmp.size = siz2;

		if ((ret =
		     _gnutls_x509_cert2gnutls_cert(
					     &cert_list[0][i - 1],
					     tmp)) < 0) {
			gnutls_free(b64);
			gnutls_assert();
			return ret;
		}
		gnutls_free(b64);

		/* now we move ptr after the pem header */
		ptr = strstr(ptr, CERT_SEP);
		if (ptr!=NULL)
			ptr++;

		i++;
		count++;
	} while ((ptr = strstr(ptr, CERT_SEP)) != NULL);

	*ncerts = i - 1;

	return count;
}



/* Reads a base64 encoded certificate from memory
 */
static int read_cert_mem(GNUTLS_CERTIFICATE_CREDENTIALS res, const char *cert, int cert_size, 
	GNUTLS_X509_CertificateFmt type)
{
	int ret;

	/* allocate space for the certificate to add
	 */
	res->cert_list = gnutls_realloc( res->cert_list, (1+ res->ncerts)*sizeof(gnutls_cert*));
	if ( res->cert_list==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	res->cert_list_length = gnutls_realloc( res->cert_list_length,
		(1+ res->ncerts)*sizeof(int));
	if (res->cert_list_length==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	res->cert_list[res->ncerts] = NULL; /* for realloc */
	res->cert_list_length[res->ncerts] = 0;

	if (type==GNUTLS_X509_FMT_DER)
		ret = parse_pkcs7_cert_mem( &res->cert_list[res->ncerts], &res->cert_list_length[res->ncerts],
		cert, cert_size);
	else
		ret = parse_pem_cert_mem( &res->cert_list[res->ncerts], &res->cert_list_length[res->ncerts],
		cert, cert_size);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;
}

/* Reads a base64 encoded CA list from memory 
 * This is to be called once.
 */
static int read_ca_mem(GNUTLS_CERTIFICATE_CREDENTIALS res, const char *ca, int ca_size,
	GNUTLS_X509_CertificateFmt type)
{

	if (type==GNUTLS_X509_FMT_DER)
		return parse_der_cert_mem( &res->x509_ca_list, &res->x509_ncas,
			ca, ca_size);
	else
		return parse_pem_cert_mem( &res->x509_ca_list, &res->x509_ncas,
			ca, ca_size);

}


/* This will check if the given DER key is a PKCS-1 RSA key.
 */
int _gnutls_der_check_if_rsa_key(const gnutls_datum * key_struct)
{
	node_asn *c2;
	int result;
	char root2[128];

	/* Step 1. Parse content and content info */
	
	if (key_struct->size == 0 || key_struct->data == NULL) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	_gnutls_str_cpy( root2, sizeof(root2), "GNUTLS.RSAPrivateKey");
	if ((result=asn1_create_structure
	    (_gnutls_get_gnutls_asn(), root2, &c2, "rsakey")) != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_get_der(c2, key_struct->data, key_struct->size);
	asn1_delete_structure(c2);

	if (result != ASN_OK) {
		/* couldn't decode DER */
	
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	return 0;
}





/* Reads a PEM encoded PKCS-1 RSA private key from memory
 * 2002-01-26: Added ability to read DSA keys.
 * type==0 then certificate is DER formatted, else -> DER
 */
static int read_key_mem(GNUTLS_CERTIFICATE_CREDENTIALS res, const char *key, int key_size, 
	GNUTLS_X509_CertificateFmt type)
{
	int ret;
	opaque *b64 = NULL;
	gnutls_datum tmp;
	PKAlgorithm pk;

	/* allocate space for the pkey list
	 */
	res->pkey = gnutls_realloc( res->pkey, (res->ncerts+1)*sizeof(gnutls_private_key));
	if (res->pkey==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* read PKCS-1 private key */

	if (type==GNUTLS_X509_FMT_DER) { /* DER */
		int cv;
		
		tmp.data = (opaque*)key;
		tmp.size = key_size;

		/* The only way to distinguish the keys
		 * is to count the sequence of integers.
		 */
		cv = _gnutls_der_check_if_rsa_key( &tmp);
		if (cv==0)
			pk = GNUTLS_PK_RSA;
		else
			pk = GNUTLS_PK_DSA;

	} else { /* PEM */

		/* If we find the "DSA PRIVATE" string in the
		 * pem encoded certificate then it's a DSA key.
		 */
		if (strstr( key, "DSA PRIVATE")!=NULL) 
			pk = GNUTLS_PK_DSA;
		else
			pk = GNUTLS_PK_RSA;

		ret = _gnutls_fbase64_decode(key, key_size, &b64);

		if (ret < 0) {
			gnutls_assert();
			return GNUTLS_E_PARSING_ERROR;
		}

		tmp.data = b64;
		tmp.size = ret;
	}

	switch (pk) { /* decode the key */
		case GNUTLS_PK_RSA:
			if ((ret =
			     _gnutls_PKCS1key2gnutlsKey(&res->pkey[res->ncerts],
						tmp)) < 0) {
				gnutls_assert();
				gnutls_free(b64);
				return ret;
			}
			break;
		case GNUTLS_PK_DSA:
			if ((ret =
			     _gnutls_DSAkey2gnutlsKey(&res->pkey[res->ncerts],
							tmp)) < 0) {
				gnutls_assert();
				gnutls_free(b64);
				return ret;
			}
			break;	
	}

	/* this doesn't hurt in the DER case, since
	 * b64 is NULL
	 */
	gnutls_free(b64);
	
	return 0;
}


/* Reads a certificate file
 */
static int read_cert_file(GNUTLS_CERTIFICATE_CREDENTIALS res, char *certfile,
	GNUTLS_X509_CertificateFmt type)
{
	int siz;
	char x[MAX_FILE_SIZE];
	FILE *fd1;

	fd1 = fopen(certfile, "rb");
	if (fd1 == NULL)
		return GNUTLS_E_FILE_ERROR;

	siz = fread(x, 1, sizeof(x)-1, fd1);
	fclose(fd1);

	x[siz] = 0;

	return read_cert_mem( res, x, siz, type);

}

/* Reads a base64 encoded CA file (file contains multiple certificate
 * authorities). This is to be called once.
 */
static int read_ca_file(GNUTLS_CERTIFICATE_CREDENTIALS res, char *cafile, 
	GNUTLS_X509_CertificateFmt type)
{
	int siz;
	char x[MAX_FILE_SIZE];
	FILE *fd1;

	fd1 = fopen(cafile, "rb");
	if (fd1 == NULL) {
		gnutls_assert();
		return GNUTLS_E_FILE_ERROR;
	}

	siz = fread(x, 1, sizeof(x)-1, fd1);
	fclose(fd1);

	x[siz] = 0;

	return read_ca_mem( res, x, siz, type);
}


/* Reads PKCS-1 RSA private key file or a DSA file (in the format openssl
 * stores it).
 */
static int read_key_file(GNUTLS_CERTIFICATE_CREDENTIALS res, char *keyfile,
	GNUTLS_X509_CertificateFmt type)
{
	int siz;
	char x[MAX_FILE_SIZE];
	FILE *fd2;

	fd2 = fopen(keyfile, "rb");
	if (fd2 == NULL)
		return GNUTLS_E_FILE_ERROR;

	siz = fread(x, 1, sizeof(x)-1, fd2);
	fclose(fd2);

	x[siz] = 0;

	return read_key_mem( res, x, siz, type);
}


/**
  * gnutls_certificate_set_x509_key_file - Used to set keys in a GNUTLS_CERTIFICATE_CREDENTIALS structure
  * @res: is an &GNUTLS_CERTIFICATE_CREDENTIALS structure.
  * @CERTFILE: is a file that containing the certificate list (path) for
  * the specified private key, in PKCS7 format, or a list of certificates
  * @KEYFILE: is a file that contains the private key
  * @type: is PEM or DER
  *
  * This function sets a certificate/private key pair in the 
  * GNUTLS_CERTIFICATE_CREDENTIALS structure. This function may be called
  * more than once (in case multiple keys/certificates exist for the
  * server).
  *
  * Currently only PKCS-1 encoded RSA and DSA private keys are accepted by
  * this function.
  *
  **/
int gnutls_certificate_set_x509_key_file(GNUTLS_CERTIFICATE_CREDENTIALS res, char *CERTFILE,
			   char *KEYFILE, GNUTLS_X509_CertificateFmt type)
{
	int ret;

	/* this should be first 
	 */
	if ((ret = read_key_file(res, KEYFILE, type)) < 0)
		return ret;

	if ((ret = read_cert_file(res, CERTFILE, type)) < 0)
		return ret;

	res->ncerts++;

	if ((ret=_gnutls_check_key_cert_match( res)) < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

static int generate_rdn_seq( GNUTLS_CERTIFICATE_CREDENTIALS res) {
gnutls_datum tmp;
int ret, size, i;
opaque *pdata;

	/* Generate the RDN sequence 
	 * This will be sent to clients when a certificate
	 * request message is sent.
	 */

	/* FIXME: in case of a client it is not needed
	 * to do that. This would save time and memory.
	 * However we don't have that information available
	 * here.
	 */

	size = 0;
	for (i = 0; i < res->x509_ncas; i++) {
		if ((ret = _gnutls_find_dn(&tmp, &res->x509_ca_list[i])) < 0) {
			gnutls_assert();
			return ret;
		}
		size += (2 + tmp.size);
	}

	if (res->x509_rdn_sequence.data != NULL)
		gnutls_free( res->x509_rdn_sequence.data);

	res->x509_rdn_sequence.data = gnutls_malloc(size);
	if (res->x509_rdn_sequence.data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	res->x509_rdn_sequence.size = size;

	pdata = res->x509_rdn_sequence.data;

	for (i = 0; i < res->x509_ncas; i++) {
		if ((ret = _gnutls_find_dn(&tmp, &res->x509_ca_list[i])) < 0) {
			gnutls_free(res->x509_rdn_sequence.data);
			res->x509_rdn_sequence.size = 0;
			res->x509_rdn_sequence.data = NULL;
			gnutls_assert();
			return ret;
		}
		WRITEdatum16(pdata, tmp);
		pdata += (2 + tmp.size);
	}

	return 0;
}

/**
  * gnutls_certificate_set_x509_trust_mem - Used to add trusted CAs in a GNUTLS_CERTIFICATE_CREDENTIALS structure
  * @res: is an &GNUTLS_CERTIFICATE_CREDENTIALS structure.
  * @CA: is a list of trusted CAs or a DER certificate
  * @type: is DER or PEM
  *
  * This function adds the trusted CAs in order to verify client
  * certificates. This function may be called multiple times.
  *
  **/
int gnutls_certificate_set_x509_trust_mem(GNUTLS_CERTIFICATE_CREDENTIALS res, 
	const gnutls_datum *CA, GNUTLS_X509_CertificateFmt type)
{
	int ret, ret2;

	if ((ret = read_ca_mem(res, CA->data, CA->size, type)) < 0)
		return ret;

	if ((ret2 = generate_rdn_seq(res)) < 0)
		return ret2;

	return ret;
}

/**
  * gnutls_certificate_set_x509_trust_file - Used to add trusted CAs in a GNUTLS_CERTIFICATE_CREDENTIALS structure
  * @res: is an &GNUTLS_CERTIFICATE_CREDENTIALS structure.
  * @CAFILE: is a file containing the list of trusted CAs (DER or PEM list)
  * @type: is PEM or DER
  *
  * This function sets the trusted CAs in order to verify client
  * certificates. This function may be called multiple times.
  * Returns the number of certificate processed.
  *
  **/
int gnutls_certificate_set_x509_trust_file(GNUTLS_CERTIFICATE_CREDENTIALS res, 
		char *CAFILE, GNUTLS_X509_CertificateFmt type)
{
	int ret, ret2;

	if ((ret = read_ca_file(res, CAFILE, type)) < 0)
		return ret;

	if ((ret2 = generate_rdn_seq(res)) < 0)
		return ret2;

	return ret;
}


/**
  * gnutls_certificate_set_x509_key_mem - Used to set keys in a GNUTLS_CERTIFICATE_CREDENTIALS structure
  * @res: is an &GNUTLS_CERTIFICATE_CREDENTIALS structure.
  * @CERT: contains a certificate list (path) for the specified private key
  * @KEY: is the private key
  * @type: is PEM or DER
  *
  * This function sets a certificate/private key pair in the 
  * GNUTLS_CERTIFICATE_CREDENTIALS structure. This function may be called
  * more than once (in case multiple keys/certificates exist for the
  * server).
  *
  * Currently are supported: RSA PKCS-1 encoded private keys, 
  * DSA private keys.
  *
  * DSA private keys are encoded the OpenSSL way, which is an ASN.1
  * DER sequence of 6 INTEGERs - version, p, q, g, pub, priv.
  *
  **/
int gnutls_certificate_set_x509_key_mem(GNUTLS_CERTIFICATE_CREDENTIALS res, const gnutls_datum* CERT,
			   const gnutls_datum* KEY, GNUTLS_X509_CertificateFmt type)
{
	int ret;

	/* this should be first 
	 */
	if ((ret = read_key_mem( res, KEY->data, KEY->size, type)) < 0)
		return ret;

	if ((ret = read_cert_mem( res, CERT->data, CERT->size, type)) < 0)
		return ret;

	if ((ret=_gnutls_check_key_cert_match( res)) < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}



static int _read_rsa_params(opaque * der, int dersize, MPI * params)
{
	opaque str[MAX_PARAMETER_SIZE];
	int result;
	node_asn *spk;

	if ((result=asn1_create_structure
	    (_gnutls_get_gnutls_asn(), "GNUTLS.RSAPublicKey", &spk,
	     "rsa_public_key")) != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_get_der(spk, der, dersize);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(spk);
		return _gnutls_asn2err(result);
	}


	if ( (result=_gnutls_x509_read_int( spk, "rsa_public_key.modulus", 
		str, sizeof(str)-1, &params[0])) < 0) {
		gnutls_assert();
		asn1_delete_structure(spk);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	if ( (result=_gnutls_x509_read_int( spk, "rsa_public_key.publicExponent", 
		str, sizeof(str)-1, &params[1])) < 0) {
		gnutls_assert();
		_gnutls_mpi_release(&params[0]);
		asn1_delete_structure(spk);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	asn1_delete_structure(spk);

	return 0;

}


/* reads p,q and g 
 * from the certificate 
 * params[0-2]
 */
static int _read_dsa_params(opaque * der, int dersize, MPI * params)
{
	opaque str[MAX_PARAMETER_SIZE];
	int result;
	node_asn *spk;

	if ((result=asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1.Dss-Parms", &spk,
	     "dsa_parms")) != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_get_der(spk, der, dersize);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(spk);
		return _gnutls_asn2err(result);
	}

	/* FIXME: If the parameters are not included in the certificate
	 * then the issuer's parameters should be used.
	 */

	/* Read p */

	if ( (result=_gnutls_x509_read_int( spk, "dsa_parms.p", str, sizeof(str)-1, &params[0])) < 0) {
		gnutls_assert();
		asn1_delete_structure(spk);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	/* Read q */

	if ( (result=_gnutls_x509_read_int( spk, "dsa_parms.q", str, sizeof(str)-1, &params[1])) < 0) {
		gnutls_assert();
		asn1_delete_structure(spk);
		_gnutls_mpi_release(&params[0]);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	/* Read g */
	
	if ( (result=_gnutls_x509_read_int( spk, "dsa_parms.g", str, sizeof(str)-1, &params[2])) < 0) {
		gnutls_assert();
		asn1_delete_structure(spk);
		_gnutls_mpi_release(&params[0]);
		_gnutls_mpi_release(&params[1]);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	asn1_delete_structure(spk);

	return 0;

}

/* reads DSA's Y
 * from the certificate 
 * params[3]
 */
static int _read_dsa_pubkey(opaque * der, int dersize, MPI * params)
{
	opaque str[MAX_PARAMETER_SIZE];
	int result;
	node_asn *spk;

	if ( (result=asn1_create_structure
	    (_gnutls_get_gnutls_asn(), "GNUTLS.DSAPublicKey", &spk,
	     "dsa_public_key")) != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_get_der(spk, der, dersize);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(spk);
		return _gnutls_asn2err(result);
	}

	/* Read p */

	if ( (result=_gnutls_x509_read_int( spk, "dsa_public_key", str, sizeof(str)-1, &params[3])) < 0) {
		gnutls_assert();
		asn1_delete_structure(spk);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	asn1_delete_structure(spk);

	return 0;

}

#define PKIX1_RSA_OID "1 2 840 113549 1 1 1"
#define DSA_OID "1 2 840 10040 4 1"

/* Extracts DSA and RSA parameters from a certificate.
 */
static 
int _gnutls_extract_x509_cert_mpi_params( const char* ALGO_OID, gnutls_cert * gCert,
	node_asn* c2, char* tmpstr, int tmpstr_size) {
int len, result;

	len = tmpstr_size - 1;
	result =
	    asn1_read_value
	    (c2, "certificate2.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey",
	     tmpstr, &len);

	if (result != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}
	
	if (strcmp( ALGO_OID, PKIX1_RSA_OID) == 0) {	/* pkix-1 1 - RSA */
		/* params[0] is the modulus,
		 * params[1] is the exponent
		 */
		gCert->subject_pk_algorithm = GNUTLS_PK_RSA;

		if ((sizeof(gCert->params) / sizeof(MPI)) < RSA_PUBLIC_PARAMS) {
			gnutls_assert();
			/* internal error. Increase the MPIs in params */
			return GNUTLS_E_INTERNAL_ERROR;
		}

		if ((result =
		     _read_rsa_params(tmpstr, len / 8, gCert->params)) < 0) {
			gnutls_assert();
			return result;
		}
		gCert->params_size = RSA_PUBLIC_PARAMS;
		
		return 0;
	}

	if (strcmp( ALGO_OID, DSA_OID) == 0) {
		/* params[0] is p,
		 * params[1] is q,
		 * params[2] is q,
		 * params[3] is pub.
		 */
		gCert->subject_pk_algorithm = GNUTLS_PK_DSA;

		if ((sizeof(gCert->params) / sizeof(MPI)) < DSA_PUBLIC_PARAMS) {
			gnutls_assert();
			/* internal error. Increase the MPIs in params */
			return GNUTLS_E_INTERNAL_ERROR;
		}

		if ((result =
		     _read_dsa_pubkey(tmpstr, len / 8, gCert->params)) < 0) {
			gnutls_assert();
			return result;
		}

		/* Now read the parameters
		 */
		len = tmpstr_size - 1;
		result =
		    asn1_read_value
		    (c2, "certificate2.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters",
		     tmpstr, &len);

		if (result != ASN_OK) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}

		if ((result =
		     _read_dsa_params(tmpstr, len, gCert->params)) < 0) {
			gnutls_assert();
			return result;
		}
		gCert->params_size = DSA_PUBLIC_PARAMS;
		
		return 0;
	}


	/* other types like DH
	 * currently not supported
	 */
	gnutls_assert();

	_gnutls_log("CERT: ALGORITHM: %s\n", ALGO_OID);

	gCert->subject_pk_algorithm = GNUTLS_PK_UNKNOWN;

	return GNUTLS_E_INVALID_PARAMETERS;
}



#define X509_SIG_SIZE 1024

/* This function will convert a der certificate, to a format
 * (structure) that gnutls can understand and use. Actually the
 * important thing on this function is that it extracts the 
 * certificate's (public key) parameters.
 */
int _gnutls_x509_cert2gnutls_cert(gnutls_cert * gCert, gnutls_datum derCert)
{
	int result;
	node_asn *c2;
	opaque str[MAX_X509_CERT_SIZE];
	char oid[128];
	int len = sizeof(str);

	memset(gCert, 0, sizeof(gnutls_cert));

	gCert->valid = 1;
	gCert->cert_type = GNUTLS_CRT_X509;

	if (gnutls_set_datum(&gCert->raw, derCert.data, derCert.size) < 0) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	if ((result=asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1.Certificate", &c2,
	     "certificate2"))
	    != ASN_OK) {
		gnutls_assert();
		gnutls_free_datum( &gCert->raw);
		return _gnutls_asn2err(result);
	}

	result = asn1_get_der(c2, derCert.data, derCert.size);
	if (result != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("CERT: Decoding error %d\n", result);

		gnutls_assert();
		asn1_delete_structure(c2);
		gnutls_free_datum( &gCert->raw);
		return _gnutls_asn2err(result);
	}

	len = sizeof(oid) - 1;
	result =
	    asn1_read_value
	    (c2,
	     "certificate2.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm",
	     oid, &len);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(c2);
		gnutls_free_datum( &gCert->raw);
		return _gnutls_asn2err(result);
	}

	if ( (result=_gnutls_extract_x509_cert_mpi_params( oid, gCert, c2, str, sizeof(str))) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		gnutls_free_datum( &gCert->raw);
		return result;
	}

	len = gCert->signature.size = X509_SIG_SIZE;
	gCert->signature.data = gnutls_malloc( gCert->signature.size);
	if (gCert->signature.data==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	result =
	    asn1_read_value
	    (c2, "certificate2.signature", gCert->signature.data, &len);

	if ((len % 8) != 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		gnutls_free_datum( &gCert->raw);
		gnutls_free_datum( &gCert->signature);
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}

	len /= 8;		/* convert to bytes */
	gCert->signature.size = len; /* put the actual sig size */


	gCert->expiration_time =
	    _gnutls_x509_get_time(c2, "certificate2", "notAfter");
	gCert->activation_time =
	    _gnutls_x509_get_time(c2, "certificate2", "notBefore");

#if 0 
	if (gCert->expiration_time == (time_t)(-1) ||
		gCert->activation_time == (time_t)(-1)) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return GNUTLS_E_UNIX_TIME_LIMIT_EXCEEDED;
	}
#endif

	gCert->version = _gnutls_x509_get_version(c2, "certificate2");
	if (gCert->version < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		gnutls_free_datum( &gCert->raw);
		return GNUTLS_E_ASN1_GENERIC_ERROR;  
	}	 

	if ((result =
	     _gnutls_get_ext_type(c2,
				  "certificate2.tbsCertificate.extensions",
				  gCert)) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		gnutls_free_datum( &gCert->raw);
		return result;
	}

	asn1_delete_structure(c2);


	gCert->valid = 0;	/* if we got until here
				 * the certificate is valid.
				 */

	return 0;

}

/* Returns 0 if it's ok to use the KXAlgorithm with this cert
 * (using KeyUsage field). 
 */
int _gnutls_check_x509_key_usage(const gnutls_cert * cert,
				    KXAlgorithm alg)
{
	if (_gnutls_map_kx_get_cred(alg) == GNUTLS_CRD_CERTIFICATE) {
		switch (alg) {
		case GNUTLS_KX_RSA:
			if (cert->keyUsage != 0) {
				if (!
				    (cert->
				     keyUsage & GNUTLS_X509KEY_KEY_ENCIPHERMENT))
					return
					    GNUTLS_E_X509_KEY_USAGE_VIOLATION;
				else
					return 0;
			}
			return 0;
		case GNUTLS_KX_DHE_RSA:
		case GNUTLS_KX_DHE_DSS:
			if (cert->keyUsage != 0) {
				if (!
				    (cert->
				     keyUsage & GNUTLS_X509KEY_DIGITAL_SIGNATURE))
					return
					    GNUTLS_E_X509_KEY_USAGE_VIOLATION;
				else
					return 0;
			}
			return 0;
		default:
			gnutls_assert();
			return GNUTLS_E_X509_KEY_USAGE_VIOLATION;
		}
	}
	return 0;
}

#ifdef DEBUG

/* Verifies a base64 encoded certificate list from memory 
 */
int _gnutls_verify_x509_mem( const char *ca, int ca_size)
{
	int siz, siz2, i;
	opaque *b64;
	const char *ptr;
	int ret;
	gnutls_datum tmp;
	gnutls_cert* x509_ca_list=NULL;
	int x509_ncas;

	siz = ca_size;

	ptr = ca;

	i = 1;

	do {
		siz2 = _gnutls_fbase64_decode(ptr, siz, &b64);
		siz -= siz2;	/* FIXME: this is not enough
				 */

		if (siz2 < 0) {
			gnutls_assert();
			return GNUTLS_E_PARSING_ERROR;
		}

		x509_ca_list =
		    (gnutls_cert *) gnutls_realloc( x509_ca_list,
						   i *
						   sizeof(gnutls_cert));
		if (x509_ca_list == NULL) {
			gnutls_assert();
			gnutls_free(b64);
			return GNUTLS_E_MEMORY_ERROR;
		}

		tmp.data = b64;
		tmp.size = siz2;

		if ((ret =
		     _gnutls_x509_cert2gnutls_cert(&x509_ca_list[i - 1],
					     tmp)) < 0) {
			gnutls_assert();
			gnutls_free(b64);
			return ret;
		}
		gnutls_free(b64);

		/* now we move ptr after the pem header */
		ptr = strstr(ptr, CERT_SEP);
		if (ptr!=NULL)
			ptr++;

		i++;
	} while ((ptr = strstr(ptr, CERT_SEP)) != NULL);

	x509_ncas = i - 1;

	siz = _gnutls_x509_verify_certificate( x509_ca_list, x509_ncas-1,
		&x509_ca_list[x509_ncas-1], 1, NULL, 0);

	return siz;
}



/* Reads and verifies a base64 encoded certificate file 
 */
int _gnutls_verify_x509_file( char *cafile)
{
	int siz;
	char x[MAX_FILE_SIZE];
	FILE *fd1;

	fd1 = fopen(cafile, "rb");
	if (fd1 == NULL) {
		gnutls_assert();
		return GNUTLS_E_FILE_ERROR;
	}

	siz = fread(x, 1, sizeof(x)-1, fd1);
	fclose(fd1);

	x[siz] = 0;

	return _gnutls_verify_x509_mem( x, siz);
}



#endif

/**
  * gnutls_x509_pkcs7_extract_certificate - This function returns a certificate in a PKCS7 certificate set
  * @pkcs7_struct: should contain a PKCS7 DER formatted structure
  * @indx: contains the index of the certificate to extract
  * @certificate: the contents of the certificate will be copied there
  * @certificate_size: should hold the size of the certificate
  *
  * This function will return a certificate of the PKCS7 or RFC2630 certificate set.
  * Returns 0 on success. If the provided buffer is not long enough,
  * then GNUTLS_E_INVALID_REQUEST is returned.
  *
  **/
int gnutls_x509_pkcs7_extract_certificate(const gnutls_datum * pkcs7_struct, int indx, char* certificate, int* certificate_size)
{
	node_asn *c2, *c1;
	int result, len;
	char root1[128];
	char oid[128];
	char root2[128];
	char counter[MAX_INT_DIGITS];
	opaque* pkcs7_str = pkcs7_struct->data;
	int pkcs7_str_size = pkcs7_struct->size;

	opaque* pcert;
	int pcert_size;

	/* Step 1. Parse content and content info */
	
	if (pkcs7_str_size == 0 || pkcs7_str == NULL) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}
	
	_gnutls_str_cpy( root1, sizeof(root1), "PKIX1.ContentInfo");
	if ((result=asn1_create_structure
	    (_gnutls_get_pkix(), root1, &c1, "c1")) != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_get_der(c1, pkcs7_str, pkcs7_str_size);
	if (result != ASN_OK) {
		/* couldn't decode DER */

		gnutls_assert();
		asn1_delete_structure(c1);
		return _gnutls_asn2err(result);
	}

	len = sizeof(oid) - 1;

	/* root2 is used as a temp storage area
	 */
	_gnutls_str_cpy( root2, sizeof(root2), "c1.contentType");
	result = asn1_read_value(c1, root2, oid, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(c1);
		return _gnutls_asn2err(result);
	}

	if ( strcmp( oid, "1 2 840 113549 1 7 2") != 0) {
		gnutls_assert();
		asn1_delete_structure(c1);
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}					 		 	

	pcert_size = *certificate_size - 1;
	pcert = certificate;

	_gnutls_str_cpy( root2, sizeof(root2), "c1.content");
	result = asn1_read_value(c1, root2, pcert, &pcert_size);

	asn1_delete_structure(c1);

	if (result != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	/* pcert, pcert_size hold the data and the size of the CertificateSet structure
	 * actually the ANY stuff.
	 */


	/* Step 1.5. In case of a signed structure extract certificate set.
	 */
	_gnutls_str_cpy( root2, sizeof(root2), "PKIX1.SignedData");
	if ((result=asn1_create_structure
	    (_gnutls_get_pkix(), root2, &c2, "c2")) != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_get_der(c2, pcert, pcert_size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
	
		gnutls_assert();
		asn1_delete_structure(c2);
		return _gnutls_asn2err(result);
	}
		
		
	/* Step 2. Parse CertificateSet */
	

	_gnutls_str_cpy( root2, sizeof(root2), "c2.certificates.?"); 
	_gnutls_int2str( indx+1, counter);
	_gnutls_str_cat( root2, sizeof(root2), counter); 

	len = sizeof(oid) - 1;

	result = asn1_read_value(c2, root2, oid, &len);

	if (result == ASN_VALUE_NOT_FOUND) {
		asn1_delete_structure(c2);
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}
	
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return _gnutls_asn2err(result);
	}

	/* if 'Certificate' is the choice found: */
	if (strcmp( oid, "certificate") == 0) {
		int start, end;

/*		_gnutls_str_cat( root2, sizeof(root2), ".certificate"); */

		result = asn1_get_start_end_der(c2, pcert, pcert_size, 
			root2, &start, &end);

		if (result != ASN_OK) {
			gnutls_assert();
			asn1_delete_structure(c2);
			return _gnutls_asn2err(result);
		}
			
		end = end-start+1;
		
		if (certificate!=NULL && end <= *certificate_size)
			memcpy( certificate, &pcert[start], end);
		else {
			*certificate_size = end;
			return GNUTLS_E_INVALID_REQUEST;
		}

		*certificate_size = end;

	} else {
		asn1_delete_structure(c2);
		return GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
	}

	asn1_delete_structure(c2);

	return 0;
}


/**
  * gnutls_x509_extract_certificate_pk_algorithm - This function returns the certificate's PublicKey algorithm
  * @cert: is a DER encoded X.509 certificate
  * @bits: if bits is non null it will hold the size of the parameters' in bits
  *
  * This function will return the public key algorithm of an X.509 
  * certificate.
  *
  * If bits is non null, it should have enough size to hold the parameters
  * size in bits. For RSA the bits returned is the modulus. 
  * For DSA the bits returned are of the public
  * exponent.
  *
  * Returns a member of the GNUTLS_PKAlgorithm enumeration on success,
  * or a negative value on error.
  *
  **/
int gnutls_x509_extract_certificate_pk_algorithm( const gnutls_datum * cert, int* bits)
{
	int result;
	node_asn *c2;
	opaque str[MAX_X509_CERT_SIZE];
	int algo;
	int len = sizeof(str);
	MPI params[MAX_PARAMS_SIZE];

	if ((result=asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1.Certificate", &c2,
	     "certificate2"))
	    != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_get_der(c2, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("CERT: Decoding error %d\n", result);

		gnutls_assert();
		asn1_delete_structure(c2);
		return _gnutls_asn2err(result);
	}

	len = sizeof(str) - 1;
	result =
	    asn1_read_value
	    (c2,
	     "certificate2.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm",
	     str, &len);


	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return _gnutls_asn2err(result);
	}

	algo = GNUTLS_E_UNKNOWN_PK_ALGORITHM;

	if ( strcmp( str, PKIX1_RSA_OID)==0)
		algo = GNUTLS_PK_RSA;

	if ( strcmp( str, DSA_OID)==0)
		algo = GNUTLS_PK_DSA;

	if ( bits==NULL) {
		asn1_delete_structure(c2);
		return algo;
	}

	/* Now read the parameters' bits */

	len = sizeof(str) - 1;
	result =
	    asn1_read_value
	    (c2, "certificate2.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey",
	     str, &len);

	if (result != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}


	if (algo==GNUTLS_PK_RSA) {
		if ((result=_read_rsa_params( str, len/8, params)) < 0) {
			gnutls_assert();
			asn1_delete_structure(c2);
			return result;
		}

		bits[0] = gcry_mpi_get_nbits( params[0]);
	
		_gnutls_mpi_release( &params[0]);
		_gnutls_mpi_release( &params[1]);
	}

	if (algo==GNUTLS_PK_DSA) {

		if ((result =
		     _read_dsa_pubkey(str, len / 8, params)) < 0) {
			gnutls_assert();
			asn1_delete_structure(c2);
			return result;
		}

		bits[0] = gcry_mpi_get_nbits( params[3]);

		_gnutls_mpi_release( &params[3]);
	}

	asn1_delete_structure(c2);
	return algo;
}

/**
  * gnutls_x509_pkcs7_extract_certificate_count - This function returns the number of certificates in a PKCS7 certificate set
  * @pkcs7_struct: should contain a PKCS7 DER formatted structure
  *
  * This function will return the certificate number of the PKCS7 or RFC2630 certificate set.
  * Returns a negative value on failure.
  *
  **/
int gnutls_x509_pkcs7_extract_certificate_count(const gnutls_datum * pkcs7_struct)
{
	node_asn *c2, *c1;
	int result, len, count;
	char root1[128];
	char oid[64];
	char tmp[MAX_X509_CERT_SIZE];
	char root2[128];
	opaque* pkcs7_str = pkcs7_struct->data;
	int pkcs7_str_size = pkcs7_struct->size;

	opaque* pcert;
	int pcert_size;

	/* Step 1. Parse content and content info */
	
	if (pkcs7_str_size == 0 || pkcs7_str == NULL) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	_gnutls_str_cpy( root1, sizeof(root1), "PKIX1.ContentInfo");
	if ((result=asn1_create_structure
	    (_gnutls_get_pkix(), root1, &c1, "c1")) != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_get_der(c1, pkcs7_str, pkcs7_str_size);
	if (result != ASN_OK) {
		/* couldn't decode DER */

		gnutls_assert();
		asn1_delete_structure(c1);
		return _gnutls_asn2err(result);
	}

	len = sizeof(oid) - 1;

	/* root2 is used as a temp storage area
	 */
	_gnutls_str_cpy( root2, sizeof(root2), "c1.contentType");
	result = asn1_read_value(c1, root2, oid, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(c1);
		return _gnutls_asn2err(result);
	}

	if ( strcmp( oid, "1 2 840 113549 1 7 2") != 0) {
		gnutls_assert();
		asn1_delete_structure(c1);
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}					 		 	

	pcert_size = sizeof(tmp) - 1;
	pcert = tmp;

	_gnutls_str_cpy( root2, sizeof(root2), "c1.content");
	result = asn1_read_value(c1, root2, pcert, &pcert_size);

	asn1_delete_structure(c1);

	if (result != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	/* pcert, pcert_size hold the data and the size of the CertificateSet structure
	 * actually the ANY stuff.
	 */


	/* Step 1.5. In case of a signed structure count the certificate set.
	 */
	_gnutls_str_cpy( root2, sizeof(root2), "PKIX1.SignedData");
	if ((result=asn1_create_structure
	    (_gnutls_get_pkix(), root2, &c2, "c2")) != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_get_der(c2, pcert, pcert_size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
	
		gnutls_assert();
		asn1_delete_structure(c2);
		return _gnutls_asn2err(result);
	}
		
	/* Step 2. Count the CertificateSet */
	

	_gnutls_str_cpy( root2, sizeof(root2), "c2.certificates"); 
	result = asn1_number_of_elements( c2, root2, &count);

	asn1_delete_structure(c2);
	
	if (result != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	return count;
}
