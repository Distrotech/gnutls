/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
 * Author: Simon Josefsson
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
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

/* Online Certificate Status Protocol - RFC 2560
 */

#include <gnutls_int.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <libtasn1.h>
#include <gnutls_pk.h>
#include "algorithms.h"
#include "output.h"

#include <gnutls/ocsp.h>

/* I18n of error codes. */
#include "gettext.h"
#define _(String) dgettext (PACKAGE, String)

#define addf _gnutls_buffer_append_printf
#define adds _gnutls_buffer_append_str

static void
print_req (gnutls_buffer_st * str, gnutls_ocsp_req_t req)
{
  int ret;
  unsigned indx;

  /* Version. */
  {
    int version = gnutls_ocsp_req_get_version (req);
    if (version < 0)
      addf (str, "error: get_version: %s\n", gnutls_strerror (version));
    else
      addf (str, _("\tVersion: %d\n"), version);
  }

  /* XXX requestorName */

  /* requestList */
  addf (str, "\tRequest List:\n");
  for (indx = 0; ; indx++)
    {
      gnutls_digest_algorithm_t digest;
      gnutls_datum_t in, ik, sn;

      ret = gnutls_ocsp_req_get_certid (req, indx, &digest, &in, &ik, &sn);
      if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
	break;
      addf (str, "\t\tCertificate ID:\n");
      if (ret != GNUTLS_E_SUCCESS)
	{
	  addf (str, "error: get_certid: %s\n",
		gnutls_strerror (ret));
	  continue;
	}
      addf (str, "\t\t\tHash Algorithm: %s\n",
	    _gnutls_digest_get_name (digest));

      adds (str, "\t\t\tIssuer Name Hash: ");
      hexprint (str, in.data, in.size);
      adds (str, "\n");

      adds (str, "\t\t\tIssuer Key Hash: ");
      hexprint (str, ik.data, ik.size);
      adds (str, "\n");

      adds (str, "\t\t\tSerial Number: ");
      hexprint (str, sn.data, sn.size);
      adds (str, "\n");

      gnutls_free (in.data);
      gnutls_free (ik.data);
      gnutls_free (sn.data);

      /* XXX singleRequestExtensions */
    }

  for (indx = 0; ; indx++)
    {
      gnutls_datum_t oid;
      unsigned int critical;
      gnutls_datum_t data;

      ret = gnutls_ocsp_req_get_extension (req, indx, &oid, &critical, &data);
      if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
	break;
      else if (ret != GNUTLS_E_SUCCESS)
	{
	  addf (str, "error: get_extension: %s\n",
		gnutls_strerror (ret));
	  continue;
	}
      if (indx == 0)
	adds (str, "\tExtensions:\n");

      if (memcmp (oid.data, GNUTLS_OCSP_NONCE, oid.size) == 0)
	{
	  gnutls_datum_t nonce;
	  unsigned int critical;

	  ret = gnutls_ocsp_req_get_nonce (req, &critical, &nonce);
	  if (ret != GNUTLS_E_SUCCESS)
	    {
	      addf (str, "error: get_nonce: %s\n",
		    gnutls_strerror (ret));
	    }
	  else
	    {
	      addf (str, "\t\tNonce%s: ", critical ? " (critical)" : "");
	      hexprint (str, nonce.data, nonce.size);
	      adds (str, "\n");
	    }
	}
      else
	{
	  addf (str, "\t\tUnknown extension %s (%s):\n", oid.data,
		critical ? "critical" : "not critical");

	  addf (str, _("\t\t\tASCII: "));
	  asciiprint (str, data.data, data.size);
	  addf (str, "\n");

	  addf (str, _("\t\t\tHexdump: "));
	  hexprint (str, data.data, data.size);
	  adds (str, "\n");
	}

      gnutls_free (oid.data);
      gnutls_free (data.data);
    }

  /* XXX Signature */
}

/**
 * gnutls_ocsp_req_print:
 * @req: The structure to be printed
 * @format: Indicate the format to use
 * @out: Newly allocated datum with (0) terminated string.
 *
 * This function will pretty print a OCSP request, suitable for
 * display to a human.
 *
 * If the format is %GNUTLS_REQ_PRINT_FULL then all fields of the
 * request will be output, on multiple lines.
 *
 * The output @out->data needs to be deallocate using gnutls_free().
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_ocsp_req_print (gnutls_ocsp_req_t req,
                       gnutls_ocsp_print_formats_t format,
                       gnutls_datum_t * out)
{
  gnutls_buffer_st str;

  if (format != GNUTLS_OCSP_PRINT_FULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  _gnutls_buffer_init (&str);

  _gnutls_buffer_append_str (&str, _("OCSP Request Information:\n"));

  print_req (&str, req);

  _gnutls_buffer_append_data (&str, "\0", 1);
  out->data = str.data;
  out->size = strlen (str.data);

  return GNUTLS_E_SUCCESS;
}

static void
print_resp (gnutls_buffer_st * str, gnutls_ocsp_resp_t resp)
{
  int ret;
  unsigned indx;

  ret = gnutls_ocsp_resp_get_status (resp);
  if (ret < 0)
    {
      addf (str, "error: ocsp_resp_get_status: %s\n",
	    gnutls_strerror (ret));
      return;
    }

  adds (str, "\tResponse Status: ");
  switch (ret)
    {
    case GNUTLS_OCSP_RESP_SUCCESSFUL:
      adds (str, "Successful\n");
      break;

    case GNUTLS_OCSP_RESP_MALFORMEDREQUEST:
      adds (str, "malformedRequest\n");
      return;

    case GNUTLS_OCSP_RESP_INTERNALERROR:
      adds (str, "internalError\n");
      return;

    case GNUTLS_OCSP_RESP_TRYLATER:
      adds (str, "tryLater\n");
      return;

    case GNUTLS_OCSP_RESP_SIGREQUIRED:
      adds (str, "sigRequired\n");
      return;

    case GNUTLS_OCSP_RESP_UNAUTHORIZED:
      adds (str, "unauthorized\n");
      return;

    default:
      adds (str, "unknown\n");
      return;
    }

  {
    gnutls_datum_t oid;

    ret = gnutls_ocsp_resp_get_response (resp, &oid, NULL);
    if (ret < 0)
      {
	addf (str, "error: get_response: %s\n", gnutls_strerror (ret));
	return;
      }

    adds (str, "\tResponse Type: ");
#define OCSP_BASIC "1.3.6.1.5.5.7.48.1.1"

    if (oid.size == sizeof (OCSP_BASIC)
	&& memcmp (oid.data, OCSP_BASIC, oid.size) == 0)
      {
	adds (str, "Basic OCSP Response\n");
	gnutls_free (oid.data);
      }
    else
      {
	addf (str, "Unknown response type (%.*s)\n", oid.size, oid.data);
	gnutls_free (oid.data);
	return;
      }
  }

  /* Version. */
  {
    int version = gnutls_ocsp_resp_get_version (resp);
    if (version < 0)
      addf (str, "error: get_version: %s\n", gnutls_strerror (version));
    else
      addf (str, _("\tVersion: %d\n"), version);
  }

  /* responderID */
  {
    gnutls_datum_t dn;

    /* XXX byKey */

    ret = gnutls_ocsp_resp_get_responderid_dn (resp, &dn);
    if (ret < 0)
      addf (str, "error: get_dn: %s\n", gnutls_strerror (ret));
    else
      {
	addf (str, _("\tResponder ID: %.*s\n"), dn.size, dn.data);
	gnutls_free (dn.data);
      }
  }

  {
    char s[42];
    size_t max = sizeof (s);
    struct tm t;
    time_t tim = gnutls_ocsp_resp_get_produceat (resp);

    if (tim == (time_t) -1)
      addf (str, "error: ocsp_resp_get_produceat\n");
    else if (gmtime_r (&tim, &t) == NULL)
      addf (str, "error: gmtime_r (%ld)\n", (unsigned long) tim);
    else if (strftime (s, max, "%a %b %d %H:%M:%S UTC %Y", &t) == 0)
      addf (str, "error: strftime (%ld)\n", (unsigned long) tim);
    else
      addf (str, _("\tProduced At: %s\n"), s);
  }

  addf (str, "\tResponses:\n");
  for (indx = 0; ; indx++)
    {
      gnutls_digest_algorithm_t digest;
      gnutls_datum_t in, ik, sn;
      int cert_status;
      time_t this_update;
      time_t next_update;
      time_t revocation_time;
      int revocation_reason;

      ret = gnutls_ocsp_resp_get_singleresponse (resp,
						 indx,
						 &digest, &in, &ik, &sn,
						 &cert_status,
						 &this_update,
						 &next_update,
						 &revocation_time,
						 &revocation_reason);
      if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
	break;
      addf (str, "\t\tCertificate ID:\n");
      if (ret != GNUTLS_E_SUCCESS)
	{
	  addf (str, "error: get_singleresponse: %s\n",
		gnutls_strerror (ret));
	  continue;
	}
      addf (str, "\t\t\tHash Algorithm: %s\n",
	    _gnutls_digest_get_name (digest));

      adds (str, "\t\t\tIssuer Name Hash: ");
      hexprint (str, in.data, in.size);
      adds (str, "\n");

      adds (str, "\t\t\tIssuer Key Hash: ");
      hexprint (str, ik.data, ik.size);
      adds (str, "\n");

      adds (str, "\t\t\tSerial Number: ");
      hexprint (str, sn.data, sn.size);
      adds (str, "\n");

      gnutls_free (in.data);
      gnutls_free (ik.data);
      gnutls_free (sn.data);

      {
	const char *p = NULL;

	switch (cert_status)
	  {
	  case GNUTLS_OCSP_CERT_GOOD:
	    p = "good";
	    break;

	  case GNUTLS_OCSP_CERT_REVOKED:
	    p = "revoked";
	    break;

	  case GNUTLS_OCSP_CERT_UNKNOWN:
	    p = "unknown";
	    break;

	  default:
	    addf (str, "\t\tCertificate Status: unexpected value %d\n",
		  cert_status);
	    break;
	  }

	if (p)
	  addf (str, "\t\tCertificate Status: %s\n", p);
      }

      /* XXX revocation reason */

      if (cert_status == GNUTLS_OCSP_CERT_REVOKED)
	{
	  char s[42];
	  size_t max = sizeof (s);
	  struct tm t;

	  if (revocation_time == (time_t) -1)
	    addf (str, "error: revocation_time\n");
	  else if (gmtime_r (&revocation_time, &t) == NULL)
	    addf (str, "error: gmtime_r (%ld)\n",
		  (unsigned long) revocation_time);
	  else if (strftime (s, max, "%a %b %d %H:%M:%S UTC %Y", &t) == 0)
	    addf (str, "error: strftime (%ld)\n",
		  (unsigned long) revocation_time);
	  else
	    addf (str, _("\t\tRevocation time: %s\n"), s);
      }

      {
	char s[42];
	size_t max = sizeof (s);
	struct tm t;

	if (this_update == (time_t) -1)
	  addf (str, "error: this_update\n");
	else if (gmtime_r (&this_update, &t) == NULL)
	  addf (str, "error: gmtime_r (%ld)\n", (unsigned long) this_update);
	else if (strftime (s, max, "%a %b %d %H:%M:%S UTC %Y", &t) == 0)
	  addf (str, "error: strftime (%ld)\n", (unsigned long) this_update);
	else
	  addf (str, _("\t\tThis Update: %s\n"), s);
      }

      {
	char s[42];
	size_t max = sizeof (s);
	struct tm t;

	if (next_update == (time_t) -1)
	  addf (str, "error: next_update\n");
	else if (gmtime_r (&next_update, &t) == NULL)
	  addf (str, "error: gmtime_r (%ld)\n", (unsigned long) next_update);
	else if (strftime (s, max, "%a %b %d %H:%M:%S UTC %Y", &t) == 0)
	  addf (str, "error: strftime (%ld)\n", (unsigned long) next_update);
	else
	  addf (str, _("\t\tNext Update: %s\n"), s);
      }

      /* XXX singleRequestExtensions */
    }

  adds (str, "\tExtensions:\n");
  for (indx = 0; ; indx++)
    {
      gnutls_datum_t oid;
      unsigned int critical;
      gnutls_datum_t data;

      ret = gnutls_ocsp_resp_get_extension (resp, indx, &oid, &critical, &data);
      if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
	break;
      else if (ret != GNUTLS_E_SUCCESS)
	{
	  addf (str, "error: get_extension: %s\n",
		gnutls_strerror (ret));
	  continue;
	}

      if (memcmp (oid.data, GNUTLS_OCSP_NONCE, oid.size) == 0)
	{
	  gnutls_datum_t nonce;
	  unsigned int critical;

	  ret = gnutls_ocsp_resp_get_nonce (resp, &critical, &nonce);
	  if (ret != GNUTLS_E_SUCCESS)
	    {
	      addf (str, "error: get_nonce: %s\n",
		    gnutls_strerror (ret));
	    }
	  else
	    {
	      addf (str, "\t\tNonce%s: ", critical ? " (critical)" : "");
	      hexprint (str, nonce.data, nonce.size);
	      adds (str, "\n");
	    }
	}
      else
	{
	  addf (str, "\t\tUnknown extension %s (%s):\n", oid.data,
		critical ? "critical" : "not critical");

	  addf (str, _("\t\t\tASCII: "));
	  asciiprint (str, data.data, data.size);
	  addf (str, "\n");

	  addf (str, _("\t\t\tHexdump: "));
	  hexprint (str, data.data, data.size);
	  adds (str, "\n");
	}

      gnutls_free (oid.data);
      gnutls_free (data.data);
    }

  /* Signature. */
  {
    gnutls_datum_t sig;

    ret = gnutls_ocsp_resp_get_signature_algorithm (resp);
    if (ret < 0)
      addf (str, "retor: get_signature_algorithm: %s\n",
	    gnutls_strerror (ret));
    else
      {
	const char *name = gnutls_sign_algorithm_get_name (ret);
	if (name == NULL)
	  name = _("unknown");
	addf (str, _("\tSignature Algorithm: %s\n"), name);
      }
    if (ret == GNUTLS_SIGN_RSA_MD5 || ret == GNUTLS_SIGN_RSA_MD2)
      {
	adds (str, _("warning: signed using a broken signature "
		     "algorithm that can be forged.\n"));
      }

    ret = gnutls_ocsp_resp_get_signature (resp, &sig);
    if (ret < 0)
      addf (str, "error: get_signature: %s\n", gnutls_strerror (ret));
    else
      {
	adds (str, _("\tSignature:\n"));
	hexdump (str, sig.data, sig.size, "\t\t");

	gnutls_free (sig.data);
      }
  }

  /* certs */
  {
    gnutls_x509_crt_t *certs;
    size_t ncerts, i;
    gnutls_datum_t out;

    ret = gnutls_ocsp_resp_get_certs (resp, &certs, &ncerts);
    if (ret < 0)
      addf (str, "error: get_certs: %s\n", gnutls_strerror (ret));
    else
      {
	for (i = 0; i < ncerts; i++)
	  {
	    size_t s = 0;

	    ret = gnutls_x509_crt_print (certs[i], GNUTLS_CRT_PRINT_FULL,
					 &out);
	    if (ret < 0)
	      addf (str, "error: crt_print: %s\n", gnutls_strerror (ret));
	    else
	      {
		addf (str, "%.*s", out.size, out.data);
		gnutls_free (out.data);
	      }

	    ret = gnutls_x509_crt_export (certs[i], GNUTLS_X509_FMT_PEM,
					  NULL, &s);
	    if (ret != GNUTLS_E_SHORT_MEMORY_BUFFER)
	      addf (str, "error: crt_export: %s\n", gnutls_strerror (ret));
	    else
	      {
		out.data = gnutls_malloc (s);
		if (out.data == NULL)
		  addf (str, "error: malloc: %s\n",
			gnutls_strerror (GNUTLS_E_MEMORY_ERROR));
		else
		  {
		    ret = gnutls_x509_crt_export (certs[i], GNUTLS_X509_FMT_PEM,
						  out.data, &s);
		    out.size = s;
		    addf (str, "%.*s", out.size, out.data);
		    gnutls_free (out.data);
		  }
	      }

	    gnutls_x509_crt_deinit (certs[i]);
	  }
	gnutls_free (certs);
      }
  }
}

/**
 * gnutls_ocsp_resp_print:
 * @resp: The structure to be printed
 * @format: Indicate the format to use
 * @out: Newly allocated datum with (0) terminated string.
 *
 * This function will pretty print a OCSP response, suitable for
 * display to a human.
 *
 * If the format is %GNUTLS_RESP_PRINT_FULL then all fields of the
 * response will be output, on multiple lines.
 *
 * The output @out->data needs to be deallocate using gnutls_free().
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_ocsp_resp_print (gnutls_ocsp_resp_t resp,
			gnutls_ocsp_print_formats_t format,
			gnutls_datum_t * out)
{
  gnutls_buffer_st str;

  if (format != GNUTLS_OCSP_PRINT_FULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  _gnutls_buffer_init (&str);

  _gnutls_buffer_append_str (&str, _("OCSP Response Information:\n"));

  print_resp (&str, resp);

  _gnutls_buffer_append_data (&str, "\0", 1);
  out->data = str.data;
  out->size = strlen (str.data);

  return GNUTLS_E_SUCCESS;
}
