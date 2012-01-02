/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/ocsp.h>

#include "read-file.h"

/* This program will read a file (argv[1]) containing a certificate in
   PEM format and print the "CA issuers" and "OCSP address" extensions
   for the certificate.  If another file is given (argv[2]) it holds
   the issuer certificate for the first certificate, and another file
   (argv[3]) should contain a set of trust anchors in PEM format.
   Then the tool will generate an OCSP request and will read an OCSP
   response from standard input and verify it against the trust
   anchors. */

int
main (int argc, char *argv[])
{
  int rc;
  gnutls_x509_crt_t cert = NULL, issuer = NULL;
  gnutls_datum_t certdata, issuerdata, tmp;
  size_t s;
  unsigned int seq;

  rc = gnutls_global_init ();
  if (rc < 0)
    goto done;

  /* Read certificate and print AIA info. */

  rc = gnutls_x509_crt_init (&cert);
  if (rc < 0)
    goto done;

  certdata.data = read_binary_file (argv[1], &s);
  if (certdata.data == NULL)
    {
      printf ("cannot read certificate\n");
      goto done;
    }
  certdata.size = s;

  rc = gnutls_x509_crt_import (cert, &certdata, GNUTLS_X509_FMT_PEM);
  free (certdata.data);
  if (rc < 0)
    goto done;

  rc = gnutls_x509_crt_print (cert, GNUTLS_CRT_PRINT_ONELINE, &tmp);
  if (rc < 0)
    goto done;

  printf ("cert: %.*s\n", tmp.size, tmp.data);

  gnutls_free (tmp.data); tmp.data = NULL;

  for (seq = 0; ; seq++)
    {
      rc = gnutls_x509_crt_get_authority_info_access (cert, seq,
						      GNUTLS_IA_CAISSUERS_URI,
						      &tmp, NULL);
      if (rc == GNUTLS_E_UNKNOWN_ALGORITHM)
	continue;
      if (rc == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
	break;
      if (rc < 0)
	goto done;

      printf ("CA issuers URI: %.*s\n", tmp.size, tmp.data);
      gnutls_free (tmp.data);
      break;
    }

  if (!tmp.data)
    printf ("No CA issuers URI found\n");

  for (seq = 0; ; seq++)
    {
      rc = gnutls_x509_crt_get_authority_info_access (cert, seq,
						      GNUTLS_IA_OCSP_URI,
						      &tmp, NULL);
      if (rc == GNUTLS_E_UNKNOWN_ALGORITHM)
	continue;
      if (rc == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
	break;
      if (rc < 0)
	goto done;

      printf ("OCSP URI: %.*s\n", tmp.size, tmp.data);
      gnutls_free (tmp.data);
      break;
    }

  if (!tmp.data)
    printf ("No OCSP URI URI found\n");

  if (argc < 3)
    {
      printf ("Done...\n");
      goto done;
    }

  /* Read issuer and print OCSP request. */

  rc = gnutls_x509_crt_init (&issuer);
  if (rc < 0)
    goto done;

  issuerdata.data = read_binary_file (argv[2], &s);
  if (issuerdata.data == NULL)
    {
      printf ("cannot read issuer\n");
      goto done;
    }
  issuerdata.size = s;

  rc = gnutls_x509_crt_import (issuer, &issuerdata, GNUTLS_X509_FMT_PEM);
  free (issuerdata.data);
  if (rc < 0)
    goto done;

  rc = gnutls_x509_crt_print (issuer, GNUTLS_CRT_PRINT_ONELINE, &tmp);
  if (rc < 0)
    goto done;

  printf ("issuer: %.*s\n", tmp.size, tmp.data);

  gnutls_free (tmp.data);

  rc = 0;

 done:
  if (rc != 0)
    printf ("error (%d): %s\n", rc, gnutls_strerror (rc));
  gnutls_x509_crt_deinit (cert);
  gnutls_x509_crt_deinit (issuer);
  gnutls_global_deinit ();

  return rc == 0 ? 0 : 1;
}
