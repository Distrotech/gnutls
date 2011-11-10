/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
 *
 * Author: Simon Josefsson
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/ocsp.h>
#include <gnutls/x509.h>

#include "utils.h"

/* sample request */

#define REQ1 "\x30\x67\x30\x65\x30\x3e\x30\x3c\x30\x3a\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14\x13\x9d\xa0\x9e\xf4\x32\xab\x8f\xe2\x89\x56\x67\xfa\xd0\xd4\xe3\x35\x86\x71\xb9\x04\x14\x5d\xa7\xdd\x70\x06\x51\x32\x7e\xe7\xb6\x6d\xb3\xb5\xe5\xe0\x60\xea\x2e\x4d\xef\x02\x01\x1d\xa2\x23\x30\x21\x30\x1f\x06\x09\x2b\x06\x01\x05\x05\x07\x30\x01\x02\x04\x12\x04\x10\x35\xc5\xe3\x50\xc3\xcf\x04\x33\xcc\x9e\x06\x3a\x9a\x18\x80\xcc"

static const gnutls_datum_t req1 =
  { (unsigned char *) REQ1, sizeof (REQ1) - 1 };

#define REQ1INFO							\
  "OCSP Request Information:\n"						\
  "	Version: 1\n"							\
  "	Request List:\n"						\
  "		Certificate ID:\n"					\
  "			Hash Algorithm: SHA1\n"				\
  "			Issuer Name Hash: 139da09ef432ab8fe2895667fad0d4e3358671b9\n" \
  "			Issuer Key Hash: 5da7dd700651327ee7b66db3b5e5e060ea2e4def\n" \
  "			Serial Number: 1d\n"				\
  "	Extensions:\n"							\
  "		Nonce: 35c5e350c3cf0433cc9e063a9a1880cc\n"

#define REQ1NONCE "\x04\x10\x35\xc5\xe3\x50\xc3\xcf\x04\x33\xcc\x9e\x06\x3a\x9a\x18\x80\xcc"

#define REQ1INH "\x13\x9d\xa0\x9e\xf4\x32\xab\x8f\xe2\x89\x56\x67\xfa\xd0\xd4\xe3\x35\x86\x71\xb9"
#define REQ1IKH "\x5d\xa7\xdd\x70\x06\x51\x32\x7e\xe7\xb6\x6d\xb3\xb5\xe5\xe0\x60\xea\x2e\x4d\xef"
#define REQ1SN "\x1d"

/* sample response */

#define RESP1 "\x30\x03\x0a\x01\x01"

static const gnutls_datum_t resp1 =
  { (unsigned char*) RESP1, sizeof (RESP1) - 1 };

#define RESP1INFO							\
  "OCSP Response Information:\n"					\
  "	Response Status: malformedRequest\n"

#define RESP2 "\x30\x82\x06\x8C\x0A\x01\x00\xA0\x82\x06\x85\x30\x82\x06\x81\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x01\x04\x82\x06\x72\x30\x82\x06\x6E\x30\x82\x01\x07\xA1\x69\x30\x67\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x43\x48\x31\x19\x30\x17\x06\x03\x55\x04\x0A\x13\x10\x4C\x69\x6E\x75\x78\x20\x73\x74\x72\x6F\x6E\x67\x53\x77\x61\x6E\x31\x1F\x30\x1D\x06\x03\x55\x04\x0B\x13\x16\x4F\x43\x53\x50\x20\x53\x69\x67\x6E\x69\x6E\x67\x20\x41\x75\x74\x68\x6F\x72\x69\x74\x79\x31\x1C\x30\x1A\x06\x03\x55\x04\x03\x13\x13\x6F\x63\x73\x70\x2E\x73\x74\x72\x6F\x6E\x67\x73\x77\x61\x6E\x2E\x6F\x72\x67\x18\x0F\x32\x30\x31\x31\x30\x39\x32\x37\x30\x39\x35\x34\x32\x38\x5A\x30\x64\x30\x62\x30\x3A\x30\x09\x06\x05\x2B\x0E\x03\x02\x1A\x05\x00\x04\x14\x13\x9D\xA0\x9E\xF4\x32\xAB\x8F\xE2\x89\x56\x67\xFA\xD0\xD4\xE3\x35\x86\x71\xB9\x04\x14\x5D\xA7\xDD\x70\x06\x51\x32\x7E\xE7\xB6\x6D\xB3\xB5\xE5\xE0\x60\xEA\x2E\x4D\xEF\x02\x01\x1D\x80\x00\x18\x0F\x32\x30\x31\x31\x30\x39\x32\x37\x30\x39\x35\x34\x32\x38\x5A\xA0\x11\x18\x0F\x32\x30\x31\x31\x30\x39\x32\x37\x30\x39\x35\x39\x32\x38\x5A\xA1\x23\x30\x21\x30\x1F\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x02\x04\x12\x04\x10\x16\x89\x7D\x91\x3A\xB5\x25\xA4\x45\xFE\xC9\xFD\xC2\xE5\x08\xA4\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x03\x82\x01\x01\x00\x4E\xAD\x6B\x2B\xF7\xF2\xBF\xA9\x23\x1E\x3A\x0B\x06\xDB\x55\x53\x2B\x64\x54\x11\x32\xBF\x60\xF7\x4F\xE0\x8E\x9B\xA0\xA2\x4C\x79\xC3\x2A\xE0\x43\xF7\x40\x1A\xDC\xB9\xB4\x25\xEF\x48\x01\x97\x8C\xF5\x1E\xDB\xD1\x30\x37\x73\x69\xD6\xA7\x7A\x2D\x8E\xDE\x5C\xAA\xEA\x39\xB9\x52\xAA\x25\x1E\x74\x7D\xF9\x78\x95\x8A\x92\x1F\x98\x21\xF4\x60\x7F\xD3\x28\xEE\x47\x9C\xBF\xE2\x5D\xF6\x3F\x68\x0A\xD6\xFF\x08\xC1\xDC\x95\x1E\x29\xD7\x3E\x85\xD5\x65\xA4\x4B\xC0\xAF\xC3\x78\xAB\x06\x98\x88\x19\x8A\x64\xA6\x83\x91\x87\x13\xDB\x17\xCC\x46\xBD\xAB\x4E\xC7\x16\xD1\xF8\x35\xFD\x27\xC8\xF6\x6B\xEB\x37\xB8\x08\x6F\xE2\x6F\xB4\x7E\xD5\x68\xDB\x7F\x5D\x5E\x36\x38\xF2\x77\x59\x13\xE7\x3E\x4D\x67\x5F\xDB\xA2\xF5\x5D\x7C\xBF\xBD\xB5\x37\x33\x51\x36\x63\xF8\x21\x1E\xFC\x73\x8F\x32\x69\xBB\x97\xA7\xBD\xF1\xB6\xE0\x40\x09\x68\xEA\xD5\x93\xB8\xBB\x39\x8D\xA8\x16\x1B\xBF\x04\x7A\xBC\x18\x43\x01\xE9\x3C\x19\x5C\x4D\x4B\x98\xD8\x23\x37\x39\xA4\xC4\xDD\xED\x9C\xEC\x37\xAB\x66\x44\x9B\xE7\x5B\x5D\x32\xA2\xDB\xA6\x0B\x3B\x8C\xE1\xF5\xDB\xCB\x7D\x58\xA0\x82\x04\x4B\x30\x82\x04\x47\x30\x82\x04\x43\x30\x82\x03\x2B\xA0\x03\x02\x01\x02\x02\x01\x1E\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B\x05\x00\x30\x45\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x43\x48\x31\x19\x30\x17\x06\x03\x55\x04\x0A\x13\x10\x4C\x69\x6E\x75\x78\x20\x73\x74\x72\x6F\x6E\x67\x53\x77\x61\x6E\x31\x1B\x30\x19\x06\x03\x55\x04\x03\x13\x12\x73\x74\x72\x6F\x6E\x67\x53\x77\x61\x6E\x20\x52\x6F\x6F\x74\x20\x43\x41\x30\x1E\x17\x0D\x30\x39\x31\x31\x32\x34\x31\x32\x35\x31\x35\x33\x5A\x17\x0D\x31\x34\x31\x31\x32\x33\x31\x32\x35\x31\x35\x33\x5A\x30\x67\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x43\x48\x31\x19\x30\x17\x06\x03\x55\x04\x0A\x13\x10\x4C\x69\x6E\x75\x78\x20\x73\x74\x72\x6F\x6E\x67\x53\x77\x61\x6E\x31\x1F\x30\x1D\x06\x03\x55\x04\x0B\x13\x16\x4F\x43\x53\x50\x20\x53\x69\x67\x6E\x69\x6E\x67\x20\x41\x75\x74\x68\x6F\x72\x69\x74\x79\x31\x1C\x30\x1A\x06\x03\x55\x04\x03\x13\x13\x6F\x63\x73\x70\x2E\x73\x74\x72\x6F\x6E\x67\x73\x77\x61\x6E\x2E\x6F\x72\x67\x30\x82\x01\x22\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01\x0F\x00\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xBC\x05\x3E\x4B\xBE\xC6\xB1\x33\x48\x0E\xC3\xD4\x0C\xEF\x83\x0B\xBD\xBC\x57\x5F\x14\xEF\xF5\x6D\x0B\xFF\xFA\x01\x9C\xFA\x21\x6D\x5C\xAE\x79\x29\x74\xFE\xBD\xAB\x70\x87\x98\x6B\x48\x35\x79\xE3\xE0\xC1\x14\x41\x1F\x0A\xF7\xE7\xA3\xA6\xDA\x6B\xFF\xCD\x74\xE9\x95\x00\x38\xAA\xD6\x3A\x60\xC6\x64\xA1\xE6\x02\x39\x58\x4E\xFD\xF2\x78\x08\x63\xB6\xD7\x7A\x96\x79\x62\x18\x39\xEE\x27\x8D\x3B\xA2\x3D\x48\x88\xDB\x43\xD6\x6A\x77\x20\x6A\x27\x39\x50\xE0\x02\x50\x19\xF2\x7A\xCF\x78\x23\x99\x01\xD4\xE5\xB1\xD1\x31\xE6\x6B\x84\xAF\xD0\x77\x41\x46\x85\xB0\x3B\xE6\x6A\x00\x0F\x3B\x7E\x95\x7F\x59\xA8\x22\xE8\x49\x49\x05\xC8\xCB\x6C\xEE\x47\xA7\x2D\xC9\x74\x5B\xEB\x8C\xD5\x99\xC2\xE2\x70\xDB\xEA\x87\x43\x84\x0E\x4F\x83\x1C\xA6\xEB\x1F\x22\x38\x17\x69\x9B\x72\x12\x95\x48\x71\xB2\x7B\x92\x73\x52\xAB\xE3\x1A\xA5\xD3\xF4\x44\x14\xBA\xC3\x35\xDA\x91\x6C\x7D\xB4\xC2\x00\x07\xD8\x0A\x51\xF1\x0D\x4C\xD9\x7A\xD1\x99\xE6\xA8\x8D\x0A\x80\xA8\x91\xDD\x8A\xA2\x6B\xF6\xDB\xB0\x3E\xC9\x71\xA9\xE0\x39\xC3\xA3\x58\x0D\x87\xD0\xB2\xA7\x9C\xB7\x69\x02\x03\x01\x00\x01\xA3\x82\x01\x1A\x30\x82\x01\x16\x30\x09\x06\x03\x55\x1D\x13\x04\x02\x30\x00\x30\x0B\x06\x03\x55\x1D\x0F\x04\x04\x03\x02\x03\xA8\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14\x34\x91\x6E\x91\x32\xBF\x35\x25\x43\xCC\x28\x74\xEF\x82\xC2\x57\x92\x79\x13\x73\x30\x6D\x06\x03\x55\x1D\x23\x04\x66\x30\x64\x80\x14\x5D\xA7\xDD\x70\x06\x51\x32\x7E\xE7\xB6\x6D\xB3\xB5\xE5\xE0\x60\xEA\x2E\x4D\xEF\xA1\x49\xA4\x47\x30\x45\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x43\x48\x31\x19\x30\x17\x06\x03\x55\x04\x0A\x13\x10\x4C\x69\x6E\x75\x78\x20\x73\x74\x72\x6F\x6E\x67\x53\x77\x61\x6E\x31\x1B\x30\x19\x06\x03\x55\x04\x03\x13\x12\x73\x74\x72\x6F\x6E\x67\x53\x77\x61\x6E\x20\x52\x6F\x6F\x74\x20\x43\x41\x82\x01\x00\x30\x1E\x06\x03\x55\x1D\x11\x04\x17\x30\x15\x82\x13\x6F\x63\x73\x70\x2E\x73\x74\x72\x6F\x6E\x67\x73\x77\x61\x6E\x2E\x6F\x72\x67\x30\x13\x06\x03\x55\x1D\x25\x04\x0C\x30\x0A\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x09\x30\x39\x06\x03\x55\x1D\x1F\x04\x32\x30\x30\x30\x2E\xA0\x2C\xA0\x2A\x86\x28\x68\x74\x74\x70\x3A\x2F\x2F\x63\x72\x6C\x2E\x73\x74\x72\x6F\x6E\x67\x73\x77\x61\x6E\x2E\x6F\x72\x67\x2F\x73\x74\x72\x6F\x6E\x67\x73\x77\x61\x6E\x2E\x63\x72\x6C\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B\x05\x00\x03\x82\x01\x01\x00\x6D\x78\xD7\x66\x90\xA6\xEB\xDD\xB5\x09\x48\xA4\xDA\x27\xFA\xAC\xB1\xBC\x8F\x8C\xBE\xCC\x8C\x09\xA2\x40\x0D\x6C\x4A\xAE\x72\x22\x1E\xC8\xAF\x6D\xF1\x12\xAF\xD7\x40\x51\x79\xD4\xDD\xB2\x0C\xDB\x97\x84\xB6\x24\xD5\xF5\xA8\xBB\xC0\x4B\xF9\x7F\x71\xF7\xB0\x65\x42\x4A\x7D\xFE\x76\x7E\x05\xD2\x46\xB8\x7D\xB3\x39\x4C\x5C\xB1\xFA\xB9\xEE\x3B\x70\x33\x39\x57\x1A\xB9\x95\x51\x33\x00\x25\x1B\x4C\xAA\xB4\xA7\x55\xAF\x63\x6D\x6F\x88\x17\x6A\x7F\xB0\x97\xDE\x49\x14\x6A\x27\x6A\xB0\x42\x80\xD6\xA6\x9B\xEF\x04\x5E\x11\x7D\xD5\x8E\x54\x20\xA2\x76\xD4\x66\x58\xAC\x9C\x12\xD3\xF5\xCA\x54\x98\xCA\x21\xEC\xC1\x55\xA1\x2F\x68\x0B\x5D\x04\x50\xD2\x5E\x70\x25\xD8\x13\xD9\x44\x51\x0E\x8A\x42\x08\x18\x84\xE6\x61\xCE\x5A\x7D\x7B\x81\x35\x90\xC3\xD4\x9D\x19\xB6\x37\xEE\x8F\x63\x5C\xDA\xD8\xF0\x64\x60\x39\xEB\x9B\x1C\x54\x66\x75\x76\xB5\x0A\x58\xB9\x3F\x91\xE1\x21\x9C\xA0\x50\x15\x97\xB6\x7E\x41\xBC\xD0\xC4\x21\x4C\xF5\xD7\xF0\x13\xF8\x77\xE9\x74\xC4\x8A\x0E\x20\x17\x32\xAE\x38\xC2\xA5\xA8\x62\x85\x17\xB1\xA2\xD3\x22\x9F\x95\xB7\xA3\x4C"

static const gnutls_datum_t resp2 =
  { (unsigned char*) RESP2, sizeof (RESP2) - 1 };

static unsigned char issuer_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIDuDCCAqCgAwIBAgIBADANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJDSDEZ\n"
  "MBcGA1UEChMQTGludXggc3Ryb25nU3dhbjEbMBkGA1UEAxMSc3Ryb25nU3dhbiBS\n"
  "b290IENBMB4XDTA0MDkxMDEwMDExOFoXDTE5MDkwNzEwMDExOFowRTELMAkGA1UE\n"
  "BhMCQ0gxGTAXBgNVBAoTEExpbnV4IHN0cm9uZ1N3YW4xGzAZBgNVBAMTEnN0cm9u\n"
  "Z1N3YW4gUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL/y\n"
  "X2LqPVZuWLPIeknK86xhz6ljd3NNhC2z+P1uoCP3sBMuZiZQEjFzhnKcbXxCeo2f\n"
  "FnvhOOjrrisSuVkzuu82oxXD3fIkzuS7m9V4E10EZzgmKWIf+WuNRfbgAuUINmLc\n"
  "4YGAXBQLPyzpP4Ou48hhz/YQo58Bics6PHy5v34qCVROIXDvqhj91P8g+pS+F21/\n"
  "7P+CH2jRcVIEHZtG8M/PweTPQ95dPzpYd2Ov6SZ/U7EWmbMmT8VcUYn1aChxFmy5\n"
  "gweVBWlkH6MP+1DeE0/tL5c87xo5KCeGK8Tdqpe7sBRC4pPEEHDQciTUvkeuJ1Pr\n"
  "K+1LwdqRxo7HgMRiDw8CAwEAAaOBsjCBrzASBgNVHRMBAf8ECDAGAQH/AgEBMAsG\n"
  "A1UdDwQEAwIBBjAdBgNVHQ4EFgQUXafdcAZRMn7ntm2zteXgYOouTe8wbQYDVR0j\n"
  "BGYwZIAUXafdcAZRMn7ntm2zteXgYOouTe+hSaRHMEUxCzAJBgNVBAYTAkNIMRkw\n"
  "FwYDVQQKExBMaW51eCBzdHJvbmdTd2FuMRswGQYDVQQDExJzdHJvbmdTd2FuIFJv\n"
  "b3QgQ0GCAQAwDQYJKoZIhvcNAQELBQADggEBACOSmqEBtBLR9aV3UyCI8gmzR5in\n"
  "Lte9aUXXS+qis6F2h2Stf4sN+Nl6Gj7REC6SpfEH4wWdwiUL5J0CJhyoOjQuDl3n\n"
  "1Dw3dE4/zqMZdyDKEYTU75TmvusNJBdGsLkrf7EATAjoi/nrTOYPPhSUZvPp/D+Y\n"
  "vORJ9Ej51GXlK1nwEB5iA8+tDYniNQn6BD1MEgIejzK+fbiy7braZB1kqhoEr2Si\n"
  "7luBSnU912sw494E88a2EWbmMvg2TVHPNzCpVkpNk7kifCiwmw9VldkqYy9y/lCa\n"
  "Epyp7lTfKw7cbD04Vk8QJW782L6Csuxkl346b17wmOqn8AZips3tFsuAY3w=\n"
  "-----END CERTIFICATE-----\n";
const gnutls_datum_t issuer_data = { issuer_pem, sizeof (issuer_pem) };

static unsigned char subject_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIEIjCCAwqgAwIBAgIBHTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJDSDEZ\n"
  "MBcGA1UEChMQTGludXggc3Ryb25nU3dhbjEbMBkGA1UEAxMSc3Ryb25nU3dhbiBS\n"
  "b290IENBMB4XDTA5MDgyNzEwNDQ1MVoXDTE0MDgyNjEwNDQ1MVowWjELMAkGA1UE\n"
  "BhMCQ0gxGTAXBgNVBAoTEExpbnV4IHN0cm9uZ1N3YW4xETAPBgNVBAsTCFJlc2Vh\n"
  "cmNoMR0wGwYDVQQDFBRjYXJvbEBzdHJvbmdzd2FuLm9yZzCCASIwDQYJKoZIhvcN\n"
  "AQEBBQADggEPADCCAQoCggEBANBdWU+BF7x4lyo+xHnr4UAOU89yQQuT5vdPoXzx\n"
  "6kRPsjYAuuktgXR+SaLkQHw/YRgDPSKj5nzmmlOQf/rWRr+8O2q+C92aUICmkNvZ\n"
  "Gamo5w2WlOMZ6T5dk2Hv+QM6xT/GzWyVr1dMYu/7tywD1Bw7aW/HqkRESDu6q95V\n"
  "Wu+Lzg6XlxCNEez0YsZrN/fC6BL2qzKAqMBbIHFW8OOnh+nEY4IF5AzkZnFrw12G\n"
  "I72Z882pw97lyKwZhSz/GMQFBJx+rnNdw5P1IJwTlG5PUdoDCte/Mcr1iiA+zOov\n"
  "x55x1GoGxduoXWU5egrf1MtalRf9Pc8Xr4q3WEKTAmsZrVECAwEAAaOCAQYwggEC\n"
  "MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgOoMB0GA1UdDgQWBBQfoamI2WSMtaCiVGQ5\n"
  "tPI9dF1ufDBtBgNVHSMEZjBkgBRdp91wBlEyfue2bbO15eBg6i5N76FJpEcwRTEL\n"
  "MAkGA1UEBhMCQ0gxGTAXBgNVBAoTEExpbnV4IHN0cm9uZ1N3YW4xGzAZBgNVBAMT\n"
  "EnN0cm9uZ1N3YW4gUm9vdCBDQYIBADAfBgNVHREEGDAWgRRjYXJvbEBzdHJvbmdz\n"
  "d2FuLm9yZzA5BgNVHR8EMjAwMC6gLKAqhihodHRwOi8vY3JsLnN0cm9uZ3N3YW4u\n"
  "b3JnL3N0cm9uZ3N3YW4uY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQC8pqX3KrSzKeul\n"
  "GdzydAV4hGwYB3WiB02oJ2nh5MJBu7J0Kn4IVkvLUHSSZhSRxx55tQZfdYqtXVS7\n"
  "ZuyG+6rV7sb595SIRwfkLAdjbvv0yZIl4xx8j50K3yMR+9aXW1NSGPEkb8BjBUMr\n"
  "F2kjGTOqomo8OIzyI369z9kJrtEhnS37nHcdpewZC1wHcWfJ6wd9wxmz2dVXmgVQ\n"
  "L2BjXd/BcpLFaIC4h7jMXQ5FURjnU7K9xSa4T8PpR6FrQhOcIYBXAp94GiM8JqmK\n"
  "ZBGUpeP+3cy4i3DV18Kyr64Q4XZlzhZClNE43sgMqiX88dc3znpDzT7T51j+d+9k\n"
  "Rf5Z0GOR\n"
  "-----END CERTIFICATE-----\n";
const gnutls_datum_t subject_data = { subject_pem, sizeof (subject_pem) };

/* import a request, query some fields and print and export it */
static void
req_parse (void)
{
  gnutls_ocsp_req_t req;
  int ret;
  gnutls_datum_t d;

  /* init request */

  ret = gnutls_ocsp_req_init (&req);
  if (ret != 0)
    {
      fail ("gnutls_ocsp_req_init\n");
      exit (1);
    }

  /* import ocsp request */

  ret = gnutls_ocsp_req_import (req, &req1);
  if (ret != 0)
    {
      fail ("gnutls_ocsp_req_import %d\n", ret);
      exit (1);
    }

  /* simple version query */

  ret = gnutls_ocsp_req_get_version (req);
  if (ret != 1)
    {
      fail ("gnutls_ocsp_req_get_version %d\n", ret);
      exit (1);
    }

  /* check nonce */
  {
    gnutls_datum_t expect =
      { (unsigned char*) REQ1NONCE + 2, sizeof (REQ1NONCE) - 3 };
    gnutls_datum_t got;
    unsigned int critical;

    ret = gnutls_ocsp_req_get_nonce (req, &critical, &got);
    if (ret != 0)
      {
	fail ("gnutls_ocsp_req_get_nonce %d\n", ret);
	exit (1);
      }

    if (critical != 0)
      {
	fail ("unexpected critical %d\n", critical);
	exit (1);
      }

    if (expect.size != got.size ||
	memcmp (expect.data, got.data, got.size) != 0)
      {
	fail ("ocsp request nonce memcmp failed\n");
	exit (1);
      }

    gnutls_free (got.data);
  }

  /* print request */

  ret = gnutls_ocsp_req_print (req, GNUTLS_OCSP_PRINT_FULL, &d);
  if (ret != 0)
    {
      fail ("gnutls_ocsp_req_print\n");
      exit (1);
    }

  if (d.size != strlen (REQ1INFO) ||
      memcmp (REQ1INFO, d.data, strlen (REQ1INFO)) != 0)
    {
      fail ("ocsp request print failed\n");
      exit (1);
    }
  gnutls_free (d.data);

  /* test export */
  ret = gnutls_ocsp_req_export (req, &d);
  if (ret != 0)
    {
      fail ("gnutls_ocsp_req_export %d\n", ret);
      exit (1);
    }

  /* compare against earlier imported bytes */

  if (req1.size != d.size ||
      memcmp (req1.data, d.data, d.size) != 0)
    {
      fail ("ocsp request export memcmp failed\n");
      exit (1);
    }
  gnutls_free (d.data);

  /* test setting nonce */
  {
    gnutls_datum_t n1 = { (unsigned char *) "foo", 3 };
    gnutls_datum_t n2 = { (unsigned char *) "foobar", 6 };
    gnutls_datum_t got;
    unsigned critical;

    ret = gnutls_ocsp_req_set_nonce (req, 0, &n1);
    if (ret != 0)
      {
	fail ("gnutls_ocsp_req_set_nonce %d\n", ret);
	exit (1);
      }

    ret = gnutls_ocsp_req_get_nonce (req, &critical, &got);
    if (ret != 0)
      {
	fail ("gnutls_ocsp_req_get_nonce %d\n", ret);
	exit (1);
      }

    if (critical != 0)
      {
	fail ("unexpected critical %d\n", critical);
	exit (1);
      }

    if (n1.size != got.size ||
	memcmp (n1.data, got.data, got.size) != 0)
      {
	fail ("ocsp request parse nonce memcmp failed\n");
	exit (1);
      }

    gnutls_free (got.data);

    /* set another time */

    ret = gnutls_ocsp_req_set_nonce (req, 1, &n2);
    if (ret != 0)
      {
	fail ("gnutls_ocsp_req_set_nonce %d\n", ret);
	exit (1);
      }

    ret = gnutls_ocsp_req_get_nonce (req, &critical, &got);
    if (ret != 0)
      {
	fail ("gnutls_ocsp_req_get_nonce %d\n", ret);
	exit (1);
      }

    if (critical != 1)
      {
	fail ("unexpected critical %d\n", critical);
	exit (1);
      }

    if (n2.size != got.size ||
	memcmp (n2.data, got.data, got.size) != 0)
      {
	fail ("ocsp request parse2 nonce memcmp failed\n");
	exit (1);
      }

    gnutls_free (got.data);

    /* randomize nonce */

    ret = gnutls_ocsp_req_randomize_nonce (req);
    if (ret != 0)
      {
	fail ("gnutls_ocsp_req_randomize_nonce %d\n", ret);
	exit (1);
      }

    ret = gnutls_ocsp_req_get_nonce (req, &critical, &n1);
    if (ret != 0)
      {
	fail ("gnutls_ocsp_req_get_nonce %d\n", ret);
	exit (1);
      }

    if (critical != 0)
      {
	fail ("unexpected random critical %d\n", critical);
	exit (1);
      }

    ret = gnutls_ocsp_req_randomize_nonce (req);
    if (ret != 0)
      {
	fail ("gnutls_ocsp_req_randomize_nonce %d\n", ret);
	exit (1);
      }

    ret = gnutls_ocsp_req_get_nonce (req, &critical, &n2);
    if (ret != 0)
      {
	fail ("gnutls_ocsp_req_get_nonce %d\n", ret);
	exit (1);
      }

    if (critical != 0)
      {
	fail ("unexpected random critical %d\n", critical);
	exit (1);
      }

    if (n2.size == got.size && memcmp (n1.data, n2.data, n1.size) == 0)
      {
	fail ("ocsp request random nonce memcmp failed\n");
	exit (1);
      }

    gnutls_free (n1.data);
    gnutls_free (n2.data);
  }

  /* cleanup */

  gnutls_ocsp_req_deinit (req);
}

/* check that creating a request (using low-level add_certid) ends up
   with same DER as above. */
static void
req_addcertid (void)
{
  gnutls_ocsp_req_t req;
  int ret;
  gnutls_datum_t d;

  /* init request */

  ret = gnutls_ocsp_req_init (&req);
  if (ret != 0)
    {
      fail ("gnutls_ocsp_req_init\n");
      exit (1);
    }

  /* add ocsp request nonce */

  {
    gnutls_datum_t nonce =
      { (unsigned char*) REQ1NONCE, sizeof (REQ1NONCE) - 1 };

    ret = gnutls_ocsp_req_set_extension (req, "1.3.6.1.5.5.7.48.1.2",
					 0, &nonce);
    if (ret != 0)
      {
	fail ("gnutls_ocsp_req_set_extension %d\n", ret);
	exit (1);
      }
  }

  /* add certid */
  {
    gnutls_datum_t issuer_name_hash =
      { (unsigned char*) REQ1INH, sizeof (REQ1INH) - 1 };
    gnutls_datum_t issuer_key_hash =
      { (unsigned char*) REQ1IKH, sizeof (REQ1IKH) - 1 };
    gnutls_datum_t serial_number =
      { (unsigned char*) REQ1SN, sizeof (REQ1SN) - 1 };

    ret = gnutls_ocsp_req_add_certid (req, GNUTLS_DIG_SHA1,
				      &issuer_name_hash,
				      &issuer_key_hash,
				      &serial_number);
    if (ret != 0)
      {
	fail ("gnutls_ocsp_add_certid %d\n", ret);
	exit (1);
      }
  }

  /* print request */

  ret = gnutls_ocsp_req_print (req, GNUTLS_OCSP_PRINT_FULL, &d);
  if (ret != 0)
    {
      fail ("gnutls_ocsp_req_print\n");
      exit (1);
    }

  if (d.size != strlen (REQ1INFO) ||
      memcmp (REQ1INFO, d.data, strlen (REQ1INFO)) != 0)
    {
      fail ("ocsp request print failed\n");
      exit (1);
    }
  gnutls_free (d.data);

  /* test export */
  ret = gnutls_ocsp_req_export (req, &d);
  if (ret != 0)
    {
      fail ("gnutls_ocsp_req_export %d\n", ret);
      exit (1);
    }

  /* compare against earlier imported bytes */

  if (req1.size != d.size ||
      memcmp (req1.data, d.data, d.size) != 0)
    {
      fail ("ocsp request export memcmp failed\n");
      exit (1);
    }
  gnutls_free (d.data);

  /* cleanup */

  gnutls_ocsp_req_deinit (req);
}

/* check that creating a request (using high-level add_cert) ends up
   with same DER as above. */
static void
req_addcert (void)
{
  gnutls_ocsp_req_t req;
  int ret;
  gnutls_datum_t d;

  /* init request */

  ret = gnutls_ocsp_req_init (&req);
  if (ret != 0)
    {
      fail ("gnutls_ocsp_req_init\n");
      exit (1);
    }

  /* add ocsp request nonce */

  {
    gnutls_datum_t nonce =
      { (unsigned char*) REQ1NONCE, sizeof (REQ1NONCE) - 1 };

    ret = gnutls_ocsp_req_set_extension (req, "1.3.6.1.5.5.7.48.1.2",
					 0, &nonce);
    if (ret != 0)
      {
	fail ("gnutls_ocsp_req_set_extension %d\n", ret);
	exit (1);
      }
  }

  /* add certid */
  {
    gnutls_x509_crt_t issuer = NULL, subject = NULL;

    ret = gnutls_x509_crt_init (&issuer);
    if (ret < 0)
      {
	fail ("gnutls_x509_crt_init (issuer) %d\n", ret);
	exit (1);
      }

    ret = gnutls_x509_crt_init (&subject);
    if (ret < 0)
      {
	fail ("gnutls_x509_crt_init (subject) %d\n", ret);
	exit (1);
      }

    ret = gnutls_x509_crt_import (issuer, &issuer_data, GNUTLS_X509_FMT_PEM);
    if (ret < 0)
      {
	fail ("gnutls_x509_crt_import (issuer) %d\n", ret);
	exit (1);
      }

    ret = gnutls_x509_crt_import (subject, &subject_data, GNUTLS_X509_FMT_PEM);
    if (ret < 0)
      {
	fail ("gnutls_x509_crt_import (subject) %d\n", ret);
	exit (1);
      }

    ret = gnutls_ocsp_req_add_cert (req, GNUTLS_DIG_SHA1,
				    issuer, subject);
    if (ret != 0)
      {
	fail ("gnutls_ocsp_add_cert %d\n", ret);
	exit (1);
      }

    gnutls_x509_crt_deinit (subject);
    gnutls_x509_crt_deinit (issuer);
  }

  /* print request */

  ret = gnutls_ocsp_req_print (req, GNUTLS_OCSP_PRINT_FULL, &d);
  if (ret != 0)
    {
      fail ("gnutls_ocsp_req_print\n");
      exit (1);
    }

  if (d.size != strlen (REQ1INFO) ||
      memcmp (REQ1INFO, d.data, strlen (REQ1INFO)) != 0)
    {
      fail ("ocsp request print failed\n");
      exit (1);
    }
  gnutls_free (d.data);

  /* test export */
  ret = gnutls_ocsp_req_export (req, &d);
  if (ret != 0)
    {
      fail ("gnutls_ocsp_req_export %d\n", ret);
      exit (1);
    }

  /* compare against earlier imported bytes */

  if (req1.size != d.size ||
      memcmp (req1.data, d.data, d.size) != 0)
    {
      fail ("ocsp request export memcmp failed\n");
      exit (1);
    }
  gnutls_free (d.data);

  /* cleanup */

  gnutls_ocsp_req_deinit (req);
}

static void
resp_import (void)
{
  gnutls_ocsp_resp_t resp;
  int ret;
  gnutls_datum_t d;

  /* init response */

  ret = gnutls_ocsp_resp_init (&resp);
  if (ret != 0)
    {
      fail ("gnutls_ocsp_resp_init\n");
      exit (1);
    }

  /* import ocsp response */

  ret = gnutls_ocsp_resp_import (resp, &resp1);
  if (ret != 0)
    {
      fail ("gnutls_ocsp_resp_import %d\n", ret);
      exit (1);
    }

  /* print response */

  ret = gnutls_ocsp_resp_print (resp, GNUTLS_OCSP_PRINT_FULL, &d);
  if (ret != 0)
    {
      fail ("gnutls_ocsp_resp_print\n");
      exit (1);
    }

  if (d.size != strlen (RESP1INFO) ||
      memcmp (RESP1INFO, d.data, strlen (RESP1INFO)) != 0)
    {
      fail ("ocsp response print failed\n");
      exit (1);
    }
  gnutls_free (d.data);

  /* import ocsp response */

  ret = gnutls_ocsp_resp_import (resp, &resp2);
  if (ret != 0)
    {
      fail ("gnutls_ocsp_resp_import %d\n", ret);
      exit (1);
    }

  /* print response */

  ret = gnutls_ocsp_resp_print (resp, GNUTLS_OCSP_PRINT_FULL, &d);
  if (ret != 0)
    {
      fail ("gnutls_ocsp_resp_print\n");
      exit (1);
    }

  /* cleanup */

  gnutls_ocsp_resp_deinit (resp);
}

void
doit (void)
{
  int ret;

  ret = gnutls_global_init ();
  if (ret < 0)
    {
      fail ("gnutls_global_init\n");
      exit (1);
    }

  req_parse ();
  resp_import ();
  req_addcertid ();
  req_addcert ();

  /* we're done */

  gnutls_global_deinit ();
}
