/*
 *      Copyright (C) 2000,2001 Nikos Mavroyanopoulos
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

#include "gnutls_int.h"

#ifdef ENABLE_SRP

#include "crypt_bcrypt.h"
#include "crypt_srpsha1.h"
#include "gnutls_random.h"

char * gnutls_crypt(const char* username, const char *passwd, crypt_algo algo, int salt, GNUTLS_MPI g, GNUTLS_MPI n) {
	
	switch(algo) {
	case BLOWFISH_CRYPT: /* bcrypt */
		/* salt in bcrypt is actually the cost */
		return crypt_bcrypt_wrapper(username, passwd, salt, g, n);
	case SRPSHA1_CRYPT: /* bcrypt */
		/* salt in bcrypt is the salt size */
		return crypt_srpsha1_wrapper(username, passwd, salt, g, n);
	}
	return NULL;
}

int gnutls_crypt_vrfy(const char* username, const char *passwd, char* salt, GNUTLS_MPI g, GNUTLS_MPI n) {
	char* cr;

	switch(salt[0]) {
	case '$':
		switch(salt[1]) {
		case '2':
			cr = crypt_bcrypt(username, passwd, salt, g, n);
			if (cr==NULL) return 1;
			if (strncmp(cr, salt, strlen(cr))==0) return 0;
			break;
		}
	default:
		cr = crypt_srpsha1(username, passwd, salt, g, n);
		if (cr==NULL) return 1;
		if (strncmp(cr, salt, strlen(cr))==0) return 0;
		break;
	}
	return 1;
}

#endif
