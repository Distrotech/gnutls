/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
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

#include "gnutls_random.h"
#include "gnutls_hash_int.h"
#include "auth_srp_passwd.h"
#include "gnutls_srp.h"
#include <gnutls_errors.h>

/*	x = SHA(<salt> | SHA(<username> | ":" | <raw password>)) */

static const char magic[] = "";

char *crypt_srpsha1(const char *username, const char *passwd,
		    const char *salt, GNUTLS_MPI g, GNUTLS_MPI n)
{
	unsigned char *sp, r1[MAX_HASH_SIZE];
	int salt_size = strlen(salt);
	unsigned char *local_salt, *v;
	int passwd_len;
	GNUTLS_HASH_HANDLE h1;
	int vsize, hash_len = _gnutls_hash_get_algo_len(GNUTLS_MAC_SHA);
	opaque *tmp;
	uint8 *rtext, *csalt;
	int rsalt_size, len, tmpsize;

	passwd_len = strlen(passwd);	/* we do not want the null */

	h1 = _gnutls_hash_init(GNUTLS_MAC_SHA);
	_gnutls_hash(h1, (char *) username, strlen(username));
	_gnutls_hash(h1, ":", 1);
	_gnutls_hash(h1, (char *) passwd, passwd_len);
	_gnutls_hash_deinit(h1, r1);

	
	local_salt = gnutls_malloc(salt_size + 1);
	if (local_salt==NULL) {
		gnutls_assert();
		return NULL;
	}
	strcpy((char *) local_salt, salt); /* Flawfinder: ignore */

	sp = index( local_salt, ':'); /* move to salt - after verifier */
	if (sp==NULL) {
		gnutls_assert();
		gnutls_free( local_salt);
		return NULL;
	}
	sp++;
	
	len = (int)rindex(sp, ':');
	if (len==0) { /* parse error */
		len = strlen(sp);
	} else
		len -= (int)sp;
	
	rsalt_size = _gnutls_sbase64_decode(sp, len, &csalt);
	if (rsalt_size < 0) {
		gnutls_assert();
		gnutls_free(local_salt);
		return NULL;
	}

	h1 = _gnutls_hash_init(GNUTLS_MAC_SHA);
	if (h1==NULL) {
		gnutls_assert();
		gnutls_free(local_salt);
		return NULL;
	}
	_gnutls_hash(h1, csalt, rsalt_size);
	gnutls_free(csalt);

	_gnutls_hash(h1, r1, hash_len);

	_gnutls_hash_deinit(h1, r1);

	/* v = g^x mod n */
	vsize = _gnutls_srp_gx(r1, hash_len, &v, g, n);

	if (vsize == -1 || v == NULL) {
		gnutls_assert();
		gnutls_free(local_salt);
		return NULL;
	}

	if (_gnutls_sbase64_encode(v, vsize, &rtext) < 0) {
		gnutls_free(v);
		gnutls_free(local_salt);
		gnutls_assert();
		return NULL;
	}
	gnutls_free(v);

	tmpsize = strlen(sp) + strlen(rtext) + strlen(magic) + 1 + 1;
	tmp =
	    gnutls_malloc( tmpsize);
	if (tmp==NULL) {
		gnutls_assert();
		gnutls_free(local_salt);
		return NULL;
	}
	sprintf(tmp, "%s%s:%s", magic, rtext, sp); /* Flawfinder: ignore */

	gnutls_free(rtext);
	gnutls_free(local_salt);

	return tmp;
}

/* salt here is the salt size */
char *crypt_srpsha1_wrapper(const char *username, const char *pass_new,
			    int salt, GNUTLS_MPI g, GNUTLS_MPI n)
{
	unsigned char *result;
	char *tcp;
	opaque *rand;
	char *e = NULL;
	int result_size;

	if (salt > 50 || salt <= 0)
		return NULL;	/* wow that's pretty long salt */

	rand = gnutls_malloc(salt);
	if (rand==NULL || _gnutls_get_random(rand, salt, GNUTLS_WEAK_RANDOM) < 0) {
		gnutls_assert();
		return NULL;
	}

	result_size = _gnutls_sbase64_encode(rand, salt, &result);
	if (result_size < 0) {
		gnutls_free(rand);
		gnutls_assert();
		return NULL;
	}

	tcp = gnutls_calloc(1, 1+ result_size + 1);
	if (tcp==NULL) {
		gnutls_assert();
		gnutls_free(rand);
		return NULL;
	}	
	sprintf(tcp, ":%s", result); /* Flawfinder: ignore */

	gnutls_free(result);
	gnutls_free(rand);
	/* no longer need cleartext */

	e = crypt_srpsha1(username, pass_new, (const char *) tcp, g, n);
	gnutls_free(tcp);

	return e;
}

#endif
