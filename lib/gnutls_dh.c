/*
 *      Copyright (C) 2000,2001,2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *           someday was part of gsti
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
#include <gnutls_errors.h>
#include <gnutls_gcry.h>


/* 
	--Example-- 
	you: X = g ^ x mod p;
	peer:Y = g ^ y mod p;

	your_key = Y ^ x mod p;
	his_key  = X ^ y mod p;

//      generate our secret and the public value (X) for it
	X = gnutls_calc_dh_secret(&x, g, p);
//      now we can calculate the shared secret
	key = gnutls_calc_dh_key(Y, x, g, p);
	_gnutls_mpi_release(x);
	_gnutls_mpi_release(g);
*/


/* This function should return a resonable size for X
 * (DH secret key). The input is the number of bits of 
 * the modulus.
 * FIXME: This function is not correct
 */
int _gnutls_dh_get_secret_bits(int prime_bits) 
{
	if (prime_bits <= 2048)
		return 512;
	if (prime_bits <= 4096)
		return 768;
	return 1024;
}


/* returns the public value (X), and the secret (ret_x).
 */
GNUTLS_MPI gnutls_calc_dh_secret(GNUTLS_MPI * ret_x, GNUTLS_MPI g, GNUTLS_MPI prime, int secret_bits)
{
	GNUTLS_MPI e, x;

	x = _gnutls_mpi_new(secret_bits);
	if (x == NULL) {
		gnutls_assert();
		if (ret_x)
			*ret_x = NULL;

		return NULL;
	}

	_gnutls_mpi_randomize(x, secret_bits, GCRY_STRONG_RANDOM);

	/* fixme: set high bit of x and select a larger one */

	e = _gnutls_mpi_alloc_like(prime);
	if (e == NULL) {
		gnutls_assert();
		if (ret_x)
			*ret_x = NULL;

		_gnutls_mpi_release( &x);
		return NULL;
	}
	_gnutls_mpi_powm(e, g, x, prime);

	if (ret_x)
		*ret_x = x;
	else
		_gnutls_mpi_release(&x);
	return e;
}


GNUTLS_MPI gnutls_calc_dh_key(GNUTLS_MPI f, GNUTLS_MPI x, GNUTLS_MPI prime)
{
	GNUTLS_MPI k;

	k = _gnutls_mpi_alloc_like(prime);
	if (k == NULL)
		return NULL;
	_gnutls_mpi_powm(k, f, x, prime);
	return k;
}

