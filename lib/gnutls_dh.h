/*
 *      Copyright (C) 2000,2002 Nikos Mavroyanopoulos
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

MPI gnutls_get_dh_params(GNUTLS_DH_PARAMS, MPI *ret_p, int bits, int* qbits);
MPI gnutls_calc_dh_secret( MPI *ret_x, MPI g, MPI prime, int qbits);
MPI gnutls_calc_dh_key( MPI f, MPI x, MPI prime );
int _gnutls_dh_generate_prime(MPI *ret_g, MPI* ret_n, int bits, int* _qbits);
void _gnutls_dh_clear_mpis(void);
int _gnutls_dh_calc_mpis(void);
MPI _gnutls_get_rnd_srp_params( MPI * ret_p, int bits);

extern _GNUTLS_DH_PARAMS _gnutls_dh_default_params;
