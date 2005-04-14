/*
 * Copyright (C) 2001, 2002, 2003, 2004, 2005 Free Software Foundation
 *
 * Author: Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

/* this is not to be included by gnutls_anon.c */
#include <gnutls_auth.h>
#include <auth_dh_common.h>

typedef struct gnutls_anon_server_credentials_st {
    gnutls_dh_params_t dh_params;
    /* this callback is used to retrieve the DH or RSA
     * parameters.
     */
    gnutls_params_function *params_func;
} anon_server_credentials_st;

typedef struct gnutls_anon_client_credentials_st {
  int dummy;
} anon_client_credentials_st;

typedef struct anon_client_auth_info_st {
    dh_info_st dh;
} *anon_client_auth_info_t;

typedef anon_client_auth_info_t anon_server_auth_info_t;
typedef anon_client_auth_info_t anon_auth_info_t;

typedef struct anon_client_auth_info_st anon_client_auth_info_st;
typedef anon_client_auth_info_st anon_server_auth_info_st;

gnutls_dh_params_t _gnutls_anon_get_dh_params(const
					      gnutls_anon_server_credentials_t
					      sc,
					      gnutls_session_t session);
