/*   -*- buffer-read-only: t -*- vi: set ro:
 *
 *  DO NOT EDIT THIS FILE   (ocsptool-args.h)
 *
 *  It has been AutoGen-ed  April 15, 2014 at 12:47:01 PM by AutoGen 5.18.1
 *  From the definitions    ocsptool-args.def
 *  and the template file   options
 *
 * Generated from AutoOpts 40:1:15 templates.
 *
 *  AutoOpts is a copyrighted work.  This header file is not encumbered
 *  by AutoOpts licensing, but is provided under the licensing terms chosen
 *  by the ocsptool author or copyright holder.  AutoOpts is
 *  licensed under the terms of the LGPL.  The redistributable library
 *  (``libopts'') is licensed under the terms of either the LGPL or, at the
 *  users discretion, the BSD license.  See the AutoOpts and/or libopts sources
 *  for details.
 *
 * The ocsptool program is copyrighted and licensed
 * under the following terms:
 *
 *  Copyright (C) 2000-@YEAR@ Free Software Foundation, and others, all rights reserved.
 *  This is free software. It is licensed for use, modification and
 *  redistribution under the terms of the GNU General Public License,
 *  version 3 or later <http://gnu.org/licenses/gpl.html>
 *
 *  ocsptool is free software: you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  ocsptool is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/**
 *  This file contains the programmatic interface to the Automated
 *  Options generated for the ocsptool program.
 *  These macros are documented in the AutoGen info file in the
 *  "AutoOpts" chapter.  Please refer to that doc for usage help.
 */
#ifndef AUTOOPTS_OCSPTOOL_ARGS_H_GUARD
#define AUTOOPTS_OCSPTOOL_ARGS_H_GUARD 1
#include "config.h"
#include <autoopts/options.h>

/**
 *  Ensure that the library used for compiling this generated header is at
 *  least as new as the version current when the header template was released
 *  (not counting patch version increments).  Also ensure that the oldest
 *  tolerable version is at least as old as what was current when the header
 *  template was released.
 */
#define AO_TEMPLATE_VERSION 163841
#if (AO_TEMPLATE_VERSION < OPTIONS_MINIMUM_VERSION) \
 || (AO_TEMPLATE_VERSION > OPTIONS_STRUCT_VERSION)
# error option template version mismatches autoopts/options.h header
  Choke Me.
#endif

/**
 *  Enumeration of each option type for ocsptool
 */
typedef enum {
    INDEX_OPT_DEBUG             =  0,
    INDEX_OPT_VERBOSE           =  1,
    INDEX_OPT_INFILE            =  2,
    INDEX_OPT_OUTFILE           =  3,
    INDEX_OPT_ASK               =  4,
    INDEX_OPT_VERIFY_RESPONSE   =  5,
    INDEX_OPT_REQUEST_INFO      =  6,
    INDEX_OPT_RESPONSE_INFO     =  7,
    INDEX_OPT_GENERATE_REQUEST  =  8,
    INDEX_OPT_NONCE             =  9,
    INDEX_OPT_LOAD_ISSUER       = 10,
    INDEX_OPT_LOAD_CERT         = 11,
    INDEX_OPT_LOAD_TRUST        = 12,
    INDEX_OPT_LOAD_SIGNER       = 13,
    INDEX_OPT_INDER             = 14,
    INDEX_OPT_LOAD_REQUEST      = 15,
    INDEX_OPT_LOAD_RESPONSE     = 16,
    INDEX_OPT_VERSION           = 17,
    INDEX_OPT_HELP              = 18,
    INDEX_OPT_MORE_HELP         = 19
} teOptIndex;
/** count of all options for ocsptool */
#define OPTION_CT    20
/** ocsptool version */
#define OCSPTOOL_VERSION       "@VERSION@"
/** Full ocsptool version text */
#define OCSPTOOL_FULL_VERSION  "ocsptool @VERSION@"

/**
 *  Interface defines for all options.  Replace "n" with the UPPER_CASED
 *  option name (as in the teOptIndex enumeration above).
 *  e.g. HAVE_OPT(DEBUG)
 */
#define         DESC(n) (ocsptoolOptions.pOptDesc[INDEX_OPT_## n])
/** 'true' if an option has been specified in any way */
#define     HAVE_OPT(n) (! UNUSED_OPT(& DESC(n)))
/** The string argument to an option. The argument type must be \"string\". */
#define      OPT_ARG(n) (DESC(n).optArg.argString)
/** Mask the option state revealing how an option was specified.
 *  It will be one and only one of \a OPTST_SET, \a OPTST_PRESET,
 * \a OPTST_DEFINED, \a OPTST_RESET or zero.
 */
#define    STATE_OPT(n) (DESC(n).fOptState & OPTST_SET_MASK)
/** Count of option's occurrances *on the command line*. */
#define    COUNT_OPT(n) (DESC(n).optOccCt)
/** mask of \a OPTST_SET and \a OPTST_DEFINED. */
#define    ISSEL_OPT(n) (SELECTED_OPT(&DESC(n)))
/** 'true' if \a HAVE_OPT would yield 'false'. */
#define ISUNUSED_OPT(n) (UNUSED_OPT(& DESC(n)))
/** 'true' if OPTST_DISABLED bit not set. */
#define  ENABLED_OPT(n) (! DISABLED_OPT(& DESC(n)))
/** number of stacked option arguments.
 *  Valid only for stacked option arguments. */
#define  STACKCT_OPT(n) (((tArgList*)(DESC(n).optCookie))->useCt)
/** stacked argument vector.
 *  Valid only for stacked option arguments. */
#define STACKLST_OPT(n) (((tArgList*)(DESC(n).optCookie))->apzArgs)
/** Reset an option. */
#define    CLEAR_OPT(n) STMTS( \
                DESC(n).fOptState &= OPTST_PERSISTENT_MASK;   \
                if ((DESC(n).fOptState & OPTST_INITENABLED) == 0) \
                    DESC(n).fOptState |= OPTST_DISABLED; \
                DESC(n).optCookie = NULL )
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/**
 *  Enumeration of ocsptool exit codes
 */
typedef enum {
    OCSPTOOL_EXIT_SUCCESS         = 0,
    OCSPTOOL_EXIT_FAILURE         = 1,
    OCSPTOOL_EXIT_USAGE_ERROR     = 64,
    OCSPTOOL_EXIT_LIBOPTS_FAILURE = 70
}   ocsptool_exit_code_t;
/**
 *  Interface defines for specific options.
 * @{
 */
#define VALUE_OPT_DEBUG          'd'

#define OPT_VALUE_DEBUG          (DESC(DEBUG).optArg.argInt)
#define VALUE_OPT_VERBOSE        'V'
#define VALUE_OPT_INFILE         0x1001
#define VALUE_OPT_OUTFILE        0x1002
#define VALUE_OPT_ASK            0x1003
#define VALUE_OPT_VERIFY_RESPONSE 'e'
#define VALUE_OPT_REQUEST_INFO   'i'
#define VALUE_OPT_RESPONSE_INFO  'j'
#define VALUE_OPT_GENERATE_REQUEST 'q'
#define VALUE_OPT_NONCE          0x1004
#define VALUE_OPT_LOAD_ISSUER    0x1005
#define VALUE_OPT_LOAD_CERT      0x1006
#define VALUE_OPT_LOAD_TRUST     0x1007
#define VALUE_OPT_LOAD_SIGNER    0x1008
#define VALUE_OPT_INDER          0x1009
#define VALUE_OPT_LOAD_REQUEST   'Q'
#define VALUE_OPT_LOAD_RESPONSE  'S'
/** option flag (value) for " (get "val-name") " option */
#define VALUE_OPT_HELP          'h'
/** option flag (value) for " (get "val-name") " option */
#define VALUE_OPT_MORE_HELP     '!'
/** option flag (value) for " (get "val-name") " option */
#define VALUE_OPT_VERSION       'v'
/*
 *  Interface defines not associated with particular options
 */
#define ERRSKIP_OPTERR  STMTS(ocsptoolOptions.fOptSet &= ~OPTPROC_ERRSTOP)
#define ERRSTOP_OPTERR  STMTS(ocsptoolOptions.fOptSet |= OPTPROC_ERRSTOP)
#define RESTART_OPT(n)  STMTS( \
                ocsptoolOptions.curOptIdx = (n); \
                ocsptoolOptions.pzCurOpt  = NULL )
#define START_OPT       RESTART_OPT(1)
#define USAGE(c)        (*ocsptoolOptions.pUsageProc)(&ocsptoolOptions, c)

#ifdef  __cplusplus
extern "C" {
#endif
/*
 *  global exported definitions
 */
#include <gettext.h>


/* * * * * *
 *
 *  Declare the ocsptool option descriptor.
 */
extern tOptions ocsptoolOptions;

#if defined(ENABLE_NLS)
# ifndef _
#   include <stdio.h>
#   ifndef HAVE_GETTEXT
      extern char * gettext(char const *);
#   else
#     include <libintl.h>
#   endif

static inline char* aoGetsText(char const* pz) {
    if (pz == NULL) return NULL;
    return (char*)gettext(pz);
}
#   define _(s)  aoGetsText(s)
# endif /* _() */

# define OPT_NO_XLAT_CFG_NAMES  STMTS(ocsptoolOptions.fOptSet |= \
                                    OPTPROC_NXLAT_OPT_CFG;)
# define OPT_NO_XLAT_OPT_NAMES  STMTS(ocsptoolOptions.fOptSet |= \
                                    OPTPROC_NXLAT_OPT|OPTPROC_NXLAT_OPT_CFG;)

# define OPT_XLAT_CFG_NAMES     STMTS(ocsptoolOptions.fOptSet &= \
                                  ~(OPTPROC_NXLAT_OPT|OPTPROC_NXLAT_OPT_CFG);)
# define OPT_XLAT_OPT_NAMES     STMTS(ocsptoolOptions.fOptSet &= \
                                  ~OPTPROC_NXLAT_OPT;)

#else   /* ENABLE_NLS */
# define OPT_NO_XLAT_CFG_NAMES
# define OPT_NO_XLAT_OPT_NAMES

# define OPT_XLAT_CFG_NAMES
# define OPT_XLAT_OPT_NAMES

# ifndef _
#   define _(_s)  _s
# endif
#endif  /* ENABLE_NLS */

#ifdef  __cplusplus
}
#endif
#endif /* AUTOOPTS_OCSPTOOL_ARGS_H_GUARD */

/* ocsptool-args.h ends here */
