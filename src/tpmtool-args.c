/*   -*- buffer-read-only: t -*- vi: set ro:
 *  
 *  DO NOT EDIT THIS FILE   (tpmtool-args.c)
 *  
 *  It has been AutoGen-ed  July 20, 2012 at 10:21:17 PM by AutoGen 5.16
 *  From the definitions    tpmtool-args.def
 *  and the template file   options
 *
 * Generated from AutoOpts 36:4:11 templates.
 *
 *  AutoOpts is a copyrighted work.  This source file is not encumbered
 *  by AutoOpts licensing, but is provided under the licensing terms chosen
 *  by the tpmtool author or copyright holder.  AutoOpts is
 *  licensed under the terms of the LGPL.  The redistributable library
 *  (``libopts'') is licensed under the terms of either the LGPL or, at the
 *  users discretion, the BSD license.  See the AutoOpts and/or libopts sources
 *  for details.
 *
 * The tpmtool program is copyrighted and licensed
 * under the following terms:
 *
 *  Copyright (C) 2000-2012 Free Software Foundation, all rights reserved.
 *  This is free software. It is licensed for use, modification and
 *  redistribution under the terms of the
 *  GNU General Public License, version 3 or later
 *      <http://gnu.org/licenses/gpl.html>
 *
 *  tpmtool is free software: you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  tpmtool is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License along
 *  with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __doxygen__
#define OPTION_CODE_COMPILE 1
#include "tpmtool-args.h"
#include <sys/types.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#ifdef  __cplusplus
extern "C" {
#endif
extern FILE * option_usage_fp;

/* TRANSLATORS: choose the translation for option names wisely because you
                cannot ever change your mind. */
#define zCopyright      (tpmtool_opt_strs+0)
#define zLicenseDescrip (tpmtool_opt_strs+278)


#ifndef NULL
#  define NULL 0
#endif

/*
 *  tpmtool option static const strings
 */
static char const tpmtool_opt_strs[2031] =
/*     0 */ "tpmtool @VERSION@\n"
            "Copyright (C) 2000-2012 Free Software Foundation, all rights reserved.\n"
            "This is free software. It is licensed for use, modification and\n"
            "redistribution under the terms of the\n"
            "GNU General Public License, version 3 or later\n"
            "    <http://gnu.org/licenses/gpl.html>\n\0"
/*   278 */ "tpmtool is free software: you can redistribute it and/or modify it under\n"
            "the terms of the GNU General Public License as published by the Free\n"
            "Software Foundation, either version 3 of the License, or (at your option)\n"
            "any later version.\n\n"
            "tpmtool is distributed in the hope that it will be useful, but WITHOUT ANY\n"
            "WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS\n"
            "FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more\n"
            "details.\n\n"
            "You should have received a copy of the GNU General Public License along\n"
            "with this program.  If not, see <http://www.gnu.org/licenses/>.\n\0"
/*   881 */ "Enable debugging.\0"
/*   899 */ "DEBUG\0"
/*   905 */ "debug\0"
/*   911 */ "Input file\0"
/*   922 */ "INFILE\0"
/*   929 */ "infile\0"
/*   936 */ "Output file\0"
/*   948 */ "OUTFILE\0"
/*   956 */ "outfile\0"
/*   964 */ "Generate an RSA private-public key pair\0"
/*  1004 */ "GENERATE_RSA\0"
/*  1017 */ "generate-rsa\0"
/*  1030 */ "Any generated key will be registered in the TPM\0"
/*  1078 */ "REGISTER\0"
/*  1087 */ "register\0"
/*  1096 */ "Any generated key will be a signing key\0"
/*  1136 */ "SIGNING\0"
/*  1144 */ "signing\0"
/*  1152 */ "Any generated key will be a legacy key\0"
/*  1191 */ "LEGACY\0"
/*  1198 */ "legacy\0"
/*  1205 */ "Any registered key will be a user key\0"
/*  1243 */ "USER\0"
/*  1248 */ "user\0"
/*  1253 */ "Any registred key will be a system key\0"
/*  1292 */ "SYSTEM\0"
/*  1299 */ "system\0"
/*  1306 */ "Prints the public key of the provided key\0"
/*  1348 */ "PUBKEY\0"
/*  1355 */ "pubkey\0"
/*  1362 */ "Lists all stored keys in the TPM\0"
/*  1395 */ "LIST\0"
/*  1400 */ "list\0"
/*  1405 */ "Delete the key identified by the given URL (UUID).\0"
/*  1456 */ "DELETE\0"
/*  1463 */ "delete\0"
/*  1470 */ "Specify the security level [low, legacy, normal, high, ultra].\0"
/*  1533 */ "SEC_PARAM\0"
/*  1543 */ "sec-param\0"
/*  1553 */ "Specify the number of bits for key generate\0"
/*  1597 */ "BITS\0"
/*  1602 */ "bits\0"
/*  1607 */ "Display extended usage information and exit\0"
/*  1651 */ "help\0"
/*  1656 */ "Extended usage information passed thru pager\0"
/*  1701 */ "more-help\0"
/*  1711 */ "Output version information and exit\0"
/*  1747 */ "version\0"
/*  1755 */ "TPMTOOL\0"
/*  1763 */ "tpmtool - GnuTLS TPM tool - Ver. @VERSION@\n"
            "USAGE:  %s [ -<flag> [<val>] | --<name>[{=| }<val>] ]...\n\0"
/*  1864 */ "bug-gnutls@gnu.org\0"
/*  1883 */ "\n\n\0"
/*  1886 */ "\n"
            "Program that allows handling cryptographic data from the TPM chip.\n\0"
/*  1955 */ "tpmtool @VERSION@\0"
/*  1973 */ "tpmtool [options]\n"
            "tpmtool --help for usage instructions.\n";

/*
 *  debug option description:
 */
#define DEBUG_DESC      (tpmtool_opt_strs+881)
#define DEBUG_NAME      (tpmtool_opt_strs+899)
#define DEBUG_name      (tpmtool_opt_strs+905)
#define DEBUG_FLAGS     (OPTST_DISABLED \
        | OPTST_SET_ARGTYPE(OPARG_TYPE_NUMERIC))

/*
 *  infile option description:
 */
#define INFILE_DESC      (tpmtool_opt_strs+911)
#define INFILE_NAME      (tpmtool_opt_strs+922)
#define INFILE_name      (tpmtool_opt_strs+929)
#define INFILE_FLAGS     (OPTST_DISABLED \
        | OPTST_SET_ARGTYPE(OPARG_TYPE_FILE))

/*
 *  outfile option description:
 */
#define OUTFILE_DESC      (tpmtool_opt_strs+936)
#define OUTFILE_NAME      (tpmtool_opt_strs+948)
#define OUTFILE_name      (tpmtool_opt_strs+956)
#define OUTFILE_FLAGS     (OPTST_DISABLED \
        | OPTST_SET_ARGTYPE(OPARG_TYPE_STRING))

/*
 *  generate-rsa option description:
 */
#define GENERATE_RSA_DESC      (tpmtool_opt_strs+964)
#define GENERATE_RSA_NAME      (tpmtool_opt_strs+1004)
#define GENERATE_RSA_name      (tpmtool_opt_strs+1017)
#define GENERATE_RSA_FLAGS     (OPTST_DISABLED)

/*
 *  register option description with
 *  "Must also have options" and "Incompatible options":
 */
#define REGISTER_DESC      (tpmtool_opt_strs+1030)
#define REGISTER_NAME      (tpmtool_opt_strs+1078)
#define REGISTER_name      (tpmtool_opt_strs+1087)
static int const aRegisterMustList[] = {
    INDEX_OPT_GENERATE_RSA, NO_EQUIVALENT };
#define REGISTER_FLAGS     (OPTST_DISABLED)

/*
 *  signing option description with
 *  "Must also have options" and "Incompatible options":
 */
#define SIGNING_DESC      (tpmtool_opt_strs+1096)
#define SIGNING_NAME      (tpmtool_opt_strs+1136)
#define SIGNING_name      (tpmtool_opt_strs+1144)
static int const aSigningMustList[] = {
    INDEX_OPT_GENERATE_RSA, NO_EQUIVALENT };
static int const aSigningCantList[] = {
    INDEX_OPT_LEGACY, NO_EQUIVALENT };
#define SIGNING_FLAGS     (OPTST_DISABLED)

/*
 *  legacy option description with
 *  "Must also have options" and "Incompatible options":
 */
#define LEGACY_DESC      (tpmtool_opt_strs+1152)
#define LEGACY_NAME      (tpmtool_opt_strs+1191)
#define LEGACY_name      (tpmtool_opt_strs+1198)
static int const aLegacyMustList[] = {
    INDEX_OPT_GENERATE_RSA, NO_EQUIVALENT };
static int const aLegacyCantList[] = {
    INDEX_OPT_SIGNING, NO_EQUIVALENT };
#define LEGACY_FLAGS     (OPTST_DISABLED)

/*
 *  user option description with
 *  "Must also have options" and "Incompatible options":
 */
#define USER_DESC      (tpmtool_opt_strs+1205)
#define USER_NAME      (tpmtool_opt_strs+1243)
#define USER_name      (tpmtool_opt_strs+1248)
static int const aUserMustList[] = {
    INDEX_OPT_REGISTER, NO_EQUIVALENT };
static int const aUserCantList[] = {
    INDEX_OPT_SYSTEM, NO_EQUIVALENT };
#define USER_FLAGS     (OPTST_DISABLED)

/*
 *  system option description with
 *  "Must also have options" and "Incompatible options":
 */
#define SYSTEM_DESC      (tpmtool_opt_strs+1253)
#define SYSTEM_NAME      (tpmtool_opt_strs+1292)
#define SYSTEM_name      (tpmtool_opt_strs+1299)
static int const aSystemMustList[] = {
    INDEX_OPT_REGISTER, NO_EQUIVALENT };
static int const aSystemCantList[] = {
    INDEX_OPT_USER, NO_EQUIVALENT };
#define SYSTEM_FLAGS     (OPTST_DISABLED)

/*
 *  pubkey option description:
 */
#define PUBKEY_DESC      (tpmtool_opt_strs+1306)
#define PUBKEY_NAME      (tpmtool_opt_strs+1348)
#define PUBKEY_name      (tpmtool_opt_strs+1355)
#define PUBKEY_FLAGS     (OPTST_DISABLED \
        | OPTST_SET_ARGTYPE(OPARG_TYPE_STRING))

/*
 *  list option description:
 */
#define LIST_DESC      (tpmtool_opt_strs+1362)
#define LIST_NAME      (tpmtool_opt_strs+1395)
#define LIST_name      (tpmtool_opt_strs+1400)
#define LIST_FLAGS     (OPTST_DISABLED)

/*
 *  delete option description:
 */
#define DELETE_DESC      (tpmtool_opt_strs+1405)
#define DELETE_NAME      (tpmtool_opt_strs+1456)
#define DELETE_name      (tpmtool_opt_strs+1463)
#define DELETE_FLAGS     (OPTST_DISABLED \
        | OPTST_SET_ARGTYPE(OPARG_TYPE_STRING))

/*
 *  sec-param option description:
 */
#define SEC_PARAM_DESC      (tpmtool_opt_strs+1470)
#define SEC_PARAM_NAME      (tpmtool_opt_strs+1533)
#define SEC_PARAM_name      (tpmtool_opt_strs+1543)
#define SEC_PARAM_FLAGS     (OPTST_DISABLED \
        | OPTST_SET_ARGTYPE(OPARG_TYPE_STRING))

/*
 *  bits option description:
 */
#define BITS_DESC      (tpmtool_opt_strs+1553)
#define BITS_NAME      (tpmtool_opt_strs+1597)
#define BITS_name      (tpmtool_opt_strs+1602)
#define BITS_FLAGS     (OPTST_DISABLED \
        | OPTST_SET_ARGTYPE(OPARG_TYPE_NUMERIC))

/*
 *  Help/More_Help/Version option descriptions:
 */
#define HELP_DESC       (tpmtool_opt_strs+1607)
#define HELP_name       (tpmtool_opt_strs+1651)
#ifdef HAVE_WORKING_FORK
#define MORE_HELP_DESC  (tpmtool_opt_strs+1656)
#define MORE_HELP_name  (tpmtool_opt_strs+1701)
#define MORE_HELP_FLAGS (OPTST_IMM | OPTST_NO_INIT)
#else
#define MORE_HELP_DESC  NULL
#define MORE_HELP_name  NULL
#define MORE_HELP_FLAGS (OPTST_OMITTED | OPTST_NO_INIT)
#endif
#ifdef NO_OPTIONAL_OPT_ARGS
#  define VER_FLAGS     (OPTST_IMM | OPTST_NO_INIT)
#else
#  define VER_FLAGS     (OPTST_SET_ARGTYPE(OPARG_TYPE_STRING) | \
                         OPTST_ARG_OPTIONAL | OPTST_IMM | OPTST_NO_INIT)
#endif
#define VER_DESC        (tpmtool_opt_strs+1711)
#define VER_name        (tpmtool_opt_strs+1747)
/*
 *  Declare option callback procedures
 */
extern tOptProc
    optionBooleanVal,   optionNestedVal,    optionNumericVal,
    optionPagedUsage,   optionPrintVersion, optionResetOpt,
    optionStackArg,     optionTimeDate,     optionTimeVal,
    optionUnstackArg,   optionVendorOption;
static tOptProc
    doOptDebug, doOptInfile, doUsageOpt;
#define VER_PROC        optionPrintVersion

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/**
 *  Define the tpmtool Option Descriptions.
 * This is an array of OPTION_CT entries, one for each
 * option that the tpmtool program responds to.
 */
static tOptDesc optDesc[OPTION_CT] = {
  {  /* entry idx, value */ 0, VALUE_OPT_DEBUG,
     /* equiv idx, value */ 0, VALUE_OPT_DEBUG,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ DEBUG_FLAGS, 0,
     /* last opt argumnt */ { NULL }, /* --debug */
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ NULL, NULL,
     /* option proc      */ doOptDebug,
     /* desc, NAME, name */ DEBUG_DESC, DEBUG_NAME, DEBUG_name,
     /* disablement strs */ NULL, NULL },

  {  /* entry idx, value */ 1, VALUE_OPT_INFILE,
     /* equiv idx, value */ 1, VALUE_OPT_INFILE,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ INFILE_FLAGS, 0,
     /* last opt argumnt */ { NULL }, /* --infile */
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ NULL, NULL,
     /* option proc      */ doOptInfile,
     /* desc, NAME, name */ INFILE_DESC, INFILE_NAME, INFILE_name,
     /* disablement strs */ NULL, NULL },

  {  /* entry idx, value */ 2, VALUE_OPT_OUTFILE,
     /* equiv idx, value */ 2, VALUE_OPT_OUTFILE,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ OUTFILE_FLAGS, 0,
     /* last opt argumnt */ { NULL }, /* --outfile */
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ NULL, NULL,
     /* option proc      */ NULL,
     /* desc, NAME, name */ OUTFILE_DESC, OUTFILE_NAME, OUTFILE_name,
     /* disablement strs */ NULL, NULL },

  {  /* entry idx, value */ 3, VALUE_OPT_GENERATE_RSA,
     /* equiv idx, value */ 3, VALUE_OPT_GENERATE_RSA,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ GENERATE_RSA_FLAGS, 0,
     /* last opt argumnt */ { NULL }, /* --generate-rsa */
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ NULL, NULL,
     /* option proc      */ NULL,
     /* desc, NAME, name */ GENERATE_RSA_DESC, GENERATE_RSA_NAME, GENERATE_RSA_name,
     /* disablement strs */ NULL, NULL },

  {  /* entry idx, value */ 4, VALUE_OPT_REGISTER,
     /* equiv idx, value */ 4, VALUE_OPT_REGISTER,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ REGISTER_FLAGS, 0,
     /* last opt argumnt */ { NULL }, /* --register */
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ aRegisterMustList, NULL,
     /* option proc      */ NULL,
     /* desc, NAME, name */ REGISTER_DESC, REGISTER_NAME, REGISTER_name,
     /* disablement strs */ NULL, NULL },

  {  /* entry idx, value */ 5, VALUE_OPT_SIGNING,
     /* equiv idx, value */ 5, VALUE_OPT_SIGNING,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ SIGNING_FLAGS, 0,
     /* last opt argumnt */ { NULL }, /* --signing */
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ aSigningMustList, aSigningCantList,
     /* option proc      */ NULL,
     /* desc, NAME, name */ SIGNING_DESC, SIGNING_NAME, SIGNING_name,
     /* disablement strs */ NULL, NULL },

  {  /* entry idx, value */ 6, VALUE_OPT_LEGACY,
     /* equiv idx, value */ 6, VALUE_OPT_LEGACY,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ LEGACY_FLAGS, 0,
     /* last opt argumnt */ { NULL }, /* --legacy */
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ aLegacyMustList, aLegacyCantList,
     /* option proc      */ NULL,
     /* desc, NAME, name */ LEGACY_DESC, LEGACY_NAME, LEGACY_name,
     /* disablement strs */ NULL, NULL },

  {  /* entry idx, value */ 7, VALUE_OPT_USER,
     /* equiv idx, value */ 7, VALUE_OPT_USER,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ USER_FLAGS, 0,
     /* last opt argumnt */ { NULL }, /* --user */
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ aUserMustList, aUserCantList,
     /* option proc      */ NULL,
     /* desc, NAME, name */ USER_DESC, USER_NAME, USER_name,
     /* disablement strs */ NULL, NULL },

  {  /* entry idx, value */ 8, VALUE_OPT_SYSTEM,
     /* equiv idx, value */ 8, VALUE_OPT_SYSTEM,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ SYSTEM_FLAGS, 0,
     /* last opt argumnt */ { NULL }, /* --system */
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ aSystemMustList, aSystemCantList,
     /* option proc      */ NULL,
     /* desc, NAME, name */ SYSTEM_DESC, SYSTEM_NAME, SYSTEM_name,
     /* disablement strs */ NULL, NULL },

  {  /* entry idx, value */ 9, VALUE_OPT_PUBKEY,
     /* equiv idx, value */ 9, VALUE_OPT_PUBKEY,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ PUBKEY_FLAGS, 0,
     /* last opt argumnt */ { NULL }, /* --pubkey */
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ NULL, NULL,
     /* option proc      */ NULL,
     /* desc, NAME, name */ PUBKEY_DESC, PUBKEY_NAME, PUBKEY_name,
     /* disablement strs */ NULL, NULL },

  {  /* entry idx, value */ 10, VALUE_OPT_LIST,
     /* equiv idx, value */ 10, VALUE_OPT_LIST,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ LIST_FLAGS, 0,
     /* last opt argumnt */ { NULL }, /* --list */
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ NULL, NULL,
     /* option proc      */ NULL,
     /* desc, NAME, name */ LIST_DESC, LIST_NAME, LIST_name,
     /* disablement strs */ NULL, NULL },

  {  /* entry idx, value */ 11, VALUE_OPT_DELETE,
     /* equiv idx, value */ 11, VALUE_OPT_DELETE,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ DELETE_FLAGS, 0,
     /* last opt argumnt */ { NULL }, /* --delete */
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ NULL, NULL,
     /* option proc      */ NULL,
     /* desc, NAME, name */ DELETE_DESC, DELETE_NAME, DELETE_name,
     /* disablement strs */ NULL, NULL },

  {  /* entry idx, value */ 12, VALUE_OPT_SEC_PARAM,
     /* equiv idx, value */ 12, VALUE_OPT_SEC_PARAM,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ SEC_PARAM_FLAGS, 0,
     /* last opt argumnt */ { NULL }, /* --sec-param */
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ NULL, NULL,
     /* option proc      */ NULL,
     /* desc, NAME, name */ SEC_PARAM_DESC, SEC_PARAM_NAME, SEC_PARAM_name,
     /* disablement strs */ NULL, NULL },

  {  /* entry idx, value */ 13, VALUE_OPT_BITS,
     /* equiv idx, value */ 13, VALUE_OPT_BITS,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ BITS_FLAGS, 0,
     /* last opt argumnt */ { NULL }, /* --bits */
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ NULL, NULL,
     /* option proc      */ optionNumericVal,
     /* desc, NAME, name */ BITS_DESC, BITS_NAME, BITS_name,
     /* disablement strs */ NULL, NULL },

  {  /* entry idx, value */ INDEX_OPT_VERSION, VALUE_OPT_VERSION,
     /* equiv idx value  */ NO_EQUIVALENT, VALUE_OPT_VERSION,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ VER_FLAGS, 0,
     /* last opt argumnt */ { NULL },
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ NULL, NULL,
     /* option proc      */ VER_PROC,
     /* desc, NAME, name */ VER_DESC, NULL, VER_name,
     /* disablement strs */ NULL, NULL },



  {  /* entry idx, value */ INDEX_OPT_HELP, VALUE_OPT_HELP,
     /* equiv idx value  */ NO_EQUIVALENT, VALUE_OPT_HELP,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ OPTST_IMM | OPTST_NO_INIT, 0,
     /* last opt argumnt */ { NULL },
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ NULL, NULL,
     /* option proc      */ doUsageOpt,
     /* desc, NAME, name */ HELP_DESC, NULL, HELP_name,
     /* disablement strs */ NULL, NULL },

  {  /* entry idx, value */ INDEX_OPT_MORE_HELP, VALUE_OPT_MORE_HELP,
     /* equiv idx value  */ NO_EQUIVALENT, VALUE_OPT_MORE_HELP,
     /* equivalenced to  */ NO_EQUIVALENT,
     /* min, max, act ct */ 0, 1, 0,
     /* opt state flags  */ MORE_HELP_FLAGS, 0,
     /* last opt argumnt */ { NULL },
     /* arg list/cookie  */ NULL,
     /* must/cannot opts */ NULL,  NULL,
     /* option proc      */ optionPagedUsage,
     /* desc, NAME, name */ MORE_HELP_DESC, NULL, MORE_HELP_name,
     /* disablement strs */ NULL, NULL }
};


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  Define the tpmtool Option Environment
 */
#define zPROGNAME       (tpmtool_opt_strs+1755)
#define zUsageTitle     (tpmtool_opt_strs+1763)
#define zRcName         NULL
#define apzHomeList     NULL
#define zBugsAddr       (tpmtool_opt_strs+1864)
#define zExplain        (tpmtool_opt_strs+1883)
#define zDetail         (tpmtool_opt_strs+1886)
#define zFullVersion    (tpmtool_opt_strs+1955)
/* extracted from optcode.tlib near line 350 */

#if defined(ENABLE_NLS)
# define OPTPROC_BASE OPTPROC_TRANSLATE | OPTPROC_NXLAT_OPT
  static tOptionXlateProc translate_option_strings;
#else
# define OPTPROC_BASE OPTPROC_NONE
# define translate_option_strings NULL
#endif /* ENABLE_NLS */


#define tpmtool_full_usage (NULL)

#define tpmtool_short_usage (tpmtool_opt_strs+1973)

#endif /* not defined __doxygen__ */

/*
 *  Create the static procedure(s) declared above.
 */
/**
 * The callout function that invokes the optionUsage function.
 *
 * @param pOptions the AutoOpts option description structure
 * @param pOptDesc the descriptor for the "help" (usage) option.
 * @noreturn
 */
static void
doUsageOpt(tOptions * pOptions, tOptDesc * pOptDesc)
{
    optionUsage(&tpmtoolOptions, TPMTOOL_EXIT_SUCCESS);
    /* NOTREACHED */
    (void)pOptDesc;
    (void)pOptions;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/**
 * Code to handle the debug option.
 *
 * @param pOptions the tpmtool options data structure
 * @param pOptDesc the option descriptor for this option.
 */
static void
doOptDebug(tOptions* pOptions, tOptDesc* pOptDesc)
{
    static struct {long rmin, rmax;} const rng[1] = {
        { 0 ,  9999 } };
    int  ix;

    if (pOptions <= OPTPROC_EMIT_LIMIT)
        goto emit_ranges;
    optionNumericVal(pOptions, pOptDesc);

    for (ix = 0; ix < 1; ix++) {
        if (pOptDesc->optArg.argInt < rng[ix].rmin)
            continue;  /* ranges need not be ordered. */
        if (pOptDesc->optArg.argInt == rng[ix].rmin)
            return;
        if (rng[ix].rmax == LONG_MIN)
            continue;
        if (pOptDesc->optArg.argInt <= rng[ix].rmax)
            return;
    }

    option_usage_fp = stderr;

emit_ranges:

    optionShowRange(pOptions, pOptDesc, (void *)rng, 1);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/**
 * Code to handle the infile option.
 *
 * @param pOptions the tpmtool options data structure
 * @param pOptDesc the option descriptor for this option.
 */
static void
doOptInfile(tOptions* pOptions, tOptDesc* pOptDesc)
{
    static teOptFileType const  type =
        FTYPE_MODE_MUST_EXIST + FTYPE_MODE_NO_OPEN;
    static tuFileMode           mode;
#ifndef O_CLOEXEC
#  define O_CLOEXEC 0
#endif
    mode.file_flags = O_CLOEXEC;

    optionFileCheck(pOptions, pOptDesc, type, mode);
}
/* extracted from optmain.tlib near line 1113 */

/**
 * The directory containing the data associated with tpmtool.
 */
#ifndef  PKGDATADIR
# define PKGDATADIR ""
#endif

/**
 * Information about the person or institution that packaged tpmtool
 * for the current distribution.
 */
#ifndef  WITH_PACKAGER
# define tpmtool_packager_info NULL
#else
static char const tpmtool_packager_info[] =
    "Packaged by " WITH_PACKAGER

# ifdef WITH_PACKAGER_VERSION
        " ("WITH_PACKAGER_VERSION")"
# endif

# ifdef WITH_PACKAGER_BUG_REPORTS
    "\nReport tpmtool bugs to " WITH_PACKAGER_BUG_REPORTS
# endif
    "\n";
#endif
#ifndef __doxygen__

#endif /* __doxygen__ */
/**
 * The option definitions for tpmtool.  The one structure that
 * binds them all.
 */
tOptions tpmtoolOptions = {
    OPTIONS_STRUCT_VERSION,
    0, NULL,                    /* original argc + argv    */
    ( OPTPROC_BASE
    + OPTPROC_ERRSTOP
    + OPTPROC_SHORTOPT
    + OPTPROC_LONGOPT
    + OPTPROC_NO_REQ_OPT
    + OPTPROC_NO_ARGS
    + OPTPROC_GNUUSAGE
    + OPTPROC_MISUSE ),
    0, NULL,                    /* current option index, current option */
    NULL,         NULL,         zPROGNAME,
    zRcName,      zCopyright,   zLicenseDescrip,
    zFullVersion, apzHomeList,  zUsageTitle,
    zExplain,     zDetail,      optDesc,
    zBugsAddr,                  /* address to send bugs to */
    NULL, NULL,                 /* extensions/saved state  */
    optionUsage, /* usage procedure */
    translate_option_strings,   /* translation procedure */
    /*
     *  Indexes to special options
     */
    { INDEX_OPT_MORE_HELP, /* more-help option index */
      NO_EQUIVALENT, /* save option index */
      NO_EQUIVALENT, /* '-#' option index */
      NO_EQUIVALENT /* index of default opt */
    },
    17 /* full option count */, 14 /* user option count */,
    tpmtool_full_usage, tpmtool_short_usage,
    NULL, NULL,
    PKGDATADIR, tpmtool_packager_info
};

#if ENABLE_NLS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <autoopts/usage-txt.h>

static char* AO_gettext(char const* pz);
static void  coerce_it(void** s);

/**
 * AutoGen specific wrapper function for gettext.
 * It relies on the macro _() to convert from English to the target
 * language, then strdup-duplicates the result string.
 *
 * @param[in] pz the input text used as a lookup key.
 * @returns the translated text (if there is one),
 *   or the original text (if not).
 */
static char *
AO_gettext(char const* pz)
{
    char* pzRes;
    if (pz == NULL)
        return NULL;
    pzRes = _(pz);
    if (pzRes == pz)
        return pzRes;
    pzRes = strdup(pzRes);
    if (pzRes == NULL) {
        fputs(_("No memory for duping translated strings\n"), stderr);
        exit(TPMTOOL_EXIT_FAILURE);
    }
    return pzRes;
}

static void coerce_it(void** s) { *s = AO_gettext(*s);
}

/**
 * Translate all the translatable strings in the tpmtoolOptions
 * structure defined above.  This is done only once.
 */
static void
translate_option_strings(void)
{
    tOptions * const pOpt = &tpmtoolOptions;

    /*
     *  Guard against re-translation.  It won't work.  The strings will have
     *  been changed by the first pass through this code.  One shot only.
     */
    if (option_usage_text.field_ct != 0) {
        /*
         *  Do the translations.  The first pointer follows the field count
         *  field.  The field count field is the size of a pointer.
         */
        tOptDesc * pOD = pOpt->pOptDesc;
        char **    ppz = (char**)(void*)&(option_usage_text);
        int        ix  = option_usage_text.field_ct;

        do {
            ppz++;
            *ppz = AO_gettext(*ppz);
        } while (--ix > 0);

        coerce_it((void*)&(pOpt->pzCopyright));
        coerce_it((void*)&(pOpt->pzCopyNotice));
        coerce_it((void*)&(pOpt->pzFullVersion));
        coerce_it((void*)&(pOpt->pzUsageTitle));
        coerce_it((void*)&(pOpt->pzExplain));
        coerce_it((void*)&(pOpt->pzDetail));
        coerce_it((void*)&(pOpt->pzPackager));
        coerce_it((void*)&(pOpt->pzShortUsage));
        option_usage_text.field_ct = 0;

        for (ix = pOpt->optCt; ix > 0; ix--, pOD++)
            coerce_it((void*)&(pOD->pzText));
    }

    if ((pOpt->fOptSet & OPTPROC_NXLAT_OPT_CFG) == 0) {
        tOptDesc * pOD = pOpt->pOptDesc;
        int        ix;

        for (ix = pOpt->optCt; ix > 0; ix--, pOD++) {
            coerce_it((void*)&(pOD->pz_Name));
            coerce_it((void*)&(pOD->pz_DisableName));
            coerce_it((void*)&(pOD->pz_DisablePfx));
        }
        /* prevent re-translation */
        tpmtoolOptions.fOptSet |= OPTPROC_NXLAT_OPT_CFG | OPTPROC_NXLAT_OPT;
    }
}

#endif /* ENABLE_NLS */

#ifdef  __cplusplus
}
#endif
/* tpmtool-args.c ends here */
