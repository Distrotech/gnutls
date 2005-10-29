
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 119 "cli.gaa"
	char *rest_args;
#line 110 "cli.gaa"
	int insecure;
#line 107 "cli.gaa"
	char *psk_key;
#line 104 "cli.gaa"
	char *psk_username;
#line 101 "cli.gaa"
	char *srp_passwd;
#line 98 "cli.gaa"
	char *srp_username;
#line 95 "cli.gaa"
	char *x509_certfile;
#line 92 "cli.gaa"
	char *x509_keyfile;
#line 89 "cli.gaa"
	char *pgp_certfile;
#line 86 "cli.gaa"
	char *pgp_trustdb;
#line 83 "cli.gaa"
	char *pgp_keyring;
#line 80 "cli.gaa"
	char *pgp_keyfile;
#line 77 "cli.gaa"
	char *x509_crlfile;
#line 74 "cli.gaa"
	char *x509_cafile;
#line 71 "cli.gaa"
	char **ctype;
#line 70 "cli.gaa"
	int nctype;
#line 67 "cli.gaa"
	char **kx;
#line 66 "cli.gaa"
	int nkx;
#line 63 "cli.gaa"
	char **macs;
#line 62 "cli.gaa"
	int nmacs;
#line 59 "cli.gaa"
	char **comp;
#line 58 "cli.gaa"
	int ncomp;
#line 55 "cli.gaa"
	char **proto;
#line 54 "cli.gaa"
	int nproto;
#line 51 "cli.gaa"
	char **ciphers;
#line 50 "cli.gaa"
	int nciphers;
#line 47 "cli.gaa"
	int verbose;
#line 44 "cli.gaa"
	int record_size;
#line 41 "cli.gaa"
	int port;
#line 38 "cli.gaa"
	int print_cert;
#line 35 "cli.gaa"
	int xml;
#line 32 "cli.gaa"
	int disable_extensions;
#line 29 "cli.gaa"
	int fingerprint;
#line 26 "cli.gaa"
	int fmtder;
#line 23 "cli.gaa"
	int crlf;
#line 20 "cli.gaa"
	int starttls;
#line 17 "cli.gaa"
	int resume;
#line 14 "cli.gaa"
	int debug;

#line 114 "gaa.skel"
};

#ifdef __cplusplus
extern "C"
{
#endif

    int gaa(int argc, char *argv[], gaainfo *gaaval);

    void gaa_help(void);
    
    int gaa_file(const char *name, gaainfo *gaaval);
    
#ifdef __cplusplus
}
#endif


#endif
