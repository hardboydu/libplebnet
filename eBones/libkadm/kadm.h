/*
 * $Source: /usr/cvs/src/eBones/libkadm/kadm.h,v $
 * $Author: mark $
 * Header: /afs/athena.mit.edu/astaff/project/kerberos/src/include/RCS/kadm.h,v 4.2 89/09/26 09:15:20 jtkohl Exp
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * Copyright.MIT.
 *
 * Definitions for Kerberos administration server & client
 */

#ifndef KADM_DEFS
#define KADM_DEFS

/*
 * kadm.h
 * Header file for the fourth attempt at an admin server
 * Doug Church, December 28, 1989, MIT Project Athena
 */

/* for those broken Unixes without this defined... should be in sys/param.h */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <krb.h>
#include <krb_db.h>
#include <des.h>

/* The global structures for the client and server */
typedef struct {
  struct sockaddr_in admin_addr;
  struct sockaddr_in my_addr;
  int my_addr_len;
  int admin_fd;			/* file descriptor for link to admin server */
  char sname[ANAME_SZ];		/* the service name */
  char sinst[INST_SZ];		/* the services instance */
  char krbrlm[REALM_SZ];
} Kadm_Client;

typedef struct {		/* status of the server, i.e the parameters */
   int inter;			/* Space for command line flags */
   char *sysfile;		/* filename of server */
} admin_params;			/* Well... it's the admin's parameters */

/* Largest password length to be supported */
#define MAX_KPW_LEN	128

/* Largest packet the admin server will ever allow itself to return */
#define KADM_RET_MAX 2048

/* That's right, versions are 8 byte strings */
#define KADM_VERSTR	"KADM0.0A"
#define KADM_ULOSE	"KYOULOSE"	/* sent back when server can't
					   decrypt client's msg */
#define KADM_VERSIZE strlen(KADM_VERSTR)

/* the lookups for the server instances */
#define PWSERV_NAME  "changepw"
#define KADM_SNAME   "kerberos_master"
#define KADM_SINST   "kerberos"

/* Attributes fields constants and macros */
#define ALLOC        2
#define RESERVED     3
#define DEALLOC      4
#define DEACTIVATED  5
#define ACTIVE       6

/* Kadm_vals structure for passing db fields into the server routines */
#define FLDSZ        4

typedef struct {
    u_char         fields[FLDSZ];     /* The active fields in this struct */
    char           name[ANAME_SZ];
    char           instance[INST_SZ];
    unsigned long  key_low;
    unsigned long  key_high;
    unsigned long  exp_date;
    unsigned short attributes;
    unsigned char  max_life;
} Kadm_vals;                    /* The basic values structure in Kadm */

/* Kadm_vals structure for passing db fields into the server routines */
#define FLDSZ        4

/* Need to define fields types here */
#define KADM_NAME       31
#define KADM_INST       30
#define KADM_EXPDATE    29
#define KADM_ATTR       28
#define KADM_MAXLIFE    27
#define KADM_DESKEY     26

/* To set a field entry f in a fields structure d */
#define SET_FIELD(f,d)  (d[3-(f/8)]|=(1<<(f%8)))

/* To set a field entry f in a fields structure d */
#define CLEAR_FIELD(f,d)  (d[3-(f/8)]&=(~(1<<(f%8))))

/* Is field f in fields structure d */
#define IS_FIELD(f,d)   (d[3-(f/8)]&(1<<(f%8)))

/* Various return codes */
#define KADM_SUCCESS    0

#define WILDCARD_STR "*"

enum acl_types {
ADDACL,
GETACL,
MODACL
};

/* Various opcodes for the admin server's functions */
#define CHANGE_PW    2
#define ADD_ENT      3
#define MOD_ENT      4
#define GET_ENT      5

/* XXX This doesn't belong here!!! */
#ifdef POSIX
typedef void sigtype;
#else
typedef int sigtype;
#endif

int vals_to_stream(Kadm_vals *dt_in, u_char **dt_out);
int stream_to_vals(u_char *dt_in, Kadm_vals *dt_out, int maxlen);

int build_field_header(u_char *cont, u_char **st);
int check_field_header(u_char *st, u_char *cont, int maxlen);

int stv_string(u_char *st, char *dat, int loc, int stlen, int maxlen);
int stv_short(u_char *st, u_short *dat, int loc, int maxlen);
int stv_long(u_char *st, u_long *dat, int loc, int maxlen);
int stv_char(u_char *st, u_char *dat, int loc, int maxlen);

int vts_string(char *dat, u_char **st, int loc);
int vts_short(u_short dat, u_char **st, int loc);
int vts_long(u_long dat, u_char **st, int loc);
int vts_char(u_char dat, u_char **st, int loc);

int kadm_cli_conn(void);
void kadm_cli_disconn(void);
int kadm_cli_send(u_char *st_dat, int st_siz, u_char **ret_dat, int *ret_siz);
int kadm_cli_out(u_char *dat, int dat_len, u_char **ret_dat, int *ret_siz);
int kadm_cli_keyd(des_cblock s_k, des_key_schedule s_s);

int kadm_get(Kadm_vals *vals, u_char fl[4]);
int kadm_mod(Kadm_vals *vals1, Kadm_vals *vals2);
int kadm_add(Kadm_vals *vals);
int kadm_change_pw(des_cblock newkey);
int kadm_init_link(char n[], char i[], char r[]);
void prin_vals(Kadm_vals *vals);
void kadm_vals_to_prin(u_char fields[FLDSZ], Principal *new, Kadm_vals *old);
void kadm_prin_to_vals(u_char fields[FLDSZ], Kadm_vals *new, Principal *old);

#endif KADM_DEFS
