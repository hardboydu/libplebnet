/* opie.h: Data structures and values for the OPIE authentication
	system that a program might need.

%%% portions-copyright-cmetz-96
Portions of this software are Copyright 1996-1997 by Craig Metz, All Rights
Reserved. The Inner Net License Version 2 applies to these portions of
the software.
You should have received a copy of the license with this software. If
you didn't get a copy, you may request one from <license@inner.net>.

Portions of this software are Copyright 1995 by Randall Atkinson and Dan
McDonald, All Rights Reserved. All Rights under this copyright are assigned
to the U.S. Naval Research Laboratory (NRL). The NRL Copyright Notice and
License Agreement applies to this software.

	History:

	Modified by cmetz for OPIE 2.31. Removed active attack protection.
	Modified by cmetz for OPIE 2.3. Renamed PTR to VOIDPTR. Added
		re-init key and extension file fields to struct opie. Added
		opie_ prefix on struct opie members. Added opie_flags field
		and definitions. Added more prototypes. Changed opiehash()
		prototype.
	Modified by cmetz for OPIE 2.22. Define __P correctly if this file
		is included in a third-party program.
	Modified by cmetz for OPIE 2.2. Re-did prototypes. Added FUNCTION
                definition et al. Multiple-include protection. Added struct
		utsname fake. Got rid of gethostname() cruft. Moved UINT4
                here. Provide for *seek whence values. Move MDx context here
                and unify. Re-did prototypes.
	Modified at NRL for OPIE 2.0.
	Written at Bellcore for the S/Key Version 1 software distribution
		(skey.h).
*/
#ifndef _OPIE_H
#define _OPIE_H 1

struct opie {
  int opie_flags;
  char opie_buf[256];
  char *opie_principal;
  int opie_n;
  char *opie_seed;
  char *opie_val;
  long opie_recstart;
};

#define __OPIE_FLAGS_RW 1
#define __OPIE_FLAGS_READ 2

/* Minimum length of a secret password */
#define OPIE_SECRET_MIN 10

/* Maximum length of a secret password */
#define OPIE_SECRET_MAX 127

/* Minimum length of a seed */
#define OPIE_SEED_MIN 5

/* Maximum length of a seed */
#define OPIE_SEED_MAX 16

/* Maximum length of a challenge (otp-md? 9999 seed) */
#define OPIE_CHALLENGE_MAX (7+1+4+1+OPIE_SEED_MAX)

/* Maximum length of a response that we allow */
#define OPIE_RESPONSE_MAX (9+1+19+1+9+OPIE_SEED_MAX+1+19+1+19+1+19)

/* Maximum length of a principal (read: user name) */
#define OPIE_PRINCIPAL_MAX 32

#include <sys/cdefs.h>

__BEGIN_DECLS
int  opieaccessfile __P((char *));
int  rdnets __P((long));
int  isaddr __P((register char *));
int  opiealways __P((char *));
char *opieatob8 __P((char *,char *));
void opiebackspace __P((char *));
char *opiebtoa8 __P((char *,char *));
char *opiebtoe __P((char *,char *));
char *opiebtoh __P((char *,char *));
int  opieetob __P((char *,char *));
int  opiechallenge __P((struct opie *,char *,char *));
int  opiegenerator __P((char *,char *,char *));
int  opiegetsequence __P((struct opie *));
void opiehash __P((void *, unsigned));
int  opiehtoi __P((register char));
int  opiekeycrunch __P((int, char *, char *, char *));
int  opielock __P((char *));
int  opielookup __P((struct opie *,char *));
int  opiepasscheck __P((char *));
void opierandomchallenge __P((char *));
char * opieskipspace __P((register char *));
void opiestripcrlf __P((char *));
int  opieverify __P((struct opie *,char *));
int opiepasswd __P((struct opie *, int, char *, int, char *, char *));
char *opiereadpass __P((char *, int, int));
int opielogin __P((char *line, char *name, char *host));
__END_DECLS

#if _OPIE
#define VOIDPTR void *
#define VOIDRET void
#define NOARGS  void
#define FUNCTION(arglist, args) (args)
#define AND ,
#define FUNCTION_NOARGS ()
#define UINT4 u_int32_t

__BEGIN_DECLS
struct utmp;
int __opiegetutmpentry __P((char *, struct utmp *));
#ifdef EOF
FILE *__opieopen __P((char *, int, int));
#endif /* EOF */
int __opiereadrec __P((struct opie *));
int __opiewriterec __P((struct opie *));
__END_DECLS
#endif /* _OPIE */
#endif /* _OPIE_H */
