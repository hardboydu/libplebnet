/*
 * Copyright (c) 1988, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
static const char copyright[] =
"@(#) Copyright (c) 1988, 1993, 1994\n\
	The Regents of the University of California.  All rights reserved.\n";
#endif /* not lint */

#ifndef lint
/*
static char sccsid[] = "@(#)su.c	8.3 (Berkeley) 4/2/94";
*/
static const char rcsid[] =
	"$Id: su.c,v 1.18 1997/02/24 20:32:24 guido Exp $";
#endif /* not lint */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <err.h>
#include <errno.h>
#include <grp.h>
#include <paths.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#ifdef LOGIN_CAP
#include <login_cap.h>
#ifdef LOGIN_CAP_AUTH
#undef SKEY
#undef KERBEROS
#endif
#endif

#ifdef	SKEY
#include <skey.h>
#endif

#ifdef KERBEROS
#include <des.h>
#include <kerberosIV/krb.h>
#include <netdb.h>

#define	ARGSTR	"-Kflm"

static int kerberos(char *username, char *user, int uid, char *pword);
static int koktologin(char *name, char *toname);

int use_kerberos = 1;
#else /* !KERBEROS */
#define	ARGSTR	"-flm"
#endif /* KERBEROS */

char   *ontty __P((void));
int	chshell __P((char *));

int
main(argc, argv)
	int argc;
	char **argv;
{
	extern char **environ;
	struct passwd *pwd;
#ifdef WHEELSU
	char *targetpass;
	int iswheelsu;
#endif /* WHEELSU */
	char *p, **g, *user, *shell=NULL, *username, *cleanenv[20], **nargv, **np;
	struct group *gr;
	uid_t ruid;
	int asme, ch, asthem, fastlogin, prio, i;
	enum { UNSET, YES, NO } iscsh = UNSET;
#ifdef LOGIN_CAP
	login_cap_t *lc;
	int setwhat;
#ifdef LOGIN_CAP_AUTH
	char *style, *approvep, *auth_method = NULL;
#endif
#endif
	char shellbuf[MAXPATHLEN];

#ifdef WHEELSU
	iswheelsu =
#endif /* WHEELSU */
	asme = asthem = fastlogin = 0;
	user = "root";
	while(optind < argc)
	    if((ch = getopt(argc, argv, ARGSTR)) != -1)
		switch((char)ch) {
#ifdef KERBEROS
		case 'K':
			use_kerberos = 0;
			break;
#endif
		case 'f':
			fastlogin = 1;
			break;
		case '-':
		case 'l':
			asme = 0;
			asthem = 1;
			break;
		case 'm':
			asme = 1;
			asthem = 0;
			break;
		case '?':
		default:
			(void)fprintf(stderr, "usage: su [%s] [login]\n",
				      ARGSTR);
			exit(1);
		      }
	    else
	    {
		user = argv[optind++];
		break;
	    }

	if((nargv = malloc (sizeof (char *) * (argc + 4))) == NULL) {
	    errx(1, "malloc failure");
	}

	nargv[argc + 3] = NULL;
	for (i = argc; i >= optind; i--)
	    nargv[i + 3] = argv[i];
	np = &nargv[i + 3];

	argv += optind;

	errno = 0;
	prio = getpriority(PRIO_PROCESS, 0);
	if (errno)
		prio = 0;
	(void)setpriority(PRIO_PROCESS, 0, -2);
	openlog("su", LOG_CONS, 0);

	/* get current login name and shell */
	ruid = getuid();
	username = getlogin();
	if (username == NULL || (pwd = getpwnam(username)) == NULL ||
	    pwd->pw_uid != ruid)
		pwd = getpwuid(ruid);
	if (pwd == NULL)
		errx(1, "who are you?");
	username = strdup(pwd->pw_name);
	if (username == NULL)
		err(1, NULL);
	if (asme) {
		if (pwd->pw_shell != NULL && *pwd->pw_shell != '\0') {
			/* copy: pwd memory is recycled */
			shell = strncpy(shellbuf,  pwd->pw_shell, sizeof shellbuf);
			shellbuf[sizeof shellbuf - 1] = '\0';
		} else {
			shell = _PATH_BSHELL;
			iscsh = NO;
		}
	}

#ifdef LOGIN_CAP_AUTH
	if (auth_method = strchr(user, ':')) {
		*auth_method = '\0';
		auth_method++;
		if (*auth_method == '\0')
			auth_method = NULL;
	}
#endif /* !LOGIN_CAP_AUTH */

	/* get target login information, default to root */
	if ((pwd = getpwnam(user)) == NULL) {
		errx(1, "unknown login: %s", user);
	}
#ifdef LOGIN_CAP
	lc = login_getclass(pwd);
#endif

#ifdef WHEELSU
	targetpass = strdup(pwd->pw_passwd);
#endif /* WHEELSU */

	if (ruid) {
#ifdef KERBEROS
		if (use_kerberos && koktologin(username, user)
		    && !pwd->pw_uid) {
			warnx("kerberos: not in %s's ACL.", user);
			use_kerberos = 0;
		}
#endif
		{
			/* only allow those in group zero to su to root. */
			if (pwd->pw_uid == 0 && (gr = getgrgid((gid_t)0)) &&
			    gr->gr_mem && *(gr->gr_mem))
				for (g = gr->gr_mem;; ++g) {
					if (!*g)
						errx(1,
			    "you are not in the correct group to su %s.",
						    user);
					if (strcmp(username, *g) == 0) {
#ifdef WHEELSU
						iswheelsu = 1;
#endif /* WHEELSU */
						break;
					}
				}
		}
		/* if target requires a password, verify it */
		if (*pwd->pw_passwd) {
#ifdef LOGIN_CAP_AUTH
		/*
		 * This hands off authorisation to an authorisation program,
		 * depending on the styles available for the "auth-su",
		 * authorisation styles.
		 */
		if ((style = login_getstyle(lc, auth_method, "su")) == NULL)
			errx(1, "auth method available for su.\n");
		if (authenticate(user, lc ? lc->lc_class : "default", style, "su") != 0) {
#ifdef WHEELSU
			if (!iswheelsu || authenticate(username, lc ? lc->lc_class : "default", style, "su") != 0) {
#endif /* WHEELSU */
			{
			fprintf(stderr, "Sorry\n");
			syslog(LOG_AUTH|LOG_WARNING,"BAD SU %s to %s%s", username, user, ontty());
			exit(1);
			}
		}

		/*
		 * If authentication succeeds, run any approval
		 * program, if applicable for this class.
		 */
		approvep = login_getcapstr(lc, "approve", NULL, NULL);
		if (approvep==NULL || auth_script(approvep, approvep, username, lc->lc_class, 0) == 0) {
			int     r = auth_scan(AUTH_OKAY);
			/* See what the authorise program says */
			if (!(r & AUTH_ROOTOKAY) && pwd->pw_uid == 0) {
				fprintf(stderr, "Sorry\n");
				syslog(LOG_AUTH|LOG_WARNING,"UNAPPROVED ROOT SU %s%s", user, ontty());
				exit(1);
			}
		}
#else /* !LOGIN_CAP_AUTH */
#ifdef	SKEY
#ifdef WHEELSU
			if (iswheelsu) {
				pwd = getpwnam(username);
			}
#endif /* WHEELSU */
			p = skey_getpass("Password:", pwd, 1);
			if (!(!strcmp(pwd->pw_passwd, skey_crypt(p, pwd->pw_passwd, pwd, 1))
#ifdef WHEELSU
			      || (iswheelsu && !strcmp(targetpass, crypt(p,targetpass)))
#endif /* WHEELSU */
			      )) {
#else
			p = getpass("Password:");
			if (strcmp(pwd->pw_passwd, crypt(p, pwd->pw_passwd))) {
#endif
#ifdef KERBEROS
	    			if (!use_kerberos || (use_kerberos && kerberos(username, user, pwd->pw_uid, p)))
#endif
					{
					fprintf(stderr, "Sorry\n");
					syslog(LOG_AUTH|LOG_WARNING, "BAD SU %s to %s%s", username, user, ontty());
					exit(1);
				}
			}
#ifdef WHEELSU
			if (iswheelsu) {
				pwd = getpwnam(user);
			}
#endif /* WHEELSU */
#endif /* LOGIN_CAP_AUTH */
		}
		if (pwd->pw_expire && time(NULL) >= pwd->pw_expire) {
			fprintf(stderr, "Sorry - account expired\n");
			syslog(LOG_AUTH|LOG_WARNING,
				"BAD SU %s to %s%s", username,
				user, ontty());
			exit(1);
		}
	}

	if (asme) {
		/* if asme and non-standard target shell, must be root */
		if (!chshell(pwd->pw_shell) && ruid)
			errx(1, "permission denied (shell).");
	} else if (pwd->pw_shell && *pwd->pw_shell) {
		shell = pwd->pw_shell;
		iscsh = UNSET;
	} else {
		shell = _PATH_BSHELL;
		iscsh = NO;
	}

	/* if we're forking a csh, we want to slightly muck the args */
	if (iscsh == UNSET) {
		p = strrchr(shell, '/');
		if (p)
			++p;
		else
			p = shell;
		if ((iscsh = strcmp(p, "csh") ? NO : YES) == NO)
		    iscsh = strcmp(p, "tcsh") ? NO : YES;
	}

	(void)setpriority(PRIO_PROCESS, 0, prio);

#ifdef LOGIN_CAP
	/* Set everything now except the environment & umask */
	setwhat = LOGIN_SETUSER|LOGIN_SETGROUP|LOGIN_SETRESOURCES|LOGIN_SETPRIORITY;
	/*
	 * Don't touch resource/priority settings if -m has been
	 * used or -l hasn't, and we're not su'ing to root.
	 */
        if ((asme || !asthem) && pwd->pw_uid)
		setwhat &= ~(LOGIN_SETPRIORITY|LOGIN_SETRESOURCES);
	if (setusercontext(lc, pwd, pwd->pw_uid, setwhat) < 0)
		err(1, "setusercontext");
#else
	/* set permissions */
	if (setgid(pwd->pw_gid) < 0)
		err(1, "setgid");
	if (initgroups(user, pwd->pw_gid))
		errx(1, "initgroups failed");
	if (setuid(pwd->pw_uid) < 0)
		err(1, "setuid");
#endif

	if (!asme) {
		if (asthem) {
			p = getenv("TERM");
			cleanenv[0] = NULL;
			environ = cleanenv;
#ifdef LOGIN_CAP
			/* set the su'd user's environment & umask */
			setusercontext(lc, pwd, pwd->pw_uid, LOGIN_SETPATH|LOGIN_SETUMASK|LOGIN_SETENV);
#else
			(void)setenv("PATH", _PATH_DEFPATH, 1);
#endif
			if (p)
				(void)setenv("TERM", p, 1);
			if (chdir(pwd->pw_dir) < 0)
				errx(1, "no directory");
		}
		if (asthem || pwd->pw_uid)
			(void)setenv("USER", pwd->pw_name, 1);
		(void)setenv("HOME", pwd->pw_dir, 1);
		(void)setenv("SHELL", shell, 1);
	}
	if (iscsh == YES) {
		if (fastlogin)
			*np-- = "-f";
		if (asme)
			*np-- = "-m";
	}

	/* csh strips the first character... */
	*np = asthem ? "-su" : iscsh == YES ? "_su" : "su";

	if (ruid != 0)
		syslog(LOG_NOTICE|LOG_AUTH, "%s to %s%s",
		    username, user, ontty());

	login_close(lc);

	execv(shell, np);
	err(1, "%s", shell);
}

int
chshell(sh)
	char *sh;
{
	int  r = 0;
	char *cp;

	setusershell();
	while (!r && (cp = getusershell()) != NULL)
		r = strcmp(cp, sh) == 0;
	endusershell();
	return r;
}

char *
ontty()
{
	char *p;
	static char buf[MAXPATHLEN + 4];

	buf[0] = 0;
	p = ttyname(STDERR_FILENO);
	if (p)
		snprintf(buf, sizeof(buf), " on %s", p);
	return (buf);
}

#ifdef KERBEROS
int
kerberos(username, user, uid, pword)
	char *username, *user;
	int uid;
	char *pword;
{
	extern char *krb_err_txt[];
	KTEXT_ST ticket;
	AUTH_DAT authdata;
	int kerno;
	u_long faddr;
	struct sockaddr_in local_addr;
	char lrealm[REALM_SZ], krbtkfile[MAXPATHLEN];
	char hostname[MAXHOSTNAMELEN], savehost[MAXHOSTNAMELEN];
	char *krb_get_phost();

	if (krb_get_lrealm(lrealm, 1) != KSUCCESS)
		return (1);
	(void)sprintf(krbtkfile, "%s_%s_%lu", TKT_ROOT, user,
	    (unsigned long)getuid());

	(void)setenv("KRBTKFILE", krbtkfile, 1);
	(void)krb_set_tkt_string(krbtkfile);
	/*
	 * Set real as well as effective ID to 0 for the moment,
	 * to make the kerberos library do the right thing.
	 */
	if (setuid(0) < 0) {
		warn("setuid");
		return (1);
	}

	/*
	 * Little trick here -- if we are su'ing to root,
	 * we need to get a ticket for "xxx.root", where xxx represents
	 * the name of the person su'ing.  Otherwise (non-root case),
	 * we need to get a ticket for "yyy.", where yyy represents
	 * the name of the person being su'd to, and the instance is null
	 *
	 * We should have a way to set the ticket lifetime,
	 * with a system default for root.
	 */
	kerno = krb_get_pw_in_tkt((uid == 0 ? username : user),
		(uid == 0 ? "root" : ""), lrealm,
	    	"krbtgt", lrealm, DEFAULT_TKT_LIFE, pword);

	if (kerno != KSUCCESS) {
		if (kerno == KDC_PR_UNKNOWN) {
			warnx("kerberos: principal unknown: %s.%s@%s",
				(uid == 0 ? username : user),
				(uid == 0 ? "root" : ""), lrealm);
			return (1);
		}
		warnx("kerberos: unable to su: %s", krb_err_txt[kerno]);
		syslog(LOG_NOTICE|LOG_AUTH,
		    "BAD Kerberos SU: %s to %s%s: %s",
		    username, user, ontty(), krb_err_txt[kerno]);
		return (1);
	}

	if (chown(krbtkfile, uid, -1) < 0) {
		warn("chown");
		(void)unlink(krbtkfile);
		return (1);
	}

	(void)setpriority(PRIO_PROCESS, 0, -2);

	if (gethostname(hostname, sizeof(hostname)) == -1) {
		warn("gethostname");
		dest_tkt();
		return (1);
	}

	(void)strncpy(savehost, krb_get_phost(hostname), sizeof(savehost));
	savehost[sizeof(savehost) - 1] = '\0';

	kerno = krb_mk_req(&ticket, "rcmd", savehost, lrealm, 33);

	if (kerno == KDC_PR_UNKNOWN) {
		warnx("Warning: TGT not verified.");
		syslog(LOG_NOTICE|LOG_AUTH,
		    "%s to %s%s, TGT not verified (%s); %s.%s not registered?",
		    username, user, ontty(), krb_err_txt[kerno],
		    "rcmd", savehost);
	} else if (kerno != KSUCCESS) {
		warnx("Unable to use TGT: %s", krb_err_txt[kerno]);
		syslog(LOG_NOTICE|LOG_AUTH, "failed su: %s to %s%s: %s",
		    username, user, ontty(), krb_err_txt[kerno]);
		dest_tkt();
		return (1);
	} else {
		if ((kerno = krb_get_local_addr(&local_addr)) != KSUCCESS) {
			warnx("Unable to get our local address: %s",
			      krb_err_txt[kerno]);
			dest_tkt();
			return (1);
		}
		faddr = local_addr.sin_addr.s_addr;
		if ((kerno = krb_rd_req(&ticket, "rcmd", savehost, faddr,
		    &authdata, "")) != KSUCCESS) {
			warnx("kerberos: unable to verify rcmd ticket: %s\n",
			    krb_err_txt[kerno]);
			syslog(LOG_NOTICE|LOG_AUTH,
			    "failed su: %s to %s%s: %s", username,
			     user, ontty(), krb_err_txt[kerno]);
			dest_tkt();
			return (1);
		}
	}
	return (0);
}

int
koktologin(name, toname)
	char *name, *toname;
{
	AUTH_DAT *kdata;
	AUTH_DAT kdata_st;
	char realm[REALM_SZ];

	if (krb_get_lrealm(realm, 1) != KSUCCESS)
		return (1);
	kdata = &kdata_st;
	memset((char *)kdata, 0, sizeof(*kdata));
	(void)strncpy(kdata->pname, name, sizeof kdata->pname - 1);
	(void)strncpy(kdata->pinst,
	    ((strcmp(toname, "root") == 0) ? "root" : ""), sizeof kdata->pinst - 1);
	(void)strncpy(kdata->prealm, realm, sizeof kdata->prealm - 1);
	return (kuserok(kdata, toname));
}
#endif
