/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@FreeBSD.ORG> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/jail.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <grp.h>
#include <login_cap.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void	usage(void);

#define GET_USER_INFO do {						\
	pwd = getpwnam(username);					\
	if (pwd == NULL) {						\
		if (errno)						\
			err(1, "getpwnam: %s", username);		\
		else							\
			errx(1, "%s: no such user", username);		\
	}								\
	lcap = login_getpwclass(pwd);					\
	if (lcap == NULL)						\
		err(1, "getpwclass: %s", username);			\
	ngroups = NGROUPS;						\
	if (getgrouplist(username, pwd->pw_gid, groups, &ngroups) != 0)	\
		err(1, "getgrouplist: %s", username);			\
} while (0)

int
main(int argc, char **argv)
{
	login_cap_t *lcap;
	struct jail j;
	struct passwd *pwd;
	struct in_addr in;
	int ch, groups[NGROUPS], i, iflag, ngroups, uflag, Uflag;
	char path[PATH_MAX], *username;

	iflag = uflag = Uflag = 0;
	username = NULL;

	while ((ch = getopt(argc, argv, "iu:U:")) != -1) {
		switch (ch) {
		case 'i':
			iflag = 1;
			break;
		case 'u':
			username = optarg;
			uflag = 1;
			break;
		case 'U':
			username = optarg;
			Uflag = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 4)
		usage();
	if (uflag && Uflag)
		usage();
	if (uflag)
		GET_USER_INFO;
	if (realpath(argv[0], path) == NULL)
		err(1, "realpath: %s", argv[0]);
	if (chdir(path) != 0)
		err(1, "chdir: %s", path);
	memset(&j, 0, sizeof(j));
	j.version = 0;
	j.path = path;
	j.hostname = argv[1];
	if (inet_aton(argv[2], &in) == 0)
		errx(1, "Could not make sense of ip-number: %s", argv[2]);
	j.ip_number = ntohl(in.s_addr);
	i = jail(&j);
	if (i == -1)
		err(1, "jail");
	if (iflag) {
		printf("%d\n", i);
		fflush(stdout);
	}
	if (username != NULL) {
		if (Uflag)
			GET_USER_INFO;
		if (setgroups(ngroups, groups) != 0)
			err(1, "setgroups");
		if (setgid(pwd->pw_gid) != 0)
			err(1, "setgid");
		if (setusercontext(lcap, pwd, pwd->pw_uid,
		    LOGIN_SETALL & ~LOGIN_SETGROUP) != 0)
			err(1, "setusercontext");
		login_close(lcap);
	}
	if (execv(argv[3], argv + 3) != 0)
		err(1, "execv: %s", argv[3]);
	exit(0);
}

static void
usage(void)
{

	(void)fprintf(stderr, "%s%s\n",
	     "usage: jail [-i] [-u username | -U username]",
	     " path hostname ip-number command ...");
	exit(1);
}
