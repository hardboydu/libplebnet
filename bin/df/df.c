/*
 * Copyright (c) 1980, 1990, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#if 0
#ifndef lint
static const char copyright[] =
"@(#) Copyright (c) 1980, 1990, 1993, 1994\n\
	The Regents of the University of California.  All rights reserved.\n";
#endif /* not lint */

#ifndef lint
static char sccsid[] = "@(#)df.c	8.9 (Berkeley) 5/8/95";
#endif /* not lint */
#endif
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <ufs/ufs/ufsmount.h>
#include <err.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "extern.h"

#define UNITS_SI 1
#define UNITS_2 2

#define KILO_SZ(n) (n)
#define MEGA_SZ(n) ((n) * (n))
#define GIGA_SZ(n) ((n) * (n) * (n))
#define TERA_SZ(n) ((n) * (n) * (n) * (n))
#define PETA_SZ(n) ((n) * (n) * (n) * (n) * (n))

#define KILO_2_SZ (KILO_SZ(1024ULL))
#define MEGA_2_SZ (MEGA_SZ(1024ULL))
#define GIGA_2_SZ (GIGA_SZ(1024ULL))
#define TERA_2_SZ (TERA_SZ(1024ULL))
#define PETA_2_SZ (PETA_SZ(1024ULL))

#define KILO_SI_SZ (KILO_SZ(1000ULL))
#define MEGA_SI_SZ (MEGA_SZ(1000ULL))
#define GIGA_SI_SZ (GIGA_SZ(1000ULL))
#define TERA_SI_SZ (TERA_SZ(1000ULL))
#define PETA_SI_SZ (PETA_SZ(1000ULL))

/* Maximum widths of various fields. */
struct maxwidths {
	int	mntfrom;
	int	total;
	int	used;
	int	avail;
	int	iused;
	int	ifree;
};

static uintmax_t vals_si [] = {
	1,
	KILO_SI_SZ,
	MEGA_SI_SZ,
	GIGA_SI_SZ,
	TERA_SI_SZ,
	PETA_SI_SZ
};
static uintmax_t vals_base2[] = {
	1,
	KILO_2_SZ,
	MEGA_2_SZ,
	GIGA_2_SZ,
	TERA_2_SZ,
	PETA_2_SZ
};
static uintmax_t *valp;

typedef enum { NONE, KILO, MEGA, GIGA, TERA, PETA, UNIT_MAX } unit_t;

static unit_t unitp [] = { NONE, KILO, MEGA, GIGA, TERA, PETA };

static char	 *getmntpt(const char *);
static int	  int64width(int64_t);
static char	 *makenetvfslist(void);
static void	  prthuman(const struct statfs *, int64_t);
static void	  prthumanval(double);
static void	  prtstat(struct statfs *, struct maxwidths *);
static void	  addstat(struct statfs *, struct statfs *);
static size_t	  regetmntinfo(struct statfs **, long, const char **);
static unit_t	  unit_adjust(double *);
static void	  update_maxwidths(struct maxwidths *, const struct statfs *);
static void	  usage(void);

static __inline int
imax(int a, int b)
{
	return (a > b ? a : b);
}

static int	aflag = 0, cflag, hflag, iflag, nflag;
static struct	ufs_args mdev;

int
main(int argc, char *argv[])
{
	struct stat stbuf;
	struct statfs statfsbuf, totalbuf, *mntbuf;
	struct maxwidths maxwidths;
	const char *fstype;
	char *mntpath, *mntpt;
	const char **vfslist;
	size_t i, mntsize;
	int ch, rv;

	fstype = "ufs";

	memset (&totalbuf, 0, sizeof (totalbuf));
	totalbuf.f_bsize = DEV_BSIZE;
	strncpy (totalbuf.f_mntfromname, "total", MNAMELEN);
	vfslist = NULL;
	while ((ch = getopt(argc, argv, "abcgHhiklmnPt:")) != -1)
		switch (ch) {
		case 'a':
			aflag = 1;
			break;
		case 'c':
			cflag = 1;
			break;
		case 'b':
				/* FALLTHROUGH */
		case 'P':
			putenv("BLOCKSIZE=512");
			hflag = 0;
			break;
		case 'g':
			putenv("BLOCKSIZE=1g");
			hflag = 0;
			break;
		case 'H':
			hflag = UNITS_SI;
			valp = vals_si;
			break;
		case 'h':
			hflag = UNITS_2;
			valp = vals_base2;
			break;
		case 'i':
			iflag = 1;
			break;
		case 'k':
			putenv("BLOCKSIZE=1k");
			hflag = 0;
			break;
		case 'l':
			if (vfslist != NULL)
				errx(1, "-l and -t are mutually exclusive.");
			vfslist = makevfslist(makenetvfslist());
			break;
		case 'm':
			putenv("BLOCKSIZE=1m");
			hflag = 0;
			break;
		case 'n':
			nflag = 1;
			break;
		case 't':
			if (vfslist != NULL)
				errx(1, "only one -t option may be specified");
			fstype = optarg;
			vfslist = makevfslist(optarg);
			break;
		case '?':
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	mntsize = getmntinfo(&mntbuf, MNT_NOWAIT);
	bzero(&maxwidths, sizeof(maxwidths));
	for (i = 0; i < mntsize; i++)
		update_maxwidths(&maxwidths, &mntbuf[i]);

	rv = 0;
	if (!*argv) {
		mntsize = regetmntinfo(&mntbuf, mntsize, vfslist);
		bzero(&maxwidths, sizeof(maxwidths));
		for (i = 0; i < mntsize; i++) {
			if (cflag)
				addstat(&totalbuf, &mntbuf[i]);
			update_maxwidths(&maxwidths, &mntbuf[i]);
		}
		if (cflag)
			update_maxwidths(&maxwidths, &totalbuf);
		for (i = 0; i < mntsize; i++)
			if (aflag || (mntbuf[i].f_flags & MNT_IGNORE) == 0)
				prtstat(&mntbuf[i], &maxwidths);
		if (cflag)
			prtstat(&totalbuf, &maxwidths);
		exit(rv);
	}

	for (; *argv; argv++) {
		if (stat(*argv, &stbuf) < 0) {
			if ((mntpt = getmntpt(*argv)) == 0) {
				warn("%s", *argv);
				rv = 1;
				continue;
			}
		} else if (S_ISCHR(stbuf.st_mode)) {
			if ((mntpt = getmntpt(*argv)) == 0) {
				mdev.fspec = *argv;
				mntpath = strdup("/tmp/df.XXXXXX");
				if (mntpath == NULL) {
					warn("strdup failed");
					rv = 1;
					continue;
				}
				mntpt = mkdtemp(mntpath);
				if (mntpt == NULL) {
					warn("mkdtemp(\"%s\") failed", mntpath);
					rv = 1;
					free(mntpath);
					continue;
				}
				if (mount(fstype, mntpt, MNT_RDONLY,
				    &mdev) != 0) {
					warn("%s", *argv);
					rv = 1;
					(void)rmdir(mntpt);
					free(mntpath);
					continue;
				} else if (statfs(mntpt, &statfsbuf) == 0) {
					statfsbuf.f_mntonname[0] = '\0';
					prtstat(&statfsbuf, &maxwidths);
					if (cflag)
						addstat(&totalbuf, &statfsbuf);
				} else {
					warn("%s", *argv);
					rv = 1;
				}
				(void)unmount(mntpt, 0);
				(void)rmdir(mntpt);
				free(mntpath);
				continue;
			}
		} else
			mntpt = *argv;

		/*
		 * Statfs does not take a `wait' flag, so we cannot
		 * implement nflag here.
		 */
		if (statfs(mntpt, &statfsbuf) < 0) {
			warn("%s", mntpt);
			rv = 1;
			continue;
		}

		/*
		 * Check to make sure the arguments we've been given are
		 * satisfied.  Return an error if we have been asked to
		 * list a mount point that does not match the other args
		 * we've been given (-l, -t, etc.).
		 */
		if (checkvfsname(statfsbuf.f_fstypename, vfslist)) {
			rv = 1;
			continue;
		}

		if (argc == 1) {
			bzero(&maxwidths, sizeof(maxwidths));
			update_maxwidths(&maxwidths, &statfsbuf);
		}
		prtstat(&statfsbuf, &maxwidths);
		if (cflag)
			addstat(&totalbuf, &statfsbuf);
	}
	if (cflag)
		prtstat(&totalbuf, &maxwidths);
	return (rv);
}

static char *
getmntpt(const char *name)
{
	size_t mntsize, i;
	struct statfs *mntbuf;

	mntsize = getmntinfo(&mntbuf, MNT_NOWAIT);
	for (i = 0; i < mntsize; i++) {
		if (!strcmp(mntbuf[i].f_mntfromname, name))
			return (mntbuf[i].f_mntonname);
	}
	return (0);
}

/*
 * Make a pass over the file system info in ``mntbuf'' filtering out
 * file system types not in vfslist and possibly re-stating to get
 * current (not cached) info.  Returns the new count of valid statfs bufs.
 */
static size_t
regetmntinfo(struct statfs **mntbufp, long mntsize, const char **vfslist)
{
	int i, j;
	struct statfs *mntbuf;

	if (vfslist == NULL)
		return (nflag ? mntsize : getmntinfo(mntbufp, MNT_WAIT));

	mntbuf = *mntbufp;
	for (j = 0, i = 0; i < mntsize; i++) {
		if (checkvfsname(mntbuf[i].f_fstypename, vfslist))
			continue;
		if (!nflag)
			(void)statfs(mntbuf[i].f_mntonname,&mntbuf[j]);
		else if (i != j)
			mntbuf[j] = mntbuf[i];
		j++;
	}
	return (j);
}

/*
 * Output in "human-readable" format.  Uses 3 digits max and puts
 * unit suffixes at the end.  Makes output compact and easy to read,
 * especially on huge disks.
 *
 */
static unit_t
unit_adjust(double *val)
{
	double abval;
	unit_t unit;
	int unit_sz;

	abval = fabs(*val);

	unit_sz = abval ? ilogb(abval) / 10 : 0;

	if (unit_sz >= (int)UNIT_MAX) {
		unit = NONE;
	} else {
		unit = unitp[unit_sz];
		*val /= (double)valp[unit_sz];
	}

	return (unit);
}

static void
prthuman(const struct statfs *sfsp, int64_t used)
{

	prthumanval((double)sfsp->f_blocks * (double)sfsp->f_bsize);
	prthumanval((double)used * (double)sfsp->f_bsize);
	prthumanval((double)sfsp->f_bavail * (double)sfsp->f_bsize);
}

static void
prthumanval(double bytes)
{

	unit_t unit;
	unit = unit_adjust(&bytes);

	if (bytes == 0)
		(void)printf("      0B");
	else if (bytes > 10)
		(void)printf(" % 6.0f%c", bytes, "BKMGTPE"[unit]);
	else
		(void)printf(" % 6.1f%c", bytes, "BKMGTPE"[unit]);
}

/*
 * Convert statfs returned file system size into BLOCKSIZE units.
 * Attempts to avoid overflow for large file systems.
 */
#define fsbtoblk(num, fsbs, bs) \
	(((fsbs) != 0 && (fsbs) < (bs)) ? \
		(num) / (intmax_t)((bs) / (fsbs)) : \
		(num) * (intmax_t)((fsbs) / (bs)))

/*
 * Print out status about a file system.
 */
static void
prtstat(struct statfs *sfsp, struct maxwidths *mwp)
{
	static u_long blocksize;
	static int headerlen, timesthrough = 0;
	static const char *header;
	int64_t used, availblks, inodes;
	int total;

	if (++timesthrough == 1) {
		mwp->mntfrom = imax(mwp->mntfrom, (int)strlen("Filesystem"));
		if (hflag) {
			header = "   Size";
			mwp->total = mwp->used = mwp->avail =
			    (int)strlen(header);
		} else {
			header = getbsize(&headerlen, &blocksize);
			mwp->total = imax(mwp->total, headerlen);
		}
		mwp->used = imax(mwp->used, (int)strlen("Used"));
		mwp->avail = imax(mwp->avail, (int)strlen("Avail"));

		(void)printf("%-*s %-*s %*s %*s Capacity",
		    mwp->mntfrom, "Filesystem", mwp->total, header,
		    mwp->used, "Used", mwp->avail, "Avail");
		if (iflag) {
			mwp->iused = imax(mwp->iused, (int)strlen("  iused"));
			mwp->ifree = imax(mwp->ifree, (int)strlen("ifree"));
			(void)printf(" %*s %*s %%iused",
			    mwp->iused - 2, "iused", mwp->ifree, "ifree");
		}
		(void)printf("  Mounted on\n");
	}
	(void)printf("%-*s", mwp->mntfrom, sfsp->f_mntfromname);
	used = sfsp->f_blocks - sfsp->f_bfree;
	availblks = sfsp->f_bavail + used;
	if (hflag) {
		prthuman(sfsp, used);
	} else {
		(void)printf(" %*jd %*jd %*jd",
		    mwp->total, (intmax_t)fsbtoblk(sfsp->f_blocks,
		    sfsp->f_bsize, blocksize),
		    mwp->used, (intmax_t)fsbtoblk(used, sfsp->f_bsize,
		    blocksize),
		    mwp->avail, (intmax_t)fsbtoblk(sfsp->f_bavail,
		    sfsp->f_bsize, blocksize));
	}
	(void)printf(" %5.0f%%",
	    availblks == 0 ? 100.0 : (double)used / (double)availblks * 100.0);
	total = !*sfsp->f_mntonname &&
	    strncmp(sfsp->f_mntfromname, "total", MNAMELEN) == 0;
	if (iflag) {
		inodes = sfsp->f_files;
		used = inodes - sfsp->f_ffree;
		(void)printf(" %*jd %*jd %4.0f%% ", mwp->iused, (intmax_t)used,
		    mwp->ifree, (intmax_t)sfsp->f_ffree, inodes == 0 ? 100.0 :
		    (double)used / (double)inodes * 100.0);
	} else
		(void)printf("  ");
	if (!total)
		(void)printf("  %s", sfsp->f_mntonname);
	(void)printf("\n");
}

void
addstat(struct statfs *totalfsp, struct statfs *statfsp)
{
	double bsize = statfsp->f_bsize / totalfsp->f_bsize;

	totalfsp->f_blocks += statfsp->f_blocks * bsize;
	totalfsp->f_bfree += statfsp->f_bfree * bsize;
	totalfsp->f_bavail += statfsp->f_bavail * bsize;
	totalfsp->f_files += statfsp->f_files;
	totalfsp->f_ffree += statfsp->f_ffree;
}

/*
 * Update the maximum field-width information in `mwp' based on
 * the file system specified by `sfsp'.
 */
static void
update_maxwidths(struct maxwidths *mwp, const struct statfs *sfsp)
{
	static u_long blocksize = 0;
	int dummy;

	if (blocksize == 0)
		getbsize(&dummy, &blocksize);

	mwp->mntfrom = imax(mwp->mntfrom, (int)strlen(sfsp->f_mntfromname));
	mwp->total = imax(mwp->total, int64width(
	    fsbtoblk((int64_t)sfsp->f_blocks, sfsp->f_bsize, blocksize)));
	mwp->used = imax(mwp->used,
	    int64width(fsbtoblk((int64_t)sfsp->f_blocks -
	    (int64_t)sfsp->f_bfree, sfsp->f_bsize, blocksize)));
	mwp->avail = imax(mwp->avail, int64width(fsbtoblk(sfsp->f_bavail,
	    sfsp->f_bsize, blocksize)));
	mwp->iused = imax(mwp->iused, int64width((int64_t)sfsp->f_files -
	    sfsp->f_ffree));
	mwp->ifree = imax(mwp->ifree, int64width(sfsp->f_ffree));
}

/* Return the width in characters of the specified value. */
static int
int64width(int64_t val)
{
	int len;

	len = 0;
	/* Negative or zero values require one extra digit. */
	if (val <= 0) {
		val = -val;
		len++;
	}
	while (val > 0) {
		len++;
		val /= 10;
	}

	return (len);
}

static void
usage(void)
{

	(void)fprintf(stderr,
	    "usage: df [-b | -H | -h | -k | -m | -P] [-aciln] [-t type] [file | filesystem ...]\n");
	exit(EX_USAGE);
}

static char *
makenetvfslist(void)
{
	char *str, *strptr, **listptr;
	struct xvfsconf *xvfsp, *keep_xvfsp;
	size_t buflen;
	int cnt, i, maxvfsconf;

	if (sysctlbyname("vfs.conflist", NULL, &buflen, NULL, 0) < 0) {
		warn("sysctl(vfs.conflist)");
		return (NULL);
	}
	xvfsp = malloc(buflen);
	if (xvfsp == NULL) {
		warnx("malloc failed");
		return (NULL);
	}
	keep_xvfsp = xvfsp;
	if (sysctlbyname("vfs.conflist", xvfsp, &buflen, NULL, 0) < 0) {
		warn("sysctl(vfs.conflist)");
		free(keep_xvfsp);
		return (NULL);
	}
	maxvfsconf = buflen / sizeof(struct xvfsconf);

	if ((listptr = malloc(sizeof(char*) * maxvfsconf)) == NULL) {
		warnx("malloc failed");
		free(keep_xvfsp);
		return (NULL);
	}

	for (cnt = 0, i = 0; i < maxvfsconf; i++) {
		if (xvfsp->vfc_flags & VFCF_NETWORK) {
			listptr[cnt++] = strdup(xvfsp->vfc_name);
			if (listptr[cnt-1] == NULL) {
				warnx("malloc failed");
				free(listptr);
				free(keep_xvfsp);
				return (NULL);
			}
		}
		xvfsp++;
	}

	if (cnt == 0 ||
	    (str = malloc(sizeof(char) * (32 * cnt + cnt + 2))) == NULL) {
		if (cnt > 0)
			warnx("malloc failed");
		free(listptr);
		free(keep_xvfsp);
		return (NULL);
	}

	*str = 'n'; *(str + 1) = 'o';
	for (i = 0, strptr = str + 2; i < cnt; i++, strptr++) {
		strncpy(strptr, listptr[i], 32);
		strptr += strlen(listptr[i]);
		*strptr = ',';
		free(listptr[i]);
	}
	*(--strptr) = '\0';

	free(keep_xvfsp);
	free(listptr);
	return (str);
}
