/*
 * Copyright (c) 1983, 1993
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
"@(#) Copyright (c) 1983, 1993\n\
	The Regents of the University of California.  All rights reserved.\n";
#endif /* not lint */

#ifndef lint
#if 0
static char sccsid[] = "@(#)tunefs.c	8.2 (Berkeley) 4/19/94";
#endif
static const char rcsid[] =
  "$FreeBSD$";
#endif /* not lint */

/*
 * tunefs: change layout parameters to an existing file system.
 */
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <ufs/ffs/fs.h>
#include <ufs/ufs/ufsmount.h>

#include <err.h>
#include <fcntl.h>
#include <fstab.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* the optimization warning string template */
#define	OPTWARN	"should optimize for %s with minfree %s %d%%"

union {
	struct	fs sb;
	char pad[MAXBSIZE];
} sbun;
#define	sblock sbun.sb

int fi;
long dev_bsize = 1;

void bwrite __P((daddr_t, const char *, int));
int bread __P((daddr_t, char *, int));
void getsb __P((struct fs *, const char *));
void putsb __P((struct fs *, const char *, int));
void usage __P((void));
void printfs __P((void));

int
main(argc, argv)
	int argc;
	char *argv[];
{
	char *special;
	const char *name;
	struct stat st;
	int Aflag = 0, active = 0;
	int aflag = 0, dflag = 0, eflag = 0, fflag = 0, mflag = 0;
	int nflag = 0, oflag = 0, pflag = 0, sflag = 0;
	int avalue = 0, dvalue = 0, evalue = 0, fvalue = 0;
	int mvalue = 0, ovalue = 0, svalue = 0;
	char *nvalue = NULL; 
	struct fstab *fs;
	const char *chg[2];
	char device[MAXPATHLEN];
	struct ufs_args args;
	struct statfs stfs;
	int found_arg, ch;

        if (argc < 3)
                usage();
	found_arg = 0; /* at least one arg is required */
	while ((ch = getopt(argc, argv, "Aa:d:e:f:m:n:o:ps:")) != -1)
	  switch (ch) {
	  case 'A':
		found_arg = 1;
		Aflag++;
		break;
	  case 'a':
		found_arg = 1;
		name = "maximum contiguous block count";
		avalue = atoi(optarg);
		if (avalue < 1)
			errx(10, "%s must be >= 1 (was %s)", name, optarg);
		aflag = 1;
		break;
	  case 'd':
		found_arg = 1;
		name = "rotational delay between contiguous blocks";
		dvalue = atoi(optarg);
		dflag = 1;
		break;
	  case 'e':
		found_arg = 1;
		name = "maximum blocks per file in a cylinder group";
		evalue = atoi(optarg);
		if (evalue < 1)
			errx(10, "%s must be >= 1 (was %s)", name, optarg);
		eflag = 1;
		break;
	  case 'f':
		found_arg = 1;
		name = "average file size";
		fvalue = atoi(optarg);
		if (fvalue < 1)
			errx(10, "%s must be >= 1 (was %s)", name, optarg);
		fflag = 1;
		break;
	  case 'm':
		found_arg = 1;
		name = "minimum percentage of free space";
		mvalue = atoi(optarg);
		if (mvalue < 0 || mvalue > 99)
			errx(10, "bad %s (%s)", name, optarg);
		mflag = 1;
		break;
	  case 'n':
		found_arg = 1;
 		name = "soft updates";
 		nvalue = optarg;
                if (strcmp(nvalue, "enable") && strcmp(nvalue, "disable")) {
 			errx(10, "bad %s (options are %s)",
 			    name, "`enable' or `disable'");
 		}
		nflag = 1;
 		break;
	  case 'o':
		found_arg = 1;
		name = "optimization preference";
		chg[FS_OPTSPACE] = "space";
		chg[FS_OPTTIME] = "time";
		if (strcmp(optarg, chg[FS_OPTSPACE]) == 0)
			ovalue = FS_OPTSPACE;
		else if (strcmp(optarg, chg[FS_OPTTIME]) == 0)
			ovalue = FS_OPTTIME;
		else
			errx(10, "bad %s (options are `space' or `time')",
					    name);
		oflag = 1;
		break;
	  case 'p':
		found_arg = 1;
		pflag = 1;
		break;
	  case 's':
		found_arg = 1;
		name = "expected number of files per directory";
		svalue = atoi(optarg);
		if (svalue < 1)
			errx(10, "%s must be >= 1 (was %s)", name, optarg);
		sflag = 1;
		break;
	  default:
		usage();
	  }
	argc -= optind;
	argv += optind;

	if (found_arg == 0 || argc != 1)
	  usage();

	special = argv[0];
	fs = getfsfile(special);
	if (fs) {
		if (statfs(special, &stfs) == 0 &&
		    strcmp(special, stfs.f_mntonname) == 0) {
			active = 1;
		}
		special = fs->fs_spec;
	}
again:
	if (stat(special, &st) < 0) {
		if (*special != '/') {
			if (*special == 'r')
				special++;
			(void)snprintf(device, sizeof(device), "%s/%s",
				       _PATH_DEV, special);
			special = device;
			goto again;
		}
		err(1, "%s", special);
	}
	if ((st.st_mode & S_IFMT) != S_IFBLK &&
	    (st.st_mode & S_IFMT) != S_IFCHR)
		errx(10, "%s: not a block or character device", special);
	getsb(&sblock, special);

	if (pflag) {
		printfs();
		exit(0);
	}
	if (aflag) {
		name = "maximum contiguous block count";
		if (sblock.fs_maxcontig == avalue) {
			warnx("%s remains unchanged as %d", name, avalue);
		}
		else {
			warnx("%s changes from %d to %d",
					name, sblock.fs_maxcontig, avalue);
			sblock.fs_maxcontig = avalue;
		}
	}
	if (dflag) {
		name = "rotational delay between contiguous blocks";
		if (sblock.fs_rotdelay == dvalue) {
			warnx("%s remains unchanged as %dms", name, dvalue);
		}
		else {
			warnx("%s changes from %dms to %dms",
				    name, sblock.fs_rotdelay, dvalue);
			sblock.fs_rotdelay = dvalue;
		}
	}
	if (eflag) {
		name = "maximum blocks per file in a cylinder group";
		if (sblock.fs_maxbpg == evalue) {
			warnx("%s remains unchanged as %d", name, evalue);
		}
		else {
			warnx("%s changes from %d to %d",
					name, sblock.fs_maxbpg, evalue);
			sblock.fs_maxbpg = evalue;
		}
	}
	if (fflag) {
		name = "average file size";
		if (sblock.fs_avgfilesize == fvalue) {
			warnx("%s remains unchanged as %d", name, fvalue);
		}
		else {
			warnx("%s changes from %d to %d",
					name, sblock.fs_avgfilesize, fvalue);
			sblock.fs_avgfilesize = fvalue;
		}
	}
	if (mflag) {
		name = "minimum percentage of free space";
		if (sblock.fs_minfree == mvalue) {
			warnx("%s remains unchanged as %d%%", name, mvalue);
		}
		else {
			warnx("%s changes from %d%% to %d%%",
				    name, sblock.fs_minfree, mvalue);
			sblock.fs_minfree = mvalue;
			if (mvalue >= MINFREE && sblock.fs_optim == FS_OPTSPACE)
				warnx(OPTWARN, "time", ">=", MINFREE);
			if (mvalue < MINFREE && sblock.fs_optim == FS_OPTTIME)
				warnx(OPTWARN, "space", "<", MINFREE);
		}
	}
	if (nflag) {
 		name = "soft updates";
 		if (strcmp(nvalue, "enable") == 0) {
			if (sblock.fs_flags & FS_DOSOFTDEP) {
				warnx("%s remains unchanged as enabled", name);
			} else if (sblock.fs_clean == 0) {
				warnx("%s cannot be enabled until fsck is run",
				    name);
			} else {
 				sblock.fs_flags |= FS_DOSOFTDEP;
 				warnx("%s set", name);
			}
 		} else if (strcmp(nvalue, "disable") == 0) {
			if ((~sblock.fs_flags & FS_DOSOFTDEP) == FS_DOSOFTDEP) {
				warnx("%s remains unchanged as disabled", name);
			} else {
 				sblock.fs_flags &= ~FS_DOSOFTDEP;
 				warnx("%s cleared", name);
			}
 		}
	}
	if (oflag) {
		name = "optimization preference";
		chg[FS_OPTSPACE] = "space";
		chg[FS_OPTTIME] = "time";
		if (sblock.fs_optim == ovalue) {
			warnx("%s remains unchanged as %s", name, chg[ovalue]);
		}
		else {
			warnx("%s changes from %s to %s",
				    name, chg[sblock.fs_optim], chg[ovalue]);
			sblock.fs_optim = ovalue;
			if (sblock.fs_minfree >= MINFREE &&
					ovalue == FS_OPTSPACE)
				warnx(OPTWARN, "time", ">=", MINFREE);
			if (sblock.fs_minfree < MINFREE &&
					ovalue == FS_OPTTIME)
				warnx(OPTWARN, "space", "<", MINFREE);
		}
	}
	if (sflag) {
		name = "expected number of files per directory";
		if (sblock.fs_avgfpdir == svalue) {
			warnx("%s remains unchanged as %d", name, svalue);
		}
		else {
			warnx("%s changes from %d to %d",
					name, sblock.fs_avgfpdir, svalue);
			sblock.fs_avgfpdir = svalue;
		}
	}

	putsb(&sblock, special, Aflag);
	if (active) {
		bzero(&args, sizeof(args));
		if (mount("ufs", fs->fs_file,
		    stfs.f_flags | MNT_UPDATE | MNT_RELOAD, &args) < 0)
			err(9, "%s: reload", special);
		warnx("file system reloaded");
	}
	exit(0);
}

void
usage()
{
	fprintf(stderr, "%s\n%s\n%s\n",
"usage: tunefs [-A] [-a maxcontig] [-d rotdelay] [-e maxbpg] [-f avgfilesize]",
"              [-m minfree] [-p] [-n enable | disable] [-o space | time]",
"              [-s filesperdir] special | filesystem");
	exit(2);
}

void
getsb(fs, file)
	struct fs *fs;
	const char *file;
{

	fi = open(file, O_RDONLY);
	if (fi < 0)
		err(3, "cannot open %s", file);
	if (bread((daddr_t)SBOFF, (char *)fs, SBSIZE))
		err(4, "%s: bad super block", file);
	if (fs->fs_magic != FS_MAGIC)
		err(5, "%s: bad magic number", file);
	dev_bsize = fs->fs_fsize / fsbtodb(fs, 1);
}

void
putsb(fs, file, all)
	struct fs *fs;
	const char *file;
	int all;
{
	int i;

	/*
	 * Re-open the device read-write. Use the read-only file
	 * descriptor as an interlock to prevent the device from
	 * being mounted while we are switching mode.
	 */
	i = fi;
	fi = open(file, O_RDWR);
	close(i);
	if (fi < 0)
		err(3, "cannot open %s", file);
	bwrite((daddr_t)SBOFF / dev_bsize, (const char *)fs, SBSIZE);
	if (all)
		for (i = 0; i < fs->fs_ncg; i++)
			bwrite(fsbtodb(fs, cgsblock(fs, i)),
			    (const char *)fs, SBSIZE);
	close(fi);
}

void
printfs()
{
	warnx("soft updates:  (-n)                                %s", 
		(sblock.fs_flags & FS_DOSOFTDEP)? "enabled" : "disabled");
	warnx("maximum contiguous block count: (-a)               %d",
	      sblock.fs_maxcontig);
	warnx("rotational delay between contiguous blocks: (-d)   %d ms",
	      sblock.fs_rotdelay);
	warnx("maximum blocks per file in a cylinder group: (-e)  %d",
	      sblock.fs_maxbpg);
	warnx("average file size: (-f)                            %d",
	      sblock.fs_avgfilesize);
	warnx("average number of files in a directory: (-s)       %d",
	      sblock.fs_avgfpdir);
	warnx("minimum percentage of free space: (-m)             %d%%",
	      sblock.fs_minfree);
	warnx("optimization preference: (-o)                      %s",
	      sblock.fs_optim == FS_OPTSPACE ? "space" : "time");
	if (sblock.fs_minfree >= MINFREE &&
	    sblock.fs_optim == FS_OPTSPACE)
		warnx(OPTWARN, "time", ">=", MINFREE);
	if (sblock.fs_minfree < MINFREE &&
	    sblock.fs_optim == FS_OPTTIME)
		warnx(OPTWARN, "space", "<", MINFREE);
}

void
bwrite(blk, buf, size)
	daddr_t blk;
	const char *buf;
	int size;
{

	if (lseek(fi, (off_t)blk * dev_bsize, SEEK_SET) < 0)
		err(6, "FS SEEK");
	if (write(fi, buf, size) != size)
		err(7, "FS WRITE");
}

int
bread(bno, buf, cnt)
	daddr_t bno;
	char *buf;
	int cnt;
{
	int i;

	if (lseek(fi, (off_t)bno * dev_bsize, SEEK_SET) < 0)
		return(1);
	if ((i = read(fi, buf, cnt)) != cnt) {
		for(i=0; i<sblock.fs_bsize; i++)
			buf[i] = 0;
		return (1);
	}
	return (0);
}
