/*
 * Copyright (c) 1980, 1986, 1993
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
#if 0
static const char sccsid[] = "@(#)pass5.c	8.9 (Berkeley) 4/28/95";
#endif
static const char rcsid[] =
  "$FreeBSD$";
#endif /* not lint */

#include <sys/param.h>
#include <sys/sysctl.h>

#include <ufs/ufs/dinode.h>
#include <ufs/ffs/fs.h>

#include <err.h>
#include <string.h>

#include "fsck.h"

static void check_maps __P((u_char *, u_char *, int, int, char *, int *,
				int, int));

void
pass5()
{
	int c, blk, frags, basesize, sumsize, mapsize, savednrpos = 0;
	int inomapsize, blkmapsize;
	struct fs *fs = &sblock;
	struct cg *cg = &cgrp;
	ufs_daddr_t dbase, dmax, d;
	int i, j, excessdirs;
	struct csum *cs;
	struct csum cstotal;
	struct inodesc idesc[3];
	char buf[MAXBSIZE];
	register struct cg *newcg = (struct cg *)buf;
	struct ocg *ocg = (struct ocg *)buf;

	inoinfo(WINO)->ino_state = USTATE;
	memset(newcg, 0, (size_t)fs->fs_cgsize);
	newcg->cg_niblk = fs->fs_ipg;
	if (cvtlevel >= 3) {
		if (fs->fs_maxcontig < 2 && fs->fs_contigsumsize > 0) {
			if (preen)
				pwarn("DELETING CLUSTERING MAPS\n");
			if (preen || reply("DELETE CLUSTERING MAPS")) {
				fs->fs_contigsumsize = 0;
				doinglevel1 = 1;
				sbdirty();
			}
		}
		if (fs->fs_maxcontig > 1) {
			char *doit = 0;

			if (fs->fs_contigsumsize < 1) {
				doit = "CREAT";
			} else if (fs->fs_contigsumsize < fs->fs_maxcontig &&
				   fs->fs_contigsumsize < FS_MAXCONTIG) {
				doit = "EXPAND";
			}
			if (doit) {
				i = fs->fs_contigsumsize;
				fs->fs_contigsumsize =
				    MIN(fs->fs_maxcontig, FS_MAXCONTIG);
				if (CGSIZE(fs) > (u_int)fs->fs_bsize) {
					pwarn("CANNOT %s CLUSTER MAPS\n", doit);
					fs->fs_contigsumsize = i;
				} else if (preen ||
				    reply("CREATE CLUSTER MAPS")) {
					if (preen)
						pwarn("%sING CLUSTER MAPS\n",
						    doit);
					fs->fs_cgsize =
					    fragroundup(fs, CGSIZE(fs));
					doinglevel1 = 1;
					sbdirty();
				}
			}
		}
	}
	switch ((int)fs->fs_postblformat) {

	case FS_42POSTBLFMT:
		basesize = (char *)(&ocg->cg_btot[0]) -
		    (char *)(&ocg->cg_firstfield);
		sumsize = &ocg->cg_iused[0] - (u_int8_t *)(&ocg->cg_btot[0]);
		mapsize = &ocg->cg_free[howmany(fs->fs_fpg, NBBY)] -
			(u_char *)&ocg->cg_iused[0];
		blkmapsize = howmany(fs->fs_fpg, NBBY);
		inomapsize = &ocg->cg_free[0] - (u_char *)&ocg->cg_iused[0];
		ocg->cg_magic = CG_MAGIC;
		savednrpos = fs->fs_nrpos;
		fs->fs_nrpos = 8;
		break;

	case FS_DYNAMICPOSTBLFMT:
		newcg->cg_btotoff =
		     &newcg->cg_space[0] - (u_char *)(&newcg->cg_firstfield);
		newcg->cg_boff =
		    newcg->cg_btotoff + fs->fs_cpg * sizeof(int32_t);
		newcg->cg_iusedoff = newcg->cg_boff +
		    fs->fs_cpg * fs->fs_nrpos * sizeof(u_int16_t);
		newcg->cg_freeoff =
		    newcg->cg_iusedoff + howmany(fs->fs_ipg, NBBY);
		inomapsize = newcg->cg_freeoff - newcg->cg_iusedoff;
		newcg->cg_nextfreeoff = newcg->cg_freeoff +
		    howmany(fs->fs_cpg * fs->fs_spc / NSPF(fs), NBBY);
		blkmapsize = newcg->cg_nextfreeoff - newcg->cg_freeoff;
		if (fs->fs_contigsumsize > 0) {
			newcg->cg_clustersumoff = newcg->cg_nextfreeoff -
			    sizeof(u_int32_t);
			newcg->cg_clustersumoff =
			    roundup(newcg->cg_clustersumoff, sizeof(u_int32_t));
			newcg->cg_clusteroff = newcg->cg_clustersumoff +
			    (fs->fs_contigsumsize + 1) * sizeof(u_int32_t);
			newcg->cg_nextfreeoff = newcg->cg_clusteroff +
			    howmany(fs->fs_cpg * fs->fs_spc / NSPB(fs), NBBY);
		}
		newcg->cg_magic = CG_MAGIC;
		basesize = &newcg->cg_space[0] -
		    (u_char *)(&newcg->cg_firstfield);
		sumsize = newcg->cg_iusedoff - newcg->cg_btotoff;
		mapsize = newcg->cg_nextfreeoff - newcg->cg_iusedoff;
		break;

	default:
		inomapsize = blkmapsize = sumsize = 0;	/* keep lint happy */
		errx(EEXIT, "UNKNOWN ROTATIONAL TABLE FORMAT %d",
			fs->fs_postblformat);
	}
	memset(&idesc[0], 0, sizeof idesc);
	for (i = 0; i < 3; i++) {
		idesc[i].id_type = ADDR;
		if (doinglevel2)
			idesc[i].id_fix = FIX;
	}
	memset(&cstotal, 0, sizeof(struct csum));
	j = blknum(fs, fs->fs_size + fs->fs_frag - 1);
	for (i = fs->fs_size; i < j; i++)
		setbmap(i);
	for (c = 0; c < fs->fs_ncg; c++) {
		if (got_siginfo) {
			printf("%s: phase 5: cyl group %d of %d (%d%%)\n",
			    cdevname, c, sblock.fs_ncg,
			    c * 100 / sblock.fs_ncg);
			got_siginfo = 0;
		}
		getblk(&cgblk, cgtod(fs, c), fs->fs_cgsize);
		if (!cg_chkmagic(cg))
			pfatal("CG %d: BAD MAGIC NUMBER\n", c);
		dbase = cgbase(fs, c);
		dmax = dbase + fs->fs_fpg;
		if (dmax > fs->fs_size)
			dmax = fs->fs_size;
		newcg->cg_time = cg->cg_time;
		newcg->cg_cgx = c;
		if (c == fs->fs_ncg - 1)
			newcg->cg_ncyl = fs->fs_ncyl % fs->fs_cpg;
		else
			newcg->cg_ncyl = fs->fs_cpg;
		newcg->cg_ndblk = dmax - dbase;
		if (fs->fs_contigsumsize > 0)
			newcg->cg_nclusterblks = newcg->cg_ndblk / fs->fs_frag;
		newcg->cg_cs.cs_ndir = 0;
		newcg->cg_cs.cs_nffree = 0;
		newcg->cg_cs.cs_nbfree = 0;
		newcg->cg_cs.cs_nifree = fs->fs_ipg;
		if (cg->cg_rotor < newcg->cg_ndblk)
			newcg->cg_rotor = cg->cg_rotor;
		else
			newcg->cg_rotor = 0;
		if (cg->cg_frotor < newcg->cg_ndblk)
			newcg->cg_frotor = cg->cg_frotor;
		else
			newcg->cg_frotor = 0;
		if (cg->cg_irotor < newcg->cg_niblk)
			newcg->cg_irotor = cg->cg_irotor;
		else
			newcg->cg_irotor = 0;
		memset(&newcg->cg_frsum[0], 0, sizeof newcg->cg_frsum);
		memset(&cg_blktot(newcg)[0], 0,
		      (size_t)(sumsize + mapsize));
		if (fs->fs_postblformat == FS_42POSTBLFMT)
			ocg->cg_magic = CG_MAGIC;
		j = fs->fs_ipg * c;
		for (i = 0; i < inostathead[c].il_numalloced; j++, i++) {
			switch (inoinfo(j)->ino_state) {

			case USTATE:
				break;

			case DSTATE:
			case DCLEAR:
			case DFOUND:
				newcg->cg_cs.cs_ndir++;
				/* fall through */

			case FSTATE:
			case FCLEAR:
				newcg->cg_cs.cs_nifree--;
				setbit(cg_inosused(newcg), i);
				break;

			default:
				if (j < (int)ROOTINO)
					break;
				errx(EEXIT, "BAD STATE %d FOR INODE I=%ld",
				    inoinfo(j)->ino_state, j);
			}
		}
		if (c == 0)
			for (i = 0; i < (int)ROOTINO; i++) {
				setbit(cg_inosused(newcg), i);
				newcg->cg_cs.cs_nifree--;
			}
		for (i = 0, d = dbase;
		     d < dmax;
		     d += fs->fs_frag, i += fs->fs_frag) {
			frags = 0;
			for (j = 0; j < fs->fs_frag; j++) {
				if (testbmap(d + j))
					continue;
				setbit(cg_blksfree(newcg), i + j);
				frags++;
			}
			if (frags == fs->fs_frag) {
				newcg->cg_cs.cs_nbfree++;
				j = cbtocylno(fs, i);
				cg_blktot(newcg)[j]++;
				cg_blks(fs, newcg, j)[cbtorpos(fs, i)]++;
				if (fs->fs_contigsumsize > 0)
					setbit(cg_clustersfree(newcg),
					    i / fs->fs_frag);
			} else if (frags > 0) {
				newcg->cg_cs.cs_nffree += frags;
				blk = blkmap(fs, cg_blksfree(newcg), i);
				ffs_fragacct(fs, blk, newcg->cg_frsum, 1);
			}
		}
		if (fs->fs_contigsumsize > 0) {
			int32_t *sump = cg_clustersum(newcg);
			u_char *mapp = cg_clustersfree(newcg);
			int map = *mapp++;
			int bit = 1;
			int run = 0;

			for (i = 0; i < newcg->cg_nclusterblks; i++) {
				if ((map & bit) != 0) {
					run++;
				} else if (run != 0) {
					if (run > fs->fs_contigsumsize)
						run = fs->fs_contigsumsize;
					sump[run]++;
					run = 0;
				}
				if ((i & (NBBY - 1)) != (NBBY - 1)) {
					bit <<= 1;
				} else {
					map = *mapp++;
					bit = 1;
				}
			}
			if (run != 0) {
				if (run > fs->fs_contigsumsize)
					run = fs->fs_contigsumsize;
				sump[run]++;
			}
		}
		cstotal.cs_nffree += newcg->cg_cs.cs_nffree;
		cstotal.cs_nbfree += newcg->cg_cs.cs_nbfree;
		cstotal.cs_nifree += newcg->cg_cs.cs_nifree;
		cstotal.cs_ndir += newcg->cg_cs.cs_ndir;
		cs = &fs->fs_cs(fs, c);
		if (cursnapshot == 0 &&
		    memcmp(&newcg->cg_cs, cs, sizeof *cs) != 0 &&
		    dofix(&idesc[0], "FREE BLK COUNT(S) WRONG IN SUPERBLK")) {
			memmove(cs, &newcg->cg_cs, sizeof *cs);
			sbdirty();
		}
		if (doinglevel1) {
			memmove(cg, newcg, (size_t)fs->fs_cgsize);
			cgdirty();
			continue;
		}
		if (cursnapshot == 0 &&
		    (memcmp(newcg, cg, basesize) != 0 ||
		     memcmp(&cg_blktot(newcg)[0],
			  &cg_blktot(cg)[0], sumsize) != 0) &&
		    dofix(&idesc[2], "SUMMARY INFORMATION BAD")) {
			memmove(cg, newcg, (size_t)basesize);
			memmove(&cg_blktot(cg)[0],
			       &cg_blktot(newcg)[0], (size_t)sumsize);
			cgdirty();
		}
		if (bkgrdflag != 0 || usedsoftdep || debug) {
			excessdirs = cg->cg_cs.cs_ndir - newcg->cg_cs.cs_ndir;
			if (excessdirs < 0) {
				pfatal("LOST %d DIRECTORIES\n", -excessdirs);
				excessdirs = 0;
			}
			if (excessdirs > 0)
				check_maps(cg_inosused(newcg), cg_inosused(cg),
				    inomapsize, cg->cg_cgx * fs->fs_ipg, "DIR",
				    freedirs, 0, excessdirs);
			check_maps(cg_inosused(newcg), cg_inosused(cg),
			    inomapsize, cg->cg_cgx * fs->fs_ipg, "FILE",
			    freefiles, excessdirs, fs->fs_ipg);
			check_maps(cg_blksfree(cg), cg_blksfree(newcg),
			    blkmapsize, cg->cg_cgx * fs->fs_fpg, "FRAG",
			    freeblks, 0, fs->fs_fpg);
		}
		if (cursnapshot == 0 &&
		    memcmp(cg_inosused(newcg), cg_inosused(cg), mapsize) != 0 &&
		    dofix(&idesc[1], "BLK(S) MISSING IN BIT MAPS")) {
			memmove(cg_inosused(cg), cg_inosused(newcg),
			      (size_t)mapsize);
			cgdirty();
		}
	}
	if (fs->fs_postblformat == FS_42POSTBLFMT)
		fs->fs_nrpos = savednrpos;
	if (cursnapshot == 0 &&
	    memcmp(&cstotal, &fs->fs_cstotal, sizeof *cs) != 0
	    && dofix(&idesc[0], "FREE BLK COUNT(S) WRONG IN SUPERBLK")) {
		memmove(&fs->fs_cstotal, &cstotal, sizeof *cs);
		fs->fs_ronly = 0;
		fs->fs_fmod = 0;
		sbdirty();
	}
}

static void
check_maps(map1, map2, mapsize, startvalue, name, opcode, skip, limit)
	u_char *map1;	/* map of claimed allocations */
	u_char *map2;	/* map of determined allocations */
	int mapsize;	/* size of above two maps */
	int startvalue;	/* resource value for first element in map */
	char *name;	/* name of resource found in maps */
	int *opcode;	/* sysctl opcode to free resource */
	int skip;	/* number of entries to skip before starting to free */
	int limit;	/* limit on number of entries to free */
{
#	define BUFSIZE 16
	char buf[BUFSIZE];
	long i, j, k, l, m, n, size;
	int astart, aend, ustart, uend;

	astart = ustart = aend = uend = -1;
	for (i = 0; i < mapsize; i++) {
		j = *map1++;
		k = *map2++;
		if (j == k)
			continue;
		for (m = 0, l = 1; m < NBBY; m++, l <<= 1) {
			if ((j & l) == (k & l))
				continue;
			n = startvalue + i * NBBY + m;
			if ((j & l) != 0) {
				if (astart == -1) {
					astart = aend = n;
					continue;
				}
				if (aend + 1 == n) {
					aend = n;
					continue;
				}
				if (astart == aend)
					pfatal("ALLOCATED %s %d MARKED FREE\n",
					    name, astart);
				else
					pfatal("%s %sS %d-%d MARKED FREE\n",
					    "ALLOCATED", name, astart, aend);
				astart = aend = n;
			} else {
				if (ustart == -1) {
					ustart = uend = n;
					continue;
				}
				if (uend + 1 == n) {
					uend = n;
					continue;
				}
				size = uend - ustart + 1;
				if (size <= skip) {
					skip -= size;
					ustart = uend = n;
					continue;
				}
				if (skip > 0) {
					ustart += skip;
					size -= skip;
					skip = 0;
				}
				if (size > limit)
					size = limit;
				if (debug && size == 1)
					pwarn("%s %s %d MARKED USED\n",
					    "UNALLOCATED", name, ustart);
				else if (debug)
					pwarn("%s %sS %d-%d MARKED USED\n",
					    "UNALLOCATED", name, ustart,
					    ustart + size - 1);
				if (bkgrdflag != 0) {
					cmd.value = ustart;
					cmd.size = size;
					if (sysctl(opcode, MIBSIZE, 0, 0,
					    &cmd, sizeof cmd) == -1) {
						snprintf(buf, BUFSIZE,
						    "FREE %s", name);
						rwerror(buf, cmd.value);
					}
				}
				limit -= size;
				if (limit <= 0)
					return;
				ustart = uend = n;
			}
		}
	}
	if (astart != -1)
		if (astart == aend)
			pfatal("ALLOCATED %s %d MARKED FREE\n", name, astart);
		else
			pfatal("ALLOCATED %sS %d-%d MARKED FREE\n",
			    name, astart, aend);
	if (ustart != -1) {
		size = uend - ustart + 1;
		if (size <= skip)
			return;
		if (skip > 0) {
			ustart += skip;
			size -= skip;
		}
		if (size > limit)
			size = limit;
		if (debug) {
			if (size == 1)
				pwarn("UNALLOCATED %s %d MARKED USED\n",
				    name, ustart);
			else
				pwarn("UNALLOCATED %sS %d-%d MARKED USED\n",
				    name, ustart, ustart + size - 1);
		}
		if (bkgrdflag != 0) {
			cmd.value = ustart;
			cmd.size = size;
			if (sysctl(opcode, MIBSIZE, 0, 0, &cmd,
			    sizeof cmd) == -1) {
				snprintf(buf, BUFSIZE, "FREE %s", name);
				rwerror(buf, cmd.value);
			}
		}
	}
}
