/*-
 * Copyright (c) 2002 Poul-Henning Kamp
 * Copyright (c) 2002 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by Poul-Henning Kamp
 * and NAI Labs, the Security Research Division of Network Associates, Inc.
 * under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the
 * DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/bio.h>
#include <sys/lock.h>
#include <sys/mutex.h>

#include <sys/diskpc98.h>
#include <geom/geom.h>
#include <geom/geom_slice.h>

#define PC98_CLASS_NAME "PC98"

struct g_pc98_softc {
	u_int fwsectors, fwheads, sectorsize;
	int type[NDOSPART];
	u_char sec[8192];
};

static void
g_pc98_print(int i, struct pc98_partition *dp)
{
	char sname[17];

	strncpy(sname, dp->dp_name, 16);
	sname[16] = '\0';

	g_hexdump(dp, sizeof(dp[0]));
	printf("[%d] mid:%d(0x%x) sid:%d(0x%x)",
	       i, dp->dp_mid, dp->dp_mid, dp->dp_sid, dp->dp_sid);
	printf(" s:%d/%d/%d", dp->dp_scyl, dp->dp_shd, dp->dp_ssect);
	printf(" e:%d/%d/%d", dp->dp_ecyl, dp->dp_ehd, dp->dp_esect);
	printf(" sname:%s\n", sname);
}

static int
g_pc98_modify(struct g_geom *gp, struct g_pc98_softc *ms, u_char *sec)
{
	int i, error;
	off_t s[NDOSPART], l[NDOSPART];
	struct pc98_partition dp[NDOSPART];

	g_topology_assert();
	
	if (sec[0x1fe] != 0x55 || sec[0x1ff] != 0xaa)
		return (EBUSY);

#if 0
	/*
	 * XXX: Some sources indicate this is a magic sequence, but appearantly
	 * XXX: it is not universal. Documentation would be wonderful to have.
	 */
	if (sec[4] != 'I' || sec[5] != 'P' || sec[6] != 'L' || sec[7] != '1')
		return (EBUSY);
#endif

	for (i = 0; i < NDOSPART; i++)
		pc98_partition_dec(
			sec + 512 + i * sizeof(struct pc98_partition), &dp[i]);

	for (i = 0; i < NDOSPART; i++) {
		/* If start and end are identical it's bogus */
		if (dp[i].dp_ssect == dp[i].dp_esect &&
		    dp[i].dp_shd == dp[i].dp_ehd &&
		    dp[i].dp_scyl == dp[i].dp_ecyl)
			s[i] = l[i] = 0;
		else if (dp[i].dp_ecyl == 0)
			s[i] = l[i] = 0;
		else {
			s[i] = (off_t)dp[i].dp_scyl *
				ms->fwsectors * ms->fwheads * ms->sectorsize;
			l[i] = (off_t)(dp[i].dp_ecyl - dp[i].dp_scyl + 1) *
				ms->fwsectors * ms->fwheads * ms->sectorsize;
		}
		if (bootverbose) {
			printf("PC98 Slice %d on %s:\n", i + 1, gp->name);
			g_pc98_print(i, dp + i);
		}
		if (s[i] < 0 || l[i] < 0)
			error = EBUSY;
		else
			error = g_slice_config(gp, i, G_SLICE_CONFIG_CHECK,
				       s[i], l[i], ms->sectorsize,
				       "%ss%d", gp->name, i + 1);
		if (error)
			return (error);
	}

	for (i = 0; i < NDOSPART; i++) {
		ms->type[i] = (dp[i].dp_sid << 8) | dp[i].dp_mid;
		g_slice_config(gp, i, G_SLICE_CONFIG_SET, s[i], l[i],
			       ms->sectorsize, "%ss%d", gp->name, i + 1);
	}

	bcopy(sec, ms->sec, sizeof (ms->sec));

	return (0);
}

static void
g_pc98_ioctl(void *arg, int flag)
{
	struct bio *bp;
	struct g_geom *gp;
	struct g_slicer *gsp;
	struct g_pc98_softc *ms;
	struct g_ioctl *gio;
	struct g_consumer *cp;
	u_char *sec;
	int error;

	bp = arg;
	if (flag == EV_CANCEL) {
		g_io_deliver(bp, ENXIO);
		return;
	}
	gp = bp->bio_to->geom;
	gsp = gp->softc;
	ms = gsp->softc;
	gio = (struct g_ioctl *)bp->bio_data;

	/* The disklabel to set is the ioctl argument. */
	sec = gio->data;

	error = g_pc98_modify(gp, ms, sec);
	if (error) {
		g_io_deliver(bp, error);
		return;
	}
	cp = LIST_FIRST(&gp->consumer);
	error = g_write_data(cp, 0, sec, 8192);
	g_io_deliver(bp, error);
}

static int
g_pc98_start(struct bio *bp)
{
	struct g_provider *pp;
	struct g_geom *gp;
	struct g_pc98_softc *mp;
	struct g_slicer *gsp;
	struct g_ioctl *gio;
	int idx, error;

	pp = bp->bio_to;
	idx = pp->index;
	gp = pp->geom;
	gsp = gp->softc;
	mp = gsp->softc;
	if (bp->bio_cmd == BIO_GETATTR) {
		if (g_handleattr_int(bp, "PC98::type", mp->type[idx]))
			return (1);
		if (g_handleattr_off_t(bp, "PC98::offset",
				       gsp->slices[idx].offset))
			return (1);
	}

	/* We only handle ioctl(2) requests of the right format. */
	if (strcmp(bp->bio_attribute, "GEOM::ioctl"))
		return (0);
	else if (bp->bio_length != sizeof(*gio))
		return (0);
	/* Get hold of the ioctl parameters. */
	gio = (struct g_ioctl *)bp->bio_data;

	switch (gio->cmd) {
	case DIOCSPC98:
		/*
		 * These we cannot do without the topology lock and some
		 * some I/O requests.  Ask the event-handler to schedule
		 * us in a less restricted environment.
		 */
		error = g_post_event(g_pc98_ioctl, bp, M_NOWAIT, gp, NULL);
		if (error)
			g_io_deliver(bp, error);
		/*
		 * We must return non-zero to indicate that we will deal
		 * with this bio, even though we have not done so yet.
		 */
		return (1);
	default:
		return (0);
	}

	return (0);
}

static void
g_pc98_dumpconf(struct sbuf *sb, const char *indent, struct g_geom *gp,
		struct g_consumer *cp __unused, struct g_provider *pp)
{
	struct g_pc98_softc *mp;
	struct g_slicer *gsp;
	struct pc98_partition dp;
	char sname[17];

	gsp = gp->softc;
	mp = gsp->softc;
	g_slice_dumpconf(sb, indent, gp, cp, pp);
	if (pp != NULL) {
		pc98_partition_dec(
			mp->sec + 512 +
			pp->index * sizeof(struct pc98_partition), &dp);
		strncpy(sname, dp.dp_name, 16);
		sname[16] = '\0';
		if (indent == NULL) {
			sbuf_printf(sb, " ty %d", mp->type[pp->index]);
			sbuf_printf(sb, " sn %s", sname);
		} else {
			sbuf_printf(sb, "%s<type>%d</type>\n", indent,
				    mp->type[pp->index]);
			sbuf_printf(sb, "%s<sname>%s</sname>\n", indent,
				    sname);
		}
	}
}

static struct g_geom *
g_pc98_taste(struct g_class *mp, struct g_provider *pp, int flags)
{
	struct g_geom *gp;
	struct g_consumer *cp;
	int error;
	struct g_pc98_softc *ms;
	struct g_slicer *gsp;
	u_int fwsectors, fwheads, sectorsize;
	u_char *buf;

	g_trace(G_T_TOPOLOGY, "g_pc98_taste(%s,%s)", mp->name, pp->name);
	g_topology_assert();
	if (flags == G_TF_NORMAL &&
	    !strcmp(pp->geom->class->name, PC98_CLASS_NAME))
		return (NULL);
	gp = g_slice_new(mp, NDOSPART, pp, &cp, &ms, sizeof *ms, g_pc98_start);
	if (gp == NULL)
		return (NULL);
	gsp = gp->softc;
	g_topology_unlock();
	gp->dumpconf = g_pc98_dumpconf;
	do {
		if (gp->rank != 2 && flags == G_TF_NORMAL)
			break;
		error = g_getattr("GEOM::fwsectors", cp, &fwsectors);
		if (error || fwsectors == 0) {
			fwsectors = 17;
			if (bootverbose)
				printf("g_pc98_taste: guessing %d sectors\n",
				    fwsectors);
		}
		error = g_getattr("GEOM::fwheads", cp, &fwheads);
		if (error || fwheads == 0) {
			fwheads = 8;
			if (bootverbose)
				printf("g_pc98_taste: guessing %d heads\n",
				    fwheads);
		}
		sectorsize = cp->provider->sectorsize;
		if (sectorsize < 512)
			break;
		buf = g_read_data(cp, 0, 8192, &error);
		if (buf == NULL || error != 0)
			break;
		ms->fwsectors = fwsectors;
		ms->fwheads = fwheads;
		ms->sectorsize = sectorsize;
		g_topology_lock();
		g_pc98_modify(gp, ms, buf);
		g_topology_unlock();
		g_free(buf);
		break;
	} while (0);
	g_topology_lock();
	g_access_rel(cp, -1, 0, 0);
	if (LIST_EMPTY(&gp->provider)) {
		g_slice_spoiled(cp);
		return (NULL);
	}
	return (gp);
}

static struct g_class g_pc98_class = {
	.name = PC98_CLASS_NAME,
	.taste = g_pc98_taste,
	G_CLASS_INITIALIZER
};

DECLARE_GEOM_CLASS(g_pc98_class, g_pc98);
