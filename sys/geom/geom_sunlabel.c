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
 * 3. The names of the authors may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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
#include <sys/conf.h>
#include <sys/bio.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sun_disklabel.h>
#include <geom/geom.h>
#include <geom/geom_slice.h>
#include <machine/endian.h>

#define SUNLABEL_CLASS_NAME "SUN"

struct g_sunlabel_softc {
	int sectorsize;
	int nheads;
	int nsects;
	int nalt;
};

static int
g_sunlabel_modify(struct g_geom *gp, struct g_sunlabel_softc *ms, u_char *sec0)
{
	int i, error;
	u_int u, v, csize;
	struct sun_disklabel sl;

	error = sunlabel_dec(sec0, &sl);
	if (error)
		return (error);

	csize = sl.sl_ntracks * sl.sl_nsectors;

	for (i = 0; i < SUN_NPART; i++) {
		v = sl.sl_part[i].sdkp_cyloffset;
		u = sl.sl_part[i].sdkp_nsectors;
		g_topology_lock();
		error = g_slice_config(gp, i, G_SLICE_CONFIG_CHECK,
		    ((off_t)v * csize) << 9ULL,
		    ((off_t)u) << 9ULL,
		    ms->sectorsize,
		    "%s%c", gp->name, 'a' + i);
		g_topology_unlock();
		if (error)
			return (error);
	}
	for (i = 0; i < SUN_NPART; i++) {
		v = sl.sl_part[i].sdkp_cyloffset;
		u = sl.sl_part[i].sdkp_nsectors;
		g_topology_lock();
		g_slice_config(gp, i, G_SLICE_CONFIG_SET,
		    ((off_t)v * csize) << 9ULL,
		    ((off_t)u) << 9ULL,
		    ms->sectorsize,
		    "%s%c", gp->name, 'a' + i);
		g_topology_unlock();
	}
	ms->nalt = sl.sl_acylinders;
	ms->nheads = sl.sl_ntracks;
	ms->nsects = sl.sl_nsectors;

	return (0);
}

static void
g_sunlabel_hotwrite(void *arg, int flag)
{
	struct bio *bp;
	struct g_geom *gp;
	struct g_slicer *gsp;
	struct g_slice *gsl;
	struct g_sunlabel_softc *ms;
	u_char *p;
	int error;

	KASSERT(flag != EV_CANCEL, ("g_sunlabel_hotwrite cancelled"));
	bp = arg;
	gp = bp->bio_to->geom;
	gsp = gp->softc;
	ms = gsp->softc;
	gsl = &gsp->slices[bp->bio_to->index];
	/*
	 * XXX: For all practical purposes, this whould be equvivalent to
	 * XXX: "p = (u_char *)bp->bio_data;" because the label is always
	 * XXX: in the first sector and we refuse sectors smaller than the
	 * XXX: label.
	 */
	p = (u_char *)bp->bio_data - (bp->bio_offset + gsl->offset);

	g_topology_unlock();
	error = g_sunlabel_modify(gp, ms, p);
	g_topology_lock();
	if (error) {
		g_io_deliver(bp, EPERM);
		return;
	}
	g_slice_finish_hot(bp);
}

static void
g_sunlabel_dumpconf(struct sbuf *sb, const char *indent, struct g_geom *gp, struct g_consumer *cp __unused, struct g_provider *pp)
{
	struct g_slicer *gsp;
	struct g_sunlabel_softc *ms;

	gsp = gp->softc;
	ms = gsp->softc;
	g_slice_dumpconf(sb, indent, gp, cp, pp);
	if (indent == NULL) {
		sbuf_printf(sb, " sc %u hd %u alt %u",
		    ms->nsects, ms->nheads, ms->nalt);
	}
}

static struct g_geom *
g_sunlabel_taste(struct g_class *mp, struct g_provider *pp, int flags)
{
	struct g_geom *gp;
	struct g_consumer *cp;
	int error, npart;
	u_char *buf;
	struct g_sunlabel_softc *ms;
	off_t mediasize;
	struct g_slicer *gsp;

	g_trace(G_T_TOPOLOGY, "g_sunlabel_taste(%s,%s)", mp->name, pp->name);
	g_topology_assert();
	if (flags == G_TF_NORMAL &&
	    !strcmp(pp->geom->class->name, SUNLABEL_CLASS_NAME))
		return (NULL);
	gp = g_slice_new(mp, 8, pp, &cp, &ms, sizeof *ms, NULL);
	if (gp == NULL)
		return (NULL);
	gsp = gp->softc;
	g_topology_unlock();
	gp->dumpconf = g_sunlabel_dumpconf;
	npart = 0;
	do {
		if (gp->rank != 2 && flags == G_TF_NORMAL)
			break;
		ms->sectorsize = cp->provider->sectorsize;
		if (ms->sectorsize < 512)
			break;
		mediasize = cp->provider->mediasize;
		buf = g_read_data(cp, 0, ms->sectorsize, &error);
		if (buf == NULL || error != 0)
			break;
		
		g_sunlabel_modify(gp, ms, buf);

		break;
	} while (0);
	g_topology_lock();
	g_access_rel(cp, -1, 0, 0);
	if (LIST_EMPTY(&gp->provider)) {
		g_std_spoiled(cp);
		return (NULL);
	} else {
		g_slice_conf_hot(gp, 0, 0, SUN_SIZE,
		    G_SLICE_HOT_ALLOW, G_SLICE_HOT_DENY, G_SLICE_HOT_CALL);
		gsp->hot = g_sunlabel_hotwrite;
	}
	return (gp);
}

static struct g_class g_sunlabel_class = {
	.name = SUNLABEL_CLASS_NAME,
	.taste = g_sunlabel_taste,
	G_CLASS_INITIALIZER
};

DECLARE_GEOM_CLASS(g_sunlabel_class, g_sunlabel);
