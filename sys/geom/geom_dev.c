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
#include <sys/stdint.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/bio.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/disk.h>
#include <sys/fcntl.h>
#include <geom/geom.h>
#include <geom/geom_int.h>
#include <geom/geom_stats.h>
#include <machine/limits.h>

static d_open_t		g_dev_open;
static d_close_t	g_dev_close;
static d_strategy_t	g_dev_strategy;
static d_ioctl_t	g_dev_ioctl;
static d_psize_t	g_dev_psize;

static struct cdevsw g_dev_cdevsw = {
	/* open */      g_dev_open,
	/* close */     g_dev_close,
	/* read */      physread,
	/* write */     physwrite,
	/* ioctl */     g_dev_ioctl,
	/* poll */      nopoll,
	/* mmap */      nommap,
	/* strategy */  g_dev_strategy,
	/* name */      "g_dev",
	/* maj */       GEOM_MAJOR,
	/* dump */      nodump,
	/* psize */     g_dev_psize,
	/* flags */     D_DISK | D_TRACKCLOSE,
	/* kqfilter */	nokqfilter
};

static g_taste_t g_dev_taste;
static g_orphan_t g_dev_orphan;

static struct g_class g_dev_class	= {
	"DEV",
	g_dev_taste,
	NULL,
	G_CLASS_INITIALIZER
};

int
g_dev_print(void)
{
	struct g_geom *gp;

	if (LIST_EMPTY(&g_dev_class.geom))
		return (0);
	printf("List of GEOM disk devices:\n  ");
	LIST_FOREACH(gp, &g_dev_class.geom, geom)
		printf(" %s", gp->name);
	printf("\n");
	return (1);
}

/*
 * XXX: This is disgusting and wrong in every way imaginable:  The only reason
 * XXX: we have a clone function is because of the root-mount hack we currently
 * XXX: employ.  An improvment would be to unregister this cloner once we know
 * XXX: we no longer need it.  Ideally, root-fs would be mounted through DEVFS
 * XXX: eliminating the need for this hack.
 */
static void
g_dev_clone(void *arg __unused, char *name, int namelen __unused, dev_t *dev)
{
	struct g_geom *gp;

	if (*dev != NODEV)
		return;

	g_waitidle();

	/* g_topology_lock(); */
	LIST_FOREACH(gp, &g_dev_class.geom, geom) {
		if (strcmp(gp->name, name))
			continue;
		*dev = gp->softc;
		g_trace(G_T_TOPOLOGY, "g_dev_clone(%s) = %p", name, *dev);
		return;
	}
	/* g_topology_unlock(); */
	return;
}

static void
g_dev_register_cloner(void *foo __unused)
{
	static int once;

	/* XXX: why would this happen more than once ?? */
	if (!once) {
		EVENTHANDLER_REGISTER(dev_clone, g_dev_clone, 0, 1000);
		once++;
	}
}

SYSINIT(geomdev,SI_SUB_DRIVERS,SI_ORDER_MIDDLE,g_dev_register_cloner,NULL);

static struct g_geom *
g_dev_taste(struct g_class *mp, struct g_provider *pp, int insist __unused)
{
	struct g_geom *gp;
	struct g_consumer *cp;
	static int unit = GEOM_MINOR_PROVIDERS;
	int error;
	dev_t dev;

	g_trace(G_T_TOPOLOGY, "dev_taste(%s,%s)", mp->name, pp->name);
	g_topology_assert();
	LIST_FOREACH(cp, &pp->consumers, consumers)
		if (cp->geom->class == mp)
			return (NULL);
	gp = g_new_geomf(mp, pp->name);
	gp->orphan = g_dev_orphan;
	cp = g_new_consumer(gp);
	error = g_attach(cp, pp);
	KASSERT(error == 0,
	    ("g_dev_taste(%s) failed to g_attach, err=%d", pp->name, error));
	/*
	 * XXX: I'm not 100% sure we can call make_dev(9) without Giant
	 * yet.  Once we can, we don't need to drop topology here either.
	 */
	g_topology_unlock();
	mtx_lock(&Giant);
	dev = make_dev(&g_dev_cdevsw, unit2minor(unit++),
	    UID_ROOT, GID_OPERATOR, 0640, gp->name);
	if (pp->flags & G_PF_CANDELETE)
		dev->si_flags |= SI_CANDELETE;
	mtx_unlock(&Giant);
	g_topology_lock();

	dev->si_stripesize = pp->stripesize;
	dev->si_stripeoffset = pp->stripeoffset;
	gp->softc = dev;
	dev->si_drv1 = gp;
	dev->si_drv2 = cp;
	return (gp);
}

static int
g_dev_open(dev_t dev, int flags, int fmt, struct thread *td)
{
	struct g_geom *gp;
	struct g_consumer *cp;
	int error, r, w, e;

	gp = dev->si_drv1;
	cp = dev->si_drv2;
	if (gp == NULL || cp == NULL)
		return(ENXIO);
	g_trace(G_T_ACCESS, "g_dev_open(%s, %d, %d, %p)",
	    gp->name, flags, fmt, td);
	DROP_GIANT();
	g_topology_lock();
	r = flags & FREAD ? 1 : 0;
	w = flags & FWRITE ? 1 : 0;
#ifdef notyet
	e = flags & O_EXCL ? 1 : 0;
#else
	e = 0;
#endif
	error = g_access_rel(cp, r, w, e);
	g_topology_unlock();
	PICKUP_GIANT();
	g_waitidle();
	dev->si_bsize_phys = cp->provider->sectorsize;
	return(error);
}

static int
g_dev_close(dev_t dev, int flags, int fmt, struct thread *td)
{
	struct g_geom *gp;
	struct g_consumer *cp;
	int error, r, w, e;

	gp = dev->si_drv1;
	cp = dev->si_drv2;
	if (gp == NULL || cp == NULL)
		return(ENXIO);
	g_trace(G_T_ACCESS, "g_dev_close(%s, %d, %d, %p)",
	    gp->name, flags, fmt, td);
	DROP_GIANT();
	g_topology_lock();
	r = flags & FREAD ? -1 : 0;
	w = flags & FWRITE ? -1 : 0;
#ifdef notyet
	e = flags & O_EXCL ? -1 : 0;
#else
	e = 0;
#endif
	error = g_access_rel(cp, r, w, e);
	g_topology_unlock();
	PICKUP_GIANT();
	g_waitidle();
	return (error);
}

static int
g_dev_ioctl(dev_t dev, u_long cmd, caddr_t data, int fflag, struct thread *td)
{
	struct g_geom *gp, *gp2;
	struct g_consumer *cp;
	struct g_provider *pp2;
	struct g_kerneldump kd;
	int i, error;
	u_int u;
	struct g_ioctl *gio;

	gp = dev->si_drv1;
	cp = dev->si_drv2;
	pp2 = cp->provider;
	gp2 = pp2->geom;
	gio = NULL;

	error = 0;
	DROP_GIANT();

	gio = NULL;
	i = IOCPARM_LEN(cmd);
	switch (cmd) {
	case DIOCGSECTORSIZE:
		*(u_int *)data = cp->provider->sectorsize;
		if (*(u_int *)data == 0)
			error = ENOENT;
		break;
	case DIOCGMEDIASIZE:
		*(off_t *)data = cp->provider->mediasize;
		if (*(off_t *)data == 0)
			error = ENOENT;
		break;
	case DIOCGFWSECTORS:
		error = g_io_getattr("GEOM::fwsectors", cp, &i, data);
		if (error == 0 && *(u_int *)data == 0)
			error = ENOENT;
		break;
	case DIOCGFWHEADS:
		error = g_io_getattr("GEOM::fwheads", cp, &i, data);
		if (error == 0 && *(u_int *)data == 0)
			error = ENOENT;
		break;
	case DIOCGFRONTSTUFF:
		error = g_io_getattr("GEOM::frontstuff", cp, &i, data);
		break;
	case DIOCSKERNELDUMP:
		u = *((u_int *)data);
		if (!u) {
			set_dumper(NULL);
			error = 0;
			break;
		}
		kd.offset = 0;
		kd.length = OFF_MAX;
		i = sizeof kd;
		error = g_io_getattr("GEOM::kerneldump", cp, &i, &kd);
		if (!error)
			dev->si_flags |= SI_DUMPDEV;
		break;

	default:
		gio = g_malloc(sizeof *gio, M_ZERO);
		gio->cmd = cmd;
		gio->data = data;
		gio->fflag = fflag;
		gio->td = td;
		i = sizeof *gio;
		/*
		 * We always issue ioctls as getattr since the direction of data
		 * movement in ioctl is no indication of the ioctl being a "set"
		 * or "get" type ioctl or if such simplistic terms even apply
		 */
		error = g_io_getattr("GEOM::ioctl", cp, &i, gio);
		break;
	}

	PICKUP_GIANT();
	if (error == EDIRIOCTL) {
		KASSERT(gio != NULL, ("NULL gio but EDIRIOCTL"));
		KASSERT(gio->func != NULL, ("NULL function but EDIRIOCTL"));
		error = (gio->func)(gio->dev, cmd, data, fflag, td);
	}
	g_waitidle();
	if (gio != NULL && (error == EOPNOTSUPP || error == ENOIOCTL)) {
		if (g_debugflags & G_T_TOPOLOGY) {
			i = IOCGROUP(cmd);
			printf("IOCTL(0x%lx) \"%s\"", cmd, gp->name);
			if (i > ' ' && i <= '~')
				printf(" '%c'", (int)IOCGROUP(cmd));
			else
				printf(" 0x%lx", IOCGROUP(cmd));
			printf("/%ld ", cmd & 0xff);
			if (cmd & IOC_IN)
				printf("I");
			if (cmd & IOC_OUT)
				printf("O");
			printf("(%ld) = ENOIOCTL\n", IOCPARM_LEN(cmd));
		}
		error = ENOTTY;
	}
	if (gio != NULL)
		g_free(gio);
	return (error);
}

static int
g_dev_psize(dev_t dev)
{
	struct g_consumer *cp;
	off_t mediasize;

	cp = dev->si_drv2;

	mediasize = cp->provider->mediasize;
	return (mediasize >> DEV_BSHIFT);
}

static void
g_dev_done(struct bio *bp2)
{
	struct bio *bp;

	bp = bp2->bio_parent;
	bp->bio_error = bp2->bio_error;
	if (bp->bio_error != 0) {
		g_trace(G_T_BIO, "g_dev_done(%p) had error %d",
		    bp2, bp->bio_error);
		bp->bio_flags |= BIO_ERROR;
	} else {
		g_trace(G_T_BIO, "g_dev_done(%p/%p) resid %ld completed %jd",
		    bp2, bp, bp->bio_resid, (intmax_t)bp2->bio_completed);
	}
	bp->bio_resid = bp->bio_bcount - bp2->bio_completed;
	g_destroy_bio(bp2);
	mtx_lock(&Giant);
	biodone(bp);
	mtx_unlock(&Giant);
}

static void
g_dev_strategy(struct bio *bp)
{
	struct g_geom *gp;
	struct g_consumer *cp;
	struct bio *bp2;
	dev_t dev;

	KASSERT(bp->bio_cmd == BIO_READ ||
	        bp->bio_cmd == BIO_WRITE ||
	        bp->bio_cmd == BIO_DELETE,
		("Wrong bio_cmd bio=%p cmd=%d", bp, bp->bio_cmd));
	dev = bp->bio_dev;
	gp = dev->si_drv1;
	cp = dev->si_drv2;
	bp2 = g_clone_bio(bp);
	KASSERT(bp2 != NULL, ("XXX: ENOMEM in a bad place"));
	bp2->bio_offset = (off_t)bp->bio_blkno << DEV_BSHIFT;
	KASSERT(bp2->bio_offset >= 0,
	    ("Negative bio_offset (%jd) on bio %p",
	    (intmax_t)bp2->bio_offset, bp));
	bp2->bio_length = (off_t)bp->bio_bcount;
	bp2->bio_done = g_dev_done;
	g_trace(G_T_BIO,
	    "g_dev_strategy(%p/%p) offset %jd length %jd data %p cmd %d",
	    bp, bp2, (intmax_t)bp->bio_offset, (intmax_t)bp2->bio_length,
	    bp2->bio_data, bp2->bio_cmd);
	g_io_request(bp2, cp);
}

/*
 * g_dev_orphan()
 *
 * Called from below when the provider orphaned us.  It is our responsibility
 * to get the access counts back to zero, until we do so the stack below will
 * not unravel.  We must clear the kernel-dump settings, if this is the
 * current dumpdev.  We call destroy_dev(9) to send our dev_t the way of
 * punched cards and if we have non-zero access counts, we call down with
 * them negated before we detattch and selfdestruct.
 */

static void
g_dev_orphan(struct g_consumer *cp)
{
	struct g_geom *gp;
	dev_t dev;

	gp = cp->geom;
	g_trace(G_T_TOPOLOGY, "g_dev_orphan(%p(%s))", cp, gp->name);
	g_topology_assert();
	if (cp->stat->nop != cp->stat->nend)	/* XXX ? */
		return;
	dev = gp->softc;
	if (dev->si_flags & SI_DUMPDEV)
		set_dumper(NULL);
	/* XXX: we may need Giant for now */
	destroy_dev(dev);
	if (cp->acr > 0 || cp->acw > 0 || cp->ace > 0)
		g_access_rel(cp, -cp->acr, -cp->acw, -cp->ace);
	g_detach(cp);
	g_destroy_consumer(cp);
	g_destroy_geom(gp);
}

DECLARE_GEOM_CLASS(g_dev_class, g_dev);
