/*-
 * Copyright (c) 1999-2002 Poul-Henning Kamp
 * All rights reserved.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sysctl.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/conf.h>
#include <sys/vnode.h>
#include <sys/queue.h>
#include <sys/ctype.h>
#include <machine/stdarg.h>

static MALLOC_DEFINE(M_DEVT, "dev_t", "dev_t storage");

/* Built at compile time from sys/conf/majors */
extern unsigned char reserved_majors[256];

/*
 * This is the number of hash-buckets.  Experiements with 'real-life'
 * udev_t's show that a prime halfway between two powers of two works
 * best.
 */
#define DEVT_HASH 83

/* The number of dev_t's we can create before malloc(9) kick in.  */
#define DEVT_STASH 50

static struct cdev devt_stash[DEVT_STASH];

static LIST_HEAD(, cdev) dev_hash[DEVT_HASH];

static LIST_HEAD(, cdev) dev_free;

static int ready_for_devs;

static int free_devt;
SYSCTL_INT(_debug, OID_AUTO, free_devt, CTLFLAG_RW, &free_devt, 0, "");

/* Define a dead_cdevsw for use when devices leave unexpectedly. */

static int
enxio(void)
{
	return (ENXIO);
}

#define dead_open	(d_open_t *)enxio
#define dead_close	(d_close_t *)enxio
#define dead_read	(d_read_t *)enxio
#define dead_write	(d_write_t *)enxio
#define dead_ioctl	(d_ioctl_t *)enxio
#define dead_poll	nopoll
#define dead_mmap	nommap

static void
dead_strategy(struct bio *bp)
{

	biofinish(bp, NULL, ENXIO);
}

#define dead_dump	(dumper_t *)enxio

#define dead_kqfilter	(d_kqfilter_t *)enxio

static struct cdevsw dead_cdevsw = {
	.d_open =	dead_open,
	.d_close =	dead_close,
	.d_read =	dead_read,
	.d_write =	dead_write,
	.d_ioctl =	dead_ioctl,
	.d_poll =	dead_poll,
	.d_mmap =	dead_mmap,
	.d_strategy =	dead_strategy,
	.d_name =	"dead",
	.d_maj =	255,
	.d_dump =	dead_dump,
	.d_kqfilter =	dead_kqfilter
};


struct cdevsw *
devsw(dev_t dev)
{
	if (dev->si_devsw)
		return (dev->si_devsw);
	return (&dead_cdevsw);
}

/*
 * dev_t and u_dev_t primitives
 */

int
major(dev_t x)
{
	if (x == NODEV)
		return NOUDEV;
	return((x->si_udev >> 8) & 0xff);
}

int
minor(dev_t x)
{
	if (x == NODEV)
		return NOUDEV;
	return(x->si_udev & 0xffff00ff);
}

int
dev2unit(dev_t x)
{
	int i;

	if (x == NODEV)
		return NOUDEV;
	i = minor(x);
	return ((i & 0xff) | (i >> 8));
}

int
unit2minor(int unit)
{

	KASSERT(unit <= 0xffffff, ("Invalid unit (%d) in unit2minor", unit));
	return ((unit & 0xff) | ((unit << 8) & ~0xffff));
}

static dev_t
allocdev(void)
{
	static int stashed;
	struct cdev *si;

	if (LIST_FIRST(&dev_free)) {
		si = LIST_FIRST(&dev_free);
		LIST_REMOVE(si, si_hash);
	} else if (stashed >= DEVT_STASH) {
		MALLOC(si, struct cdev *, sizeof(*si), M_DEVT,
		    M_USE_RESERVE | M_ZERO | M_WAITOK);
	} else {
		si = devt_stash + stashed++;
		bzero(si, sizeof *si);
		si->si_flags |= SI_STASHED;
	}
	si->__si_namebuf[0] = '\0';
	si->si_name = si->__si_namebuf;
	LIST_INIT(&si->si_children);
	TAILQ_INIT(&si->si_snapshots);
	return (si);
}

dev_t
makedev(int x, int y)
{
	struct cdev *si;
	udev_t	udev;
	int hash;

	if (x == umajor(NOUDEV) && y == uminor(NOUDEV))
		panic("makedev of NOUDEV");
	udev = (x << 8) | y;
	hash = udev % DEVT_HASH;
	LIST_FOREACH(si, &dev_hash[hash], si_hash) {
		if (si->si_udev == udev)
			return (si);
	}
	si = allocdev();
	si->si_udev = udev;
	LIST_INSERT_HEAD(&dev_hash[hash], si, si_hash);
        return (si);
}

void
freedev(dev_t dev)
{

	if (!free_devt)
		return;
	if (SLIST_FIRST(&dev->si_hlist))
		return;
	if (dev->si_devsw || dev->si_drv1 || dev->si_drv2)
		return;
	LIST_REMOVE(dev, si_hash);
	if (dev->si_flags & SI_STASHED) {
		bzero(dev, sizeof(*dev));
		dev->si_flags |= SI_STASHED;
		LIST_INSERT_HEAD(&dev_free, dev, si_hash);
	} else {
		FREE(dev, M_DEVT);
	}
}

udev_t
dev2udev(dev_t x)
{
	if (x == NODEV)
		return NOUDEV;
	return (x->si_udev);
}

dev_t
udev2dev(udev_t x, int b)
{

	if (x == NOUDEV)
		return (NODEV);
	switch (b) {
		case 0:
			return makedev(umajor(x), uminor(x));
		case 1:
			return (NODEV);
		default:
			Debugger("udev2dev(...,X)");
			return NODEV;
	}
}

int
uminor(udev_t dev)
{
	return(dev & 0xffff00ff);
}

int
umajor(udev_t dev)
{
	return((dev & 0xff00) >> 8);
}

udev_t
makeudev(int x, int y)
{
        return ((x << 8) | y);
}

dev_t
make_dev(struct cdevsw *devsw, int minor, uid_t uid, gid_t gid, int perms, const char *fmt, ...)
{
	dev_t	dev;
	va_list ap;
	int i;

	KASSERT((minor & ~0xffff00ff) == 0,
	    ("Invalid minor (0x%x) in make_dev", minor));

	if (devsw->d_open == NULL)	devsw->d_open = nullopen;
	if (devsw->d_close == NULL)	devsw->d_close = nullclose;
	if (devsw->d_read == NULL)	devsw->d_read = noread;
	if (devsw->d_write == NULL)	devsw->d_write = nowrite;
	if (devsw->d_ioctl == NULL)	devsw->d_ioctl = noioctl;
	if (devsw->d_poll == NULL)	devsw->d_poll = nopoll;
	if (devsw->d_mmap == NULL)	devsw->d_mmap = nommap;
	if (devsw->d_strategy == NULL)	devsw->d_strategy = nostrategy;
	if (devsw->d_dump == NULL)	devsw->d_dump = nodump;
	if (devsw->d_kqfilter == NULL)	devsw->d_kqfilter = nokqfilter;

	if (devsw->d_maj == MAJOR_AUTO) {
		for (i = NUMCDEVSW - 1; i > 0; i--)
			if (reserved_majors[i] != i)
				break;
		KASSERT(i > 0, ("Out of major numbers (%s)", devsw->d_name));
		devsw->d_maj = i;
		reserved_majors[i] = i;
	} else {
		if (devsw->d_maj == 256)	/* XXX: tty_cons.c is magic */
			devsw->d_maj = 0;	
		KASSERT(devsw->d_maj >= 0 && devsw->d_maj < 256,
		    ("Invalid major (%d) in make_dev", devsw->d_maj));
		if (reserved_majors[devsw->d_maj] != devsw->d_maj) {
			printf("WARNING: driver \"%s\" used %s %d\n",
			    devsw->d_name, "unreserved major device number",
			    devsw->d_maj);
			reserved_majors[devsw->d_maj] = devsw->d_maj;
		}
	}

	if (!ready_for_devs) {
		printf("WARNING: Driver mistake: make_dev(%s) called before SI_SUB_DRIVERS\n",
		       fmt);
		/* XXX panic here once drivers are cleaned up */
	}

	dev = makedev(devsw->d_maj, minor);
	if (dev->si_flags & SI_NAMED) {
		printf( "WARNING: Driver mistake: repeat make_dev(\"%s\")\n",
		    dev->si_name);
		panic("don't do that");
	}
	va_start(ap, fmt);
	i = vsnrprintf(dev->__si_namebuf, sizeof dev->__si_namebuf, 32, fmt, ap);
	if (i > (sizeof dev->__si_namebuf - 1)) {
		printf("WARNING: Device name truncated! (%s)", 
		    dev->__si_namebuf);
	}
	va_end(ap);
	dev->si_devsw = devsw;
	dev->si_uid = uid;
	dev->si_gid = gid;
	dev->si_mode = perms;
	dev->si_flags |= SI_NAMED;

	devfs_create(dev);
	return (dev);
}

int
dev_named(dev_t pdev, const char *name)
{
	dev_t cdev;

	if (strcmp(devtoname(pdev), name) == 0)
		return (1);
	LIST_FOREACH(cdev, &pdev->si_children, si_siblings)
		if (strcmp(devtoname(cdev), name) == 0)
			return (1);
	return (0);
}

void
dev_depends(dev_t pdev, dev_t cdev)
{

	cdev->si_parent = pdev;
	cdev->si_flags |= SI_CHILD;
	LIST_INSERT_HEAD(&pdev->si_children, cdev, si_siblings);
}

dev_t
make_dev_alias(dev_t pdev, const char *fmt, ...)
{
	dev_t	dev;
	va_list ap;
	int i;

	dev = allocdev();
	dev->si_flags |= SI_ALIAS;
	dev->si_flags |= SI_NAMED;
	dev_depends(pdev, dev);
	va_start(ap, fmt);
	i = vsnrprintf(dev->__si_namebuf, sizeof dev->__si_namebuf, 32, fmt, ap);
	if (i > (sizeof dev->__si_namebuf - 1)) {
		printf("WARNING: Device name truncated! (%s)", 
		    dev->__si_namebuf);
	}
	va_end(ap);

	devfs_create(dev);
	return (dev);
}

void
revoke_and_destroy_dev(dev_t dev)
{
	struct vnode *vp;

	GIANT_REQUIRED;

	vp = SLIST_FIRST(&dev->si_hlist);
	if (vp != NULL)
		VOP_REVOKE(vp, REVOKEALL);
	destroy_dev(dev);
}

void
destroy_dev(dev_t dev)
{
	
	if (!(dev->si_flags & SI_NAMED)) {
		printf( "WARNING: Driver mistake: destroy_dev on %d/%d\n",
		    major(dev), minor(dev));
		panic("don't do that");
	}
		
	devfs_destroy(dev);
	if (dev->si_flags & SI_CHILD) {
		LIST_REMOVE(dev, si_siblings);
		dev->si_flags &= ~SI_CHILD;
	}
	while (!LIST_EMPTY(&dev->si_children))
		destroy_dev(LIST_FIRST(&dev->si_children));
	dev->si_drv1 = 0;
	dev->si_drv2 = 0;
	dev->si_devsw = 0;
	bzero(&dev->__si_u, sizeof(dev->__si_u));
	dev->si_flags &= ~SI_NAMED;
	dev->si_flags &= ~SI_ALIAS;
	freedev(dev);
}

const char *
devtoname(dev_t dev)
{
	char *p;
	int mynor;

	if (dev->si_name[0] == '#' || dev->si_name[0] == '\0') {
		p = dev->si_name;
		if (devsw(dev))
			sprintf(p, "#%s/", devsw(dev)->d_name);
		else
			sprintf(p, "#%d/", major(dev));
		p += strlen(p);
		mynor = minor(dev);
		if (mynor < 0 || mynor > 255)
			sprintf(p, "%#x", (u_int)mynor);
		else
			sprintf(p, "%d", mynor);
	}
	return (dev->si_name);
}

int
dev_stdclone(char *name, char **namep, const char *stem, int *unit)
{
	int u, i;

	i = strlen(stem);
	if (bcmp(stem, name, i) != 0)
		return (0);
	if (!isdigit(name[i]))
		return (0);
	u = 0;
	if (name[i] == '0' && isdigit(name[i+1]))
		return (0);
	while (isdigit(name[i])) {
		u *= 10;
		u += name[i++] - '0';
	}
	if (u > 0xffffff)
		return (0);
	*unit = u;
	if (namep)
		*namep = &name[i];
	if (name[i]) 
		return (2);
	return (1);
}

/*
 * Helper sysctl for devname(3).  We're given a {u}dev_t and return
 * the name, if any, registered by the device driver.
 */
static int
sysctl_devname(SYSCTL_HANDLER_ARGS)
{
	int error;
	udev_t ud;
	dev_t dev;

	error = SYSCTL_IN(req, &ud, sizeof (ud));
	if (error)
		return (error);
	if (ud == NOUDEV)
		return(EINVAL);
	dev = makedev(umajor(ud), uminor(ud));
	if (dev->si_name[0] == '\0')
		error = ENOENT;
	else
		error = SYSCTL_OUT(req, dev->si_name, strlen(dev->si_name) + 1);
	freedev(dev);
	return (error);
}

SYSCTL_PROC(_kern, OID_AUTO, devname, CTLTYPE_OPAQUE|CTLFLAG_RW|CTLFLAG_ANYBODY,
	NULL, 0, sysctl_devname, "", "devname(3) handler");

/*
 * Set ready_for_devs; prior to this point, device creation is not allowed.
 */	
static void
dev_set_ready(void *junk)
{
	ready_for_devs = 1;
}

SYSINIT(dev_ready, SI_SUB_DEVFS, SI_ORDER_FIRST, dev_set_ready, NULL);
