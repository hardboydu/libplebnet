/*-
 * Parts Copyright (c) 1995 Terrence R. Lambert
 * Copyright (c) 1995 Julian R. Elischer
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Terrence R. Lambert.
 * 4. The name Terrence R. Lambert may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Julian R. Elischer ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE TERRENCE R. LAMBERT BE LIABLE
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
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/conf.h>
#include <sys/vnode.h>
#include <sys/queue.h>
#include <machine/stdarg.h>

#define cdevsw_ALLOCSTART	(NUMCDEVSW/2)

struct cdevsw 	*cdevsw[NUMCDEVSW];

static int	bmaj2cmaj[NUMCDEVSW];

MALLOC_DEFINE(M_DEVT, "dev_t", "dev_t storage");

/*
 * This is the number of hash-buckets.  Experiements with 'real-life'
 * udev_t's show that a prime halfway between two powers of two works
 * best.
 */
#define DEVT_HASH 83

/* The number of dev_t's we can create before malloc(9) kick in.  */
#define DEVT_STASH 50

static struct specinfo devt_stash[DEVT_STASH];

static LIST_HEAD(, specinfo) dev_hash[DEVT_HASH];

static LIST_HEAD(, specinfo) dev_free;

devfs_create_t *devfs_create_hook;
devfs_remove_t *devfs_remove_hook;

static int free_devt;
SYSCTL_INT(_debug, OID_AUTO, free_devt, CTLFLAG_RW, &free_devt, 0, "");

/*
 * Routine to convert from character to block device number.
 *
 * A minimal stub routine can always return NODEV.
 */
dev_t
chrtoblk(dev_t dev)
{
	struct cdevsw *cd;

	if((cd = devsw(dev)) != NULL) {
          if (cd->d_bmaj != -1)
	    return(makebdev(cd->d_bmaj,minor(dev)));
	}
	return(NODEV);
}

struct cdevsw *
devsw(dev_t dev)
{       
	if (dev->si_devsw)
		return (dev->si_devsw);
        return(cdevsw[major(dev)]);
}

/*
 *  Add a cdevsw entry
 */

int
cdevsw_add(struct cdevsw *newentry)
{
	int i;
	static int setup;

	if (!setup) {
		for (i = 0; i < NUMCDEVSW; i++)
			if (!bmaj2cmaj[i])
				bmaj2cmaj[i] = 254;
		setup++;
	}

	if (newentry->d_maj < 0 || newentry->d_maj >= NUMCDEVSW) {
		printf("%s: ERROR: driver has bogus cdevsw->d_maj = %d\n",
		    newentry->d_name, newentry->d_maj);
		return EINVAL;
	}

	if (cdevsw[newentry->d_maj]) {
		printf("WARNING: \"%s\" is usurping \"%s\"'s cdevsw[]\n",
		    newentry->d_name, cdevsw[newentry->d_maj]->d_name);
	}
	cdevsw[newentry->d_maj] = newentry;

	if (newentry->d_bmaj >= 0 && newentry->d_bmaj < NUMCDEVSW) {
		if (bmaj2cmaj[newentry->d_bmaj] != 254) {
			printf("WARNING: \"%s\" is usurping \"%s\"'s bmaj\n",
			    newentry->d_name, 
			    cdevsw[bmaj2cmaj[newentry->d_bmaj]]->d_name);
		}
		bmaj2cmaj[newentry->d_bmaj] = newentry->d_maj;
	}

	return 0;
} 

/*
 *  Remove a cdevsw entry
 */

int
cdevsw_remove(struct cdevsw *oldentry)
{
	if (oldentry->d_maj < 0 || oldentry->d_maj >= NUMCDEVSW) {
		printf("%s: ERROR: driver has bogus cdevsw->d_maj = %d\n",
		    oldentry->d_name, oldentry->d_maj);
		return EINVAL;
	}

	cdevsw[oldentry->d_maj] = NULL;

	if (oldentry->d_bmaj >= 0 && oldentry->d_bmaj < NUMCDEVSW) 
		bmaj2cmaj[oldentry->d_bmaj] = 254;

	return 0;
} 

int
devsw_module_handler(module_t mod, int what, void* arg)
{
	struct devsw_module_data* data = (struct devsw_module_data*) arg;
	int error = 0;

	switch (what) {
	case MOD_LOAD:
		error = cdevsw_add(data->cdevsw);
		if (!error && data->chainevh)
			error = data->chainevh(mod, what, data->chainarg);
		return error;

	case MOD_UNLOAD:
		if (data->chainevh) {
			error = data->chainevh(mod, what, data->chainarg);
			if (error)
				return error;
		}
		cdevsw_remove(data->cdevsw);
		return error;
	}

	if (data->chainevh)
		return data->chainevh(mod, what, data->chainarg);
	else
		return 0;
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
lminor(dev_t x)
{
	int i;

	if (x == NODEV)
		return NOUDEV;
	i = minor(x);
	return ((i & 0xff) | (i >> 8));
}

dev_t
makebdev(int x, int y)
{
	return (makedev(bmaj2cmaj[x], y));
}

dev_t
makedev(int x, int y)
{
	struct specinfo *si;
	udev_t	udev;
	int hash;
	static int stashed;

	udev = (x << 8) | y;
	hash = udev % DEVT_HASH;
	LIST_FOREACH(si, &dev_hash[hash], si_hash) {
		if (si->si_udev == udev)
			return (si);
	}
	if (stashed >= DEVT_STASH) {
		MALLOC(si, struct specinfo *, sizeof(*si), M_DEVT, 
		    M_USE_RESERVE);
		bzero(si, sizeof(*si));
	} else if (LIST_FIRST(&dev_free)) {
		si = LIST_FIRST(&dev_free);
		LIST_REMOVE(si, si_hash);
	} else {
		si = devt_stash + stashed++;
		si->si_flags |= SI_STASHED;
	}
	si->si_udev = udev;
	LIST_INSERT_HEAD(&dev_hash[hash], si, si_hash);
        return (si);
}

void
freedev(dev_t dev)
{
	int hash;

	if (!free_devt)
		return;
	if (SLIST_FIRST(&dev->si_hlist))
		return;
	if (dev->si_devsw || dev->si_drv1 || dev->si_drv2) 
		return;
	hash = dev->si_udev % DEVT_HASH;
	LIST_REMOVE(dev, si_hash);
	if (dev->si_flags & SI_STASHED) {
		bzero(dev, sizeof(*dev));
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

udev_t
dev2budev(dev_t x)
{
	if (x == NODEV)
		return NOUDEV;
	else
		return makeudev(devsw(x)->d_bmaj, minor(x));
}

dev_t
udev2dev(udev_t x, int b)
{
	switch (b) {
		case 0:
			return makedev(umajor(x), uminor(x));
		case 1:
			return makebdev(umajor(x), uminor(x));
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
make_dev(struct cdevsw *devsw, int minor, uid_t uid, gid_t gid, int perms, char *fmt, ...)
{
	dev_t	dev;
	va_list ap;
	int i;

	dev = makedev(devsw->d_maj, minor);
	va_start(ap, fmt);
	i = kvprintf(fmt, NULL, dev->si_name, 32, ap);
	dev->si_name[i] = '\0';
	va_end(ap);
	dev->si_devsw = devsw;

	if (devfs_create_hook)
		devfs_create_hook(dev, uid, gid, perms);
	return (dev);
}

void
remove_dev(dev_t dev)
{
	if (devfs_remove_hook)
		devfs_remove_hook(dev);
	dev->si_drv1 = 0;
	dev->si_drv2 = 0;
	dev->si_devsw = 0;
	freedev(dev);
}

char *
devtoname(dev_t dev)
{
	char *p;

	if (dev->si_name[0] == '#' || dev->si_name[0] == '\0') {
		p = dev->si_name;
		if (devsw(dev))
			sprintf(p, "#%s/", devsw(dev)->d_name);
		else
			sprintf(p, "#%d/", major(dev));
		p += strlen(p);
		sprintf(p, minor(dev) > 255 ? "0x%x" : "%d", minor(dev));
	}
	return (dev->si_name);
}

