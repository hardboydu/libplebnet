/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@FreeBSD.ORG> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * $FreeBSD$
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/bio.h>
#include <sys/conf.h>
#include <sys/disk.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>
#include <machine/md_var.h>
#include <sys/ctype.h>

static MALLOC_DEFINE(M_DISK, "disk", "disk data");

static d_strategy_t diskstrategy;
static d_open_t diskopen;
static d_close_t diskclose; 
static d_ioctl_t diskioctl;
static d_psize_t diskpsize;

static LIST_HEAD(, disk) disklist = LIST_HEAD_INITIALIZER(&disklist);

static void
disk_clone(void *arg, char *name, int namelen, dev_t *dev)
{
	struct disk *dp;
	char const *d;
	int i, u, s, p;
	dev_t pdev;

	if (*dev != NODEV)
		return;

	LIST_FOREACH(dp, &disklist, d_list) {
		d = dp->d_devsw->d_name;
		i = strlen(d);
		if (bcmp(d, name, i) != 0)
			continue;
		u = 0;
		if (!isdigit(name[i]))
			continue;
		while (isdigit(name[i])) {
			u *= 10;
			u += name[i++] - '0';
		}
		if (u > DKMAXUNIT)
			continue;
		p = RAW_PART;
		s = WHOLE_DISK_SLICE;
		pdev = makedev(dp->d_devsw->d_maj, dkmakeminor(u, s, p));
		if (pdev->si_disk == NULL)
			continue;
		if (name[i] != '\0') {
			if (name[i] == 's') {
				s = 0;
				i++;
				if (!isdigit(name[i]))
					continue;
				while (isdigit(name[i])) {
					s *= 10;
					s += name[i++] - '0';
				}
				s += BASE_SLICE - 1;
			} else {
				s = COMPATIBILITY_SLICE;
			}
			if (name[i] == '\0')
				;
			else if (name[i] < 'a' || name[i] > 'h')
				continue;
			else
				p = name[i] - 'a';
		}

		*dev = make_dev(pdev->si_devsw, dkmakeminor(u, s, p), 
		    UID_ROOT, GID_OPERATOR, 0640, name);
		return;
	}
}

static void
inherit_raw(dev_t pdev, dev_t dev)
{
	dev->si_disk = pdev->si_disk;
	dev->si_drv1 = pdev->si_drv1;
	dev->si_drv2 = pdev->si_drv2;
	dev->si_iosize_max = pdev->si_iosize_max;
	dev->si_bsize_phys = pdev->si_bsize_phys;
	dev->si_bsize_best = pdev->si_bsize_best;
}

dev_t
disk_create(int unit, struct disk *dp, int flags, struct cdevsw *cdevsw, struct cdevsw *proto)
{
	static int once;
	dev_t dev;

	bzero(dp, sizeof(*dp));

	dev = makedev(cdevsw->d_maj, 0);	
	if (!devsw(dev)) {
		*proto = *cdevsw;
		proto->d_open = diskopen;
		proto->d_close = diskclose;
		proto->d_ioctl = diskioctl;
		proto->d_strategy = diskstrategy;
		proto->d_psize = diskpsize;
		cdevsw_add(proto);
	}

	if (bootverbose)
		printf("Creating DISK %s%d\n", cdevsw->d_name, unit);
	dev = make_dev(proto, dkmakeminor(unit, WHOLE_DISK_SLICE, RAW_PART),
	    UID_ROOT, GID_OPERATOR, 0640, "%s%d", cdevsw->d_name, unit);

	dev->si_disk = dp;
	dp->d_dev = dev;
	dp->d_dsflags = flags;
	dp->d_devsw = cdevsw;
	LIST_INSERT_HEAD(&disklist, dp, d_list);
	if (!once) {
		EVENTHANDLER_REGISTER(dev_clone, disk_clone, 0, 1000);
		once++;
	}
	return (dev);
}

int
disk_dumpcheck(dev_t dev, u_int *count, u_int *blkno, u_int *secsize)
{
	struct disk *dp;
	struct disklabel *dl;
	u_int boff;

	dp = dev->si_disk;
	if (!dp)
		return (ENXIO);
	if (!dp->d_slice)
		return (ENXIO);
	dl = dsgetlabel(dev, dp->d_slice);
	if (!dl)
		return (ENXIO);
	*count = (u_long)Maxmem * PAGE_SIZE / dl->d_secsize;
	if (dumplo < 0 || 
	    (dumplo + *count > dl->d_partitions[dkpart(dev)].p_size))
		return (EINVAL);
	boff = dl->d_partitions[dkpart(dev)].p_offset +
	    dp->d_slice->dss_slices[dkslice(dev)].ds_offset;
	*blkno = boff + dumplo;
	*secsize = dl->d_secsize;
	return (0);
	
}

void 
disk_invalidate (struct disk *disk)
{
	if (disk->d_slice)
		dsgone(&disk->d_slice);
}

void
disk_destroy(dev_t dev)
{
	LIST_REMOVE(dev->si_disk, d_list);
	bzero(dev->si_disk, sizeof(*dev->si_disk));
    	dev->si_disk = NULL;
	destroy_dev(dev);
	return;
}

struct disk *
disk_enumerate(struct disk *disk)
{
	if (!disk)
		return (LIST_FIRST(&disklist));
	else
		return (LIST_NEXT(disk, d_list));
}

static int
sysctl_disks(SYSCTL_HANDLER_ARGS)
{
	struct disk *disk;
	int error, first;

	disk = NULL;
	first = 1;

	while ((disk = disk_enumerate(disk))) {
		if (!first) {
			error = SYSCTL_OUT(req, " ", 1);
			if (error)
				return error;
		} else {
			first = 0;
		}
		error = SYSCTL_OUT(req, disk->d_dev->si_name, strlen(disk->d_dev->si_name));
		if (error)
			return error;
	}
	error = SYSCTL_OUT(req, "", 1);
	return error;
}
 
SYSCTL_PROC(_kern, OID_AUTO, disks, CTLTYPE_STRING | CTLFLAG_RD, 0, NULL, 
    sysctl_disks, "A", "names of available disks");

/*
 * The cdevsw functions
 */

static int
diskopen(dev_t dev, int oflags, int devtype, struct proc *p)
{
	dev_t pdev;
	struct disk *dp;
	int error;

	error = 0;
	pdev = dkmodpart(dkmodslice(dev, WHOLE_DISK_SLICE), RAW_PART);

	dp = pdev->si_disk;
	if (!dp)
		return (ENXIO);

	while (dp->d_flags & DISKFLAG_LOCK) {
		dp->d_flags |= DISKFLAG_WANTED;
		error = tsleep(dp, PRIBIO | PCATCH, "diskopen", hz);
		if (error)
			return (error);
	}
	dp->d_flags |= DISKFLAG_LOCK;

	if (!dsisopen(dp->d_slice)) {
		if (!pdev->si_iosize_max)
			pdev->si_iosize_max = dev->si_iosize_max;
		error = dp->d_devsw->d_open(pdev, oflags, devtype, p);
	}

	/* Inherit properties from the whole/raw dev_t */
	inherit_raw(pdev, dev);

	if (error)
		goto out;
	
	error = dsopen(dev, devtype, dp->d_dsflags, &dp->d_slice, &dp->d_label);

	if (!dsisopen(dp->d_slice)) 
		dp->d_devsw->d_close(pdev, oflags, devtype, p);
out:	
	dp->d_flags &= ~DISKFLAG_LOCK;
	if (dp->d_flags & DISKFLAG_WANTED) {
		dp->d_flags &= ~DISKFLAG_WANTED;
		wakeup(dp);
	}
	
	return(error);
}

static int
diskclose(dev_t dev, int fflag, int devtype, struct proc *p)
{
	struct disk *dp;
	int error;
	dev_t pdev;

	error = 0;
	pdev = dkmodpart(dkmodslice(dev, WHOLE_DISK_SLICE), RAW_PART);
	dp = pdev->si_disk;
	dsclose(dev, devtype, dp->d_slice);
	if (!dsisopen(dp->d_slice)) {
		error = dp->d_devsw->d_close(dp->d_dev, fflag, devtype, p);
	}
	return (error);
}

static void
diskstrategy(struct bio *bp)
{
	dev_t pdev;
	struct disk *dp;

	pdev = dkmodpart(dkmodslice(bp->bio_dev, WHOLE_DISK_SLICE), RAW_PART);
	dp = pdev->si_disk;
	if (dp != bp->bio_dev->si_disk)
		inherit_raw(pdev, bp->bio_dev);

	if (!dp) {
		bp->bio_error = ENXIO;
		bp->bio_flags |= BIO_ERROR;
		biodone(bp);
		return;
	}

	if (dscheck(bp, dp->d_slice) <= 0) {
		biodone(bp);
		return;
	}

	KASSERT(dp->d_devsw != NULL, ("NULL devsw"));
	KASSERT(dp->d_devsw->d_strategy != NULL, ("NULL d_strategy"));
	dp->d_devsw->d_strategy(bp);
	return;
	
}

static int
diskioctl(dev_t dev, u_long cmd, caddr_t data, int fflag, struct proc *p)
{
	struct disk *dp;
	int error;
	dev_t pdev;

	pdev = dkmodpart(dkmodslice(dev, WHOLE_DISK_SLICE), RAW_PART);
	dp = pdev->si_disk;
	error = dsioctl(dev, cmd, data, fflag, &dp->d_slice);
	if (error == ENOIOCTL)
		error = dp->d_devsw->d_ioctl(dev, cmd, data, fflag, p);
	return (error);
}

static int
diskpsize(dev_t dev)
{
	struct disk *dp;
	dev_t pdev;

	pdev = dkmodpart(dkmodslice(dev, WHOLE_DISK_SLICE), RAW_PART);
	dp = pdev->si_disk;
	if (!dp)
		return (-1);
	if (dp != dev->si_disk) {
		dev->si_drv1 = pdev->si_drv1;
		dev->si_drv2 = pdev->si_drv2;
		/* XXX: don't set bp->b_dev->si_disk (?) */
	}
	return (dssize(dev, &dp->d_slice));
}

SYSCTL_DECL(_debug_sizeof);

SYSCTL_INT(_debug_sizeof, OID_AUTO, disklabel, CTLFLAG_RD, 
    0, sizeof(struct disklabel), "sizeof(struct disklabel)");

SYSCTL_INT(_debug_sizeof, OID_AUTO, diskslices, CTLFLAG_RD, 
    0, sizeof(struct diskslices), "sizeof(struct diskslices)");

SYSCTL_INT(_debug_sizeof, OID_AUTO, disk, CTLFLAG_RD, 
    0, sizeof(struct disk), "sizeof(struct disk)");
