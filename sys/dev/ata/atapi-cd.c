/*-
 * Copyright (c) 1998,1999,2000 S�ren Schmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification, immediately at the beginning of the file.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include "apm.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/buf.h>
#include <sys/bus.h>
#include <sys/disklabel.h>
#include <sys/devicestat.h>
#include <sys/cdio.h>
#include <sys/cdrio.h>
#include <sys/dvdio.h>
#include <sys/fcntl.h>
#include <sys/conf.h>
#include <sys/stat.h>
#if NAPM > 0
#include <machine/apm_bios.h>
#endif
#include <dev/ata/ata-all.h>
#include <dev/ata/atapi-all.h>
#include <dev/ata/atapi-cd.h>

static d_open_t		acdopen;
static d_close_t	acdclose;
static d_ioctl_t	acdioctl;
static d_strategy_t	acdstrategy;

static struct cdevsw acd_cdevsw = {
	/* open */	acdopen,
	/* close */	acdclose,
	/* read */	physread,
	/* write */	physwrite,
	/* ioctl */	acdioctl,
	/* poll */	nopoll,
	/* mmap */	nommap,
	/* strategy */	acdstrategy,
	/* name */	"acd",
	/* maj */	117,
	/* dump */	nodump,
	/* psize */	nopsize,
	/* flags */	D_DISK,
	/* bmaj */	31
};

/* prototypes */
int32_t acdattach(struct atapi_softc *);
static struct acd_softc *acd_init_lun(struct atapi_softc *, int32_t, struct devstat *);
static void acd_describe(struct acd_softc *);
static void lba2msf(int32_t, u_int8_t *, u_int8_t *, u_int8_t *);
static int32_t msf2lba(u_int8_t, u_int8_t, u_int8_t);
static void acd_start(struct acd_softc *);
static int32_t acd_done(struct atapi_request *);
static int32_t acd_read_toc(struct acd_softc *);
static int32_t acd_setchan(struct acd_softc *, u_int8_t, u_int8_t, u_int8_t, u_int8_t);
static void acd_select_slot(struct acd_softc *);
static int32_t acd_open_track(struct acd_softc *, struct cdr_track *);
static int32_t acd_close_track(struct acd_softc *);
static int32_t acd_close_disk(struct acd_softc *);
static int32_t acd_read_track_info(struct acd_softc *, int32_t, struct acd_track_info*);
static int acd_report_key(struct acd_softc *, struct dvd_authinfo *);
static int acd_send_key(struct acd_softc *, struct dvd_authinfo *);
static int acd_read_structure(struct acd_softc *, struct dvd_struct *);
static int32_t acd_eject(struct acd_softc *, int32_t);
static int32_t acd_blank(struct acd_softc *);
static int32_t acd_prevent_allow(struct acd_softc *, int32_t);
static int32_t acd_start_stop(struct acd_softc *, int32_t);
static int32_t acd_pause_resume(struct acd_softc *, int32_t);
static int32_t acd_mode_sense(struct acd_softc *, u_int8_t, void *, int32_t);
static int32_t acd_mode_select(struct acd_softc *, void *, int32_t);
static int32_t acd_set_speed(struct acd_softc *cdp, int32_t);

/* internal vars */
MALLOC_DEFINE(M_ACD, "ACD driver", "ATAPI CD driver buffers");

int
acdattach(struct atapi_softc *atp)
{
    struct acd_softc *cdp;
    struct changer *chp;
    int32_t count, error = 0;
    static int32_t acd_cdev_done = 0, acdnlun = 0;

    if (!acd_cdev_done) {
	cdevsw_add(&acd_cdevsw);
	acd_cdev_done++;
    }

    if ((cdp = acd_init_lun(atp, acdnlun, NULL)) == NULL) {
	printf("acd: out of memory\n");
	return -1;
    }

    /* get drive capabilities, some drives needs this repeated */
    for (count = 0 ; count < 5 ; count++) {
	if (!(error = acd_mode_sense(cdp, ATAPI_CDROM_CAP_PAGE,
				     &cdp->cap, sizeof(cdp->cap))))
	    break;
    }
    if (error) {
	free(cdp, M_ACD);
	return -1;
    }
    cdp->cap.max_read_speed = ntohs(cdp->cap.max_read_speed);
    cdp->cap.cur_read_speed = ntohs(cdp->cap.cur_read_speed);
    cdp->cap.max_write_speed = ntohs(cdp->cap.max_write_speed);
    cdp->cap.cur_write_speed = ntohs(cdp->cap.cur_write_speed);
    cdp->cap.max_vol_levels = ntohs(cdp->cap.max_vol_levels);
    cdp->cap.buf_size = ntohs(cdp->cap.buf_size);
    acd_describe(cdp);

    /* if this is a changer device, allocate the neeeded lun's */
    if (cdp->cap.mech == MST_MECH_CHANGER) {
	int8_t ccb[16] = { ATAPI_MECH_STATUS,
			   0, 0, 0, 0, 0, 0, 0, 
			   sizeof(struct changer)>>8, sizeof(struct changer),
			   0, 0, 0, 0, 0, 0 };

	chp = malloc(sizeof(struct changer), M_ACD, M_NOWAIT);
	if (chp == NULL) {
	    printf("acd: out of memory\n");
	    return 0;
	}
	bzero(chp, sizeof(struct changer));
	error = atapi_queue_cmd(cdp->atp, ccb, chp, sizeof(struct changer),
				A_READ, 60, NULL, NULL, NULL);

	if (!error) {
	    struct acd_softc *tmpcdp = cdp;
	    int32_t count;
	    int8_t string[16];

	    chp->table_length = htons(chp->table_length);
	    for (count = 0; count < chp->slots; count++) {
		if (count > 0) {
		    tmpcdp = acd_init_lun(atp, acdnlun, cdp->stats);
		    if (!tmpcdp) {
			printf("acd: out of memory\n");
			return -1;
		    }
		}
		tmpcdp->slot = count;
		tmpcdp->changer_info = chp;
		printf("acd%d: changer slot %d %s\n", acdnlun, count,
		       (chp->slot[count].present ? "CD present" : "empty"));
		acdnlun++;
	    }
	    sprintf(string, "acd%d-", cdp->lun);
	    devstat_add_entry(cdp->stats, string, tmpcdp->lun, DEV_BSIZE,
			      DEVSTAT_NO_ORDERED_TAGS,
			      DEVSTAT_TYPE_CDROM | DEVSTAT_TYPE_IF_IDE,
			      DEVSTAT_PRIORITY_CD);
	}
    }
    else {
	devstat_add_entry(cdp->stats, "acd", cdp->lun, DEV_BSIZE,
			  DEVSTAT_NO_ORDERED_TAGS,
			  DEVSTAT_TYPE_CDROM | DEVSTAT_TYPE_IF_IDE,
			  0x178);
	acdnlun++;
    }
    return 0;
}

static struct acd_softc *
acd_init_lun(struct atapi_softc *atp, int32_t lun, struct devstat *stats)
{
    struct acd_softc *acd;
    dev_t dev;

    if (!(acd = malloc(sizeof(struct acd_softc), M_ACD, M_NOWAIT)))
	return NULL;
    bzero(acd, sizeof(struct acd_softc));
    bufq_init(&acd->buf_queue);
    acd->atp = atp;
    acd->lun = lun;
    acd->flags &= ~(F_WRITTEN|F_DISK_OPEN|F_TRACK_OPEN);
    acd->block_size = 2048;
    acd->refcnt = 0;
    acd->slot = -1;
    acd->changer_info = NULL;
    acd->atp->flags |= ATAPI_F_MEDIA_CHANGED;
    if (stats == NULL) {
	if (!(acd->stats = malloc(sizeof(struct devstat), M_ACD, M_NOWAIT))) {
	    free(acd, M_ACD);
	    return NULL;
	}
	bzero(acd->stats, sizeof(struct devstat));
    }
    else
	acd->stats = stats;
    dev = make_dev(&acd_cdevsw, dkmakeminor(lun, 0, 0),
		   UID_ROOT, GID_OPERATOR, 0644, "racd%da", lun);
    dev->si_drv1 = acd;
    dev->si_iosize_max = 252 * DEV_BSIZE;
    dev = make_dev(&acd_cdevsw, dkmakeminor(lun, 0, RAW_PART),
		   UID_ROOT, GID_OPERATOR, 0644, "racd%dc", lun);
    dev->si_drv1 = acd;
    dev->si_iosize_max = 252 * DEV_BSIZE;
    dev = make_dev(&acd_cdevsw, dkmakeminor(lun, 0, 0),
		   UID_ROOT, GID_OPERATOR, 0644, "acd%da", lun);
    dev->si_drv1 = acd;
    dev->si_iosize_max = 252 * DEV_BSIZE;
    dev = make_dev(&acd_cdevsw, dkmakeminor(lun, 0, RAW_PART),
		   UID_ROOT, GID_OPERATOR, 0644, "acd%dc", lun);
    dev->si_drv1 = acd;
    dev->si_iosize_max = 252 * DEV_BSIZE;
    if ((acd->atp->devname = malloc(8, M_ACD, M_NOWAIT)))
        sprintf(acd->atp->devname, "acd%d", acd->lun);
    return acd;
}

static void 
acd_describe(struct acd_softc *cdp)
{
    int32_t comma = 0;
    int8_t *mechanism;
    int8_t model_buf[40+1];
    int8_t revision_buf[8+1];

    bpack(cdp->atp->atapi_parm->model, model_buf, sizeof(model_buf));
    bpack(cdp->atp->atapi_parm->revision, revision_buf, sizeof(revision_buf));
    printf("acd%d: <%s/%s> %s drive at ata%d as %s\n",
	   cdp->lun, model_buf, revision_buf,
	   (cdp->cap.write_dvdr) ? "DVD-R" : 
		(cdp->cap.write_dvdram) ? "DVD-RAM" : 
		    (cdp->cap.write_cdrw) ? "CD-RW" :
			(cdp->cap.write_cdr) ? "CD-R" : 
			    (cdp->cap.read_dvdrom) ? "DVD-ROM" : "CDROM",
	   cdp->atp->controller->lun,
	   (cdp->atp->unit == ATA_MASTER) ? "master" : "slave ");

    printf("acd%d:", cdp->lun);
    if (cdp->cap.cur_read_speed) {
	printf(" read %dKB/s", cdp->cap.cur_read_speed * 1000 / 1024);
	if (cdp->cap.max_read_speed) 
	    printf(" (%dKB/s)", cdp->cap.max_read_speed * 1000 / 1024);
	if ((cdp->cap.cur_write_speed) &&
	    (cdp->cap.write_cdr || cdp->cap.write_cdrw || 
	     cdp->cap.write_dvdr || cdp->cap.write_dvdram)) {
	    printf(" write %dKB/s", cdp->cap.cur_write_speed * 1000 / 1024);
	    if (cdp->cap.max_write_speed)
		printf(" (%dKB/s)", cdp->cap.max_write_speed * 1000 / 1024);
	}
	comma = 1;
    }
    if (cdp->cap.buf_size) {
	printf("%s %dKB buffer", comma ? "," : "", cdp->cap.buf_size);
	comma = 1;
    }
    printf("%s %s\n", 
	   comma ? "," : "", ata_mode2str(cdp->atp->controller->mode[
	   (cdp->atp->unit == ATA_MASTER) ? 0 : 1]));

    printf("acd%d: Reads:", cdp->lun);
    comma = 0;
    if (cdp->cap.read_cdr) {
	printf(" CD-R"); comma = 1;
    }
    if (cdp->cap.read_cdrw) {
	printf("%s CD-RW", comma ? "," : ""); comma = 1;
    }
    if (cdp->cap.cd_da) {
	if (cdp->cap.cd_da_stream)
	    printf("%s CD-DA stream", comma ? "," : "");
	else
	    printf("%s CD-DA", comma ? "," : "");
	comma = 1;
    }
    if (cdp->cap.read_dvdrom) {
	printf("%s DVD-ROM", comma ? "," : ""); comma = 1;
    }
    if (cdp->cap.read_dvdr) {
	printf("%s DVD-R", comma ? "," : ""); comma = 1;
    }
    if (cdp->cap.read_dvdram) {
	printf("%s DVD-RAM", comma ? "," : ""); comma = 1;
    }
    if (cdp->cap.read_packet)
	printf("%s packet", comma ? "," : "");

    if (cdp->cap.write_cdr || cdp->cap.write_cdrw || 
	cdp->cap.write_dvdr || cdp->cap.write_dvdram) {
	printf("\nacd%d: Writes:", cdp->lun);
	comma = 0;
	if (cdp->cap.write_cdr) {
	    printf(" CD-R" ); comma = 1;
	}
	if (cdp->cap.write_cdrw) {
	    printf("%s CD-RW", comma ? "," : ""); comma = 1;
	}
	if (cdp->cap.write_dvdr) {
	    printf("%s DVD-R", comma ? "," : ""); comma = 1;
	}
	if (cdp->cap.write_dvdram) {
	    printf("%s DVD-RAM", comma ? "," : ""); comma = 1; 
	}
	if (cdp->cap.test_write)
	    printf("%s test write", comma ? "," : "");
    }
    if (cdp->cap.audio_play) {
	printf("\nacd%d: Audio: ", cdp->lun);
	if (cdp->cap.audio_play)
	    printf("play");
	if (cdp->cap.max_vol_levels)
	    printf(", %d volume levels", cdp->cap.max_vol_levels);
    }
    printf("\nacd%d: Mechanism: ", cdp->lun);
    switch (cdp->cap.mech) {
    case MST_MECH_CADDY:
	mechanism = "caddy"; break;
    case MST_MECH_TRAY:
	mechanism = "tray"; break;
    case MST_MECH_POPUP:
	mechanism = "popup"; break;
    case MST_MECH_CHANGER:
	mechanism = "changer"; break;
    case MST_MECH_CARTRIDGE:
	mechanism = "cartridge"; break;
    default:
	mechanism = 0; break;
    }
    if (mechanism)
	printf("%s%s", cdp->cap.eject ? "ejectable " : "", mechanism);
    else if (cdp->cap.eject)
	printf("ejectable");

    if (cdp->cap.mech != MST_MECH_CHANGER) {
	printf("\nacd%d: Medium: ", cdp->lun);
	switch (cdp->cap.medium_type & MST_TYPE_MASK_HIGH) {
	case MST_CDROM:
	    printf("CD-ROM "); break;
	case MST_CDR:
	    printf("CD-R "); break;
	case MST_CDRW:
	    printf("CD-RW "); break;
	case MST_DOOR_OPEN:
	    printf("door open"); break;
	case MST_NO_DISC:
	    printf("no/blank disc inside"); break;
	case MST_FMT_ERROR:
	    printf("medium format error"); break;
	}
	if ((cdp->cap.medium_type & MST_TYPE_MASK_HIGH) < MST_TYPE_MASK_HIGH) {
	    switch (cdp->cap.medium_type & MST_TYPE_MASK_LOW) {
	    case MST_DATA_120:
		printf("120mm data disc loaded"); break;
	    case MST_AUDIO_120:
		printf("120mm audio disc loaded"); break;
	    case MST_COMB_120:
		printf("120mm data/audio disc loaded"); break;
	    case MST_PHOTO_120:
		printf("120mm photo disc loaded"); break;
	    case MST_DATA_80:
		printf("80mm data disc loaded"); break;
	    case MST_AUDIO_80:
		printf("80mm audio disc loaded"); break;
	    case MST_COMB_80:
		printf("80mm data/audio disc loaded"); break;
	    case MST_PHOTO_80:
		printf("80mm photo disc loaded"); break;
	    case MST_FMT_NONE:
		switch (cdp->cap.medium_type & MST_TYPE_MASK_HIGH) {
		case MST_CDROM:
		    printf("unknown medium"); break;
		case MST_CDR:
		case MST_CDRW:
		    printf("blank medium"); break;
		}
		break;
	    default:
		printf("unknown type=0x%x", cdp->cap.medium_type); break;
	    }
	}
    }
    if (cdp->cap.lock)
	printf(cdp->cap.locked ? ", locked" : ", unlocked");
    if (cdp->cap.prevent)
	printf(", lock protected");
    printf("\n");
}

static __inline void 
lba2msf(int32_t lba, u_int8_t *m, u_int8_t *s, u_int8_t *f)
{
    lba += 150;
    lba &= 0xffffff;
    *m = lba / (60 * 75);
    lba %= (60 * 75);
    *s = lba / 75;
    *f = lba % 75;
}

static __inline int32_t 
msf2lba(u_int8_t m, u_int8_t s, u_int8_t f)
{
    return (m * 60 + s) * 75 + f - 150;
}

static int
acdopen(dev_t dev, int32_t flags, int32_t fmt, struct proc *p)
{
    struct acd_softc *cdp = dev->si_drv1;

    if (!cdp)
	return ENXIO;

    if (cdp->flags & F_WRITING)
	return EBUSY;

    if (flags & FWRITE) {
	if ((cdp->flags & F_BOPEN) || cdp->refcnt)
	    return EBUSY;
	else
	    cdp->flags |= F_WRITING;
    }

    dev->si_bsize_phys = 2048; /* XXX SOS */
    if (!(cdp->flags & F_BOPEN) && !cdp->refcnt) {
	acd_prevent_allow(cdp, 1);
	cdp->flags |= F_LOCKED;
	if (!(flags & O_NONBLOCK) && !(flags & FWRITE))
	    acd_read_toc(cdp);
    }
    if (fmt == S_IFBLK)
	cdp->flags |= F_BOPEN;
    else
	cdp->refcnt++;
    return 0;
}

static int 
acdclose(dev_t dev, int32_t flags, int32_t fmt, struct proc *p)
{
    struct acd_softc *cdp = dev->si_drv1;
    
    if (fmt == S_IFBLK)
	cdp->flags &= ~F_BOPEN;
    else
	cdp->refcnt--;

    /* are we the last open ?? */
    if (!(cdp->flags & F_BOPEN) && !cdp->refcnt)
	acd_prevent_allow(cdp, 0);

    cdp->flags &= ~(F_LOCKED | F_WRITING);
    return 0;
}

static int 
acdioctl(dev_t dev, u_long cmd, caddr_t addr, int32_t flag, struct proc *p)
{
    struct acd_softc *cdp = dev->si_drv1;
    int32_t error = 0;

    if (cdp->atp->flags & ATAPI_F_MEDIA_CHANGED)
	switch (cmd) {
	case CDIOCRESET:
	    atapi_test_ready(cdp->atp);
	    break;
	   
	default:
	    acd_read_toc(cdp);
	    acd_prevent_allow(cdp, 1);
	    cdp->flags |= F_LOCKED;
	    break;
	}
    switch (cmd) {

    case CDIOCRESUME:
	error = acd_pause_resume(cdp, 1);
	break;

    case CDIOCPAUSE:
	error = acd_pause_resume(cdp, 0);
	break;

    case CDIOCSTART:
	error = acd_start_stop(cdp, 1);
	break;

    case CDIOCSTOP:
	error = acd_start_stop(cdp, 0);
	break;

    case CDIOCALLOW:
	acd_select_slot(cdp);
	cdp->flags &= ~F_LOCKED;
	error = acd_prevent_allow(cdp, 0);
	break;

    case CDIOCPREVENT:
	acd_select_slot(cdp);
	cdp->flags |= F_LOCKED;
	error = acd_prevent_allow(cdp, 1);
	break;

    case CDIOCRESET:
	error = suser(p);
	if (error)
	    break;
	error = atapi_test_ready(cdp->atp);
	break;

    case CDIOCEJECT:
	if ((cdp->flags & F_BOPEN) && cdp->refcnt) {
	    error = EBUSY;
	    break;
	}
	error = acd_eject(cdp, 0);
	break;

    case CDIOCCLOSE:
	if ((cdp->flags & F_BOPEN) && cdp->refcnt)
	    break;
	error = acd_eject(cdp, 1);
	break;

    case CDIOREADTOCHEADER:
	if (!cdp->toc.hdr.ending_track) {
	    error = EIO;
	    break;
	}
	bcopy(&cdp->toc.hdr, addr, sizeof(cdp->toc.hdr));
	break;

    case CDIOREADTOCENTRYS:
	{
	    struct ioc_read_toc_entry *te = (struct ioc_read_toc_entry *)addr;
	    struct toc *toc = &cdp->toc;
	    struct toc buf;
	    u_int32_t len;
	    u_int8_t starting_track = te->starting_track;

	    if (!cdp->toc.hdr.ending_track) {
		error = EIO;
		break;
	    }

	    if (te->data_len < sizeof(toc->tab[0]) || 
		(te->data_len % sizeof(toc->tab[0])) != 0 || 
		(te->address_format != CD_MSF_FORMAT &&
		te->address_format != CD_LBA_FORMAT)) {
		error = EINVAL;
		break;
	    }

	    if (!starting_track)
		starting_track = toc->hdr.starting_track;
	    else if (starting_track == 170) 
		starting_track = toc->hdr.ending_track + 1;
	    else if (starting_track < toc->hdr.starting_track ||
		     starting_track > toc->hdr.ending_track + 1) {
		error = EINVAL;
		break;
	    }

	    len = ((toc->hdr.ending_track + 1 - starting_track) + 1) *
		  sizeof(toc->tab[0]);
	    if (te->data_len < len)
		len = te->data_len;
	    if (len > sizeof(toc->tab)) {
		error = EINVAL;
		break;
	    }

	    if (te->address_format == CD_MSF_FORMAT) {
		struct cd_toc_entry *entry;

		buf = cdp->toc;
		toc = &buf;
		entry = toc->tab + (toc->hdr.ending_track + 1 -
			toc->hdr.starting_track) + 1;
		while (--entry >= toc->tab)
		    lba2msf(ntohl(entry->addr.lba), &entry->addr.msf.minute,
			    &entry->addr.msf.second, &entry->addr.msf.frame);
	    }
	    error = copyout(toc->tab + starting_track - toc->hdr.starting_track,
			    te->data, len);
	    break;
	}
    case CDIOREADTOCENTRY:
	{
	    struct ioc_read_toc_single_entry *te =
		(struct ioc_read_toc_single_entry *)addr;
	    struct toc *toc = &cdp->toc;
	    struct toc buf;
	    u_int8_t track = te->track;

	    if (!cdp->toc.hdr.ending_track) {
		error = EIO;
		break;
	    }

	    if (te->address_format != CD_MSF_FORMAT && 
		te->address_format != CD_LBA_FORMAT) {
		error = EINVAL;
		break;
	    }

	    if (!track)
		track = toc->hdr.starting_track;
	    else if (track == 170)
		track = toc->hdr.ending_track + 1;
	    else if (track < toc->hdr.starting_track ||
		     track > toc->hdr.ending_track + 1) {
		error = EINVAL;
		break;
	    }

	    if (te->address_format == CD_MSF_FORMAT) {
		struct cd_toc_entry *entry;

		buf = cdp->toc;
		toc = &buf;
		entry = toc->tab + (track - toc->hdr.starting_track);
		lba2msf(ntohl(entry->addr.lba), &entry->addr.msf.minute,
			&entry->addr.msf.second, &entry->addr.msf.frame);
	    }
	    bcopy(toc->tab + track - toc->hdr.starting_track,
		  &te->entry, sizeof(struct cd_toc_entry));
	}
	break;

    case CDIOCREADSUBCHANNEL:
	{
	    struct ioc_read_subchannel *args =
		(struct ioc_read_subchannel *)addr;
	    struct cd_sub_channel_info data;
	    u_int32_t len = args->data_len;
	    int32_t abslba, rellba;
	    int8_t ccb[16] = { ATAPI_READ_SUBCHANNEL, 0, 0x40, 1, 0, 0, 0,
			       sizeof(cdp->subchan)>>8, sizeof(cdp->subchan),
			       0, 0, 0, 0, 0, 0, 0 };

	    if (len > sizeof(data) ||
		len < sizeof(struct cd_sub_channel_header)) {
		error = EINVAL;
		break;
	    }

	    if ((error = atapi_queue_cmd(cdp->atp, ccb, &cdp->subchan, 
					 sizeof(cdp->subchan), A_READ, 10,
					 NULL, NULL, NULL))) {
		break;
	    }
	    abslba = cdp->subchan.abslba;
	    rellba = cdp->subchan.rellba;
	    if (args->address_format == CD_MSF_FORMAT) {
		lba2msf(ntohl(abslba),
		    &data.what.position.absaddr.msf.minute,
		    &data.what.position.absaddr.msf.second,
		    &data.what.position.absaddr.msf.frame);
		lba2msf(ntohl(rellba),
		    &data.what.position.reladdr.msf.minute,
		    &data.what.position.reladdr.msf.second,
		    &data.what.position.reladdr.msf.frame);
	    } else {
		data.what.position.absaddr.lba = abslba;
		data.what.position.reladdr.lba = rellba;
	    }
	    data.header.audio_status = cdp->subchan.audio_status;
	    data.what.position.control = cdp->subchan.control & 0xf;
	    data.what.position.addr_type = cdp->subchan.control >> 4;
	    data.what.position.track_number = cdp->subchan.track;
	    data.what.position.index_number = cdp->subchan.indx;
	    error = copyout(&data, args->data, len);
	    break;
	}

    case CDIOCPLAYMSF:
	{
	    struct ioc_play_msf *args = (struct ioc_play_msf *)addr;
	    int8_t ccb[16] = { ATAPI_PLAY_MSF, 0, 0,
			       args->start_m, args->start_s, args->start_f,
			       args->end_m, args->end_s, args->end_f,
			       0, 0, 0, 0, 0, 0, 0 };

	    error = atapi_queue_cmd(cdp->atp, ccb, NULL, 0, 0, 10,
				    NULL, NULL, NULL);
	    break;
	}

    case CDIOCPLAYBLOCKS:
	{
	    struct ioc_play_blocks *args = (struct ioc_play_blocks *)addr;
	    int8_t ccb[16]  = { ATAPI_PLAY_BIG, 0,
				args->blk>>24, args->blk>>16, args->blk>>8,
				args->blk, args->len>>24, args->len>>16,
				args->len>>8, args->len,
				0, 0, 0, 0, 0, 0 };

	    error = atapi_queue_cmd(cdp->atp, ccb, NULL, 0, 0, 10,
				    NULL, NULL, NULL);
	    break;
	}

    case CDIOCPLAYTRACKS:
	{
	    struct ioc_play_track *args = (struct ioc_play_track *)addr;
	    u_int32_t start, len;
	    int32_t t1, t2;
	    int8_t ccb[16];

	    if (!cdp->toc.hdr.ending_track) {
		error = EIO;
		break;
	    }

	    if (args->end_track < cdp->toc.hdr.ending_track + 1)
		++args->end_track;
	    if (args->end_track > cdp->toc.hdr.ending_track + 1)
		args->end_track = cdp->toc.hdr.ending_track + 1;
	    t1 = args->start_track - cdp->toc.hdr.starting_track;
	    t2 = args->end_track - cdp->toc.hdr.starting_track;
	    if (t1 < 0 || t2 < 0) {
		error = EINVAL;
		break;
	    }
	    start = ntohl(cdp->toc.tab[t1].addr.lba);
	    len = ntohl(cdp->toc.tab[t2].addr.lba) - start;

	    bzero(ccb, sizeof(ccb));
	    ccb[0] = ATAPI_PLAY_BIG;
	    ccb[2] = start>>24;
	    ccb[3] = start>>16;
	    ccb[4] = start>>8;
	    ccb[5] = start;
	    ccb[6] = len>>24;
	    ccb[7] = len>>16;
	    ccb[8] = len>>8;
	    ccb[9] = len;

	    error = atapi_queue_cmd(cdp->atp, ccb, NULL, 0, 0, 10,
				    NULL, NULL, NULL);
	    break;
	}

    case CDIOCREADAUDIO:
	{
	    struct ioc_read_audio *args = (struct ioc_read_audio *)addr;
	    int32_t lba, frames, error = 0;
	    u_int8_t *buffer, *ubuf = args->buffer;
	    int8_t ccb[16];

	    if (!cdp->toc.hdr.ending_track) {
		error = EIO;
		break;
	    }
		
	    if ((frames = args->nframes) < 0) {
		error = EINVAL;
		break;
	    }

	    if (args->address_format == CD_LBA_FORMAT)
		lba = args->address.lba;
	    else if (args->address_format == CD_MSF_FORMAT)
		lba = msf2lba(args->address.msf.minute,
			     args->address.msf.second,
			     args->address.msf.frame);
	    else {
		error = EINVAL;
		break;
	    }

#ifndef CD_BUFFER_BLOCKS
#define CD_BUFFER_BLOCKS 13
#endif
	    if (!(buffer = malloc(CD_BUFFER_BLOCKS * 2352, M_ACD, M_NOWAIT))){
		error = ENOMEM;
		break;
	    }
	    bzero(ccb, sizeof(ccb));
	    while (frames > 0) {
		int32_t size;
		u_int8_t blocks;

		blocks = (frames>CD_BUFFER_BLOCKS) ? CD_BUFFER_BLOCKS : frames;
		size = blocks * 2352;

		ccb[0] = ATAPI_READ_CD;
		ccb[1] = 4;
		ccb[2] = lba>>24;
		ccb[3] = lba>>16;
		ccb[4] = lba>>8;
		ccb[5] = lba;
		ccb[8] = blocks;
		ccb[9] = 0xf0;
		if ((error = atapi_queue_cmd(cdp->atp, ccb, buffer, size, 
					     A_READ, 30, NULL, NULL, NULL)))
		    break;

		if ((error = copyout(buffer, ubuf, size)))
		    break;
		    
		ubuf += size;
		frames -= blocks;
		lba += blocks;
	    }
	    free(buffer, M_ACD);
	    if (args->address_format == CD_LBA_FORMAT)
		args->address.lba = lba;
	    else if (args->address_format == CD_MSF_FORMAT)
		lba2msf(lba, &args->address.msf.minute,
			     &args->address.msf.second,
			     &args->address.msf.frame);
	    break;
	}

    case CDIOCGETVOL:
	{
	    struct ioc_vol *arg = (struct ioc_vol *)addr;

	    if ((error = acd_mode_sense(cdp, ATAPI_CDROM_AUDIO_PAGE,
					&cdp->au, sizeof(cdp->au))))
		break;

	    if (cdp->au.page_code != ATAPI_CDROM_AUDIO_PAGE) {
		error = EIO;
		break;
	    }
	    arg->vol[0] = cdp->au.port[0].volume;
	    arg->vol[1] = cdp->au.port[1].volume;
	    arg->vol[2] = cdp->au.port[2].volume;
	    arg->vol[3] = cdp->au.port[3].volume;
	    break;
	}

    case CDIOCSETVOL:
	{
	    struct ioc_vol *arg = (struct ioc_vol *)addr;

	    if ((error = acd_mode_sense(cdp, ATAPI_CDROM_AUDIO_PAGE,
					&cdp->au, sizeof(cdp->au))))
		break;
	    if (cdp->au.page_code != ATAPI_CDROM_AUDIO_PAGE) {
		error = EIO;
		break;
	    }
	    if ((error = acd_mode_sense(cdp, ATAPI_CDROM_AUDIO_PAGE_MASK,
					&cdp->aumask, sizeof(cdp->aumask))))
		break;
	    cdp->au.data_length = 0;
	    cdp->au.port[0].channels = CHANNEL_0;
	    cdp->au.port[1].channels = CHANNEL_1;
	    cdp->au.port[0].volume = arg->vol[0] & cdp->aumask.port[0].volume;
	    cdp->au.port[1].volume = arg->vol[1] & cdp->aumask.port[1].volume;
	    cdp->au.port[2].volume = arg->vol[2] & cdp->aumask.port[2].volume;
	    cdp->au.port[3].volume = arg->vol[3] & cdp->aumask.port[3].volume;
	    error =  acd_mode_select(cdp, &cdp->au, sizeof(cdp->au));
	    break;
	}
    case CDIOCSETPATCH:
	{
	    struct ioc_patch *arg = (struct ioc_patch *)addr;

	    error = acd_setchan(cdp, arg->patch[0], arg->patch[1],
				arg->patch[2], arg->patch[3]);
	    break;
	}

    case CDIOCSETMONO:
	error = acd_setchan(cdp, CHANNEL_0|CHANNEL_1, CHANNEL_0|CHANNEL_1, 0,0);
	break;

    case CDIOCSETSTEREO:
	error = acd_setchan(cdp, CHANNEL_0, CHANNEL_1, 0, 0);
	break;

    case CDIOCSETMUTE:
	error = acd_setchan(cdp, 0, 0, 0, 0);
	break;

    case CDIOCSETLEFT:
	error = acd_setchan(cdp, CHANNEL_0, CHANNEL_0, 0, 0);
	break;

    case CDIOCSETRIGHT:
	error = acd_setchan(cdp, CHANNEL_1, CHANNEL_1, 0, 0);
	break;

    case CDRIOCBLANK:
	error = acd_blank(cdp);
	break;

    case CDRIOCNEXTWRITEABLEADDR:
	{
	    struct acd_track_info track_info;

	    if ((error = acd_read_track_info(cdp, 0xff, &track_info)))
		break;

	    if (!track_info.nwa_valid) {
		error = EINVAL;
		break;
	    }
	    cdp->next_writeable_addr = track_info.next_writeable_addr;
	    *(int*)addr = track_info.next_writeable_addr;
	}
	break;
 
    case CDRIOCOPENDISK:
	if ((cdp->flags & F_WRITTEN) || (cdp->flags & F_DISK_OPEN)) {
	    error = EINVAL;
	    printf("acd%d: sequence error (disk already open)\n", cdp->lun);
	}
	cdp->next_writeable_addr = 0;
	cdp->flags &= ~(F_WRITTEN | F_TRACK_OPEN);
	cdp->flags |= F_DISK_OPEN;
	break;

    case CDRIOCOPENTRACK:
	if (!(cdp->flags & F_DISK_OPEN)) {
	    error = EINVAL;
	    printf("acd%d: sequence error (disk not open)\n", cdp->lun);
	} 
	else {
	    if ((error = acd_open_track(cdp, (struct cdr_track *)addr)))
		break;
	    cdp->flags |= F_TRACK_OPEN;
	}
	break;

    case CDRIOCCLOSETRACK:
	if (!(cdp->flags & F_TRACK_OPEN)) {
	    error = EINVAL;
	    printf("acd%d: sequence error (no track open)\n", cdp->lun);
	}
	else {
	    if (cdp->flags & F_WRITTEN) {
		acd_close_track(cdp);
		cdp->flags &= ~F_TRACK_OPEN;
	    }
	}
	break;

    case CDRIOCCLOSEDISK:
	if (!(cdp->flags & F_WRITTEN) || !(cdp->flags & F_DISK_OPEN)) {
	    error = EINVAL;
	    printf("acd%d: sequence error (nothing to close)\n", cdp->lun);
	}
	else {
	    error = acd_close_disk(cdp);
	    cdp->flags &= ~(F_WRITTEN | F_DISK_OPEN | F_TRACK_OPEN);
	}
	break;

    case CDRIOCWRITESPEED:
	error = acd_set_speed(cdp, (*(int32_t *)addr) * 177);
	break;

    case CDRIOCGETBLOCKSIZE:
	*(int32_t *)addr = cdp->block_size;
	break;

    case CDRIOCSETBLOCKSIZE:
	cdp->block_size = *(int32_t *)addr;
	break;

    case DVDIOCREPORTKEY:
	if (!cdp->cap.read_dvdrom)
	    error = EINVAL;
	else
	    error = acd_report_key(cdp, (struct dvd_authinfo *)addr);
	break;

    case DVDIOCSENDKEY:
	if (!cdp->cap.read_dvdrom)
	    error = EINVAL;
	else
	    error = acd_send_key(cdp, (struct dvd_authinfo *)addr);
	break;

    case DVDIOCREADSTRUCTURE:
	if (!cdp->cap.read_dvdrom)
	    error = EINVAL;
	else
	    error = acd_read_structure(cdp, (struct dvd_struct *)addr);
	break;

    default:
	error = ENOTTY;
    }
    return error;
}

static void 
acdstrategy(struct buf *bp)
{
    struct acd_softc *cdp = bp->b_dev->si_drv1;
    int32_t s;

#ifdef NOTYET
    /* allow write only on CD-R/RW media */   /* all for now SOS */
    if (!(bp->b_flags & B_READ) && !(writeable_media)) {
	bp->b_error = EROFS;
	bp->b_flags |= B_ERROR;
	biodone(bp);
	return;
    }
#endif
    /* if it's a null transfer, return immediatly. */
    if (bp->b_bcount == 0) {
	bp->b_resid = 0;
	biodone(bp);
	return;
    }
    
    /* check for valid blocksize SOS */

    bp->b_pblkno = bp->b_blkno;
    bp->b_resid = bp->b_bcount;

    s = splbio();
    bufqdisksort(&cdp->buf_queue, bp);
    acd_start(cdp);
    splx(s);
}

static void 
acd_start(struct acd_softc *cdp)
{
    struct buf *bp = bufq_first(&cdp->buf_queue);
    u_int32_t lba, count;
    int8_t ccb[16];

    if (!bp)
	return;

    bufq_remove(&cdp->buf_queue, bp);

    /* reject all queued entries if media changed */
    if (cdp->atp->flags & ATAPI_F_MEDIA_CHANGED) {
	bp->b_error = EIO;
	bp->b_flags |= B_ERROR;
	biodone(bp);
	return;
    }

    acd_select_slot(cdp);

    if (!(bp->b_flags & B_READ) &&
	(!(cdp->flags & F_DISK_OPEN) || !(cdp->flags & F_TRACK_OPEN))) {
	printf("acd%d: sequence error (no open)\n", cdp->lun);
	bp->b_error = EIO;
	bp->b_flags |= B_ERROR;
	biodone(bp);
	return;
    }

    bzero(ccb, sizeof(ccb));
    if (bp->b_flags & B_READ) {
	lba = bp->b_blkno / (cdp->block_size / DEV_BSIZE);
	ccb[0] = ATAPI_READ_BIG;
    }
    else {
	lba = cdp->next_writeable_addr + (bp->b_offset / cdp->block_size);
	ccb[0] = ATAPI_WRITE_BIG;
    }
    count = (bp->b_bcount + (cdp->block_size - 1)) / cdp->block_size;

    ccb[1] = 0;
    ccb[2] = lba>>24;
    ccb[3] = lba>>16;
    ccb[4] = lba>>8;
    ccb[5] = lba;
    ccb[7] = count>>8;
    ccb[8] = count;

    devstat_start_transaction(cdp->stats);

    atapi_queue_cmd(cdp->atp, ccb, bp->b_data, bp->b_bcount,
		    (bp->b_flags&B_READ)?A_READ : 0, 30, acd_done, cdp, bp);
}

static int32_t 
acd_done(struct atapi_request *request)
{
    struct buf *bp = request->bp;
    struct acd_softc *cdp = request->driver;
    
    if (request->error) {
	bp->b_error = request->error;
	bp->b_flags |= B_ERROR;
    }	
    else {
	bp->b_resid = request->bytecount;
	if ((bp->b_flags & B_READ) == B_WRITE)
	    cdp->flags |= F_WRITTEN;
    }
    devstat_end_transaction_buf(cdp->stats, bp);
    biodone(bp);
    acd_start(cdp);
    return 0;
}

static int32_t 
acd_read_toc(struct acd_softc *cdp)
{
    int32_t ntracks, len;
    int8_t ccb[16];

    bzero(&cdp->toc, sizeof(cdp->toc));
    bzero(&cdp->info, sizeof(cdp->info));
    bzero(ccb, sizeof(ccb));

    acd_select_slot(cdp);

    atapi_test_ready(cdp->atp);
    if (cdp->atp->flags & ATAPI_F_MEDIA_CHANGED)
	cdp->flags &= ~(F_WRITTEN | F_DISK_OPEN | F_TRACK_OPEN);

    cdp->atp->flags &= ~ATAPI_F_MEDIA_CHANGED;

    len = sizeof(struct ioc_toc_header) + sizeof(struct cd_toc_entry);
    ccb[0] = ATAPI_READ_TOC;
    ccb[7] = len>>8;
    ccb[8] = len;
    if (atapi_queue_cmd(cdp->atp, ccb, &cdp->toc, len, A_READ, 30,
			NULL, NULL, NULL)) {
	bzero(&cdp->toc, sizeof(cdp->toc));
	return 0;
    }
    ntracks = cdp->toc.hdr.ending_track - cdp->toc.hdr.starting_track + 1;
    if (ntracks <= 0 || ntracks > MAXTRK) {
	bzero(&cdp->toc, sizeof(cdp->toc));
	return 0;
    }

    len = sizeof(struct ioc_toc_header)+(ntracks+1)*sizeof(struct cd_toc_entry);
    bzero(ccb, sizeof(ccb));
    ccb[0] = ATAPI_READ_TOC;
    ccb[7] = len>>8;
    ccb[8] = len;
    if (atapi_queue_cmd(cdp->atp, ccb, &cdp->toc, len, A_READ, 30,
			NULL, NULL, NULL)) {
	bzero(&cdp->toc, sizeof(cdp->toc));
	return 0;
    }

    cdp->toc.hdr.len = ntohs(cdp->toc.hdr.len);

    bzero(ccb, sizeof(ccb));
    ccb[0] = ATAPI_READ_CAPACITY;
    if (atapi_queue_cmd(cdp->atp, ccb, &cdp->info, sizeof(cdp->info), 
			A_READ, 30, NULL, NULL, NULL))
	bzero(&cdp->info, sizeof(cdp->info));

    cdp->info.volsize = ntohl(cdp->info.volsize);
    cdp->info.blksize = ntohl(cdp->info.blksize);

#ifdef ACD_DEBUG
    if (cdp->info.volsize && cdp->toc.hdr.ending_track) {
	printf("acd%d: ", cdp->lun);
	if (cdp->toc.tab[0].control & 4)
	    printf("%dMB ", cdp->info.volsize / 512);
	else
	    printf("%d:%d audio ", cdp->info.volsize / 75 / 60,
		cdp->info.volsize / 75 % 60);
	printf("(%d sectors (%d bytes)), %d tracks\n", 
	    cdp->info.volsize, cdp->info.blksize,
	    cdp->toc.hdr.ending_track - cdp->toc.hdr.starting_track + 1);
    }
#endif
    return 0;
}

static int32_t 
acd_setchan(struct acd_softc *cdp,
	    u_int8_t c0, u_int8_t c1, u_int8_t c2, u_int8_t c3)
{
    int32_t error;

    if ((error = acd_mode_sense(cdp, ATAPI_CDROM_AUDIO_PAGE, &cdp->au, 
				sizeof(cdp->au))))
	return error;
    if (cdp->au.page_code != ATAPI_CDROM_AUDIO_PAGE)
	return EIO;
    cdp->au.data_length = 0;
    cdp->au.port[0].channels = c0;
    cdp->au.port[1].channels = c1;
    cdp->au.port[2].channels = c2;
    cdp->au.port[3].channels = c3;
    return acd_mode_select(cdp, &cdp->au, sizeof(cdp->au));
}

static void
acd_select_slot(struct acd_softc *cdp)
{
    int8_t ccb[16];

    if (cdp->slot < 0 || cdp->changer_info->current_slot == cdp->slot)
	return;

    /* unlock (might not be needed but its cheaper than asking) */
    acd_prevent_allow(cdp, 0);

    bzero(ccb, sizeof(ccb));
    /* unload the current media from player */
    ccb[0] = ATAPI_LOAD_UNLOAD;
    ccb[1] = 0x01;
    ccb[4] = 2;
    ccb[8] = cdp->changer_info->current_slot;
    atapi_queue_cmd(cdp->atp, ccb, NULL, 0, 0, 10, NULL, NULL, NULL);
    atapi_wait_ready(cdp->atp, 30);

    /* load the wanted slot */
    ccb[0] = ATAPI_LOAD_UNLOAD;
    ccb[1] = 0x01;
    ccb[4] = 3;
    ccb[8] = cdp->slot;
    atapi_queue_cmd(cdp->atp, ccb, NULL, 0, 0, 10, NULL, NULL, NULL);
    atapi_wait_ready(cdp->atp, 30);

    cdp->changer_info->current_slot = cdp->slot;

    /* lock the media if needed */
    if (cdp->flags & F_LOCKED)
	acd_prevent_allow(cdp, 1);
}

static int32_t
acd_close_disk(struct acd_softc *cdp)
{
    int8_t ccb[16] = { ATAPI_CLOSE_TRACK, 0x01, 0x02, 0, 0, 0, 0, 0, 
		       0, 0, 0, 0, 0, 0, 0, 0 };
    int32_t error;

    error = atapi_queue_cmd(cdp->atp, ccb, NULL, 0, 0, 10, NULL, NULL, NULL);
    if (error)
	return error;
    return atapi_wait_ready(cdp->atp, 10*60);
}

static int32_t
acd_open_track(struct acd_softc *cdp, struct cdr_track *track)
{
    struct write_param param;
    int32_t error;

    if ((error = acd_mode_sense(cdp, ATAPI_CDROM_WRITE_PARAMETERS_PAGE,
				&param, sizeof(param))))
	return error;
    param.page_code = 0x05;
    param.page_length = 0x32;
    param.test_write = track->test_write ? 1 : 0;
    param.write_type = CDR_WTYPE_TRACK;

    switch (track->track_type) {

    case CDR_DB_RAW:
	if (track->preemp)
	    param.track_mode = CDR_TMODE_AUDIO_PREEMP;
	else
	    param.track_mode = CDR_TMODE_AUDIO;
	cdp->block_size = 2352;
	param.data_block_type = CDR_DB_RAW;
	param.session_format = CDR_SESS_CDROM;
	break;

    case CDR_DB_ROM_MODE1:
	cdp->block_size = 2048;
	param.track_mode = CDR_TMODE_DATA;
	param.data_block_type = CDR_DB_ROM_MODE1;
	param.session_format = CDR_SESS_CDROM;
	break;

    case CDR_DB_ROM_MODE2:
	cdp->block_size = 2336;
	param.track_mode = CDR_TMODE_DATA;
	param.data_block_type = CDR_DB_ROM_MODE2;
	param.session_format = CDR_SESS_CDROM;
	break;

    case CDR_DB_XA_MODE1:
	cdp->block_size = 2048;
	param.track_mode = CDR_TMODE_DATA;
	param.data_block_type = CDR_DB_XA_MODE1;
	param.session_format = CDR_SESS_CDROM_XA;
	break;

    case CDR_DB_XA_MODE2_F1:
	cdp->block_size = 2056;
	param.track_mode = CDR_TMODE_DATA;
	param.data_block_type = CDR_DB_XA_MODE2_F1;
	param.session_format = CDR_SESS_CDROM_XA;
	break;

    case CDR_DB_XA_MODE2_F2:
	cdp->block_size = 2324;
	param.track_mode = CDR_TMODE_DATA;
	param.data_block_type = CDR_DB_XA_MODE2_F2;
	param.session_format = CDR_SESS_CDROM_XA;
	break;

    case CDR_DB_XA_MODE2_MIX:
	cdp->block_size = 2332;
	param.track_mode = CDR_TMODE_DATA;
	param.data_block_type = CDR_DB_XA_MODE2_MIX;
	param.session_format = CDR_SESS_CDROM_XA;
	break;
    }

#if 1
        param.multi_session = CDR_MSES_MULTI;
#else
        param.multi_session = CDR_MSES_NONE;
#endif
    param.fp = 0;
    param.packet_size = 0;
    return acd_mode_select(cdp, &param, sizeof(param));
}

static int32_t
acd_close_track(struct acd_softc *cdp)
{
    int8_t ccb1[16] = { ATAPI_SYNCHRONIZE_CACHE, 0x02, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0 };
    int32_t error;

    error = atapi_queue_cmd(cdp->atp, ccb1, NULL, 0, 0, 10, NULL, NULL, NULL);
    if (error)
	return error;
    return atapi_wait_ready(cdp->atp, 5*60);
}

static int32_t
acd_read_track_info(struct acd_softc *cdp,
		    int32_t lba, struct acd_track_info *info)
{
    int8_t ccb[16] = { ATAPI_READ_TRACK_INFO, 1,
		     lba>>24, lba>>16, lba>>8, lba,
		     0,
		     sizeof(*info)>>8, sizeof(*info),
		     0, 0, 0, 0, 0, 0, 0 };
    int32_t error;

    if ((error = atapi_queue_cmd(cdp->atp, ccb, info, sizeof(*info), 
				 A_READ, 30, NULL, NULL, NULL)))
	return error;
    info->track_start_addr = ntohl(info->track_start_addr);
    info->next_writeable_addr = ntohl(info->next_writeable_addr);
    info->free_blocks = ntohl(info->free_blocks);
    info->fixed_packet_size = ntohl(info->fixed_packet_size);
    info->track_length = ntohl(info->track_length);
    return 0;
}

static int
acd_report_key(struct acd_softc *cdp, struct dvd_authinfo *ai)
{
    struct {
	u_int16_t length;
	u_char reserved[2];
	u_char data[12];
    } d;
    u_int32_t lba = 0;
    int32_t error;
    int16_t length;
    int8_t ccb[16];

    printf("dvd_report_key: format=0x%x\n", ai->format);

    switch (ai->format) {
    case DVD_REPORT_AGID:
    case DVD_REPORT_ASF:
    case DVD_REPORT_RPC:
	length = 8;
	break;
    case DVD_REPORT_KEY1:
	length = 12;
	break;
    case DVD_REPORT_TITLE_KEY:
	length = 12;
	lba = ai->lba;
	break;
    case DVD_REPORT_CHALLENGE:
	length = 16;
	break;
    case DVD_INVALIDATE_AGID:
	length = 0;
	break;
    default:
	return EINVAL;
    }

    bzero(ccb, sizeof(ccb));
    ccb[0] = ATAPI_REPORT_KEY;
    ccb[2] = (lba >> 24) & 0xff;
    ccb[3] = (lba >> 16) & 0xff;
    ccb[4] = (lba >> 8) & 0xff;
    ccb[5] = lba & 0xff;
    ccb[8] = (length >> 8) & 0xff;
    ccb[9] = length & 0xff;
    ccb[10] = (ai->agid << 6) | ai->format;
    bzero(&d, sizeof(d));
    d.length = htons(length - 2);
    error = atapi_queue_cmd(cdp->atp, ccb, &d, length,
			    (ai->format == DVD_INVALIDATE_AGID) ? 0 : A_READ,
			    10, NULL, NULL, NULL);
    if (error)
	return error;

    switch (ai->format) {
    case DVD_REPORT_AGID:
	ai->agid = d.data[3] >> 6;
	break;
    
    case DVD_REPORT_CHALLENGE:
	bcopy(&d.data[0], &ai->keychal[0], 10);
	break;
    
    case DVD_REPORT_KEY1:
	bcopy(&d.data[0], &ai->keychal[0], 5);
	break;
    
    case DVD_REPORT_TITLE_KEY:
	ai->cpm = (d.data[0] >> 7);
	ai->cp_sec = (d.data[0] >> 6) & 0x1;
	ai->cgms = (d.data[0] >> 4) & 0x3;
	bcopy(&d.data[1], &ai->keychal[0], 5);
	break;
    
    case DVD_REPORT_ASF:
	ai->asf = d.data[3] & 1;
	break;
    
    case DVD_REPORT_RPC:
	ai->reg_type = (d.data[0] >> 6);
	ai->vend_rsts = (d.data[0] >> 3) & 0x7;
	ai->user_rsts = d.data[0] & 0x7;
	break;
    
    case DVD_INVALIDATE_AGID:
	break;

    default:
	return EINVAL;
    }
    return 0;
}

static int
acd_send_key(struct acd_softc *cdp, struct dvd_authinfo *ai)
{
    struct {
	u_int16_t length;
	u_char reserved[2];
	u_char data[12];
    } d;
    int16_t length;
    int8_t ccb[16];

    printf("dvd_send_key: format=0x%x\n", ai->format);

    bzero(&d, sizeof(d));

    switch (ai->format) {
    case DVD_SEND_CHALLENGE:
	length = 16;
	bcopy(ai->keychal, &d.data[0], 10);
	break;

    case DVD_SEND_KEY2:
	length = 12;
	bcopy(&ai->keychal[0], &d.data[0], 5);
	break;
    
    case DVD_SEND_RPC:
	length = 8;
	break;

    default:
	return EINVAL;
    }

    bzero(ccb, sizeof(ccb));
    ccb[0] = ATAPI_SEND_KEY;
    ccb[8] = (length >> 8) & 0xff;
    ccb[9] = length & 0xff;
    ccb[10] = (ai->agid << 6) | ai->format;
    d.length = htons(length - 2);
    return atapi_queue_cmd(cdp->atp, ccb, &d, length, 0, 10, NULL, NULL, NULL);
}

static int
acd_read_structure(struct acd_softc *cdp, struct dvd_struct *s)
{
    struct {
	u_int16_t length;
	u_char reserved[2];
	u_char data[2048];
    } d;
    u_int16_t length;
    int32_t error = 0;
    int8_t ccb[16];

    printf("dvd_read_structure: format=0x%x\n", s->format);

    bzero(&d, sizeof(d));

    switch(s->format) {
    case DVD_STRUCT_PHYSICAL:
	length = 21;
	break;

    case DVD_STRUCT_COPYRIGHT:
	length = 8;
	break;

    case DVD_STRUCT_DISCKEY:
	length = 2052;
	break;

    case DVD_STRUCT_BCA:
	length = 192;
	break;

    case DVD_STRUCT_MANUFACT:
	length = 2052;
	break;

    case DVD_STRUCT_DDS:
    case DVD_STRUCT_PRERECORDED:
    case DVD_STRUCT_UNIQUEID:
    case DVD_STRUCT_LIST:
    case DVD_STRUCT_CMI:
    case DVD_STRUCT_RMD_LAST:
    case DVD_STRUCT_RMD_RMA:
    case DVD_STRUCT_DCB:
	return ENOSYS;

    default:
	return EINVAL;
    }

    bzero(ccb, sizeof(ccb));
    ccb[0] = ATAPI_READ_STRUCTURE;
    ccb[6] = s->layer_num;
    ccb[7] = s->format;
    ccb[8] = (length >> 8) & 0xff;
    ccb[9] = length & 0xff;
    ccb[10] = s->agid << 6;
    d.length = htons(length - 2);
    error = atapi_queue_cmd(cdp->atp, ccb, &d, length, A_READ, 30,
			    NULL, NULL, NULL);
    if (error)
	return error;

    switch (s->format) {
    case DVD_STRUCT_PHYSICAL: {
	struct dvd_layer *layer = (struct dvd_layer *)&s->data[0];

	layer->book_type = d.data[0] >> 4;
	layer->book_version = d.data[0] & 0xf;
	layer->disc_size = d.data[1] >> 4;
	layer->max_rate = d.data[1] & 0xf;
	layer->nlayers = (d.data[2] >> 5) & 3;
	layer->track_path = (d.data[2] >> 4) & 1;
	layer->layer_type = d.data[2] & 0xf;
	layer->linear_density = d.data[3] >> 4;
	layer->track_density = d.data[3] & 0xf;
	layer->start_sector = d.data[5] << 16 | d.data[6] << 8 | d.data[7];
	layer->end_sector = d.data[9] << 16 | d.data[10] << 8 | d.data[11];
	layer->end_sector_l0 = d.data[13] << 16 | d.data[14] << 8 | d.data[15];
	layer->bca = d.data[16] >> 7;
	break;
    }

    case DVD_STRUCT_COPYRIGHT:
	s->cpst = d.data[0];
	s->rmi = d.data[0];
	break;

    case DVD_STRUCT_DISCKEY:
	bcopy(&d.data[0], &s->data[0], 2048);
	break;

    case DVD_STRUCT_BCA:
	s->length = ntohs(d.length);
	bcopy(&d.data[0], &s->data[0], s->length);
	break;

    case DVD_STRUCT_MANUFACT:
	s->length = ntohs(d.length);
	bcopy(&d.data[0], &s->data[0], s->length);
	break;
		
    default:
	return EINVAL;
    }
    return 0;
}

static int32_t 
acd_eject(struct acd_softc *cdp, int32_t close)
{
    int32_t error;

    acd_select_slot(cdp);
    if ((error = acd_start_stop(cdp, 0)) == EBUSY) {
	if (!close)
	    return 0;
	if ((error = acd_start_stop(cdp, 3)))
	    return error;
	acd_read_toc(cdp);
	acd_prevent_allow(cdp, 1);
	cdp->flags |= F_LOCKED;
	return 0;
    }
    if (error)
	return error;
    if (close)
	return 0;
    acd_prevent_allow(cdp, 0);
    cdp->flags &= ~F_LOCKED;
    cdp->flags &= ~(F_WRITTEN | F_DISK_OPEN | F_TRACK_OPEN);
    cdp->atp->flags |= ATAPI_F_MEDIA_CHANGED;
    return acd_start_stop(cdp, 2);
}

static int32_t
acd_blank(struct acd_softc *cdp)
{
    int8_t ccb[16] = { ATAPI_BLANK, 1, 0, 0, 0, 0, 0, 0, 
		       0, 0, 0, 0, 0, 0, 0, 0 };
    int32_t error;

    error = atapi_queue_cmd(cdp->atp, ccb, NULL, 0, 0, 60*60, NULL, NULL, NULL);
    cdp->flags &= ~(F_WRITTEN | F_DISK_OPEN | F_TRACK_OPEN);
    cdp->atp->flags |= ATAPI_F_MEDIA_CHANGED;
    return error;
}

static int32_t
acd_prevent_allow(struct acd_softc *cdp, int32_t lock)
{
    int8_t ccb[16] = { ATAPI_PREVENT_ALLOW, 0, 0, 0, lock,
		       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    return atapi_queue_cmd(cdp->atp, ccb, NULL, 0, 0, 30, NULL, NULL, NULL);
}

static int32_t
acd_start_stop(struct acd_softc *cdp, int32_t start)
{
    int8_t ccb[16] = { ATAPI_START_STOP, 0, 0, 0, start,
		       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    return atapi_queue_cmd(cdp->atp, ccb, NULL, 0, 0, 30, NULL, NULL, NULL);
}

static int32_t
acd_pause_resume(struct acd_softc *cdp, int32_t pause)
{
    int8_t ccb[16] = { ATAPI_PAUSE, 0, 0, 0, 0, 0, 0, 0, pause,
		       0, 0, 0, 0, 0, 0, 0 };

    return atapi_queue_cmd(cdp->atp, ccb, NULL, 0, 0, 30, NULL, NULL, NULL);
}

static int32_t
acd_mode_sense(struct acd_softc *cdp, u_int8_t page,
	       void *pagebuf, int32_t pagesize)
{
    int8_t ccb[16] = { ATAPI_MODE_SENSE_BIG, 0, page, 0, 0, 0, 0,
		       pagesize>>8, pagesize, 0, 0, 0, 0, 0, 0, 0 };
    int32_t error;

    error = atapi_queue_cmd(cdp->atp, ccb, pagebuf, pagesize, A_READ, 10, 
			    NULL, NULL, NULL);
#ifdef ACD_DEBUG
    atapi_dump("acd: mode sense ", pagebuf, pagesize);
#endif
    return error;
}

static int32_t
acd_mode_select(struct acd_softc *cdp, void *pagebuf, int32_t pagesize)
{
    int8_t ccb[16] = { ATAPI_MODE_SELECT_BIG, 0x10, 0, 0, 0, 0, 0,
		     pagesize>>8, pagesize, 0, 0, 0, 0, 0, 0, 0 };

#ifdef ACD_DEBUG
    printf("acd: modeselect pagesize=%d\n", pagesize);
    atapi_dump("acd: mode select ", pagebuf, pagesize);
#endif
    return atapi_queue_cmd(cdp->atp, ccb, pagebuf, pagesize, 0, 30, 
			   NULL, NULL, NULL);
}

static int32_t
acd_set_speed(struct acd_softc *cdp, int32_t speed)
{
    int8_t ccb[16] = { ATAPI_SET_SPEED, 0, 0xff, 0xff, speed>>8, speed, 
		       0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    return atapi_queue_cmd(cdp->atp, ccb, NULL, 0, 0, 30, NULL, NULL, NULL);
}

