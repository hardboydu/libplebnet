/*-
 * Copyright (c) 1998,1999 S�ren Schmidt
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
#include <sys/conf.h>
#include <sys/malloc.h>
#include <sys/buf.h>
#include <sys/bus.h>
#include <sys/mtio.h>
#include <sys/disklabel.h>
#include <sys/devicestat.h>
#if NAPM > 0
#include <machine/apm_bios.h>
#endif
#include <dev/ata/ata-all.h>
#include <dev/ata/atapi-all.h>
#include <dev/ata/atapi-tape.h>

static	d_open_t	astopen;
static	d_close_t	astclose;
static	d_ioctl_t	astioctl;
static	d_strategy_t	aststrategy;

static struct cdevsw ast_cdevsw = {
	/* open */	astopen,
	/* close */	astclose,
	/* read */	physread,
	/* write */	physwrite,
	/* ioctl */	astioctl,
	/* poll */	nopoll,
	/* mmap */	nommap,
	/* strategy */	aststrategy,
	/* name */	"ast",
	/* maj */	119,
	/* dump */	nodump,
	/* psize */	nopsize,
	/* flags */	D_TAPE,
	/* bmaj */	-1
};

/* prototypes */
int32_t astattach(struct atapi_softc *);
static int32_t ast_sense(struct ast_softc *);
static void ast_describe(struct ast_softc *);
static void ast_start(struct ast_softc *);
static int32_t ast_done(struct atapi_request *);
static int32_t ast_mode_sense(struct ast_softc *, u_int8_t, void *, int32_t); 
static int32_t ast_mode_select(struct ast_softc *, void *, int32_t);
static int32_t ast_write_filemark(struct ast_softc *, u_int8_t);
static int32_t ast_read_position(struct ast_softc *, int32_t, struct ast_readposition *);
static int32_t ast_space(struct ast_softc *, u_int8_t, u_int32_t);
static int32_t ast_locate(struct ast_softc *, int32_t, int32_t);
static int32_t ast_prevent_allow(struct ast_softc *stp, int32_t lock);
static int32_t ast_load_unload(struct ast_softc *, u_int8_t);
static int32_t ast_rewind(struct ast_softc *);
static int32_t ast_erase(struct ast_softc *);

/* internal vars */
static u_int64_t ast_total = 0;
MALLOC_DEFINE(M_AST, "AST driver", "ATAPI tape driver buffers");

int32_t 
astattach(struct atapi_softc *atp)
{
    struct ast_softc *stp;
    struct ast_readposition position;
    dev_t dev;
    static int32_t ast_cdev_done = 0, astnlun = 0;

    if (!ast_cdev_done) {
	cdevsw_add(&ast_cdevsw);
	ast_cdev_done = 1;
    }
    stp = malloc(sizeof(struct ast_softc), M_AST, M_NOWAIT);
    if (!stp) {
	printf("ast: out of memory\n");
	return -1;
    }
    bzero(stp, sizeof(struct ast_softc));
    bufq_init(&stp->buf_queue);
    stp->atp = atp;
    stp->lun = astnlun++;
    stp->atp->flags |= ATAPI_F_MEDIA_CHANGED;
    if (ast_sense(stp)) {
	free(stp, M_AST);
	return -1;
    }
    ast_describe(stp);
    if (!strcmp(stp->atp->atapi_parm->model, " OnStream DI-30")) {
	struct ast_transferpage transfer;
	struct ast_identifypage identify;

	stp->flags |= F_ONSTREAM;
	bzero(&transfer, sizeof(struct ast_transferpage));
	ast_mode_sense(stp, ATAPI_TAPE_TRANSFER_PAGE,
		       &transfer, sizeof(transfer));
#ifdef AST_DEBUG
	printf("ast: rd32k=%d rd32k5=%d wr32k=%d wr32k5=%d stream=%d\n",
	transfer.read32k, transfer.read32k5, 
	transfer.write32k, transfer.write32k5, transfer.streaming);
#endif

	bzero(&identify, sizeof(struct ast_identifypage));
	ast_mode_sense(stp, ATAPI_TAPE_IDENTIFY_PAGE,
		       &identify, sizeof(identify));
	strncpy(identify.ident, "FBSD", 4);
	ast_mode_select(stp, &identify, sizeof(identify));
	ast_read_position(stp, 0, &position);
    }
    devstat_add_entry(&stp->stats, "ast", stp->lun, DEV_BSIZE,
		      DEVSTAT_NO_ORDERED_TAGS,
		      DEVSTAT_TYPE_SEQUENTIAL | DEVSTAT_TYPE_IF_IDE,
		      DEVSTAT_PRIORITY_TAPE);
    dev = make_dev(&ast_cdevsw, dkmakeminor(stp->lun, 0, 0),
		   UID_ROOT, GID_OPERATOR, 0640, "rast%d", stp->lun);
    dev->si_drv1 = stp;
    dev->si_iosize_max = 252 * DEV_BSIZE;
    dev = make_dev(&ast_cdevsw, dkmakeminor(stp->lun, 0, 1),
		   UID_ROOT, GID_OPERATOR, 0640, "nrast%d", stp->lun);
    dev->si_drv1 = stp;
    dev->si_iosize_max = 252 * DEV_BSIZE;
    if ((stp->atp->devname = malloc(8, M_AST, M_NOWAIT)))
        sprintf(stp->atp->devname, "ast%d", stp->lun);
    return 0;
}

static int32_t
ast_sense(struct ast_softc *stp)
{
    int32_t count, error = 0;

    /* get drive capabilities, some drives needs this repeated */
    for (count = 0 ; count < 5 ; count++) {
	if (!(error = ast_mode_sense(stp, ATAPI_TAPE_CAP_PAGE,
				     &stp->cap, sizeof(stp->cap))))
	    break;
    }
    if (error) 
	return 1;

    stp->cap.max_speed = ntohs(stp->cap.max_speed);
    stp->cap.max_defects = ntohs(stp->cap.max_defects);
    stp->cap.ctl = ntohs(stp->cap.ctl);
    stp->cap.speed = ntohs(stp->cap.speed);
    stp->cap.buffer_size = ntohs(stp->cap.buffer_size);
    if (stp->cap.blk32k)
	stp->blksize = 32768;
    if (stp->cap.blk1024)
	stp->blksize = 1024;
    if (stp->cap.blk512)
	stp->blksize = 512;
    return 0;
}

static void 
ast_describe(struct ast_softc *stp)
{
    int8_t model_buf[40+1];
    int8_t revision_buf[8+1];

    bpack(stp->atp->atapi_parm->model, model_buf, sizeof(model_buf));
    bpack(stp->atp->atapi_parm->revision, revision_buf, sizeof(revision_buf));
    printf("ast%d: <%s/%s> tape drive at ata%d as %s\n",
	   stp->lun, model_buf, revision_buf,
	   stp->atp->controller->lun,
	   (stp->atp->unit == ATA_MASTER) ? "master" : "slave ");
    printf("ast%d: ", stp->lun);
    printf("%dKB/s, ", stp->cap.max_speed);
    printf("transfer limit %d blk%s, ", stp->cap.ctl, (stp->cap.ctl>1)?"s":"");
    printf("%dKB buffer, ", (stp->cap.buffer_size * DEV_BSIZE) / 1024);
    printf("%s\n", ata_mode2str(stp->atp->controller->mode[
                                (stp->atp->unit == ATA_MASTER) ? 0 : 1]));
    printf("ast%d: ", stp->lun);
    switch (stp->cap.medium_type) {
	case 0x00:	printf("Drive empty"); break;
	case 0x17:	printf("Travan 1 (400 Mbyte) media"); break;
	case 0xb6:	printf("Travan 4 (4 Gbyte) media"); break;
	case 0xda:	printf("OnStream ADR (15Gyte) media"); break;
	default: printf("Unknown media (0x%x)", stp->cap.medium_type);
    }
    if (stp->cap.readonly) printf(", readonly");
    if (stp->cap.reverse) printf(", reverse");
    if (stp->cap.eformat) printf(", eformat");
    if (stp->cap.qfa) printf(", qfa");
    if (stp->cap.lock) printf(", lock");
    if (stp->cap.locked) printf(", locked");
    if (stp->cap.prevent) printf(", prevent");
    if (stp->cap.eject) printf(", eject");
    if (stp->cap.disconnect) printf(", disconnect");
    if (stp->cap.ecc) printf(", ecc");
    if (stp->cap.compress) printf(", compress");
    if (stp->cap.blk512) printf(", 512b");
    if (stp->cap.blk1024) printf(", 1024b");
    if (stp->cap.blk32k) printf(", 32kb");
    printf("\n");
}

static int
astopen(dev_t dev, int32_t flags, int32_t fmt, struct proc *p)
{
    struct ast_softc *stp = dev->si_drv1;

    if (!stp)
	return ENXIO;

    if (stp->flags == F_OPEN)
	return EBUSY;

    if (stp->cap.lock)
	ast_prevent_allow(stp, 1);

    if (ast_sense(stp))
	printf("ast%d: sense media type failed\n", stp->lun);
    
    stp->flags &= ~(F_DATA_WRITTEN | F_FM_WRITTEN);
    stp->flags |= F_OPEN;
    stp->atp->flags &= ~ATAPI_F_MEDIA_CHANGED;
    ast_total = 0;
    return 0;
}

static int 
astclose(dev_t dev, int32_t flags, int32_t fmt, struct proc *p)
{
    struct ast_softc *stp = dev->si_drv1;

    /* flush buffers, some drives fail here, they should report ctl = 0 */
    if (stp->cap.ctl && (stp->flags & F_DATA_WRITTEN))
	ast_write_filemark(stp, 0);

    /* write filemark if data written to tape */
    if (!(stp->flags & F_ONSTREAM) &&
	(stp->flags & (F_DATA_WRITTEN | F_FM_WRITTEN)) == F_DATA_WRITTEN)
	ast_write_filemark(stp, WF_WRITE);

    /* if minor is even rewind on close */
    if (!(minor(dev) & 0x01))
	ast_rewind(stp);

    if (stp->cap.lock)
	ast_prevent_allow(stp, 0);

    stp->flags &= ~(F_OPEN | F_CTL_WARN);
#ifdef AST_DEBUG
    printf("ast%d: %llu total bytes transferred\n", stp->lun, ast_total);
#endif
    return 0;
}

static int 
astioctl(dev_t dev, u_long cmd, caddr_t addr, int32_t flag, struct proc *p)
{
    struct ast_softc *stp = dev->si_drv1;
    int32_t error = 0;

    switch (cmd) {
    case MTIOCGET:
	{
	    struct mtget *g = (struct mtget *) addr;

	    bzero(g, sizeof(struct mtget));
	    g->mt_type = 7;
	    g->mt_density = 1;
	    g->mt_blksiz = stp->blksize;
	    g->mt_comp = stp->cap.compress;
	    g->mt_density0 = 0; g->mt_density1 = 0;
	    g->mt_density2 = 0; g->mt_density3 = 0;
	    g->mt_blksiz0 = 0; g->mt_blksiz1 = 0;
	    g->mt_blksiz2 = 0; g->mt_blksiz3 = 0;
	    g->mt_comp0 = 0; g->mt_comp1 = 0;
	    g->mt_comp2 = 0; g->mt_comp3 = 0;
	    break;	 
	}
    case MTIOCTOP:
	{	
	    int32_t i;
	    struct mtop *mt = (struct mtop *)addr;

	    switch ((int16_t) (mt->mt_op)) {

	    case MTWEOF:
		for (i=0; i < mt->mt_count && !error; i++)
		    error = ast_write_filemark(stp, WF_WRITE);
		break;

	    case MTFSF:
		if (mt->mt_count)
		    error = ast_space(stp, SP_FM, mt->mt_count);
		break;

	    case MTBSF:
		if (mt->mt_count)
		    error = ast_space(stp, SP_FM, -(mt->mt_count));
		break;

	    case MTREW:
		error = ast_rewind(stp);
		break;

	    case MTOFFL:
		error = ast_load_unload(stp, SS_EJECT);
		break;

	    case MTNOP:
		error = ast_write_filemark(stp, 0);
		break;

	    case MTERASE:
		error = ast_erase(stp);
		break;

	    case MTEOD:
		error = ast_space(stp, SP_EOD, 0);
		break;

	    case MTRETENS:
		error = ast_load_unload(stp, SS_RETENSION | SS_LOAD);
		break;

	    case MTFSR:		
	    case MTBSR:
	    case MTCACHE:
	    case MTNOCACHE:
	    case MTSETBSIZ:
	    case MTSETDNSTY:
	    case MTCOMP:
	    default:
		error = EINVAL;
	    }
	    break;
	}
    case MTIOCRDSPOS:
	{
	    struct ast_readposition position;

	    if ((error = ast_read_position(stp, 0, &position)))
		break;
	    *(u_int32_t *)addr = position.tape;
	    break;
	}
    case MTIOCRDHPOS:
	{
	    struct ast_readposition position;

	    if ((error = ast_read_position(stp, 1, &position)))
		break;
	    *(u_int32_t *)addr = position.tape;
	    break;
	}
    case MTIOCSLOCATE:
	error = ast_locate(stp, 0, *(u_int32_t *)addr);
	break;
    case MTIOCHLOCATE:
	error = ast_locate(stp, 1, *(u_int32_t *)addr);
	break;
    default:
	error = ENOTTY;
    }
    return error;
}

static void 
aststrategy(struct buf *bp)
{
    struct ast_softc *stp = bp->b_dev->si_drv1;
    int32_t s;

    /* if it's a null transfer, return immediatly. */
    if (bp->b_bcount == 0) {
	bp->b_resid = 0;
	biodone(bp);
	return;
    }
    if (!(bp->b_flags & B_READ) && stp->flags & F_WRITEPROTECT) {
	bp->b_error = EPERM;
	bp->b_flags |= B_ERROR;
	biodone(bp);
	return;
    }
	
    /* check for != blocksize requests */
    if (bp->b_bcount % stp->blksize) {
	printf("ast%d: bad request, must be multiple of %d\n",
	       stp->lun, stp->blksize);
	bp->b_error = EIO;
	bp->b_flags |= B_ERROR;
	biodone(bp);
	return;
    }

    /* warn about transfers bigger than the device suggests */
    if (bp->b_bcount > stp->blksize * stp->cap.ctl) {  
	if ((stp->flags & F_CTL_WARN) == 0) {
	    printf("ast%d: WARNING: CTL exceeded %ld>%d\n", 
		    stp->lun, bp->b_bcount, stp->blksize * stp->cap.ctl);
	    stp->flags |= F_CTL_WARN;
	}
    }

    s = splbio();
    bufq_insert_tail(&stp->buf_queue, bp);
    ast_start(stp);
    splx(s);
}

static void 
ast_start(struct ast_softc *stp)
{
    struct buf *bp = bufq_first(&stp->buf_queue);
    u_int32_t blkcount;
    int8_t ccb[16];
    
    if (!bp)
	return;

    bzero(ccb, sizeof(ccb));

    if (bp->b_flags & B_READ) {
	ccb[0] = ATAPI_READ;
	if (!(stp->flags & ATAPI_F_DSC_USED))
	    atapi_queue_cmd(stp->atp, ccb, NULL, 0, 0, 2*60, NULL, NULL, NULL);
    } 
    else {
	ccb[0] = ATAPI_WRITE;
	if (!(stp->flags & ATAPI_F_DSC_USED))
	    atapi_queue_cmd(stp->atp, ccb, NULL, 0, 0, 2*60, NULL, NULL, NULL);
    } 
    
    bufq_remove(&stp->buf_queue, bp);
    blkcount = bp->b_bcount / stp->blksize;

    ccb[1] = 1;
    ccb[2] = blkcount>>16;
    ccb[3] = blkcount>>8;
    ccb[4] = blkcount;

    devstat_start_transaction(&stp->stats);

    atapi_queue_cmd(stp->atp, ccb, bp->b_data, bp->b_bcount, 
		    (bp->b_flags & B_READ) ? A_READ : 0, 60, ast_done, stp, bp);
}

static int32_t 
ast_done(struct atapi_request *request)
{
    struct buf *bp = request->bp;
    struct ast_softc *stp = request->driver;

    if (request->error) {
	bp->b_error = request->error;
	bp->b_flags |= B_ERROR;
    }
    else {
	if (!(bp->b_flags & B_READ))
	    stp->flags |= F_DATA_WRITTEN;
	bp->b_resid = request->bytecount;
        ast_total += (bp->b_bcount - bp->b_resid);
    }
    devstat_end_transaction_buf(&stp->stats, bp);
    biodone(bp);
    ast_start(stp);
    return 0;
}

static int32_t
ast_mode_sense(struct ast_softc *stp, u_int8_t page,
	       void *pagebuf, int32_t pagesize)
{
    int8_t ccb[16] = { ATAPI_MODE_SENSE, 0x08, page, pagesize>>8, pagesize,
		       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    int32_t error;
 
    error = atapi_queue_cmd(stp->atp, ccb, pagebuf, pagesize, A_READ, 10, 
			    NULL, NULL, NULL);
#ifdef AST_DEBUG
    atapi_dump("ast: mode sense ", pagebuf, pagesize);
#endif
    return error;
}

static int32_t	 
ast_mode_select(struct ast_softc *stp, void *pagebuf, int32_t pagesize)
{
    int8_t ccb[16] = { ATAPI_MODE_SELECT, 0x10, 0, pagesize>>8, pagesize,
		       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
     
#ifdef AST_DEBUG
    printf("ast: modeselect pagesize=%d\n", pagesize);
    atapi_dump("ast: mode select ", pagebuf, pagesize);
#endif
    return atapi_queue_cmd(stp->atp, ccb, pagebuf, pagesize, 0, 10,
			   NULL, NULL, NULL);
}

static int32_t
ast_write_filemark(struct ast_softc *stp, u_int8_t function)
{
    int8_t ccb[16] = { ATAPI_WEOF, 0x01, 0, 0, function, 0, 0, 0,
		       0, 0, 0, 0, 0, 0, 0, 0 };
    int32_t error;

    if (stp->flags & F_ONSTREAM)
	ccb[4] = 0x00;		/* only flush buffers supported */
    else {
	if (function) {
	    if (stp->flags & F_FM_WRITTEN)
		stp->flags &= ~F_DATA_WRITTEN;
	    else
		stp->flags |= F_FM_WRITTEN;
	}
    }
    error = atapi_queue_cmd(stp->atp, ccb, NULL, 0, 0, 10, NULL, NULL, NULL);
    if (error)
	return error;
    return atapi_wait_ready(stp->atp, 5*60);
}

static int32_t
ast_read_position(struct ast_softc *stp, int32_t hard,
		  struct ast_readposition *position)
{
    int8_t ccb[16] = { ATAPI_READ_POSITION, (hard ? 0x01 : 0), 0, 0, 0, 0, 0, 0,
		       0, 0, 0, 0, 0, 0, 0, 0 };
    int32_t error;

    error = atapi_queue_cmd(stp->atp, ccb, position, 
			    sizeof(struct ast_readposition), A_READ, 10,
			    NULL, NULL, NULL);
    position->tape = ntohl(position->tape);
    position->host = ntohl(position->host);
#ifdef AST_DEBUG
    printf("ast%d: BOP=%d EOP=%d host=%ld tape=%ld in buf=%d error=%02x\n",
	   stp->lun, position->bop, position->eop, ntohl(position->host), 
	   ntohl(position->tape), position->blks_in_buf, error);
#endif
    return error;
}

static int32_t
ast_space(struct ast_softc *stp, u_int8_t function, u_int32_t count)
{
    int8_t ccb[16] = { ATAPI_SPACE, function, count>>16, count>>8, count,
		       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    return atapi_queue_cmd(stp->atp, ccb, NULL, 0, 0, 60*60, NULL, NULL, NULL);
}

static int32_t
ast_locate(struct ast_softc *stp, int32_t hard, int32_t pos)
{
    int8_t ccb[16] = { ATAPI_LOCATE, 0x01 | (hard ? 0x4 : 0), 0,
		       pos>>24, pos>>16, pos>>8, pos,
		       0, 0, 0, 0, 0, 0, 0, 0, 0 };
    int32_t error;

    error = atapi_queue_cmd(stp->atp, ccb, NULL, 0, 0, 10, NULL, NULL, NULL);
    if (error)
	return error;
    return atapi_wait_ready(stp->atp, 60*60);
}

static int32_t
ast_prevent_allow(struct ast_softc *stp, int32_t lock)
{
    int8_t ccb[16] = { ATAPI_PREVENT_ALLOW, 0, 0, 0, lock,
		       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    return atapi_queue_cmd(stp->atp, ccb, NULL, 0, 0,30, NULL, NULL, NULL);
}

static int32_t
ast_load_unload(struct ast_softc *stp, u_int8_t function)
{
    int8_t ccb[16] = { ATAPI_START_STOP, 0x01, 0, 0, function, 0, 0, 0,
		       0, 0, 0, 0, 0, 0, 0, 0 };
    int32_t error;

    if ((function & SS_EJECT) && !stp->cap.eject)
	return 0;
    error = atapi_queue_cmd(stp->atp, ccb, NULL, 0, 0, 10, NULL, NULL, NULL);
    if (error)
	return error;
    tsleep((caddr_t)&error, PRIBIO, "astlu", 1 * hz);
    if (function == SS_EJECT)
	return 0;
    return atapi_wait_ready(stp->atp, 60*60);
}

static int32_t
ast_rewind(struct ast_softc *stp)
{
    int8_t ccb[16] = { ATAPI_REWIND, 0x01, 0, 0, 0, 0, 0, 0,
		       0, 0, 0, 0, 0, 0, 0, 0 };
    int32_t error;

    error = atapi_queue_cmd(stp->atp, ccb, NULL, 0, 0, 10, NULL, NULL, NULL);
    if (error)
	return error;
    return atapi_wait_ready(stp->atp, 60*60);
}

static int32_t
ast_erase(struct ast_softc *stp)
{
    int8_t ccb[16] = { ATAPI_ERASE, 3, 0, 0, 0, 0, 0, 0,
		       0, 0, 0, 0, 0, 0, 0, 0 };
    int32_t error;

    if ((error = ast_rewind(stp)))
	return error;

    return atapi_queue_cmd(stp->atp, ccb, NULL, 0, 0, 60*60, NULL, NULL, NULL);
}
