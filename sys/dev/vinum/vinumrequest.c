/*-
 * Copyright (c) 1997, 1998
 *	Nan Yang Computer Services Limited.  All rights reserved.
 *
 *  This software is distributed under the so-called ``Berkeley
 *  License'':
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
 *	This product includes software developed by Nan Yang Computer
 *      Services Limited.
 * 4. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even if
 * advised of the possibility of such damage.
 *
 * $Id: vinumrequest.c,v 1.23 1999/03/20 21:58:38 grog Exp grog $
 */

#include <dev/vinum/vinumhdr.h>
#include <dev/vinum/request.h>
#include <miscfs/specfs/specdev.h>
#include <sys/resourcevar.h>

enum requeststatus bre(struct request *rq,
    int plexno,
    daddr_t * diskstart,
    daddr_t diskend);
enum requeststatus bre5(struct request *rq,
    int plexno,
    daddr_t * diskstart,
    daddr_t diskend);
enum requeststatus build_read_request(struct request *rq, int volplexno);
enum requeststatus build_write_request(struct request *rq);
enum requeststatus build_rq_buffer(struct rqelement *rqe, struct plex *plex);
void freerq(struct request *rq);
int find_alternate_sd(struct request *rq);
int check_range_covered(struct request *);
void complete_rqe(struct buf *bp);
void complete_raid5_write(struct rqelement *);
int abortrequest(struct request *rq, int error);
void sdio_done(struct buf *bp);
int vinum_bounds_check(struct buf *bp, struct volume *vol);
caddr_t allocdatabuf(struct rqelement *rqe);
void freedatabuf(struct rqelement *rqe);

#ifdef VINUMDEBUG
struct rqinfo rqinfo[RQINFO_SIZE];
struct rqinfo *rqip = rqinfo;

void 
logrq(enum rqinfo_type type, union rqinfou info, struct buf *ubp)
{
    int s = splhigh();

    microtime(&rqip->timestamp);			    /* when did this happen? */
    rqip->type = type;
    rqip->bp = ubp;					    /* user buffer */
    switch (type) {
    case loginfo_user_bp:
    case loginfo_user_bpl:
	bcopy(info.bp, &rqip->info.b, sizeof(struct buf));
	break;

    case loginfo_iodone:
    case loginfo_rqe:
    case loginfo_raid5_data:
    case loginfo_raid5_parity:
	bcopy(info.rqe, &rqip->info.rqe, sizeof(struct rqelement));
	break;

    case loginfo_unused:
	break;
    }
    rqip++;
    if (rqip >= &rqinfo[RQINFO_SIZE])			    /* wrap around */
	rqip = rqinfo;
    splx(s);
}

#endif

void 
vinumstrategy(struct buf *bp)
{
    int volno;
    struct volume *vol = NULL;

    switch (DEVTYPE(bp->b_dev)) {
    case VINUM_SD_TYPE:
    case VINUM_RAWSD_TYPE:
	sdio(bp);
	return;

	/*
	 * In fact, vinum doesn't handle drives: they're
	 * handled directly by the disk drivers
	 */
    case VINUM_DRIVE_TYPE:
    default:
	bp->b_error = EIO;				    /* I/O error */
	bp->b_flags |= B_ERROR;
	biodone(bp);
	return;

    case VINUM_VOLUME_TYPE:				    /* volume I/O */
	volno = Volno(bp->b_dev);
	vol = &VOL[volno];
	if (vol->state != volume_up) {			    /* can't access this volume */
	    bp->b_error = EIO;				    /* I/O error */
	    bp->b_flags |= B_ERROR;
	    biodone(bp);
	    return;
	}
	if (vinum_bounds_check(bp, vol) <= 0) {		    /* don't like them bounds */
	    biodone(bp);				    /* have nothing to do with this */
	    return;
	}
	/* FALLTHROUGH */
	/*
	 * Plex I/O is pretty much the same as volume I/O
	 * for a single plex.  Indicate this by passing a NULL
	 * pointer (set above) for the volume
	 */
    case VINUM_PLEX_TYPE:
    case VINUM_RAWPLEX_TYPE:
	bp->b_resid = bp->b_bcount;			    /* transfer everything */
	vinumstart(bp, 0);
	return;
    }
}

/*
 * Start a transfer.  Return -1 on error,
 * 0 if OK, 1 if we need to retry.
 * Parameter reviveok is set when doing
 * transfers for revives: it allows transfers to
 * be started immediately when a revive is in
 * progress.  During revive, normal transfers
 * are queued if they share address space with
 * a currently active revive operation.
 */
int 
vinumstart(struct buf *bp, int reviveok)
{
    int plexno;
    int maxplex;					    /* maximum number of plexes to handle */
    struct volume *vol;
    struct request *rq;					    /* build up our request here */
    enum requeststatus status;

#if VINUMDEBUG
    if (debug & DEBUG_LASTREQS)
	logrq(loginfo_user_bp, (union rqinfou) bp, bp);
#endif

    /*
     * XXX In these routines, we're assuming that
     * we will always be called with bp->b_bcount
     * which is a multiple of the sector size.  This
     * is a reasonable assumption, since we are only
     * called from system routines.  Should we check
     * anyway?
     */

    if ((bp->b_bcount % DEV_BSIZE) != 0) {		    /* bad length */
	bp->b_error = EINVAL;				    /* invalid size */
	bp->b_flags |= B_ERROR;
	biodone(bp);
	return -1;
    }
    rq = (struct request *) Malloc(sizeof(struct request)); /* allocate a request struct */
    if (rq == NULL) {					    /* can't do it */
	bp->b_error = ENOMEM;				    /* can't get memory */
	bp->b_flags |= B_ERROR;
	biodone(bp);
	return -1;
    }
    bzero(rq, sizeof(struct request));

    /*
     * Note the volume ID.  This can be NULL, which
     * the request building functions use as an
     * indication for single plex I/O
     */
    rq->bp = bp;					    /* and the user buffer struct */

    if (DEVTYPE(bp->b_dev) == VINUM_VOLUME_TYPE) {	    /* it's a volume, */
	rq->volplex.volno = Volno(bp->b_dev);		    /* get the volume number */
	vol = &VOL[rq->volplex.volno];			    /* and point to it */
	vol->active++;					    /* one more active request */
	maxplex = vol->plexes;				    /* consider all its plexes */
    } else {
	vol = NULL;					    /* no volume */
	rq->volplex.plexno = Plexno(bp->b_dev);		    /* point to the plex */
	rq->isplex = 1;					    /* note that it's a plex */
	maxplex = 1;					    /* just the one plex */
    }

    if (bp->b_flags & B_READ) {
	/*
	 * This is a read request.  Decide
	 * which plex to read from.
	 *
	 * There's a potential race condition here,
	 * since we're not locked, and we could end
	 * up multiply incrementing the round-robin
	 * counter.  This doesn't have any serious
	 * effects, however.
	 */
	if (vol != NULL) {
	    vol->reads++;
	    vol->bytes_read += bp->b_bcount;
	    plexno = vol->preferred_plex;		    /* get the plex to use */
	    if (plexno < 0) {				    /* round robin */
		plexno = vol->last_plex_read;
		vol->last_plex_read++;
		if (vol->last_plex_read == vol->plexes)	    /* got the the end? */
		    vol->last_plex_read = 0;		    /* wrap around */
	    }
	    status = build_read_request(rq, plexno);	    /* build a request */
	} else {
	    daddr_t diskaddr = bp->b_blkno;		    /* start offset of transfer */
	    status = bre(rq,				    /* build a request list */
		rq->volplex.plexno,
		&diskaddr,
		diskaddr + (bp->b_bcount / DEV_BSIZE));
	}

	if ((status > REQUEST_RECOVERED)		    /* can't satisfy it */
	||(bp->b_flags & B_DONE)) {			    /* XXX shouldn't get this without bad status */
	    if (status == REQUEST_DOWN) {		    /* not enough subdisks */
		bp->b_error = EIO;			    /* I/O error */
		bp->b_flags |= B_ERROR;
	    }
	    biodone(bp);
	    freerq(rq);
	    return -1;
	}
	return launch_requests(rq, reviveok);		    /* now start the requests if we can */
    } else
	/*
	 * This is a write operation.  We write to all
	 * plexes.  If this is a RAID 5 plex, we must also
	 * update the parity stripe.
	 */
    {
	if (vol != NULL) {
	    vol->writes++;
	    vol->bytes_written += bp->b_bcount;
	    status = build_write_request(rq);		    /* Not all the subdisks are up */
	} else {					    /* plex I/O */
	    daddr_t diskstart;

	    diskstart = bp->b_blkno;			    /* start offset of transfer */
	    status = bre(rq,
		Plexno(bp->b_dev),
		&diskstart,
		bp->b_blkno + (bp->b_bcount / DEV_BSIZE));  /* build requests for the plex */
	}
	if ((status > REQUEST_RECOVERED)		    /* can't satisfy it */
	||(bp->b_flags & B_DONE)) {			    /* XXX shouldn't get this without bad status */
	    if (status == REQUEST_DOWN) {		    /* not enough subdisks */
		bp->b_error = EIO;			    /* I/O error */
		bp->b_flags |= B_ERROR;
	    }
	    if ((bp->b_flags & B_DONE) == 0)
		biodone(bp);
	    freerq(rq);
	    return -1;
	}
	return launch_requests(rq, reviveok);		    /* now start the requests if we can */
    }
}

/*
 * Call the low-level strategy routines to
 * perform the requests in a struct request
 */
int 
launch_requests(struct request *rq, int reviveok)
{
    struct rqgroup *rqg;
    int rqno;						    /* loop index */
    struct rqelement *rqe;				    /* current element */
    int s;

    /*
     * First find out whether we're reviving, and the
     * request contains a conflict.  If so, we hang
     * the request off plex->waitlist of the first
     * plex we find which is reviving
     */
    if ((rq->flags & XFR_REVIVECONFLICT)		    /* possible revive conflict */
    &&(!reviveok)) {					    /* and we don't want to do it now, */
	struct sd *sd;
	struct request *waitlist;			    /* point to the waitlist */

	sd = &SD[rq->sdno];
	if (sd->waitlist != NULL) {			    /* something there already, */
	    waitlist = sd->waitlist;
	    while (waitlist->next != NULL)		    /* find the end */
		waitlist = waitlist->next;
	    waitlist->next = rq;			    /* hook our request there */
	} else
	    sd->waitlist = rq;				    /* hook our request at the front */

#if VINUMDEBUG
	if (debug & DEBUG_REVIVECONFLICT)
	    log(LOG_DEBUG,
		"Revive conflict sd %d: %x\n%s dev %d.%d, offset 0x%x, length %ld\n",
		rq->sdno,
		(u_int) rq,
		rq->bp->b_flags & B_READ ? "Read" : "Write",
		major(rq->bp->b_dev),
		minor(rq->bp->b_dev),
		rq->bp->b_blkno,
		rq->bp->b_bcount);			    /* XXX */
#endif
	return 0;					    /* and get out of here */
    }
    rq->active = 0;					    /* nothing yet */
    /* XXX This is probably due to a bug */
    if (rq->rqg == NULL) {				    /* no request */
	log(LOG_ERR, "vinum: null rqg\n");
	abortrequest(rq, EINVAL);
	return -1;
    }
#if VINUMDEBUG
    if (debug & DEBUG_ADDRESSES)
	log(LOG_DEBUG,
	    "Request: %x\n%s dev %d.%d, offset 0x%x, length %ld\n",
	    (u_int) rq,
	    rq->bp->b_flags & B_READ ? "Read" : "Write",
	    major(rq->bp->b_dev),
	    minor(rq->bp->b_dev),
	    rq->bp->b_blkno,
	    rq->bp->b_bcount);				    /* XXX */
    vinum_conf.lastrq = (int) rq;
    vinum_conf.lastbuf = rq->bp;
    if (debug & DEBUG_LASTREQS)
	logrq(loginfo_user_bpl, (union rqinfou) rq->bp, rq->bp);
#endif
    s = splbio();
    for (rqg = rq->rqg; rqg != NULL; rqg = rqg->next) {	    /* through the whole request chain */
	rqg->active = rqg->count;			    /* they're all active */
	rq->active++;					    /* one more active request group */
	for (rqno = 0; rqno < rqg->count; rqno++) {
	    rqe = &rqg->rqe[rqno];
	    if (rqe->flags & XFR_BAD_SUBDISK)		    /* this subdisk is bad, */
		rqg->active--;				    /* one less active request */
	    else {
		if ((rqe->b.b_flags & B_READ) == 0)
		    rqe->b.b_vp->v_numoutput++;		    /* one more output going */
		rqe->b.b_flags |= B_ORDERED;		    /* XXX chase SCSI driver */
#if VINUMDEBUG
		if (debug & DEBUG_ADDRESSES)
		    log(LOG_DEBUG,
			"  %s dev %d.%d, sd %d, offset 0x%x, devoffset 0x%x, length %ld\n",
			rqe->b.b_flags & B_READ ? "Read" : "Write",
			major(rqe->b.b_dev),
			minor(rqe->b.b_dev),
			rqe->sdno,
			(u_int) (rqe->b.b_blkno - SD[rqe->sdno].driveoffset),
			rqe->b.b_blkno,
			rqe->b.b_bcount);		    /* XXX */
		if (debug & DEBUG_NUMOUTPUT)
		    log(LOG_DEBUG,
			"  vinumstart sd %d numoutput %ld\n",
			rqe->sdno,
			rqe->b.b_vp->v_numoutput);
		if (debug & DEBUG_LASTREQS)
		    logrq(loginfo_rqe, (union rqinfou) rqe, rq->bp);
#endif
		/* fire off the request */
		(*bdevsw(rqe->b.b_dev)->d_strategy) (&rqe->b);
	    }
	    /* XXX Do we need caching?  Think about this more */
	}
    }
    splx(s);
    return 0;
}

/*
 * define the low-level requests needed to perform a
 * high-level I/O operation for a specific plex 'plexno'.
 *
 * Return 0 if all subdisks involved in the request are up, 1 if some
 * subdisks are not up, and -1 if the request is at least partially
 * outside the bounds of the subdisks.
 *
 * Modify the pointer *diskstart to point to the end address.  On
 * read, return on the first bad subdisk, so that the caller
 * (build_read_request) can try alternatives.
 *
 * On entry to this routine, the rqg structures are not assigned.  The
 * assignment is performed by expandrq().  Strictly speaking, the
 * elements rqe->sdno of all entries should be set to -1, since 0
 * (from bzero) is a valid subdisk number.  We avoid this problem by
 * initializing the ones we use, and not looking at the others (index
 * >= rqg->requests).
 */
enum requeststatus 
bre(struct request *rq,
    int plexno,
    daddr_t * diskaddr,
    daddr_t diskend)
{
    int sdno;
    struct sd *sd;
    struct rqgroup *rqg;
    struct buf *bp;					    /* user's bp */
    struct plex *plex;
    enum requeststatus status;				    /* return value */
    daddr_t plexoffset;					    /* offset of transfer in plex */
    daddr_t stripebase;					    /* base address of stripe (1st subdisk) */
    daddr_t stripeoffset;				    /* offset in stripe */
    daddr_t blockoffset;				    /* offset in stripe on subdisk */
    struct rqelement *rqe;				    /* point to this request information */
    daddr_t diskstart = *diskaddr;			    /* remember where this transfer starts */

    bp = rq->bp;					    /* buffer pointer */
    status = REQUEST_OK;				    /* return value: OK until proven otherwise */
    plex = &PLEX[plexno];				    /* point to the plex */

    switch (plex->organization) {
    case plex_concat:
	for (sdno = 0; sdno < plex->subdisks; sdno++) {
	    sd = &SD[plex->sdnos[sdno]];
	    if ((*diskaddr < (sd->plexoffset + sd->sectors)) /* The request starts before the end of this */
	    &&(diskend > sd->plexoffset)) {		    /* subdisk and ends after the start of this sd */
		if (sd->state != sd_up) {
		    enum requeststatus s;

		    s = checksdstate(sd, rq, *diskaddr, diskend); /* do we need to change state? */
		    if (s)
			return s;			    /* XXX get this right */
		}
		rqg = allocrqg(rq, 1);			    /* space for the request */
		if (rqg == NULL) {			    /* malloc failed */
		    bp->b_flags |= B_ERROR;
		    bp->b_error = ENOMEM;
		    biodone(bp);
		    return REQUEST_ENOMEM;
		}
		rqg->plexno = plexno;

		rqe = &rqg->rqe[0];			    /* point to the element */
		rqe->rqg = rqg;				    /* group */
		rqe->sdno = sd->sdno;			    /* put in the subdisk number */
		plexoffset = max(sd->plexoffset, *diskaddr); /* start offset in plex */
		rqe->sdoffset = plexoffset - sd->plexoffset; /* start offset in subdisk */
		rqe->useroffset = plexoffset - diskstart;   /* start offset in user buffer */
		rqe->dataoffset = 0;
		rqe->datalen = min(diskend - *diskaddr,	    /* number of sectors to transfer in this sd */
		    sd->sectors - rqe->sdoffset);
		rqe->groupoffset = 0;			    /* no groups for concatenated plexes */
		rqe->grouplen = 0;
		rqe->buflen = rqe->datalen;		    /* buffer length is data buffer length */
		rqe->flags = 0;
		rqe->driveno = sd->driveno;
		*diskaddr += rqe->datalen;		    /* bump the address */
		if (build_rq_buffer(rqe, plex)) {	    /* build the buffer */
		    deallocrqg(rqg);
		    bp->b_flags |= B_ERROR;
		    bp->b_error = ENOMEM;
		    biodone(bp);
		    return REQUEST_ENOMEM;		    /* can't do it */
		}
	    }
	    if (*diskaddr > diskend)			    /* we're finished, */
		break;					    /* get out of here */
	}
	break;

    case plex_striped:
	{
	    while (*diskaddr < diskend) {		    /* until we get it all sorted out */
		/*
		 * The offset of the start address from
		 * the start of the stripe
		 */
		stripeoffset = *diskaddr % (plex->stripesize * plex->subdisks);

		/*
		 * The plex-relative address of the
		 * start of the stripe
		 */
		stripebase = *diskaddr - stripeoffset;

		/*
		 * The number of the subdisk in which
		 * the start is located
		 */
		sdno = stripeoffset / plex->stripesize;

		/*
		 * The offset from the beginning of the stripe
		 * on this subdisk
		 */
		blockoffset = stripeoffset % plex->stripesize;

		sd = &SD[plex->sdnos[sdno]];		    /* the subdisk in question */
		if (sd->state != sd_up) {
		    enum requeststatus s;

		    s = checksdstate(sd, rq, *diskaddr, diskend); /* do we need to change state? */
		    if (s)				    /* give up? */
			return s;			    /* yup */
		}
		rqg = allocrqg(rq, 1);			    /* space for the request */
		if (rqg == NULL) {			    /* malloc failed */
		    bp->b_flags |= B_ERROR;
		    bp->b_error = ENOMEM;
		    biodone(bp);
		    return REQUEST_ENOMEM;
		}
		rqg->plexno = plexno;

		rqe = &rqg->rqe[0];			    /* point to the element */
		rqe->rqg = rqg;
		rqe->sdoffset = stripebase / plex->subdisks + blockoffset; /* start offset in this subdisk */
		rqe->useroffset = *diskaddr - diskstart;    /* The offset of the start in the user buffer */
		rqe->dataoffset = 0;
		rqe->datalen = min(diskend - *diskaddr,	    /* the amount remaining to transfer */
		    plex->stripesize - blockoffset);	    /* and the amount left in this stripe */
		rqe->groupoffset = 0;			    /* no groups for striped plexes */
		rqe->grouplen = 0;
		rqe->buflen = rqe->datalen;		    /* buffer length is data buffer length */
		rqe->flags = 0;
		rqe->sdno = sd->sdno;			    /* put in the subdisk number */
		rqe->driveno = sd->driveno;

		if (rqe->sdoffset >= sd->sectors) {	    /* starts beyond the end of the subdisk? */
		    deallocrqg(rqg);
#if VINUMDEBUG
		    if (debug & DEBUG_EOFINFO) {	    /* tell on the request */
			log(LOG_DEBUG,
			    "vinum: EOF on plex %s, sd %s offset %x (user offset %x)\n",
			    plex->name,
			    sd->name,
			    (u_int) sd->sectors,
			    bp->b_blkno);
			log(LOG_DEBUG,
			    "vinum: stripebase %x, stripeoffset %x, blockoffset %x\n",
			    stripebase,
			    stripeoffset,
			    blockoffset);
		    }
#endif
		    return REQUEST_EOF;
		} else if (rqe->sdoffset + rqe->datalen > sd->sectors) /* ends beyond the end of the subdisk? */
		    rqe->datalen = sd->sectors - rqe->sdoffset;	/* yes, truncate */

		if (build_rq_buffer(rqe, plex)) {	    /* build the buffer */
		    deallocrqg(rqg);
		    bp->b_flags |= B_ERROR;
		    bp->b_error = ENOMEM;
		    biodone(bp);
		    return REQUEST_ENOMEM;		    /* can't do it */
		}
		*diskaddr += rqe->datalen;		    /* look at the remainder */
		if (*diskaddr < diskend) {		    /* didn't finish the request on this stripe */
		    plex->multiblock++;			    /* count another one */
		    if (sdno == plex->subdisks - 1)	    /* last subdisk, */
			plex->multistripe++;		    /* another stripe as well */
		}
	    }
	}
	break;


    default:
	log(LOG_ERR, "vinum: invalid plex type %d in bre\n", plex->organization);
	status = REQUEST_DOWN;				    /* can't access it */
    }

    return status;
}

/*
 * Build up a request structure for reading volumes.
 * This function is not needed for plex reads, since there's
 * no recovery if a plex read can't be satisified.
 */
enum requeststatus 
build_read_request(struct request *rq,			    /* request */
    int plexindex)
{							    /* index in the volume's plex table */
    struct buf *bp;
    daddr_t startaddr;					    /* offset of previous part of transfer */
    daddr_t diskaddr;					    /* offset of current part of transfer */
    daddr_t diskend;					    /* and end offset of transfer */
    int plexno;						    /* plex index in vinum_conf */
    struct rqgroup *rqg;				    /* point to the request we're working on */
    struct volume *vol;					    /* volume in question */
    off_t oldstart;					    /* note where we started */
    int recovered = 0;					    /* set if we recover a read */
    enum requeststatus status = REQUEST_OK;

    bp = rq->bp;					    /* buffer pointer */
    diskaddr = bp->b_blkno;				    /* start offset of transfer */
    diskend = diskaddr + (bp->b_bcount / DEV_BSIZE);	    /* and end offset of transfer */
    rqg = &rq->rqg[plexindex];				    /* plex request */
    vol = &VOL[rq->volplex.volno];			    /* point to volume */

    while (diskaddr < diskend) {			    /* build up request components */
	startaddr = diskaddr;
	status = bre(rq, vol->plex[plexindex], &diskaddr, diskend); /* build up a request */
	switch (status) {
	case REQUEST_OK:
	    continue;

	case REQUEST_RECOVERED:
	    recovered = 1;
	    break;

	case REQUEST_EOF:
	case REQUEST_ENOMEM:
	    return status;

	    /*
	     * if we get here, we have either had a failure or
	     * a RAID 5 recovery.  We don't want to use the
	     * recovery, because it's expensive, so first we
	     * check if we have alternatives
	     */
	case REQUEST_DOWN:				    /* can't access the plex */
	    if (vol != NULL) {				    /* and this is volume I/O */
		/*
		 * Try to satisfy the request
		 * from another plex
		 */
		for (plexno = 0; plexno < vol->plexes; plexno++) {
		    diskaddr = startaddr;		    /* start at the beginning again */
		    oldstart = startaddr;		    /* and note where that was */
		    if (plexno != plexindex) {		    /* don't try this plex again */
			bre(rq, vol->plex[plexno], &diskaddr, diskend);	/* try a request */
			if (diskaddr > oldstart) {	    /* we satisfied another part */
			    recovered = 1;		    /* we recovered from the problem */
			    status = REQUEST_OK;	    /* don't complain about it */
			    break;
			}
		    }
		    if (plexno == (vol->plexes - 1))	    /* couldn't satisfy the request */
			return REQUEST_DOWN;		    /* failed */
		}
	    } else
		return REQUEST_DOWN;			    /* bad luck */
	}
	if (recovered)
	    vol->recovered_reads += recovered;		    /* adjust our recovery count */
    }
    return status;
}

/*
 * Build up a request structure for writes.
 * Return 0 if all subdisks involved in the request are up, 1 if some
 * subdisks are not up, and -1 if the request is at least partially
 * outside the bounds of the subdisks.
 */
enum requeststatus 
build_write_request(struct request *rq)
{							    /* request */
    struct buf *bp;
    daddr_t diskstart;					    /* offset of current part of transfer */
    daddr_t diskend;					    /* and end offset of transfer */
    int plexno;						    /* plex index in vinum_conf */
    struct volume *vol;					    /* volume in question */
    enum requeststatus status;

    bp = rq->bp;					    /* buffer pointer */
    vol = &VOL[rq->volplex.volno];			    /* point to volume */
    diskend = bp->b_blkno + (bp->b_bcount / DEV_BSIZE);	    /* end offset of transfer */
    status = REQUEST_DOWN;				    /* assume the worst */
    for (plexno = 0; plexno < vol->plexes; plexno++) {
	diskstart = bp->b_blkno;			    /* start offset of transfer */
	/*
	 * Build requests for the plex.
	 * We take the best possible result here (min,
	 * not max): we're happy if we can write at all
	 */
	status = min(status, bre(rq,
		vol->plex[plexno],
		&diskstart,
		diskend));
    }
    return status;
}

/* Fill in the struct buf part of a request element. */
enum requeststatus 
build_rq_buffer(struct rqelement *rqe, struct plex *plex)
{
    struct sd *sd;					    /* point to subdisk */
    struct volume *vol;
    struct buf *bp;
    struct buf *ubp;					    /* user (high level) buffer header */

    vol = &VOL[rqe->rqg->rq->volplex.volno];
    sd = &SD[rqe->sdno];				    /* point to subdisk */
    bp = &rqe->b;
    ubp = rqe->rqg->rq->bp;				    /* pointer to user buffer header */

    /* Initialize the buf struct */
    bzero(&rqe->b, sizeof(struct buf));
    bp->b_flags = ubp->b_flags & (B_NOCACHE | B_READ | B_ASYNC); /* copy these flags from user bp */
    bp->b_flags |= B_CALL | B_BUSY;			    /* inform us when it's done */
    /*
     * XXX Should we check for reviving plexes here, and
     * set B_ORDERED if so?
     */
    bp->b_iodone = complete_rqe;			    /* by calling us here */
    bp->b_dev = DRIVE[rqe->driveno].vp->v_rdev;		    /* drive device */
    bp->b_blkno = rqe->sdoffset + sd->driveoffset;	    /* start address */
    bp->b_bcount = rqe->buflen << DEV_BSHIFT;		    /* number of bytes to transfer */
    bp->b_resid = bp->b_bcount;				    /* and it's still all waiting */
    bp->b_bufsize = bp->b_bcount;			    /* and buffer size */
    bp->b_vp = DRIVE[rqe->driveno].vp;			    /* drive vnode */
    bp->b_rcred = FSCRED;				    /* we have the file system credentials */
    bp->b_wcred = FSCRED;				    /* we have the file system credentials */

    if (rqe->flags & XFR_MALLOCED) {			    /* this operation requires a malloced buffer */
	bp->b_data = Malloc(bp->b_bcount);		    /* get a buffer to put it in */
	if (bp->b_data == NULL) {			    /* failed */
	    Debugger("XXX");
	    abortrequest(rqe->rqg->rq, ENOMEM);
	    return REQUEST_ENOMEM;			    /* no memory */
	}
    } else
	/*
	 * Point directly to user buffer data.  This means
	 * that we don't need to do anything when we have
	 * finished the transfer
	 */
	bp->b_data = ubp->b_data + rqe->useroffset * DEV_BSIZE;
    return 0;
}
/*
 * Abort a request: free resources and complete the
 * user request with the specified error
 */
int 
abortrequest(struct request *rq, int error)
{
    struct buf *bp = rq->bp;				    /* user buffer */

    bp->b_flags |= B_ERROR;
    bp->b_error = error;
    freerq(rq);						    /* free everything we're doing */
    biodone(bp);
    return error;					    /* and give up */
}

/*
 * Check that our transfer will cover the
 * complete address space of the user request.
 *
 * Return 1 if it can, otherwise 0
 */
int 
check_range_covered(struct request *rq)
{
    /* XXX */
    return 1;
}

/* Perform I/O on a subdisk */
void 
sdio(struct buf *bp)
{
    int s;						    /* spl */
    struct sd *sd;
    struct sdbuf *sbp;
    daddr_t endoffset;
    struct drive *drive;

    sd = &SD[Sdno(bp->b_dev)];				    /* point to the subdisk */
    drive = &DRIVE[sd->driveno];

    if (drive->state != drive_up) {			    /* XXX until we get the states fixed */
	if (bp->b_flags & B_WRITE)			    /* writing, */
	    set_sd_state(Sdno(bp->b_dev), sd_stale, setstate_force);
	else
	    set_sd_state(Sdno(bp->b_dev), sd_crashed, setstate_force);
	bp->b_flags |= B_ERROR;
	bp->b_error = EIO;
	biodone(bp);
	return;
    }
    if (sd->state < sd_empty) {				    /* nothing to talk to, */
	bp->b_flags |= B_ERROR;
	bp->b_flags = EIO;
	if (bp->b_flags & B_BUSY)			    /* XXX why isn't this always the case? */
	    biodone(bp);
	return;
    }
    /* Get a buffer */
    sbp = (struct sdbuf *) Malloc(sizeof(struct sdbuf));
    if (sbp == NULL) {
	bp->b_flags |= B_ERROR;
	bp->b_error = ENOMEM;
	biodone(bp);
	return;
    }
    bcopy(bp, &sbp->b, sizeof(struct buf));		    /* start with the user's buffer */
    sbp->b.b_flags |= B_CALL;				    /* tell us when it's done */
    sbp->b.b_iodone = sdio_done;			    /* here */
    sbp->b.b_dev = DRIVE[sd->driveno].vp->v_rdev;	    /* device */
    sbp->b.b_vp = DRIVE[sd->driveno].vp;		    /* vnode */
    sbp->b.b_blkno += sd->driveoffset;
    sbp->bp = bp;					    /* note the address of the original header */
    sbp->sdno = sd->sdno;				    /* note for statistics */
    sbp->driveno = sd->driveno;
    endoffset = bp->b_blkno + sbp->b.b_bcount / DEV_BSIZE;  /* final sector offset */
    if (endoffset > sd->sectors) {			    /* beyond the end */
	sbp->b.b_bcount -= (endoffset - sd->sectors) * DEV_BSIZE; /* trim */
	if (sbp->b.b_bcount <= 0) {			    /* nothing to transfer */
	    bp->b_resid = bp->b_bcount;			    /* nothing transferred */
	    /*
	     * XXX Grrr.  This doesn't seem to work.  Return
	     * an error after all
	     */
	    bp->b_flags |= B_ERROR;
	    bp->b_error = ENOSPC;
	    biodone(bp);
	    Free(sbp);
	    return;
	}
    }
    if ((sbp->b.b_flags & B_READ) == 0)			    /* write */
	sbp->b.b_vp->v_numoutput++;			    /* one more output going */
#if VINUMDEBUG
    if (debug & DEBUG_ADDRESSES)
	log(LOG_DEBUG,
	    "  %s dev %d.%d, sd %d, offset 0x%x, devoffset 0x%x, length %ld\n",
	    sbp->b.b_flags & B_READ ? "Read" : "Write",
	    major(sbp->b.b_dev),
	    minor(sbp->b.b_dev),
	    sbp->sdno,
	    (u_int) (sbp->b.b_blkno - SD[sbp->sdno].driveoffset),
	    (int) sbp->b.b_blkno,
	    sbp->b.b_bcount);				    /* XXX */
    if (debug & DEBUG_NUMOUTPUT)
	log(LOG_DEBUG,
	    "  vinumstart sd %d numoutput %ld\n",
	    sbp->sdno,
	    sbp->b.b_vp->v_numoutput);
#endif
    s = splbio();
    (*bdevsw(sbp->b.b_dev)->d_strategy) (&sbp->b);
    splx(s);
}

/*
 * Simplified version of bounds_check_with_label
 * Determine the size of the transfer, and make sure it is
 * within the boundaries of the partition. Adjust transfer
 * if needed, and signal errors or early completion.
 *
 * Volumes are simpler than disk slices: they only contain
 * one component (though we call them a, b and c to make
 * system utilities happy), and they always take up the
 * complete space of the "partition".
 *
 * I'm still not happy with this: why should the label be
 * protected?  If it weren't so damned difficult to write
 * one in the first pleace (because it's protected), it wouldn't
 * be a problem.
 */
int 
vinum_bounds_check(struct buf *bp, struct volume *vol)
{
    int maxsize = vol->size;				    /* size of the partition (sectors) */
    int size = (bp->b_bcount + DEV_BSIZE - 1) >> DEV_BSHIFT; /* size of this request (sectors) */

    /* Would this transfer overwrite the disk label? */
    if (bp->b_blkno <= LABELSECTOR			    /* starts before or at the label */
#if LABELSECTOR != 0
	&& bp->b_blkno + size > LABELSECTOR		    /* and finishes after */
#endif
	&& (!(vol->flags & VF_RAW))			    /* and it's not raw */
	&&major(bp->b_dev) == BDEV_MAJOR		    /* and it's the block device */
	&& (bp->b_flags & B_READ) == 0			    /* and it's a write */
	&& (!vol->flags & (VF_WLABEL | VF_LABELLING))) {    /* and we're not allowed to write the label */
	bp->b_error = EROFS;				    /* read-only */
	bp->b_flags |= B_ERROR;
	return -1;
    }
    if (size == 0)					    /* no transfer specified, */
	return 0;					    /* treat as EOF */
    /* beyond partition? */
    if (bp->b_blkno < 0					    /* negative start */
	|| bp->b_blkno + size > maxsize) {		    /* or goes beyond the end of the partition */
	/* if exactly at end of disk, return an EOF */
	if (bp->b_blkno == maxsize) {
	    bp->b_resid = bp->b_bcount;
	    return 0;
	}
	/* or truncate if part of it fits */
	size = maxsize - bp->b_blkno;
	if (size <= 0) {				    /* nothing to transfer */
	    bp->b_error = EINVAL;
	    bp->b_flags |= B_ERROR;
	    return -1;
	}
	bp->b_bcount = size << DEV_BSHIFT;
    }
    bp->b_pblkno = bp->b_blkno;
    return 1;
}

/*
 * Allocate a request group and hook
 * it in in the list for rq
 */
struct rqgroup *
allocrqg(struct request *rq, int elements)
{
    struct rqgroup *rqg;				    /* the one we're going to allocate */
    int size = sizeof(struct rqgroup) + elements * sizeof(struct rqelement);

    rqg = (struct rqgroup *) Malloc(size);
    if (rqg != NULL) {					    /* malloc OK, */
	if (rq->rqg)					    /* we already have requests */
	    rq->lrqg->next = rqg;			    /* hang it off the end */
	else						    /* first request */
	    rq->rqg = rqg;				    /* at the start */
	rq->lrqg = rqg;					    /* this one is the last in the list */

	bzero(rqg, size);				    /* no old junk */
	rqg->rq = rq;					    /* point back to the parent request */
	rqg->count = elements;				    /* number of requests in the group */
    }
    return rqg;
}

/*
 * Deallocate a request group out of a chain.  We do
 * this by linear search: the chain is short, this
 * almost never happens, and currently it can only
 * happen to the first member of the chain.
 */
void 
deallocrqg(struct rqgroup *rqg)
{
    struct rqgroup *rqgc = rqg->rq->rqg;		    /* point to the request chain */

    if (rqgc == rqg)					    /* we're first in line */
	rqg->rq->rqg = rqg->next;			    /* unhook ourselves */
    else {
	while ((rqgc->next != NULL)			    /* find the group */
	&&(rqgc->next != rqg))
	    rqgc = rqgc->next;
	if (rqgc->next == NULL)
	    log(LOG_ERR,
		"vinum deallocrqg: rqg %p not found in request %p\n",
		rqg->rq,
		rqg);
	else
	    rqgc->next = rqg->next;			    /* make the chain jump over us */
    }
    Free(rqg);
}
