/*-
 * Copyright (c) 1998 Nicolas Souchu
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
 *
 * $FreeBSD$
 *
 */

#ifdef _KERNEL
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/buf.h>

#include <machine/clock.h>

#endif

#ifdef	_KERNEL
#include <sys/kernel.h>
#endif

#include "opt_vpo.h"

#include <dev/ppbus/ppbconf.h>
#include <dev/ppbus/ppb_msq.h>
#include <dev/ppbus/vpoio.h>

/*
 * The driver pools the drive. We may add a timeout queue to avoid
 * active polling on nACK. I've tried this but it leads to unreliable
 * transfers
 */
#define VP0_SELTMO		5000	/* select timeout */
#define VP0_FAST_SPINTMO	500000	/* wait status timeout */
#define VP0_LOW_SPINTMO		5000000	/* wait status timeout */

/*
 * Actually, VP0 timings are more accurate (about few 16MHZ cycles),
 * but succeeding in respecting such timings leads to architecture
 * dependent considerations.
 */
#define VP0_PULSE		1

#define VP0_SECTOR_SIZE	512
#define VP0_BUFFER_SIZE	0x12000

#define n(flags) (~(flags) & (flags))

/*
 * VP0 connections.
 */
#define H_AUTO		n(AUTOFEED)
#define H_nAUTO		AUTOFEED
#define H_STROBE	n(STROBE)
#define H_nSTROBE	STROBE
#define H_BSY		n(nBUSY)
#define H_nBSY		nBUSY
#define H_SEL		SELECT
#define H_nSEL		n(SELECT)
#define H_ERR		PERROR
#define H_nERR		n(PERROR)
#define H_ACK		nACK
#define H_nACK		n(nACK)
#define H_FLT		nFAULT
#define H_nFLT		n(nFAULT)
#define H_SELIN		n(SELECTIN)
#define H_nSELIN	SELECTIN
#define H_INIT		nINIT
#define H_nINIT		n(nINIT)

/*
 * Microcode to execute very fast I/O sequences at the lowest bus level.
 */

/* call this macro to initialize connect/disconnect microsequences */
#define INIT_TRIG_MICROSEQ {						\
	int i;								\
	for (i=1; i <= 7; i+=2) {					\
		disconnect_microseq[i].arg[2] = (union ppb_insarg)d_pulse; \
		connect_epp_microseq[i].arg[2] = 			\
		connect_spp_microseq[i].arg[2] = (union ppb_insarg)c_pulse; \
	}								\
}

#define trig_d_pulse MS_TRIG(MS_REG_CTR,5,MS_UNKNOWN /* d_pulse */)
static char d_pulse[] = {
	 H_AUTO | H_nSELIN | H_INIT | H_STROBE, 0,
	H_nAUTO | H_nSELIN | H_INIT | H_STROBE, VP0_PULSE,
	 H_AUTO | H_nSELIN | H_INIT | H_STROBE, 0,
	 H_AUTO |  H_SELIN | H_INIT | H_STROBE, VP0_PULSE,
	 H_AUTO | H_nSELIN | H_INIT | H_STROBE, VP0_PULSE
};

#define trig_c_pulse MS_TRIG(MS_REG_CTR,5,MS_UNKNOWN /* c_pulse */)
static char c_pulse[] = {
	 H_AUTO | H_nSELIN | H_INIT | H_STROBE, 0,
	 H_AUTO |  H_SELIN | H_INIT | H_STROBE, 0,
	H_nAUTO |  H_SELIN | H_INIT | H_STROBE, VP0_PULSE,
	 H_AUTO |  H_SELIN | H_INIT | H_STROBE, 0,
	 H_AUTO | H_nSELIN | H_INIT | H_STROBE, VP0_PULSE
};

static struct ppb_microseq disconnect_microseq[] = {
	  MS_DASS(0x0), trig_d_pulse, MS_DASS(0x3c), trig_d_pulse,
	  MS_DASS(0x20), trig_d_pulse, MS_DASS(0xf), trig_d_pulse, MS_RET(0)
};

static struct ppb_microseq connect_epp_microseq[] = {
	  MS_DASS(0x0), trig_c_pulse, MS_DASS(0x3c), trig_c_pulse,
	  MS_DASS(0x20), trig_c_pulse, MS_DASS(0xcf), trig_c_pulse, MS_RET(0)
};

static struct ppb_microseq connect_spp_microseq[] = {
	  MS_DASS(0x0), trig_c_pulse, MS_DASS(0x3c), trig_c_pulse,
	  MS_DASS(0x20), trig_c_pulse, MS_DASS(0x8f), trig_c_pulse, MS_RET(0)
};

/*
 * nibble_inbyte_hook()
 *
 * Formats high and low nibble into a character
 */
static int
nibble_inbyte_hook (void *p, char *ptr)
{
	struct vpo_nibble *s = (struct vpo_nibble *)p;

	/* increment the buffer pointer */
	*ptr++ = ((s->l >> 4) & 0x0f) + (s->h & 0xf0);

	return (0);
}

/*
 * Macro used to initialize each vpoio_data structure during
 * low level attachment
 *
 * XXX should be converted to ppb_MS_init_msq()
 */
#define INIT_NIBBLE_INBYTE_SUBMICROSEQ(vpo) {		    	\
	(vpo)->vpo_nibble_inbyte_msq[2].arg[2].p =		\
			(void *)&(vpo)->vpo_nibble.h;		\
	(vpo)->vpo_nibble_inbyte_msq[4].arg[2].p =		\
			(void *)&(vpo)->vpo_nibble.l;		\
	(vpo)->vpo_nibble_inbyte_msq[5].arg[0].f =		\
			nibble_inbyte_hook;			\
	(vpo)->vpo_nibble_inbyte_msq[5].arg[1].p =		\
			(void *)&(vpo)->vpo_nibble;		\
}

/*
 * This is the sub-microseqence for MS_GET in NIBBLE mode
 * Retrieve the two nibbles and call the C function to generate the character
 * and store it in the buffer (see nibble_inbyte_hook())
 */
static struct ppb_microseq nibble_inbyte_submicroseq[] = {

/* loop: */
	  MS_CASS( H_AUTO | H_SELIN | H_INIT | H_STROBE),
	  MS_DELAY(VP0_PULSE),
	  MS_RFETCH(MS_REG_STR, MS_FETCH_ALL, MS_UNKNOWN /* high nibble */),
	  MS_CASS(H_nAUTO | H_SELIN | H_INIT | H_STROBE),
	  MS_RFETCH(MS_REG_STR, MS_FETCH_ALL, MS_UNKNOWN /* low nibble */),

	  /* do a C call to format the received nibbles */
	  MS_C_CALL(MS_UNKNOWN /* C hook */, MS_UNKNOWN /* param */),
	  MS_DBRA(-7 /* loop */),

	  MS_CASS(H_AUTO | H_nSELIN | H_INIT | H_STROBE),
	  MS_RET(0)
};

/*
 * This is the sub-microseqence for MS_GET in PS2 mode
 */
static struct ppb_microseq ps2_inbyte_submicroseq[] = {
	  MS_CASS(PCD | H_AUTO | H_SELIN | H_INIT | H_nSTROBE),

/* loop: */
	  MS_RFETCH_P(1, MS_REG_DTR, MS_FETCH_ALL),
	  MS_CASS(PCD | H_nAUTO | H_SELIN | H_INIT | H_nSTROBE),
	  MS_CASS(PCD |  H_AUTO | H_SELIN | H_INIT | H_nSTROBE),
	  MS_DBRA(-4 /* loop */),

	  MS_CASS(H_AUTO | H_nSELIN | H_INIT | H_STROBE),
	  MS_RET(0)
};

/*
 * This is the sub-microsequence for MS_PUT in both NIBBLE and PS2 modes
 */
static struct ppb_microseq spp_outbyte_submicroseq[] = {

/* loop: */
	  MS_RASSERT_P(1, MS_REG_DTR), 
	  MS_CASS(H_nAUTO | H_nSELIN | H_INIT | H_STROBE),
	  MS_CASS( H_AUTO | H_nSELIN | H_INIT | H_STROBE),
	  MS_DELAY(VP0_PULSE),
	  MS_DBRA(-5 /* loop */),

	  /* return from the put call */
	  MS_RET(0)
};

/* EPP 1.7 microsequences, ptr and len set at runtime */
static struct ppb_microseq epp17_outstr_body[] = {
	  MS_CASS(H_AUTO | H_SELIN | H_INIT | H_STROBE),

/* loop: */
	  MS_RASSERT_P(1, MS_REG_EPP_D), 
	  MS_BRSET(TIMEOUT, 3 /* error */),	/* EPP timeout? */
	  MS_DBRA(-3 /* loop */),

	  MS_CASS(H_AUTO | H_nSELIN | H_INIT | H_STROBE),
	  MS_RET(0),
/* error: */
	  MS_CASS(H_AUTO | H_nSELIN | H_INIT | H_STROBE),
	  MS_RET(1)
};

static struct ppb_microseq epp17_instr_body[] = {
	  MS_CASS(PCD | H_AUTO | H_SELIN | H_INIT | H_STROBE),

/* loop: */
	  MS_RFETCH_P(1, MS_REG_EPP_D, MS_FETCH_ALL), 
	  MS_BRSET(TIMEOUT, 3 /* error */),	/* EPP timeout? */
	  MS_DBRA(-3 /* loop */),

	  MS_CASS(PCD | H_AUTO | H_nSELIN | H_INIT | H_STROBE),
	  MS_RET(0),
/* error: */
	  MS_CASS(PCD | H_AUTO | H_nSELIN | H_INIT | H_STROBE),
	  MS_RET(1)
};

static struct ppb_microseq in_disk_mode[] = {
	  MS_CASS( H_AUTO | H_nSELIN | H_INIT | H_STROBE),
	  MS_CASS(H_nAUTO | H_nSELIN | H_INIT | H_STROBE),

	  MS_BRCLEAR(H_FLT, 3 /* error */),
	  MS_CASS( H_AUTO | H_nSELIN | H_INIT | H_STROBE),
	  MS_BRSET(H_FLT, 1 /* error */),

	  MS_RET(1),
/* error: */
	  MS_RET(0)
};

static int
vpoio_disconnect(struct vpoio_data *vpo)
{
	int ret;

	ppb_MS_microseq(&vpo->vpo_dev, disconnect_microseq, &ret);
	return (ppb_release_bus(&vpo->vpo_dev));
}

/*
 * how	: PPB_WAIT or PPB_DONTWAIT
 */
static int
vpoio_connect(struct vpoio_data *vpo, int how)
{
	int error;
	int ret;

	if ((error = ppb_request_bus(&vpo->vpo_dev, how))) {

#ifdef VP0_DEBUG
		printf("%s: can't request bus!\n", __FUNCTION__);
#endif
		return error;
	}

	if (PPB_IN_EPP_MODE(&vpo->vpo_dev))
		ppb_MS_microseq(&vpo->vpo_dev, connect_epp_microseq, &ret);
	else
		ppb_MS_microseq(&vpo->vpo_dev, connect_spp_microseq, &ret);

	return (0);
}

/*
 * vpoio_reset()
 *
 * SCSI reset signal, the drive must be in disk mode
 */
static void
vpoio_reset (struct vpoio_data *vpo)
{
	int ret;

	struct ppb_microseq reset_microseq[] = {

		#define INITIATOR	MS_PARAM(0, 1, MS_TYP_INT)

		MS_DASS(MS_UNKNOWN),
		MS_CASS(H_AUTO | H_nSELIN | H_nINIT | H_STROBE),
		MS_DELAY(25),
		MS_CASS(H_AUTO | H_nSELIN |  H_INIT | H_STROBE),
		MS_RET(0)
	};

	ppb_MS_init_msq(reset_microseq, 1, INITIATOR, 1 << VP0_INITIATOR);
	ppb_MS_microseq(&vpo->vpo_dev, reset_microseq, &ret);

	return;
}

/*
 * vpoio_in_disk_mode()
 */
static int
vpoio_in_disk_mode(struct vpoio_data *vpo)
{
	int ret;

	ppb_MS_microseq(&vpo->vpo_dev, in_disk_mode, &ret);

	return (ret);
}

/*
 * vpoio_detect()
 *
 * Detect and initialise the VP0 adapter.
 */
static int
vpoio_detect(struct vpoio_data *vpo)
{
	int error, ret;

	/* allocate the bus, then apply microsequences */
	if ((error = ppb_request_bus(&vpo->vpo_dev, PPB_DONTWAIT)))
                return (error);

	ppb_MS_microseq(&vpo->vpo_dev, disconnect_microseq, &ret);

	if (PPB_IN_EPP_MODE(&vpo->vpo_dev))
		ppb_MS_microseq(&vpo->vpo_dev, connect_epp_microseq, &ret);
	else
		ppb_MS_microseq(&vpo->vpo_dev, connect_spp_microseq, &ret);

	ppb_MS_microseq(&vpo->vpo_dev, in_disk_mode, &ret);
	if (!ret) {

		/* try spp mode (maybe twice or because previous mode was PS2)
		 * NIBBLE mode will be restored on next transfers if detection
		 * succeed
		 */
		ppb_set_mode(&vpo->vpo_dev, PPB_NIBBLE);
		ppb_MS_microseq(&vpo->vpo_dev, connect_spp_microseq, &ret);

		ppb_MS_microseq(&vpo->vpo_dev, in_disk_mode, &ret);
		if (!ret) {
			if (bootverbose)
				printf("vpo%d: can't connect to the drive\n",
					vpo->vpo_unit);

			/* disconnect and release the bus */
			ppb_MS_microseq(&vpo->vpo_dev, disconnect_microseq,
					&ret);
			goto error;
		}
	}

	/* send SCSI reset signal */
	vpoio_reset(vpo);

	ppb_MS_microseq(&vpo->vpo_dev, disconnect_microseq, &ret);

	/* ensure we are disconnected or daisy chained peripheral 
	 * may cause serious problem to the disk */

	ppb_MS_microseq(&vpo->vpo_dev, in_disk_mode, &ret);
	if (ret) {
		if (bootverbose)
			printf("vpo%d: can't disconnect from the drive\n",
				vpo->vpo_unit);
		goto error;
	}

	ppb_release_bus(&vpo->vpo_dev);
	return (0);

error:
	ppb_release_bus(&vpo->vpo_dev);
	return (VP0_EINITFAILED);
}

/*
 * vpoio_outstr()
 */
static int
vpoio_outstr(struct vpoio_data *vpo, char *buffer, int size)
{

	int error = 0;

	ppb_MS_exec(&vpo->vpo_dev, MS_OP_PUT, (union ppb_insarg)buffer,
		(union ppb_insarg)size, (union ppb_insarg)MS_UNKNOWN, &error);

#if 0
		/* XXX EPP 1.9 not implemented with microsequences */
		else {

			ppb_reset_epp_timeout(&vpo->vpo_dev);
			ppb_wctr(&vpo->vpo_dev,
				H_AUTO | H_SELIN | H_INIT | H_STROBE);

			if (((long) buffer | size) & 0x03)
				ppb_outsb_epp(&vpo->vpo_dev,
						buffer, size);
			else
				ppb_outsl_epp(&vpo->vpo_dev,
						buffer, size/4);

			if ((ppb_rstr(&vpo->vpo_dev) & TIMEOUT)) {
				error = VP0_EPPDATA_TIMEOUT;
				goto error;
			}

			ppb_wctr(&vpo->vpo_dev,
				H_AUTO | H_nSELIN | H_INIT | H_STROBE);
		}
#endif
	ppb_ecp_sync(&vpo->vpo_dev);

	return (error);
}

/*
 * vpoio_instr()
 */
static int
vpoio_instr(struct vpoio_data *vpo, char *buffer, int size)
{
	int error = 0;

	ppb_MS_exec(&vpo->vpo_dev, MS_OP_GET, (union ppb_insarg)buffer,
		(union ppb_insarg)size, (union ppb_insarg)MS_UNKNOWN, &error);

#if 0
		/* XXX EPP 1.9 not implemented with microsequences */
		else {

			ppb_reset_epp_timeout(&vpo->vpo_dev);
			ppb_wctr(&vpo->vpo_dev, PCD |
				H_AUTO | H_SELIN | H_INIT | H_STROBE);

			if (((long) buffer | size) & 0x03)
				ppb_insb_epp(&vpo->vpo_dev,
						buffer, size);
			else
				ppb_insl_epp(&vpo->vpo_dev,
						buffer, size/4);

			if ((ppb_rstr(&vpo->vpo_dev) & TIMEOUT)) {
				error = VP0_EPPDATA_TIMEOUT;
				goto error;
			}

			ppb_wctr(&vpo->vpo_dev, PCD |
				H_AUTO | H_nSELIN | H_INIT | H_STROBE);
		}
#endif
	ppb_ecp_sync(&vpo->vpo_dev);

	return (error);
}

static char
vpoio_select(struct vpoio_data *vpo, int initiator, int target)
{
	int ret;

	struct ppb_microseq select_microseq[] = {

		/* parameter list
		 */
		#define SELECT_TARGET		MS_PARAM(0, 1, MS_TYP_INT)
		#define SELECT_INITIATOR	MS_PARAM(3, 1, MS_TYP_INT)

		/* send the select command to the drive */
		MS_DASS(MS_UNKNOWN),
		MS_CASS(H_nAUTO | H_nSELIN |  H_INIT | H_STROBE),
		MS_CASS( H_AUTO | H_nSELIN |  H_INIT | H_STROBE),
		MS_DASS(MS_UNKNOWN),
		MS_CASS( H_AUTO | H_nSELIN | H_nINIT | H_STROBE),

		/* now, wait until the drive is ready */
		MS_SET(VP0_SELTMO),
/* loop: */	MS_BRSET(H_ACK, 2 /* ready */),
		MS_DBRA(-2 /* loop */),
/* error: */	MS_RET(1),
/* ready: */	MS_RET(0)
	};

	/* initialize the select microsequence */
	ppb_MS_init_msq(select_microseq, 2,
			SELECT_TARGET, 1 << target,
			SELECT_INITIATOR, 1 << initiator);
				
	ppb_MS_microseq(&vpo->vpo_dev, select_microseq, &ret);

	if (ret)
		return (VP0_ESELECT_TIMEOUT);

	return (0);
}

/*
 * vpoio_wait()
 *
 * H_SELIN must be low.
 *
 * XXX should be ported to microseq
 */
static char
vpoio_wait(struct vpoio_data *vpo, int tmo)
{

	register int	k;
	register char	r;

#if 0	/* broken */
	if (ppb_poll_device(&vpo->vpo_dev, 150, nBUSY, nBUSY, PPB_INTR))
		return (0);

	return (ppb_rstr(&vpo->vpo_dev) & 0xf0);
#endif

	/* XXX should be ported to microseq */
	k = 0;
	while (!((r = ppb_rstr(&vpo->vpo_dev)) & nBUSY) && (k++ < tmo))
		;

	/*
	 * Return some status information.
	 * Semantics :	0xc0 = ZIP wants more data
	 *		0xd0 = ZIP wants to send more data
	 *		0xe0 = ZIP wants command
	 *		0xf0 = end of transfer, ZIP is sending status
	 */
	if (k < tmo)
	  return (r & 0xf0);

	return (0);			   /* command timed out */	
}

/*
 * vpoio_probe()
 *
 * Low level probe of vpo device
 *
 */
struct ppb_device *
vpoio_probe(struct ppb_data *ppb, struct vpoio_data *vpo)
{

	/* ppbus dependent initialisation */
	vpo->vpo_dev.id_unit = vpo->vpo_unit;
	vpo->vpo_dev.name = "vpo";
	vpo->vpo_dev.ppb = ppb;

	/*
	 * Initialize microsequence code
	 */
	INIT_TRIG_MICROSEQ;

	/* now, try to initialise the drive */
	if (vpoio_detect(vpo)) {
		return (NULL);
	}

	return (&vpo->vpo_dev);
}

/*
 * vpoio_attach()
 *
 * Low level attachment of vpo device
 *
 */
int
vpoio_attach(struct vpoio_data *vpo)
{
	int epp;

	/*
	 * Report ourselves
	 */
	printf("vpo%d: <Iomega VPI0 Parallel to SCSI interface> on ppbus %d\n",
		vpo->vpo_dev.id_unit, vpo->vpo_dev.ppb->ppb_link->adapter_unit);

	vpo->vpo_nibble_inbyte_msq = (struct ppb_microseq *)malloc(
		sizeof(nibble_inbyte_submicroseq), M_DEVBUF, M_NOWAIT);

	if (!vpo->vpo_nibble_inbyte_msq)
		return (0);

	bcopy((void *)nibble_inbyte_submicroseq,
		(void *)vpo->vpo_nibble_inbyte_msq,
		sizeof(nibble_inbyte_submicroseq));

	INIT_NIBBLE_INBYTE_SUBMICROSEQ(vpo);

	/*
	 * Initialize mode dependent in/out microsequences
	 */
	ppb_request_bus(&vpo->vpo_dev, PPB_WAIT);

	/* enter NIBBLE mode to configure submsq */
	if (ppb_set_mode(&vpo->vpo_dev, PPB_NIBBLE) != -1) {

		ppb_MS_GET_init(&vpo->vpo_dev, vpo->vpo_nibble_inbyte_msq);

		ppb_MS_PUT_init(&vpo->vpo_dev, spp_outbyte_submicroseq);
	}

	/* enter PS2 mode to configure submsq */
	if (ppb_set_mode(&vpo->vpo_dev, PPB_PS2) != -1) {

		ppb_MS_GET_init(&vpo->vpo_dev, ps2_inbyte_submicroseq);

		ppb_MS_PUT_init(&vpo->vpo_dev, spp_outbyte_submicroseq);
	}

	epp = ppb_get_epp_protocol(&vpo->vpo_dev);

	/* enter EPP mode to configure submsq */
	if (ppb_set_mode(&vpo->vpo_dev, PPB_EPP) != -1) {

		switch (epp) {
		case EPP_1_9:
			/* XXX EPP 1.9 support should be improved */
		case EPP_1_7:
			ppb_MS_GET_init(&vpo->vpo_dev, epp17_instr_body);

			ppb_MS_PUT_init(&vpo->vpo_dev, epp17_outstr_body);
			break;
		default:
			panic("%s: unknown EPP protocol (0x%x)", __FUNCTION__,
				epp);
		}
	}

	/* try to enter EPP or PS/2 mode, NIBBLE otherwise */
	if (ppb_set_mode(&vpo->vpo_dev, PPB_EPP) != -1) {
		switch (epp) {
		case EPP_1_9:
			printf("vpo%d: EPP 1.9 mode\n", vpo->vpo_unit);
			break;
		case EPP_1_7:
			printf("vpo%d: EPP 1.7 mode\n", vpo->vpo_unit);
			break;
		default:
			panic("%s: unknown EPP protocol (0x%x)", __FUNCTION__,
				epp);
		}
	} else if (ppb_set_mode(&vpo->vpo_dev, PPB_PS2) != -1)
		printf("vpo%d: PS2 mode\n", vpo->vpo_unit);

	else if (ppb_set_mode(&vpo->vpo_dev, PPB_NIBBLE) != -1)
		printf("vpo%d: NIBBLE mode\n", vpo->vpo_unit);

	else {
		printf("vpo%d: can't enter NIBBLE, PS2 or EPP mode\n",
			vpo->vpo_unit);

		ppb_release_bus(&vpo->vpo_dev);

		free(vpo->vpo_nibble_inbyte_msq, M_DEVBUF);
		return (0);
	}

	ppb_release_bus(&vpo->vpo_dev);

	return (1);
}

/*
 * vpoio_reset_bus()
 *
 */
int
vpoio_reset_bus(struct vpoio_data *vpo)
{
	/* first, connect to the drive */
	if (vpoio_connect(vpo, PPB_WAIT|PPB_INTR) || !vpoio_in_disk_mode(vpo)) {

#ifdef VP0_DEBUG
		printf("%s: not in disk mode!\n", __FUNCTION__);
#endif
		/* release ppbus */
		vpoio_disconnect(vpo);
		return (1);
	}

	/* reset the SCSI bus */
	vpoio_reset(vpo);

	/* then disconnect */
	vpoio_disconnect(vpo);

	return (0);
}

/*
 * vpoio_do_scsi()
 *
 * Send an SCSI command
 *
 */
int 
vpoio_do_scsi(struct vpoio_data *vpo, int host, int target, char *command,
		int clen, char *buffer, int blen, int *result, int *count,
		int *ret)
{

	register char r;
	char l, h = 0;
	int len, error = 0;
	register int k;

	/*
	 * enter disk state, allocate the ppbus
	 *
	 * XXX
	 * Should we allow this call to be interruptible?
	 * The only way to report the interruption is to return
	 * EIO do upper SCSI code :^(
	 */
	if ((error = vpoio_connect(vpo, PPB_WAIT|PPB_INTR)))
		return (error);

	if (!vpoio_in_disk_mode(vpo)) {
		*ret = VP0_ECONNECT; goto error;
	}

	if ((*ret = vpoio_select(vpo,host,target)))
		goto error;

	/*
	 * Send the command ...
	 *
	 * set H_SELIN low for vpoio_wait().
	 */
	ppb_wctr(&vpo->vpo_dev, H_AUTO | H_nSELIN | H_INIT | H_STROBE);

	for (k = 0; k < clen; k++) {
		if (vpoio_wait(vpo, VP0_FAST_SPINTMO) != (char)0xe0) {
			*ret = VP0_ECMD_TIMEOUT;
			goto error;
		}
		if (vpoio_outstr(vpo, &command[k], 1)) {
			*ret = VP0_EPPDATA_TIMEOUT;
			goto error;
		}
	}

	/* 
	 * Completion ... 
	 */

	*count = 0;
	for (;;) {

		if (!(r = vpoio_wait(vpo, VP0_LOW_SPINTMO))) {
			*ret = VP0_ESTATUS_TIMEOUT; goto error;
		}

		/* stop when the ZIP wants to send status */
		if (r == (char)0xf0)
			break;

		if (*count >= blen) {
			*ret = VP0_EDATA_OVERFLOW;
			goto error;
		}

		/* if in EPP mode or writing bytes, try to transfer a sector
		 * otherwise, just send one byte
		 */
		if (PPB_IN_EPP_MODE(&vpo->vpo_dev) || r == (char)0xc0)
			len = (((blen - *count) >= VP0_SECTOR_SIZE)) ?
				VP0_SECTOR_SIZE : 1;
		else
			len = 1;

		/* ZIP wants to send data? */
		if (r == (char)0xc0)
			error = vpoio_outstr(vpo, &buffer[*count], len);
		else
			error = vpoio_instr(vpo, &buffer[*count], len);

		if (error) {
			*ret = error;
			goto error;
		}

		*count += len;
	}

	if (vpoio_instr(vpo, &l, 1)) {
		*ret = VP0_EOTHER; goto error;
	}

	/* check if the ZIP wants to send more status */
	if (vpoio_wait(vpo, VP0_FAST_SPINTMO) == (char)0xf0)
		if (vpoio_instr(vpo, &h, 1)) {
			*ret = VP0_EOTHER+2; goto error;
		}

	*result = ((int) h << 8) | ((int) l & 0xff);

error:
	/* return to printer state, release the ppbus */
	vpoio_disconnect(vpo);
	return (0);
}
