/*
 * Copyright (c) 1997, 1998 Hellmuth Michaelis. All rights reserved.
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
 *---------------------------------------------------------------------------
 *
 *      i4b_l2.c - ISDN layer 2 (Q.921)
 *	-------------------------------
 *
 *	$Id: i4b_l2.c,v 1.23 1998/12/05 18:05:08 hm Exp $ 
 *
 *      last edit-date: [Sat Dec  5 18:27:00 1998]
 *
 *---------------------------------------------------------------------------*/

#ifdef __FreeBSD__
#include "i4bq921.h"
#else
#define NI4BQ921	1
#endif
#if NI4BQ921 > 0

#include <sys/param.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/ioccom.h>
#else
#include <sys/ioctl.h>
#endif
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <net/if.h>

#ifdef __FreeBSD__
#include <machine/i4b_debug.h>
#include <machine/i4b_ioctl.h>
#else
#include <i4b/i4b_debug.h>
#include <i4b/i4b_ioctl.h>
#endif

#include <i4b/include/i4b_l1l2.h>
#include <i4b/include/i4b_l2l3.h>
#include <i4b/include/i4b_isdnq931.h>
#include <i4b/include/i4b_mbuf.h>
#include <i4b/include/i4b_global.h>

#include <i4b/layer2/i4b_l2.h>
#include <i4b/layer2/i4b_l2fsm.h>

int i4b_dl_establish_ind(int);
int i4b_dl_establish_cnf(int);
int i4b_dl_release_ind(int);
int i4b_dl_release_cnf(int);
int i4b_dl_data_ind(int, struct mbuf *);
int i4b_dl_unit_data_ind(int, struct mbuf *);

static int i4b_mdl_command_req(int, int, int);

/* from layer 2 */

extern int i4b_mdl_attach_ind(int, int);
extern int i4b_mdl_status_ind(int, int, int);

/* this layers debug level */

unsigned int i4b_l2_debug = L2_DEBUG_DEFAULT;

struct i4b_l2l3_func i4b_l2l3_func = {

	/* Layer 2 --> Layer 3 */
	
	(int (*)(int))				i4b_dl_establish_ind,
	(int (*)(int)) 				i4b_dl_establish_cnf,
	(int (*)(int))				i4b_dl_release_ind,
	(int (*)(int))				i4b_dl_release_cnf,
	(int (*)(int, struct mbuf *))		i4b_dl_data_ind,
	(int (*)(int, struct mbuf *))		i4b_dl_unit_data_ind,

	/* Layer 3 --> Layer 2 */

	(int (*)(int))				i4b_dl_establish_req,
	(int (*)(int))				i4b_dl_release_req,
	(int (*)(int, struct mbuf *))		i4b_dl_data_req,
	(int (*)(int, struct mbuf *))		i4b_dl_unit_data_req,

	/* Layer 2 --> Layer 3 management */
	
	(int (*)(int, int, int))		i4b_mdl_status_ind,

	/* Layer 3  --> Layer 2 management */
	
	(int (*)(int, int, int))		i4b_mdl_command_req	
};

/*---------------------------------------------------------------------------*
 *	DL_ESTABLISH_REQ from layer 3
 *---------------------------------------------------------------------------*/
int i4b_dl_establish_req(int unit)
{
	l2_softc_t *l2sc = &l2_softc[unit];
	
	DBGL2(L2_PRIM, "DL-ESTABLISH-REQ", ("unit %d\n",unit));
	i4b_l1_activate(l2sc);
	i4b_next_l2state(l2sc, EV_DLESTRQ);
	return(0);
}

/*---------------------------------------------------------------------------*
 *	DL_RELEASE_REQ from layer 3
 *---------------------------------------------------------------------------*/
int i4b_dl_release_req(int unit)
{
	l2_softc_t *l2sc = &l2_softc[unit];

	DBGL2(L2_PRIM, "DL-RELEASE-REQ", ("unit %d\n",unit));	
	i4b_next_l2state(l2sc, EV_DLRELRQ);
	return(0);	
}

/*---------------------------------------------------------------------------*
 *	DL UNIT DATA REQUEST from Layer 3
 *---------------------------------------------------------------------------*/
int i4b_dl_unit_data_req(int unit, struct mbuf *m)
{
#ifdef NOTDEF
	DBGL2(L2_PRIM, "DL-UNIT-DATA-REQ", ("unit %d\n",unit));
#endif
	return(0);
}

/*---------------------------------------------------------------------------*
 *	DL DATA REQUEST from Layer 3
 *---------------------------------------------------------------------------*/
int i4b_dl_data_req(int unit, struct mbuf *m)
{
	l2_softc_t *l2sc = &l2_softc[unit];
	int x;
#ifdef NOTDEF
	DBGL2(L2_PRIM, "DL-DATA-REQ", ("unit %d\n",unit));
#endif
	switch(l2sc->Q921_state)
	{
		case ST_AW_EST:
		case ST_MULTIFR:
		case ST_TIMREC:
		
		        if(IF_QFULL(&l2sc->i_queue))
		        {
		        	DBGL2(L2_ERROR, "i4b_dl_data_req", ("i_queue full!!\n"));
		        	i4b_Dfreembuf(m);
		        }
		        else
		        {
			        x = splimp();		        	
				IF_ENQUEUE(&l2sc->i_queue, m);
				splx(x);
				i4b_i_frame_queued_up(l2sc);
			}
			break;
			
		default:
			DBGL2(L2_ERROR, "i4b_dl_data_req", ("unit %d ERROR in state [%s], freeing mbuf\n", unit, i4b_print_l2state(l2sc)));
			i4b_Dfreembuf(m);
			break;
	}		
	return(0);
}

/*---------------------------------------------------------------------------*
 *	i4b_ph_activate_ind - link activation indication from layer 1
 *---------------------------------------------------------------------------*/
int
i4b_ph_activate_ind(int unit)
{
	l2_softc_t *l2sc = &l2_softc[unit];

	DBGL1(L1_PRIM, "PH-ACTIVATE-IND", ("unit %d\n",unit));
	l2sc->ph_active = PH_ACTIVE;
	return(0);
}

/*---------------------------------------------------------------------------*
 *	i4b_ph_deactivate_ind - link deactivation indication from layer 1
 *---------------------------------------------------------------------------*/
int
i4b_ph_deactivate_ind(int unit)
{
	l2_softc_t *l2sc = &l2_softc[unit];

	DBGL1(L1_PRIM, "PH-DEACTIVATE-IND", ("unit %d\n",unit));
	l2sc->ph_active = PH_INACTIVE;
	return(0);
}


/*---------------------------------------------------------------------------*
 *	i4b_l2_unit_init - place layer 2 unit into known state
 *---------------------------------------------------------------------------*/
static void
i4b_l2_unit_init(int unit)
{
	l2_softc_t *l2sc = &l2_softc[unit];

	l2sc->Q921_state = ST_TEI_UNAS;
	l2sc->tei_valid = TEI_INVALID;
	l2sc->vr = 0;
	l2sc->vs = 0;
	l2sc->va = 0;
	l2sc->ack_pend = 0;
	l2sc->rej_excpt = 0;
	l2sc->peer_busy = 0;
	l2sc->own_busy = 0;
	l2sc->l3initiated = 0;

	l2sc->rxd_CR = 0;
	l2sc->rxd_PF = 0;
	l2sc->rxd_NR = 0;
	l2sc->RC = 0;
	l2sc->iframe_sent = 0;
		
	l2sc->postfsmfunc = NULL;

	if(l2sc->ua_num != UA_EMPTY)
	{
		i4b_Dfreembuf(l2sc->ua_frame);
		l2sc->ua_num = UA_EMPTY;
		l2sc->ua_frame = NULL;
	}

	i4b_T200_stop(l2sc);
	i4b_T202_stop(l2sc);
	i4b_T203_stop(l2sc);	
}

/*---------------------------------------------------------------------------*
 *	i4b_mph_status_ind - status indication upward
 *---------------------------------------------------------------------------*/
int
i4b_mph_status_ind(int unit, int status, int parm)
{
	l2_softc_t *l2sc = &l2_softc[unit];
	int sendup = 1;

	int x = SPLI4B();

	DBGL1(L1_PRIM, "MPH-STATUS-IND", ("unit %d, status=%d, parm=%d\n", unit, status, parm));

	switch(status)
	{
		case STI_ATTACH:
			l2sc->unit = unit;
			l2sc->i_queue.ifq_maxlen = IQUEUE_MAXLEN;
			l2sc->ua_frame = NULL;
			i4b_l2_unit_init(unit);
			
#if defined(__FreeBSD_version) && __FreeBSD_version >= 300001
			/* initialize the callout handles for timeout routines */
			callout_handle_init(&l2sc->T200_callout);
			callout_handle_init(&l2sc->T202_callout);
			callout_handle_init(&l2sc->T203_callout);
#endif
			break;

		case STI_L1STAT:	/* state of layer 1 */
			break;
		
		case STI_PDEACT:	/* Timer 4 expired */
			if((l2sc->Q921_state >= ST_AW_EST) &&
			   (l2sc->Q921_state <= ST_TIMREC))
			{
				DBGL2(L2_ERROR, "i4b_mph_status_ind", ("unit %d, persistent deactivation!\n", unit));
				i4b_l2_unit_init(unit);
			}
			else
			{
				sendup = 0;
			}
			break;

		case STI_NOL1ACC:
			i4b_l2_unit_init(unit);
			DBGL2(L2_ERROR, "i4b_mph_status_ind", ("unit %d, cannot access S0 bus!\n", unit));
			break;
			
		default:
			DBGL2(L2_ERROR, "i4b_mph_status_ind", ("ERROR, unit %d, unknown status message!\n", unit));
			break;
	}
	
	if(sendup)
		MDL_Status_Ind(unit, status, parm);  /* send up to layer 3 */

	splx(x);
	
	return(0);
}

/*---------------------------------------------------------------------------*
 *	MDL_COMMAND_REQ from layer 3
 *---------------------------------------------------------------------------*/
int i4b_mdl_command_req(int unit, int command, int parm)
{
	DBGL2(L2_PRIM, "MDL-COMMAND-REQ", ("unit %d, command=%d, parm=%d\n", unit, command, parm));

	switch(command)
	{
		case CMR_DOPEN:
			i4b_l2_unit_init(unit);
			break;
	}		

	MPH_Command_Req(unit, command, parm);
	
	return(0);
}

/*---------------------------------------------------------------------------*
 *	i4b_ph_data_ind - process a rx'd frame got from layer 1
 *---------------------------------------------------------------------------*/
int
i4b_ph_data_ind(int unit, struct mbuf *m)
{
#ifdef NOTDEF
	DBGL1(L1_PRIM, "PH-DATA-IND", ("unit %d\n", unit));
#endif
	u_char *ptr = m->m_data;

	if ( (*(ptr + OFF_CNTL) & 0x01) == 0 )
	{
		if(m->m_len < 4)	/* 6 oct - 2 chksum oct */
		{
			DBGL2(L2_ERROR, "i4b_ph_data_ind", ("ERROR, I-frame < 6 octetts!\n"));
			i4b_Dfreembuf(m);
			return(0);
		}
		i4b_rxd_i_frame(unit, m);
	}
	else if ( (*(ptr + OFF_CNTL) & 0x03) == 0x01 )
	{
		if(m->m_len < 4)	/* 6 oct - 2 chksum oct */
		{
			DBGL2(L2_ERROR, "i4b_ph_data_ind", ("ERROR, S-frame < 6 octetts!\n"));
			i4b_Dfreembuf(m);
			return(0);
		}
		i4b_rxd_s_frame(unit, m);
	}
	else if ( (*(ptr + OFF_CNTL) & 0x03) == 0x03 )
	{
		if(m->m_len < 3)	/* 5 oct - 2 chksum oct */
		{
			DBGL2(L2_ERROR, "i4b_ph_data_ind", ("ERROR, U-frame < 5 octetts!\n"));
			i4b_Dfreembuf(m);
			return(0);
		}
		i4b_rxd_u_frame(unit, m);
	}
	else
	{
		DBGL2(L2_ERROR, "i4b_ph_data_ind", ("ERROR, bad frame rx'd - "));
		i4b_print_frame(m->m_len, m->m_data);
		i4b_Dfreembuf(m);
	}
	return(0);
}

#endif /* NI4BQ921 > 0 */

