/*
 * Copyright (c) 1997, 1999 Hellmuth Michaelis. All rights reserved.
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
 *	i4b_l4if.c - Layer 3 interface to Layer 4
 *	-------------------------------------------
 *
 *	$Id: i4b_l4if.c,v 1.18 1999/02/14 09:45:01 hm Exp $ 
 *
 *      last edit-date: [Sun Feb 14 10:33:44 1999]
 *
 *---------------------------------------------------------------------------*/

#ifdef __FreeBSD__
#include "i4bq931.h"
#else
#define	NI4BQ931	1
#endif
#if NI4BQ931 > 0

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
#include <machine/i4b_cause.h>
#else
#include <i4b/i4b_debug.h>
#include <i4b/i4b_ioctl.h>
#include <i4b/i4b_cause.h>
#endif

#include <i4b/include/i4b_isdnq931.h>
#include <i4b/include/i4b_l2l3.h>
#include <i4b/include/i4b_l3l4.h>
#include <i4b/include/i4b_mbuf.h>
#include <i4b/include/i4b_global.h>

#include <i4b/layer3/i4b_l3.h>
#include <i4b/layer3/i4b_l3fsm.h>
#include <i4b/layer3/i4b_q931.h>

#include <i4b/layer4/i4b_l4.h>

extern void isic_settrace(int unit, int val);		/*XXX*/
extern int isic_gettrace(int unit);			/*XXX*/

static void n_connect_request(u_int cdid);
static void n_connect_response(u_int cdid, int response, int cause);
static void n_disconnect_request(u_int cdid, int cause);
static void n_alert_request(u_int cdid);
static void n_mgmt_command(int unit, int cmd, int parm);

/*---------------------------------------------------------------------------*
 *	i4b_mdl_status_ind - status indication from lower layers
 *---------------------------------------------------------------------------*/
int
i4b_mdl_status_ind(int unit, int status, int parm)
{
	int sendup;
	int i;
	
	DBGL3(L3_MSG, "i4b_mdl_status_ind", ("unit = %d, status = %d, parm = %d\n", unit, status, parm));

	switch(status)
	{
		case STI_ATTACH:
			DBGL3(L3_MSG, "i4b_mdl_status_ind", ("STI_ATTACH: attaching unit %d to controller %d\n", unit, nctrl));
		
			/* init function pointers */
			
			ctrl_desc[nctrl].N_CONNECT_REQUEST = n_connect_request;
			ctrl_desc[nctrl].N_CONNECT_RESPONSE = n_connect_response;
			ctrl_desc[nctrl].N_DISCONNECT_REQUEST = n_disconnect_request;
			ctrl_desc[nctrl].N_ALERT_REQUEST = n_alert_request;	
			ctrl_desc[nctrl].N_SET_TRACE = isic_settrace;
			ctrl_desc[nctrl].N_GET_TRACE = isic_gettrace;
			ctrl_desc[nctrl].N_DOWNLOAD = NULL;	/* only used by active cards */
			ctrl_desc[nctrl].N_DIAGNOSTICS = NULL;	/* only used by active cards */
			ctrl_desc[nctrl].N_MGMT_COMMAND = n_mgmt_command;
		
			/* init type and unit */
			
			ctrl_desc[nctrl].unit = unit;
			ctrl_desc[nctrl].ctrl_type = CTRL_PASSIVE;
			ctrl_desc[nctrl].card_type = parm;
		
			/* state fields */
		
			ctrl_desc[nctrl].dl_est = DL_DOWN;
			ctrl_desc[nctrl].bch_state[CHAN_B1] = BCH_ST_FREE;
			ctrl_desc[nctrl].bch_state[CHAN_B2] = BCH_ST_FREE;	
			ctrl_desc[nctrl].tei = -1;
			
			/* init unit to controller table */
			
			utoc_tab[unit] = nctrl;
			
			/* increment no. of controllers */
			
			nctrl++;

			break;
			
		case STI_L1STAT:
			i4b_l4_l12stat(unit, 1, parm);
			DBGL3(L3_MSG, "i4b_mdl_status_ind", ("STI_L1STAT: unit %d layer 1 = %s\n", unit, status ? "up" : "down"));
			break;
			
		case STI_L2STAT:
			i4b_l4_l12stat(unit, 2, parm);
			DBGL3(L3_MSG, "i4b_mdl_status_ind", ("STI_L2STAT: unit %d layer 2 = %s\n", unit, status ? "up" : "down"));
			break;

		case STI_TEIASG:
			ctrl_desc[unit].tei = parm;
			i4b_l4_teiasg(unit, parm);
			DBGL3(L3_MSG, "i4b_mdl_status_ind", ("STI_TEIASG: unit %d TEI = %d = 0x%02x\n", unit, parm, parm));
			break;

		case STI_PDEACT:	/* L1 T4 timeout */
			DBGL3(L3_ERR, "i4b_mdl_status_ind", ("STI_PDEACT: unit %d TEI = %d = 0x%02x\n", unit, parm, parm));

			sendup = 0;

			for(i=0; i < N_CALL_DESC; i++)
			{
				if( (ctrl_desc[call_desc[i].controller].ctrl_type == CTRL_PASSIVE) &&
				    (ctrl_desc[call_desc[i].controller].unit == unit))
                		{
					if(call_desc[i].cdid != CDID_UNUSED)
						sendup++;
				}
			}

			ctrl_desc[utoc_tab[unit]].dl_est = DL_DOWN;
			ctrl_desc[utoc_tab[unit]].bch_state[CHAN_B1] = BCH_ST_FREE;
			ctrl_desc[utoc_tab[unit]].bch_state[CHAN_B2] = BCH_ST_FREE;
			ctrl_desc[utoc_tab[unit]].tei = -1;

			if(sendup)
				i4b_l4_pdeact(unit, sendup);
			break;

		case STI_NOL1ACC:	/* no outgoing access to S0 */
			DBGL3(L3_ERR, "i4b_mdl_status_ind", ("STI_NOL1ACC: unit %d no outgoing access to S0\n", unit));

			for(i=0; i < N_CALL_DESC; i++)
			{
				if( (ctrl_desc[call_desc[i].controller].ctrl_type == CTRL_PASSIVE) &&
				    (ctrl_desc[call_desc[i].controller].unit == unit))
                		{
					if(call_desc[i].cdid != CDID_UNUSED)
					{
						SET_CAUSE_TYPE(call_desc[i].cause_in, CAUSET_I4B);
						SET_CAUSE_VAL(call_desc[i].cause_in, CAUSE_I4B_L1ERROR);
						i4b_l4_disconnect_ind(&(call_desc[i]));
					}
				}
			}

			ctrl_desc[utoc_tab[unit]].dl_est = DL_DOWN;
			ctrl_desc[utoc_tab[unit]].bch_state[CHAN_B1] = BCH_ST_FREE;
			ctrl_desc[utoc_tab[unit]].bch_state[CHAN_B2] = BCH_ST_FREE;
			ctrl_desc[utoc_tab[unit]].tei = -1;
			break;

		default:
			DBGL3(L3_ERR, "i4b_mdl_status_ind", ("ERROR, unit %d, unknown status value %d!\n", unit, status));
			break;
	}		
	return(0);
}

/*---------------------------------------------------------------------------*
 *	send command to the lower layers
 *---------------------------------------------------------------------------*/
static void
n_mgmt_command(int unit, int cmd, int parm)
{
	int i;

	switch(cmd)
	{
		case CMR_DOPEN:
			DBGL3(L3_MSG, "n_mgmt_command", ("CMR_DOPEN for unit %d\n", unit));
			
			for(i=0; i < N_CALL_DESC; i++)
			{
				if( (ctrl_desc[call_desc[i].controller].ctrl_type == CTRL_PASSIVE) &&
				    (ctrl_desc[call_desc[i].controller].unit == unit))
                		{
                			call_desc[i].cdid = CDID_UNUSED;
				}
			}

			ctrl_desc[utoc_tab[unit]].dl_est = DL_DOWN;
			ctrl_desc[utoc_tab[unit]].bch_state[CHAN_B1] = BCH_ST_FREE;
			ctrl_desc[utoc_tab[unit]].bch_state[CHAN_B2] = BCH_ST_FREE;
			ctrl_desc[utoc_tab[unit]].tei = -1;
			break;

		case CMR_DCLOSE:
			DBGL3(L3_MSG, "n_mgmt_command", ("CMR_DCLOSE for unit %d\n", unit));
			break;
			
		default:
			break;
			
	}

	MDL_Command_Req(unit, cmd, parm);
	
}

/*---------------------------------------------------------------------------*
 *	handle connect request message from userland
 *---------------------------------------------------------------------------*/
static void
n_connect_request(u_int cdid)
{
	call_desc_t *cd;

	cd = cd_by_cdid(cdid);

	next_l3state(cd, EV_SETUPRQ);	
}

/*---------------------------------------------------------------------------*
 *	handle setup response message from userland
 *---------------------------------------------------------------------------*/
static void
n_connect_response(u_int cdid, int response, int cause)
{
	call_desc_t *cd;
	int chstate;

	cd = cd_by_cdid(cdid);

	T400_stop(cd);
	
	cd->response = response;
	cd->cause_out = cause;

	switch(response)
	{
		case SETUP_RESP_ACCEPT:
			next_l3state(cd, EV_SETACRS);
			chstate = BCH_ST_USED;
			break;
		
		case SETUP_RESP_REJECT:
			next_l3state(cd, EV_SETRJRS);
			chstate = BCH_ST_FREE;
			break;
			
		case SETUP_RESP_DNTCRE:
			next_l3state(cd, EV_SETDCRS);
			chstate = BCH_ST_FREE;
			break;

		default:	/* failsafe */
			next_l3state(cd, EV_SETDCRS);
			chstate = BCH_ST_FREE;
			DBGL3(L3_ERR, "n_connect_response", ("unknown response, doing SETUP_RESP_DNTCRE"));
			break;
	}

	if((cd->channelid == CHAN_B1) || (cd->channelid == CHAN_B2))
	{
		ctrl_desc[cd->controller].bch_state[cd->channelid] = chstate;
	}
	else
	{
		DBGL3(L3_ERR, "n_connect_response", ("ERROR, invalid channel %d\n", cd->channelid));
	}
}

/*---------------------------------------------------------------------------*
 *	handle disconnect request message from userland
 *---------------------------------------------------------------------------*/
static void
n_disconnect_request(u_int cdid, int cause)
{
	call_desc_t *cd;

	cd = cd_by_cdid(cdid);

	cd->cause_out = cause;

	next_l3state(cd, EV_DISCRQ);
}

/*---------------------------------------------------------------------------*
 *	handle alert request message from userland
 *---------------------------------------------------------------------------*/
static void
n_alert_request(u_int cdid)
{
	call_desc_t *cd;

	cd = cd_by_cdid(cdid);

	next_l3state(cd, EV_ALERTRQ);
}

#endif /* NI4BQ931 > 0 */
