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
 *	i4b daemon - misc support routines
 *	----------------------------------
 *
 * $FreeBSD$ 
 *
 *      last edit-date: [Mon Jul  5 15:29:22 1999]
 *
 *---------------------------------------------------------------------------*/

#include "isdnd.h"
	
/*---------------------------------------------------------------------------*
 *	find an active entry by driver type and driver unit
 *---------------------------------------------------------------------------*/
cfg_entry_t *
find_active_entry_by_driver(int drivertype, int driverunit)
{
	cfg_entry_t *cep = NULL;
	int i;

	for(i=0; i < nentries; i++)
	{
		cep = &cfg_entry_tab[i];	/* ptr to config entry */

		if(!((cep->usrdevicename == drivertype) &&
		     (cep->usrdeviceunit == driverunit)))
		{
			continue;
		}

		/* found */
		
		if(cep->cdid == CDID_UNUSED)
		{
			DBGL(DL_MSG, (log(LL_DBG, "find_active_entry_by_driver: entry %d, cdid is CDID_UNUSED!", i)));
			return(NULL);
		}
		else if(cep->cdid == CDID_RESERVED)
		{
			DBGL(DL_MSG, (log(LL_DBG, "find_active_entry_by_driver: entry %d, cdid is CDID_RESERVED!", i)));
			return(NULL);
		}
		return(cep);
	}
	return(NULL);
}

/*---------------------------------------------------------------------------*
 *	find entry by drivertype and driverunit and setup for dialing out
 *---------------------------------------------------------------------------*/
cfg_entry_t *
find_by_device_for_dialout(int drivertype, int driverunit)
{
	cfg_entry_t *cep = NULL;
	int i;

	for(i=0; i < nentries; i++)
	{
		cep = &cfg_entry_tab[i];	/* ptr to config entry */

		/* compare driver type and unit */

		if(!((cep->usrdevicename == drivertype) &&
		     (cep->usrdeviceunit == driverunit)))
		{
			continue;
		}

		/* found, check if already reserved */
		
		if(cep->cdid == CDID_RESERVED)
		{
			DBGL(DL_MSG, (log(LL_DBG, "find_by_device_for_dialout: entry %d, cdid reserved!", i)));
			return(NULL);
		}

		/* check if this entry is already in use ? */
		
		if(cep->cdid != CDID_UNUSED)	
		{
			DBGL(DL_MSG, (log(LL_DBG, "find_by_device_for_dialout: entry %d, cdid in use", i)));
			return(NULL);
		}

		if((setup_dialout(cep)) == GOOD)
		{
			/* found an entry to be used for calling out */
		
			DBGL(DL_MSG, (log(LL_DBG, "find_by_device_for_dialout: found entry %d!", i)));
			return(cep);
		}
		else
		{
			DBGL(DL_MSG, (log(LL_DBG, "find_by_device_for_dialout: entry %d, setup_dialout() failed!", i)));
			return(NULL);
		}
	}

	DBGL(DL_MSG, (log(LL_DBG, "find_by_device_for_dialout: no entry found!")));
	return(NULL);
}

/*---------------------------------------------------------------------------*
 *	find entry by drivertype and driverunit and setup for dialing out
 *---------------------------------------------------------------------------*/
cfg_entry_t *
find_by_device_for_dialoutnumber(int drivertype, int driverunit, int cmdlen, char *cmd)
{
	cfg_entry_t *cep = NULL;
	int i, j;

	for(i=0; i < nentries; i++)
	{
		cep = &cfg_entry_tab[i];	/* ptr to config entry */

		/* compare driver type and unit */

		if(!((cep->usrdevicename == drivertype) &&
		     (cep->usrdeviceunit == driverunit)))
		{
			continue;
		}

		/* found, check if already reserved */
		
		if(cep->cdid == CDID_RESERVED)
		{
			DBGL(DL_MSG, (log(LL_DBG, "find_by_device_for_dialoutnumber: entry %d, cdid reserved!", i)));
			return(NULL);
		}

		/* check if this entry is already in use ? */
		
		if(cep->cdid != CDID_UNUSED)	
		{
			DBGL(DL_MSG, (log(LL_DBG, "find_by_device_for_dialoutnumber: entry %d, cdid in use", i)));
			return(NULL);
		}

		/* check number and copy to cep->remote_numbers[] */
		
		for(j = 0; j < cmdlen; j++)
		{
			if(!(isdigit(*(cmd+j))))
			{
				DBGL(DL_MSG, (log(LL_DBG, "find_by_device_for_dialoutnumber: entry %d, dial string contains non-digit at pos %d", i, j)));
				return(NULL);
			}
			/* fill in number to dial */
			cep->remote_numbers[0].number[j] = *(cmd+j);
		}				
		cep->remote_numbers[0].number[j] = '\0';
		cep->remote_numbers_count = 1;

		if((setup_dialout(cep)) == GOOD)
		{
			/* found an entry to be used for calling out */
		
			DBGL(DL_MSG, (log(LL_DBG, "find_by_device_for_dialoutnumber: found entry %d!", i)));
			return(cep);
		}
		else
		{
			DBGL(DL_MSG, (log(LL_DBG, "find_by_device_for_dialoutnumber: entry %d, setup_dialout() failed!", i)));
			return(NULL);
		}
	}

	DBGL(DL_MSG, (log(LL_DBG, "find_by_device_for_dialoutnumber: no entry found!")));
	return(NULL);
}

/*---------------------------------------------------------------------------*
 *	find entry by drivertype and driverunit and setup for dialing out
 *---------------------------------------------------------------------------*/
int
setup_dialout(cfg_entry_t *cep)
{
	/* check controller operational */

	if((get_controller_state(cep->isdncontroller)) != CTRL_UP)
	{
		DBGL(DL_MSG, (log(LL_DBG, "setup_dialout: entry %s, controller is down", cep->name)));
		return(ERROR);
	}

	cep->isdncontrollerused = cep->isdncontroller;

	/* check channel available */

	switch(cep->isdnchannel)
	{
		case CHAN_B1:
		case CHAN_B2:
			if((ret_channel_state(cep->isdncontroller, cep->isdnchannel)) != CHAN_IDLE)
			{
				DBGL(DL_MSG, (log(LL_DBG, "setup_dialout: entry %s, channel not free", cep->name)));
				return(ERROR);
			}
			cep->isdnchannelused = cep->isdnchannel;
			break;

		case CHAN_ANY:
			if(((ret_channel_state(cep->isdncontroller, CHAN_B1)) != CHAN_IDLE) &&
			   ((ret_channel_state(cep->isdncontroller, CHAN_B2)) != CHAN_IDLE))
			{
				DBGL(DL_MSG, (log(LL_DBG, "setup_dialout: entry %s, no channel free", cep->name)));
				return(ERROR);
			}
			cep->isdnchannelused = CHAN_ANY;
			break;

		default:
			DBGL(DL_MSG, (log(LL_DBG, "setup_dialout: entry %s, channel undefined", cep->name)));
			return(ERROR);
			break;
	}

	DBGL(DL_MSG, (log(LL_DBG, "setup_dialout: entry %s ok!", cep->name)));

	/* preset disconnect cause */
	
	SET_CAUSE_TYPE(cep->disc_cause, CAUSET_I4B);
	SET_CAUSE_VAL(cep->disc_cause, CAUSE_I4B_NORMAL);
	
	return(GOOD);
}

/*---------------------------------------------------------------------------*
 *	find entry by drivertype and driverunit
 *---------------------------------------------------------------------------*/
cfg_entry_t *
get_cep_by_driver(int drivertype, int driverunit)
{
	cfg_entry_t *cep = NULL;
	int i;

	for(i=0; i < nentries; i++)
	{
		cep = &cfg_entry_tab[i];	/* ptr to config entry */

		if(!((cep->usrdevicename == drivertype) &&
		     (cep->usrdeviceunit == driverunit)))
		{
			continue;
		}

		DBGL(DL_MSG, (log(LL_DBG, "get_cep_by_driver: found entry %d!", i)));
		return(cep);
	}
	return(NULL);
}

/*---------------------------------------------------------------------------*
 *	find a matching entry for an incoming call
 *
 *	- not found/no match: log output with LL_CHD and return NULL
 *	- found/match: make entry in free cep, return address
 *---------------------------------------------------------------------------*/
cfg_entry_t *
find_matching_entry_incoming(msg_connect_ind_t *mp)
{
	cfg_entry_t *cep = NULL;
	int i;

	/* check for CW (call waiting) early */

	if(mp->channel == CHAN_NO)
	{
		if(aliasing)
	        {
			char *src_tela = "ERROR-src_tela";
			char *dst_tela = "ERROR-dst_tela";
	
	                src_tela = get_alias(mp->src_telno);
	                dst_tela = get_alias(mp->dst_telno);
	
			log(LL_CHD, "%05d <unknown> CW from %s to %s (no channel free)",
				mp->header.cdid, src_tela, dst_tela);
		}
		else
		{
			log(LL_CHD, "%05d <unknown> call waiting from %s to %s (no channel free)",
				mp->header.cdid, mp->src_telno, mp->dst_telno);
		}
		return(NULL);
	}
	
	for(i=0; i < nentries; i++)
	{
		int n;
		cep = &cfg_entry_tab[i];	/* ptr to config entry */

		/* check my number */

		if(strncmp(cep->local_phone_incoming, mp->dst_telno, strlen(cep->local_phone_incoming)))
		{
			DBGL(DL_MSG, (log(LL_DBG, "find_matching_entry_incoming: entry %d, myno %s != incomingno %s", i,
				cep->local_phone_incoming, mp->dst_telno)));
			continue;
		}

		/* check all allowed remote number's for this entry */

		for (n = 0; n < cep->incoming_numbers_count; n++)
		{
			incoming_number_t *in = &cep->remote_phone_incoming[n];
			if(in->number[0] == '*')
				break;
			if(strncmp(in->number, mp->src_telno, strlen(in->number)))
			{
				DBGL(DL_MSG, (log(LL_DBG, "find_matching_entry_incoming: entry %d, remno %s != incomingfromno %s", i,
					in->number, mp->src_telno)));
			}
			else
				break;
		}
		if (n >= cep->incoming_numbers_count)
			continue;

		/* screening indicator XXX */
		
		switch(mp->scr_ind)
		{
			case SCR_NONE:
				DBGL(DL_MSG, (log(LL_DBG, "find_matching_entry_incoming: %s - no screening indicator", mp->src_telno)));
				break;

			case SCR_USR_NOSC:
				DBGL(DL_MSG, (log(LL_DBG, "find_matching_entry_incoming: %s - screening user provided, not screened", mp->src_telno)));
				break;

			case SCR_USR_PASS:
				DBGL(DL_MSG, (log(LL_DBG, "find_matching_entry_incoming: %s - screening user provided, verified & passed", mp->src_telno)));
				break;

			case SCR_USR_FAIL:
				DBGL(DL_MSG, (log(LL_DBG, "find_matching_entry_incoming: %s - screening user provided, verified & failed", mp->src_telno)));
				break;

			case SCR_NET:
				DBGL(DL_MSG, (log(LL_DBG, "find_matching_entry_incoming: %s - screening network provided", mp->src_telno)));
				break;

			default:
				DBGL(DL_MSG, (log(LL_DBG, "find_matching_entry_incoming: ERROR %s - invalid screening indicator!", mp->src_telno)));
				break;
		}
				
		/* check b protocol */

		if(cep->b1protocol != mp->bprot)
		{
			DBGL(DL_MSG, (log(LL_DBG, "find_matching_entry_incoming: entry %d, bprot %d != incomingprot %d", i,
				cep->b1protocol, mp->bprot)));
			continue;
		}

		/* is this entry currently in use ? */

		if(cep->cdid != CDID_UNUSED)
		{
			if(cep->cdid == CDID_RESERVED)
			{
				DBGL(DL_MSG, (log(LL_DBG, "find_matching_entry_incoming: entry %d, cdid is reserved", i)));
			}
			else if (cep->dialin_reaction == REACT_ACCEPT
				 && cep->dialouttype == DIALOUT_CALLEDBACK)
			{
				/*
				 * We might consider doing this even if this is
				 * not a calledback config entry - BUT: there are
				 * severe race conditions and timinig problems
				 * ex. if both sides run I4B with no callback
				 * delay - both may shutdown the outgoing call
				 * and never be able to establish a connection.
				 * In the called-back case this should not happen.
				 */
				DBGL(DL_MSG, (log(LL_DBG, "find_matching_entry_incoming: entry %d, incoming call for callback in progress (cdid %05d)", i, cep->cdid)));

				/* save the current call state, we're going to overwrite it with the
				 * new incoming state below... */
				cep->saved_call.cdid = cep->cdid;
				cep->saved_call.controller = cep->isdncontrollerused;
				cep->saved_call.channel = cep->isdnchannelused;
			}
			else
			{
				DBGL(DL_MSG, (log(LL_DBG, "find_matching_entry_incoming: entry %d, cdid in use", i)));
				continue;	/* yes, next */
			}
		}

		/* check controller value ok */

		if(mp->controller > ncontroller)
		{
			log(LL_CHD, "%05d %s incoming call with invalid controller %d",
                        	mp->header.cdid, cep->name, mp->controller);
			return(NULL);
		}

		/* check controller marked up */

		if((get_controller_state(mp->controller)) != CTRL_UP)
		{
			log(LL_CHD, "%05d %s incoming call, controller %d DOWN!",
                        	mp->header.cdid, cep->name, mp->controller);
			return(NULL);
		}

		/* check channel he wants */

		switch(mp->channel)
		{
			case CHAN_B1:
			case CHAN_B2:
				if((ret_channel_state(mp->controller, mp->channel)) != CHAN_IDLE)
				{
					log(LL_CHD, "%05d %s incoming call, channel %s not free!",
	                	        	mp->header.cdid, cep->name, mp->channel == CHAN_B1 ? "B1" : "B2");
					return(NULL);
				}
				break;

			case CHAN_ANY:
				if(((ret_channel_state(mp->controller, CHAN_B1)) != CHAN_IDLE) &&
				   ((ret_channel_state(mp->controller, CHAN_B2)) != CHAN_IDLE))
				{
					log(LL_CHD, "%05d %s incoming call, no channel free!",
	                	        	mp->header.cdid, cep->name);
					return(NULL);
				}
				break;

			case CHAN_NO:
				log(LL_CHD, "%05d %s incoming call, call waiting (no channel available)!",
                	        	mp->header.cdid, cep->name);
                	        return(NULL);
                	        break;

			default:
				log(LL_CHD, "%05d %s incoming call, ERROR, channel undefined!",
                	        	mp->header.cdid, cep->name);
				return(NULL);
				break;
		}

		/* found a matching entry */

		cep->cdid = mp->header.cdid;
		cep->isdncontrollerused = mp->controller;
		cep->isdnchannelused = mp->channel;
/*XXX*/		cep->disc_cause = 0;

		/* cp number to real one used */
		
		strcpy(cep->real_phone_incoming, mp->src_telno);

		/* copy display string */
		
		strcpy(cep->display, mp->display);
		
		/* entry currently down ? */
		
		if(cep->state == ST_DOWN)
		{
			msg_updown_ind_t mui;
			
			/* set interface up */
	
			DBGL(DL_MSG, (log(LL_DBG, "find_matching_entry_incoming: entry %d, ", i)));
	
			mui.driver = cep->usrdevicename;
			mui.driver_unit = cep->usrdeviceunit;
			mui.updown = SOFT_ENA;
			
			if((ioctl(isdnfd, I4B_UPDOWN_IND, &mui)) < 0)
			{
				log(LL_ERR, "find_matching_entry_incoming: ioctl I4B_UPDOWN_IND failed: %s", strerror(errno));
				do_exit(1);
			}

			cep->down_retry_count = 0;
			cep->state = ST_IDLE;
		}
		return(cep);
	}

	if(aliasing)
        {
		char *src_tela = "ERROR-src_tela";
		char *dst_tela = "ERROR-dst_tela";

                src_tela = get_alias(mp->src_telno);
                dst_tela = get_alias(mp->dst_telno);

		log(LL_CHD, "%05d Call from %s to %s",
			mp->header.cdid, src_tela, dst_tela);
	}
	else
	{
		log(LL_CHD, "%05d <unknown> incoming call from %s to %s",
			mp->header.cdid, mp->src_telno, mp->dst_telno);
	}
	return(NULL);
}

/*---------------------------------------------------------------------------*
 *	return address of ACTIVE config entry by controller and channel
 *---------------------------------------------------------------------------*/
cfg_entry_t *
get_cep_by_cc(int ctrlr, int chan)
{
	int i;

	if((chan != CHAN_B1) && (chan != CHAN_B2))
		return(NULL);
		
	for(i=0; i < nentries; i++)
	{
		if((cfg_entry_tab[i].cdid != CDID_UNUSED)		&&
		   (cfg_entry_tab[i].cdid != CDID_RESERVED)		&&
		   (cfg_entry_tab[i].isdnchannelused == chan)		&&
		   (cfg_entry_tab[i].isdncontrollerused == ctrlr)	&&
		   ((ret_channel_state(ctrlr, chan)) == CHAN_RUN))
		{
			return(&cfg_entry_tab[i]);
		}
	}
	return(NULL);
}

/*---------------------------------------------------------------------------*
 *	return address of config entry identified by cdid
 *---------------------------------------------------------------------------*/
cfg_entry_t *
get_cep_by_cdid(int cdid)
{
	int i;

	for(i=0; i < nentries; i++)
	{
		if(cfg_entry_tab[i].cdid == cdid
		  || cfg_entry_tab[i].saved_call.cdid == cdid)
			return(&cfg_entry_tab[i]);
	}
	return(NULL);
}

/*---------------------------------------------------------------------------*
 *	get name of a controller
 *---------------------------------------------------------------------------*/
const char *
name_of_controller(int ctrl_type, int card_type)
{
	static char *passive_card[] = {
		"Teles S0/8",
		"Teles S0/16",
		"Teles S0/16.3",
		"AVM A1 or Fritz!Card",
		"Teles S0/16.3 PnP",
		"Creatix S0 PnP",
		"USRobotics Sportster ISDN TA",
		"Dr. Neuhaus NICCY Go@",
		"Sedlbauer win speed",
 		"Dynalink IS64PH",
		"ISDN Master, MasterII or Blaster",
		"AVM PCMCIA Fritz!Card",
		"ELSA QuickStep 1000pro/ISA",
		"ELSA QuickStep 1000pro/PCI",
		"Siemens I-Talk",
		"ELSA MicroLink ISDN/MC",
		"ELSA MicroLink MCall",
 		"ITK ix1 micro",
		"AVM Fritz!Card PCI",
		"ELSA PCC-16",
		"AVM Fritz!Card PnP",		
		"Siemens I-Surf 2.0 PnP",		
 		"Asuscom ISDNlink 128K PnP"
	};

	static char *daic_card[] = {
		"EICON.Diehl S",
		"EICON.Diehl SX/SXn",
		"EICON.Diehl SCOM",
		"EICON.Diehl QUADRO",
	};

	if(ctrl_type == CTRL_PASSIVE)
	{
		int index = card_type - CARD_TYPEP_8;
		if (index >= 0 && index < (sizeof passive_card / sizeof passive_card[0]))
			return passive_card[index];
	}
	else if(ctrl_type == CTRL_DAIC)
	{
		int index = card_type - CARD_TYPEA_DAIC_S;
		if (index >= 0 && index < (sizeof daic_card / sizeof daic_card[0] ))
			return daic_card[index];
	}
	else if(ctrl_type == CTRL_TINADD)
	{
		return "Stollmann tina-dd";
	}

	return "unknown card type";
}
 
/*---------------------------------------------------------------------------*
 *	init controller state array
 *---------------------------------------------------------------------------*/
void
init_controller(void)
{
	int i;
	int max = 1;
	msg_ctrl_info_req_t mcir;
	
	for(i=0; i < max; i++)
	{
		mcir.controller = i;
		
		if((ioctl(isdnfd, I4B_CTRL_INFO_REQ, &mcir)) < 0)
		{
			log(LL_ERR, "init_controller: ioctl I4B_CTRL_INFO_REQ failed: %s", strerror(errno));
			do_exit(1);
		}

		if((ncontroller = max = mcir.ncontroller) == 0)
		{
			log(LL_ERR, "init_controller: no ISDN controller found!");
			do_exit(1);
		}

		if(mcir.ctrl_type == -1 || mcir.card_type == -1)
		{
			log(LL_ERR, "init_controller: ctrl/card is invalid!");
			do_exit(1);
		}

		/* init controller tab */

		if((init_controller_state(i, mcir.ctrl_type, mcir.card_type, mcir.tei)) == ERROR)
		{
			log(LL_ERR, "init_controller: init_controller_state for controller %d failed", i);
			do_exit(1);
		}
	}
	DBGL(DL_RCCF, (log(LL_DBG, "init_controller: found %d ISDN controller(s)", max)));
}

/*---------------------------------------------------------------------------*
 *	return b channel driver type name string
 *---------------------------------------------------------------------------*/
char *
bdrivername(int drivertype)
{
	static char *bdtab[] = {
		"rbch",
		"tel",
		"ipr",
		"isp",
		"ibc"
	};

	if(drivertype >= BDRV_RBCH && drivertype <= BDRV_IBC)
		return(bdtab[drivertype]);
	else
		return("unknown");
}

/*---------------------------------------------------------------------------*
 *	process AOCD charging messages
 *---------------------------------------------------------------------------*/
void
handle_charge(cfg_entry_t *cep)
{
	time_t now = time(NULL);

	if(cep->aoc_last == 0)		/* no last timestamp yet ? */
	{
		cep->aoc_last = now;	/* add time stamp */
	}
	else if(cep->aoc_now == 0)	/* no current timestamp yet ? */
	{
		cep->aoc_now = now;	/* current timestamp */
	}
	else
	{
		cep->aoc_last = cep->aoc_now;
		cep->aoc_now = now;
		cep->aoc_diff = cep->aoc_now - cep->aoc_last;
		cep->aoc_valid = AOC_VALID;
	}
	
#ifdef USE_CURSES
	if(do_fullscreen)
		display_charge(cep);
#endif

#ifdef I4B_EXTERNAL_MONITOR
	if(do_monitor && accepted)
		monitor_evnt_charge(cep, cep->charge, 0);
#endif

	if(cep->aoc_valid == AOC_VALID)
	{
		if(cep->aoc_diff != cep->unitlength)
		{
			DBGL(DL_MSG, (log(LL_DBG, "handle_charge: AOCD unit length updated %d -> %d secs", cep->unitlength, cep->aoc_diff)));

			cep->unitlength = cep->aoc_diff;

			unitlen_chkupd(cep);
		}
		else
		{
#ifdef NOTDEF
			DBGL(DL_MSG, (log(LL_DBG, "handle_charge: AOCD unit length still %d secs", cep->unitlength)));
#endif
		}
	}
}

/*---------------------------------------------------------------------------*
 *	update kernel idle_time, earlyhup_time and unitlen_time
 *---------------------------------------------------------------------------*/
void
unitlen_chkupd(cfg_entry_t *cep)
{
	msg_timeout_upd_t tupd;

	tupd.cdid = cep->cdid;

	/* init the short hold data based on the shorthold algorithm type */
	
	switch(cep->shorthold_algorithm)
	{
		case SHA_FIXU:
			tupd.shorthold_data.shorthold_algorithm = SHA_FIXU;
			tupd.shorthold_data.unitlen_time = cep->unitlength;
			tupd.shorthold_data.idle_time = cep->idle_time_out;
			tupd.shorthold_data.earlyhup_time = cep->earlyhangup;
			break;

		case SHA_VARU:
			tupd.shorthold_data.shorthold_algorithm = SHA_VARU;
			tupd.shorthold_data.unitlen_time = cep->unitlength;
			tupd.shorthold_data.idle_time = cep->idle_time_out;
			tupd.shorthold_data.earlyhup_time = 0;
			break;
		default:
			log(LL_ERR, "unitlen_chkupd bad shorthold_algorithm %d", cep->shorthold_algorithm );
			return;
			break;			
	}

	if((ioctl(isdnfd, I4B_TIMEOUT_UPD, &tupd)) < 0)
	{
		log(LL_ERR, "ioctl I4B_TIMEOUT_UPD failed: %s", strerror(errno));
		do_exit(1);
	}
}

/*--------------------------------------------------------------------------*
 *	this is intended to be called by do_exit and closes down all
 *	active connections before the daemon exits or is reconfigured.
 *--------------------------------------------------------------------------*/
void
close_allactive(void)
{
	int i, j;
	cfg_entry_t *cep = NULL;

	j = 0;
	
	for (i = 0; i < ncontroller; i++)
	{
		if((get_controller_state(i)) != CTRL_UP)
			continue;

		if((ret_channel_state(i, CHAN_B1)) == CHAN_RUN)
		{
			if((cep = get_cep_by_cc(i, CHAN_B1)) != NULL)
			{
#ifdef USE_CURSES
				if(do_fullscreen)
					display_disconnect(cep);
#endif
#ifdef I4B_EXTERNAL_MONITOR
				monitor_evnt_disconnect(cep);
#endif
				next_state(cep, EV_DRQ);
				j++;
			}
		}

		if((ret_channel_state(i, CHAN_B2)) == CHAN_RUN)
		{
			if((cep = get_cep_by_cc(i, CHAN_B2)) != NULL)
			{
#ifdef USE_CURSES
				if(do_fullscreen)
					display_disconnect(cep);
#endif
#ifdef I4B_EXTERNAL_MONITOR
				monitor_evnt_disconnect(cep);
#endif
				next_state(cep, EV_DRQ);
				j++;				
			}
		}
	}

	if(j)
	{
		log(LL_DMN, "close_allactive: waiting for all connections terminated");
		sleep(5);
	}
}

/*--------------------------------------------------------------------------*
 *	set an interface up
 *--------------------------------------------------------------------------*/
void
if_up(cfg_entry_t *cep)
{
	msg_updown_ind_t mui;
			
	/* set interface up */
	
	DBGL(DL_MSG, (log(LL_DBG, "if_up: taking %s%d up", bdrivername(cep->usrdevicename), cep->usrdeviceunit)));
	
	mui.driver = cep->usrdevicename;
	mui.driver_unit = cep->usrdeviceunit;
	mui.updown = SOFT_ENA;
			
	if((ioctl(isdnfd, I4B_UPDOWN_IND, &mui)) < 0)
	{
		log(LL_ERR, "if_up: ioctl I4B_UPDOWN_IND failed: %s", strerror(errno));
		do_exit(1);
	}
	cep->down_retry_count = 0;

#ifdef USE_CURSES
	if(do_fullscreen)
		display_updown(cep, 1);
#endif
#ifdef I4B_EXTERNAL_MONITOR
	monitor_evnt_updown(cep, 1);
#endif
	
}

/*--------------------------------------------------------------------------*
 *	set an interface down
 *--------------------------------------------------------------------------*/
void
if_down(cfg_entry_t *cep)
{
	msg_updown_ind_t mui;
			
	/* set interface up */
	
	DBGL(DL_MSG, (log(LL_DBG, "if_down: taking %s%d down", bdrivername(cep->usrdevicename), cep->usrdeviceunit)));
	
	mui.driver = cep->usrdevicename;
	mui.driver_unit = cep->usrdeviceunit;
	mui.updown = SOFT_DIS;
			
	if((ioctl(isdnfd, I4B_UPDOWN_IND, &mui)) < 0)
	{
		log(LL_ERR, "if_down: ioctl I4B_UPDOWN_IND failed: %s", strerror(errno));
		do_exit(1);
	}
	cep->went_down_time = time(NULL);
	cep->down_retry_count = 0;

#ifdef USE_CURSES
	if(do_fullscreen)
		display_updown(cep, 0);
#endif
#ifdef I4B_EXTERNAL_MONITOR
	monitor_evnt_updown(cep, 0);
#endif

}

/*--------------------------------------------------------------------------*
 *	send a dial response to (an interface in) the kernel 
 *--------------------------------------------------------------------------*/
void
dialresponse(cfg_entry_t *cep, int dstat)
{
	msg_dialout_resp_t mdr;

	static char *stattab[] = {
		"normal condition",
		"temporary failure",
		"permanent failure",
		"dialout not allowed"
	};

	if(dstat < DSTAT_NONE || dstat > DSTAT_INONLY)
	{
		log(LL_ERR, "dialresponse: dstat out of range %d!", dstat);
		return;
	}
	
	mdr.driver = cep->usrdevicename;
	mdr.driver_unit = cep->usrdeviceunit;
	mdr.stat = dstat;
	mdr.cause = cep->disc_cause;	
	
	if((ioctl(isdnfd, I4B_DIALOUT_RESP, &mdr)) < 0)
	{
		log(LL_ERR, "dialresponse: ioctl I4B_DIALOUT_RESP failed: %s", strerror(errno));
		do_exit(1);
	}

	DBGL(DL_DRVR, (log(LL_DBG, "dialresponse: sent [%s]", stattab[dstat])));
}
/* EOF */

