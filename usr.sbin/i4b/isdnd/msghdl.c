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
 *	i4b daemon - message from kernel handling routines
 *	--------------------------------------------------
 *
 *	$Id: msghdl.c,v 1.57 1999/02/25 12:45:41 hm Exp $ 
 *
 *      last edit-date: [Thu Feb 25 13:43:46 1999]
 *
 *---------------------------------------------------------------------------*/

#include "isdnd.h"

/*---------------------------------------------------------------------------*
 *	handle incoming CONNECT_IND (=SETUP) message
 *---------------------------------------------------------------------------*/
void
msg_connect_ind(msg_connect_ind_t *mp)
{
	cfg_entry_t *cep;
	char *src_tela = "ERROR-src_tela";
	char *dst_tela = "ERROR-dst_tela";

#define SRC (aliasing == 0 ? mp->src_telno : src_tela)
#define DST (aliasing == 0 ? mp->dst_telno : dst_tela)

	if((cep = find_matching_entry_incoming(mp)) == NULL)
	{
		/* log message generated in find_matching_entry_incoming() */
		sendm_connect_resp(NULL, mp->header.cdid, SETUP_RESP_DNTCRE, 0);
		return;
	}

	if(cep->cdid != CDID_UNUSED && cep->cdid != CDID_RESERVED)
	{	
		/* 
		 * This is an incoming call on a number we just dialed out.
		 * Stop our dial-out and accept the incoming call.
		 */
		if(cep->saved_call.cdid != CDID_UNUSED &&
		   cep->saved_call.cdid != CDID_RESERVED)
		{
			int cdid;

			/* disconnect old, not new */
			
			cdid = cep->cdid;
			cep->cdid = cep->saved_call.cdid;
			sendm_disconnect_req(cep, (CAUSET_I4B << 8) | CAUSE_I4B_NORMAL);
			cep->cdid = cdid;

			/*
			 * Shortcut the state machine and mark this
			 * entry as free
			 */
/* XXX */		cep->state = ST_IDLE;	/* this is an invalid	*/
						/* transition,		*/
						/* so no next_state()	*/
			/* we have to wait here for an incoming	*/
			/* disconnect message !!! (-hm)		*/
		}
	}

	if(aliasing)
	{
		src_tela = get_alias(mp->src_telno);
		dst_tela = get_alias(mp->dst_telno);
	}

	if(cep->inout == DIR_OUTONLY)
	{
		log(LL_CHD, "%05d %s incoming call from %s to %s not allowed by configuration!",
			mp->header.cdid, cep->name, SRC, DST);
		sendm_connect_resp(NULL, mp->header.cdid, SETUP_RESP_DNTCRE, 0);
		return;
	}

	cep->charge = 0;
	cep->last_charge = 0;
		
	switch(cep->dialin_reaction)
	{
		case REACT_ACCEPT:
			log(LL_CHD, "%05d %s accepting: incoming call from %s to %s",
				mp->header.cdid, cep->name, SRC, DST);
			decr_free_channels(mp->controller);
			next_state(cep, EV_MCI);
			break;

		case REACT_REJECT:
			log(LL_CHD, "%05d %s rejecting: incoming call from %s to %s",
				mp->header.cdid, cep->name, SRC, DST);
			sendm_connect_resp(cep, mp->header.cdid, SETUP_RESP_REJECT,
				(CAUSET_I4B << 8) | CAUSE_I4B_REJECT);
			cep->cdid = CDID_UNUSED;
			break;

		case REACT_IGNORE:
			log(LL_CHD, "%05d %s ignoring: incoming call from %s to %s",
				mp->header.cdid, cep->name, SRC, DST);
			sendm_connect_resp(NULL, mp->header.cdid, SETUP_RESP_DNTCRE, 0);
			break;

		case REACT_ANSWER:
			decr_free_channels(mp->controller);
			if(cep->alert)
			{
				if(mp->display)
				{
					log(LL_CHD, "%05d %s alerting: incoming call from %s to %s (%s)",
					        mp->header.cdid, cep->name, SRC, DST, mp->display);
				}
				else
				{
					log(LL_CHD, "%05d %s alerting: incoming call from %s to %s",
					        mp->header.cdid, cep->name, SRC, DST);
				}
				next_state(cep, EV_ALRT);
			}
			else
			{
				if(mp->display)
				{				
					log(LL_CHD, "%05d %s answering: incoming call from %s to %s (%s)",
						mp->header.cdid, cep->name, SRC, DST, mp->display);
				}
				else
				{
					log(LL_CHD, "%05d %s answering: incoming call from %s to %s",
						mp->header.cdid, cep->name, SRC, DST);
				}
				next_state(cep, EV_MCI);
			}
			break;

		case REACT_CALLBACK:
#ifdef NOTDEF
/*XXX reserve channel ??? */	decr_free_channels(mp->controller);
#endif
			if(cep->cdid == CDID_RESERVED)
			{
				log(LL_CHD, "%05d %s reserved: incoming call from %s to %s",
					mp->header.cdid, cep->name, SRC, DST);
				sendm_connect_resp(cep, mp->header.cdid, SETUP_RESP_REJECT,
					(CAUSET_I4B << 8) | CAUSE_I4B_NORMAL);
				/* no state change */
			}
			else
			{
				log(LL_CHD, "%05d %s callback: incoming call from %s to %s",
					mp->header.cdid, cep->name, SRC, DST);
				sendm_connect_resp(cep, mp->header.cdid, SETUP_RESP_REJECT,
					(CAUSET_I4B << 8) | CAUSE_I4B_NORMAL);
				cep->last_release_time = time(NULL);
				cep->cdid = CDID_RESERVED;
				next_state(cep, EV_CBRQ);
			}
			break;
			
		default:
			log(LL_WRN, "msg_connect_ind: unknown response type, tx SETUP_RESP_DNTCRE");
			sendm_connect_resp(NULL, mp->header.cdid, SETUP_RESP_DNTCRE, 0);
			break;
	}
#undef SRC
#undef DST
}

/*---------------------------------------------------------------------------*
 *	handle incoming CONNECT_ACTIVE_IND message
 *---------------------------------------------------------------------------*/
void
msg_connect_active_ind(msg_connect_active_ind_t *mp)
{
	cfg_entry_t *cep;
	
	if((cep = get_cep_by_cdid(mp->header.cdid)) == NULL)
	{
		log(LL_WRN, "msg_connect_active_ind: cdid not found!");
		return;
	}

	cep->isdncontrollerused = mp->controller;
	cep->isdnchannelused = mp->channel;	
                                                                                
	cep->aoc_now = cep->connect_time = time(NULL);
	cep->aoc_last = 0;
	cep->aoc_diff = 0;
	cep->aoc_valid = AOC_INVALID;

	cep->local_disconnect = DISCON_REM;	
	
	cep->inbytes = INVALID;
	cep->outbytes = INVALID;
	cep->hangup = 0;

	/* set the B-channel to active */

	if((set_channel_busy(cep->isdncontrollerused, cep->isdnchannelused)) == ERROR)
		log(LL_ERR, "msg_connect_active_ind: set_channel_busy failed!");

	if(cep->direction == DIR_OUT)
	{
		log(LL_CHD, "%05d %s outgoing call active (ctl %d, ch %d)",
			cep->cdid, cep->name,
			cep->isdncontrollerused, cep->isdnchannelused);
	}
	else
	{
		log(LL_CHD, "%05d %s incoming call active (ctl %d, ch %d)",
			cep->cdid, cep->name,
			cep->isdncontrollerused, cep->isdnchannelused);
	}
	
#ifdef USE_CURSES
	if(do_fullscreen)
		display_connect(cep);
#endif
#ifdef I4B_EXTERNAL_MONITOR
	if(do_monitor && accepted)
		monitor_evnt_connect(cep);
#endif

	if(isdntime && (mp->datetime[0] != '\0'))
	{
		log(LL_DMN, "date/time from exchange = %s", mp->datetime);
	}

	next_state(cep, EV_MCAI);
}
                                                                                
/*---------------------------------------------------------------------------*
 *	handle incoming PROCEEDING_IND message
 *---------------------------------------------------------------------------*/
void
msg_proceeding_ind(msg_proceeding_ind_t *mp)
{
	cfg_entry_t *cep;
	
	if((cep = get_cep_by_cdid(mp->header.cdid)) == NULL)
	{
		log(LL_WRN, "msg_proceeding_ind: cdid not found!");
		return;
	}

	cep->isdncontrollerused = mp->controller;
	cep->isdnchannelused = mp->channel;	
                                                                                
	/* set the B-channels active */

	if((set_channel_busy(cep->isdncontrollerused, cep->isdnchannelused)) == ERROR)
		log(LL_ERR, "msg_proceeding_ind: set_channel_busy failed!");
	
	log(LL_CHD, "%05d %s outgoing call proceeding (ctl %d, ch %d)",
			cep->cdid, cep->name,
			cep->isdncontrollerused, cep->isdnchannelused);
}
                                                                                
/*---------------------------------------------------------------------------*
 *	handle incoming ALERT_IND message
 *---------------------------------------------------------------------------*/
void
msg_alert_ind(msg_alert_ind_t *mp)
{
	cfg_entry_t *cep;
	
	if((cep = get_cep_by_cdid(mp->header.cdid)) == NULL)
	{
		log(LL_WRN, "msg_alert_ind: cdid not found!");
		return;
	}
#ifdef NOTDEF
	log(LL_CHD, "%05d %s incoming alert", cep->cdid, cep->name);
#endif
}
                                                                                
/*---------------------------------------------------------------------------*
 *	handle incoming L12STAT_IND message
 *---------------------------------------------------------------------------*/
void
msg_l12stat_ind(msg_l12stat_ind_t *ml)
{
#ifdef USE_CURSES
	if(do_fullscreen)
		display_l12stat(ml->controller, ml->layer, ml->state);
#endif

	DBGL(DL_CNST, (log(LL_DBG, "msg_l12stat_ind: unit %d, layer %d, state %d",
		ml->controller, ml->layer, ml->state)));
}
                                                                                
/*---------------------------------------------------------------------------*
 *	handle incoming TEIASG_IND message
 *---------------------------------------------------------------------------*/
void
msg_teiasg_ind(msg_teiasg_ind_t *mt)
{
#ifdef USE_CURSES
	if(do_fullscreen)
		display_tei(mt->controller, mt->tei);
#endif

	DBGL(DL_CNST, (log(LL_DBG, "msg_teiasg_ind: unit %d, tei = %d",
		mt->controller, mt->tei)));
}

/*---------------------------------------------------------------------------*
 *	handle incoming L12STAT_IND message
 *---------------------------------------------------------------------------*/
void
msg_pdeact_ind(msg_pdeact_ind_t *md)
{
	int i;
	int ctrl = md->controller;
	cfg_entry_t *cep;

#ifdef USE_CURSES
	if(do_fullscreen)
	{
		display_l12stat(ctrl, LAYER_ONE, LAYER_IDLE);
		display_l12stat(ctrl, LAYER_TWO, LAYER_IDLE);
		display_tei(ctrl, -1);
	}
#endif

	DBGL(DL_CNST, (log(LL_DBG, "msg_pdeact_ind: unit %d, persistent deactivation", ctrl)));

	for(i=0; i < nentries; i++)
	{
		if((cfg_entry_tab[i].cdid != CDID_UNUSED)	&&
		   (cfg_entry_tab[i].isdncontrollerused == ctrl))
		{
			cep = &cfg_entry_tab[i];
			
			if(cep->cdid == CDID_RESERVED)
			{
				cep->cdid = CDID_UNUSED;
				continue;
			}

			cep->cdid = CDID_UNUSED;
			
			cep->last_release_time = time(NULL);

			SET_CAUSE_TYPE(cep->disc_cause, CAUSET_I4B);
			SET_CAUSE_VAL(cep->disc_cause, CAUSE_I4B_L1ERROR);
		
			if(cep->direction == DIR_OUT)
			{
				log(LL_CHD, "%05d %s outgoing call disconnected (local)",
					cep->cdid, cep->name);
			}
			else
			{
				log(LL_CHD, "%05d %s incoming call disconnected (local)",
					cep->cdid, cep->name);
			}
		
			log(LL_CHD, "%05d %s cause %s",
				cep->cdid, cep->name, print_i4b_cause(cep->disc_cause));
		
#ifdef USE_CURSES
			if(do_fullscreen && (cep->connect_time > 0))
				display_disconnect(cep);
#endif
		
#ifdef I4B_EXTERNAL_MONITOR
			if(do_monitor && accepted)
				monitor_evnt_disconnect(cep);
#endif
			if(cep->disconnectprog)
				exec_connect_prog(cep, cep->disconnectprog, 1);
		
			if(cep->connect_time > 0)
			{
				if(cep->direction == DIR_OUT)
				{
					log(LL_CHD, "%05d %s charging: %d units, %d seconds",
						cep->cdid, cep->name, cep->charge,
						(int)difftime(time(NULL), cep->connect_time));
				}
				else
				{
					log(LL_CHD, "%05d %s connected %d seconds",
						cep->cdid, cep->name,
						(int)difftime(time(NULL), cep->connect_time));
				}
		
				if((cep->inbytes != INVALID) && (cep->outbytes != INVALID))
				{
					if((cep->ioutbytes != cep->outbytes) ||
					   (cep->iinbytes != cep->inbytes))
					{
						log(LL_CHD, "%05d %s accounting: in %d, out %d (in %d, out %d)",
							cep->cdid, cep->name,
							cep->inbytes, cep->outbytes,
							cep->iinbytes, cep->ioutbytes);
					}
					else
					{
						log(LL_CHD, "%05d %s accounting: in %d, out %d",
							cep->cdid, cep->name,
							cep->inbytes, cep->outbytes);
					}
				}
			}

			if(useacctfile && (cep->connect_time > 0))
			{
				int con_secs;
				char logdatetime[41];
				struct tm *tp;
		
				con_secs = difftime(time(NULL), cep->connect_time);
					
				tp = localtime(&cep->connect_time);
				
		strftime(logdatetime,40,I4B_TIME_FORMAT,tp);
		
				if(cep->inbytes != INVALID && cep->outbytes != INVALID)
				{
					fprintf(acctfp, "%s - %s %s %d (%d) (%d/%d)\n",
						logdatetime, getlogdatetime(),
						cep->name, cep->charge, con_secs,
						cep->inbytes, cep->outbytes);
				}
				else
				{
					fprintf(acctfp, "%s - %s %s %d (%d)\n",
						logdatetime, getlogdatetime(),
						cep->name, cep->charge, con_secs);
				}
			}
		
			/* set the B-channel inactive */
		
			if((set_channel_idle(cep->isdncontrollerused, cep->isdnchannelused)) == ERROR)
				log(LL_ERR, "msg_pdeact_ind: set_channel_idle failed!");
		
			incr_free_channels(cep->isdncontrollerused);
			
			cep->connect_time = 0;
		}
	}
}
                                                                                
/*---------------------------------------------------------------------------*
 *	handle incoming NEGCOMP_IND message
 *---------------------------------------------------------------------------*/
void
msg_negcomplete_ind(msg_negcomplete_ind_t *mp)
{
	cfg_entry_t *cep;

	if((cep = get_cep_by_cdid(mp->header.cdid)) == NULL)
	{
		log(LL_WRN, "msg_negcomp_ind: cdid not found");
		return;
	}

	if(cep->connectprog)
		exec_connect_prog(cep, cep->connectprog, 0);
}
                                                                                
/*---------------------------------------------------------------------------*
 *	handle incoming IFSTATE_CHANGED indication
 *---------------------------------------------------------------------------*/
void
msg_ifstatechg_ind(msg_ifstatechg_ind_t *mp)
{
	cfg_entry_t *cep;
	char *device;

	if((cep = get_cep_by_cdid(mp->header.cdid)) == NULL)
	{
		log(LL_WRN, "msg_negcomp_ind: cdid not found");
		return;
	}

	device = bdrivername(cep->usrdevicename);
	log(LL_DBG, "%s%d: switched to state %d", device, cep->usrdeviceunit, mp->state);
}

/*---------------------------------------------------------------------------*
 *	handle incoming DISCONNECT_IND message
 *---------------------------------------------------------------------------*/
void
msg_disconnect_ind(msg_disconnect_ind_t *mp)
{
	cfg_entry_t *cep;

	if((cep = get_cep_by_cdid(mp->header.cdid)) == NULL)
	{
		log(LL_WRN, "msg_disconnect_ind: cdid not found");
		return;
	}

	/* is this an aborted out-call prematurely called back? */
	if (cep->saved_call.cdid == mp->header.cdid)
	{
		DBGL(DL_CNST, (log(LL_DBG, "aborted outcall %05d disconnected",
			mp->header.cdid)));
		cep->saved_call.cdid = CDID_UNUSED;

		if((set_channel_idle(cep->saved_call.controller, cep->saved_call.channel)) == ERROR)
			log(LL_ERR, "msg_disconnect_ind: set_channel_idle failed!");

		incr_free_channels(cep->saved_call.controller);
		return;
	}

	cep->last_release_time = time(NULL);
	cep->disc_cause = mp->cause;

	if(cep->direction == DIR_OUT)
	{
		log(LL_CHD, "%05d %s outgoing call disconnected %s",
			cep->cdid, cep->name, 
			cep->local_disconnect == DISCON_LOC ?
						"(local)" : "(remote)");
	}
	else
	{
		log(LL_CHD, "%05d %s incoming call disconnected %s", 
			cep->cdid, cep->name,
			cep->local_disconnect == DISCON_LOC ?
						"(local)" : "(remote)");
	}

	log(LL_CHD, "%05d %s cause %s",
		cep->cdid, cep->name, print_i4b_cause(mp->cause));

#ifdef USE_CURSES
	if(do_fullscreen && (cep->connect_time > 0))
		display_disconnect(cep);
#endif

#ifdef I4B_EXTERNAL_MONITOR
	if(do_monitor && accepted)
		monitor_evnt_disconnect(cep);
#endif

	if(cep->disconnectprog)
		exec_connect_prog(cep, cep->disconnectprog, 1);

	if(cep->connect_time > 0)
	{
		if(cep->direction == DIR_OUT)
		{
			log(LL_CHD, "%05d %s charging: %d units, %d seconds",
				cep->cdid, cep->name, cep->charge,
				(int)difftime(time(NULL), cep->connect_time));
		}
		else
		{
			log(LL_CHD, "%05d %s connected %d seconds",
				cep->cdid, cep->name,
				(int)difftime(time(NULL), cep->connect_time));
		}

		if((cep->inbytes != INVALID) && (cep->outbytes != INVALID))
		{
			if((cep->ioutbytes != cep->outbytes) ||
			   (cep->iinbytes != cep->inbytes))
			{
				log(LL_CHD, "%05d %s accounting: in %d, out %d (in %d, out %d)",
					cep->cdid, cep->name,
					cep->inbytes, cep->outbytes,
					cep->iinbytes, cep->ioutbytes);
			}
			else
			{
				log(LL_CHD, "%05d %s accounting: in %d, out %d",
					cep->cdid, cep->name,
					cep->inbytes, cep->outbytes);
			}
		}
	}			

	if(useacctfile && (cep->connect_time > 0))
	{
		int con_secs;
		char logdatetime[41];
		struct tm *tp;

		con_secs = difftime(time(NULL), cep->connect_time);
			
		tp = localtime(&cep->connect_time);
		
		strftime(logdatetime,40,I4B_TIME_FORMAT,tp);

		if(cep->inbytes != INVALID && cep->outbytes != INVALID)
		{
			fprintf(acctfp, "%s - %s %s %d (%d) (%d/%d)\n",
				logdatetime, getlogdatetime(),
				cep->name, cep->charge, con_secs,
				cep->inbytes, cep->outbytes);
		}
		else
		{
			fprintf(acctfp, "%s - %s %s %d (%d)\n",
				logdatetime, getlogdatetime(),
				cep->name, cep->charge, con_secs);
		}
	}

	/* set the B-channel inactive */

	if((set_channel_idle(cep->isdncontrollerused, cep->isdnchannelused)) == ERROR)
		log(LL_ERR, "msg_disconnect_ind: set_channel_idle failed!");

	incr_free_channels(cep->isdncontrollerused);
	
	cep->connect_time = 0;			

	next_state(cep, EV_MDI);
}

/*---------------------------------------------------------------------------*
 *	handle incoming DIALOUT message
 *---------------------------------------------------------------------------*/
void
msg_dialout(msg_dialout_ind_t *mp)
{
	cfg_entry_t *cep;
	
	DBGL(DL_DRVR, (log(LL_DBG, "msg_dialout: dial req from %s, unit %d", bdrivername(mp->driver), mp->driver_unit)));

	if((cep = find_by_device_for_dialout(mp->driver, mp->driver_unit)) == NULL)
	{
		DBGL(DL_DRVR, (log(LL_DBG, "msg_dialout: config entry reserved or no match")));
		return;
	}

	if(cep->inout == DIR_INONLY)
	{
		dialresponse(cep, DSTAT_INONLY);
		return;
	}
	
	if((cep->cdid = get_cdid()) == 0)
	{
		DBGL(DL_DRVR, (log(LL_DBG, "msg_dialout: get_cdid() returned 0!")));
		return;
	}
	
	cep->charge = 0;
	cep->last_charge = 0;

	next_state(cep, EV_MDO);	
}

/*---------------------------------------------------------------------------*
 *	handle incoming DRVRDISC_REQ message
 *---------------------------------------------------------------------------*/
void
msg_drvrdisc_req(msg_drvrdisc_req_t *mp)
{
	cfg_entry_t *cep;
	
	DBGL(DL_DRVR, (log(LL_DBG, "msg_drvrdisc_req: req from %s, unit %d", bdrivername(mp->driver), mp->driver_unit)));

	if((cep = get_cep_by_driver(mp->driver, mp->driver_unit)) == NULL)
	{
		DBGL(DL_DRVR, (log(LL_DBG, "msg_drvrdisc_req: config entry not found")));
		return;
	}
	next_state(cep, EV_DRQ);
}

/*---------------------------------------------------------------------------*
 *	handle incoming ACCOUNTING message
 *---------------------------------------------------------------------------*/
void
msg_accounting(msg_accounting_ind_t *mp)
{
	cfg_entry_t *cep;

	if((cep = find_active_entry_by_driver(mp->driver, mp->driver_unit)) == NULL)
	{
		log(LL_WRN, "msg_accounting: no config entry found!");	
		return;
	}

	cep->inbytes = mp->inbytes;
	cep->iinbytes = mp->iinbytes;
	cep->outbytes = mp->outbytes;
	cep->ioutbytes = mp->ioutbytes;
	cep->inbps = mp->inbps;
	cep->outbps = mp->outbps;

	if(mp->accttype == ACCT_DURING) 
	{
#ifdef USE_CURSES
		if(do_fullscreen)
			display_acct(cep);
#endif
#ifdef NOTDEF
		else
			DBGL(DL_DRVR, (log(LL_DBG, "msg_accounting: %s%d, ioutb=%d, iinb=%d, outb=%d, inb=%d, outbps=%d, inbps=%d",
				bdrivername(mp->driver), mp->driver_unit,
				mp->ioutbytes, mp->iinbytes,
				mp->outbytes, mp->inbytes,
				mp->outbps, mp->inbps)));
#endif				
	}
}

/*---------------------------------------------------------------------------*
 *	handle incoming CHARGING message
 *---------------------------------------------------------------------------*/
void
msg_charging_ind(msg_charging_ind_t *mp)
{
	static char *cttab[] = {
		"invalid",
		"AOCD",
		"AOCE",
		"estimated" };
		
	cfg_entry_t *cep;

	if((cep = get_cep_by_cdid(mp->header.cdid)) == NULL)
	{
		log(LL_WRN, "msg_charging_ind: cdid not found");
		return;
	}

	if(mp->units_type < CHARGE_INVALID || mp->units_type > CHARGE_CALC)
	{ 
		log(LL_ERR, "msg_charging: units_type %d out of range!", mp->units_type);
		do_exit(1);
	}
	
	DBGL(DL_DRVR, (log(LL_DBG, "msg_charging: %d unit(s) (%s)",
			mp->units, cttab[mp->units_type])));

	switch(mp->units_type)
	{
		case CHARGE_AOCD:
			cep->charge = mp->units;

			if((cep->unitlengthsrc == ULSRC_DYN) &&
			   (cep->charge != cep->last_charge))
			{
				cep->last_charge = cep->charge;
				handle_charge(cep);
			}
			break;

		case CHARGE_AOCE:
			cep->charge = mp->units;
			break;
			
		case CHARGE_CALC:
			cep->charge = mp->units;	
#ifdef USE_CURSES
		        if(do_fullscreen)
                	        display_ccharge(cep, mp->units);
#endif
#ifdef I4B_EXTERNAL_MONITOR
			if(do_monitor && accepted)
				monitor_evnt_charge(cep, mp->units, 1);
#endif
			break;
	}
}

/*---------------------------------------------------------------------------*
 *	handle incoming IDLE_TIMEOUT_IND message
 *---------------------------------------------------------------------------*/
void
msg_idle_timeout_ind(msg_idle_timeout_ind_t *mp)
{
	cfg_entry_t *cep;
	
	if((cep = get_cep_by_cdid(mp->header.cdid)) == NULL)
	{
		log(LL_WRN, "msg_idle_timeout_ind: cdid not found!");
		return;
	}

	cep->local_disconnect = DISCON_LOC;
	
	DBGL(DL_DRVR, (log(LL_DBG, "msg_idle_timeout_ind: idletimeout, kernel sent disconnect!")));
	
	check_and_kill(cep);
}

/*---------------------------------------------------------------------------*
 *	get a cdid from kernel
 *---------------------------------------------------------------------------*/
int
get_cdid(void)
{
	msg_cdid_req_t mcr;

	mcr.cdid = 0;
	
	if((ioctl(isdnfd, I4B_CDID_REQ, &mcr)) < 0)
	{
		log(LL_ERR, "get_cdid: ioctl I4B_CDID_REQ failed: %s", strerror(errno));
		do_exit(1);
	}

	return(mcr.cdid);
}

/*---------------------------------------------------------------------------*
 *      send message "connect request" to kernel
 *---------------------------------------------------------------------------*/
int
sendm_connect_req(cfg_entry_t *cep)
{
        msg_connect_req_t mcr;
        int ret;

	cep->local_disconnect = DISCON_REM;
        
	cep->unitlength = get_current_rate(cep, 1);
	
	mcr.cdid = cep->cdid;

	mcr.controller = cep->isdncontrollerused;
	mcr.channel = cep->isdnchannelused;
	mcr.txdelay = cep->isdntxdelout;

	mcr.bprot = cep->b1protocol;

	mcr.driver = cep->usrdevicename;
	mcr.driver_unit = cep->usrdeviceunit;

	/* setup the shorthold data */
	mcr.shorthold_data.shorthold_algorithm = cep->shorthold_algorithm;
	mcr.shorthold_data.unitlen_time = cep->unitlength;
	mcr.shorthold_data.idle_time = cep->idle_time_out;		
	mcr.shorthold_data.earlyhup_time = cep->earlyhangup;

	if(cep->unitlengthsrc == ULSRC_DYN)
		mcr.unitlen_method = ULEN_METHOD_DYNAMIC;
	else
		mcr.unitlen_method = ULEN_METHOD_STATIC;
	
	strcpy(mcr.dst_telno, cep->remote_phone_dialout);
	strcpy(mcr.src_telno, cep->local_phone_dialout);

	cep->last_dial_time = time(NULL);
	cep->direction = DIR_OUT;

	DBGL(DL_CNST, (log(LL_DBG, "sendm_connect_req: ctrl = %d, chan = %d", cep->isdncontrollerused, cep->isdnchannelused)));
		
	if((ret = ioctl(isdnfd, I4B_CONNECT_REQ, &mcr)) < 0)
	{
		log(LL_ERR, "sendm_connect_req: ioctl I4B_CONNECT_REQ failed: %s", strerror(errno));
		do_exit(1);
	}

	decr_free_channels(cep->isdncontrollerused);
	
	log(LL_CHD, "%05d %s dialing out from %s to %s",
		cep->cdid,
	        cep->name,
		aliasing ? get_alias(cep->local_phone_dialout) : cep->local_phone_dialout,
		aliasing ? get_alias(cep->remote_phone_dialout) : cep->remote_phone_dialout);

	return(ret);
}

/*---------------------------------------------------------------------------*
 *	send message "connect response" to kernel
 *---------------------------------------------------------------------------*/
int
sendm_connect_resp(cfg_entry_t *cep, int cdid, int response, int cause)
{
	msg_connect_resp_t mcr;
	int ret;

	mcr.cdid = cdid;

	mcr.response = response;

	if(response == SETUP_RESP_REJECT)
	{
		mcr.cause = cause;
	}
	else if(response == SETUP_RESP_ACCEPT)
	{
		cep->direction = DIR_IN;

		mcr.txdelay = cep->isdntxdelin;

		mcr.bprot = cep->b1protocol;

		mcr.driver = cep->usrdevicename;
		mcr.driver_unit = cep->usrdeviceunit;

		mcr.max_idle_time = cep->idle_time_in;
	}
	
	if((ret = ioctl(isdnfd, I4B_CONNECT_RESP, &mcr)) < 0)
	{
		log(LL_ERR, "sendm_connect_resp: ioctl I4B_CONNECT_RESP failed: %s", strerror(errno));
		do_exit(1);
	}

	DBGL(DL_DRVR, (log(LL_DBG, "sendm_connect_resp: sent CONNECT_RESP")));

	return(ret);
}

/*---------------------------------------------------------------------------*
 *	send message "disconnect request" to kernel
 *---------------------------------------------------------------------------*/
int
sendm_disconnect_req(cfg_entry_t *cep, int cause)
{
	msg_discon_req_t mcr;
	int ret;

	mcr.cdid = cep->cdid;

	mcr.cause = cause;

	cep->local_disconnect = DISCON_LOC;
	
	if((ret = ioctl(isdnfd, I4B_DISCONNECT_REQ, &mcr)) < 0)
	{
		log(LL_ERR, "sendm_disconnect_req: ioctl I4B_DISCONNECT_REQ failed: %s", strerror(errno));
		do_exit(1);
	}
	else
	{
		DBGL(DL_DRVR, (log(LL_DBG, "sendm_disconnect_req: sent DISCONNECT_REQ")));
	}
	return(ret);
}
	
/*---------------------------------------------------------------------------*
 *	send message "alert request" to kernel
 *---------------------------------------------------------------------------*/
int
sendm_alert_req(cfg_entry_t *cep)
{
	msg_alert_req_t mar;
	int ret;

	mar.cdid = cep->cdid;
	
	if((ret = ioctl(isdnfd, I4B_ALERT_REQ, &mar)) < 0)
	{
		log(LL_ERR, "sendm_alert_req: ioctl I4B_ALERT_REQ failed: %s", strerror(errno));
		do_exit(1);
	}
	else
	{
		DBGL(DL_DRVR, (log(LL_DBG, "sendm_alert_req: sent ALERT_REQ")));
	}
	return(ret);
}
	
/* EOF */
