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
 *	i4b_global.h - i4b global include file
 *	--------------------------------------
 *
 *	$Id: i4b_global.h,v 1.19 1999/02/27 11:08:01 hm Exp $
 *
 *	last edit-date: [Sun Feb 14 10:03:55 1999]
 *
 *---------------------------------------------------------------------------*/

#ifndef _I4B_GLOBAL_H_
#define _I4B_GLOBAL_H_

#define	SPLI4B()	splimp()	/* spl for i4b		*/

#define TIMER_IDLE	1		/* a timer is running	*/
#define TIMER_ACTIVE	2		/* a timer is idle	*/

#ifdef __FreeBSD__
#include <sys/param.h>
#if defined(__FreeBSD_version) && __FreeBSD_version >= 300001

#define TIMEOUT_FUNC_T	timeout_t *
#define SECOND		time_second
#define MICROTIME(x)	getmicrotime(&(x))

#else /* FreeBSD < 3 */

#define TIMEOUT_FUNC_T  timeout_func_t
#define SECOND		time.tv_sec
#define MICROTIME(x)	microtime(&(x))

#endif /* >= 3 */
#endif /* __FreeBSD__ */

#if defined(__NetBSD__) || defined (__OpenBSD__) || defined(__bsdi__)

#define TIMEOUT_FUNC_T	void *
#define SECOND		time.tv_sec
#define MICROTIME(x)	(x) = time

#endif /* __NetBSD__ */

/* definitions for the STATUS indications L1 -> L2 -> L3 */

#define	STI_ATTACH	0	/* attach at boot time	*/
#define	STI_L1STAT	1	/* layer 1 status	*/
#define	STI_L2STAT	2	/* layer 2 status	*/
#define	STI_TEIASG	3	/* TEI assignments	*/
#define	STI_PDEACT	4	/* Layer 1 T4 expired = persistent deactivation */
#define STI_NOL1ACC	5	/* no outgoing L1 access possible */

/* definitions for the COMMAND requests L3 -> L2 -> L1 */

#define CMR_DOPEN	0	/* daemon opened /dev/i4b */
#define CMR_DCLOSE	1	/* daemon closed /dev/i4b */

/*---------------------------------------------------------------------------
 *
 *	Number of max supported passive card units
 *
 *	Teles/Creatix/Neuhaus cards have a hardware limitation
 *	as one is able to set 3 (sometimes 4) different configurations by
 *      jumpers so a maximum of 3 (4) cards per ISA bus is possible.
 *      (Note: there are multiple ISA buses on some architectures)
 *
 *---------------------------------------------------------------------------*/
#define ISIC_MAXUNIT	3		/* max no of supported units 0..3 */

#endif /* _I4B_GLOBAL_H_ */
