/*
 *
 * ===================================
 * HARP  |  Host ATM Research Platform
 * ===================================
 *
 *
 * This Host ATM Research Platform ("HARP") file (the "Software") is
 * made available by Network Computing Services, Inc. ("NetworkCS")
 * "AS IS".  NetworkCS does not provide maintenance, improvements or
 * support of any kind.
 *
 * NETWORKCS MAKES NO WARRANTIES OR REPRESENTATIONS, EXPRESS OR IMPLIED,
 * INCLUDING, BUT NOT LIMITED TO, IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE, AS TO ANY ELEMENT OF THE
 * SOFTWARE OR ANY SUPPORT PROVIDED IN CONNECTION WITH THIS SOFTWARE.
 * In no event shall NetworkCS be responsible for any damages, including
 * but not limited to consequential damages, arising from or relating to
 * any use of the Software or related support.
 *
 * Copyright 1994-1998 Network Computing Services, Inc.
 *
 * Copies of this Software may be made, however, the above copyright
 * notice must be reproduced on all copies.
 *
 *	@(#) $Id: atmarp_config.c,v 1.5 1998/08/13 20:11:11 johnc Exp $
 *
 */

/*
 * Server Cache Synchronization Protocol (SCSP) Support
 * ----------------------------------------------------
 *
 * SCSP-ATMARP server interface: configuration support
 *
 */

#ifndef lint
static char *RCSid = "@(#) $Id: atmarp_config.c,v 1.5 1998/08/13 20:11:11 johnc Exp $";
#endif

#include <sys/types.h>
#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netatm/port.h>
#include <netatm/queue.h>
#include <netatm/atm.h>
#include <netatm/atm_if.h>
#include <netatm/atm_sap.h>
#include <netatm/atm_sys.h>
#include <netatm/atm_ioctl.h>
 
#include <libatm.h>
#include "../scspd/scsp_msg.h"
#include "../scspd/scsp_if.h"
#include "../scspd/scsp_var.h"
#include "atmarp_var.h"


/*
 * Configure network interface for ATMARP cache synchronization
 *
 * Verify the network interface name and set the appropriate fields
 * in the ATMARP interface entry.
 *
 * Arguments:
 *	netif	pointer to network interface name
 *
 * Returns:
 *	0	success
 *	errno	reason for failure
 *
 */
int
atmarp_cfg_netif(netif)
	char	*netif;
{
	int			rc;
	Atmarp_intf		*aip = (Atmarp_intf *)0;
	Atm_addr_nsap		*anp;

	/*
	 * Get an ATMARP interface block
	 */
	aip = (Atmarp_intf *)UM_ALLOC(sizeof(Atmarp_intf));
	if (!aip)
		atmarp_mem_err("atmarp_cfg_netif: sizeof(Atmarp_intf)");
	UM_ZERO(aip, sizeof(Atmarp_intf));

	/*
	 * Make sure we're configuring a valid
	 * network interface
	 */
	rc = verify_nif_name(netif);
	if (rc == 0) {
		fprintf(stderr, "%s: \"%s\" is not a valid network interface\n",
				prog, netif);
		rc = EINVAL;
		goto cfg_fail;
	} else if (rc < 0) {
		rc = errno;
		fprintf(stderr, "%s: can't verify network interface \"%s\"\n",
				prog, netif);
		goto cfg_fail;
	}

	/*
	 * Update the interface entry
	 */
	strcpy(aip->ai_intf, netif);
	aip->ai_state = AI_STATE_NULL;
	aip->ai_scsp_sock = -1;
	LINK2TAIL(aip, Atmarp_intf, atmarp_intf_head, ai_next);

	return(0);

cfg_fail:
	if (aip)
		UM_FREE(aip);

	return(rc);
}
