/*
 * Driver for a device we can't identify.
 * by Julian Elischer (julian@tfs.com)
 *
 *      $Id: uk.c,v 1.8 1995/03/04 20:51:08 dufault Exp $
 *
 * If you find that you are adding any code to this file look closely
 * at putting it in "scsi_driver.c" instead.
 */

#include <sys/param.h>
#include <scsi/scsi_all.h>
#include <scsi/scsiconf.h>

SCSI_DEVICE_ENTRIES(uk)

struct scsi_device uk_switch =
{
    NULL,
    NULL,
    NULL,
    NULL,
    "uk",
    0,
	{0, 0},
	SDEV_ONCE_ONLY,	/* Only one open allowed */
	0,
	"Unknown",
	ukopen,
    0,
	T_UNKNOWN,
	0,
	0,
	0,
	0,
	0,
	0,
};
