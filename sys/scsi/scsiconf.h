/*
 * Written by Julian Elischer (julian@tfs.com)
 * for TRW Financial Systems for use under the MACH(2.5) operating system.
 *
 * TRW Financial Systems, in accordance with their agreement with Carnegie
 * Mellon University, makes this software available to CMU to distribute
 * or use in any manner that they see fit as long as this message is kept with
 * the software. For this reason TFS also grants any other persons or
 * organisations permission to use or modify this software.
 *
 * TFS supplies this software to be publicly redistributed
 * on the understanding that TFS is not responsible for the correct
 * functioning of this software in any circumstances.
 *
 * Ported to run under 386BSD by Julian Elischer (julian@tfs.com) Sept 1992
 *
 *	$Id: scsiconf.h,v 1.11 1994/10/19 01:20:44 wollman Exp $
 */
#ifndef	SCSI_SCSICONF_H
#define SCSI_SCSICONF_H 1
typedef	int			boolean;
typedef	int			errval;
typedef	long int		int32;
typedef	short int		int16;
typedef	char 			int8;
typedef	unsigned long int	u_int32;
typedef	unsigned short int	u_int16;
typedef	unsigned char 		u_int8;

#include <scsi/scsi_debug.h>

/*
 * The following documentation tries to describe the relationship between the
 * various structures defined in this file:
 *
 * each adapter type has a scsi_adapter struct. This describes the adapter and
 *    identifies routines that can be called to use the adapter.
 * each device type has a scsi_device struct. This describes the device and
 *    identifies routines that can be called to use the device.
 * each existing device position (scsibus + target + lun)
 *    can be described by a scsi_link struct.
 *    Only scsi positions that actually have devices, have a scsi_link
 *    structure assigned. so in effect each device has scsi_link struct.
 *    The scsi_link structure contains information identifying both the
 *    device driver and the adapter driver for that position on that scsi bus,
 *    and can be said to 'link' the two.
 * each individual scsi bus has an array that points to all the scsi_link
 *    structs associated with that scsi bus. Slots with no device have
 *    a NULL pointer.
 * each individual device also knows the address of it's own scsi_link
 *    structure.
 *
 *				-------------
 *
 * The key to all this is the scsi_link structure which associates all the 
 * other structures with each other in the correct configuration.  The
 * scsi_link is the connecting information that allows each part of the 
 * scsi system to find the associated other parts.
 */


/*
 * These entrypoints are called by the high-end drivers to get services from
 * whatever low-end drivers they are attached to each adapter type has one of
 * these statically allocated.
 */
struct scsi_adapter
{
/* 04*/	int32		(*scsi_cmd)();
/* 08*/	void		(*scsi_minphys)();
/* 12*/	int32		(*open_target_lu)();
/* 16*/	int32		(*close_target_lu)();
/* 20*/	u_int32		(*adapter_info)(); /* see definitions below */
/* 24*/	char		*name; /* name of scsi bus controller */
/* 32*/	u_long	spare[2];
};

/*
 * return values for scsi_cmd()
 */
#define SUCCESSFULLY_QUEUED	0
#define TRY_AGAIN_LATER		1
#define	COMPLETE		2
#define	HAD_ERROR		3 /* do not use this, use COMPLETE */
#define	ESCAPE_NOT_SUPPORTED	4

/*
 * Format of adapter_info() response data
 * e.g. maximum number of entries queuable to a device by the adapter
 */
#define	AD_INF_MAX_CMDS		0x000000FF
/* 24 bits of other adapter characteristics go here */

/*
 * These entry points are called by the low-end drivers to get services from
 * whatever high-end drivers they are attached to.  Each device type has one
 * of these statically allocated.
 */
struct scsi_device
{
/*  4*/	errval	(*err_handler)(); /* returns -1 to say err processing complete */
/*  8*/	void	(*start)();
/* 12*/	int32	(*async)();
/* 16*/	int32	(*done)();	/* returns -1 to say done processing complete */
/* 20*/	char	*name;		/* name of device type */
/* 24*/	u_int32 flags;		/* device type dependent flags */
/* 32*/	int32	spare[2];
};

#ifdef NEW_SCSICONF
/*
 * Define various devices that we know mis-behave in some way,
 * and note how they are bad, so we can correct for them
 */
struct st_mode {
/*  4*/	u_int32 blksiz;
/*  6*/	u_int16 quirks;		/* same definitions as in XXX */
/*  7*/	char    density;
/*  8*/	char    spare[1];
};

typedef struct st_mode st_modes[4];

/* define behaviour codes (quirks) */
/* common to all SCSI devices */
#define SCSI_Q_NO_SYNC		0x8000
#define SCSI_Q_NO_FAST		0x4000
#define SCSI_Q_NO_WIDE		0x2000

/* tape specific ST_Q_* */
#define ST_Q_NEEDS_PAGE_0	0x0001
#define ST_Q_FORCE_FIXED_MODE	0x0002
#define ST_Q_FORCE_VAR_MODE	0x0004
#define ST_Q_SNS_HLP		0x0008	/* must do READ for good MODE SENSE */
#define ST_Q_IGNORE_LOADS	0x0010
#define ST_Q_BLKSIZ		0x0020	/* variable-block media_blksiz > 0 */
#define ST_Q_CC_NOMSG		0x0040	/* no messages accepted in CC state */

#define ST_Q_NO_SYNC		SCSI_Q_NO_SYNC
#define ST_Q_NO_FAST		SCSI_Q_NO_FAST
#define ST_Q_NO_WIDE		SCSI_Q_NO_WIDE

/* disk specific SD_Q_* */
#define SD_Q_NO_TAGS		0x0001

#define SD_Q_NO_SYNC		SCSI_Q_NO_SYNC
#define SD_Q_NO_FAST		SCSI_Q_NO_FAST
#define SD_Q_NO_WIDE		SCSI_Q_NO_WIDE

#endif

/*
 * This structure describes the connection between an adapter driver and
 * a device driver, and is used by each to call services provided by
 * the other, and to allow generic scsi glue code to call these services
 * as well.
 */
struct scsi_link
{
/*  1*/	u_int8	target;			/* targ of this dev */
/*  2*/	u_int8	lun;			/* lun of this dev */
/*  3*/	u_int8	adapter_targ;		/* what are we on the scsi bus */
/*  4*/	u_int8	adapter_unit;		/* e.g. the 0 in aha0 */
/*  5*/	u_int8	scsibus;		/* the Nth scsibus	*/
/*  6*/	u_int8	dev_unit;		/* e.g. the 0 in sd0 */
/*  7*/	u_int8	opennings;		/* available operations */
/*  8*/	u_int8	active;			/* operations in progress */
/* 10*/	u_int16	flags;			/* flags that all devices have */
/* 12*/	u_int16	quirks;			/* device specific quirks */
/* 16*/	struct	scsi_adapter *adapter;	/* adapter entry points etc. */
/* 20*/	struct	scsi_device *device;	/* device entry points etc. */
/* 24*/	struct	scsi_xfer *active_xs;	/* operations under way */
/* 28*/	void *	fordriver;		/* for private use by the driver */
/* 32*/	void *  devmodes;		/* device specific mode tables */
};
#define	SDEV_MEDIA_LOADED 	0x01	/* device figures are still valid */
#define	SDEV_WAITING	 	0x02	/* a process is waiting for this */
#define	SDEV_OPEN	 	0x04	/* at least 1 open session */
#define SDEV_BOUNCE		0x08	/* unit requires DMA bounce buffer */
#define	SDEV_DBX		0xF0	/* debuging flags (scsi_debug.h) */	

/*
 * One of these is allocated and filled in for each scsi bus.
 * it holds pointers to allow the scsi bus to get to the driver
 * That is running each LUN on the bus
 * it also has a template entry which is the prototype struct
 * supplied by the adapter driver, this is used to initialise
 * the others, before they have the rest of the fields filled in
 */
struct scsibus_data {
	struct scsi_link *adapter_link;		/* prototype supplied by adapter */
	struct scsi_link *sc_link[8][8];
};

/*
 * Each scsi transaction is fully described by one of these structures
 * It includes information about the source of the command and also the
 * device and adapter for which the command is destined.
 * (via the scsi_link structure)						*
 */
struct scsi_xfer
{
/*04*/	struct	scsi_xfer *next;	/* when free */
/*08*/	u_int32	flags;
/*12*/	struct	scsi_link *sc_link;	/* all about our device and adapter */
/*13*/	u_int8	retries;		/* the number of times to retry */
/*16*/	u_int8	spare[3];
/*20*/	int32	timeout;		/* in milliseconds */
/*24*/	struct	scsi_generic *cmd;	/* The scsi command to execute */
/*28*/	int32	cmdlen;			/* how long it is */
/*32*/	u_char	*data;			/* dma address OR a uio address */
/*36*/	int32	datalen;		/* data len (blank if uio)    */
/*40*/	int32	resid;			/* how much buffer was not touched */
/*44*/	int32	error;			/* an error value	*/
/*48*/	struct	buf *bp;		/* If we need to associate with a buf */
/*80*/	struct	scsi_sense_data	sense; /* 32 bytes*/
	/*
	 * Believe it or not, Some targets fall on the ground with
	 * anything but a certain sense length.
	 */
/*84*/	int32 req_sense_length;		/* Explicit request sense length */
/*88*/	int32 status;			/* SCSI status */
/*100*/	struct	scsi_generic cmdstore;	/* stash the command in here */
};

/*
 * Per-request Flag values
 */
#define	SCSI_NOSLEEP	0x01	/* Not a user... don't sleep		*/
#define	SCSI_NOMASK	0x02	/* dont allow interrupts.. booting	*/
#define	SCSI_NOSTART	0x04	/* left over from ancient history	*/
#define	SCSI_USER	0x08	/* Is a user cmd, call scsi_user_done	*/
#define	ITSDONE		0x10	/* the transfer is as done as it gets	*/
#define	INUSE		0x20	/* The scsi_xfer block is in use	*/
#define	SCSI_SILENT	0x40	/* Don't report errors to console	*/
#define SCSI_ERR_OK	0x80	/* An error on this operation is OK.	*/
#define	SCSI_RESET	0x100	/* Reset the device in question		*/
#define	SCSI_DATA_UIO	0x200	/* The data address refers to a UIO	*/
#define	SCSI_DATA_IN	0x400	/* expect data to come INTO memory	*/
#define	SCSI_DATA_OUT	0x800	/* expect data to flow OUT of memory	*/
#define	SCSI_TARGET	0x1000	/* This defines a TARGET mode op.	*/
#define	SCSI_ESCAPE	0x2000	/* Escape operation			*/

/*
 * Escape op codes.  This provides an extensible setup for operations
 * that are not scsi commands.  They are intended for modal operations.
 */

#define SCSI_OP_TARGET	0x0001
#define	SCSI_OP_RESET	0x0002
#define	SCSI_OP_BDINFO	0x0003

/*
 * Error values an adapter driver may return
 */
#define XS_NOERROR	0x0	/* there is no error, (sense is invalid)  */
#define XS_SENSE	0x1	/* Check the returned sense for the error */
#define	XS_DRIVER_STUFFUP 0x2	/* Driver failed to perform operation	  */
#define XS_TIMEOUT	0x03	/* The device timed out.. turned off?	  */
#define XS_SWTIMEOUT	0x04	/* The Timeout reported was caught by SW  */
#define XS_BUSY		0x08	/* The device busy, try again later?	  */

#ifdef KERNEL
void scsi_attachdevs __P((struct scsi_link *sc_link_proto));
struct scsi_xfer *get_xs( struct scsi_link *sc_link, u_int32 flags);
void free_xs(struct scsi_xfer *xs, struct scsi_link *sc_link,u_int32 flags);
u_int32 scsi_size( struct scsi_link *sc_link,u_int32 flags);
errval scsi_test_unit_ready( struct scsi_link *sc_link, u_int32 flags);
errval scsi_change_def( struct scsi_link *sc_link, u_int32 flags);
errval scsi_inquire( struct scsi_link *sc_link,
			struct scsi_inquiry_data *inqbuf, u_int32 flags);
errval scsi_prevent( struct scsi_link *sc_link, u_int32 type,u_int32 flags);
errval scsi_start_unit( struct scsi_link *sc_link, u_int32 flags);
void scsi_done(struct scsi_xfer *xs);
errval scsi_scsi_cmd( struct scsi_link *sc_link, struct scsi_generic *scsi_cmd,
			u_int32 cmdlen, u_char *data_addr,
			u_int32 datalen, u_int32 retries,
			u_int32 timeout, struct buf *bp,
			u_int32 flags);
errval	scsi_do_ioctl __P((struct scsi_link *sc_link, int cmd, caddr_t addr, int f));

void show_scsi_xs(struct scsi_xfer *xs);
void show_scsi_cmd(struct scsi_xfer *xs);
void show_mem(unsigned char * , u_int32);

void	lto3b __P((int val, u_char *bytes));
int	_3btol __P((u_char *bytes));

extern void sc_print_addr(struct scsi_link *);

extern int scsi_externalize(struct scsi_link *, void *, size_t *);
extern int scsi_internalize(struct scsi_link *, void **, size_t *);

#endif

#define SCSI_EXTERNALLEN (sizeof(struct scsi_link))

#ifdef NEW_SCSICONF
/**********************************************************************
			from the scsi2 spec
                Value Tracks Density(bpi) Code Type  Reference     Note
                0x1     9       800       NRZI  R    X3.22-1983    2
                0x2     9      1600       PE    R    X3.39-1986    2
                0x3     9      6250       GCR   R    X3.54-1986    2
                0x5    4/9     8000       GCR   C    X3.136-1986   1
                0x6     9      3200       PE    R    X3.157-1987   2
                0x7     4      6400       IMFM  C    X3.116-1986   1
                0x8     4      8000       GCR   CS   X3.158-1986   1
                0x9    18     37871       GCR   C    X3B5/87-099   2
                0xA    22      6667       MFM   C    X3B5/86-199   1
                0xB     4      1600       PE    C    X3.56-1986    1
                0xC    24     12690       GCR   C    HI-TC1        1,5
                0xD    24     25380       GCR   C    HI-TC2        1,5
                0xF    15     10000       GCR   C    QIC-120       1,5
                0x10   18     10000       GCR   C    QIC-150       1,5
                0x11   26     16000       GCR   C    QIC-320(525?) 1,5
                0x12   30     51667       RLL   C    QIC-1350      1,5
                0x13    1     61000       DDS   CS    X3B5/88-185A 4
                0x14    1     43245       RLL   CS    X3.202-1991  4
                0x15    1     45434       RLL   CS    ECMA TC17    4
                0x16   48     10000       MFM   C     X3.193-1990  1
                0x17   48     42500       MFM   C     X3B5/91-174  1

                where Code means:
                NRZI Non Return to Zero, change on ones
                GCR  Group Code Recording
                PE   Phase Encoded
                IMFM Inverted Modified Frequency Modulation
                MFM  Modified Frequency Modulation
                DDS  Dat Data Storage
                RLL  Run Length Encoding

                where Type means:
                R    Real-to-Real
                C    Cartridge
                CS   cassette

                where Notes means:
                1    Serial Recorded
                2    Parallel Recorded
                3    Old format know as QIC-11
                4    Helical Scan
                5    Not ANSI standard, rather industry standard.

********************************************************************/

#define	HALFINCH_800	0x01
#define	HALFINCH_1600	0x02
#define	HALFINCH_6250	0x03
#define	QIC_11		0x04	/* from Archive 150S Theory of Op. XXX	*/
#define QIC_24		0x05	/* may be bad, works for CIPHER ST150S XXX */
#define QIC_120		0x0f
#define QIC_150		0x10
#define QIC_320		0x11
#define QIC_525		0x11
#define QIC_1320	0x12
#define DDS		0x13
#define DAT_1		0x13
#endif /* NEW_SCSICONF */

#endif /*SCSI_SCSICONF_H*/
/* END OF FILE */
