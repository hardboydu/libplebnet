/*-
 * Copyright (c) 1999 Michael Smith
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
 *	$FreeBSD$
 */

/*
 * We could actually use all 33 segments, but using only 32 means that
 * each scatter/gather map is 256 bytes in size, and thus we don't have to worry about
 * maps crossing page boundaries.
 */
#define	MLX_NSEG	32		/* max scatter/gather segments we use */
#define MLX_NSLOTS	256		/* max number of command slots */

#define MLX_MAXDRIVES	32

/*
 * Structure describing a System Drive as attached to the controller.
 */
struct mlx_sysdrive 
{
    /* from MLX_CMD_ENQSYSDRIVE */
    u_int32_t		ms_size;
    int			ms_state;
    int			ms_raidlevel;

    /* synthetic geometry */
    int			ms_cylinders;
    int			ms_heads;
    int			ms_sectors;

    /* handle for attached driver */
    device_t		ms_disk;
};

/*
 * Per-command control structure.
 */
struct mlx_command 
{
    TAILQ_ENTRY(mlx_command)	mc_link;	/* list linkage */

    struct mlx_softc		*mc_sc;		/* controller that owns us */
    u_int8_t			mc_slot;	/* command slot we occupy */
    u_int16_t			mc_status;	/* command completion status */
    time_t			mc_timeout;	/* when this command expires */
    u_int8_t			mc_mailbox[16];	/* command mailbox */
    u_int32_t			mc_sgphys;	/* physical address of s/g array in controller space */
    int				mc_nsgent;	/* number of entries in s/g map */
    int				mc_flags;
#define MLX_CMD_DATAIN		(1<<0)
#define MLX_CMD_DATAOUT		(1<<1)
#define MLX_CMD_PRIORITY	(1<<2)		/* high-priority command */

    void			*mc_data;	/* data buffer */
    size_t			mc_length;
    bus_dmamap_t		mc_dmamap;	/* DMA map for data */
    u_int32_t			mc_dataphys;	/* data buffer base address controller space */

    void			(* mc_complete)(struct mlx_command *mc);	/* completion handler */
    void			*mc_private;	/* submitter-private data or wait channel */
};

/*
 * Per-controller structure.
 */
struct mlx_softc 
{
    /* bus connections */
    device_t		mlx_dev;
    struct resource	*mlx_mem;	/* mailbox interface window */
    bus_space_handle_t	mlx_bhandle;	/* bus space handle */
    bus_space_tag_t	mlx_btag;	/* bus space tag */
    bus_dma_tag_t	mlx_parent_dmat;/* parent DMA tag */
    bus_dma_tag_t	mlx_buffer_dmat;/* data buffer DMA tag */
    struct resource	*mlx_irq;	/* interrupt */
    void		*mlx_intr;	/* interrupt handle */

    /* scatter/gather lists and their controller-visible mappings */
    struct mlx_sgentry	*mlx_sgtable;	/* s/g lists */
    u_int32_t		mlx_sgbusaddr;	/* s/g table base address in bus space */
    bus_dma_tag_t	mlx_sg_dmat;	/* s/g buffer DMA tag */
    bus_dmamap_t	mlx_sg_dmamap;	/* map for s/g buffers */
    
    /* controller limits and features */
    int			mlx_hwid;	/* hardware identifier */
    int			mlx_maxiop;	/* maximum number of I/O operations */
    int			mlx_nchan;	/* number of active channels */
    int			mlx_maxiosize;	/* largest I/O for this controller */
    int			mlx_maxtarg;	/* maximum number of targets per channel */
    int			mlx_maxtags;	/* maximum number of tags per device */
    int			mlx_scsicap;	/* SCSI capabilities */
    int			mlx_feature;	/* controller features/quirks */
#define MLX_FEAT_PAUSEWORKS	(1<<0)	/* channel pause works as expected */

    /* controller queues and arrays */
    TAILQ_HEAD(, mlx_command)	mlx_freecmds;		/* command structures available for reuse */
    TAILQ_HEAD(, mlx_command)	mlx_work;		/* active commands */
    struct mlx_command	*mlx_busycmd[MLX_NSLOTS];	/* busy commands */
    int			mlx_busycmds;			/* count of busy commands */
    struct mlx_sysdrive	mlx_sysdrive[MLX_MAXDRIVES];	/* system drives */
    struct buf_queue_head mlx_bufq;			/* outstanding I/O operations */
    int			mlx_waitbufs;			/* number of bufs awaiting commands */

    /* controller status */
    u_int8_t		mlx_fwminor;	/* firmware revision */
    u_int8_t		mlx_fwmajor;
    int			mlx_geom;
#define MLX_GEOM_128_32		0	/* geoemetry translation modes */
#define MLX_GEOM_256_63		1
    int			mlx_state;
#define MLX_STATE_INTEN		(1<<0)	/* interrupts have been enabled */
#define MLX_STATE_SHUTDOWN	(1<<1)	/* controller is shut down */
#define MLX_STATE_OPEN		(1<<2)	/* control device is open */
#define MLX_STATE_SUSPEND	(1<<3)	/* controller is suspended */
    struct callout_handle mlx_timeout;	/* periodic status monitor */
    time_t		mlx_lastpoll;	/* last time_second we polled for status */
    u_int16_t		mlx_lastevent;	/* sequence number of the last event we recorded */
    u_int16_t		mlx_currevent;	/* sequence number last time we looked */
    int			mlx_polling;	/* if > 0, polling operations still running */
    int			mlx_rebuild;	/* if >= 0, drive is being rebuilt */
    u_int32_t		mlx_rebuildstat;/* blocks left to rebuild if active */
    int			mlx_check;	/* if >= 0, drive is being checked */
    struct mlx_pause	mlx_pause;	/* pending pause operation details */

    int			mlx_locks;	/* reentrancy avoidance */

    /* interface-specific accessor functions */
    int			mlx_iftype;	/* interface protocol */
#define MLX_IFTYPE_3	3
#define MLX_IFTYPE_4	4
#define MLX_IFTYPE_5	5
    int			(* mlx_tryqueue)(struct mlx_softc *sc, struct mlx_command *mc);
    int			(* mlx_findcomplete)(struct mlx_softc *sc, u_int8_t *slot, u_int16_t *status);
    void		(* mlx_intaction)(struct mlx_softc *sc, int action);
#define MLX_INTACTION_DISABLE		0
#define MLX_INTACTION_ENABLE		1
};

/*
 * Simple (stupid) locks.
 *
 * Note that these are designed to avoid reentrancy, not concurrency, and will
 * need to be replaced with something better.
 */
#define MLX_LOCK_COMPLETING	(1<<0)
#define MLX_LOCK_STARTING	(1<<1)

static __inline int
mlx_lock_tas(struct mlx_softc *sc, int lock)
{
    if ((sc)->mlx_locks & (lock))
	return(1);
    atomic_set_int(&sc->mlx_locks, lock);
    return(0);
}

static __inline void
mlx_lock_clr(struct mlx_softc *sc, int lock)
{
    atomic_clear_int(&sc->mlx_locks, lock);
}

/*
 * Interface between bus connections and driver core.
 */
extern void		mlx_free(struct mlx_softc *sc);
extern int		mlx_attach(struct mlx_softc *sc);
extern void		mlx_startup(struct mlx_softc *sc);
extern void		mlx_intr(void *data);
extern int		mlx_detach(device_t dev);
extern int		mlx_shutdown(device_t dev);
extern int		mlx_suspend(device_t dev); 
extern int		mlx_resume(device_t dev);
extern d_open_t		mlx_open;
extern d_close_t	mlx_close;
extern d_ioctl_t	mlx_ioctl;

extern devclass_t	mlx_devclass;

/*
 * Mylex System Disk driver
 */
struct mlxd_softc 
{
    device_t		mlxd_dev;
    struct mlx_softc	*mlxd_controller;
    struct mlx_sysdrive	*mlxd_drive;
    struct disk		mlxd_disk;
    struct devstat	mlxd_stats;
    struct disklabel	mlxd_label;
    int			mlxd_unit;
    int			mlxd_flags;
#define MLXD_OPEN	(1<<0)		/* drive is open (can't shut down) */
};

/*
 * Interface between driver core and disk driver (should be using a bus?)
 */
extern int	mlx_submit_buf(struct mlx_softc *sc, struct buf *bp);
extern int	mlx_submit_ioctl(struct mlx_softc *sc, struct mlx_sysdrive *drive, u_long cmd, 
				 caddr_t addr, int32_t flag, struct proc *p);
extern void	mlxd_intr(void *data);


