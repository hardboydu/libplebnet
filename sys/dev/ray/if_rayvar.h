/*
 * Copyright (C) 2000
 * Dr. Duncan McLennan Barclay, dmlb@ragnet.demon.co.uk.
 *
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
 * 3. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DUNCAN BARCLAY AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL DUNCAN BARCLAY OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: if_rayvar.h,v 1.3 2000/05/11 18:53:50 dmlb Exp $
 *
 */

/*
 * Network parameters, used twice in sotfc to store what we want and what
 * we have.
 */
struct ray_nw_param {
    struct ray_cmd_net	p_1;
    u_int8_t		np_ap_status;
    struct ray_net_params \
    			p_2;
    u_int8_t		np_countrycode;
};
#define np_upd_param	p_1.c_upd_param
#define	np_bss_id	p_1.c_bss_id
#define	np_inited	p_1.c_inited
#define	np_def_txrate	p_1.c_def_txrate
#define	np_encrypt	p_1.c_encrypt
#define np_net_type	p_2.p_net_type
#define np_ssid		p_2.p_ssid
#define np_priv_start	p_2.p_privacy_must_start
#define np_priv_join	p_2.p_privacy_can_join

/*
 * One of these structures per allocated device
 */
struct ray_softc {

    device_t dev;			/* Device */
    struct arpcom	arpcom;		/* Ethernet common 		*/
    struct ifmedia	ifmedia;	/* Ifnet common 		*/
    struct callout_handle
    			reset_timerh;	/* Handle for reset timer	*/
    struct callout_handle
    			tx_timerh;	/* Handle for tx timer	*/
    struct callout_handle
    			com_timerh;	/* Handle for command timer	*/

    bus_space_tag_t	am_bst;		/* Bus space tag for attribute memory */
    bus_space_handle_t	am_bsh;		/* Bus space handle for attribute mem */
    int			am_rid;		/* Resource id for attribute memory */
    struct resource*	am_res;		/* Resource for attribute memory */
    bus_space_tag_t	cm_bst;		/* Bus space tag for common memory */
    bus_space_handle_t	cm_bsh;		/* Bus space handle for common memory */
    int			cm_rid;		/* Resource id for common memory */
    struct resource*	cm_res;		/* Resource for common memory */
    int			irq_rid;	/* Resource id for irq */
    struct resource*	irq_res;	/* Resource for irq */
    void *		irq_handle;	/* Handle for irq handler */

    u_char		gone;		/* 1 = Card bailed out		*/

    int			framing;	/* Packet framing types		*/

    struct ray_ecf_startup_v5
    			sc_ecf_startup; /* Startup info from card	*/

    TAILQ_HEAD(ray_comq, ray_comq_entry) 
			sc_comq;	/* Command queue		*/

    struct ray_nw_param	sc_c;		/* current network params 	*/
    struct ray_nw_param sc_d;		/* desired network params	*/
    int			sc_havenet;	/* true if we have a network	*/
    int			sc_promisc;	/* current set value		*/
    u_int8_t		sc_ccsinuse[64];/* ccss' in use -- not for tx	*/

    int			sc_checkcounters;
    u_int64_t		sc_rxoverflow;	/* Number of rx overflows	*/
    u_int64_t		sc_rxcksum;	/* Number of checksum errors	*/
    u_int64_t		sc_rxhcksum;	/* Number of header checksum errors */
    u_int8_t		sc_rxnoise;	/* Average receiver level	*/
    struct ray_siglev	sc_siglevs[RAY_NSIGLEVRECS]; /* Antenna/levels	*/
};

#define	sc_station_addr	sc_ecf_startup.e_station_addr
#define	sc_version	sc_ecf_startup.e_fw_build_string
#define	sc_tibsize	sc_ecf_startup.e_tibsize

/*
 * Command queue definitions
 */
typedef void (*ray_comqfn_t)(struct ray_softc *sc, struct ray_comq_entry *com);
MALLOC_DECLARE(M_RAYCOM);
MALLOC_DEFINE(M_RAYCOM, "raycom", "Raylink command queue entry");
struct ray_comq_entry {
	TAILQ_ENTRY(ray_comq_entry) c_chain;	/* Tail queue.		*/
	ray_comqfn_t	c_function;		/* Function to call */
	int		c_flags;		/* Flags		*/
	u_int8_t	c_retval;		/* Return value		*/
	void		*c_wakeup;		/* Sleeping on this	*/
	size_t		c_ccs;			/* CCS structure	*/
	struct ray_param_req
    			*c_pr;			/* MIB report/update	*/
#if RAY_DEBUG & RAY_DBG_COM
	char		*c_mesg;
#endif /* RAY_DEBUG & RAY_DBG_COM */
};

/*
 * Framing types
 */
/* XXX maybe better as part of the if structure? */
#define SC_FRAMING_WEBGEAR	0

/*
 * Macro's and constants
 */
static int mib_info[RAY_MIB_MAX+1][3] = RAY_MIB_INFO;

/* Indirections for reading/writing memory - from NetBSD/if_ray.c */
#ifndef offsetof
#define offsetof(type, member) \
    ((size_t)(&((type *)0)->member))
#endif /* offsetof */

#if RAY_NEED_CM_REMAPPING

#define ATTR_READ_1(sc, off) \
    ray_attr_read_1((sc), (off))

#define ATTR_WRITE_1(sc, off, val) \
    ray_attr_write_1((sc), (off), (val))

#else

#define ATTR_READ_1(sc, off) \
    ((u_int8_t)bus_space_read_1((sc)->am_bst, (sc)->am_bsh, (off)))

#define ATTR_WRITE_1(sc, off, val) \
    bus_space_write_1((sc)->am_bst, (sc)->am_bsh, (off), (val))

#endif /* RAY_NEED_CM_REMAPPING */

#define	SRAM_READ_1(sc, off) \
    ((u_int8_t)bus_space_read_1((sc)->cm_bst, (sc)->cm_bsh, (off)))

#define SRAM_READ_REGION(sc, off, p, n) \
    bus_space_read_region_1((sc)->cm_bst, (sc)->cm_bsh, (off), (void *)(p), (n))

#define	SRAM_READ_FIELD_1(sc, off, s, f) \
    SRAM_READ_1((sc), (off) + offsetof(struct s, f))

#define	SRAM_READ_FIELD_2(sc, off, s, f)			\
    ((((u_int16_t)SRAM_READ_1((sc), (off) + offsetof(struct s, f)) << 8) \
    |(SRAM_READ_1((sc), (off) + 1 + offsetof(struct s, f)))))

#define	SRAM_READ_FIELD_N(sc, off, s, f, p, n)	\
    SRAM_READ_REGION((sc), (off) + offsetof(struct s, f), (p), (n))

#define	SRAM_WRITE_1(sc, off, val)	\
    bus_space_write_1((sc)->cm_bst, (sc)->cm_bsh, (off), (val))

#define SRAM_WRITE_REGION(sc, off, p, n) \
    bus_space_write_region_1((sc)->cm_bst, (sc)->cm_bsh, (off), (void *)(p), (n))

#define	SRAM_WRITE_FIELD_1(sc, off, s, f, v) 	\
    SRAM_WRITE_1((sc), (off) + offsetof(struct s, f), (v))

#define	SRAM_WRITE_FIELD_2(sc, off, s, f, v) do {	\
    SRAM_WRITE_1((sc), (off) + offsetof(struct s, f), (((v) >> 8 ) & 0xff)); \
    SRAM_WRITE_1((sc), (off) + 1 + offsetof(struct s, f), ((v) & 0xff)); \
} while (0)

#define	SRAM_WRITE_FIELD_N(sc, off, s, f, p, n)	\
    SRAM_WRITE_REGION((sc), (off) + offsetof(struct s, f), (p), (n))

#define RAY_COM_FWOK		0x0001		/* Wakeup on completion	*/
#define RAY_COM_FRUNNING	0x0002		/* This one running	*/
#define RAY_COM_FCOMPLETED	0x0004		/* This one completed	*/
#define RAY_COM_FWAIT		0x0008		/* Do not run the queue */
#define RAY_COM_FLAGS_PRINTFB	\
	"\020"			\
	"\001WOK"		\
	"\002RUNNING"		\
	"\003COMPLETED"		\
	"\004WAIT"

#define RAY_COM_NEEDS_TIMO(cmd)	(		\
	 (cmd == RAY_CMD_DOWNLOAD_PARAMS) ||	\
	 (cmd == RAY_CMD_UPDATE_PARAMS) ||	\
	 (cmd == RAY_CMD_UPDATE_MCAST)		\
	)

#ifndef RAY_COM_TIMEOUT
#define RAY_COM_TIMEOUT		(hz / 2)
#endif

#ifndef RAY_RESET_TIMEOUT
#define RAY_RESET_TIMEOUT	(10 * hz)
#endif

#ifndef RAY_TX_TIMEOUT
#define RAY_TX_TIMEOUT		(hz / 2)
#endif

#define RAY_CCS_FREE(sc, ccs) \
    SRAM_WRITE_FIELD_1((sc), (ccs), ray_cmd, c_status, RAY_CCS_STATUS_FREE)

#define RAY_ECF_READY(sc) \
    (!(ATTR_READ_1((sc), RAY_ECFIR) & RAY_ECFIR_IRQ))

#define	RAY_ECF_START_CMD(sc)	ATTR_WRITE_1((sc), RAY_ECFIR, RAY_ECFIR_IRQ)

#define	RAY_HCS_CLEAR_INTR(sc)	ATTR_WRITE_1((sc), RAY_HCSIR, 0)

#define RAY_HCS_INTR(sc)	(ATTR_READ_1((sc), RAY_HCSIR) & RAY_HCSIR_IRQ)

#define RAY_PANIC(sc, fmt, args...) do {				\
    panic("ray%d: %s(%d) " fmt "\n", device_get_unit((sc)->dev),	\
	__FUNCTION__ , __LINE__ , ##args);				\
} while (0)

#define RAY_PRINTF(sc, fmt, args...) do {				\
    device_printf((sc)->dev, "%s(%d) " fmt "\n",			\
        __FUNCTION__ , __LINE__ , ##args);				\
} while (0)

#ifndef RAY_COM_MALLOC
#define RAY_COM_MALLOC(function, flags)	ray_com_malloc((function), (flags));
#endif /* RAY_COM_MALLOC */

#ifndef RAY_COM_CHECK
#define RAY_COM_CHECK(sc, com)
#endif /* RAY_COM_CHECK */

#ifndef RAY_COM_DUMP
#define RAY_COM_DUMP(sc, com, s)
#endif /* RAY_COM_DUMP */

#ifndef RAY_MBUF_DUMP
#define RAY_MBUF_DUMP(sc, mask, m, s)
#endif /* RAY_MBUF_DUMP */

/*
 * The driver assumes that the common memory is always mapped in,
 * for the moment we ensure this with the following macro at the
 * head of each function and by using functions to access attribute
 * memory. Hysterical raisins led to the non-"reflexive" approach.
 * Roll on NEWCARD and it can all die...
 */
#if RAY_NEED_CM_REMAPPING
#define	RAY_MAP_CM(sc)		ray_attr_mapcm(sc)
#else
#define RAY_MAP_CM(sc)
#endif /* RAY_NEED_CM_REMAPPING */