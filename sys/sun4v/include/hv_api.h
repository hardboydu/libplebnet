/*-
 * Copyright (c) 2006 Kip Macy
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
 * $FreeBSD$
 */

#ifndef _MACHINE_HV_API_H
#define	_MACHINE_HV_API_H

typedef uint64_t devhandle_t;
typedef uint64_t pci_device_t;
typedef uint32_t pci_config_offset_t;
typedef uint8_t pci_config_size_t;

typedef uint64_t tsbid_t;
typedef uint32_t pages_t;
typedef enum io_attributes {
	PCI_MAP_ATTR_READ	= (uint32_t)0x01,
	PCI_MAP_ATTR_WRITE	= (uint32_t)0x02,
} io_attributes_t;
typedef enum io_sync_direction {
	IO_SYNC_DEVICE		= (uint32_t)0x01,
	IO_SYNC_CPU		= (uint32_t)0x02,
} io_sync_direction_t;
typedef uint64_t io_page_list_t;
typedef uint64_t r_addr_t;
typedef uint64_t io_addr_t;

/*
 * Section 10 Domain Services
 */

extern uint64_t hv_mach_desc(uint64_t buffer_ra, uint64_t *buffer_sizep);
extern uint64_t hv_mach_watchdog(uint64_t timeout, uint64_t *time_remaining);

/*
 * Section 11 CPU Services
 */

/*
 * Section 12 MMU Services
 */
/*
 * TSB description structure for MMU_TSB_CTX0 and MMU_TSB_CTXNON0.
 */
typedef struct hv_tsb_info {
	uint16_t	hti_idxpgsz;	/* page size used for index shift in TSB */
	uint16_t	hti_assoc;	/* associativity of TSB                  */
	uint32_t	hti_ntte;	/* size of TSB in TTEs                   */
	uint32_t	hti_ctx_index;  /* context index                         */
	uint32_t	hti_pgszs;	/* page size bitmasx                     */
	uint64_t	hti_ra;	        /* real address of TSB base              */
	uint64_t	hti_rsvd;	/* reserved                              */
} hv_tsb_info_t;


extern uint64_t	hv_mmu_tsb_ctx0(uint64_t, uint64_t);
extern uint64_t	hv_mmu_tsb_ctxnon0(uint64_t, uint64_t);

/*
 * Section 13 Cache and Memory Services
 */

/*
 * Section 14 Device Interrupt Services
 */

/*
 * Section 15 Time of Day Services
 */

extern uint64_t hv_tod_get(uint64_t *seconds);
extern uint64_t hv_tod_set(uint64_t);

/*
 * Section 16 Console Services
 */

extern int64_t hv_cons_putchar(uint8_t);
extern int64_t hv_cons_getchar(uint8_t *);
extern int64_t hv_cons_write(uint64_t buf_raddr, uint64_t size, uint64_t *nwritten);
extern int64_t hv_cons_read(uint64_t buf_raddr, uint64_t size, uint64_t *nread);

extern void hv_cnputs(char *);

/*
 * Section 17 Core Dump Services
 */

extern uint64_t hv_dump_buf_update(uint64_t, uint64_t, uint64_t *);


/*
 * Section 18 Trap Trace Services
 */

typedef struct trap_trace_entry {
	uint8_t		tte_type;	/* Hypervisor or guest entry. */
	uint8_t		tte_hpstat;	/* Hyper-privileged state. */
	uint8_t		tte_tl;		/* Trap level. */
	uint8_t		tte_gl;		/* Global register level. */
	uint16_t	tte_tt;		/* Trap type.*/
	uint16_t	tte_tag;	/* Extended trap identifier. */
	uint64_t	tte_tstate;	/* Trap state. */
	uint64_t	tte_tick;	/* Tick. */
	uint64_t	tte_tpc;	/* Trap PC. */
	uint64_t	tte_f1;		/* Entry specific. */
	uint64_t	tte_f2;		/* Entry specific. */
	uint64_t	tte_f3;		/* Entry specific. */
	uint64_t	tte_f4;		/* Entry specific. */
} trap_trace_entry_t;

extern uint64_t hv_ttrace_buf_info(uint64_t *, uint64_t *);
extern uint64_t hv_ttrace_buf_conf(uint64_t, uint64_t, uint64_t *);
extern uint64_t hv_ttrace_enable(uint64_t, uint64_t *);
extern uint64_t hv_ttrace_freeze(uint64_t, uint64_t *);
extern uint64_t hv_ttrace_addentry(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/*
 * Section 19 Logical Domain Channel Services
 *
 */
typedef struct ldc_state_info {
	uint64_t lsi_head_offset;
	uint64_t lsi_tail_offset;
	uint64_t lsi_channel_state;
} ldc_state_info_t;

#define LDC_CHANNEL_DOWN     0
#define LDC_CHANNEL_UP       1

extern uint64_t hv_ldc_tx_qconf(uint64_t ldc_id, uint64_t base_raddr, uint64_t nentries);
extern uint64_t hv_ldc_tx_qinfo(uint64_t ldc_id, uint64_t *base_raddr, uint64_t *nentries);
extern uint64_t hv_ldc_tx_get_state(uint64_t ldc_id, ldc_state_info_t *info); 
extern uint64_t hv_ldc_tx_set_qtail(uint64_t ldc_id, uint64_t tail_offset);
extern uint64_t hv_ldc_rx_get_state(uint64_t ldc_id, ldc_state_info_t *info); 
extern uint64_t hv_ldc_rx_qconf(uint64_t ldc_id, uint64_t base_raddr, uint64_t nentries);
extern uint64_t hv_ldc_rx_qinfo(uint64_t ldc_id, uint64_t *base_raddr, uint64_t *nentries);
extern uint64_t hv_ldc_rx_set_qhead(uint64_t ldc_id, uint64_t head_offset);


/*
 * Section 20 PCI I/O Services
 *
 */

extern uint64_t hv_pci_iommu_map(devhandle_t dh, uint64_t tsbid, uint64_t nttes, uint64_t io_attributes, 
				 vm_paddr_t io_page_list, pages_t *nttes_mapped);
extern uint64_t hv_pci_iommu_demap(devhandle_t dh, uint64_t tsbid, uint64_t nttes, pages_t *nttes_demapped);
extern uint64_t hv_pci_iommu_getmap(devhandle_t dh, uint64_t tsbid, uint64_t nttes, uint64_t *io_attributes, 
				    vm_paddr_t *ra);
extern uint64_t hv_pci_iommu_getbypass(devhandle_t dh, vm_paddr_t ra, uint64_t io_attributes, uint64_t *io_addr);
extern uint64_t hv_pci_config_get(devhandle_t dh, uint64_t pci_device, uint64_t pci_config_offset, uint64_t size,
				  uint64_t *error, uint64_t *data);
extern uint64_t hv_pci_config_put(devhandle_t dh, uint64_t pci_device, uint64_t pci_config_offset, uint64_t size,
				  uint64_t data, uint64_t *error_flag);
extern uint64_t hv_pci_peek(devhandle_t dh, vm_paddr_t ra, uint64_t size, uint64_t *error_flag, uint64_t *data);
extern uint64_t hv_pci_poke(devhandle_t dh, vm_paddr_t ra, uint64_t size, uint64_t data, uint64_t pci_device, 
			    uint64_t *error_flag);
extern uint64_t hv_pci_dma_sync(devhandle_t dh, vm_paddr_t ra, uint64_t size, uint64_t io_sync_direction, 
			    uint64_t *nsynced);


/*
 * Section 21 MSI Services
 *
 */

/*
 * Section 22 UltraSPARC T1 Performance Counters
 *
 */

/*
 * Section 23 UltraSPARC T1 MMU Statistics Counters
 *
 */

/*
 * Simulator Services
 */
extern void hv_magic_trap_on(void);
extern void hv_magic_trap_off(void);
extern int hv_sim_read(uint64_t offset, vm_paddr_t buffer_ra, uint64_t size);
extern int hv_sim_write(uint64_t offset, vm_paddr_t buffer_ra, uint64_t size);

#endif /* _MACHINE_HV_API_H */
