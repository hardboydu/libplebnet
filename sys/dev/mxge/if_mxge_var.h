/*******************************************************************************

Copyright (c) 2006, Myricom Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

 3. Neither the name of the Myricom Inc, nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

$FreeBSD$

***************************************************************************/

#define MXGE_MAX_ETHER_MTU 9014

#define MXGE_ETH_STOPPED 0
#define MXGE_ETH_STOPPING 1
#define MXGE_ETH_STARTING 2
#define MXGE_ETH_RUNNING 3
#define MXGE_ETH_OPEN_FAILED 4

#define MXGE_FW_OFFSET 1024*1024
#define MXGE_EEPROM_STRINGS_SIZE 256
#define MXGE_MAX_SEND_DESC 64 /* should be large enough for
				 any TSO packet */

typedef struct {
	void *addr;
	bus_addr_t bus_addr;
	bus_dma_tag_t dmat;
	bus_dmamap_t map;
} mxge_dma_t;


typedef struct {
	mcp_slot_t *entry;
	mxge_dma_t dma;
	int cnt;
	int idx;
} mxge_rx_done_t;

typedef struct
{
  uint32_t data0;
  uint32_t data1;
  uint32_t data2;
} mxge_cmd_t;

struct mxge_rx_buffer_state {
	struct mbuf *m;
	bus_dmamap_t map;
};

struct mxge_tx_buffer_state {
	struct mbuf *m;
	bus_dmamap_t map;
	int flag;
};

typedef struct
{
	volatile mcp_kreq_ether_recv_t *lanai;	/* lanai ptr for recv ring */
	volatile uint8_t *wc_fifo;	/* w/c rx dma addr fifo address */
	mcp_kreq_ether_recv_t *shadow;	/* host shadow of recv ring */
	struct mxge_rx_buffer_state *info;
	bus_dma_tag_t dmat;
	bus_dmamap_t extra_map;
	int cnt;
	int alloc_fail;
	int mask;			/* number of rx slots -1 */
} mxge_rx_buf_t;

typedef struct
{
	volatile mcp_kreq_ether_send_t *lanai;	/* lanai ptr for sendq	*/
	volatile uint8_t *wc_fifo;		/* w/c send fifo address */
	mcp_kreq_ether_send_t *req_list;	/* host shadow of sendq */
	char *req_bytes;
	bus_dma_segment_t *seg_list;
	struct mxge_tx_buffer_state *info;
	bus_dma_tag_t dmat;
	int req;			/* transmits submitted	*/
	int mask;			/* number of transmit slots -1 */
	int done;			/* transmits completed	*/
	int pkt_done;			/* packets completed */
	int boundary;			/* boundary transmits cannot cross*/

} mxge_tx_buf_t;

typedef struct {
	struct ifnet* ifp;
	int big_bytes;
	struct mtx tx_lock;
	int csum_flag;			/* rx_csums? 		*/
	uint8_t	mac_addr[6];		/* eeprom mac address */
	mxge_tx_buf_t tx;	/* transmit ring 	*/
	mxge_rx_buf_t rx_small;
	mxge_rx_buf_t rx_big;
	mxge_rx_done_t rx_done;
	mcp_irq_data_t *fw_stats;
	bus_dma_tag_t	parent_dmat;
	volatile uint8_t *sram;
	int sram_size;
	volatile uint32_t *irq_deassert;
	volatile uint32_t *irq_claim;
	mcp_cmd_response_t *cmd;
	mxge_dma_t cmd_dma;
	mxge_dma_t zeropad_dma;
	mxge_dma_t fw_stats_dma;
	struct pci_dev *pdev;
	int msi_enabled;
	int link_state;
	unsigned int rdma_tags_available;
	int intr_coal_delay;
	volatile uint32_t *intr_coal_delay_ptr;
	int wc;
	struct mtx cmd_lock;
	struct sx driver_lock;
	int wake_queue;
	int stop_queue;
	int down_cnt;
	int watchdog_resets;
	int tx_defragged;
	int pause;
	struct resource *mem_res;
	struct resource *irq_res;
	void *ih; 
	char *fw_name;
	char eeprom_strings[MXGE_EEPROM_STRINGS_SIZE];
	char fw_version[128];
	device_t dev;
	struct ifmedia media;
	int read_dma;
	int write_dma;
	int read_write_dma;
	char *mac_addr_string;
	char product_code_string[64];
	char serial_number_string[64];
	char scratch[256];
} mxge_softc_t;

#define MXGE_PCI_VENDOR_MYRICOM 	0x14c1
#define MXGE_PCI_DEVICE_Z8E 	0x0008

#define MXGE_HIGHPART_TO_U32(X) \
(sizeof (X) == 8) ? ((uint32_t)((uint64_t)(X) >> 32)) : (0)
#define MXGE_LOWPART_TO_U32(X) ((uint32_t)(X))


/* implement our own memory barriers, since bus_space_barrier
   cannot handle write-combining regions */

#if defined (__GNUC__)
  #if #cpu(i386) || defined __i386 || defined i386 || defined __i386__ || #cpu(x86_64) || defined __x86_64__
    #define mb()  __asm__ __volatile__ ("sfence;": : :"memory")
  #elif #cpu(sparc64) || defined sparc64 || defined __sparcv9 
    #define mb()  __asm__ __volatile__ ("membar #MemIssue": : :"memory")
  #elif #cpu(sparc) || defined sparc || defined __sparc__
    #define mb()  __asm__ __volatile__ ("stbar;": : :"memory")
  #else
    #define mb() 	/* XXX just to make this compile */
  #endif
#else
  #error "unknown compiler"
#endif

static inline void
mxge_pio_copy(volatile void *to_v, void *from_v, size_t size)
{
  register volatile uintptr_t *to;
  volatile uintptr_t *from;
  size_t i;

  to = (volatile uintptr_t *) to_v;
  from = from_v;
  for (i = (size / sizeof (uintptr_t)); i; i--) {
	  *to = *from;
	  to++;
	  from++;
  }

}


/*
  This file uses Myri10GE driver indentation.

  Local Variables:
  c-file-style:"linux"
  tab-width:8
  End:
*/
