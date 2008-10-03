/*	$OpenBSD: if_nfereg.h,v 1.16 2006/02/22 19:23:44 damien Exp $	*/

/*-
 * Copyright (c) 2005 Jonathan Gray <jsg@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $FreeBSD$
 */

#define	NFE_RX_RING_COUNT	256
#define	NFE_JUMBO_RX_RING_COUNT	NFE_RX_RING_COUNT
#define	NFE_TX_RING_COUNT	256

#define	NFE_PROC_DEFAULT	((NFE_RX_RING_COUNT * 3) / 4)
#define	NFE_PROC_MIN		50
#define	NFE_PROC_MAX		(NFE_RX_RING_COUNT - 1)

#define	NFE_INC(x, y)	(x) = ((x) + 1) % y

/* RX/TX MAC addr + type + VLAN + align + slack */
#define	NFE_RX_HEADERS		64

/* Maximum MTU size. */
#define	NV_PKTLIMIT_1		ETH_DATA_LEN	/* Hard limit not known. */
#define	NV_PKTLIMIT_2		9100 /* Actual limit according to NVidia:9202 */

#define	NFE_JUMBO_FRAMELEN	NV_PKTLIMIT_2
#define	NFE_JUMBO_MTU		\
	(NFE_JUMBO_FRAMELEN - NFE_RX_HEADERS)
#define	NFE_MIN_FRAMELEN	(ETHER_MIN_LEN - ETHER_CRC_LEN)

#define	NFE_MAX_SCATTER		32
#define	NFE_TSO_MAXSGSIZE	4096
#define	NFE_TSO_MAXSIZE		(65535 + sizeof(struct ether_vlan_header))

#define	NFE_IRQ_STATUS		0x000
#define	NFE_IRQ_MASK		0x004
#define	NFE_SETUP_R6		0x008
#define	NFE_IMTIMER		0x00c
#define	NFE_MSI_MAP0		0x020
#define	NFE_MSI_MAP1		0x024
#define	NFE_MSI_IRQ_MASK	0x030
#define	NFE_MAC_RESET		0x03c
#define	NFE_MISC1		0x080
#define	NFE_TX_CTL		0x084
#define	NFE_TX_STATUS		0x088
#define	NFE_RXFILTER		0x08c
#define	NFE_RXBUFSZ		0x090
#define	NFE_RX_CTL		0x094
#define	NFE_RX_STATUS		0x098
#define	NFE_RNDSEED		0x09c
#define	NFE_SETUP_R1		0x0a0
#define	NFE_SETUP_R2		0x0a4
#define	NFE_MACADDR_HI		0x0a8
#define	NFE_MACADDR_LO		0x0ac
#define	NFE_MULTIADDR_HI	0x0b0
#define	NFE_MULTIADDR_LO	0x0b4
#define	NFE_MULTIMASK_HI	0x0b8
#define	NFE_MULTIMASK_LO	0x0bc
#define	NFE_PHY_IFACE		0x0c0
#define	NFE_TX_RING_ADDR_LO	0x100
#define	NFE_RX_RING_ADDR_LO	0x104
#define	NFE_RING_SIZE		0x108
#define	NFE_TX_UNK		0x10c
#define	NFE_LINKSPEED		0x110
#define	NFE_SETUP_R5		0x130
#define	NFE_SETUP_R3		0x13C
#define	NFE_SETUP_R7		0x140
#define	NFE_RXTX_CTL		0x144
#define	NFE_TX_RING_ADDR_HI	0x148
#define	NFE_RX_RING_ADDR_HI	0x14c
#define	NFE_TX_PAUSE_FRAME	0x170
#define	NFE_PHY_STATUS		0x180
#define	NFE_SETUP_R4		0x184
#define	NFE_STATUS		0x188
#define	NFE_PHY_SPEED		0x18c
#define	NFE_PHY_CTL		0x190
#define	NFE_PHY_DATA		0x194
#define	NFE_TX_UNICAST		0x1a0
#define	NFE_TX_MULTICAST	0x1a4
#define	NFE_TX_BROADCAST	0x1a8
#define	NFE_WOL_CTL		0x200
#define	NFE_PATTERN_CRC		0x204
#define	NFE_PATTERN_MASK	0x208
#define	NFE_PWR_CAP		0x268
#define	NFE_PWR_STATE		0x26c
#define	NFE_TX_OCTET		0x280
#define	NFE_TX_ZERO_REXMIT	0x284
#define	NFE_TX_ONE_REXMIT	0x288
#define	NFE_TX_MULTI_REXMIT	0x28c
#define	NFE_TX_LATE_COL		0x290
#define	NFE_TX_FIFO_UNDERUN	0x294
#define	NFE_TX_CARRIER_LOST	0x298
#define	NFE_TX_EXCESS_DEFERRAL	0x29c
#define	NFE_TX_RETRY_ERROR	0x2a0
#define	NFE_RX_FRAME_ERROR	0x2a4
#define	NFE_RX_EXTRA_BYTES	0x2a8
#define	NFE_RX_LATE_COL		0x2ac
#define	NFE_RX_RUNT		0x2b0
#define	NFE_RX_JUMBO		0x2b4
#define	NFE_RX_FIFO_OVERUN	0x2b8
#define	NFE_RX_CRC_ERROR	0x2bc
#define	NFE_RX_FAE		0x2c0
#define	NFE_RX_LEN_ERROR	0x2c4
#define	NFE_RX_UNICAST		0x2c8
#define	NFE_RX_MULTICAST	0x2cc
#define	NFE_RX_BROADCAST	0x2d0
#define	NFE_TX_DEFERAL		0x2d4
#define	NFE_TX_FRAME		0x2d8
#define	NFE_RX_OCTET		0x2dc
#define	NFE_TX_PAUSE		0x2e0
#define	NFE_RX_PAUSE		0x2e4
#define	NFE_RX_DROP		0x2e8
#define	NFE_VTAG_CTL		0x300
#define	NFE_MSIX_MAP0		0x3e0
#define	NFE_MSIX_MAP1		0x3e4
#define	NFE_MSIX_IRQ_STATUS	0x3f0
#define	NFE_PWR2_CTL		0x600

#define	NFE_MAC_RESET_MAGIC	0x00f3

#define	NFE_MAC_ADDR_INORDER	0x8000

#define	NFE_PHY_ERROR		0x00001
#define	NFE_PHY_WRITE		0x00400
#define	NFE_PHY_BUSY		0x08000
#define	NFE_PHYADD_SHIFT	5

#define	NFE_STATUS_MAGIC	0x140000

#define	NFE_R1_MAGIC_1000	0x14050f
#define	NFE_R1_MAGIC_10_100	0x16070f
#define	NFE_R1_MAGIC_DEFAULT	0x15050f
#define	NFE_R2_MAGIC		0x16
#define	NFE_R4_MAGIC		0x08
#define	NFE_R6_MAGIC		0x03
#define	NFE_WOL_MAGIC		0x1111
#define	NFE_RX_START		0x01
#define	NFE_TX_START		0x01

#define	NFE_IRQ_RXERR		0x0001
#define	NFE_IRQ_RX		0x0002
#define	NFE_IRQ_RX_NOBUF	0x0004
#define	NFE_IRQ_TXERR		0x0008
#define	NFE_IRQ_TX_DONE		0x0010
#define	NFE_IRQ_TIMER		0x0020
#define	NFE_IRQ_LINK		0x0040
#define	NFE_IRQ_TXERR2		0x0080
#define	NFE_IRQ_TX1		0x0100

#define	NFE_IRQ_WANTED							\
	(NFE_IRQ_RXERR | NFE_IRQ_RX_NOBUF | NFE_IRQ_RX |		\
	 NFE_IRQ_TXERR | NFE_IRQ_TXERR2 | NFE_IRQ_TX_DONE |		\
	 NFE_IRQ_LINK)

#define	NFE_RXTX_KICKTX		0x0001
#define	NFE_RXTX_BIT1		0x0002
#define	NFE_RXTX_BIT2		0x0004
#define	NFE_RXTX_RESET		0x0010
#define	NFE_RXTX_VTAG_STRIP	0x0040
#define	NFE_RXTX_VTAG_INSERT	0x0080
#define	NFE_RXTX_RXCSUM		0x0400
#define	NFE_RXTX_V2MAGIC	0x2100
#define	NFE_RXTX_V3MAGIC	0x2200
#define	NFE_RXFILTER_MAGIC	0x007f0000
#define	NFE_PFF_RX_PAUSE	(1 << 3)
#define	NFE_PFF_LOOPBACK	(1 << 4)
#define	NFE_PFF_U2M		(1 << 5)
#define	NFE_PFF_PROMISC		(1 << 7)
#define	NFE_CSUM_FEATURES	(CSUM_IP | CSUM_TCP | CSUM_UDP)

/* default interrupt moderation timer of 128us */
#define	NFE_IM_DEFAULT	((128 * 100) / 1024)

#define	NFE_VTAG_ENABLE		(1 << 13)

#define	NFE_PWR_VALID		(1 << 8)
#define	NFE_PWR_WAKEUP		(1 << 15)

#define	NFE_PWR2_WAKEUP_MASK	0x0f11
#define	NFE_PWR2_REVA3		(1 << 0)

#define	NFE_MEDIA_SET		0x10000
#define	NFE_MEDIA_1000T		0x00032
#define	NFE_MEDIA_100TX		0x00064
#define	NFE_MEDIA_10T		0x003e8

#define	NFE_PHY_100TX		(1 << 0)
#define	NFE_PHY_1000T		(1 << 1)
#define	NFE_PHY_HDX		(1 << 8)

#define	NFE_MISC1_MAGIC		0x003b0f3c
#define	NFE_MISC1_TX_PAUSE	(1 << 0)
#define	NFE_MISC1_HDX		(1 << 1)

#define	NFE_TX_PAUSE_FRAME_DISABLE	0x1ff0080
#define	NFE_TX_PAUSE_FRAME_ENABLE	0x0c00030

#define	NFE_SEED_MASK		0x0003ff00
#define	NFE_SEED_10T		0x00007f00
#define	NFE_SEED_100TX		0x00002d00
#define	NFE_SEED_1000T		0x00007400

#define	NFE_NUM_MIB_STATV1	21
#define	NFE_NUM_MIB_STATV2	27
#define	NFE_NUM_MIB_STATV3	30

#define	NFE_MSI_MESSAGES	8
#define	NFE_MSI_VECTOR_0_ENABLED	0x01

/*
 * It seems that nForce supports only the lower 40 bits of a DMA address.
 */
#if (BUS_SPACE_MAXADDR < 0xFFFFFFFFFF)
#define	NFE_DMA_MAXADDR		BUS_SPACE_MAXADDR
#else
#define	NFE_DMA_MAXADDR		0xFFFFFFFFFF
#endif

#define	NFE_ADDR_LO(x)		((u_int64_t) (x) & 0xffffffff)
#define	NFE_ADDR_HI(x)		((u_int64_t) (x) >> 32)

/* Rx/Tx descriptor */
struct nfe_desc32 {
	uint32_t	physaddr;
	uint16_t	length;
	uint16_t	flags;
#define	NFE_RX_FIXME_V1		0x6004
#define	NFE_RX_VALID_V1		(1 << 0)
#define	NFE_TX_ERROR_V1		0x7808
#define	NFE_TX_LASTFRAG_V1	(1 << 0)
#define	NFE_RX_ERROR1_V1	(1<<7)
#define	NFE_RX_ERROR2_V1	(1<<8)
#define	NFE_RX_ERROR3_V1	(1<<9)
#define	NFE_RX_ERROR4_V1	(1<<10)
} __packed;

#define	NFE_V1_TXERR	"\020"	\
	"\14TXERROR\13UNDERFLOW\12LATECOLLISION\11LOSTCARRIER\10DEFERRED" \
	"\08FORCEDINT\03RETRY\00LASTPACKET"

/* V2 Rx/Tx descriptor */
struct nfe_desc64 {
	uint32_t	physaddr[2];
	uint32_t	vtag;
#define	NFE_RX_VTAG		(1 << 16)
#define	NFE_TX_VTAG		(1 << 18)
	uint16_t	length;
	uint16_t	flags;
#define	NFE_RX_FIXME_V2		0x4300
#define	NFE_RX_VALID_V2		(1 << 13)
#define	NFE_TX_ERROR_V2		0x5c04
#define	NFE_TX_LASTFRAG_V2	(1 << 13)
#define	NFE_RX_ERROR1_V2	(1<<2)
#define	NFE_RX_ERROR2_V2	(1<<3)
#define	NFE_RX_ERROR3_V2	(1<<4)
#define	NFE_RX_ERROR4_V2	(1<<5)
} __packed;

#define	NFE_V2_TXERR	"\020"	\
	"\14FORCEDINT\13LASTPACKET\12UNDERFLOW\10LOSTCARRIER\09DEFERRED\02RETRY"

#define	NFE_RING_ALIGN	(sizeof(struct nfe_desc64))

/* flags common to V1/V2 descriptors */
#define	NFE_RX_UDP_CSUMOK	(1 << 10)
#define	NFE_RX_TCP_CSUMOK	(1 << 11)
#define	NFE_RX_IP_CSUMOK	(1 << 12)
#define	NFE_RX_ERROR		(1 << 14)
#define	NFE_RX_READY		(1 << 15)
#define	NFE_RX_LEN_MASK		0x3fff
#define	NFE_TX_TCP_UDP_CSUM	(1 << 10)
#define	NFE_TX_IP_CSUM		(1 << 11)
#define	NFE_TX_TSO		(1 << 12)
#define	NFE_TX_TSO_SHIFT	14
#define	NFE_TX_VALID		(1 << 15)

#define	NFE_READ(sc, reg) \
	bus_read_4((sc)->nfe_res[0], (reg))

#define	NFE_WRITE(sc, reg, val) \
	bus_write_4((sc)->nfe_res[0], (reg), (val))

#define	NFE_TIMEOUT	1000

#ifndef PCI_VENDOR_NVIDIA
#define	PCI_VENDOR_NVIDIA	0x10DE
#endif

#define	PCI_PRODUCT_NVIDIA_NFORCE_LAN		0x01C3
#define	PCI_PRODUCT_NVIDIA_NFORCE2_LAN		0x0066
#define	PCI_PRODUCT_NVIDIA_NFORCE3_LAN1		0x00D6
#define	PCI_PRODUCT_NVIDIA_NFORCE2_400_LAN1	0x0086
#define	PCI_PRODUCT_NVIDIA_NFORCE2_400_LAN2	0x008C
#define	PCI_PRODUCT_NVIDIA_NFORCE3_250_LAN	0x00E6
#define	PCI_PRODUCT_NVIDIA_NFORCE3_LAN4		0x00DF
#define	PCI_PRODUCT_NVIDIA_NFORCE4_LAN1		0x0056
#define	PCI_PRODUCT_NVIDIA_NFORCE4_LAN2		0x0057
#define	PCI_PRODUCT_NVIDIA_MCP04_LAN1		0x0037
#define	PCI_PRODUCT_NVIDIA_MCP04_LAN2		0x0038
#define	PCI_PRODUCT_NVIDIA_NFORCE430_LAN1	0x0268
#define	PCI_PRODUCT_NVIDIA_NFORCE430_LAN2	0x0269
#define	PCI_PRODUCT_NVIDIA_MCP55_LAN1		0x0372
#define	PCI_PRODUCT_NVIDIA_MCP55_LAN2		0x0373
#define	PCI_PRODUCT_NVIDIA_MCP61_LAN1		0x03e5
#define	PCI_PRODUCT_NVIDIA_MCP61_LAN2		0x03e6
#define	PCI_PRODUCT_NVIDIA_MCP61_LAN3		0x03ee
#define	PCI_PRODUCT_NVIDIA_MCP61_LAN4		0x03ef
#define	PCI_PRODUCT_NVIDIA_MCP65_LAN1		0x0450
#define	PCI_PRODUCT_NVIDIA_MCP65_LAN2		0x0451
#define	PCI_PRODUCT_NVIDIA_MCP65_LAN3		0x0452
#define	PCI_PRODUCT_NVIDIA_MCP65_LAN4		0x0453
#define	PCI_PRODUCT_NVIDIA_MCP67_LAN1		0x054c
#define	PCI_PRODUCT_NVIDIA_MCP67_LAN2		0x054d
#define	PCI_PRODUCT_NVIDIA_MCP67_LAN3		0x054e
#define	PCI_PRODUCT_NVIDIA_MCP67_LAN4		0x054f
#define	PCI_PRODUCT_NVIDIA_MCP73_LAN1		0x07dc
#define	PCI_PRODUCT_NVIDIA_MCP73_LAN2		0x07dd
#define	PCI_PRODUCT_NVIDIA_MCP73_LAN3		0x07de
#define	PCI_PRODUCT_NVIDIA_MCP73_LAN4		0x07df
#define	PCI_PRODUCT_NVIDIA_MCP77_LAN1		0x0760
#define	PCI_PRODUCT_NVIDIA_MCP77_LAN2		0x0761
#define	PCI_PRODUCT_NVIDIA_MCP77_LAN3		0x0762
#define	PCI_PRODUCT_NVIDIA_MCP77_LAN4		0x0763
#define	PCI_PRODUCT_NVIDIA_MCP79_LAN1		0x0ab0
#define	PCI_PRODUCT_NVIDIA_MCP79_LAN2		0x0ab1
#define	PCI_PRODUCT_NVIDIA_MCP79_LAN3		0x0ab2
#define	PCI_PRODUCT_NVIDIA_MCP79_LAN4		0x0ab3

#define	PCI_PRODUCT_NVIDIA_NFORCE3_LAN2	PCI_PRODUCT_NVIDIA_NFORCE2_400_LAN1
#define	PCI_PRODUCT_NVIDIA_NFORCE3_LAN3	PCI_PRODUCT_NVIDIA_NFORCE2_400_LAN2
#define	PCI_PRODUCT_NVIDIA_NFORCE3_LAN5	PCI_PRODUCT_NVIDIA_NFORCE3_250_LAN
#define	PCI_PRODUCT_NVIDIA_CK804_LAN1	PCI_PRODUCT_NVIDIA_NFORCE4_LAN1
#define	PCI_PRODUCT_NVIDIA_CK804_LAN2	PCI_PRODUCT_NVIDIA_NFORCE4_LAN2
#define	PCI_PRODUCT_NVIDIA_MCP51_LAN1	PCI_PRODUCT_NVIDIA_NFORCE430_LAN1
#define	PCI_PRODUCT_NVIDIA_MCP51_LAN2	PCI_PRODUCT_NVIDIA_NFORCE430_LAN2

#define	NFE_DEBUG		0x0000
#define	NFE_DEBUG_INIT		0x0001
#define	NFE_DEBUG_RUNNING	0x0002
#define	NFE_DEBUG_DEINIT 	0x0004
#define	NFE_DEBUG_IOCTL		0x0008
#define	NFE_DEBUG_INTERRUPT	0x0010
#define	NFE_DEBUG_API		0x0020
#define	NFE_DEBUG_LOCK		0x0040
#define	NFE_DEBUG_BROKEN	0x0080
#define	NFE_DEBUG_MII		0x0100
#define	NFE_DEBUG_ALL		0xFFFF
