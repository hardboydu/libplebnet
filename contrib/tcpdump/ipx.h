/*
 * IPX protocol formats 
 *
 * @(#) $Header: /tcpdump/master/tcpdump/ipx.h,v 1.2 2000/10/03 02:54:56 itojun Exp $
 */

/* well-known sockets */
#define	IPX_SKT_NCP		0x0451
#define	IPX_SKT_SAP		0x0452
#define	IPX_SKT_RIP		0x0453
#define	IPX_SKT_NETBIOS		0x0455
#define	IPX_SKT_DIAGNOSTICS	0x0456

/* IPX transport header */
struct ipxHdr {
    u_int16_t	cksum;		/* Checksum */
    u_int16_t	length;		/* Length, in bytes, including header */
    u_int8_t	tCtl;		/* Transport Control (i.e. hop count) */
    u_int8_t	pType;		/* Packet Type (i.e. level 2 protocol) */
    u_int16_t	dstNet[2];	/* destination net */
    u_int8_t	dstNode[6];	/* destination node */
    u_int16_t	dstSkt;		/* destination socket */
    u_int16_t	srcNet[2];	/* source net */
    u_int8_t	srcNode[6];	/* source node */
    u_int16_t	srcSkt;		/* source socket */
} ipx_hdr_t;

#define ipxSize	30

