/*-
 * Copyright (c) 2003 Pawel Jakub Dawidek <pjd@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
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

#ifndef	_G_STRIPE_H_
#define	_G_STRIPE_H_

#include <sys/endian.h>

#define	G_STRIPE_CLASS_NAME	"STRIPE"

#define	G_STRIPE_MAGIC		"GEOM::STRIPE"
#define	G_STRIPE_VERSION	1

#ifdef _KERNEL
#define	G_STRIPE_TYPE_MANUAL	0
#define	G_STRIPE_TYPE_AUTOMATIC	1

#define	G_STRIPE_DEBUG(lvl, ...)	do {				\
	if (g_stripe_debug >= (lvl)) {					\
		printf("GEOM_STRIPE");					\
		if (g_stripe_debug > 0)					\
			printf("[%u]", lvl);				\
		printf(": ");						\
		printf(__VA_ARGS__);					\
		printf("\n");						\
	}								\
} while (0)
#define	G_STRIPE_LOGREQ(bp, ...)	do {				\
	if (g_stripe_debug >= 2) {					\
		printf("GEOM_STRIPE[2]: ");				\
		printf(__VA_ARGS__);					\
		printf(" ");						\
		g_print_bio(bp);					\
		printf("\n");						\
	}								\
} while (0)

struct g_stripe_softc {
	u_int		 sc_type;	/* provider type */
	struct g_geom	*sc_geom;
	struct g_provider *sc_provider;
	char		 sc_name[16];	/* stripe name */
	uint32_t	 sc_id;		/* stripe unique ID */
	struct g_consumer **sc_disks;
	uint16_t	 sc_ndisks;
	uint32_t	 sc_stripesize;
	uint32_t	 sc_stripebits;
};
#endif	/* _KERNEL */

struct g_stripe_metadata {
	char		md_magic[16];	/* Magic value. */
	uint32_t	md_version;	/* Version number. */
	char		md_name[16];	/* Stripe name. */
	uint32_t	md_id;		/* Unique ID. */
	uint16_t	md_no;		/* Disk number. */
	uint16_t	md_all;		/* Number of all disks. */
	uint32_t	md_stripesize;	/* Stripe size. */
};
static __inline void
stripe_metadata_encode(const struct g_stripe_metadata *md, u_char *data)
{

	bcopy(md->md_magic, data, sizeof(md->md_magic));
	le32enc(data + 16, md->md_version);
	bcopy(md->md_name, data + 20, sizeof(md->md_name));
	le32enc(data + 36, md->md_id);
	le16enc(data + 40, md->md_no);
	le16enc(data + 42, md->md_all);
	le32enc(data + 44, md->md_stripesize);
}
static __inline void
stripe_metadata_decode(const u_char *data, struct g_stripe_metadata *md)
{

	bcopy(data, md->md_magic, sizeof(md->md_magic));
	md->md_version = le32dec(data + 16);
	bcopy(data + 20, md->md_name, sizeof(md->md_name));
	md->md_id = le32dec(data + 36);
	md->md_no = le16dec(data + 40);
	md->md_all = le16dec(data + 42);
	md->md_stripesize = le32dec(data + 44);
}

#ifndef BITCOUNT
#define	BITCOUNT(x)	(((BX_(x) + (BX_(x) >> 4)) & 0x0F0F0F0F) % 255)
#define	BX_(x)		((x) - (((x) >> 1) & 0x77777777) -		\
			 (((x) >> 2) & 0x33333333) - (((x) >> 3) & 0x11111111))
#endif

#endif	/* _G_STRIPE_H_ */
