/*-
 * Copyright (c) 1998 Doug Rabson
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
 *	$Id: lca.c,v 1.1 1998/08/10 07:53:59 dfr Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/bus.h>

#include <alpha/pci/lcareg.h>
#include <alpha/pci/lcavar.h>
#include <machine/swiz.h>
#include <machine/intr.h>
#include <machine/cpuconf.h>

#define KV(pa)			ALPHA_PHYS_TO_K0SEG(pa)

static devclass_t	lca_devclass;
static device_t		lca0;		/* XXX only one for now */
static device_t		isa0;

struct lca_softc {
	int		junk;
};

#define LCA_SOFTC(dev)	(struct lca_softc*) device_get_softc(dev)

static alpha_chipset_inb_t	lca_inb;
static alpha_chipset_inw_t	lca_inw;
static alpha_chipset_inl_t	lca_inl;
static alpha_chipset_outb_t	lca_outb;
static alpha_chipset_outw_t	lca_outw;
static alpha_chipset_outl_t	lca_outl;
static alpha_chipset_readb_t	lca_readb;
static alpha_chipset_readw_t	lca_readw;
static alpha_chipset_readl_t	lca_readl;
static alpha_chipset_writeb_t	lca_writeb;
static alpha_chipset_writew_t	lca_writew;
static alpha_chipset_writel_t	lca_writel;
static alpha_chipset_maxdevs_t	lca_maxdevs;
static alpha_chipset_cfgreadb_t	lca_cfgreadb;
static alpha_chipset_cfgreadw_t	lca_cfgreadw;
static alpha_chipset_cfgreadl_t	lca_cfgreadl;
static alpha_chipset_cfgwriteb_t lca_cfgwriteb;
static alpha_chipset_cfgwritew_t lca_cfgwritew;
static alpha_chipset_cfgwritel_t lca_cfgwritel;

static alpha_chipset_t lca_chipset = {
	lca_inb,
	lca_inw,
	lca_inl,
	lca_outb,
	lca_outw,
	lca_outl,
	lca_readb,
	lca_readw,
	lca_readl,
	lca_writeb,
	lca_writew,
	lca_writel,
	lca_maxdevs,
	lca_cfgreadb,
	lca_cfgreadw,
	lca_cfgreadl,
	lca_cfgwriteb,
	lca_cfgwritew,
	lca_cfgwritel,
};

static u_int8_t
lca_inb(u_int32_t port)
{
	alpha_mb();
	return SPARSE_READ_BYTE(KV(LCA_PCI_SIO), port);
}

static u_int16_t
lca_inw(u_int32_t port)
{
	alpha_mb();
	return SPARSE_READ_WORD(KV(LCA_PCI_SIO), port);
}

static u_int32_t
lca_inl(u_int32_t port)
{
	alpha_mb();
	return SPARSE_READ_LONG(KV(LCA_PCI_SIO), port);
}

static void
lca_outb(u_int32_t port, u_int8_t data)
{
	SPARSE_WRITE_BYTE(KV(LCA_PCI_SIO), port, data);
	alpha_wmb();
}

static void
lca_outw(u_int32_t port, u_int16_t data)
{
	SPARSE_WRITE_WORD(KV(LCA_PCI_SIO), port, data);
	alpha_wmb();
}

static void
lca_outl(u_int32_t port, u_int32_t data)
{
	SPARSE_WRITE_LONG(KV(LCA_PCI_SIO), port, data);
	alpha_wmb();
}

/*
 * The LCA HAE is write-only.  According to NetBSD, this is where it starts.
 */
static u_int32_t	lca_hae_mem = 0x80000000;

/*
 * The first 16Mb ignores the HAE.  The next 112Mb uses the HAE to set
 * the high bits of the PCI address.
 */
#define REG1 (1UL << 24)

static __inline  void
lca_set_hae_mem(u_int32_t *pa)
{
	int s; 
	u_int32_t msb;
	if(*pa >= REG1){
		msb = *pa & 0xf8000000;
		*pa -= msb;
		s = splhigh();
                if (msb != lca_hae_mem) {
			lca_hae_mem = msb;
			REGVAL(LCA_IOC_HAE) = lca_hae_mem;
			alpha_mb();
			alpha_mb();
		}
		splx(s);
	}
}

static u_int8_t
lca_readb(u_int32_t pa)
{
	alpha_mb();
	lca_set_hae_mem(&pa);
	return SPARSE_READ_BYTE(KV(LCA_PCI_SPARSE), pa);
}

static u_int16_t
lca_readw(u_int32_t pa)
{
	alpha_mb();
	lca_set_hae_mem(&pa);
	return SPARSE_READ_WORD(KV(LCA_PCI_SPARSE), pa);
}

static u_int32_t
lca_readl(u_int32_t pa)
{
	alpha_mb();
	lca_set_hae_mem(&pa);
	return SPARSE_READ_LONG(KV(LCA_PCI_SPARSE), pa);
}

static void
lca_writeb(u_int32_t pa, u_int8_t data)
{
	lca_set_hae_mem(&pa);
	SPARSE_WRITE_BYTE(KV(LCA_PCI_SPARSE), pa, data);
	alpha_wmb();
}

static void
lca_writew(u_int32_t pa, u_int16_t data)
{
	lca_set_hae_mem(&pa);
	SPARSE_WRITE_WORD(KV(LCA_PCI_SPARSE), pa, data);
	alpha_wmb();
}

static void
lca_writel(u_int32_t pa, u_int32_t data)
{
	lca_set_hae_mem(&pa);
	SPARSE_WRITE_LONG(KV(LCA_PCI_SPARSE), pa, data);
	alpha_wmb();
}

static int
lca_maxdevs(u_int b)
{
	return 12;		/* XXX */
}

#define LCA_CFGOFF(b, s, f, r) \
	((b) ? (((b) << 16) | ((s) << 11) | ((f) << 8) | (r)) \
	 : ((1 << ((s) + 11)) | ((f) << 8) | (r)))

#define LCA_TYPE1_SETUP(b,s) if ((b)) {		\
        do {					\
		(s) = splhigh();		\
		alpha_mb();			\
		REGVAL(LCA_IOC_CONF) = 1;	\
		alpha_mb();			\
        } while(0);				\
}

#define LCA_TYPE1_TEARDOWN(b,s) if ((b)) {	\
        do {					\
		alpha_mb();			\
		REGVAL(LCA_IOC_CONF) = 0;	\
		alpha_mb();			\
		splx((s));			\
        } while(0);				\
}

#define CFGREAD(b, s, f, r, width, type)				 \
	type val = ~0;							 \
	int ipl = 0;							 \
	vm_offset_t off = LCA_CFGOFF(b, s, f, r);			 \
	vm_offset_t kv = SPARSE_##width##_ADDRESS(KV(LCA_PCI_CONF), off); \
	alpha_mb();							 \
	LCA_TYPE1_SETUP(b,ipl);						 \
	if (!badaddr((caddr_t)kv, sizeof(type))) {			 \
		val = SPARSE_##width##_EXTRACT(off, SPARSE_READ(kv));	 \
	}								 \
        LCA_TYPE1_TEARDOWN(b,ipl);					 \
	return val							

#define CFGWRITE(b, s, f, r, data, width, type)				\
	int ipl = 0;							\
	vm_offset_t off = LCA_CFGOFF(b, s, f, r);			\
	vm_offset_t kv = SPARSE_##width##_ADDRESS(KV(LCA_PCI_CONF), off); \
	alpha_mb();							\
	LCA_TYPE1_SETUP(b,ipl);						\
	if (!badaddr((caddr_t)kv, sizeof(type))) {			\
                SPARSE_WRITE(kv, SPARSE_##width##_INSERT(off, data));	\
		alpha_wmb();						\
	}								\
        LCA_TYPE1_TEARDOWN(b,ipl);					\
	return

static u_int8_t
lca_cfgreadb(u_int b, u_int s, u_int f, u_int r)
{
	CFGREAD(b, s, f, r, BYTE, u_int8_t);
}

static u_int16_t
lca_cfgreadw(u_int b, u_int s, u_int f, u_int r)
{
	CFGREAD(b, s, f, r, WORD, u_int16_t);
}

static u_int32_t
lca_cfgreadl(u_int b, u_int s, u_int f, u_int r)
{
	CFGREAD(b, s, f, r, LONG, u_int32_t);
}

static void
lca_cfgwriteb(u_int b, u_int s, u_int f, u_int r, u_int8_t data)
{
	CFGWRITE(b, s, f, r, data, BYTE, u_int8_t);
}

static void
lca_cfgwritew(u_int b, u_int s, u_int f, u_int r, u_int16_t data)
{
	CFGWRITE(b, s, f, r, data, WORD, u_int16_t);
}

static void
lca_cfgwritel(u_int b, u_int s, u_int f, u_int r, u_int32_t data)
{
	CFGWRITE(b, s, f, r, data, LONG, u_int16_t);
}

static int lca_probe(device_t dev);
static int lca_attach(device_t dev);
static void *lca_create_intr(device_t dev, device_t child, int irq, driver_intr_t *intr, void *arg);
static int lca_connect_intr(device_t dev, void* ih);

static device_method_t lca_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		lca_probe),
	DEVMETHOD(device_attach,	lca_attach),

	/* Bus interface */

	{ 0, 0 }
};

static driver_t lca_driver = {
	"lca",
	lca_methods,
	DRIVER_TYPE_MISC,
	sizeof(struct lca_softc),
};

void
lca_init()
{
	static int initted = 0;

	if (initted) return;
	initted = 1;

	/* Type 0 PCI conf access. */
	REGVAL64(LCA_IOC_CONF) = 0;

	if (platform.pci_intr_init)
		platform.pci_intr_init();

	chipset = lca_chipset;
}

static int
lca_probe(device_t dev)
{
	if (lca0)
		return ENXIO;
	lca0 = dev;
	device_set_desc(dev, "21066 PCI adapter"); /* XXX */

	isa0 = device_add_child(dev, "isa", 0, 0);

	return 0;
}

static int
lca_attach(device_t dev)
{
	struct lca_softc* sc = LCA_SOFTC(dev);

	lca_init();
	chipset.intrdev = isa0;

	set_iointr(alpha_dispatch_intr);

	bus_generic_attach(dev);
	return 0;
}

DRIVER_MODULE(lca, root, lca_driver, lca_devclass, 0, 0);

