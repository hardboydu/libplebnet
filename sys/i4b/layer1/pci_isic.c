/*
 *   Copyright (c) 1998 Martin Husemann. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *   3. Neither the name of the author nor the names of any co-contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *   4. Altered versions must be plainly marked as such, and must not be
 *      misrepresented as being the original software and/or documentation.
 *   
 *   THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 *   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *   ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 *   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 *   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *   SUCH DAMAGE.
 *
 *---------------------------------------------------------------------------
 *
 *	pci_isic.c - pcmcia bus frontend for i4b_isic driver
 *	-------------------------------------------------------
 *
 *	$Id: pci_isic.c,v 1.2 1999/02/14 09:45:00 hm Exp $ 
 *
 *      last edit-date: [Sun Feb 14 10:29:25 1999]
 *
 *	-mh	original implementation
 *
 *---------------------------------------------------------------------------*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/syslog.h>
#include <sys/device.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/systm.h>
#include <sys/malloc.h>

#include <machine/cpu.h>
#include <machine/intr.h>
#include <machine/bus.h>


#include <machine/bus.h>
#include <machine/intr.h>
#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcidevs.h>

#ifdef __FreeBSD__
#include <machine/i4b_ioctl.h>
#else
#include <i4b/i4b_ioctl.h>
#endif

#include <i4b/layer1/i4b_l1.h>
#include <i4b/layer1/i4b_ipac.h>
#include <i4b/layer1/i4b_isac.h>
#include <i4b/layer1/i4b_hscx.h>
#include <i4b/include/i4b_global.h>
#include <i4b/include/i4b_l1l2.h>

static int pci_isic_match __P((struct device *, struct cfdata *, void *));
static void pci_isic_attach __P((struct device *, struct device *, void *));
static const struct isic_pci_product * find_matching_card __P((struct pci_attach_args *pa));

extern void isic_attach_Eqs1pp __P((struct isic_softc *sc, struct pci_attach_args *pa));
static int isic_pciattach __P((struct isic_softc *sc));

struct pci_isic_softc {
	struct isic_softc sc_isic;	/* parent class */

	/* PCI-specific goo */
	void *sc_ih;				/* interrupt handler */
};

struct cfattach pci_isic_ca = {
	sizeof(struct pci_isic_softc), pci_isic_match, pci_isic_attach
};


static const struct isic_pci_product {
	pci_vendor_id_t npp_vendor;
	pci_product_id_t npp_product;
	int cardtype;
	int flag;
	const char * name;
	void (*attach)(struct isic_softc *sc, struct pci_attach_args *pa);
} isic_pci_products[] = {
	{ PCI_VENDOR_ELSA, 0x1000,
	  CARD_TYPEP_ELSAQS1PCI, FLAG_ELSA_QS1P_PCI,
	  "ELSA QuickStep 1000pro/PCI",
	  isic_attach_Eqs1pp },

	{ 0, 0, 0, 0, NULL, NULL },
};

static const struct isic_pci_product * find_matching_card(pa)
	struct pci_attach_args *pa;
{
	const struct isic_pci_product * pp = NULL;

	for (pp = isic_pci_products; pp->npp_vendor; pp++) 
		if (PCI_VENDOR(pa->pa_id) == pp->npp_vendor &&
		    PCI_PRODUCT(pa->pa_id) == pp->npp_product)
			return pp;

	return NULL;
}

/*
 * Match card
 */
static int
pci_isic_match(parent, match, aux)
	struct device *parent;
	struct cfdata *match;
	void *aux;
{
	struct pci_attach_args *pa = aux;

	if (!find_matching_card(pa))
		return 0;

	return 1;
}

/*
 * Attach the card
 */
static void
pci_isic_attach(parent, self, aux)
	struct device *parent, *self;
	void *aux;
{
	struct pci_isic_softc *psc = (void*) self;
	struct isic_softc *sc = &psc->sc_isic;
	struct pci_attach_args *pa = aux;
	pci_chipset_tag_t pc = pa->pa_pc;
	pci_intr_handle_t ih;
	const struct isic_pci_product * prod;
	const char *intrstr;

	/* Redo probe */
	prod = find_matching_card(pa);
	if (prod == NULL) return; /* oops - not found?!? */

	sc->sc_unit = sc->sc_dev.dv_unit;
	printf(": %s\n", prod->name);

	/* card initilization and sc setup */
	prod->attach(sc, pa);

	/* generic setup */
	isic_pciattach(sc);

	/* Map and establish the interrupt. */
	if (pci_intr_map(pc, pa->pa_intrtag, pa->pa_intrpin,
	    pa->pa_intrline, &ih)) {
		printf("%s: couldn't map interrupt\n", sc->sc_dev.dv_xname);
		return;
	}
	intrstr = pci_intr_string(pc, ih);
	psc->sc_ih = pci_intr_establish(pc, ih, IPL_NET, isicintr, sc);
	if (psc->sc_ih == NULL) {
		printf("%s: couldn't establish interrupt",
		    sc->sc_dev.dv_xname);
		if (intrstr != NULL)
			printf(" at %s", intrstr);
		printf("\n");
		return;
	}
	printf("%s: interrupting at %s\n", sc->sc_dev.dv_xname, intrstr);
}

/*---------------------------------------------------------------------------*
 *	isic - pci device driver attach routine
 *---------------------------------------------------------------------------*/
static int
isic_pciattach(sc)
	struct isic_softc *sc;
{
	int ret = 0;

  	static char *ISACversion[] = {
  		"2085 Version A1/A2 or 2086/2186 Version 1.1",
		"2085 Version B1",
		"2085 Version B2",
		"2085 Version V2.3 (B3)",
		"Unknown Version"
	};

	static char *HSCXversion[] = {
		"82525 Version A1",
		"Unknown (0x01)",
		"82525 Version A2",
		"Unknown (0x03)",
		"82525 Version A3",
		"82525 or 21525 Version 2.1",
		"Unknown Version"
	};

	isic_sc[sc->sc_unit] = sc;	/* XXX - hack! */

	sc->sc_isac_version = 0;
	sc->sc_hscx_version = 0;
	
	if(sc->sc_ipac)
	{
		ret = IPAC_READ(IPAC_ID);

		switch(ret)
		{
			case 0x01:
				printf("%s: IPAC PSB2115 Version 1.1\n", sc->sc_dev.dv_xname);
				break;
	
			default:
				printf("%s: Error, IPAC version %d unknown!\n",
					sc->sc_dev.dv_xname, ret);
				return(0);
				break;
		}
	}
	else
	{
		sc->sc_isac_version = ((ISAC_READ(I_RBCH)) >> 5) & 0x03;
	
		switch(sc->sc_isac_version)
		{
			case ISAC_VA:
			case ISAC_VB1:
	                case ISAC_VB2:
			case ISAC_VB3:
				printf("%s: ISAC %s (IOM-%c)\n",
					sc->sc_dev.dv_xname,
					ISACversion[sc->sc_isac_version],
					sc->sc_bustyp == BUS_TYPE_IOM1 ? '1' : '2');
				break;
	
			default:
				printf("%s: Error, ISAC version %d unknown!\n",
					sc->sc_dev.dv_xname, sc->sc_isac_version);
				return(0);
				break;
		}
	
		sc->sc_hscx_version = HSCX_READ(0, H_VSTR) & 0xf;
	
		switch(sc->sc_hscx_version)
		{
			case HSCX_VA1:
			case HSCX_VA2:
			case HSCX_VA3:
			case HSCX_V21:
				printf("%s: HSCX %s\n",
					sc->sc_dev.dv_xname,
					HSCXversion[sc->sc_hscx_version]);
				break;
				
			default:
				printf("%s: Error, HSCX version %d unknown!\n",
					sc->sc_dev.dv_xname, sc->sc_hscx_version);
				return(0);
				break;
		}
	}
	
	/* ISAC setup */
	
	isic_isac_init(sc);

	/* HSCX setup */

	isic_bchannel_setup(sc->sc_unit, HSCX_CH_A, BPROT_NONE, 0);
	
	isic_bchannel_setup(sc->sc_unit, HSCX_CH_B, BPROT_NONE, 0);

	/* setup linktab */

	isic_init_linktab(sc);

	/* set trace level */

	sc->sc_trace = TRACE_OFF;

	sc->sc_state = ISAC_IDLE;

	sc->sc_ibuf = NULL;
	sc->sc_ib = NULL;
	sc->sc_ilen = 0;

	sc->sc_obuf = NULL;
	sc->sc_op = NULL;
	sc->sc_ol = 0;
	sc->sc_freeflag = 0;

	sc->sc_obuf2 = NULL;
	sc->sc_freeflag2 = 0;

#if defined(__FreeBSD__) && __FreeBSD__ >=3
	callout_handle_init(&sc->sc_T3_callout);
	callout_handle_init(&sc->sc_T4_callout);	
#endif
	
	/* init higher protocol layers */
	
	MPH_Status_Ind(sc->sc_unit, STI_ATTACH, sc->sc_cardtyp);
	
	return(1);
}

