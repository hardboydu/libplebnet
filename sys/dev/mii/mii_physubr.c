/*	$NetBSD: mii_physubr.c,v 1.5 1999/08/03 19:41:49 drochner Exp $	*/

/*-
 * Copyright (c) 1998, 1999 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the NetBSD
 *	Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Subroutines common to all PHYs.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/module.h>
#include <sys/bus.h>


#include <net/if.h>
#include <net/if_media.h>

#include <dev/mii/mii.h>
#include <dev/mii/miivar.h>

#include "miibus_if.h"

#if !defined(lint)
static const char rcsid[] =
  "$FreeBSD$";
#endif

/*
 * Media to register setting conversion table.  Order matters.
 */
const struct mii_media mii_media_table[MII_NMEDIA] = {
	/* None */
	{ BMCR_ISO,		ANAR_CSMA,
	  0, },

	/* 10baseT */
	{ BMCR_S10,		ANAR_CSMA|ANAR_10,
	  0, },

	/* 10baseT-FDX */
	{ BMCR_S10|BMCR_FDX,	ANAR_CSMA|ANAR_10_FD,
	  0, },

	/* 100baseT4 */
	{ BMCR_S100,		ANAR_CSMA|ANAR_T4,
	  0, },

	/* 100baseTX */
	{ BMCR_S100,		ANAR_CSMA|ANAR_TX,
	  0, },

	/* 100baseTX-FDX */
	{ BMCR_S100|BMCR_FDX,	ANAR_CSMA|ANAR_TX_FD,
	  0, },

	/* 1000baseX */
	{ BMCR_S1000,		ANAR_CSMA,
	  0, },

	/* 1000baseX-FDX */
	{ BMCR_S1000|BMCR_FDX,	ANAR_CSMA,
	  0, },

	/* 1000baseT */
	{ BMCR_S1000,		ANAR_CSMA,
	  GTCR_ADV_1000THDX },

	/* 1000baseT-FDX */
	{ BMCR_S1000,		ANAR_CSMA,
	  GTCR_ADV_1000TFDX },
};

void	mii_phy_auto_timeout(void *);

void
mii_phy_setmedia(struct mii_softc *sc)
{
	struct mii_data *mii = sc->mii_pdata;
	struct ifmedia_entry *ife = mii->mii_media.ifm_cur;
	int bmcr, anar, gtcr;

	if (IFM_SUBTYPE(ife->ifm_media) == IFM_AUTO) {
		if ((PHY_READ(sc, MII_BMCR) & BMCR_AUTOEN) == 0)
			(void) mii_phy_auto(sc, 1);
		return;
	}

	/*
	 * Table index is stored in the media entry.
	 */

#ifdef DIAGNOSTIC
	if (ife->ifm_data < 0 || ife->ifm_data >= MII_NMEDIA)
		panic("mii_phy_setmedia");
#endif

	anar = mii_media_table[ife->ifm_data].mm_anar;
	bmcr = mii_media_table[ife->ifm_data].mm_bmcr;
	gtcr = mii_media_table[ife->ifm_data].mm_gtcr;

	if (mii->mii_media.ifm_media & IFM_ETH_MASTER) {
		switch (IFM_SUBTYPE(ife->ifm_media)) {
		case IFM_1000_T:
			gtcr |= GTCR_MAN_MS|GTCR_ADV_MS;
			break;

		default:
			panic("mii_phy_setmedia: MASTER on wrong media");
		}
	}

	if (ife->ifm_media & IFM_LOOP)
		bmcr |= BMCR_LOOP;

	PHY_WRITE(sc, MII_ANAR, anar);
	PHY_WRITE(sc, MII_BMCR, bmcr);
	if (sc->mii_flags & MIIF_HAVE_GTCR)
		PHY_WRITE(sc, MII_100T2CR, gtcr);
}

int
mii_phy_auto(mii, waitfor)
	struct mii_softc *mii;
	int waitfor;
{
	int bmsr, i;

	if ((mii->mii_flags & MIIF_DOINGAUTO) == 0) {
		PHY_WRITE(mii, MII_ANAR,
		    BMSR_MEDIA_TO_ANAR(mii->mii_capabilities) | ANAR_CSMA);
		PHY_WRITE(mii, MII_BMCR, BMCR_AUTOEN | BMCR_STARTNEG);
	}

	if (waitfor) {
		/* Wait 500ms for it to complete. */
		for (i = 0; i < 500; i++) {
			if ((bmsr = PHY_READ(mii, MII_BMSR)) & BMSR_ACOMP)
				return (0);
			DELAY(1000);
#if 0
		if ((bmsr & BMSR_ACOMP) == 0)
			printf("%s: autonegotiation failed to complete\n",
			    mii->mii_dev.dv_xname);
#endif
		}

		/*
		 * Don't need to worry about clearing MIIF_DOINGAUTO.
		 * If that's set, a timeout is pending, and it will
		 * clear the flag.
		 */
		return (EIO);
	}

	/*
	 * Just let it finish asynchronously.  This is for the benefit of
	 * the tick handler driving autonegotiation.  Don't want 500ms
	 * delays all the time while the system is running!
	 */
	if ((mii->mii_flags & MIIF_DOINGAUTO) == 0) {
		mii->mii_flags |= MIIF_DOINGAUTO;
		mii->mii_auto_ch = timeout(mii_phy_auto_timeout, mii, hz >> 1);
	}
	return (EJUSTRETURN);
}

void
mii_phy_auto_stop(sc)
	struct mii_softc *sc;
{
	if (sc->mii_flags & MIIF_DOINGAUTO) {
		sc->mii_flags &= ~MIIF_DOINGAUTO;
		untimeout(mii_phy_auto_timeout, sc, sc->mii_auto_ch);
	}
}

void
mii_phy_auto_timeout(arg)
	void *arg;
{
	struct mii_softc *mii = arg;
	int s, bmsr;

	s = splnet();
	mii->mii_flags &= ~MIIF_DOINGAUTO;
	bmsr = PHY_READ(mii, MII_BMSR);
#if 0
	if ((bmsr & BMSR_ACOMP) == 0)
		printf("%s: autonegotiation failed to complete\n",
		    sc->sc_dev.dv_xname);
#endif

	/* Update the media status. */
	(void) (*mii->mii_service)(mii, mii->mii_pdata, MII_POLLSTAT);
	splx(s);
}

int
mii_phy_tick(sc)
	struct mii_softc *sc;
{
	struct ifmedia_entry *ife = sc->mii_pdata->mii_media.ifm_cur;
	struct ifnet *ifp = sc->mii_pdata->mii_ifp;
	int reg;

	/*
	 * Is the interface even up?
	 */
	if ((ifp->if_flags & IFF_UP) == 0)
		return (EJUSTRETURN);

	/*
	 * If we're not doing autonegotiation, we don't need to do
	 * any extra work here.  However, we need to check the link
	 * status so we can generate an announcement if the status
	 * changes.
	 */
	if (IFM_SUBTYPE(ife->ifm_media) != IFM_AUTO)
		return (0);

	/*
	 * check for link.
	 * Read the status register twice; BMSR_LINK is latch-low.
	 */
	reg = PHY_READ(sc, MII_BMSR) | PHY_READ(sc, MII_BMSR);
	if (reg & BMSR_LINK)
		return (0);

	/*
	 * Only retry autonegotiation every 5 seconds.
	 */
	if (++sc->mii_ticks != 5)
		return (EJUSTRETURN);

	sc->mii_ticks = 0;
	mii_phy_reset(sc);
	if (mii_phy_auto(sc, 0) == EJUSTRETURN)
		return (EJUSTRETURN);

	/*
	 * Might need to generate a status message if autonegotiation
	 * failed.
	 */
	return (0);
}

void
mii_phy_reset(mii)
	struct mii_softc *mii;
{
	int reg, i;

	if (mii->mii_flags & MIIF_NOISOLATE)
		reg = BMCR_RESET;
	else
		reg = BMCR_RESET | BMCR_ISO;
	PHY_WRITE(mii, MII_BMCR, reg);

	/* Wait 100ms for it to complete. */
	for (i = 0; i < 100; i++) {
		reg = PHY_READ(mii, MII_BMCR); 
		if ((reg & BMCR_RESET) == 0)
			break;
		DELAY(1000);
	}

	if (mii->mii_inst != 0 && ((mii->mii_flags & MIIF_NOISOLATE) == 0))
		PHY_WRITE(mii, MII_BMCR, reg | BMCR_ISO);
}

void
mii_phy_update(sc, cmd)
	struct mii_softc *sc;
	int cmd;
{
	struct mii_data *mii = sc->mii_pdata;

	if (sc->mii_media_active != mii->mii_media_active || cmd == MII_MEDIACHG) {
		MIIBUS_STATCHG(sc->mii_dev);
		sc->mii_media_active = mii->mii_media_active;
	}
	if (sc->mii_media_status != mii->mii_media_status) {
		MIIBUS_LINKCHG(sc->mii_dev);
		sc->mii_media_status = mii->mii_media_status;
	}
}

/*
 * Given an ifmedia word, return the corresponding ANAR value.
 */
int
mii_anar(media)
	int media;
{
	int rv;

	switch (media & (IFM_TMASK|IFM_NMASK|IFM_FDX)) {
	case IFM_ETHER|IFM_10_T:
		rv = ANAR_10|ANAR_CSMA;
		break;
	case IFM_ETHER|IFM_10_T|IFM_FDX:
		rv = ANAR_10_FD|ANAR_CSMA;
		break;
	case IFM_ETHER|IFM_100_TX:
		rv = ANAR_TX|ANAR_CSMA;
		break;
	case IFM_ETHER|IFM_100_TX|IFM_FDX:
		rv = ANAR_TX_FD|ANAR_CSMA;
		break;
	case IFM_ETHER|IFM_100_T4:
		rv = ANAR_T4|ANAR_CSMA;
		break;
	default:
		rv = 0;
		break;
	}

	return (rv);
}

/*
 * Given a BMCR value, return the corresponding ifmedia word.
 */
int
mii_media_from_bmcr(bmcr)
	int bmcr;
{
	int rv = IFM_ETHER;

	if (bmcr & BMCR_S100)
		rv |= IFM_100_TX;
	else
		rv |= IFM_10_T;
	if (bmcr & BMCR_FDX)
		rv |= IFM_FDX;

	return (rv);
}

/*
 * Initialize generic PHY media based on BMSR, called when a PHY is
 * attached.  We expect to be set up to print a comma-separated list
 * of media names.  Does not print a newline.
 */
void
mii_add_media(struct mii_softc *sc)
{
	const char *sep = "";
	struct mii_data *mii;

	mii = device_get_softc(sc->mii_dev);
	if ((sc->mii_capabilities & BMSR_MEDIAMASK) == 0) {
		printf("no media present");
		return;
	}

#define	ADD(m, c)	ifmedia_add(&mii->mii_media, (m), (c), NULL)
#define	PRINT(s)	printf("%s%s", sep, s); sep = ", "

	if (sc->mii_capabilities & BMSR_10THDX) {
		ADD(IFM_MAKEWORD(IFM_ETHER, IFM_10_T, 0, sc->mii_inst), 0);
		PRINT("10baseT");
	}
	if (sc->mii_capabilities & BMSR_10TFDX) {
		ADD(IFM_MAKEWORD(IFM_ETHER, IFM_10_T, IFM_FDX, sc->mii_inst),
		    BMCR_FDX);
		PRINT("10baseT-FDX");
	}
	if (sc->mii_capabilities & BMSR_100TXHDX) {
		ADD(IFM_MAKEWORD(IFM_ETHER, IFM_100_TX, 0, sc->mii_inst),
		    BMCR_S100);
		PRINT("100baseTX");
	}
	if (sc->mii_capabilities & BMSR_100TXFDX) {
		ADD(IFM_MAKEWORD(IFM_ETHER, IFM_100_TX, IFM_FDX, sc->mii_inst),
		    BMCR_S100|BMCR_FDX);
		PRINT("100baseTX-FDX");
	}
	if (sc->mii_capabilities & BMSR_100T4) {
		/*
		 * XXX How do you enable 100baseT4?  I assume we set
		 * XXX BMCR_S100 and then assume the PHYs will take
		 * XXX watever action is necessary to switch themselves
		 * XXX into T4 mode.
		 */
		ADD(IFM_MAKEWORD(IFM_ETHER, IFM_100_T4, 0, sc->mii_inst),
		    BMCR_S100);
		PRINT("100baseT4");
	}
	if (sc->mii_capabilities & BMSR_ANEG) {
		ADD(IFM_MAKEWORD(IFM_ETHER, IFM_AUTO, 0, sc->mii_inst),
		    BMCR_AUTOEN);
		PRINT("auto");
	}



#undef ADD
#undef PRINT
}
