/*
 * Copyright (c) 2002-2009 Sam Leffler, Errno Consulting
 * Copyright (c) 2002-2008 Atheros Communications, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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
#include "opt_ah.h"

#include "ah.h"
#include "ah_internal.h"
#include "ah_devid.h"

#include "ah_eeprom_v14.h"

#include "ar5416/ar5416.h"
#include "ar5416/ar5416reg.h"
#include "ar5416/ar5416phy.h"

/* Eeprom versioning macros. Returns true if the version is equal or newer than the ver specified */ 
#define	EEP_MINOR(_ah) \
	(AH_PRIVATE(_ah)->ah_eeversion & AR5416_EEP_VER_MINOR_MASK)
#define IS_EEP_MINOR_V2(_ah)	(EEP_MINOR(_ah) >= AR5416_EEP_MINOR_VER_2)
#define IS_EEP_MINOR_V3(_ah)	(EEP_MINOR(_ah) >= AR5416_EEP_MINOR_VER_3)

/* Additional Time delay to wait after activiting the Base band */
#define BASE_ACTIVATE_DELAY	100	/* 100 usec */
#define PLL_SETTLE_DELAY	300	/* 300 usec */
#define RTC_PLL_SETTLE_DELAY    1000    /* 1 ms     */

static void ar5416InitDMA(struct ath_hal *ah);
static void ar5416InitBB(struct ath_hal *ah, const struct ieee80211_channel *);
static void ar5416InitIMR(struct ath_hal *ah, HAL_OPMODE opmode);
static void ar5416InitQoS(struct ath_hal *ah);
static void ar5416InitUserSettings(struct ath_hal *ah);
static void ar5416UpdateChainMasks(struct ath_hal *ah, HAL_BOOL is_ht);
static void ar5416OverrideIni(struct ath_hal *ah, const struct ieee80211_channel *);

#if 0
static HAL_BOOL	ar5416ChannelChange(struct ath_hal *, const struct ieee80211_channel *);
#endif
static void ar5416SetDeltaSlope(struct ath_hal *, const struct ieee80211_channel *);

static HAL_BOOL ar5416SetResetPowerOn(struct ath_hal *ah);
static HAL_BOOL ar5416SetReset(struct ath_hal *ah, int type);
static HAL_BOOL ar5416SetPowerPerRateTable(struct ath_hal *ah,
	struct ar5416eeprom *pEepData, 
	const struct ieee80211_channel *chan, int16_t *ratesArray,
	uint16_t cfgCtl, uint16_t AntennaReduction,
	uint16_t twiceMaxRegulatoryPower, 
	uint16_t powerLimit);
static void ar5416Set11nRegs(struct ath_hal *ah, const struct ieee80211_channel *chan);
static void ar5416MarkPhyInactive(struct ath_hal *ah);

/*
 * Places the device in and out of reset and then places sane
 * values in the registers based on EEPROM config, initialization
 * vectors (as determined by the mode), and station configuration
 *
 * bChannelChange is used to preserve DMA/PCU registers across
 * a HW Reset during channel change.
 */
HAL_BOOL
ar5416Reset(struct ath_hal *ah, HAL_OPMODE opmode,
	struct ieee80211_channel *chan,
	HAL_BOOL bChannelChange, HAL_STATUS *status)
{
#define	N(a)	(sizeof (a) / sizeof (a[0]))
#define	FAIL(_code)	do { ecode = _code; goto bad; } while (0)
	struct ath_hal_5212 *ahp = AH5212(ah);
	HAL_CHANNEL_INTERNAL *ichan;
	uint32_t saveDefAntenna, saveLedState;
	uint32_t macStaId1;
	uint16_t rfXpdGain[2];
	HAL_STATUS ecode;
	uint32_t powerVal, rssiThrReg;
	uint32_t ackTpcPow, ctsTpcPow, chirpTpcPow;
	int i;
	uint64_t tsf = 0;

	OS_MARK(ah, AH_MARK_RESET, bChannelChange);

	/* Bring out of sleep mode */
	if (!ar5416SetPowerMode(ah, HAL_PM_AWAKE, AH_TRUE)) {
		HALDEBUG(ah, HAL_DEBUG_ANY, "%s: chip did not wakeup\n",
		    __func__);
		FAIL(HAL_EIO);
	}

	/*
	 * Map public channel to private.
	 */
	ichan = ath_hal_checkchannel(ah, chan);
	if (ichan == AH_NULL)
		FAIL(HAL_EINVAL);
	switch (opmode) {
	case HAL_M_STA:
	case HAL_M_IBSS:
	case HAL_M_HOSTAP:
	case HAL_M_MONITOR:
		break;
	default:
		HALDEBUG(ah, HAL_DEBUG_ANY, "%s: invalid operating mode %u\n",
		    __func__, opmode);
		FAIL(HAL_EINVAL);
		break;
	}
	HALASSERT(AH_PRIVATE(ah)->ah_eeversion >= AR_EEPROM_VER14_1);

	/* XXX Turn on fast channel change for 5416 */
	/*
	 * Preserve the bmiss rssi threshold and count threshold
	 * across resets
	 */
	rssiThrReg = OS_REG_READ(ah, AR_RSSI_THR);
	/* If reg is zero, first time thru set to default val */
	if (rssiThrReg == 0)
		rssiThrReg = INIT_RSSI_THR;

	/*
	 * Preserve the antenna on a channel change
	 */
	saveDefAntenna = OS_REG_READ(ah, AR_DEF_ANTENNA);
	if (saveDefAntenna == 0)		/* XXX magic constants */
		saveDefAntenna = 1;

	/* Save hardware flag before chip reset clears the register */
	macStaId1 = OS_REG_READ(ah, AR_STA_ID1) & 
		(AR_STA_ID1_BASE_RATE_11B | AR_STA_ID1_USE_DEFANT);

	/* Save led state from pci config register */
	saveLedState = OS_REG_READ(ah, AR_MAC_LED) &
		(AR_MAC_LED_ASSOC | AR_MAC_LED_MODE |
		 AR_MAC_LED_BLINK_THRESH_SEL | AR_MAC_LED_BLINK_SLOW);

	/* For chips on which the RTC reset is done, save TSF before it gets cleared */
	if (AR_SREV_HOWL(ah) ||
	    (AR_SREV_MERLIN(ah) && ath_hal_eepromGetFlag(ah, AR_EEP_OL_PWRCTRL)))
		tsf = ar5212GetTsf64(ah);

	/* Mark PHY as inactive; marked active in ar5416InitBB() */
	ar5416MarkPhyInactive(ah);

	if (!ar5416ChipReset(ah, chan)) {
		HALDEBUG(ah, HAL_DEBUG_ANY, "%s: chip reset failed\n", __func__);
		FAIL(HAL_EIO);
	}

	/* Restore TSF */
	if (tsf)
		ar5212SetTsf64(ah, tsf);

	OS_MARK(ah, AH_MARK_RESET_LINE, __LINE__);
	if (AR_SREV_MERLIN_10_OR_LATER(ah))
		OS_REG_SET_BIT(ah, AR_GPIO_INPUT_EN_VAL, AR_GPIO_JTAG_DISABLE);

	AH5416(ah)->ah_writeIni(ah, chan);

	/* Override ini values (that can be overriden in this fashion) */
	ar5416OverrideIni(ah, chan);

	/* Setup 11n MAC/Phy mode registers */
	ar5416Set11nRegs(ah, chan);	

	OS_MARK(ah, AH_MARK_RESET_LINE, __LINE__);

	/*
	 * Some AR91xx SoC devices frequently fail to accept TSF writes
	 * right after the chip reset. When that happens, write a new
	 * value after the initvals have been applied, with an offset
	 * based on measured time difference
	 */
	if (AR_SREV_HOWL(ah) && (ar5212GetTsf64(ah) < tsf)) {
		tsf += 1500;
		ar5212SetTsf64(ah, tsf);
	}

	HALDEBUG(ah, HAL_DEBUG_RESET, ">>>2 %s: AR_PHY_DAG_CTRLCCK=0x%x\n",
		__func__, OS_REG_READ(ah,AR_PHY_DAG_CTRLCCK));
	HALDEBUG(ah, HAL_DEBUG_RESET, ">>>2 %s: AR_PHY_ADC_CTL=0x%x\n",
		__func__, OS_REG_READ(ah,AR_PHY_ADC_CTL));	

	/*
	 * Setup ah_tx_chainmask / ah_rx_chainmask before we fiddle
	 * with enabling the TX/RX radio chains.
	 */
	ar5416UpdateChainMasks(ah, IEEE80211_IS_CHAN_HT(chan));
	/*
	 * This routine swaps the analog chains - it should be done
	 * before any radio register twiddling is done.
	 */
	ar5416InitChainMasks(ah);

	/* Setup the open-loop power calibration if required */
	if (ath_hal_eepromGetFlag(ah, AR_EEP_OL_PWRCTRL)) {
		AH5416(ah)->ah_olcInit(ah);
		AH5416(ah)->ah_olcTempCompensation(ah);
	}

	/* Setup the transmit power values. */
	if (!ah->ah_setTxPower(ah, chan, rfXpdGain)) {
		HALDEBUG(ah, HAL_DEBUG_ANY,
		    "%s: error init'ing transmit power\n", __func__);
		FAIL(HAL_EIO);
	}

	/* Write the analog registers */
	if (!ahp->ah_rfHal->setRfRegs(ah, chan,
	    IEEE80211_IS_CHAN_2GHZ(chan) ? 2: 1, rfXpdGain)) {
		HALDEBUG(ah, HAL_DEBUG_ANY,
		    "%s: ar5212SetRfRegs failed\n", __func__);
		FAIL(HAL_EIO);
	}

	/* Write delta slope for OFDM enabled modes (A, G, Turbo) */
	if (IEEE80211_IS_CHAN_OFDM(chan)|| IEEE80211_IS_CHAN_HT(chan))
		ar5416SetDeltaSlope(ah, chan);

	AH5416(ah)->ah_spurMitigate(ah, chan);

	/* Setup board specific options for EEPROM version 3 */
	if (!ah->ah_setBoardValues(ah, chan)) {
		HALDEBUG(ah, HAL_DEBUG_ANY,
		    "%s: error setting board options\n", __func__);
		FAIL(HAL_EIO);
	}

	OS_MARK(ah, AH_MARK_RESET_LINE, __LINE__);

	OS_REG_WRITE(ah, AR_STA_ID0, LE_READ_4(ahp->ah_macaddr));
	OS_REG_WRITE(ah, AR_STA_ID1, LE_READ_2(ahp->ah_macaddr + 4)
		| macStaId1
		| AR_STA_ID1_RTS_USE_DEF
		| ahp->ah_staId1Defaults
	);
	ar5212SetOperatingMode(ah, opmode);

	/* Set Venice BSSID mask according to current state */
	OS_REG_WRITE(ah, AR_BSSMSKL, LE_READ_4(ahp->ah_bssidmask));
	OS_REG_WRITE(ah, AR_BSSMSKU, LE_READ_2(ahp->ah_bssidmask + 4));

	/* Restore previous led state */
	if (AR_SREV_HOWL(ah))
		OS_REG_WRITE(ah, AR_MAC_LED,
		    AR_MAC_LED_ASSOC_ACTIVE | AR_CFG_SCLK_32KHZ);
	else
		OS_REG_WRITE(ah, AR_MAC_LED, OS_REG_READ(ah, AR_MAC_LED) |
		    saveLedState);

	/* Restore previous antenna */
	OS_REG_WRITE(ah, AR_DEF_ANTENNA, saveDefAntenna);

	/* then our BSSID */
	OS_REG_WRITE(ah, AR_BSS_ID0, LE_READ_4(ahp->ah_bssid));
	OS_REG_WRITE(ah, AR_BSS_ID1, LE_READ_2(ahp->ah_bssid + 4));

	/* Restore bmiss rssi & count thresholds */
	OS_REG_WRITE(ah, AR_RSSI_THR, ahp->ah_rssiThr);

	OS_REG_WRITE(ah, AR_ISR, ~0);		/* cleared on write */

	/* Restore bmiss rssi & count thresholds */
	OS_REG_WRITE(ah, AR_RSSI_THR, rssiThrReg);

	if (!ar5212SetChannel(ah, chan))
		FAIL(HAL_EIO);

	OS_MARK(ah, AH_MARK_RESET_LINE, __LINE__);

	/* Set 1:1 QCU to DCU mapping for all queues */
	for (i = 0; i < AR_NUM_DCU; i++)
		OS_REG_WRITE(ah, AR_DQCUMASK(i), 1 << i);

	ahp->ah_intrTxqs = 0;
	for (i = 0; i < AH_PRIVATE(ah)->ah_caps.halTotalQueues; i++)
		ah->ah_resetTxQueue(ah, i);

	ar5416InitIMR(ah, opmode);
	ar5212SetCoverageClass(ah, AH_PRIVATE(ah)->ah_coverageClass, 1);
	ar5416InitQoS(ah);
	/* This may override the AR_DIAG_SW register */
	ar5416InitUserSettings(ah);

	/*
	 * disable seq number generation in hw
	 */
	 OS_REG_WRITE(ah, AR_STA_ID1,
	     OS_REG_READ(ah, AR_STA_ID1) | AR_STA_ID1_PRESERVE_SEQNUM);
	 
	ar5416InitDMA(ah);

	/*
	 * program OBS bus to see MAC interrupts
	 */
	OS_REG_WRITE(ah, AR_OBS, 8);

#ifdef	AH_AR5416_INTERRUPT_MITIGATION
	OS_REG_WRITE(ah, AR_MIRT, 0);

	OS_REG_RMW_FIELD(ah, AR_RIMT, AR_RIMT_LAST, 500);
	OS_REG_RMW_FIELD(ah, AR_RIMT, AR_RIMT_FIRST, 2000);
	OS_REG_RMW_FIELD(ah, AR_TIMT, AR_TIMT_LAST, 300);
	OS_REG_RMW_FIELD(ah, AR_TIMT, AR_TIMT_FIRST, 750);
#endif	    
	
	ar5416InitBB(ah, chan);

	/* Setup compression registers */
	ar5212SetCompRegs(ah);		/* XXX not needed? */

	/*
	 * 5416 baseband will check the per rate power table
	 * and select the lower of the two
	 */
	ackTpcPow = 63;
	ctsTpcPow = 63;
	chirpTpcPow = 63;
	powerVal = SM(ackTpcPow, AR_TPC_ACK) |
		SM(ctsTpcPow, AR_TPC_CTS) |
		SM(chirpTpcPow, AR_TPC_CHIRP);
	OS_REG_WRITE(ah, AR_TPC, powerVal);

	if (!ar5416InitCal(ah, chan))
		FAIL(HAL_ESELFTEST);

	ar5416RestoreChainMask(ah);

	AH_PRIVATE(ah)->ah_opmode = opmode;	/* record operating mode */

	if (bChannelChange && !IEEE80211_IS_CHAN_DFS(chan)) 
		chan->ic_state &= ~IEEE80211_CHANSTATE_CWINT;

	if (AR_SREV_HOWL(ah)) {
		/*
		 * Enable the MBSSID block-ack fix for HOWL.
		 * This feature is only supported on Howl 1.4, but it is safe to
		 * set bit 22 of STA_ID1 on other Howl revisions (1.1, 1.2, 1.3),
		 * since bit 22 is unused in those Howl revisions.
		 */
		unsigned int reg;
		reg = (OS_REG_READ(ah, AR_STA_ID1) | (1<<22));
		OS_REG_WRITE(ah,AR_STA_ID1, reg);
		ath_hal_printf(ah, "MBSSID Set bit 22 of AR_STA_ID 0x%x\n", reg);
	}

	HALDEBUG(ah, HAL_DEBUG_RESET, "%s: done\n", __func__);

	OS_MARK(ah, AH_MARK_RESET_DONE, 0);

	return AH_TRUE;
bad:
	OS_MARK(ah, AH_MARK_RESET_DONE, ecode);
	if (status != AH_NULL)
		*status = ecode;
	return AH_FALSE;
#undef FAIL
#undef N
}

#if 0
/*
 * This channel change evaluates whether the selected hardware can
 * perform a synthesizer-only channel change (no reset).  If the
 * TX is not stopped, or the RFBus cannot be granted in the given
 * time, the function returns false as a reset is necessary
 */
HAL_BOOL
ar5416ChannelChange(struct ath_hal *ah, const structu ieee80211_channel *chan)
{
	uint32_t       ulCount;
	uint32_t   data, synthDelay, qnum;
	uint16_t   rfXpdGain[4];
	struct ath_hal_5212 *ahp = AH5212(ah);
	HAL_CHANNEL_INTERNAL *ichan;

	/*
	 * Map public channel to private.
	 */
	ichan = ath_hal_checkchannel(ah, chan);

	/* TX must be stopped or RF Bus grant will not work */
	for (qnum = 0; qnum < AH_PRIVATE(ah)->ah_caps.halTotalQueues; qnum++) {
		if (ar5212NumTxPending(ah, qnum)) {
			HALDEBUG(ah, HAL_DEBUG_ANY,
			    "%s: frames pending on queue %d\n", __func__, qnum);
			return AH_FALSE;
		}
	}

	/*
	 * Kill last Baseband Rx Frame - Request analog bus grant
	 */
	OS_REG_WRITE(ah, AR_PHY_RFBUS_REQ, AR_PHY_RFBUS_REQ_REQUEST);
	if (!ath_hal_wait(ah, AR_PHY_RFBUS_GNT, AR_PHY_RFBUS_GRANT_EN, AR_PHY_RFBUS_GRANT_EN)) {
		HALDEBUG(ah, HAL_DEBUG_ANY, "%s: could not kill baseband rx\n",
		    __func__);
		return AH_FALSE;
	}

	ar5416Set11nRegs(ah, chan);	/* NB: setup 5416-specific regs */

	/* Change the synth */
	if (!ar5212SetChannel(ah, chan))
		return AH_FALSE;

	/* Setup the transmit power values. */
	if (!ah->ah_setTxPower(ah, chan, rfXpdGain)) {
		HALDEBUG(ah, HAL_DEBUG_ANY,
		    "%s: error init'ing transmit power\n", __func__);
		return AH_FALSE;
	}

	/*
	 * Wait for the frequency synth to settle (synth goes on
	 * via PHY_ACTIVE_EN).  Read the phy active delay register.
	 * Value is in 100ns increments.
	 */
	data = OS_REG_READ(ah, AR_PHY_RX_DELAY) & AR_PHY_RX_DELAY_DELAY;
	if (IS_CHAN_CCK(ichan)) {
		synthDelay = (4 * data) / 22;
	} else {
		synthDelay = data / 10;
	}

	OS_DELAY(synthDelay + BASE_ACTIVATE_DELAY);

	/* Release the RFBus Grant */
	OS_REG_WRITE(ah, AR_PHY_RFBUS_REQ, 0);

	/* Write delta slope for OFDM enabled modes (A, G, Turbo) */
	if (IEEE80211_IS_CHAN_OFDM(ichan)|| IEEE80211_IS_CHAN_HT(chan)) {
		HALASSERT(AH_PRIVATE(ah)->ah_eeversion >= AR_EEPROM_VER5_3);
		ar5212SetSpurMitigation(ah, chan);
		ar5416SetDeltaSlope(ah, chan);
	}

	/* XXX spur mitigation for Melin */

	if (!IEEE80211_IS_CHAN_DFS(chan)) 
		chan->ic_state &= ~IEEE80211_CHANSTATE_CWINT;

	ichan->channel_time = 0;
	ichan->tsf_last = ar5212GetTsf64(ah);
	ar5212TxEnable(ah, AH_TRUE);
	return AH_TRUE;
}
#endif

static void
ar5416InitDMA(struct ath_hal *ah)
{
	struct ath_hal_5212 *ahp = AH5212(ah);

	/*
	 * set AHB_MODE not to do cacheline prefetches
	 */
	OS_REG_SET_BIT(ah, AR_AHB_MODE, AR_AHB_PREFETCH_RD_EN);

	/*
	 * let mac dma reads be in 128 byte chunks
	 */
	OS_REG_WRITE(ah, AR_TXCFG, 
		(OS_REG_READ(ah, AR_TXCFG) & ~AR_TXCFG_DMASZ_MASK) | AR_TXCFG_DMASZ_128B);

	/*
	 * let mac dma writes be in 128 byte chunks
	 */
	OS_REG_WRITE(ah, AR_RXCFG, 
		(OS_REG_READ(ah, AR_RXCFG) & ~AR_RXCFG_DMASZ_MASK) | AR_RXCFG_DMASZ_128B);

	/* restore TX trigger level */
	OS_REG_WRITE(ah, AR_TXCFG,
		(OS_REG_READ(ah, AR_TXCFG) &~ AR_FTRIG) |
		    SM(ahp->ah_txTrigLev, AR_FTRIG));

	/*
	 * Setup receive FIFO threshold to hold off TX activities
	 */
	OS_REG_WRITE(ah, AR_RXFIFO_CFG, 0x200);
	
	/*
	 * reduce the number of usable entries in PCU TXBUF to avoid
	 * wrap around.
	 */
	if (AR_SREV_KITE(ah))
		/*
		 * For AR9285 the number of Fifos are reduced to half.
		 * So set the usable tx buf size also to half to
		 * avoid data/delimiter underruns
		 */
		OS_REG_WRITE(ah, AR_PCU_TXBUF_CTRL, AR_9285_PCU_TXBUF_CTRL_USABLE_SIZE);
	else
		OS_REG_WRITE(ah, AR_PCU_TXBUF_CTRL, AR_PCU_TXBUF_CTRL_USABLE_SIZE);
}

static void
ar5416InitBB(struct ath_hal *ah, const struct ieee80211_channel *chan)
{
	uint32_t synthDelay;

	/*
	 * Wait for the frequency synth to settle (synth goes on
	 * via AR_PHY_ACTIVE_EN).  Read the phy active delay register.
	 * Value is in 100ns increments.
	  */
	synthDelay = OS_REG_READ(ah, AR_PHY_RX_DELAY) & AR_PHY_RX_DELAY_DELAY;
	if (IEEE80211_IS_CHAN_CCK(chan)) {
		synthDelay = (4 * synthDelay) / 22;
	} else {
		synthDelay /= 10;
	}

	/* Turn on PLL on 5416 */
	HALDEBUG(ah, HAL_DEBUG_RESET, "%s %s channel\n",
	    __func__, IEEE80211_IS_CHAN_5GHZ(chan) ? "5GHz" : "2GHz");

	/* Activate the PHY (includes baseband activate and synthesizer on) */
	OS_REG_WRITE(ah, AR_PHY_ACTIVE, AR_PHY_ACTIVE_EN);
	
	/* 
	 * If the AP starts the calibration before the base band timeout
	 * completes  we could get rx_clear false triggering.  Add an
	 * extra BASE_ACTIVATE_DELAY usecs to ensure this condition
	 * does not happen.
	 */
	if (IEEE80211_IS_CHAN_HALF(chan)) {
		OS_DELAY((synthDelay << 1) + BASE_ACTIVATE_DELAY);
	} else if (IEEE80211_IS_CHAN_QUARTER(chan)) {
		OS_DELAY((synthDelay << 2) + BASE_ACTIVATE_DELAY);
	} else {
		OS_DELAY(synthDelay + BASE_ACTIVATE_DELAY);
	}
}

static void
ar5416InitIMR(struct ath_hal *ah, HAL_OPMODE opmode)
{
	struct ath_hal_5212 *ahp = AH5212(ah);

	/*
	 * Setup interrupt handling.  Note that ar5212ResetTxQueue
	 * manipulates the secondary IMR's as queues are enabled
	 * and disabled.  This is done with RMW ops to insure the
	 * settings we make here are preserved.
	 */
        ahp->ah_maskReg = AR_IMR_TXERR | AR_IMR_TXURN
			| AR_IMR_RXERR | AR_IMR_RXORN
                        | AR_IMR_BCNMISC;

#ifdef	AH_AR5416_INTERRUPT_MITIGATION
	ahp->ah_maskReg |= AR_IMR_TXINTM | AR_IMR_RXINTM
			|  AR_IMR_TXMINTR | AR_IMR_RXMINTR;
#else
	ahp->ah_maskReg |= AR_IMR_TXOK | AR_IMR_RXOK;
#endif	

	if (opmode == HAL_M_HOSTAP)
		ahp->ah_maskReg |= AR_IMR_MIB;
	OS_REG_WRITE(ah, AR_IMR, ahp->ah_maskReg);

#ifdef  ADRIAN_NOTYET
	/* This is straight from ath9k */
	if (! AR_SREV_HOWL(ah)) {
		OS_REG_WRITE(ah, AR_INTR_SYNC_CAUSE, 0xFFFFFFFF);
		OS_REG_WRITE(ah, AR_INTR_SYNC_ENABLE, AR_INTR_SYNC_DEFAULT);
		OS_REG_WRITE(ah, AR_INTR_SYNC_MASK, 0);
	}
#endif

	/* Enable bus errors that are OR'd to set the HIUERR bit */
#if 0
	OS_REG_WRITE(ah, AR_IMR_S2, 
	    	OS_REG_READ(ah, AR_IMR_S2) | AR_IMR_S2_GTT | AR_IMR_S2_CST);
#endif
}

static void
ar5416InitQoS(struct ath_hal *ah)
{
	/* QoS support */
	OS_REG_WRITE(ah, AR_QOS_CONTROL, 0x100aa);	/* XXX magic */
	OS_REG_WRITE(ah, AR_QOS_SELECT, 0x3210);	/* XXX magic */

	/* Turn on NOACK Support for QoS packets */
	OS_REG_WRITE(ah, AR_NOACK,
		SM(2, AR_NOACK_2BIT_VALUE) |
		SM(5, AR_NOACK_BIT_OFFSET) |
		SM(0, AR_NOACK_BYTE_OFFSET));
		
    	/*
    	 * initialize TXOP for all TIDs
    	 */
	OS_REG_WRITE(ah, AR_TXOP_X, AR_TXOP_X_VAL);
	OS_REG_WRITE(ah, AR_TXOP_0_3, 0xFFFFFFFF);
	OS_REG_WRITE(ah, AR_TXOP_4_7, 0xFFFFFFFF);
	OS_REG_WRITE(ah, AR_TXOP_8_11, 0xFFFFFFFF);
	OS_REG_WRITE(ah, AR_TXOP_12_15, 0xFFFFFFFF);
}

static void
ar5416InitUserSettings(struct ath_hal *ah)
{
	struct ath_hal_5212 *ahp = AH5212(ah);

	/* Restore user-specified settings */
	if (ahp->ah_miscMode != 0)
		OS_REG_WRITE(ah, AR_MISC_MODE, OS_REG_READ(ah, AR_MISC_MODE) | ahp->ah_miscMode);
	if (ahp->ah_sifstime != (u_int) -1)
		ar5212SetSifsTime(ah, ahp->ah_sifstime);
	if (ahp->ah_slottime != (u_int) -1)
		ar5212SetSlotTime(ah, ahp->ah_slottime);
	if (ahp->ah_acktimeout != (u_int) -1)
		ar5212SetAckTimeout(ah, ahp->ah_acktimeout);
	if (ahp->ah_ctstimeout != (u_int) -1)
		ar5212SetCTSTimeout(ah, ahp->ah_ctstimeout);
	if (AH_PRIVATE(ah)->ah_diagreg != 0)
		OS_REG_WRITE(ah, AR_DIAG_SW, AH_PRIVATE(ah)->ah_diagreg);
	if (AH5416(ah)->ah_globaltxtimeout != (u_int) -1)
        	ar5416SetGlobalTxTimeout(ah, AH5416(ah)->ah_globaltxtimeout);
}

static void
ar5416SetRfMode(struct ath_hal *ah, const struct ieee80211_channel *chan)
{
	uint32_t rfMode;

	if (chan == AH_NULL)
		return;

	/* treat channel B as channel G , no  B mode suport in owl */
	rfMode = IEEE80211_IS_CHAN_CCK(chan) ?
	    AR_PHY_MODE_DYNAMIC : AR_PHY_MODE_OFDM;

	if (AR_SREV_MERLIN_20(ah) && IS_5GHZ_FAST_CLOCK_EN(ah, chan)) {
		/* phy mode bits for 5GHz channels require Fast Clock */
		rfMode |= AR_PHY_MODE_DYNAMIC
		       |  AR_PHY_MODE_DYN_CCK_DISABLE;
	} else if (!AR_SREV_MERLIN_10_OR_LATER(ah)) {
		rfMode |= IEEE80211_IS_CHAN_5GHZ(chan) ?
			AR_PHY_MODE_RF5GHZ : AR_PHY_MODE_RF2GHZ;
	}
	OS_REG_WRITE(ah, AR_PHY_MODE, rfMode);
}

/*
 * Places the hardware into reset and then pulls it out of reset
 */
HAL_BOOL
ar5416ChipReset(struct ath_hal *ah, const struct ieee80211_channel *chan)
{
	OS_MARK(ah, AH_MARK_CHIPRESET, chan ? chan->ic_freq : 0);
	/*
	 * Warm reset is optimistic.
	 */
	if (AR_SREV_MERLIN(ah) &&
	    ath_hal_eepromGetFlag(ah, AR_EEP_OL_PWRCTRL)) {
		if (!ar5416SetResetReg(ah, HAL_RESET_POWER_ON))
			return AH_FALSE;
	} else {
		if (!ar5416SetResetReg(ah, HAL_RESET_WARM))
			return AH_FALSE;
	}

	/* Bring out of sleep mode (AGAIN) */
	if (!ar5416SetPowerMode(ah, HAL_PM_AWAKE, AH_TRUE))
	       return AH_FALSE;

#ifdef notyet
	ahp->ah_chipFullSleep = AH_FALSE;
#endif

	AH5416(ah)->ah_initPLL(ah, chan);

	/*
	 * Perform warm reset before the mode/PLL/turbo registers
	 * are changed in order to deactivate the radio.  Mode changes
	 * with an active radio can result in corrupted shifts to the
	 * radio device.
	 */
	ar5416SetRfMode(ah, chan);

	return AH_TRUE;	
}

/*
 * Delta slope coefficient computation.
 * Required for OFDM operation.
 */
static void
ar5416GetDeltaSlopeValues(struct ath_hal *ah, uint32_t coef_scaled,
                          uint32_t *coef_mantissa, uint32_t *coef_exponent)
{
#define COEF_SCALE_S 24
    uint32_t coef_exp, coef_man;
    /*
     * ALGO -> coef_exp = 14-floor(log2(coef));
     * floor(log2(x)) is the highest set bit position
     */
    for (coef_exp = 31; coef_exp > 0; coef_exp--)
            if ((coef_scaled >> coef_exp) & 0x1)
                    break;
    /* A coef_exp of 0 is a legal bit position but an unexpected coef_exp */
    HALASSERT(coef_exp);
    coef_exp = 14 - (coef_exp - COEF_SCALE_S);

    /*
     * ALGO -> coef_man = floor(coef* 2^coef_exp+0.5);
     * The coefficient is already shifted up for scaling
     */
    coef_man = coef_scaled + (1 << (COEF_SCALE_S - coef_exp - 1));

    *coef_mantissa = coef_man >> (COEF_SCALE_S - coef_exp);
    *coef_exponent = coef_exp - 16;

#undef COEF_SCALE_S    
}

void
ar5416SetDeltaSlope(struct ath_hal *ah, const struct ieee80211_channel *chan)
{
#define INIT_CLOCKMHZSCALED	0x64000000
	uint32_t coef_scaled, ds_coef_exp, ds_coef_man;
	uint32_t clockMhzScaled;

	CHAN_CENTERS centers;

	/* half and quarter rate can divide the scaled clock by 2 or 4 respectively */
	/* scale for selected channel bandwidth */ 
	clockMhzScaled = INIT_CLOCKMHZSCALED;
	if (IEEE80211_IS_CHAN_TURBO(chan))
		clockMhzScaled <<= 1;
	else if (IEEE80211_IS_CHAN_HALF(chan))
		clockMhzScaled >>= 1;
	else if (IEEE80211_IS_CHAN_QUARTER(chan))
		clockMhzScaled >>= 2;

	/*
	 * ALGO -> coef = 1e8/fcarrier*fclock/40;
	 * scaled coef to provide precision for this floating calculation 
	 */
	ar5416GetChannelCenters(ah, chan, &centers);
	coef_scaled = clockMhzScaled / centers.synth_center;		

 	ar5416GetDeltaSlopeValues(ah, coef_scaled, &ds_coef_man, &ds_coef_exp);

	OS_REG_RMW_FIELD(ah, AR_PHY_TIMING3,
		AR_PHY_TIMING3_DSC_MAN, ds_coef_man);
	OS_REG_RMW_FIELD(ah, AR_PHY_TIMING3,
		AR_PHY_TIMING3_DSC_EXP, ds_coef_exp);

        /*
         * For Short GI,
         * scaled coeff is 9/10 that of normal coeff
         */ 
        coef_scaled = (9 * coef_scaled)/10;

        ar5416GetDeltaSlopeValues(ah, coef_scaled, &ds_coef_man, &ds_coef_exp);

        /* for short gi */
        OS_REG_RMW_FIELD(ah, AR_PHY_HALFGI,
                AR_PHY_HALFGI_DSC_MAN, ds_coef_man);
        OS_REG_RMW_FIELD(ah, AR_PHY_HALFGI,
                AR_PHY_HALFGI_DSC_EXP, ds_coef_exp);	
#undef INIT_CLOCKMHZSCALED
}

/*
 * Set a limit on the overall output power.  Used for dynamic
 * transmit power control and the like.
 *
 * NB: limit is in units of 0.5 dbM.
 */
HAL_BOOL
ar5416SetTxPowerLimit(struct ath_hal *ah, uint32_t limit)
{
	uint16_t dummyXpdGains[2];

	AH_PRIVATE(ah)->ah_powerLimit = AH_MIN(limit, MAX_RATE_POWER);
	return ah->ah_setTxPower(ah, AH_PRIVATE(ah)->ah_curchan,
			dummyXpdGains);
}

HAL_BOOL
ar5416GetChipPowerLimits(struct ath_hal *ah,
	struct ieee80211_channel *chan)
{
	struct ath_hal_5212 *ahp = AH5212(ah);
	int16_t minPower, maxPower;

	/*
	 * Get Pier table max and min powers.
	 */
	if (ahp->ah_rfHal->getChannelMaxMinPower(ah, chan, &maxPower, &minPower)) {
		/* NB: rf code returns 1/4 dBm units, convert */
		chan->ic_maxpower = maxPower / 2;
		chan->ic_minpower = minPower / 2;
	} else {
		HALDEBUG(ah, HAL_DEBUG_ANY,
		    "%s: no min/max power for %u/0x%x\n",
		    __func__, chan->ic_freq, chan->ic_flags);
		chan->ic_maxpower = AR5416_MAX_RATE_POWER;
		chan->ic_minpower = 0;
	}
	HALDEBUG(ah, HAL_DEBUG_RESET,
	    "Chan %d: MaxPow = %d MinPow = %d\n",
	    chan->ic_freq, chan->ic_maxpower, chan->ic_minpower);
	return AH_TRUE;
}

/**************************************************************
 * ar5416WriteTxPowerRateRegisters
 *
 * Write the TX power rate registers from the raw values given
 * in ratesArray[].
 *
 * The CCK and HT40 rate registers are only written if needed.
 * HT20 and 11g/11a OFDM rate registers are always written.
 *
 * The values written are raw values which should be written
 * to the registers - so it's up to the caller to pre-adjust
 * them (eg CCK power offset value, or Merlin TX power offset,
 * etc.)
 */
void
ar5416WriteTxPowerRateRegisters(struct ath_hal *ah,
    const struct ieee80211_channel *chan, const int16_t ratesArray[])
{
#define POW_SM(_r, _s)     (((_r) & 0x3f) << (_s))

    /* Write the OFDM power per rate set */
    OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE1,
        POW_SM(ratesArray[rate18mb], 24)
          | POW_SM(ratesArray[rate12mb], 16)
          | POW_SM(ratesArray[rate9mb], 8)
          | POW_SM(ratesArray[rate6mb], 0)
    );
    OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE2,
        POW_SM(ratesArray[rate54mb], 24)
          | POW_SM(ratesArray[rate48mb], 16)
          | POW_SM(ratesArray[rate36mb], 8)
          | POW_SM(ratesArray[rate24mb], 0)
    );

    if (IEEE80211_IS_CHAN_2GHZ(chan)) {
        /* Write the CCK power per rate set */
        OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE3,
            POW_SM(ratesArray[rate2s], 24)
              | POW_SM(ratesArray[rate2l],  16)
              | POW_SM(ratesArray[rateXr],  8) /* XR target power */
              | POW_SM(ratesArray[rate1l],   0)
        );
        OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE4,
            POW_SM(ratesArray[rate11s], 24)
              | POW_SM(ratesArray[rate11l], 16)
              | POW_SM(ratesArray[rate5_5s], 8)
              | POW_SM(ratesArray[rate5_5l], 0)
        );
    HALDEBUG(ah, HAL_DEBUG_RESET,
	"%s AR_PHY_POWER_TX_RATE3=0x%x AR_PHY_POWER_TX_RATE4=0x%x\n",
	    __func__, OS_REG_READ(ah,AR_PHY_POWER_TX_RATE3),
	    OS_REG_READ(ah,AR_PHY_POWER_TX_RATE4)); 
    }

    /* Write the HT20 power per rate set */
    OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE5,
        POW_SM(ratesArray[rateHt20_3], 24)
          | POW_SM(ratesArray[rateHt20_2], 16)
          | POW_SM(ratesArray[rateHt20_1], 8)
          | POW_SM(ratesArray[rateHt20_0], 0)
    );
    OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE6,
        POW_SM(ratesArray[rateHt20_7], 24)
          | POW_SM(ratesArray[rateHt20_6], 16)
          | POW_SM(ratesArray[rateHt20_5], 8)
          | POW_SM(ratesArray[rateHt20_4], 0)
    );

    if (IEEE80211_IS_CHAN_HT40(chan)) {
        /* Write the HT40 power per rate set */
        OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE7,
            POW_SM(ratesArray[rateHt40_3], 24)
              | POW_SM(ratesArray[rateHt40_2], 16)
              | POW_SM(ratesArray[rateHt40_1], 8)
              | POW_SM(ratesArray[rateHt40_0], 0)
        );
        OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE8,
            POW_SM(ratesArray[rateHt40_7], 24)
              | POW_SM(ratesArray[rateHt40_6], 16)
              | POW_SM(ratesArray[rateHt40_5], 8)
              | POW_SM(ratesArray[rateHt40_4], 0)
        );
        /* Write the Dup/Ext 40 power per rate set */
        OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE9,
            POW_SM(ratesArray[rateExtOfdm], 24)
              | POW_SM(ratesArray[rateExtCck], 16)
              | POW_SM(ratesArray[rateDupOfdm], 8)
              | POW_SM(ratesArray[rateDupCck], 0)
        );
    }
}


/**************************************************************
 * ar5416SetTransmitPower
 *
 * Set the transmit power in the baseband for the given
 * operating channel and mode.
 */
HAL_BOOL
ar5416SetTransmitPower(struct ath_hal *ah,
	const struct ieee80211_channel *chan, uint16_t *rfXpdGain)
{
#define N(a)            (sizeof (a) / sizeof (a[0]))

    MODAL_EEP_HEADER	*pModal;
    struct ath_hal_5212 *ahp = AH5212(ah);
    int16_t		ratesArray[Ar5416RateSize];
    int16_t		txPowerIndexOffset = 0;
    uint8_t		ht40PowerIncForPdadc = 2;	
    int			i;
    
    uint16_t		cfgCtl;
    uint16_t		powerLimit;
    uint16_t		twiceAntennaReduction;
    uint16_t		twiceMaxRegulatoryPower;
    int16_t		maxPower;
    HAL_EEPROM_v14 *ee = AH_PRIVATE(ah)->ah_eeprom;
    struct ar5416eeprom	*pEepData = &ee->ee_base;

    HALASSERT(AH_PRIVATE(ah)->ah_eeversion >= AR_EEPROM_VER14_1);

    /* Setup info for the actual eeprom */
    OS_MEMZERO(ratesArray, sizeof(ratesArray));
    cfgCtl = ath_hal_getctl(ah, chan);
    powerLimit = chan->ic_maxregpower * 2;
    twiceAntennaReduction = chan->ic_maxantgain;
    twiceMaxRegulatoryPower = AH_MIN(MAX_RATE_POWER, AH_PRIVATE(ah)->ah_powerLimit); 
    pModal = &pEepData->modalHeader[IEEE80211_IS_CHAN_2GHZ(chan)];
    HALDEBUG(ah, HAL_DEBUG_RESET, "%s Channel=%u CfgCtl=%u\n",
	__func__,chan->ic_freq, cfgCtl );      
  
    if (IS_EEP_MINOR_V2(ah)) {
        ht40PowerIncForPdadc = pModal->ht40PowerIncForPdadc;
    }
 
    if (!ar5416SetPowerPerRateTable(ah, pEepData,  chan,
                                    &ratesArray[0],cfgCtl,
                                    twiceAntennaReduction,
				    twiceMaxRegulatoryPower, powerLimit)) {
        HALDEBUG(ah, HAL_DEBUG_ANY,
	    "%s: unable to set tx power per rate table\n", __func__);
        return AH_FALSE;
    }

    if (!AH5416(ah)->ah_setPowerCalTable(ah,  pEepData, chan, &txPowerIndexOffset)) {
        HALDEBUG(ah, HAL_DEBUG_ANY, "%s: unable to set power table\n",
	    __func__);
        return AH_FALSE;
    }
  
    maxPower = AH_MAX(ratesArray[rate6mb], ratesArray[rateHt20_0]);

    if (IEEE80211_IS_CHAN_2GHZ(chan)) {
        maxPower = AH_MAX(maxPower, ratesArray[rate1l]);
    }

    if (IEEE80211_IS_CHAN_HT40(chan)) {
        maxPower = AH_MAX(maxPower, ratesArray[rateHt40_0]);
    }

    ahp->ah_tx6PowerInHalfDbm = maxPower;   
    AH_PRIVATE(ah)->ah_maxPowerLevel = maxPower;
    ahp->ah_txPowerIndexOffset = txPowerIndexOffset;

    /*
     * txPowerIndexOffset is set by the SetPowerTable() call -
     *  adjust the rate table (0 offset if rates EEPROM not loaded)
     */
    for (i = 0; i < N(ratesArray); i++) {
        ratesArray[i] = (int16_t)(txPowerIndexOffset + ratesArray[i]);
        if (ratesArray[i] > AR5416_MAX_RATE_POWER)
            ratesArray[i] = AR5416_MAX_RATE_POWER;
    }

#ifdef AH_EEPROM_DUMP
    /*
     * Dump the rate array whilst it represents the intended dBm*2
     * values versus what's being adjusted before being programmed
     * in. Keep this in mind if you code up this function and enable
     * this debugging; the values won't necessarily be what's being
     * programmed into the hardware.
     */
    ar5416PrintPowerPerRate(ah, ratesArray);
#endif

    /*
     * Merlin and later have a power offset, so subtract
     * pwr_table_offset * 2 from each value. The default
     * power offset is -5 dBm - ie, a register value of 0
     * equates to a TX power of -5 dBm.
     */
    if (AR_SREV_MERLIN_20_OR_LATER(ah)) {
        int8_t pwr_table_offset;

	(void) ath_hal_eepromGet(ah, AR_EEP_PWR_TABLE_OFFSET,
	    &pwr_table_offset);
	/* Underflow power gets clamped at raw value 0 */
	/* Overflow power gets camped at AR5416_MAX_RATE_POWER */
	for (i = 0; i < N(ratesArray); i++) {
		/*
		 * + pwr_table_offset is in dBm
		 * + ratesArray is in 1/2 dBm
		 */
		ratesArray[i] -= (pwr_table_offset * 2);
		if (ratesArray[i] < 0)
			ratesArray[i] = 0;
		else if (ratesArray[i] > AR5416_MAX_RATE_POWER)
		    ratesArray[i] = AR5416_MAX_RATE_POWER;
	}
    }

    /*
     * Adjust rates for OLC where needed
     *
     * The following CCK rates need adjusting when doing 2.4ghz
     * CCK transmission.
     *
     * + rate2s, rate2l, rate1l, rate11s, rate11l, rate5_5s, rate5_5l
     * + rateExtCck, rateDupCck
     *
     * They're adjusted here regardless. The hardware then gets
     * programmed as needed. 5GHz operation doesn't program in CCK
     * rates for legacy mode but they seem to be initialised for
     * HT40 regardless of channel type.
     */
    if (AR_SREV_MERLIN_20_OR_LATER(ah) &&
	    ath_hal_eepromGetFlag(ah, AR_EEP_OL_PWRCTRL)) {
        int adj[] = {
	              rate2s, rate2l, rate1l, rate11s, rate11l,
	              rate5_5s, rate5_5l, rateExtCck, rateDupCck
		    };
        int cck_ofdm_delta = 2;
	int i;
	for (i = 0; i < N(adj); i++) {
            ratesArray[adj[i]] -= cck_ofdm_delta;
	    if (ratesArray[adj[i]] < 0)
	        ratesArray[adj[i]] = 0;
        }
    }

    /*
     * Adjust the HT40 power to meet the correct target TX power
     * for 40MHz mode, based on TX power curves that are established
     * for 20MHz mode.
     *
     * XXX handle overflow/too high power level?
     */
    if (IEEE80211_IS_CHAN_HT40(chan)) {
	ratesArray[rateHt40_0] += ht40PowerIncForPdadc;
	ratesArray[rateHt40_1] += ht40PowerIncForPdadc;
	ratesArray[rateHt40_2] += ht40PowerIncForPdadc;
	ratesArray[rateHt40_3] += ht40PowerIncForPdadc;
	ratesArray[rateHt40_4] += ht40PowerIncForPdadc;
	ratesArray[rateHt40_5] += ht40PowerIncForPdadc;
	ratesArray[rateHt40_6] += ht40PowerIncForPdadc;
	ratesArray[rateHt40_7] += ht40PowerIncForPdadc;
    }

    /* Write the TX power rate registers */
    ar5416WriteTxPowerRateRegisters(ah, chan, ratesArray);

    /* Write the Power subtraction for dynamic chain changing, for per-packet powertx */
    OS_REG_WRITE(ah, AR_PHY_POWER_TX_SUB,
        POW_SM(pModal->pwrDecreaseFor3Chain, 6)
          | POW_SM(pModal->pwrDecreaseFor2Chain, 0)
    );
    return AH_TRUE;
#undef POW_SM
#undef N
}

/*
 * Exported call to check for a recent gain reading and return
 * the current state of the thermal calibration gain engine.
 */
HAL_RFGAIN
ar5416GetRfgain(struct ath_hal *ah)
{
	return HAL_RFGAIN_INACTIVE;
}

/*
 * Places all of hardware into reset
 */
HAL_BOOL
ar5416Disable(struct ath_hal *ah)
{
	if (!ar5212SetPowerMode(ah, HAL_PM_AWAKE, AH_TRUE))
		return AH_FALSE;
	if (! ar5416SetResetReg(ah, HAL_RESET_COLD))
		return AH_FALSE;

	AH5416(ah)->ah_initPLL(ah, AH_NULL);
	return AH_TRUE;
}

/*
 * Places the PHY and Radio chips into reset.  A full reset
 * must be called to leave this state.  The PCI/MAC/PCU are
 * not placed into reset as we must receive interrupt to
 * re-enable the hardware.
 */
HAL_BOOL
ar5416PhyDisable(struct ath_hal *ah)
{
	if (! ar5416SetResetReg(ah, HAL_RESET_WARM))
		return AH_FALSE;

	AH5416(ah)->ah_initPLL(ah, AH_NULL);
	return AH_TRUE;
}

/*
 * Write the given reset bit mask into the reset register
 */
HAL_BOOL
ar5416SetResetReg(struct ath_hal *ah, uint32_t type)
{
	switch (type) {
	case HAL_RESET_POWER_ON:
		return ar5416SetResetPowerOn(ah);
	case HAL_RESET_WARM:
	case HAL_RESET_COLD:
		return ar5416SetReset(ah, type);
	default:
		HALASSERT(AH_FALSE);
		return AH_FALSE;
	}
}

static HAL_BOOL
ar5416SetResetPowerOn(struct ath_hal *ah)
{
    /* Power On Reset (Hard Reset) */

    /*
     * Set force wake
     *	
     * If the MAC was running, previously calling
     * reset will wake up the MAC but it may go back to sleep
     * before we can start polling. 
     * Set force wake  stops that 
     * This must be called before initiating a hard reset.
     */
    OS_REG_WRITE(ah, AR_RTC_FORCE_WAKE,
            AR_RTC_FORCE_WAKE_EN | AR_RTC_FORCE_WAKE_ON_INT);    

    /*
     * RTC reset and clear
     */
    if (! AR_SREV_HOWL(ah))
    	OS_REG_WRITE(ah, AR_RC, AR_RC_AHB);
    OS_REG_WRITE(ah, AR_RTC_RESET, 0);
    OS_DELAY(20);

    if (! AR_SREV_HOWL(ah))
    	OS_REG_WRITE(ah, AR_RC, 0);

    OS_REG_WRITE(ah, AR_RTC_RESET, 1);

    /*
     * Poll till RTC is ON
     */
    if (!ath_hal_wait(ah, AR_RTC_STATUS, AR_RTC_PM_STATUS_M, AR_RTC_STATUS_ON)) {
        HALDEBUG(ah, HAL_DEBUG_ANY, "%s: RTC not waking up\n", __func__);
        return AH_FALSE;
    }

    return ar5416SetReset(ah, HAL_RESET_COLD);
}

static HAL_BOOL
ar5416SetReset(struct ath_hal *ah, int type)
{
    uint32_t tmpReg, mask;
    uint32_t rst_flags;

#ifdef	AH_SUPPORT_AR9130	/* Because of the AR9130 specific registers */
    if (AR_SREV_HOWL(ah)) {
        HALDEBUG(ah, HAL_DEBUG_ANY, "[ath] HOWL: Fiddling with derived clk!\n");
        uint32_t val = OS_REG_READ(ah, AR_RTC_DERIVED_CLK);
        val &= ~AR_RTC_DERIVED_CLK_PERIOD;
        val |= SM(1, AR_RTC_DERIVED_CLK_PERIOD);
        OS_REG_WRITE(ah, AR_RTC_DERIVED_CLK, val);
        (void) OS_REG_READ(ah, AR_RTC_DERIVED_CLK);
    }
#endif	/* AH_SUPPORT_AR9130 */

    /*
     * Force wake
     */
    OS_REG_WRITE(ah, AR_RTC_FORCE_WAKE,
	AR_RTC_FORCE_WAKE_EN | AR_RTC_FORCE_WAKE_ON_INT);

#ifdef	AH_SUPPORT_AR9130
    if (AR_SREV_HOWL(ah)) {
        rst_flags = AR_RTC_RC_MAC_WARM | AR_RTC_RC_MAC_COLD |
          AR_RTC_RC_COLD_RESET | AR_RTC_RC_WARM_RESET;
    } else {
#endif	/* AH_SUPPORT_AR9130 */
        /*
         * Reset AHB
         */
        tmpReg = OS_REG_READ(ah, AR_INTR_SYNC_CAUSE);
        if (tmpReg & (AR_INTR_SYNC_LOCAL_TIMEOUT|AR_INTR_SYNC_RADM_CPL_TIMEOUT)) {
            OS_REG_WRITE(ah, AR_INTR_SYNC_ENABLE, 0);
            OS_REG_WRITE(ah, AR_RC, AR_RC_AHB|AR_RC_HOSTIF);
        } else {
	    OS_REG_WRITE(ah, AR_RC, AR_RC_AHB);
        }
        rst_flags = AR_RTC_RC_MAC_WARM;
        if (type == HAL_RESET_COLD)
            rst_flags |= AR_RTC_RC_MAC_COLD;
#ifdef	AH_SUPPORT_AR9130
    }
#endif	/* AH_SUPPORT_AR9130 */

    OS_REG_WRITE(ah, AR_RTC_RC, rst_flags);

    if (AR_SREV_HOWL(ah))
        OS_DELAY(10000);
    else
        OS_DELAY(100);

    /*
     * Clear resets and force wakeup
     */
    OS_REG_WRITE(ah, AR_RTC_RC, 0);
    if (!ath_hal_wait(ah, AR_RTC_RC, AR_RTC_RC_M, 0)) {
        HALDEBUG(ah, HAL_DEBUG_ANY, "%s: RTC stuck in MAC reset\n", __func__);
        return AH_FALSE;
    }

    /* Clear AHB reset */
    if (! AR_SREV_HOWL(ah))
        OS_REG_WRITE(ah, AR_RC, 0);

    if (AR_SREV_HOWL(ah))
        OS_DELAY(50);

    if (AR_SREV_HOWL(ah)) {
                uint32_t mask;
                mask = OS_REG_READ(ah, AR_CFG);
                if (mask & (AR_CFG_SWRB | AR_CFG_SWTB | AR_CFG_SWRG)) {
                        HALDEBUG(ah, HAL_DEBUG_RESET,
                                "CFG Byte Swap Set 0x%x\n", mask);
                } else {
                        mask =  
                                INIT_CONFIG_STATUS | AR_CFG_SWRB | AR_CFG_SWTB;
                        OS_REG_WRITE(ah, AR_CFG, mask);
                        HALDEBUG(ah, HAL_DEBUG_RESET,
                                "Setting CFG 0x%x\n", OS_REG_READ(ah, AR_CFG));
                }
    } else {
	if (type == HAL_RESET_COLD) {
		if (isBigEndian()) {
			/*
			 * Set CFG, little-endian for register
			 * and descriptor accesses.
			 */
			mask = INIT_CONFIG_STATUS | AR_CFG_SWRD | AR_CFG_SWRG;
#ifndef AH_NEED_DESC_SWAP
			mask |= AR_CFG_SWTD;
#endif
			HALDEBUG(ah, HAL_DEBUG_RESET,
			    "%s Applying descriptor swap\n", __func__);
			OS_REG_WRITE(ah, AR_CFG, LE_READ_4(&mask));
		} else
			OS_REG_WRITE(ah, AR_CFG, INIT_CONFIG_STATUS);
	}
    }

    return AH_TRUE;
}

void
ar5416InitChainMasks(struct ath_hal *ah)
{
	int rx_chainmask = AH5416(ah)->ah_rx_chainmask;

	/* Flip this for this chainmask regardless of chip */
	if (rx_chainmask == 0x5)
		OS_REG_SET_BIT(ah, AR_PHY_ANALOG_SWAP, AR_PHY_SWAP_ALT_CHAIN);

	/*
	 * Workaround for OWL 1.0 calibration failure; enable multi-chain;
	 * then set true mask after calibration.
	 */
	if (IS_5416V1(ah) && (rx_chainmask == 0x5 || rx_chainmask == 0x3)) {
		OS_REG_WRITE(ah, AR_PHY_RX_CHAINMASK, 0x7);
		OS_REG_WRITE(ah, AR_PHY_CAL_CHAINMASK, 0x7);
	} else {
		OS_REG_WRITE(ah, AR_PHY_RX_CHAINMASK, AH5416(ah)->ah_rx_chainmask);
		OS_REG_WRITE(ah, AR_PHY_CAL_CHAINMASK, AH5416(ah)->ah_rx_chainmask);
	}
	OS_REG_WRITE(ah, AR_SELFGEN_MASK, AH5416(ah)->ah_tx_chainmask);

	if (AH5416(ah)->ah_tx_chainmask == 0x5)
		OS_REG_SET_BIT(ah, AR_PHY_ANALOG_SWAP, AR_PHY_SWAP_ALT_CHAIN);

	if (AR_SREV_HOWL(ah)) {
		OS_REG_WRITE(ah, AR_PHY_ANALOG_SWAP,
		OS_REG_READ(ah, AR_PHY_ANALOG_SWAP) | 0x00000001);
	}
}

/*
 * Work-around for Owl 1.0 calibration failure.
 *
 * ar5416InitChainMasks sets the RX chainmask to 0x7 if it's Owl 1.0
 * due to init calibration failures. ar5416RestoreChainMask restores
 * these registers to the correct setting.
 */
void
ar5416RestoreChainMask(struct ath_hal *ah)
{
	int rx_chainmask = AH5416(ah)->ah_rx_chainmask;

	if (IS_5416V1(ah) && (rx_chainmask == 0x5 || rx_chainmask == 0x3)) {
		OS_REG_WRITE(ah, AR_PHY_RX_CHAINMASK, rx_chainmask);
		OS_REG_WRITE(ah, AR_PHY_CAL_CHAINMASK, rx_chainmask);
	}
}

/*
 * Update the chainmask based on the current channel configuration.
 *
 * XXX ath9k checks bluetooth co-existence here
 * XXX ath9k checks whether the current state is "off-channel".
 * XXX ath9k sticks the hardware into 1x1 mode for legacy;
 *     we're going to leave multi-RX on for multi-path cancellation.
 */
static void
ar5416UpdateChainMasks(struct ath_hal *ah, HAL_BOOL is_ht)
{
	struct ath_hal_private *ahpriv = AH_PRIVATE(ah);
	HAL_CAPABILITIES *pCap = &ahpriv->ah_caps;

	if (is_ht) {
		AH5416(ah)->ah_tx_chainmask = pCap->halTxChainMask;
	} else {
		AH5416(ah)->ah_tx_chainmask = 1;
	}
	AH5416(ah)->ah_rx_chainmask = pCap->halRxChainMask;
	HALDEBUG(ah, HAL_DEBUG_RESET, "TX chainmask: 0x%x; RX chainmask: 0x%x\n",
	    AH5416(ah)->ah_tx_chainmask,
	    AH5416(ah)->ah_rx_chainmask);
}

void
ar5416InitPLL(struct ath_hal *ah, const struct ieee80211_channel *chan)
{
	uint32_t pll;

	if (AR_SREV_MERLIN_20(ah) &&
	    chan != AH_NULL && IEEE80211_IS_CHAN_5GHZ(chan)) {
		/*
		 * PLL WAR for Merlin 2.0/2.1
		 * When doing fast clock, set PLL to 0x142c
		 * Else, set PLL to 0x2850 to prevent reset-to-reset variation 
		 */
		pll = IS_5GHZ_FAST_CLOCK_EN(ah, chan) ? 0x142c : 0x2850;
	} else if (AR_SREV_MERLIN_10_OR_LATER(ah)) {
		pll = SM(0x5, AR_RTC_SOWL_PLL_REFDIV);
		if (chan != AH_NULL) {
			if (IEEE80211_IS_CHAN_HALF(chan))
				pll |= SM(0x1, AR_RTC_SOWL_PLL_CLKSEL);
			else if (IEEE80211_IS_CHAN_QUARTER(chan))
				pll |= SM(0x2, AR_RTC_SOWL_PLL_CLKSEL);

			if (IEEE80211_IS_CHAN_5GHZ(chan))
				pll |= SM(0x28, AR_RTC_SOWL_PLL_DIV);
			else
				pll |= SM(0x2c, AR_RTC_SOWL_PLL_DIV);

		} else
			pll |= SM(0x2c, AR_RTC_SOWL_PLL_DIV);
	} else if (AR_SREV_SOWL_10_OR_LATER(ah)) {
		pll = SM(0x5, AR_RTC_SOWL_PLL_REFDIV);
		if (chan != AH_NULL) {
			if (IEEE80211_IS_CHAN_HALF(chan))
				pll |= SM(0x1, AR_RTC_SOWL_PLL_CLKSEL);
			else if (IEEE80211_IS_CHAN_QUARTER(chan))
				pll |= SM(0x2, AR_RTC_SOWL_PLL_CLKSEL);

			if (IEEE80211_IS_CHAN_5GHZ(chan))
				pll |= SM(0x50, AR_RTC_SOWL_PLL_DIV);
			else
				pll |= SM(0x58, AR_RTC_SOWL_PLL_DIV);
		} else
			pll |= SM(0x58, AR_RTC_SOWL_PLL_DIV);
	} else {
		pll = AR_RTC_PLL_REFDIV_5 | AR_RTC_PLL_DIV2;
		if (chan != AH_NULL) {
			if (IEEE80211_IS_CHAN_HALF(chan))
				pll |= SM(0x1, AR_RTC_PLL_CLKSEL);
			else if (IEEE80211_IS_CHAN_QUARTER(chan))
				pll |= SM(0x2, AR_RTC_PLL_CLKSEL);

			if (IEEE80211_IS_CHAN_5GHZ(chan))
				pll |= SM(0xa, AR_RTC_PLL_DIV);
			else
				pll |= SM(0xb, AR_RTC_PLL_DIV);
		} else
			pll |= SM(0xb, AR_RTC_PLL_DIV);
	}
	OS_REG_WRITE(ah, AR_RTC_PLL_CONTROL, pll);

	/* TODO:
	* For multi-band owl, switch between bands by reiniting the PLL.
	*/

	OS_DELAY(RTC_PLL_SETTLE_DELAY);

	OS_REG_WRITE(ah, AR_RTC_SLEEP_CLK, AR_RTC_SLEEP_DERIVED_CLK);
}

static void
ar5416SetDefGainValues(struct ath_hal *ah,
    const MODAL_EEP_HEADER *pModal,
    const struct ar5416eeprom *eep,
    uint8_t txRxAttenLocal, int regChainOffset, int i)
{
	if (IS_EEP_MINOR_V3(ah)) {
		txRxAttenLocal = pModal->txRxAttenCh[i];

		if (AR_SREV_MERLIN_10_OR_LATER(ah)) {
			OS_REG_RMW_FIELD(ah, AR_PHY_GAIN_2GHZ + regChainOffset,
			      AR_PHY_GAIN_2GHZ_XATTEN1_MARGIN,
			      pModal->bswMargin[i]);
			OS_REG_RMW_FIELD(ah, AR_PHY_GAIN_2GHZ + regChainOffset,
			      AR_PHY_GAIN_2GHZ_XATTEN1_DB,
			      pModal->bswAtten[i]);
			OS_REG_RMW_FIELD(ah, AR_PHY_GAIN_2GHZ + regChainOffset,
			      AR_PHY_GAIN_2GHZ_XATTEN2_MARGIN,
			      pModal->xatten2Margin[i]);
			OS_REG_RMW_FIELD(ah, AR_PHY_GAIN_2GHZ + regChainOffset,
			      AR_PHY_GAIN_2GHZ_XATTEN2_DB,
			      pModal->xatten2Db[i]);
		} else {
			OS_REG_RMW_FIELD(ah, AR_PHY_GAIN_2GHZ + regChainOffset,
			      AR_PHY_GAIN_2GHZ_BSW_MARGIN,
			      pModal->bswMargin[i]);
			OS_REG_RMW_FIELD(ah, AR_PHY_GAIN_2GHZ + regChainOffset,
			      AR_PHY_GAIN_2GHZ_BSW_ATTEN,
			      pModal->bswAtten[i]);
		}
	}

	if (AR_SREV_MERLIN_10_OR_LATER(ah)) {
		OS_REG_RMW_FIELD(ah,
		      AR_PHY_RXGAIN + regChainOffset,
		      AR9280_PHY_RXGAIN_TXRX_ATTEN, txRxAttenLocal);
		OS_REG_RMW_FIELD(ah,
		      AR_PHY_RXGAIN + regChainOffset,
		      AR9280_PHY_RXGAIN_TXRX_MARGIN, pModal->rxTxMarginCh[i]);
	} else {
		OS_REG_RMW_FIELD(ah,
			  AR_PHY_RXGAIN + regChainOffset,
			  AR_PHY_RXGAIN_TXRX_ATTEN, txRxAttenLocal);
		OS_REG_RMW_FIELD(ah,
			  AR_PHY_GAIN_2GHZ + regChainOffset,
			  AR_PHY_GAIN_2GHZ_RXTX_MARGIN, pModal->rxTxMarginCh[i]);
	}
}

/*
 * Get the register chain offset for the given chain.
 *
 * Take into account the register chain swapping with AR5416 v2.0.
 *
 * XXX make sure that the reg chain swapping is only done for
 * XXX AR5416 v2.0 or greater, and not later chips?
 */
int
ar5416GetRegChainOffset(struct ath_hal *ah, int i)
{
	int regChainOffset;

	if (AR_SREV_5416_V20_OR_LATER(ah) && 
	    (AH5416(ah)->ah_rx_chainmask == 0x5 ||
	    AH5416(ah)->ah_tx_chainmask == 0x5) && (i != 0)) {
		/* Regs are swapped from chain 2 to 1 for 5416 2_0 with 
		 * only chains 0 and 2 populated 
		 */
		regChainOffset = (i == 1) ? 0x2000 : 0x1000;
	} else {
		regChainOffset = i * 0x1000;
	}

	return regChainOffset;
}

/*
 * Read EEPROM header info and program the device for correct operation
 * given the channel value.
 */
HAL_BOOL
ar5416SetBoardValues(struct ath_hal *ah, const struct ieee80211_channel *chan)
{
    const HAL_EEPROM_v14 *ee = AH_PRIVATE(ah)->ah_eeprom;
    const struct ar5416eeprom *eep = &ee->ee_base;
    const MODAL_EEP_HEADER *pModal;
    int			i, regChainOffset;
    uint8_t		txRxAttenLocal;    /* workaround for eeprom versions <= 14.2 */

    HALASSERT(AH_PRIVATE(ah)->ah_eeversion >= AR_EEPROM_VER14_1);
    pModal = &eep->modalHeader[IEEE80211_IS_CHAN_2GHZ(chan)];

    /* NB: workaround for eeprom versions <= 14.2 */
    txRxAttenLocal = IEEE80211_IS_CHAN_2GHZ(chan) ? 23 : 44;

    OS_REG_WRITE(ah, AR_PHY_SWITCH_COM, pModal->antCtrlCommon);
    for (i = 0; i < AR5416_MAX_CHAINS; i++) { 
	   if (AR_SREV_MERLIN(ah)) {
		if (i >= 2) break;
	   }
	regChainOffset = ar5416GetRegChainOffset(ah, i);

        OS_REG_WRITE(ah, AR_PHY_SWITCH_CHAIN_0 + regChainOffset, pModal->antCtrlChain[i]);

        OS_REG_WRITE(ah, AR_PHY_TIMING_CTRL4 + regChainOffset, 
        	(OS_REG_READ(ah, AR_PHY_TIMING_CTRL4 + regChainOffset) &
        	~(AR_PHY_TIMING_CTRL4_IQCORR_Q_Q_COFF | AR_PHY_TIMING_CTRL4_IQCORR_Q_I_COFF)) |
        	SM(pModal->iqCalICh[i], AR_PHY_TIMING_CTRL4_IQCORR_Q_I_COFF) |
        	SM(pModal->iqCalQCh[i], AR_PHY_TIMING_CTRL4_IQCORR_Q_Q_COFF));

        /*
         * Large signal upgrade,
	 * If 14.3 or later EEPROM, use
	 * txRxAttenLocal = pModal->txRxAttenCh[i]
	 * else txRxAttenLocal is fixed value above.
         */

        if ((i == 0) || AR_SREV_5416_V20_OR_LATER(ah))
	    ar5416SetDefGainValues(ah, pModal, eep, txRxAttenLocal, regChainOffset, i);

    }

	if (AR_SREV_MERLIN_10_OR_LATER(ah)) {
                if (IEEE80211_IS_CHAN_2GHZ(chan)) {
                        OS_A_REG_RMW_FIELD(ah, AR_AN_RF2G1_CH0, AR_AN_RF2G1_CH0_OB, pModal->ob);
                        OS_A_REG_RMW_FIELD(ah, AR_AN_RF2G1_CH0, AR_AN_RF2G1_CH0_DB, pModal->db);
                        OS_A_REG_RMW_FIELD(ah, AR_AN_RF2G1_CH1, AR_AN_RF2G1_CH1_OB, pModal->ob_ch1);
                        OS_A_REG_RMW_FIELD(ah, AR_AN_RF2G1_CH1, AR_AN_RF2G1_CH1_DB, pModal->db_ch1);
                } else {
                        OS_A_REG_RMW_FIELD(ah, AR_AN_RF5G1_CH0, AR_AN_RF5G1_CH0_OB5, pModal->ob);
                        OS_A_REG_RMW_FIELD(ah, AR_AN_RF5G1_CH0, AR_AN_RF5G1_CH0_DB5, pModal->db);
                        OS_A_REG_RMW_FIELD(ah, AR_AN_RF5G1_CH1, AR_AN_RF5G1_CH1_OB5, pModal->ob_ch1);
                        OS_A_REG_RMW_FIELD(ah, AR_AN_RF5G1_CH1, AR_AN_RF5G1_CH1_DB5, pModal->db_ch1);
                }
                OS_A_REG_RMW_FIELD(ah, AR_AN_TOP2, AR_AN_TOP2_XPABIAS_LVL, pModal->xpaBiasLvl);
                OS_A_REG_RMW_FIELD(ah, AR_AN_TOP2, AR_AN_TOP2_LOCALBIAS,
		    !!(pModal->flagBits & AR5416_EEP_FLAG_LOCALBIAS));
                OS_A_REG_RMW_FIELD(ah, AR_PHY_XPA_CFG, AR_PHY_FORCE_XPA_CFG,
		    !!(pModal->flagBits & AR5416_EEP_FLAG_FORCEXPAON));
        }

    OS_REG_RMW_FIELD(ah, AR_PHY_SETTLING, AR_PHY_SETTLING_SWITCH, pModal->switchSettling);
    OS_REG_RMW_FIELD(ah, AR_PHY_DESIRED_SZ, AR_PHY_DESIRED_SZ_ADC, pModal->adcDesiredSize);

    if (! AR_SREV_MERLIN_10_OR_LATER(ah))
    	OS_REG_RMW_FIELD(ah, AR_PHY_DESIRED_SZ, AR_PHY_DESIRED_SZ_PGA, pModal->pgaDesiredSize);

    OS_REG_WRITE(ah, AR_PHY_RF_CTL4,
        SM(pModal->txEndToXpaOff, AR_PHY_RF_CTL4_TX_END_XPAA_OFF)
        | SM(pModal->txEndToXpaOff, AR_PHY_RF_CTL4_TX_END_XPAB_OFF)
        | SM(pModal->txFrameToXpaOn, AR_PHY_RF_CTL4_FRAME_XPAA_ON)
        | SM(pModal->txFrameToXpaOn, AR_PHY_RF_CTL4_FRAME_XPAB_ON));

    OS_REG_RMW_FIELD(ah, AR_PHY_RF_CTL3, AR_PHY_TX_END_TO_A2_RX_ON,
	pModal->txEndToRxOn);

    if (AR_SREV_MERLIN_10_OR_LATER(ah)) {
	OS_REG_RMW_FIELD(ah, AR_PHY_CCA, AR9280_PHY_CCA_THRESH62,
	    pModal->thresh62);
	OS_REG_RMW_FIELD(ah, AR_PHY_EXT_CCA0, AR_PHY_EXT_CCA0_THRESH62,
	    pModal->thresh62);
    } else {
	OS_REG_RMW_FIELD(ah, AR_PHY_CCA, AR_PHY_CCA_THRESH62,
	    pModal->thresh62);
	OS_REG_RMW_FIELD(ah, AR_PHY_EXT_CCA, AR_PHY_EXT_CCA_THRESH62,
	    pModal->thresh62);
    }
    
    /* Minor Version Specific application */
    if (IS_EEP_MINOR_V2(ah)) {
        OS_REG_RMW_FIELD(ah, AR_PHY_RF_CTL2, AR_PHY_TX_FRAME_TO_DATA_START,
	    pModal->txFrameToDataStart);
        OS_REG_RMW_FIELD(ah, AR_PHY_RF_CTL2, AR_PHY_TX_FRAME_TO_PA_ON,
	    pModal->txFrameToPaOn);    
    }	

    if (IS_EEP_MINOR_V3(ah) && IEEE80211_IS_CHAN_HT40(chan))
		/* Overwrite switch settling with HT40 value */
		OS_REG_RMW_FIELD(ah, AR_PHY_SETTLING, AR_PHY_SETTLING_SWITCH,
		    pModal->swSettleHt40);

    if (AR_SREV_MERLIN_20_OR_LATER(ah) && EEP_MINOR(ah) >= AR5416_EEP_MINOR_VER_19)
         OS_REG_RMW_FIELD(ah, AR_PHY_CCK_TX_CTRL, AR_PHY_CCK_TX_CTRL_TX_DAC_SCALE_CCK, pModal->miscBits);

        if (AR_SREV_MERLIN_20(ah) && EEP_MINOR(ah) >= AR5416_EEP_MINOR_VER_20) {
                if (IEEE80211_IS_CHAN_2GHZ(chan))
                        OS_A_REG_RMW_FIELD(ah, AR_AN_TOP1, AR_AN_TOP1_DACIPMODE,
			    eep->baseEepHeader.dacLpMode);
                else if (eep->baseEepHeader.dacHiPwrMode_5G)
                        OS_A_REG_RMW_FIELD(ah, AR_AN_TOP1, AR_AN_TOP1_DACIPMODE, 0);
                else
                        OS_A_REG_RMW_FIELD(ah, AR_AN_TOP1, AR_AN_TOP1_DACIPMODE,
			    eep->baseEepHeader.dacLpMode);

		OS_DELAY(100);

                OS_REG_RMW_FIELD(ah, AR_PHY_FRAME_CTL, AR_PHY_FRAME_CTL_TX_CLIP,
		    pModal->miscBits >> 2);
                OS_REG_RMW_FIELD(ah, AR_PHY_TX_PWRCTRL9, AR_PHY_TX_DESIRED_SCALE_CCK,
		    eep->baseEepHeader.desiredScaleCCK);
        }

    return AH_TRUE;
}

/*
 * Helper functions common for AP/CB/XB
 */

/*
 * Set the target power array "ratesArray" from the
 * given set of target powers.
 *
 * This is used by the various chipset/EEPROM TX power
 * setup routines.
 */ 
void
ar5416SetRatesArrayFromTargetPower(struct ath_hal *ah,
    const struct ieee80211_channel *chan,
    int16_t *ratesArray,
    const CAL_TARGET_POWER_LEG *targetPowerCck,
    const CAL_TARGET_POWER_LEG *targetPowerCckExt,
    const CAL_TARGET_POWER_LEG *targetPowerOfdm,
    const CAL_TARGET_POWER_LEG *targetPowerOfdmExt,
    const CAL_TARGET_POWER_HT *targetPowerHt20,
    const CAL_TARGET_POWER_HT *targetPowerHt40)
{
#define	N(a)	(sizeof(a)/sizeof(a[0]))
	int i;

	/* Blank the rates array, to be consistent */
	for (i = 0; i < Ar5416RateSize; i++)
		ratesArray[i] = 0;

	/* Set rates Array from collected data */
	ratesArray[rate6mb] = ratesArray[rate9mb] = ratesArray[rate12mb] =
	    ratesArray[rate18mb] = ratesArray[rate24mb] = targetPowerOfdm->tPow2x[0];
	ratesArray[rate36mb] = targetPowerOfdm->tPow2x[1];
	ratesArray[rate48mb] = targetPowerOfdm->tPow2x[2];
	ratesArray[rate54mb] = targetPowerOfdm->tPow2x[3];
	ratesArray[rateXr] = targetPowerOfdm->tPow2x[0];

	for (i = 0; i < N(targetPowerHt20->tPow2x); i++) {
		ratesArray[rateHt20_0 + i] = targetPowerHt20->tPow2x[i];
	}

	if (IEEE80211_IS_CHAN_2GHZ(chan)) {
		ratesArray[rate1l]  = targetPowerCck->tPow2x[0];
		ratesArray[rate2s] = ratesArray[rate2l]  = targetPowerCck->tPow2x[1];
		ratesArray[rate5_5s] = ratesArray[rate5_5l] = targetPowerCck->tPow2x[2];
		ratesArray[rate11s] = ratesArray[rate11l] = targetPowerCck->tPow2x[3];
	}
	if (IEEE80211_IS_CHAN_HT40(chan)) {
		for (i = 0; i < N(targetPowerHt40->tPow2x); i++) {
			ratesArray[rateHt40_0 + i] = targetPowerHt40->tPow2x[i];
		}
		ratesArray[rateDupOfdm] = targetPowerHt40->tPow2x[0];
		ratesArray[rateDupCck]  = targetPowerHt40->tPow2x[0];
		ratesArray[rateExtOfdm] = targetPowerOfdmExt->tPow2x[0];
		if (IEEE80211_IS_CHAN_2GHZ(chan)) {
			ratesArray[rateExtCck]  = targetPowerCckExt->tPow2x[0];
		}
	}
#undef	N
}

/*
 * ar5416SetPowerPerRateTable
 *
 * Sets the transmit power in the baseband for the given
 * operating channel and mode.
 */
static HAL_BOOL
ar5416SetPowerPerRateTable(struct ath_hal *ah, struct ar5416eeprom *pEepData,
                           const struct ieee80211_channel *chan,
                           int16_t *ratesArray, uint16_t cfgCtl,
                           uint16_t AntennaReduction, 
                           uint16_t twiceMaxRegulatoryPower,
                           uint16_t powerLimit)
{
#define	N(a)	(sizeof(a)/sizeof(a[0]))
/* Local defines to distinguish between extension and control CTL's */
#define EXT_ADDITIVE (0x8000)
#define CTL_11A_EXT (CTL_11A | EXT_ADDITIVE)
#define CTL_11G_EXT (CTL_11G | EXT_ADDITIVE)
#define CTL_11B_EXT (CTL_11B | EXT_ADDITIVE)

	uint16_t twiceMaxEdgePower = AR5416_MAX_RATE_POWER;
	int i;
	int16_t  twiceLargestAntenna;
	CAL_CTL_DATA *rep;
	CAL_TARGET_POWER_LEG targetPowerOfdm, targetPowerCck = {0, {0, 0, 0, 0}};
	CAL_TARGET_POWER_LEG targetPowerOfdmExt = {0, {0, 0, 0, 0}}, targetPowerCckExt = {0, {0, 0, 0, 0}};
	CAL_TARGET_POWER_HT  targetPowerHt20, targetPowerHt40 = {0, {0, 0, 0, 0}};
	int16_t scaledPower, minCtlPower;

#define SUB_NUM_CTL_MODES_AT_5G_40 2   /* excluding HT40, EXT-OFDM */
#define SUB_NUM_CTL_MODES_AT_2G_40 3   /* excluding HT40, EXT-OFDM, EXT-CCK */
	static const uint16_t ctlModesFor11a[] = {
	   CTL_11A, CTL_5GHT20, CTL_11A_EXT, CTL_5GHT40
	};
	static const uint16_t ctlModesFor11g[] = {
	   CTL_11B, CTL_11G, CTL_2GHT20, CTL_11B_EXT, CTL_11G_EXT, CTL_2GHT40
	};
	const uint16_t *pCtlMode;
	uint16_t numCtlModes, ctlMode, freq;
	CHAN_CENTERS centers;

	ar5416GetChannelCenters(ah,  chan, &centers);

	/* Compute TxPower reduction due to Antenna Gain */

	twiceLargestAntenna = AH_MAX(AH_MAX(
	    pEepData->modalHeader[IEEE80211_IS_CHAN_2GHZ(chan)].antennaGainCh[0],
	    pEepData->modalHeader[IEEE80211_IS_CHAN_2GHZ(chan)].antennaGainCh[1]),
	    pEepData->modalHeader[IEEE80211_IS_CHAN_2GHZ(chan)].antennaGainCh[2]);
#if 0
	/* Turn it back on if we need to calculate per chain antenna gain reduction */
	/* Use only if the expected gain > 6dbi */
	/* Chain 0 is always used */
	twiceLargestAntenna = pEepData->modalHeader[IEEE80211_IS_CHAN_2GHZ(chan)].antennaGainCh[0];

	/* Look at antenna gains of Chains 1 and 2 if the TX mask is set */
	if (ahp->ah_tx_chainmask & 0x2)
		twiceLargestAntenna = AH_MAX(twiceLargestAntenna,
			pEepData->modalHeader[IEEE80211_IS_CHAN_2GHZ(chan)].antennaGainCh[1]);

	if (ahp->ah_tx_chainmask & 0x4)
		twiceLargestAntenna = AH_MAX(twiceLargestAntenna,
			pEepData->modalHeader[IEEE80211_IS_CHAN_2GHZ(chan)].antennaGainCh[2]);
#endif
	twiceLargestAntenna = (int16_t)AH_MIN((AntennaReduction) - twiceLargestAntenna, 0);

	/* XXX setup for 5212 use (really used?) */
	ath_hal_eepromSet(ah,
	    IEEE80211_IS_CHAN_2GHZ(chan) ? AR_EEP_ANTGAINMAX_2 : AR_EEP_ANTGAINMAX_5,
	    twiceLargestAntenna);

	/* 
	 * scaledPower is the minimum of the user input power level and
	 * the regulatory allowed power level
	 */
	scaledPower = AH_MIN(powerLimit, twiceMaxRegulatoryPower + twiceLargestAntenna);

	/* Reduce scaled Power by number of chains active to get to per chain tx power level */
	/* TODO: better value than these? */
	switch (owl_get_ntxchains(AH5416(ah)->ah_tx_chainmask)) {
	case 1:
		break;
	case 2:
		scaledPower -= pEepData->modalHeader[IEEE80211_IS_CHAN_2GHZ(chan)].pwrDecreaseFor2Chain;
		break;
	case 3:
		scaledPower -= pEepData->modalHeader[IEEE80211_IS_CHAN_2GHZ(chan)].pwrDecreaseFor3Chain;
		break;
	default:
		return AH_FALSE; /* Unsupported number of chains */
	}

	scaledPower = AH_MAX(0, scaledPower);

	/* Get target powers from EEPROM - our baseline for TX Power */
	if (IEEE80211_IS_CHAN_2GHZ(chan)) {
		/* Setup for CTL modes */
		numCtlModes = N(ctlModesFor11g) - SUB_NUM_CTL_MODES_AT_2G_40; /* CTL_11B, CTL_11G, CTL_2GHT20 */
		pCtlMode = ctlModesFor11g;

		ar5416GetTargetPowersLeg(ah,  chan, pEepData->calTargetPowerCck,
				AR5416_NUM_2G_CCK_TARGET_POWERS, &targetPowerCck, 4, AH_FALSE);
		ar5416GetTargetPowersLeg(ah,  chan, pEepData->calTargetPower2G,
				AR5416_NUM_2G_20_TARGET_POWERS, &targetPowerOfdm, 4, AH_FALSE);
		ar5416GetTargetPowers(ah,  chan, pEepData->calTargetPower2GHT20,
				AR5416_NUM_2G_20_TARGET_POWERS, &targetPowerHt20, 8, AH_FALSE);

		if (IEEE80211_IS_CHAN_HT40(chan)) {
			numCtlModes = N(ctlModesFor11g);    /* All 2G CTL's */

			ar5416GetTargetPowers(ah,  chan, pEepData->calTargetPower2GHT40,
				AR5416_NUM_2G_40_TARGET_POWERS, &targetPowerHt40, 8, AH_TRUE);
			/* Get target powers for extension channels */
			ar5416GetTargetPowersLeg(ah,  chan, pEepData->calTargetPowerCck,
				AR5416_NUM_2G_CCK_TARGET_POWERS, &targetPowerCckExt, 4, AH_TRUE);
			ar5416GetTargetPowersLeg(ah,  chan, pEepData->calTargetPower2G,
				AR5416_NUM_2G_20_TARGET_POWERS, &targetPowerOfdmExt, 4, AH_TRUE);
		}
	} else {
		/* Setup for CTL modes */
		numCtlModes = N(ctlModesFor11a) - SUB_NUM_CTL_MODES_AT_5G_40; /* CTL_11A, CTL_5GHT20 */
		pCtlMode = ctlModesFor11a;

		ar5416GetTargetPowersLeg(ah,  chan, pEepData->calTargetPower5G,
				AR5416_NUM_5G_20_TARGET_POWERS, &targetPowerOfdm, 4, AH_FALSE);
		ar5416GetTargetPowers(ah,  chan, pEepData->calTargetPower5GHT20,
				AR5416_NUM_5G_20_TARGET_POWERS, &targetPowerHt20, 8, AH_FALSE);

		if (IEEE80211_IS_CHAN_HT40(chan)) {
			numCtlModes = N(ctlModesFor11a); /* All 5G CTL's */

			ar5416GetTargetPowers(ah,  chan, pEepData->calTargetPower5GHT40,
				AR5416_NUM_5G_40_TARGET_POWERS, &targetPowerHt40, 8, AH_TRUE);
			ar5416GetTargetPowersLeg(ah,  chan, pEepData->calTargetPower5G,
				AR5416_NUM_5G_20_TARGET_POWERS, &targetPowerOfdmExt, 4, AH_TRUE);
		}
	}

	/*
	 * For MIMO, need to apply regulatory caps individually across dynamically
	 * running modes: CCK, OFDM, HT20, HT40
	 *
	 * The outer loop walks through each possible applicable runtime mode.
	 * The inner loop walks through each ctlIndex entry in EEPROM.
	 * The ctl value is encoded as [7:4] == test group, [3:0] == test mode.
	 *
	 */
	for (ctlMode = 0; ctlMode < numCtlModes; ctlMode++) {
		HAL_BOOL isHt40CtlMode = (pCtlMode[ctlMode] == CTL_5GHT40) ||
		    (pCtlMode[ctlMode] == CTL_2GHT40);
		if (isHt40CtlMode) {
			freq = centers.ctl_center;
		} else if (pCtlMode[ctlMode] & EXT_ADDITIVE) {
			freq = centers.ext_center;
		} else {
			freq = centers.ctl_center;
		}

		/* walk through each CTL index stored in EEPROM */
		for (i = 0; (i < AR5416_NUM_CTLS) && pEepData->ctlIndex[i]; i++) {
			uint16_t twiceMinEdgePower;

			/* compare test group from regulatory channel list with test mode from pCtlMode list */
			if ((((cfgCtl & ~CTL_MODE_M) | (pCtlMode[ctlMode] & CTL_MODE_M)) == pEepData->ctlIndex[i]) ||
				(((cfgCtl & ~CTL_MODE_M) | (pCtlMode[ctlMode] & CTL_MODE_M)) == 
				 ((pEepData->ctlIndex[i] & CTL_MODE_M) | SD_NO_CTL))) {
				rep = &(pEepData->ctlData[i]);
				twiceMinEdgePower = ar5416GetMaxEdgePower(freq,
							rep->ctlEdges[owl_get_ntxchains(AH5416(ah)->ah_tx_chainmask) - 1],
							IEEE80211_IS_CHAN_2GHZ(chan));
				if ((cfgCtl & ~CTL_MODE_M) == SD_NO_CTL) {
					/* Find the minimum of all CTL edge powers that apply to this channel */
					twiceMaxEdgePower = AH_MIN(twiceMaxEdgePower, twiceMinEdgePower);
				} else {
					/* specific */
					twiceMaxEdgePower = twiceMinEdgePower;
					break;
				}
			}
		}
		minCtlPower = (uint8_t)AH_MIN(twiceMaxEdgePower, scaledPower);
		/* Apply ctl mode to correct target power set */
		switch(pCtlMode[ctlMode]) {
		case CTL_11B:
			for (i = 0; i < N(targetPowerCck.tPow2x); i++) {
				targetPowerCck.tPow2x[i] = (uint8_t)AH_MIN(targetPowerCck.tPow2x[i], minCtlPower);
			}
			break;
		case CTL_11A:
		case CTL_11G:
			for (i = 0; i < N(targetPowerOfdm.tPow2x); i++) {
				targetPowerOfdm.tPow2x[i] = (uint8_t)AH_MIN(targetPowerOfdm.tPow2x[i], minCtlPower);
			}
			break;
		case CTL_5GHT20:
		case CTL_2GHT20:
			for (i = 0; i < N(targetPowerHt20.tPow2x); i++) {
				targetPowerHt20.tPow2x[i] = (uint8_t)AH_MIN(targetPowerHt20.tPow2x[i], minCtlPower);
			}
			break;
		case CTL_11B_EXT:
			targetPowerCckExt.tPow2x[0] = (uint8_t)AH_MIN(targetPowerCckExt.tPow2x[0], minCtlPower);
			break;
		case CTL_11A_EXT:
		case CTL_11G_EXT:
			targetPowerOfdmExt.tPow2x[0] = (uint8_t)AH_MIN(targetPowerOfdmExt.tPow2x[0], minCtlPower);
			break;
		case CTL_5GHT40:
		case CTL_2GHT40:
			for (i = 0; i < N(targetPowerHt40.tPow2x); i++) {
				targetPowerHt40.tPow2x[i] = (uint8_t)AH_MIN(targetPowerHt40.tPow2x[i], minCtlPower);
			}
			break;
		default:
			return AH_FALSE;
			break;
		}
	} /* end ctl mode checking */

	/* Set rates Array from collected data */
	ar5416SetRatesArrayFromTargetPower(ah, chan, ratesArray,
	    &targetPowerCck,
	    &targetPowerCckExt,
	    &targetPowerOfdm,
	    &targetPowerOfdmExt,
	    &targetPowerHt20,
	    &targetPowerHt40);
	return AH_TRUE;
#undef EXT_ADDITIVE
#undef CTL_11A_EXT
#undef CTL_11G_EXT
#undef CTL_11B_EXT
#undef SUB_NUM_CTL_MODES_AT_5G_40
#undef SUB_NUM_CTL_MODES_AT_2G_40
#undef N
}

/**************************************************************************
 * fbin2freq
 *
 * Get channel value from binary representation held in eeprom
 * RETURNS: the frequency in MHz
 */
static uint16_t
fbin2freq(uint8_t fbin, HAL_BOOL is2GHz)
{
    /*
     * Reserved value 0xFF provides an empty definition both as
     * an fbin and as a frequency - do not convert
     */
    if (fbin == AR5416_BCHAN_UNUSED) {
        return fbin;
    }

    return (uint16_t)((is2GHz) ? (2300 + fbin) : (4800 + 5 * fbin));
}

/*
 * ar5416GetMaxEdgePower
 *
 * Find the maximum conformance test limit for the given channel and CTL info
 */
uint16_t
ar5416GetMaxEdgePower(uint16_t freq, CAL_CTL_EDGES *pRdEdgesPower, HAL_BOOL is2GHz)
{
    uint16_t twiceMaxEdgePower = AR5416_MAX_RATE_POWER;
    int      i;

    /* Get the edge power */
    for (i = 0; (i < AR5416_NUM_BAND_EDGES) && (pRdEdgesPower[i].bChannel != AR5416_BCHAN_UNUSED) ; i++) {
        /*
         * If there's an exact channel match or an inband flag set
         * on the lower channel use the given rdEdgePower
         */
        if (freq == fbin2freq(pRdEdgesPower[i].bChannel, is2GHz)) {
            twiceMaxEdgePower = MS(pRdEdgesPower[i].tPowerFlag, CAL_CTL_EDGES_POWER);
            break;
        } else if ((i > 0) && (freq < fbin2freq(pRdEdgesPower[i].bChannel, is2GHz))) {
            if (fbin2freq(pRdEdgesPower[i - 1].bChannel, is2GHz) < freq && (pRdEdgesPower[i - 1].tPowerFlag & CAL_CTL_EDGES_FLAG) != 0) {
                twiceMaxEdgePower = MS(pRdEdgesPower[i - 1].tPowerFlag, CAL_CTL_EDGES_POWER);
            }
            /* Leave loop - no more affecting edges possible in this monotonic increasing list */
            break;
        }
    }
    HALASSERT(twiceMaxEdgePower > 0);
    return twiceMaxEdgePower;
}

/**************************************************************
 * ar5416GetTargetPowers
 *
 * Return the rates of target power for the given target power table
 * channel, and number of channels
 */
void
ar5416GetTargetPowers(struct ath_hal *ah,  const struct ieee80211_channel *chan,
                      CAL_TARGET_POWER_HT *powInfo, uint16_t numChannels,
                      CAL_TARGET_POWER_HT *pNewPower, uint16_t numRates,
                      HAL_BOOL isHt40Target)
{
    uint16_t clo, chi;
    int i;
    int matchIndex = -1, lowIndex = -1;
    uint16_t freq;
    CHAN_CENTERS centers;

    ar5416GetChannelCenters(ah,  chan, &centers);
    freq = isHt40Target ? centers.synth_center : centers.ctl_center;

    /* Copy the target powers into the temp channel list */
    if (freq <= fbin2freq(powInfo[0].bChannel, IEEE80211_IS_CHAN_2GHZ(chan))) {
        matchIndex = 0;
    } else {
        for (i = 0; (i < numChannels) && (powInfo[i].bChannel != AR5416_BCHAN_UNUSED); i++) {
            if (freq == fbin2freq(powInfo[i].bChannel, IEEE80211_IS_CHAN_2GHZ(chan))) {
                matchIndex = i;
                break;
            } else if ((freq < fbin2freq(powInfo[i].bChannel, IEEE80211_IS_CHAN_2GHZ(chan))) &&
                       (freq > fbin2freq(powInfo[i - 1].bChannel, IEEE80211_IS_CHAN_2GHZ(chan))))
            {
                lowIndex = i - 1;
                break;
            }
        }
        if ((matchIndex == -1) && (lowIndex == -1)) {
            HALASSERT(freq > fbin2freq(powInfo[i - 1].bChannel, IEEE80211_IS_CHAN_2GHZ(chan)));
            matchIndex = i - 1;
        }
    }

    if (matchIndex != -1) {
        OS_MEMCPY(pNewPower, &powInfo[matchIndex], sizeof(*pNewPower));
    } else {
        HALASSERT(lowIndex != -1);
        /*
         * Get the lower and upper channels, target powers,
         * and interpolate between them.
         */
        clo = fbin2freq(powInfo[lowIndex].bChannel, IEEE80211_IS_CHAN_2GHZ(chan));
        chi = fbin2freq(powInfo[lowIndex + 1].bChannel, IEEE80211_IS_CHAN_2GHZ(chan));

        for (i = 0; i < numRates; i++) {
            pNewPower->tPow2x[i] = (uint8_t)ath_ee_interpolate(freq, clo, chi,
                                   powInfo[lowIndex].tPow2x[i], powInfo[lowIndex + 1].tPow2x[i]);
        }
    }
}
/**************************************************************
 * ar5416GetTargetPowersLeg
 *
 * Return the four rates of target power for the given target power table
 * channel, and number of channels
 */
void
ar5416GetTargetPowersLeg(struct ath_hal *ah, 
                         const struct ieee80211_channel *chan,
                         CAL_TARGET_POWER_LEG *powInfo, uint16_t numChannels,
                         CAL_TARGET_POWER_LEG *pNewPower, uint16_t numRates,
			 HAL_BOOL isExtTarget)
{
    uint16_t clo, chi;
    int i;
    int matchIndex = -1, lowIndex = -1;
    uint16_t freq;
    CHAN_CENTERS centers;

    ar5416GetChannelCenters(ah,  chan, &centers);
    freq = (isExtTarget) ? centers.ext_center :centers.ctl_center;

    /* Copy the target powers into the temp channel list */
    if (freq <= fbin2freq(powInfo[0].bChannel, IEEE80211_IS_CHAN_2GHZ(chan))) {
        matchIndex = 0;
    } else {
        for (i = 0; (i < numChannels) && (powInfo[i].bChannel != AR5416_BCHAN_UNUSED); i++) {
            if (freq == fbin2freq(powInfo[i].bChannel, IEEE80211_IS_CHAN_2GHZ(chan))) {
                matchIndex = i;
                break;
            } else if ((freq < fbin2freq(powInfo[i].bChannel, IEEE80211_IS_CHAN_2GHZ(chan))) &&
                       (freq > fbin2freq(powInfo[i - 1].bChannel, IEEE80211_IS_CHAN_2GHZ(chan))))
            {
                lowIndex = i - 1;
                break;
            }
        }
        if ((matchIndex == -1) && (lowIndex == -1)) {
            HALASSERT(freq > fbin2freq(powInfo[i - 1].bChannel, IEEE80211_IS_CHAN_2GHZ(chan)));
            matchIndex = i - 1;
        }
    }

    if (matchIndex != -1) {
        OS_MEMCPY(pNewPower, &powInfo[matchIndex], sizeof(*pNewPower));
    } else {
        HALASSERT(lowIndex != -1);
        /*
         * Get the lower and upper channels, target powers,
         * and interpolate between them.
         */
        clo = fbin2freq(powInfo[lowIndex].bChannel, IEEE80211_IS_CHAN_2GHZ(chan));
        chi = fbin2freq(powInfo[lowIndex + 1].bChannel, IEEE80211_IS_CHAN_2GHZ(chan));

        for (i = 0; i < numRates; i++) {
            pNewPower->tPow2x[i] = (uint8_t)ath_ee_interpolate(freq, clo, chi,
                                   powInfo[lowIndex].tPow2x[i], powInfo[lowIndex + 1].tPow2x[i]);
        }
    }
}

/*
 * Set the gain boundaries for the given radio chain.
 *
 * The gain boundaries tell the hardware at what point in the
 * PDADC array to "switch over" from one PD gain setting
 * to another. There's also a gain overlap between two
 * PDADC array gain curves where there's valid PD values
 * for 2 gain settings.
 *
 * The hardware uses the gain overlap and gain boundaries
 * to determine which gain curve to use for the given
 * target TX power.
 */
void
ar5416SetGainBoundariesClosedLoop(struct ath_hal *ah, int i,
    uint16_t pdGainOverlap_t2, uint16_t gainBoundaries[])
{
	int regChainOffset;

	regChainOffset = ar5416GetRegChainOffset(ah, i);

	HALDEBUG(ah, HAL_DEBUG_EEPROM, "%s: chain %d: gainOverlap_t2: %d,"
	    " gainBoundaries: %d, %d, %d, %d\n", __func__, i, pdGainOverlap_t2,
	    gainBoundaries[0], gainBoundaries[1], gainBoundaries[2],
	    gainBoundaries[3]);
	OS_REG_WRITE(ah, AR_PHY_TPCRG5 + regChainOffset,
	    SM(pdGainOverlap_t2, AR_PHY_TPCRG5_PD_GAIN_OVERLAP) |
	    SM(gainBoundaries[0], AR_PHY_TPCRG5_PD_GAIN_BOUNDARY_1)  |
	    SM(gainBoundaries[1], AR_PHY_TPCRG5_PD_GAIN_BOUNDARY_2)  |
	    SM(gainBoundaries[2], AR_PHY_TPCRG5_PD_GAIN_BOUNDARY_3)  |
	    SM(gainBoundaries[3], AR_PHY_TPCRG5_PD_GAIN_BOUNDARY_4));
}

/*
 * Get the gain values and the number of gain levels given
 * in xpdMask.
 *
 * The EEPROM xpdMask determines which power detector gain
 * levels were used during calibration. Each of these mask
 * bits maps to a fixed gain level in hardware.
 */
uint16_t
ar5416GetXpdGainValues(struct ath_hal *ah, uint16_t xpdMask,
    uint16_t xpdGainValues[])
{
    int i;
    uint16_t numXpdGain = 0;

    for (i = 1; i <= AR5416_PD_GAINS_IN_MASK; i++) {
        if ((xpdMask >> (AR5416_PD_GAINS_IN_MASK - i)) & 1) {
            if (numXpdGain >= AR5416_NUM_PD_GAINS) {
                HALASSERT(0);
                break;
            }
            xpdGainValues[numXpdGain] = (uint16_t)(AR5416_PD_GAINS_IN_MASK - i);
            numXpdGain++;
        }
    }
    return numXpdGain;
}

/*
 * Write the detector gain and biases.
 *
 * There are four power detector gain levels. The xpdMask in the EEPROM
 * determines which power detector gain levels have TX power calibration
 * data associated with them. This function writes the number of
 * PD gain levels and their values into the hardware.
 *
 * This is valid for all TX chains - the calibration data itself however
 * will likely differ per-chain.
 */
void
ar5416WriteDetectorGainBiases(struct ath_hal *ah, uint16_t numXpdGain,
    uint16_t xpdGainValues[])
{
    HALDEBUG(ah, HAL_DEBUG_EEPROM, "%s: numXpdGain: %d,"
      " xpdGainValues: %d, %d, %d\n", __func__, numXpdGain,
      xpdGainValues[0], xpdGainValues[1], xpdGainValues[2]);

    OS_REG_WRITE(ah, AR_PHY_TPCRG1, (OS_REG_READ(ah, AR_PHY_TPCRG1) & 
    	~(AR_PHY_TPCRG1_NUM_PD_GAIN | AR_PHY_TPCRG1_PD_GAIN_1 |
	AR_PHY_TPCRG1_PD_GAIN_2 | AR_PHY_TPCRG1_PD_GAIN_3)) | 
	SM(numXpdGain - 1, AR_PHY_TPCRG1_NUM_PD_GAIN) |
	SM(xpdGainValues[0], AR_PHY_TPCRG1_PD_GAIN_1 ) |
	SM(xpdGainValues[1], AR_PHY_TPCRG1_PD_GAIN_2) |
	SM(xpdGainValues[2],  AR_PHY_TPCRG1_PD_GAIN_3));
}

/*
 * Write the PDADC array to the given radio chain i.
 *
 * The 32 PDADC registers are written without any care about
 * their contents - so if various chips treat values as "special",
 * this routine will not care.
 */
void
ar5416WritePdadcValues(struct ath_hal *ah, int i, uint8_t pdadcValues[])
{
	int regOffset, regChainOffset;
	int j;
	int reg32;

	regChainOffset = ar5416GetRegChainOffset(ah, i);
	regOffset = AR_PHY_BASE + (672 << 2) + regChainOffset;

	for (j = 0; j < 32; j++) {
		reg32 = ((pdadcValues[4*j + 0] & 0xFF) << 0)  |
		    ((pdadcValues[4*j + 1] & 0xFF) << 8)  |
		    ((pdadcValues[4*j + 2] & 0xFF) << 16) |
		    ((pdadcValues[4*j + 3] & 0xFF) << 24) ;
		OS_REG_WRITE(ah, regOffset, reg32);
		HALDEBUG(ah, HAL_DEBUG_EEPROM, "PDADC: Chain %d |"
		    " PDADC %3d Value %3d | PDADC %3d Value %3d | PDADC %3d"
		    " Value %3d | PDADC %3d Value %3d |\n",
		    i,
		    4*j, pdadcValues[4*j],
		    4*j+1, pdadcValues[4*j + 1],
		    4*j+2, pdadcValues[4*j + 2],
		    4*j+3, pdadcValues[4*j + 3]);
		regOffset += 4;
	}
}

/**************************************************************
 * ar5416SetPowerCalTable
 *
 * Pull the PDADC piers from cal data and interpolate them across the given
 * points as well as from the nearest pier(s) to get a power detector
 * linear voltage to power level table.
 */
HAL_BOOL
ar5416SetPowerCalTable(struct ath_hal *ah, struct ar5416eeprom *pEepData,
	const struct ieee80211_channel *chan, int16_t *pTxPowerIndexOffset)
{
    CAL_DATA_PER_FREQ *pRawDataset;
    uint8_t  *pCalBChans = AH_NULL;
    uint16_t pdGainOverlap_t2;
    static uint8_t  pdadcValues[AR5416_NUM_PDADC_VALUES];
    uint16_t gainBoundaries[AR5416_PD_GAINS_IN_MASK];
    uint16_t numPiers, i;
    int16_t  tMinCalPower;
    uint16_t numXpdGain, xpdMask;
    uint16_t xpdGainValues[AR5416_NUM_PD_GAINS];
    uint32_t regChainOffset;

    OS_MEMZERO(xpdGainValues, sizeof(xpdGainValues));
    
    xpdMask = pEepData->modalHeader[IEEE80211_IS_CHAN_2GHZ(chan)].xpdGain;

    if (IS_EEP_MINOR_V2(ah)) {
        pdGainOverlap_t2 = pEepData->modalHeader[IEEE80211_IS_CHAN_2GHZ(chan)].pdGainOverlap;
    } else { 
    	pdGainOverlap_t2 = (uint16_t)(MS(OS_REG_READ(ah, AR_PHY_TPCRG5), AR_PHY_TPCRG5_PD_GAIN_OVERLAP));
    }

    if (IEEE80211_IS_CHAN_2GHZ(chan)) {
        pCalBChans = pEepData->calFreqPier2G;
        numPiers = AR5416_NUM_2G_CAL_PIERS;
    } else {
        pCalBChans = pEepData->calFreqPier5G;
        numPiers = AR5416_NUM_5G_CAL_PIERS;
    }

    /* Calculate the value of xpdgains from the xpdGain Mask */
    numXpdGain = ar5416GetXpdGainValues(ah, xpdMask, xpdGainValues);
    
    /* Write the detector gain biases and their number */
    ar5416WriteDetectorGainBiases(ah, numXpdGain, xpdGainValues);

    for (i = 0; i < AR5416_MAX_CHAINS; i++) {
	regChainOffset = ar5416GetRegChainOffset(ah, i);

        if (pEepData->baseEepHeader.txMask & (1 << i)) {
            if (IEEE80211_IS_CHAN_2GHZ(chan)) {
                pRawDataset = pEepData->calPierData2G[i];
            } else {
                pRawDataset = pEepData->calPierData5G[i];
            }

            /* Fetch the gain boundaries and the PDADC values */
	    ar5416GetGainBoundariesAndPdadcs(ah,  chan, pRawDataset,
                                             pCalBChans, numPiers,
                                             pdGainOverlap_t2,
                                             &tMinCalPower, gainBoundaries,
                                             pdadcValues, numXpdGain);

            if ((i == 0) || AR_SREV_5416_V20_OR_LATER(ah)) {
		ar5416SetGainBoundariesClosedLoop(ah, i, pdGainOverlap_t2,
		  gainBoundaries);
            }

            /* Write the power values into the baseband power table */
	    ar5416WritePdadcValues(ah, i, pdadcValues);
        }
    }
    *pTxPowerIndexOffset = 0;

    return AH_TRUE;
}

/**************************************************************
 * ar5416GetGainBoundariesAndPdadcs
 *
 * Uses the data points read from EEPROM to reconstruct the pdadc power table
 * Called by ar5416SetPowerCalTable only.
 */
void
ar5416GetGainBoundariesAndPdadcs(struct ath_hal *ah, 
                                 const struct ieee80211_channel *chan,
				 CAL_DATA_PER_FREQ *pRawDataSet,
                                 uint8_t * bChans,  uint16_t availPiers,
                                 uint16_t tPdGainOverlap, int16_t *pMinCalPower, uint16_t * pPdGainBoundaries,
                                 uint8_t * pPDADCValues, uint16_t numXpdGains)
{

    int       i, j, k;
    int16_t   ss;         /* potentially -ve index for taking care of pdGainOverlap */
    uint16_t  idxL, idxR, numPiers; /* Pier indexes */

    /* filled out Vpd table for all pdGains (chanL) */
    static uint8_t   vpdTableL[AR5416_NUM_PD_GAINS][AR5416_MAX_PWR_RANGE_IN_HALF_DB];

    /* filled out Vpd table for all pdGains (chanR) */
    static uint8_t   vpdTableR[AR5416_NUM_PD_GAINS][AR5416_MAX_PWR_RANGE_IN_HALF_DB];

    /* filled out Vpd table for all pdGains (interpolated) */
    static uint8_t   vpdTableI[AR5416_NUM_PD_GAINS][AR5416_MAX_PWR_RANGE_IN_HALF_DB];

    uint8_t   *pVpdL, *pVpdR, *pPwrL, *pPwrR;
    uint8_t   minPwrT4[AR5416_NUM_PD_GAINS];
    uint8_t   maxPwrT4[AR5416_NUM_PD_GAINS];
    int16_t   vpdStep;
    int16_t   tmpVal;
    uint16_t  sizeCurrVpdTable, maxIndex, tgtIndex;
    HAL_BOOL    match;
    int16_t  minDelta = 0;
    CHAN_CENTERS centers;

    ar5416GetChannelCenters(ah, chan, &centers);

    /* Trim numPiers for the number of populated channel Piers */
    for (numPiers = 0; numPiers < availPiers; numPiers++) {
        if (bChans[numPiers] == AR5416_BCHAN_UNUSED) {
            break;
        }
    }

    /* Find pier indexes around the current channel */
    match = ath_ee_getLowerUpperIndex((uint8_t)FREQ2FBIN(centers.synth_center,
	IEEE80211_IS_CHAN_2GHZ(chan)), bChans, numPiers, &idxL, &idxR);

    if (match) {
        /* Directly fill both vpd tables from the matching index */
        for (i = 0; i < numXpdGains; i++) {
            minPwrT4[i] = pRawDataSet[idxL].pwrPdg[i][0];
            maxPwrT4[i] = pRawDataSet[idxL].pwrPdg[i][4];
            ath_ee_FillVpdTable(minPwrT4[i], maxPwrT4[i], pRawDataSet[idxL].pwrPdg[i],
                               pRawDataSet[idxL].vpdPdg[i], AR5416_PD_GAIN_ICEPTS, vpdTableI[i]);
        }
    } else {
        for (i = 0; i < numXpdGains; i++) {
            pVpdL = pRawDataSet[idxL].vpdPdg[i];
            pPwrL = pRawDataSet[idxL].pwrPdg[i];
            pVpdR = pRawDataSet[idxR].vpdPdg[i];
            pPwrR = pRawDataSet[idxR].pwrPdg[i];

            /* Start Vpd interpolation from the max of the minimum powers */
            minPwrT4[i] = AH_MAX(pPwrL[0], pPwrR[0]);

            /* End Vpd interpolation from the min of the max powers */
            maxPwrT4[i] = AH_MIN(pPwrL[AR5416_PD_GAIN_ICEPTS - 1], pPwrR[AR5416_PD_GAIN_ICEPTS - 1]);
            HALASSERT(maxPwrT4[i] > minPwrT4[i]);

            /* Fill pier Vpds */
            ath_ee_FillVpdTable(minPwrT4[i], maxPwrT4[i], pPwrL, pVpdL, AR5416_PD_GAIN_ICEPTS, vpdTableL[i]);
            ath_ee_FillVpdTable(minPwrT4[i], maxPwrT4[i], pPwrR, pVpdR, AR5416_PD_GAIN_ICEPTS, vpdTableR[i]);

            /* Interpolate the final vpd */
            for (j = 0; j <= (maxPwrT4[i] - minPwrT4[i]) / 2; j++) {
                vpdTableI[i][j] = (uint8_t)(ath_ee_interpolate((uint16_t)FREQ2FBIN(centers.synth_center,
		    IEEE80211_IS_CHAN_2GHZ(chan)),
                    bChans[idxL], bChans[idxR], vpdTableL[i][j], vpdTableR[i][j]));
            }
        }
    }
    *pMinCalPower = (int16_t)(minPwrT4[0] / 2);

    k = 0; /* index for the final table */
    for (i = 0; i < numXpdGains; i++) {
        if (i == (numXpdGains - 1)) {
            pPdGainBoundaries[i] = (uint16_t)(maxPwrT4[i] / 2);
        } else {
            pPdGainBoundaries[i] = (uint16_t)((maxPwrT4[i] + minPwrT4[i+1]) / 4);
        }

        pPdGainBoundaries[i] = (uint16_t)AH_MIN(AR5416_MAX_RATE_POWER, pPdGainBoundaries[i]);

	/* NB: only applies to owl 1.0 */
        if ((i == 0) && !AR_SREV_5416_V20_OR_LATER(ah) ) {
	    /*
             * fix the gain delta, but get a delta that can be applied to min to
             * keep the upper power values accurate, don't think max needs to
             * be adjusted because should not be at that area of the table?
	     */
            minDelta = pPdGainBoundaries[0] - 23;
            pPdGainBoundaries[0] = 23;
        }
        else {
            minDelta = 0;
        }

        /* Find starting index for this pdGain */
        if (i == 0) {
            if (AR_SREV_MERLIN_10_OR_LATER(ah))
                ss = (int16_t)(0 - (minPwrT4[i] / 2));
            else
                ss = 0; /* for the first pdGain, start from index 0 */
        } else {
	    /* need overlap entries extrapolated below. */
            ss = (int16_t)((pPdGainBoundaries[i-1] - (minPwrT4[i] / 2)) - tPdGainOverlap + 1 + minDelta);
        }
        vpdStep = (int16_t)(vpdTableI[i][1] - vpdTableI[i][0]);
        vpdStep = (int16_t)((vpdStep < 1) ? 1 : vpdStep);
        /*
         *-ve ss indicates need to extrapolate data below for this pdGain
         */
        while ((ss < 0) && (k < (AR5416_NUM_PDADC_VALUES - 1))) {
            tmpVal = (int16_t)(vpdTableI[i][0] + ss * vpdStep);
            pPDADCValues[k++] = (uint8_t)((tmpVal < 0) ? 0 : tmpVal);
            ss++;
        }

        sizeCurrVpdTable = (uint8_t)((maxPwrT4[i] - minPwrT4[i]) / 2 +1);
        tgtIndex = (uint8_t)(pPdGainBoundaries[i] + tPdGainOverlap - (minPwrT4[i] / 2));
        maxIndex = (tgtIndex < sizeCurrVpdTable) ? tgtIndex : sizeCurrVpdTable;

        while ((ss < maxIndex) && (k < (AR5416_NUM_PDADC_VALUES - 1))) {
            pPDADCValues[k++] = vpdTableI[i][ss++];
        }

        vpdStep = (int16_t)(vpdTableI[i][sizeCurrVpdTable - 1] - vpdTableI[i][sizeCurrVpdTable - 2]);
        vpdStep = (int16_t)((vpdStep < 1) ? 1 : vpdStep);
        /*
         * for last gain, pdGainBoundary == Pmax_t2, so will
         * have to extrapolate
         */
        if (tgtIndex >= maxIndex) {  /* need to extrapolate above */
            while ((ss <= tgtIndex) && (k < (AR5416_NUM_PDADC_VALUES - 1))) {
                tmpVal = (int16_t)((vpdTableI[i][sizeCurrVpdTable - 1] +
                          (ss - maxIndex +1) * vpdStep));
                pPDADCValues[k++] = (uint8_t)((tmpVal > 255) ? 255 : tmpVal);
                ss++;
            }
        }               /* extrapolated above */
    }                   /* for all pdGainUsed */

    /* Fill out pdGainBoundaries - only up to 2 allowed here, but hardware allows up to 4 */
    while (i < AR5416_PD_GAINS_IN_MASK) {
        pPdGainBoundaries[i] = pPdGainBoundaries[i-1];
        i++;
    }

    while (k < AR5416_NUM_PDADC_VALUES) {
        pPDADCValues[k] = pPDADCValues[k-1];
        k++;
    }
    return;
}

/*
 * The linux ath9k driver and (from what I've been told) the reference
 * Atheros driver enables the 11n PHY by default whether or not it's
 * configured.
 */
static void
ar5416Set11nRegs(struct ath_hal *ah, const struct ieee80211_channel *chan)
{
	uint32_t phymode;
	uint32_t enableDacFifo = 0;
	HAL_HT_MACMODE macmode;		/* MAC - 20/40 mode */

	if (AR_SREV_KITE_10_OR_LATER(ah))
		enableDacFifo = (OS_REG_READ(ah, AR_PHY_TURBO) & AR_PHY_FC_ENABLE_DAC_FIFO);

	/* Enable 11n HT, 20 MHz */
	phymode = AR_PHY_FC_HT_EN | AR_PHY_FC_SHORT_GI_40
		| AR_PHY_FC_SINGLE_HT_LTF1 | AR_PHY_FC_WALSH | enableDacFifo;

	/* Configure baseband for dynamic 20/40 operation */
	if (IEEE80211_IS_CHAN_HT40(chan)) {
		phymode |= AR_PHY_FC_DYN2040_EN;

		/* Configure control (primary) channel at +-10MHz */
		if (IEEE80211_IS_CHAN_HT40U(chan))
			phymode |= AR_PHY_FC_DYN2040_PRI_CH;
#if 0
		/* Configure 20/25 spacing */
		if (ht->ht_extprotspacing == HAL_HT_EXTPROTSPACING_25)
			phymode |= AR_PHY_FC_DYN2040_EXT_CH;
#endif
		macmode = HAL_HT_MACMODE_2040;
	} else
		macmode = HAL_HT_MACMODE_20;
	OS_REG_WRITE(ah, AR_PHY_TURBO, phymode);

	/* Configure MAC for 20/40 operation */
	ar5416Set11nMac2040(ah, macmode);

	/* global transmit timeout (25 TUs default)*/
	/* XXX - put this elsewhere??? */
	OS_REG_WRITE(ah, AR_GTXTO, 25 << AR_GTXTO_TIMEOUT_LIMIT_S) ;

	/* carrier sense timeout */
	OS_REG_SET_BIT(ah, AR_GTTM, AR_GTTM_CST_USEC);
	OS_REG_WRITE(ah, AR_CST, 0xF << AR_CST_TIMEOUT_LIMIT_S);
}

void
ar5416GetChannelCenters(struct ath_hal *ah,
	const struct ieee80211_channel *chan, CHAN_CENTERS *centers)
{
	uint16_t freq = ath_hal_gethwchannel(ah, chan);

	centers->ctl_center = freq;
	centers->synth_center = freq;
	/*
	 * In 20/40 phy mode, the center frequency is
	 * "between" the control and extension channels.
	 */
	if (IEEE80211_IS_CHAN_HT40U(chan)) {
		centers->synth_center += HT40_CHANNEL_CENTER_SHIFT;
		centers->ext_center =
		    centers->synth_center + HT40_CHANNEL_CENTER_SHIFT;
	} else if (IEEE80211_IS_CHAN_HT40D(chan)) {
		centers->synth_center -= HT40_CHANNEL_CENTER_SHIFT;
		centers->ext_center =
		    centers->synth_center - HT40_CHANNEL_CENTER_SHIFT;
	} else {
		centers->ext_center = freq;
	}
}

/*
 * Override the INI vals being programmed.
 */
static void
ar5416OverrideIni(struct ath_hal *ah, const struct ieee80211_channel *chan)
{
	uint32_t val;

	/*
	 * Set the RX_ABORT and RX_DIS and clear if off only after
	 * RXE is set for MAC. This prevents frames with corrupted
	 * descriptor status.
	 */
	OS_REG_SET_BIT(ah, AR_DIAG_SW, (AR_DIAG_RX_DIS | AR_DIAG_RX_ABORT));

	if (AR_SREV_MERLIN_10_OR_LATER(ah)) {
		val = OS_REG_READ(ah, AR_PCU_MISC_MODE2);
		val &= (~AR_PCU_MISC_MODE2_ADHOC_MCAST_KEYID_ENABLE);
		if (!AR_SREV_9271(ah))
			val &= ~AR_PCU_MISC_MODE2_HWWAR1;

		if (AR_SREV_KIWI_11_OR_LATER(ah))
			val = val & (~AR_PCU_MISC_MODE2_HWWAR2);

		OS_REG_WRITE(ah, AR_PCU_MISC_MODE2, val);
	}

	/*
	 * Disable RIFS search on some chips to avoid baseband
	 * hang issues.
	 */
	if (AR_SREV_HOWL(ah) || AR_SREV_SOWL(ah))
		(void) ar5416SetRifsDelay(ah, chan, AH_FALSE);

        if (!AR_SREV_5416_V20_OR_LATER(ah) || AR_SREV_MERLIN(ah))
		return;

	/*
	 * Disable BB clock gating
	 * Necessary to avoid issues on AR5416 2.0
	 */
	OS_REG_WRITE(ah, 0x9800 + (651 << 2), 0x11);
}

struct ini {
	uint32_t        *data;          /* NB: !const */
	int             rows, cols;
};

/*
 * Override XPA bias level based on operating frequency.
 * This is a v14 EEPROM specific thing for the AR9160.
 */
void
ar5416EepromSetAddac(struct ath_hal *ah, const struct ieee80211_channel *chan)
{
#define	XPA_LVL_FREQ(cnt)	(pModal->xpaBiasLvlFreq[cnt])
	MODAL_EEP_HEADER	*pModal;
	HAL_EEPROM_v14 *ee = AH_PRIVATE(ah)->ah_eeprom;
	struct ar5416eeprom	*eep = &ee->ee_base;
	uint8_t biaslevel;

	if (! AR_SREV_SOWL(ah))
		return;

        if (EEP_MINOR(ah) < AR5416_EEP_MINOR_VER_7)
                return;

	pModal = &(eep->modalHeader[IEEE80211_IS_CHAN_2GHZ(chan)]);

	if (pModal->xpaBiasLvl != 0xff)
		biaslevel = pModal->xpaBiasLvl;
	else {
		uint16_t resetFreqBin, freqBin, freqCount = 0;
		CHAN_CENTERS centers;

		ar5416GetChannelCenters(ah, chan, &centers);

		resetFreqBin = FREQ2FBIN(centers.synth_center, IEEE80211_IS_CHAN_2GHZ(chan));
		freqBin = XPA_LVL_FREQ(0) & 0xff;
		biaslevel = (uint8_t) (XPA_LVL_FREQ(0) >> 14);

		freqCount++;

		while (freqCount < 3) {
			if (XPA_LVL_FREQ(freqCount) == 0x0)
			break;

			freqBin = XPA_LVL_FREQ(freqCount) & 0xff;
			if (resetFreqBin >= freqBin)
				biaslevel = (uint8_t)(XPA_LVL_FREQ(freqCount) >> 14);
			else
				break;
			freqCount++;
		}
	}

	HALDEBUG(ah, HAL_DEBUG_EEPROM, "%s: overriding XPA bias level = %d\n",
	    __func__, biaslevel);

	/*
	 * This is a dirty workaround for the const initval data,
	 * which will upset multiple AR9160's on the same board.
	 *
	 * The HAL should likely just have a private copy of the addac
	 * data per instance.
	 */
	if (IEEE80211_IS_CHAN_2GHZ(chan))
                HAL_INI_VAL((struct ini *) &AH5416(ah)->ah_ini_addac, 7, 1) =
		    (HAL_INI_VAL(&AH5416(ah)->ah_ini_addac, 7, 1) & (~0x18)) | biaslevel << 3;
        else
                HAL_INI_VAL((struct ini *) &AH5416(ah)->ah_ini_addac, 6, 1) =
		    (HAL_INI_VAL(&AH5416(ah)->ah_ini_addac, 6, 1) & (~0xc0)) | biaslevel << 6;
#undef XPA_LVL_FREQ
}

static void
ar5416MarkPhyInactive(struct ath_hal *ah)
{
	OS_REG_WRITE(ah, AR_PHY_ACTIVE, AR_PHY_ACTIVE_DIS);
}
