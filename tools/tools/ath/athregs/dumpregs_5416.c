/*-
 * Copyright (c) 2002-2008 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 *
 * $FreeBSD$
 */
#include "diag.h"

#include "ah.h"
#include "ah_internal.h"
#include "ar5416/ar5416reg.h"
#include "ar5416/ar5416phy.h"

#include "dumpregs.h"

#define	N(a)	(sizeof(a) / sizeof(a[0]))

#define	MAC5416	SREV(13,8), SREV(0xff,0xff)	/* XXX */

static struct dumpreg ar5416regs[] = {
    { AR_CR,		"CR",		DUMP_BASIC },
    { AR_RXDP,		"RXDP",		DUMP_BASIC },
    { AR_CFG,		"CFG",		DUMP_BASIC },
    { AR_MIRT,		"MIRT",		DUMP_BASIC },
    { AR_TIMT,		"TIMT",		DUMP_BASIC },
    { AR_CST,		"CST",		DUMP_BASIC },
    { AR_IER,		"IER",		DUMP_BASIC },
    { AR_TXCFG,		"TXCFG",	DUMP_BASIC },
    { AR_RXCFG,		"RXCFG",	DUMP_BASIC },
    { AR_MIBC,		"MIBC",		DUMP_BASIC },
    { AR_TOPS,		"TOPS",		DUMP_BASIC },
    { AR_RXNPTO,	"RXNPTO",	DUMP_BASIC },
    { AR_TXNPTO,	"TXNPTO",	DUMP_BASIC },
    { AR_RPGTO,		"RPGTO",	DUMP_BASIC },
    { AR_RPCNT,		"RPCNT",	DUMP_BASIC },
    { AR_MACMISC,	"MACMISC",	DUMP_BASIC },
    { AR_SPC_0,		"SPC_0",	DUMP_BASIC },
    { AR_SPC_1,		"SPC_1",	DUMP_BASIC },
    { AR_GTXTO,		"GTXTO",	DUMP_BASIC },
    { AR_GTTM,		"GTTM",		DUMP_BASIC },

    { AR_ISR,		"ISR",		DUMP_INTERRUPT },
    { AR_ISR_S0,	"ISR_S0",	DUMP_INTERRUPT },
    { AR_ISR_S1,	"ISR_S1",	DUMP_INTERRUPT },
    { AR_ISR_S2,	"ISR_S2",	DUMP_INTERRUPT },
    { AR_ISR_S3,	"ISR_S3",	DUMP_INTERRUPT },
    { AR_ISR_S4,	"ISR_S4",	DUMP_INTERRUPT },
    { AR_IMR,		"IMR",		DUMP_INTERRUPT },
    { AR_IMR_S0,	"IMR_S0",	DUMP_INTERRUPT },
    { AR_IMR_S1,	"IMR_S1",	DUMP_INTERRUPT },
    { AR_IMR_S2,	"IMR_S2",	DUMP_INTERRUPT },
    { AR_IMR_S3,	"IMR_S3",	DUMP_INTERRUPT },
    { AR_IMR_S4,	"IMR_S4",	DUMP_INTERRUPT },
#if 0
    /* NB: don't read the RAC so we don't affect operation */
    { AR_ISR_RAC,	"ISR_RAC",	DUMP_INTERRUPT },
#endif
    { AR_ISR_S0_S,	"ISR_S0_S",	DUMP_INTERRUPT },
    { AR_ISR_S1_S,	"ISR_S1_S",	DUMP_INTERRUPT },
    { AR_ISR_S2_S,	"ISR_S2_S",	DUMP_INTERRUPT },
    { AR_ISR_S3_S,	"ISR_S3_S",	DUMP_INTERRUPT },
    { AR_ISR_S4_S,	"ISR_S4_S",	DUMP_INTERRUPT },

    { AR_DMADBG_0,	"DMADBG0",	DUMP_BASIC },
    { AR_DMADBG_1,	"DMADBG1",	DUMP_BASIC },
    { AR_DMADBG_2,	"DMADBG2",	DUMP_BASIC },
    { AR_DMADBG_3,	"DMADBG3",	DUMP_BASIC },
    { AR_DMADBG_4,	"DMADBG4",	DUMP_BASIC },
    { AR_DMADBG_5,	"DMADBG5",	DUMP_BASIC },
    { AR_DMADBG_6,	"DMADBG6",	DUMP_BASIC },
    { AR_DMADBG_7,	"DMADBG7",	DUMP_BASIC },

    { AR_DCM_A,		"DCM_A",	DUMP_BASIC },
    { AR_DCM_D,		"DCM_D",	DUMP_BASIC },
    { AR_DCCFG,		"DCCFG",	DUMP_BASIC },
    { AR_CCFG,		"CCFG",		DUMP_BASIC },
    { AR_CCUCFG,	"CCUCFG",	DUMP_BASIC },
    { AR_CPC_0,		"CPC0",		DUMP_BASIC },
    { AR_CPC_1,		"CPC1",		DUMP_BASIC },
    { AR_CPC_2,		"CPC2",		DUMP_BASIC },
    { AR_CPC_3,		"CPC3",		DUMP_BASIC },
    { AR_CPCOVF,	"CPCOVF",	DUMP_BASIC },

    { AR_Q0_TXDP,	"Q0_TXDP",	DUMP_QCU },
    { AR_Q1_TXDP,	"Q1_TXDP",	DUMP_QCU },
    { AR_Q2_TXDP,	"Q2_TXDP",	DUMP_QCU },
    { AR_Q3_TXDP,	"Q3_TXDP",	DUMP_QCU },
    { AR_Q4_TXDP,	"Q4_TXDP",	DUMP_QCU },
    { AR_Q5_TXDP,	"Q5_TXDP",	DUMP_QCU },
    { AR_Q6_TXDP,	"Q6_TXDP",	DUMP_QCU },
    { AR_Q7_TXDP,	"Q7_TXDP",	DUMP_QCU },
    { AR_Q8_TXDP,	"Q8_TXDP",	DUMP_QCU },
    { AR_Q9_TXDP,	"Q9_TXDP",	DUMP_QCU },

    { AR_Q_TXE,		"Q_TXE",	DUMP_QCU },
    { AR_Q_TXD,		"Q_TXD",	DUMP_QCU },

    { AR_Q0_CBRCFG,	"Q0_CBR",	DUMP_QCU },
    { AR_Q1_CBRCFG,	"Q1_CBR",	DUMP_QCU },
    { AR_Q2_CBRCFG,	"Q2_CBR",	DUMP_QCU },
    { AR_Q3_CBRCFG,	"Q3_CBR",	DUMP_QCU },
    { AR_Q4_CBRCFG,	"Q4_CBR",	DUMP_QCU },
    { AR_Q5_CBRCFG,	"Q5_CBR",	DUMP_QCU },
    { AR_Q6_CBRCFG,	"Q6_CBR",	DUMP_QCU },
    { AR_Q7_CBRCFG,	"Q7_CBR",	DUMP_QCU },
    { AR_Q8_CBRCFG,	"Q8_CBR",	DUMP_QCU },
    { AR_Q9_CBRCFG,	"Q9_CBR",	DUMP_QCU },

    { AR_Q0_RDYTIMECFG,	"Q0_RDYT",	DUMP_QCU },
    { AR_Q1_RDYTIMECFG,	"Q1_RDYT",	DUMP_QCU },
    { AR_Q2_RDYTIMECFG,	"Q2_RDYT",	DUMP_QCU },
    { AR_Q3_RDYTIMECFG,	"Q3_RDYT",	DUMP_QCU },
    { AR_Q4_RDYTIMECFG,	"Q4_RDYT",	DUMP_QCU },
    { AR_Q5_RDYTIMECFG,	"Q5_RDYT",	DUMP_QCU },
    { AR_Q6_RDYTIMECFG,	"Q6_RDYT",	DUMP_QCU },
    { AR_Q7_RDYTIMECFG,	"Q7_RDYT",	DUMP_QCU },
    { AR_Q8_RDYTIMECFG,	"Q8_RDYT",	DUMP_QCU },
    { AR_Q9_RDYTIMECFG,	"Q9_RDYT",	DUMP_QCU },

    { AR_Q_ONESHOTARM_SC,"Q_ONESHOTARM_SC",	DUMP_QCU },
    { AR_Q_ONESHOTARM_CC,"Q_ONESHOTARM_CC",	DUMP_QCU },

    { AR_Q0_MISC,	"Q0_MISC",	DUMP_QCU },
    { AR_Q1_MISC,	"Q1_MISC",	DUMP_QCU },
    { AR_Q2_MISC,	"Q2_MISC",	DUMP_QCU },
    { AR_Q3_MISC,	"Q3_MISC",	DUMP_QCU },
    { AR_Q4_MISC,	"Q4_MISC",	DUMP_QCU },
    { AR_Q5_MISC,	"Q5_MISC",	DUMP_QCU },
    { AR_Q6_MISC,	"Q6_MISC",	DUMP_QCU },
    { AR_Q7_MISC,	"Q7_MISC",	DUMP_QCU },
    { AR_Q8_MISC,	"Q8_MISC",	DUMP_QCU },
    { AR_Q9_MISC,	"Q9_MISC",	DUMP_QCU },

    { AR_Q0_STS,	"Q0_STS",	DUMP_QCU },
    { AR_Q1_STS,	"Q1_STS",	DUMP_QCU },
    { AR_Q2_STS,	"Q2_STS",	DUMP_QCU },
    { AR_Q3_STS,	"Q3_STS",	DUMP_QCU },
    { AR_Q4_STS,	"Q4_STS",	DUMP_QCU },
    { AR_Q5_STS,	"Q5_STS",	DUMP_QCU },
    { AR_Q6_STS,	"Q6_STS",	DUMP_QCU },
    { AR_Q7_STS,	"Q7_STS",	DUMP_QCU },
    { AR_Q8_STS,	"Q8_STS",	DUMP_QCU },
    { AR_Q9_STS,	"Q9_STS",	DUMP_QCU },

    { AR_Q_RDYTIMESHDN,	"Q_RDYTIMSHD",	DUMP_QCU },

    { AR_Q_CBBS,	"Q_CBBS",	DUMP_QCU },
    { AR_Q_CBBA,	"Q_CBBA",	DUMP_QCU },
    { AR_Q_CBC,		"Q_CBC",	DUMP_QCU },

    { AR_D0_QCUMASK,	"D0_MASK",	DUMP_DCU },
    { AR_D1_QCUMASK,	"D1_MASK",	DUMP_DCU },
    { AR_D2_QCUMASK,	"D2_MASK",	DUMP_DCU },
    { AR_D3_QCUMASK,	"D3_MASK",	DUMP_DCU },
    { AR_D4_QCUMASK,	"D4_MASK",	DUMP_DCU },
    { AR_D5_QCUMASK,	"D5_MASK",	DUMP_DCU },
    { AR_D6_QCUMASK,	"D6_MASK",	DUMP_DCU },
    { AR_D7_QCUMASK,	"D7_MASK",	DUMP_DCU },
    { AR_D8_QCUMASK,	"D8_MASK",	DUMP_DCU },
    { AR_D9_QCUMASK,	"D9_MASK",	DUMP_DCU },

    { AR_D0_LCL_IFS,	"D0_IFS",	DUMP_DCU },
    { AR_D1_LCL_IFS,	"D1_IFS",	DUMP_DCU },
    { AR_D2_LCL_IFS,	"D2_IFS",	DUMP_DCU },
    { AR_D3_LCL_IFS,	"D3_IFS",	DUMP_DCU },
    { AR_D4_LCL_IFS,	"D4_IFS",	DUMP_DCU },
    { AR_D5_LCL_IFS,	"D5_IFS",	DUMP_DCU },
    { AR_D6_LCL_IFS,	"D6_IFS",	DUMP_DCU },
    { AR_D7_LCL_IFS,	"D7_IFS",	DUMP_DCU },
    { AR_D8_LCL_IFS,	"D8_IFS",	DUMP_DCU },
    { AR_D9_LCL_IFS,	"D9_IFS",	DUMP_DCU },

    { AR_D0_RETRY_LIMIT,"D0_RTRY",	DUMP_DCU },
    { AR_D1_RETRY_LIMIT,"D1_RTRY",	DUMP_DCU },
    { AR_D2_RETRY_LIMIT,"D2_RTRY",	DUMP_DCU },
    { AR_D3_RETRY_LIMIT,"D3_RTRY",	DUMP_DCU },
    { AR_D4_RETRY_LIMIT,"D4_RTRY",	DUMP_DCU },
    { AR_D5_RETRY_LIMIT,"D5_RTRY",	DUMP_DCU },
    { AR_D6_RETRY_LIMIT,"D6_RTRY",	DUMP_DCU },
    { AR_D7_RETRY_LIMIT,"D7_RTRY",	DUMP_DCU },
    { AR_D8_RETRY_LIMIT,"D8_RTRY",	DUMP_DCU },
    { AR_D9_RETRY_LIMIT,"D9_RTRY",	DUMP_DCU },

    { AR_D0_CHNTIME,	"D0_CHNT",	DUMP_DCU },
    { AR_D1_CHNTIME,	"D1_CHNT",	DUMP_DCU },
    { AR_D2_CHNTIME,	"D2_CHNT",	DUMP_DCU },
    { AR_D3_CHNTIME,	"D3_CHNT",	DUMP_DCU },
    { AR_D4_CHNTIME,	"D4_CHNT",	DUMP_DCU },
    { AR_D5_CHNTIME,	"D5_CHNT",	DUMP_DCU },
    { AR_D6_CHNTIME,	"D6_CHNT",	DUMP_DCU },
    { AR_D7_CHNTIME,	"D7_CHNT",	DUMP_DCU },
    { AR_D8_CHNTIME,	"D8_CHNT",	DUMP_DCU },
    { AR_D9_CHNTIME,	"D9_CHNT",	DUMP_DCU },

    { AR_D0_MISC,	"D0_MISC",	DUMP_DCU },
    { AR_D1_MISC,	"D1_MISC",	DUMP_DCU },
    { AR_D2_MISC,	"D2_MISC",	DUMP_DCU },
    { AR_D3_MISC,	"D3_MISC",	DUMP_DCU },
    { AR_D4_MISC,	"D4_MISC",	DUMP_DCU },
    { AR_D5_MISC,	"D5_MISC",	DUMP_DCU },
    { AR_D6_MISC,	"D6_MISC",	DUMP_DCU },
    { AR_D7_MISC,	"D7_MISC",	DUMP_DCU },
    { AR_D8_MISC,	"D8_MISC",	DUMP_DCU },
    { AR_D9_MISC,	"D9_MISC",	DUMP_DCU },

    { AR_D_SEQNUM,	"D_SEQ",	DUMP_BASIC | DUMP_DCU },
    { AR_D_GBL_IFS_SIFS,"D_SIFS",	DUMP_BASIC },
    { AR_D_GBL_IFS_SLOT,"D_SLOT",	DUMP_BASIC },
    { AR_D_GBL_IFS_EIFS,"D_EIFS",	DUMP_BASIC },
    { AR_D_GBL_IFS_MISC,"D_MISC",	DUMP_BASIC },
    { AR_D_FPCTL,	"D_FPCTL",	DUMP_BASIC },
    { AR_D_TXPSE,	"D_TXPSE",	DUMP_BASIC },
#if 0
    { AR_D_TXBLK_CMD,	"D_CMD",	DUMP_BASIC },
    { AR_D_TXBLK_DATA,	"D_DATA",	DUMP_BASIC },
    { AR_D_TXBLK_CLR,	"D_CLR",	DUMP_BASIC },
    { AR_D_TXBLK_SET,	"D_SET",	DUMP_BASIC },
#endif

    { AR_MAC_LED,	"MAC_LED",	DUMP_BASIC },
    { AR_RC,		"RC",		DUMP_BASIC },
    { AR_SCR,		"SCR",		DUMP_BASIC },
    { AR_INTPEND,	"INTPEND",	DUMP_BASIC },
    { AR_SFR,		"SFR",		DUMP_BASIC },
    { AR_PCICFG,	"PCICFG",	DUMP_BASIC },
    { AR_SREV,		"SREV",		DUMP_BASIC },

    { AR_AHB_MODE,	"AHBMODE",	DUMP_BASIC },
    { AR5416_PCIE_PM_CTRL,"PCIEPMC",	DUMP_BASIC },
    { AR5416_PCIE_SERDES,"SERDES",	DUMP_BASIC },
    { AR5416_PCIE_SERDES2, "SERDES2",	DUMP_BASIC },

    { AR_INTR_ASYNC_MASK,"IASYNCM",	DUMP_BASIC },
    { AR_INTR_SYNC_MASK,"ISYNCM",	DUMP_BASIC },
    { AR_RTC_RC,	"RTC_RC",	DUMP_BASIC },
    { AR_RTC_PLL_CONTROL,"RTC_PLL",	DUMP_BASIC },

    { AR_GPIO_IN_OUT,	"GPIOIO",	DUMP_BASIC },
    { AR_GPIO_OE_OUT,	"GPIOOE",	DUMP_BASIC },
    { AR_GPIO_INTR_POL,	"GPIOPOL",	DUMP_BASIC },
    { AR_GPIO_INPUT_EN_VAL,	"GPIOIEV",	DUMP_BASIC },
    { AR_GPIO_INPUT_MUX1,	"GPIMUX1",	DUMP_BASIC },
    { AR_GPIO_INPUT_MUX2,	"GPIMUX2",	DUMP_BASIC },
    { AR_GPIO_OUTPUT_MUX1,	"GPOMUX1",	DUMP_BASIC },
    { AR_GPIO_OUTPUT_MUX2,	"GPOMUX2",	DUMP_BASIC },
    { AR_GPIO_OUTPUT_MUX3,	"GPOMUX3",	DUMP_BASIC },
    { AR_OBS,		"OBS",		DUMP_BASIC },
#if 0
    { AR_EEPROM_ADDR,	"EEADDR",	DUMP_BASIC },
    { AR_EEPROM_DATA,	"EEDATA",	DUMP_BASIC },
    { AR_EEPROM_CMD,	"EECMD",	DUMP_BASIC },
    { AR_EEPROM_STS,	"EESTS",	DUMP_BASIC },
    { AR_EEPROM_CFG,	"EECFG",	DUMP_BASIC },
#endif
    { AR_STA_ID0,	"STA_ID0",	DUMP_BASIC },
    { AR_STA_ID1,	"STA_ID1",	DUMP_BASIC | DUMP_KEYCACHE },
    { AR_BSS_ID0,	"BSS_ID0",	DUMP_BASIC },
    { AR_BSS_ID1,	"BSS_ID1",	DUMP_BASIC },
    { AR_SLOT_TIME,	"SLOTTIME",	DUMP_BASIC },
    { AR_TIME_OUT,	"TIME_OUT",	DUMP_BASIC },
    { AR_RSSI_THR,	"RSSI_THR",	DUMP_BASIC },
    { AR_USEC,		"USEC",		DUMP_BASIC },
    { AR_BEACON,	"BEACON",	DUMP_BASIC },
    { AR_CFP_PERIOD,	"CFP_PER",	DUMP_BASIC },
    { AR_TIMER0,	"TIMER0",	DUMP_BASIC },
    { AR_TIMER1,	"TIMER1",	DUMP_BASIC },
    { AR_TIMER2,	"TIMER2",	DUMP_BASIC },
    { AR_TIMER3,	"TIMER3",	DUMP_BASIC },
    { AR_CFP_DUR,	"CFP_DUR",	DUMP_BASIC },
    { AR_RX_FILTER,	"RXFILTER",	DUMP_BASIC },
    { AR_MCAST_FIL0,	"MCAST_0",	DUMP_BASIC },
    { AR_MCAST_FIL1,	"MCAST_1",	DUMP_BASIC },
    { AR_DIAG_SW,	"DIAG_SW",	DUMP_BASIC },
    { AR_TSF_L32,	"TSF_L32",	DUMP_BASIC },
    { AR_TSF_U32,	"TSF_U32",	DUMP_BASIC },
    { AR_TST_ADDAC,	"TST_ADAC",	DUMP_BASIC },
    { AR_DEF_ANTENNA,	"DEF_ANT",	DUMP_BASIC },
    { AR_QOS_MASK,	"QOS_MASK",	DUMP_BASIC },
    { AR_SEQ_MASK,	"SEQ_MASK",	DUMP_BASIC },
    { AR_OBSERV_2,	"OBSERV2",	DUMP_BASIC },
    { AR_OBSERV_1,	"OBSERV1",	DUMP_BASIC },

    { AR_LAST_TSTP,	"LAST_TST",	DUMP_BASIC },
    { AR_NAV,		"NAV",		DUMP_BASIC },
    { AR_RTS_OK,	"RTS_OK",	DUMP_BASIC },
    { AR_RTS_FAIL,	"RTS_FAIL",	DUMP_BASIC },
    { AR_ACK_FAIL,	"ACK_FAIL",	DUMP_BASIC },
    { AR_FCS_FAIL,	"FCS_FAIL",	DUMP_BASIC },
    { AR_BEACON_CNT,	"BEAC_CNT",	DUMP_BASIC },

    { AR_SLEEP1,	"SLEEP1",	DUMP_BASIC },
    { AR_SLEEP2,	"SLEEP2",	DUMP_BASIC },
    { AR_SLEEP3,	"SLEEP3",	DUMP_BASIC },
    { AR_BSSMSKL,	"BSSMSKL",	DUMP_BASIC },
    { AR_BSSMSKU,	"BSSMSKU",	DUMP_BASIC },
    { AR_TPC,		"TPC",		DUMP_BASIC },
    { AR_TFCNT,		"TFCNT",	DUMP_BASIC },
    { AR_RFCNT,		"RFCNT",	DUMP_BASIC },
    { AR_RCCNT,		"RCCNT",	DUMP_BASIC },
    { AR_CCCNT,		"CCCNT",	DUMP_BASIC },
    { AR_QUIET1,	"QUIET1",	DUMP_BASIC },
    { AR_QUIET2,	"QUIET2",	DUMP_BASIC },
    { AR_TSF_PARM,	"TSF_PARM",	DUMP_BASIC },
    { AR_NOACK,		"NOACK",	DUMP_BASIC },
    { AR_PHY_ERR,	"PHY_ERR",	DUMP_BASIC },
    { AR_QOS_CONTROL,	"QOS_CTRL",	DUMP_BASIC },
    { AR_QOS_SELECT,	"QOS_SEL",	DUMP_BASIC },
    { AR_MISC_MODE,	"MISCMODE",	DUMP_BASIC },
    { AR_FILTOFDM,	"FILTOFDM",	DUMP_BASIC },
    { AR_FILTCCK,	"FILTCCK",	DUMP_BASIC },
    { AR_PHYCNT1,	"PHYCNT1",	DUMP_BASIC },
    { AR_PHYCNTMASK1,	"PHYCMSK1",	DUMP_BASIC },
    { AR_PHYCNT2,	"PHYCNT2",	DUMP_BASIC },
    { AR_PHYCNTMASK2,	"PHYCMSK2",	DUMP_BASIC },

    { AR_TXOP_X,	"TXOPX",	DUMP_BASIC },
    { AR_NEXT_TBTT,	"NXTTBTT",	DUMP_BASIC},
    { AR_NEXT_DBA,	"NXTDBA",	DUMP_BASIC },
    { AR_NEXT_SWBA,	"NXTSWBA",	DUMP_BASIC },
    { AR_NEXT_CFP,	"NXTCFP",	DUMP_BASIC },
    { AR_NEXT_HCF,	"NXTHCF",	DUMP_BASIC },
    { AR_NEXT_DTIM,	"NXTDTIM",	DUMP_BASIC },
    { AR_NEXT_QUIET,	"NXTQUIET",	DUMP_BASIC },
    { AR_NEXT_NDP,	"NXTNDP",	DUMP_BASIC },
    { AR5416_BEACON_PERIOD, "BCNPER",	DUMP_BASIC },
    { AR_DBA_PERIOD,	"DBAPER",	DUMP_BASIC },
    { AR_SWBA_PERIOD,	"SWBAPER",	DUMP_BASIC },
    { AR_TIM_PERIOD,	"TIMPER",	DUMP_BASIC },
    { AR_DTIM_PERIOD,	"DTIMPER",	DUMP_BASIC },
    { AR_QUIET_PERIOD,	"QUIETPER",	DUMP_BASIC },
    { AR_NDP_PERIOD,	"NDPPER",	DUMP_BASIC },
    { AR_TIMER_MODE,	"TIMERMOD",	DUMP_BASIC },
    { AR_2040_MODE,	"2040MODE",	DUMP_BASIC },
    { AR_PCU_TXBUF_CTRL,"PCUTXBUF",	DUMP_BASIC },
    { AR_SLP32_MODE,	"SLP32MOD",	DUMP_BASIC },
    { AR_SLP32_WAKE,	"SLP32WAK",	DUMP_BASIC },
    { AR_SLP32_INC,	"SLP32INC",	DUMP_BASIC },
    { AR_SLP_CNT,	"SLPCNT",	DUMP_BASIC },
    { AR_SLP_MIB_CTRL,	"SLPMIB",	DUMP_BASIC },
    { AR_EXTRCCNT,	"EXTRCCNT",	DUMP_BASIC },

    /* XXX { AR_RATE_DURATION(0), AR_RATE_DURATION(0x20) }, */
};

static __constructor void
ar5416_ctor(void)
{
	register_regs(ar5416regs, N(ar5416regs), MAC5416, PHYANY);
	register_keycache(128, MAC5416, PHYANY);

	register_range(0x9800, 0x987c, DUMP_BASEBAND, MAC5416, PHYANY);
	register_range(0x9900, 0x997c, DUMP_BASEBAND, MAC5416, PHYANY);
	register_range(0x99a4, 0x99a4, DUMP_BASEBAND, MAC5416, PHYANY);
	register_range(0x9c00, 0x9c1c, DUMP_BASEBAND, MAC5416, PHYANY);
	register_range(0xa180, 0xa238, DUMP_BASEBAND, MAC5416, PHYANY);
	register_range(0xa258, 0xa26c, DUMP_BASEBAND, MAC5416, PHYANY);
	register_range(0xa3c8, 0xa3d4, DUMP_BASEBAND, MAC5416, PHYANY);
	register_range(0xa864, 0xa864, DUMP_BASEBAND, MAC5416, PHYANY);
	register_range(0xa9bc, 0xa9bc, DUMP_BASEBAND, MAC5416, PHYANY);
	register_range(0xb864, 0xb864, DUMP_BASEBAND, MAC5416, PHYANY);
	register_range(0xb9bc, 0xb9bc, DUMP_BASEBAND, MAC5416, PHYANY);
}
