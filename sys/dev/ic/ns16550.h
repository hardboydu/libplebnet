/*-
 * Copyright (c) 1991 The Regents of the University of California.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)ns16550.h	7.1 (Berkeley) 5/9/91
 * $FreeBSD$
 */

/*
 * NS8250... UART registers.
 */

/* 8250 registers #[0-6]. */

#define	com_data	0	/* data register (R/W) */
#define	com_thr		com_data /* transmitter holding register (W) */
#define	com_rhr		com_data /* receiver holding register (R) */

#define	com_ier		1	/* interrupt enable register (W) */
#define	IER_ERXRDY	0x1
#define	IER_ETXRDY	0x2
#define	IER_ERLS	0x4
#define	IER_EMSC	0x8

#define	com_iir		2	/* interrupt identification register (R) */
#define	com_isr		com_iir	/* interrupt status register (R) */
#define	IIR_IMASK	0xf
#define	IIR_RXTOUT	0xc
#define	IIR_RLS		0x6
#define	IIR_RXRDY	0x4
#define	IIR_TXRDY	0x2
#define	IIR_NOPEND	0x1
#define	IIR_MLSC	0x0
#define	IIR_FIFO_MASK	0xc0	/* set if FIFOs are enabled */

#define	com_lcr		3	/* line control register (R/W) */
#define	com_lctl	com_lcr
#define	com_cfcr	com_lcr	/* character format control register (R/W) */
#define	LCR_DLAB	0x80
#define	CFCR_DLAB	LCR_DLAB
#define	LCR_EFR_ENABLE	0xbf	/* magic to enable EFR on 16650 up */
#define	CFCR_EFR_ENABLE	LCR_EFR_ENABLE
#define	CFCR_SBREAK	0x40
#define	CFCR_PZERO	0x30
#define	CFCR_PONE	0x20
#define	CFCR_PEVEN	0x10
#define	CFCR_PODD	0x00
#define	CFCR_PENAB	0x08
#define	CFCR_STOPB	0x04
#define	CFCR_8BITS	0x03
#define	CFCR_7BITS	0x02
#define	CFCR_6BITS	0x01
#define	CFCR_5BITS	0x00

#define	com_mcr		4	/* modem control register (R/W) */
#define	MCR_PRESCALE	0x80	/* only available on 16650 up */
#define	MCR_LOOPBACK	0x10
#define	MCR_IENABLE	0x08
#define	MCR_DRS		0x04
#define	MCR_RTS		0x02
#define	MCR_DTR		0x01

#define	com_lsr		5	/* line status register (R/W) */
#define	LSR_RCV_FIFO	0x80
#define	LSR_TSRE	0x40
#define	LSR_TXRDY	0x20
#define	LSR_BI		0x10
#define	LSR_FE		0x08
#define	LSR_PE		0x04
#define	LSR_OE		0x02
#define	LSR_RXRDY	0x01
#define	LSR_RCV_MASK	0x1f

#define	com_msr		6	/* modem status register (R/W) */
#define	MSR_DCD		0x80
#define	MSR_RI		0x40
#define	MSR_DSR		0x20
#define	MSR_CTS		0x10
#define	MSR_DDCD	0x08
#define	MSR_TERI	0x04
#define	MSR_DDSR	0x02
#define	MSR_DCTS	0x01

/* 8250 multiplexed registers #[0-1].  Access enabled by LCR[7]. */
#define	com_dll		0	/* divisor latch low (R/W) */
#define	com_dlbl	com_dll
#define	com_dlm		1	/* divisor latch high (R/W) */
#define	com_dlbh	com_dlm

/* 16450 register #7.  Not multiplexed. */
#define	com_scr		7	/* scratch register (R/W) */

/* 16550 register #2.  Not multiplexed. */
#define	com_fcr		2	/* FIFO control register (W) */
#define	com_fifo	com_fcr
#define	FIFO_ENABLE	0x01
#define	FIFO_RCV_RST	0x02
#define	FIFO_XMT_RST	0x04
#define	FIFO_DMA_MODE	0x08
#define	FIFO_RX_LOW	0x00
#define	FIFO_RX_MEDL	0x40
#define	FIFO_RX_MEDH	0x80
#define	FIFO_RX_HIGH	0xc0

/* 16650 registers #2,[4-7].  Access enabled by LCR_EFR_ENABLE. */

#define	com_efr		2	/* enhanced features register (R/W) */
#define	EFR_EFE		0x10	/* enhanced functions enable */

#ifdef PC98
/* Hardware extension mode register for RSB-2000/3000. */
#define	com_emr		com_msr
#define	EMR_EXBUFF	0x04
#define	EMR_CTSFLW	0x08
#define	EMR_DSRFLW	0x10
#define	EMR_RTSFLW	0x20
#define	EMR_DTRFLW	0x40
#define	EMR_EFMODE	0x80
#endif
