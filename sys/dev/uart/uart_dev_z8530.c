/*
 * Copyright (c) 2003 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <machine/bus.h>

#include <dev/uart/uart.h>
#include <dev/uart/uart_cpu.h>
#include <dev/uart/uart_bus.h>
#include <dev/uart/uart_dev_z8530.h>

#include "uart_if.h"

#define	DEFAULT_RCLK	307200

#define	IS_CHANNEL_A(bas)	((uart_cpu_busaddr(bas) & 7) != 0)
#define	IS_CHANNEL_B(bas)	((uart_cpu_busaddr(bas) & 7) == 0)

/* Multiplexed I/O. */
static __inline void
uart_setmreg(struct uart_bas *bas, int reg, int val)
{

	uart_setreg(bas, REG_CTRL, reg);
	uart_barrier(bas);
	uart_setreg(bas, REG_CTRL, val);
}

static __inline uint8_t
uart_getmreg(struct uart_bas *bas, int reg)
{

	uart_setreg(bas, REG_CTRL, reg);
	uart_barrier(bas);
	return (uart_getreg(bas, REG_CTRL));
}

static int
z8530_divisor(int rclk, int baudrate)
{
	int act_baud, divisor, error;

	if (baudrate == 0)
		return (0);

	divisor = (rclk + baudrate) / (baudrate << 1) - 2;
	if (divisor >= 65536)
		return (0);
	act_baud = rclk / 2 / (divisor + 2);

	/* 10 times error in percent: */
	error = ((act_baud - baudrate) * 2000 / baudrate + 1) >> 1;

	/* 3.0% maximum error tolerance: */
	if (error < -30 || error > 30)
		return (0);

	return (divisor);
}

static int
z8530_param(struct uart_bas *bas, int baudrate, int databits, int stopbits,
    int parity, uint8_t *tpcp)
{
	int divisor;
	uint8_t mpm, rpc, tpc;

	rpc = RPC_RXE;
	mpm = MPM_CM16;
	tpc = TPC_TXE | (*tpcp & (TPC_DTR | TPC_RTS));

	if (databits >= 8) {
		rpc |= RPC_RB8;
		tpc |= TPC_TB8;
	} else if (databits == 7) {
		rpc |= RPC_RB7;
		tpc |= TPC_TB7;
	} else if (databits == 6) {
		rpc |= RPC_RB6;
		tpc |= TPC_TB6;
	} else {
		rpc |= RPC_RB5;
		tpc |= TPC_TB5;
	}
	mpm |= (stopbits > 1) ? MPM_SB2 : MPM_SB1;
	switch (parity) {
	case UART_PARITY_EVEN:	mpm |= MPM_PE | MPM_EVEN; break;
	case UART_PARITY_NONE:	break;
	case UART_PARITY_ODD:	mpm |= MPM_PE; break;
	default:		return (EINVAL);
	}

	/* Set baudrate. */
	if (baudrate > 0) {
		divisor = z8530_divisor(bas->rclk, baudrate);
		if (divisor == 0)
			return (EINVAL);
		uart_setmreg(bas, WR_TCL, divisor & 0xff);
		uart_barrier(bas);
		uart_setmreg(bas, WR_TCH, (divisor >> 8) & 0xff);
		uart_barrier(bas);
	}

	uart_setmreg(bas, WR_RPC, rpc);
	uart_barrier(bas);
	uart_setmreg(bas, WR_MPM, mpm);
	uart_barrier(bas);
	uart_setmreg(bas, WR_TPC, tpc);
	uart_barrier(bas);
	*tpcp = tpc;
	return (0);
}

static int
z8530_setup(struct uart_bas *bas, int baudrate, int databits, int stopbits,
    int parity)
{
	uint8_t tpc;

	if (bas->rclk == 0)
		bas->rclk = DEFAULT_RCLK;

	/* Assume we don't need to perform a full hardware reset. */
	uart_setmreg(bas, WR_MIC, ((IS_CHANNEL_A(bas)) ? MIC_CRA : MIC_CRB) |
	    MIC_MIE | MIC_NV);
	uart_barrier(bas);
	/* Set clock sources and enable BRG. */
	uart_setmreg(bas, WR_CMC, CMC_RC_BRG | CMC_TC_BRG);
	uart_setmreg(bas, WR_MCB2, MCB2_PCLK | MCB2_BRGE);
	uart_barrier(bas);
	/* Set data encoding. */
	uart_setmreg(bas, WR_MCB1, MCB1_NRZ);
	uart_barrier(bas);

	tpc = TPC_DTR | TPC_RTS;
	z8530_param(bas, baudrate, databits, stopbits, parity, &tpc);
	return (int)tpc;
}

/*
 * Low-level UART interface.
 */
static int z8530_probe(struct uart_bas *bas);
static void z8530_init(struct uart_bas *bas, int, int, int, int);
static void z8530_term(struct uart_bas *bas);
static void z8530_putc(struct uart_bas *bas, int);
static int z8530_poll(struct uart_bas *bas);
static int z8530_getc(struct uart_bas *bas);

struct uart_ops uart_z8530_ops = {
	.probe = z8530_probe,
	.init = z8530_init,
	.term = z8530_term,
	.putc = z8530_putc,
	.poll = z8530_poll,
	.getc = z8530_getc,
};

static int
z8530_probe(struct uart_bas *bas)
{

	return (0);
}

static void
z8530_init(struct uart_bas *bas, int baudrate, int databits, int stopbits,
    int parity)
{

	z8530_setup(bas, baudrate, databits, stopbits, parity);
}

static void
z8530_term(struct uart_bas *bas)
{
}

static void
z8530_putc(struct uart_bas *bas, int c)
{

	while (!(uart_getmreg(bas, RR_BES) & BES_TXE))
		;
	uart_setreg(bas, REG_DATA, c);
	uart_barrier(bas);
}

static int
z8530_poll(struct uart_bas *bas)
{

	if (!(uart_getmreg(bas, RR_BES) & BES_RXA))
		return (-1);
	return (uart_getreg(bas, REG_DATA));
}

static int
z8530_getc(struct uart_bas *bas)
{

	while (!(uart_getmreg(bas, RR_BES) & BES_RXA))
		;
	return (uart_getreg(bas, REG_DATA));
}

/*
 * High-level UART interface.
 */
struct z8530_softc {
	struct uart_softc base;
	uint8_t	tpc;
};

static int z8530_bus_attach(struct uart_softc *);
static int z8530_bus_detach(struct uart_softc *);
static int z8530_bus_flush(struct uart_softc *, int);
static int z8530_bus_getsig(struct uart_softc *);
static int z8530_bus_ioctl(struct uart_softc *, int, intptr_t);
static int z8530_bus_ipend(struct uart_softc *);
static int z8530_bus_param(struct uart_softc *, int, int, int, int);
static int z8530_bus_probe(struct uart_softc *);
static int z8530_bus_receive(struct uart_softc *);
static int z8530_bus_setsig(struct uart_softc *, int);
static int z8530_bus_transmit(struct uart_softc *);

static kobj_method_t z8530_methods[] = {
	KOBJMETHOD(uart_attach,		z8530_bus_attach),
	KOBJMETHOD(uart_detach,		z8530_bus_detach),
	KOBJMETHOD(uart_flush,		z8530_bus_flush),
	KOBJMETHOD(uart_getsig,		z8530_bus_getsig),
	KOBJMETHOD(uart_ioctl,		z8530_bus_ioctl),
	KOBJMETHOD(uart_ipend,		z8530_bus_ipend),
	KOBJMETHOD(uart_param,		z8530_bus_param),
	KOBJMETHOD(uart_probe,		z8530_bus_probe),
	KOBJMETHOD(uart_receive,	z8530_bus_receive),
	KOBJMETHOD(uart_setsig,		z8530_bus_setsig),
	KOBJMETHOD(uart_transmit,	z8530_bus_transmit),
	{ 0, 0 }
};

struct uart_class uart_z8530_class = {
	"z8530 class",
	z8530_methods,
	sizeof(struct z8530_softc),
	.uc_range = 2,
	.uc_rclk = DEFAULT_RCLK
};

#define	SIGCHG(c, i, s, d)				\
	if (c) {					\
		i |= (i & s) ? s : s | d;		\
	} else {					\
		i = (i & s) ? (i & ~s) | d : i;		\
	}

static int
z8530_bus_attach(struct uart_softc *sc)
{
	struct z8530_softc *z8530 = (struct z8530_softc*)sc;
	struct uart_bas *bas;
	struct uart_devinfo *di;

	bas = &sc->sc_bas;
	if (sc->sc_sysdev != NULL) {
		di = sc->sc_sysdev;
		z8530->tpc = TPC_DTR|TPC_RTS;
		z8530_param(bas, di->baudrate, di->databits, di->stopbits,
		    di->parity, &z8530->tpc);
	} else {
		z8530->tpc = z8530_setup(bas, 9600, 8, 1, UART_PARITY_NONE);
		z8530->tpc &= ~(TPC_DTR|TPC_RTS);
	}

	sc->sc_rxfifosz = 3;
	sc->sc_txfifosz = 1;

	(void)z8530_bus_getsig(sc);

	uart_setmreg(bas, WR_IC, IC_BRK | IC_CTS | IC_DCD);
	uart_barrier(bas);
	uart_setmreg(bas, WR_IDT, IDT_TIE | IDT_RIA);
	uart_barrier(bas);
	uart_setmreg(bas, WR_IV, 0);
	uart_barrier(bas);
	uart_setmreg(bas, WR_TPC, z8530->tpc);
	uart_barrier(bas);
	return (0);
}

static int
z8530_bus_detach(struct uart_softc *sc)
{

	return (0);
}

static int
z8530_bus_flush(struct uart_softc *sc, int what)
{

	return (0);
}

static int
z8530_bus_getsig(struct uart_softc *sc)
{
	uint32_t new, old, sig;
	uint8_t bes;

	do {
		old = sc->sc_hwsig;
		sig = old;
		mtx_lock_spin(&sc->sc_hwmtx);
		bes = uart_getmreg(&sc->sc_bas, RR_BES);
		mtx_unlock_spin(&sc->sc_hwmtx);
		SIGCHG(bes & BES_CTS, sig, UART_SIG_CTS, UART_SIG_DCTS);
		SIGCHG(bes & BES_DCD, sig, UART_SIG_DCD, UART_SIG_DDCD);
		new = sig & ~UART_SIGMASK_DELTA;
	} while (!atomic_cmpset_32(&sc->sc_hwsig, old, new));
	return (sig);
}

static int
z8530_bus_ioctl(struct uart_softc *sc, int request, intptr_t data)
{
	struct z8530_softc *z8530 = (struct z8530_softc*)sc;
	struct uart_bas *bas;
	int error;

	bas = &sc->sc_bas;
	error = 0;
	mtx_lock_spin(&sc->sc_hwmtx);
	switch (request) {
	case UART_IOCTL_BREAK:
		if (data)
			z8530->tpc |= TPC_BRK;
		else
			z8530->tpc &= ~TPC_BRK;
		uart_setmreg(bas, WR_TPC, z8530->tpc);
		uart_barrier(bas);
		break;
	default:
		error = EINVAL;
		break;
	}
	mtx_unlock_spin(&sc->sc_hwmtx);
	return (error);
}

static int
z8530_bus_ipend(struct uart_softc *sc)
{
	struct uart_bas *bas;
	int ipend;
	uint32_t sig;
	uint8_t bes, src;

	bas = &sc->sc_bas;
	ipend = 0;
	mtx_lock_spin(&sc->sc_hwmtx);
	uart_setreg(bas, REG_CTRL, CR_RSTIUS);
	uart_barrier(bas);
	bes = uart_getmreg(bas, RR_BES);
	if (bes & BES_BRK) {
		uart_setreg(bas, REG_CTRL, CR_RSTXSI);
		ipend |= UART_IPEND_BREAK;
	}
	if (bes & BES_TXE) {
		uart_setreg(bas, REG_CTRL, CR_RSTTXI);
		ipend |= UART_IPEND_TXIDLE;
	}
	if (bes & BES_RXA)
		ipend |= UART_IPEND_RXREADY;
	sig = sc->sc_hwsig;
	SIGCHG(bes & BES_CTS, sig, UART_SIG_CTS, UART_SIG_DCTS);
	SIGCHG(bes & BES_DCD, sig, UART_SIG_DCD, UART_SIG_DDCD);
	if (sig & UART_SIGMASK_DELTA)
		ipend |= UART_IPEND_SIGCHG;
	src = uart_getmreg(bas, RR_SRC);
	if (src & SRC_OVR) {
		uart_setreg(bas, REG_CTRL, CR_RSTERR);
		ipend |= UART_IPEND_OVERRUN;
	}
	mtx_unlock_spin(&sc->sc_hwmtx);
	return (ipend);
}

static int
z8530_bus_param(struct uart_softc *sc, int baudrate, int databits,
    int stopbits, int parity)
{
	struct z8530_softc *z8530 = (struct z8530_softc*)sc;
	int error;

	mtx_lock_spin(&sc->sc_hwmtx);
	error = z8530_param(&sc->sc_bas, baudrate, databits, stopbits, parity,
	    &z8530->tpc);
	mtx_unlock_spin(&sc->sc_hwmtx);
	return (error);
}

static int
z8530_bus_probe(struct uart_softc *sc)
{
	char buf[80];
	const char *ch;
	int error;

	error = z8530_probe(&sc->sc_bas);
	if (error)
		return (error);

	/* Assume the address range is naturally aligned. */
	ch = IS_CHANNEL_A(&sc->sc_bas) ? "A" : "B";

	snprintf(buf, sizeof(buf), "z8530, channel %s", ch);
	device_set_desc_copy(sc->sc_dev, buf);
	return (0);
}

static int
z8530_bus_receive(struct uart_softc *sc)
{
	struct uart_bas *bas;
	int xc;
	uint8_t bes, src;

	bas = &sc->sc_bas;
	mtx_lock_spin(&sc->sc_hwmtx);
	bes = uart_getmreg(bas, RR_BES);
	while ((bes & BES_RXA) && !uart_rx_full(sc)) {
		src = uart_getmreg(bas, RR_SRC);
		xc = uart_getreg(bas, REG_DATA);
		if (src & SRC_FE)
			xc |= UART_STAT_FRAMERR;
		if (src & SRC_PE)
			xc |= UART_STAT_PARERR;
		uart_rx_put(sc, xc);
		if (src & (SRC_FE | SRC_PE))
			uart_setreg(bas, REG_CTRL, CR_RSTERR);
		bes = uart_getmreg(bas, RR_BES);
	}
	mtx_unlock_spin(&sc->sc_hwmtx);
	return (0);
}

static int
z8530_bus_setsig(struct uart_softc *sc, int sig)
{
	struct z8530_softc *z8530 = (struct z8530_softc*)sc;
	struct uart_bas *bas;
	uint32_t new, old;

	bas = &sc->sc_bas;
	do {
		old = sc->sc_hwsig;
		new = old;
		if (sig & UART_SIG_DDTR) {
			SIGCHG(sig & UART_SIG_DTR, new, UART_SIG_DTR,
			    UART_SIG_DDTR);
		}
		if (sig & UART_SIG_DRTS) {
			SIGCHG(sig & UART_SIG_RTS, new, UART_SIG_RTS,
			    UART_SIG_DRTS);
		}
	} while (!atomic_cmpset_32(&sc->sc_hwsig, old, new));

	mtx_lock_spin(&sc->sc_hwmtx);
	if (new & UART_SIG_DTR)
		z8530->tpc |= TPC_DTR;
	else
		z8530->tpc &= ~TPC_DTR;
	if (new & UART_SIG_RTS)
		z8530->tpc |= TPC_RTS;
	else
		z8530->tpc &= ~TPC_RTS;
	uart_setmreg(bas, WR_TPC, z8530->tpc);
	uart_barrier(bas);
	mtx_unlock_spin(&sc->sc_hwmtx);
	return (0);
}

static int
z8530_bus_transmit(struct uart_softc *sc)
{
	struct uart_bas *bas;

	bas = &sc->sc_bas;
	mtx_lock_spin(&sc->sc_hwmtx);
	while (!(uart_getmreg(bas, RR_BES) & BES_TXE))
		;
	uart_setreg(bas, REG_DATA, sc->sc_txbuf[0]);
	uart_barrier(bas);
	sc->sc_txbusy = 1;
	mtx_unlock_spin(&sc->sc_hwmtx);
	return (0);
}
