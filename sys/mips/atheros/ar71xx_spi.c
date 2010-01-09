/*-
 * Copyright (c) 2009, Oleksandr Tymoshenko <gonzo@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>

#include <sys/bus.h>
#include <sys/interrupt.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>

#include <machine/bus.h>
#include <machine/cpu.h>
#include <machine/pmap.h>

#include <dev/spibus/spi.h>
#include <dev/spibus/spibusvar.h>
#include "spibus_if.h"

#include <mips/atheros/ar71xxreg.h>

#undef AR71XX_SPI_DEBUG
#ifdef AR71XX_SPI_DEBUG
#define dprintf printf
#else
#define dprintf(x, arg...)
#endif

/*
 * register space access macros
 */
#define SPI_WRITE(sc, reg, val)	do {	\
		bus_write_4(sc->sc_mem_res, (reg), (val)); \
	} while (0)

#define SPI_READ(sc, reg)	 bus_read_4(sc->sc_mem_res, (reg))

#define SPI_SET_BITS(sc, reg, bits)	\
	SPI_WRITE(sc, reg, SPI_READ(sc, (reg)) | (bits))

#define SPI_CLEAR_BITS(sc, reg, bits)	\
	SPI_WRITE(sc, reg, SPI_READ(sc, (reg)) & ~(bits))

struct ar71xx_spi_softc {
	device_t		sc_dev;
	struct resource		*sc_mem_res;
	uint32_t		sc_reg_ioctrl;
};

static int
ar71xx_spi_probe(device_t dev)
{
	device_set_desc(dev, "AR71XX SPI");
	return (0);
}

static int
ar71xx_spi_attach(device_t dev)
{
	struct ar71xx_spi_softc *sc = device_get_softc(dev);
	int rid;

	sc->sc_dev = dev;
        rid = 0;
	sc->sc_mem_res = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &rid, 
	    RF_ACTIVE);
	if (!sc->sc_mem_res) {
		device_printf(dev, "Could not map memory\n");
		return (ENXIO);
	}

	sc->sc_reg_ioctrl  = SPI_READ(sc, AR71XX_SPI_IO_CTRL);

	SPI_WRITE(sc, AR71XX_SPI_IO_CTRL, SPI_IO_CTRL_CS0 | SPI_IO_CTRL_CS1 |
	    SPI_IO_CTRL_CS2);
	SPI_WRITE(sc, AR71XX_SPI_CTRL, sc->sc_reg_ioctrl);
	SPI_WRITE(sc, AR71XX_SPI_FS, 0);

	device_add_child(dev, "spibus", 0);
	return (bus_generic_attach(dev));
}

static void
ar71xx_spi_chip_activate(struct ar71xx_spi_softc *sc, int cs)
{
	uint32_t ioctrl = SPI_IO_CTRL_CS0 |SPI_IO_CTRL_CS1 | SPI_IO_CTRL_CS2;
	/*
	 * Put respective CSx to low
	 */
	ioctrl &= ~(SPI_IO_CTRL_CS0 << cs);

	SPI_WRITE(sc, AR71XX_SPI_FS, 1);
	SPI_WRITE(sc, AR71XX_SPI_CTRL, 0x43);
	SPI_WRITE(sc, AR71XX_SPI_IO_CTRL, ioctrl);
}

static void
ar71xx_spi_chip_deactivate(struct ar71xx_spi_softc *sc, int cs)
{
	/*
	 * Put all CSx to high
	 */
	SPI_WRITE(sc, AR71XX_SPI_IO_CTRL, SPI_IO_CTRL_CS0 | SPI_IO_CTRL_CS1 |
	    SPI_IO_CTRL_CS2);
	SPI_WRITE(sc, AR71XX_SPI_CTRL, sc->sc_reg_ioctrl);
	SPI_WRITE(sc, AR71XX_SPI_FS, 0);
}

static uint8_t
ar71xx_spi_txrx(struct ar71xx_spi_softc *sc, uint8_t data)
{
	int bit;
	/* CS0 */
	uint32_t ioctrl = SPI_IO_CTRL_CS1 | SPI_IO_CTRL_CS2;

	uint32_t iod, rds;
	for (bit = 7; bit >=0; bit--) {
		if (data & (1 << bit))
			iod = ioctrl | SPI_IO_CTRL_DO;
		else
			iod = ioctrl & ~SPI_IO_CTRL_DO;
		SPI_WRITE(sc, AR71XX_SPI_IO_CTRL, iod);
		SPI_WRITE(sc, AR71XX_SPI_IO_CTRL, iod | SPI_IO_CTRL_CLK);
	}

	rds = SPI_READ(sc, AR71XX_SPI_RDS);

	return (rds & 0xff);
}

static int
ar71xx_spi_transfer(device_t dev, device_t child, struct spi_command *cmd)
{
	struct ar71xx_spi_softc *sc;
	uint8_t *buf_in, *buf_out;
	struct spibus_ivar *devi = SPIBUS_IVAR(child);
	int i;

	sc = device_get_softc(dev);

	ar71xx_spi_chip_activate(sc, devi->cs);

	KASSERT(cmd->tx_cmd_sz == cmd->rx_cmd_sz, 
	    ("TX/RX command sizes should be equal"));
	KASSERT(cmd->tx_data_sz == cmd->rx_data_sz, 
	    ("TX/RX data sizes should be equal"));

	/*
	 * Transfer command
	 */
	buf_out = (uint8_t *)cmd->tx_cmd;
	buf_in = (uint8_t *)cmd->rx_cmd;
	for (i = 0; i < cmd->tx_cmd_sz; i++)
		buf_in[i] = ar71xx_spi_txrx(sc, buf_out[i]);

	/*
	 * Receive/transmit data (depends on  command)
	 */
	buf_out = (uint8_t *)cmd->tx_data;
	buf_in = (uint8_t *)cmd->rx_data;
	for (i = 0; i < cmd->tx_data_sz; i++)
		buf_in[i] = ar71xx_spi_txrx(sc, buf_out[i]);

	ar71xx_spi_chip_deactivate(sc, devi->cs);

	return (0);
}

static int
ar71xx_spi_detach(device_t dev)
{

	return (EBUSY);	/* XXX */
}

static device_method_t ar71xx_spi_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		ar71xx_spi_probe),
	DEVMETHOD(device_attach,	ar71xx_spi_attach),
	DEVMETHOD(device_detach,	ar71xx_spi_detach),

	DEVMETHOD(spibus_transfer,	ar71xx_spi_transfer),

	{0, 0}
};

static driver_t ar71xx_spi_driver = {
	"spi",
	ar71xx_spi_methods,
	sizeof(struct ar71xx_spi_softc),
};

static devclass_t ar71xx_spi_devclass;

DRIVER_MODULE(ar71xx_spi, nexus, ar71xx_spi_driver, ar71xx_spi_devclass, 0, 0);
