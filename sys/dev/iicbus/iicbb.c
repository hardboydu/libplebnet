/*-
 * Copyright (c) 1998 Nicolas Souchu
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
 *	$Id: iicbb.c,v 1.3 1999/01/28 15:50:24 roger Exp $
 *
 */

/*
 * Generic I2C bit-banging code
 *
 * Example:
 *
 *	iicbus
 *	 /  \ 
 *    iicbb pcf
 *     |  \
 *   bti2c lpbb
 *
 * From Linux I2C generic interface
 * (c) 1998 Gerd Knorr <kraxel@cs.tu-berlin.de>
 *
 * TODO: port Peter's generic bit-banging code <dufault@hda.com>
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/malloc.h>

#include <machine/clock.h>

#include <dev/iicbus/iiconf.h>
#include <dev/iicbus/iicbus.h>

#include <dev/smbus/smbconf.h>

#include "iicbus_if.h"
#include "iicbb_if.h"

struct iicbb_softc {
	int dummy;
};

static int iicbb_probe(device_t);
static int iicbb_attach(device_t);
static void iicbb_print_child(device_t, device_t);

static int iicbb_callback(device_t, int, caddr_t);
static int iicbb_start(device_t, u_char, int);
static int iicbb_stop(device_t);
static int iicbb_write(device_t, char *, int, int *, int);
static int iicbb_read(device_t, char *, int, int *, int, int);
static int iicbb_reset(device_t, u_char, u_char, u_char *);

static device_method_t iicbb_methods[] = {
	/* device interface */
	DEVMETHOD(device_probe,		iicbb_probe),
	DEVMETHOD(device_attach,	iicbb_attach),

	/* bus interface */
	DEVMETHOD(bus_print_child,	iicbb_print_child),

	/* iicbus interface */
	DEVMETHOD(iicbus_callback,	iicbb_callback),
	DEVMETHOD(iicbus_start,		iicbb_start),
	DEVMETHOD(iicbus_repeated_start, iicbb_start),
	DEVMETHOD(iicbus_stop,		iicbb_stop),
	DEVMETHOD(iicbus_write,		iicbb_write),
	DEVMETHOD(iicbus_read,		iicbb_read),
	DEVMETHOD(iicbus_reset,		iicbb_reset),

	{ 0, 0 }
};

static driver_t iicbb_driver = {
	"iicbb",
	iicbb_methods,
	sizeof(struct iicbb_softc),
};

static devclass_t iicbb_devclass;

static int iicbb_probe(device_t dev)
{
	device_set_desc(dev, "I2C generic bit-banging driver");

	return (0);
}

static int iicbb_attach(device_t dev)
{
	return (0);
}

static void
iicbb_print_child(device_t bus, device_t dev)
{
	int error;
	u_char oldaddr;

	/* retrieve the interface I2C address */
	error = IICBB_RESET(device_get_parent(bus), IIC_FASTEST, 0, &oldaddr);
	if (error == IIC_ENOADDR) {
		printf(" on %s%d master-only", device_get_name(bus),
			device_get_unit(bus));

	} else {
		/* restore the address */
		IICBB_RESET(device_get_parent(bus), IIC_FASTEST, oldaddr, NULL);

		printf(" on %s%d addr 0x%x", device_get_name(bus),
			device_get_unit(bus), oldaddr & 0xff);
	}

	return;
}

#define I2C_SET(dev,ctrl,data) \
	IICBB_SETLINES(device_get_parent(dev), ctrl, data)

#define I2C_GET(dev) (IICBB_GETDATALINE(device_get_parent(dev)))

static int i2c_debug = 0;
#define I2C_DEBUG(x) if (i2c_debug) (x)

static void iicbb_one(device_t dev)
{
	I2C_SET(dev,0,1);
	I2C_SET(dev,1,1);
	I2C_SET(dev,0,1);
	return;
}

static void iicbb_zero(device_t dev)
{
	I2C_SET(dev,0,0);
	I2C_SET(dev,1,0);
	I2C_SET(dev,0,0);
	return;
}

/*
 * Waiting for ACKNOWLEDGE.
 *
 * When a chip is being addressed or has received data it will issue an
 * ACKNOWLEDGE pulse. Therefore the MASTER must release the DATA line
 * (set it to high level) and then release the CLOCK line.
 * Now it must wait for the SLAVE to pull the DATA line low.
 * Actually on the bus this looks like a START condition so nothing happens
 * because of the fact that the IC's that have not been addressed are doing
 * nothing.
 *
 * When the SLAVE has pulled this line low the MASTER will take the CLOCK
 * line low and then the SLAVE will release the SDA (data) line.
 */
static int iicbb_ack(device_t dev, int timeout)
{
	int noack;
	int k = timeout/10;
    
	I2C_SET(dev,0,1);
	I2C_SET(dev,1,1);

	do {
		noack = I2C_GET(dev);
		if (!noack)
			break;
		DELAY(10);		/* XXX wait 10us */
	} while (k--);

	I2C_SET(dev,0,1);
	I2C_DEBUG(printf("%c ",noack?'-':'+'));

	return (noack);
}

static void iicbb_sendbyte(device_t dev, u_char data)
{
	int i;
    
	I2C_SET(dev,0,0);
	for (i=7; i>=0; i--)
		(data&(1<<i)) ? iicbb_one(dev) : iicbb_zero(dev);
	I2C_DEBUG(printf("w%02x",(int)data));
	return;
}

static u_char iicbb_readbyte(device_t dev, int last)
{
	int i;
	unsigned char data=0;
    
	I2C_SET(dev,0,1);
	for (i=7; i>=0; i--) 
	{
		I2C_SET(dev,1,1);
		if (I2C_GET(dev))
			data |= (1<<i);
		I2C_SET(dev,0,1);
	}
	last ? iicbb_one(dev) : iicbb_zero(dev);
	I2C_DEBUG(printf("r%02x%c ",(int)data,last?'-':'+'));
	return data;
}

static int iicbb_callback(device_t dev, int index, caddr_t data)
{
	return (IICBB_CALLBACK(device_get_parent(dev), index, data));
}

static int iicbb_reset(device_t dev, u_char speed, u_char addr, u_char *oldaddr)
{
	return (IICBB_RESET(device_get_parent(dev), speed, addr, oldaddr));
}

static int iicbb_start(device_t dev, u_char slave, int timeout)
{
	int error;

	I2C_DEBUG(printf("<"));

	I2C_SET(dev,0,1);
	I2C_SET(dev,1,1);
	I2C_SET(dev,1,0);
	I2C_SET(dev,0,0);

	/* send address */
	iicbb_sendbyte(dev, slave);

	/* check for ack */
	if (iicbb_ack(dev, timeout)) {
		error = IIC_ENOACK;
		goto error;
	}

	return(0);

error:
	iicbb_stop(dev);
	return (error);
}

static int iicbb_stop(device_t dev)
{
	I2C_SET(dev,0,0);
	I2C_SET(dev,1,0);
	I2C_SET(dev,1,1);
	I2C_DEBUG(printf(">"));
	return (0);
}

static int iicbb_write(device_t dev, char * buf, int len, int *sent,
			int timeout)
{
	int bytes, error = 0;

	bytes = 0;
	while (len) {
		/* send byte */
		iicbb_sendbyte(dev,(u_char)*buf++);

		/* check for ack */
		if (iicbb_ack(dev, timeout)) {
			error = IIC_ENOACK;
			goto error;
		}
		bytes ++;
		len --;
	}

error:
	*sent = bytes;
	return (error);
}

static int iicbb_read(device_t dev, char * buf, int len, int *read,
			int last, int delay)
{
	int bytes;

	bytes = 0;
	while (len) {
		/* XXX should insert delay here */
		*buf++ = (char)iicbb_readbyte(dev, (len == 1) ? last : 0);

		bytes ++;
		len --;
	}

	*read = bytes;
	return (0);
}

DRIVER_MODULE(iicbb, bti2c, iicbb_driver, iicbb_devclass, 0, 0);
DRIVER_MODULE(iicbb, lpbb, iicbb_driver, iicbb_devclass, 0, 0);
