/*
 * Copyright (c) 2003 M. Warner Losh, Marcel Moolenaar
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

#include <machine/bus.h>

#include <dev/uart/uart.h>
#include <dev/uart/uart_cpu.h>

int
uart_cpu_eqres(struct uart_bas *b1, struct uart_bas *b2)
{

	return ((b1->iobase == b2->iobase && b1->bst == b2->bst) ? 1 : 0);
}

int
uart_cpu_getdev(int devtype, struct uart_devinfo *di)
{
	unsigned int i, ivar, flags;

	/*
	 * There are 2 built-in serial ports on pc98 hardware.  The 
	 * first one is 8251 and the second one is I think an enhance
	 * version of that.  However, for the sio driver, flags selected
	 * which type of uart was in the sytem.  We use something similar
	 * to sort things out.
	 */
	for (i = 0; i < 1; i++) {
		if (resource_int_value("uart", i, "flags", &flags))
			continue;
		if (devtype == UART_DEV_CONSOLE && !UART_FLAGS_CONSOLE(flags))
			continue;
		if (devtype == UART_DEV_DBGPORT && !UART_FLAGS_DBGPORT(flags))
			continue;
		/*
		 * We have a possible device. Make sure it's enabled and
		 * that we have an I/O port.
		 */
		if (resource_int_value("uart", i, "disabled", &ivar) == 0 &&
		    ivar != 0)
			continue;
		if (resource_int_value("uart", i, "port", &ivar) != 0 ||
		    ivar == 0)
			continue;
		/*
		 * Got it. Fill in the instance and return it. We have
		 * both i8251 an ns8250 and successors on pc98.
		 */
		if (flags & 0x100)
			di->ops = uart_ns8250_ops;
		else
			di->ops = uart_i8251_ops;
		di->bas.iobase = ivar;
		di->bas.bst = I386_BUS_SPACE_IO;
		if (bus_space_map(di->bas.bst, ivar, 8, 0, &di->bas.bsh) != 0)
			return (ENXIO);
		di->bas.regshft = 0;
		di->bas.rclk = 0;
		if (resource_int_value("uart", i, "baud", &ivar) != 0)
			ivar = 0;
		di->baudrate = ivar;
		di->databits = 8;
		di->stopbits = 1;
		di->parity = UART_PARITY_NONE;
		return (0);
	}

	return (ENXIO);
}
