/*-
 * Copyright (c) 2004 Takanori Watanabe
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
 *	$FreeBSD$
 */

#include "opt_acpi.h"
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include "acpi.h"
#include "acpi_if.h"
#include <sys/module.h>
#include <dev/acpica/acpivar.h>
#include <sys/sysctl.h>
#define ACPI_SNC_GET_BRIGHTNESS "GBRT"
#define ACPI_SNC_SET_BRIGHTNESS "SBRT"
#define ACPI_SNC_GET_PID "GPID"
/*
 * SNY5001
 *  [GS]BRT [GS]PBR [GS]CTR [GS]PCR [GS]CMI [CDPW GCDP]? GWDP PWAK PWRN 
 *
 */

struct acpi_snc_softc {
  int pid;
};
static struct acpi_snc_name_list
{
  char *nodename;
  char *getmethod;
  char *setmethod;
  char *comment;
}acpi_snc_oids[] = {
  { "brightness", "GBRT", "SBRT", "Display Brightness"},
  { "ctr", "GCTR", "SCTR", "??"},
  { "pcr", "GPCR", "SPCR", "???"},
#if 0
  { "cmi", "GCMI", "SCMI", "????"},
#endif
  { "wdp", "GWDP", NULL, "?????"},
  { "cdp", "GCDP", "CDPW", "??????"},  /*shares [\GL03]&0x8 flag*/
  {NULL, NULL,NULL}
};

static int	acpi_snc_probe(device_t dev);
static int	acpi_snc_attach(device_t dev);
static int 	acpi_snc_detach(device_t dev);
static int	sysctl_acpi_snc_gen_handler(SYSCTL_HANDLER_ARGS);

static device_method_t acpi_snc_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe, acpi_snc_probe),
	DEVMETHOD(device_attach, acpi_snc_attach),
	DEVMETHOD(device_detach, acpi_snc_detach),

	{0, 0}
};

static driver_t	acpi_snc_driver = {
	"acpi_snc",
	acpi_snc_methods,
	sizeof(struct acpi_snc_softc),
};

static devclass_t acpi_snc_devclass;

DRIVER_MODULE(acpi_snc, acpi, acpi_snc_driver, acpi_snc_devclass,
	      0, 0);
MODULE_DEPEND(acpi_snc, acpi, 1, 1, 1);
static char    *sny_id[] = {"SNY5001", NULL};

static int
acpi_snc_probe(device_t dev)
{
	struct acpi_snc_softc *sc;
	int		ret = ENXIO;

	sc = device_get_softc(dev);

	if (ACPI_ID_PROBE(device_get_parent(dev), dev, sny_id)) {
		device_set_desc(dev, "Sony notebook controller");
		ret = 0;
	}
	return (ret);
}

static int
acpi_snc_attach(device_t dev)
{
	struct acpi_snc_softc *sc;
	int i;

	sc = device_get_softc(dev);
	acpi_GetInteger(acpi_get_handle(dev), ACPI_SNC_GET_PID, &sc->pid);
	device_printf(dev, "PID %x\n", sc->pid);
	for (i = 0 ; acpi_snc_oids[i].nodename != NULL; i++){
		SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
		    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
		    i, acpi_snc_oids[i].nodename , CTLTYPE_INT |
		    ((acpi_snc_oids[i].setmethod)? CTLFLAG_RW: CTLFLAG_RD),
		    dev, i, sysctl_acpi_snc_gen_handler, "I",
		    acpi_snc_oids[i].comment);
	}
	
	return (0);
}

static int 
acpi_snc_detach(device_t dev)
{
	return (0);
}
#if 0
static int
acpi_snc_suspend(device_t dev)
{
	struct acpi_snc_softc *sc = device_get_softc(dev);
	return (0);
}

static int
acpi_snc_resume(device_t dev)
{
	return (0);
}
#endif

static int 
sysctl_acpi_snc_gen_handler(SYSCTL_HANDLER_ARGS)
{
	device_t	dev = arg1;
	int 	function = oidp->oid_arg2;
	int		error = 0, val;


	acpi_GetInteger(acpi_get_handle(dev), acpi_snc_oids[function].getmethod, &val);
	error = sysctl_handle_int(oidp, &val, 0, req);

	if (error || !req->newptr || !acpi_snc_oids[function].setmethod)
		return error;

	acpi_SetInteger(acpi_get_handle(dev), acpi_snc_oids[function].setmethod, val);
	return 0;
	
}
