/*-
 * Copyright (c) 2000,2001 Michael Smith
 * Copyright (c) 2000 BSDi
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

/*
 * 6.1 : Environmental support
 */

#include "acpi.h"

extern u_int64_t ia64_efi_acpi_table;
extern u_int64_t ia64_efi_acpi20_table;

ACPI_STATUS
AcpiOsInitialize(void)
{

	return(NULL);
}

ACPI_STATUS
AcpiOsTerminate(void)
{

	return(NULL);
}

ACPI_STATUS
AcpiOsGetRootPointer(
    UINT32			Flags,
    ACPI_PHYSICAL_ADDRESS	*RsdpPhysicalAddress)
{
	RSDP_DESCRIPTOR *rsdp;
	XSDT_DESCRIPTOR *xsdt;

	if (ia64_efi_acpi20_table) {
		*RsdpPhysicalAddress = ia64_efi_acpi20_table;
		rsdp = (RSDP_DESCRIPTOR *)
			IA64_PHYS_TO_RR7(ia64_efi_acpi20_table);
		xsdt = (XSDT_DESCRIPTOR *)
			IA64_PHYS_TO_RR7(rsdp->XsdtPhysicalAddress);
		ia64_parse_xsdt(xsdt);
		return(AE_OK);
	} else if (ia64_efi_acpi_table) {
		*RsdpPhysicalAddress = ia64_efi_acpi_table;
		return(AE_OK);
	}

	return(AE_NOT_FOUND);
}
