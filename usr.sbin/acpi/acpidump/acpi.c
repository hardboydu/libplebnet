/*-
 * Copyright (c) 1998 Doug Rabson
 * Copyright (c) 2000 Mitsuru IWASAKI <iwasaki@FreeBSD.org>
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "acpidump.h"

#define BEGIN_COMMENT	"/*\n"
#define END_COMMENT	" */\n"

static void	acpi_print_string(char *s, size_t length);
static void	acpi_print_gas(struct ACPIgas *gas);
static void	acpi_handle_fadt(struct FADTbody *fadt);
static void	acpi_print_cpu(u_char cpu_id);
static void	acpi_print_local_apic(u_char cpu_id, u_char apic_id,
				      u_int32_t flags);
static void	acpi_print_io_apic(u_char apic_id, u_int32_t int_base,
				   u_int64_t apic_addr);
static void	acpi_print_mps_flags(u_int16_t flags);
static void	acpi_print_intr(u_int32_t intr, u_int16_t mps_flags);
static void	acpi_print_apic(struct MADT_APIC *mp);
static void	acpi_handle_apic(struct ACPIsdt *sdp);
static void	acpi_handle_hpet(struct ACPIsdt *sdp);
static void	acpi_print_sdt(struct ACPIsdt *sdp, int endcomment);
static void	acpi_print_fadt(struct FADTbody *fadt);
static void	acpi_print_facs(struct FACSbody *facs);
static void	acpi_print_dsdt(struct ACPIsdt *dsdp);
static struct ACPIsdt *
		acpi_map_sdt(vm_offset_t pa);
static void	acpi_print_rsd_ptr(struct ACPIrsdp *rp);
static void	acpi_handle_rsdt(struct ACPIsdt *rsdp);

static void
acpi_print_string(char *s, size_t length)
{
	int	c;

	/* Trim trailing spaces and NULLs */
	while (length > 0 && (s[length - 1] == ' ' || s[length - 1] == '\0'))
		length--;

	while (length--) {
		c = *s++;
		putchar(c);
	}
}

static void
acpi_print_gas(struct ACPIgas *gas)
{
	switch(gas->address_space_id) {
	case ACPI_GAS_MEMORY:
		printf("0x%08lx:%u[%u] (Memory)\n", (u_long)gas->address,
		       gas->bit_offset, gas->bit_width);
		break;
	case ACPI_GAS_IO:
		printf("0x%08lx:%u[%u] (IO)\n", (u_long)gas->address,
		       gas->bit_offset, gas->bit_width);
		break;
	case ACPI_GAS_PCI:
		printf("%x:%x+%#x (PCI)\n", (uint16_t)(gas->address >> 32),
		       (uint16_t)((gas->address >> 16) & 0xffff),
		       (uint16_t)gas->address);
		break;
	/* XXX How to handle these below? */
	case ACPI_GAS_EMBEDDED:
		printf("0x%#x:%u[%u] (EC)\n", (uint16_t)gas->address,
		       gas->bit_offset, gas->bit_width);
		break;
	case ACPI_GAS_SMBUS:
		printf("0x%#x:%u[%u] (SMBus)\n", (uint16_t)gas->address,
		       gas->bit_offset, gas->bit_width);
		break;
	case ACPI_GAS_FIXED:
	default:
		printf("0x%08lx (?)\n", (u_long)gas->address);
		break;
	}
}

static void
acpi_handle_fadt(struct FADTbody *fadt)
{
	struct ACPIsdt	*dsdp;
	struct FACSbody	*facs;

	acpi_print_fadt(fadt);

	facs = (struct FACSbody *)acpi_map_sdt(fadt->facs_ptr);
	if (memcmp(facs->signature, "FACS", 4) != 0 || facs->len < 64)
		errx(1, "FACS is corrupt");
	acpi_print_facs(facs);

	dsdp = (struct ACPIsdt *)acpi_map_sdt(fadt->dsdt_ptr);
	if (acpi_checksum(dsdp, dsdp->len))
		errx(1, "DSDT is corrupt");
	acpi_print_dsdt(dsdp);
}

static void
acpi_print_cpu(u_char cpu_id)
{

	printf("\tACPI CPU=");
	if (cpu_id == 0xff)
		printf("ALL\n");
	else
		printf("%d\n", (u_int)cpu_id);
}

static void
acpi_print_local_apic(u_char cpu_id, u_char apic_id, u_int32_t flags)
{
	acpi_print_cpu(cpu_id);
	printf("\tFlags={");
	if (flags & ACPI_MADT_APIC_LOCAL_FLAG_ENABLED)
		printf("ENABLED");
	else
		printf("DISABLED");
	printf("}\n");
	printf("\tAPIC ID=%d\n", (u_int)apic_id);
}

static void
acpi_print_io_apic(u_char apic_id, u_int32_t int_base, u_int64_t apic_addr)
{
	printf("\tAPIC ID=%d\n", (u_int)apic_id);
	printf("\tINT BASE=%d\n", int_base);
	printf("\tADDR=0x%016jx\n", apic_addr);
}

static void
acpi_print_mps_flags(u_int16_t flags)
{

	printf("\tFlags={Polarity=");
	switch (flags & MPS_INT_FLAG_POLARITY_MASK) {
	case MPS_INT_FLAG_POLARITY_CONFORM:
		printf("conforming");
		break;
	case MPS_INT_FLAG_POLARITY_HIGH:
		printf("active-hi");
		break;
	case MPS_INT_FLAG_POLARITY_LOW:
		printf("active-lo");
		break;
	default:
		printf("0x%x", flags & MPS_INT_FLAG_POLARITY_MASK);
		break;
	}
	printf(", Trigger=");
	switch (flags & MPS_INT_FLAG_TRIGGER_MASK) {
	case MPS_INT_FLAG_TRIGGER_CONFORM:
		printf("conforming");
		break;
	case MPS_INT_FLAG_TRIGGER_EDGE:
		printf("edge");
		break;
	case MPS_INT_FLAG_TRIGGER_LEVEL:
		printf("level");
		break;
	default:
		printf("0x%x", (flags & MPS_INT_FLAG_TRIGGER_MASK) >> 2);
	}
	printf("}\n");
}

static void
acpi_print_intr(u_int32_t intr, u_int16_t mps_flags)
{

	printf("\tINTR=%d\n", (u_int)intr);
	acpi_print_mps_flags(mps_flags);
}

const char *apic_types[] = { "Local APIC", "IO APIC", "INT Override", "NMI",
			     "Local NMI", "Local APIC Override", "IO SAPIC",
			     "Local SAPIC", "Platform Interrupt" };
const char *platform_int_types[] = { "PMI", "INIT",
				     "Corrected Platform Error" };

static void
acpi_print_apic(struct MADT_APIC *mp)
{

	printf("\tType=%s\n", apic_types[mp->type]);
	switch (mp->type) {
	case ACPI_MADT_APIC_TYPE_LOCAL_APIC:
		acpi_print_local_apic(mp->body.local_apic.cpu_id,
		    mp->body.local_apic.apic_id, mp->body.local_apic.flags);
		break;
	case ACPI_MADT_APIC_TYPE_IO_APIC:
		acpi_print_io_apic(mp->body.io_apic.apic_id,
		    mp->body.io_apic.int_base,
		    mp->body.io_apic.apic_addr);
		break;
	case ACPI_MADT_APIC_TYPE_INT_OVERRIDE:
		printf("\tBUS=%d\n", (u_int)mp->body.int_override.bus);
		printf("\tIRQ=%d\n", (u_int)mp->body.int_override.source);
		acpi_print_intr(mp->body.int_override.intr,
		    mp->body.int_override.mps_flags);
		break;
	case ACPI_MADT_APIC_TYPE_NMI:
		acpi_print_intr(mp->body.nmi.intr, mp->body.nmi.mps_flags);
		break;
	case ACPI_MADT_APIC_TYPE_LOCAL_NMI:
		acpi_print_cpu(mp->body.local_nmi.cpu_id);
		printf("\tLINT Pin=%d\n", mp->body.local_nmi.lintpin);
		acpi_print_mps_flags(mp->body.local_nmi.mps_flags);
		break;
	case ACPI_MADT_APIC_TYPE_LOCAL_OVERRIDE:
		printf("\tLocal APIC ADDR=0x%016jx\n",
		    mp->body.local_apic_override.apic_addr);
		break;
	case ACPI_MADT_APIC_TYPE_IO_SAPIC:
		acpi_print_io_apic(mp->body.io_sapic.apic_id,
		    mp->body.io_sapic.int_base,
		    mp->body.io_sapic.apic_addr);
		break;
	case ACPI_MADT_APIC_TYPE_LOCAL_SAPIC:
		acpi_print_local_apic(mp->body.local_sapic.cpu_id,
		    mp->body.local_sapic.apic_id, mp->body.local_sapic.flags);
		printf("\tAPIC EID=%d\n", (u_int)mp->body.local_sapic.apic_eid);
		break;
	case ACPI_MADT_APIC_TYPE_INT_SRC:
		printf("\tType=%s\n",
		    platform_int_types[mp->body.int_src.type]);
		printf("\tCPU ID=%d\n", (u_int)mp->body.int_src.cpu_id);
		printf("\tCPU EID=%d\n", (u_int)mp->body.int_src.cpu_id);
		printf("\tSAPIC Vector=%d\n",
		    (u_int)mp->body.int_src.sapic_vector);
		acpi_print_intr(mp->body.int_src.intr,
		    mp->body.int_src.mps_flags);
		break;
	default:
		printf("\tUnknown type %d\n", (u_int)mp->type);
		break;
	}
}

static void
acpi_handle_apic(struct ACPIsdt *sdp)
{
	struct MADTbody *madtp;
	struct MADT_APIC *madt_apicp;

	acpi_print_sdt(sdp, /*endcomment*/0);
	madtp = (struct MADTbody *) sdp->body;
	printf("\tLocal APIC ADDR=0x%08x\n", madtp->lapic_addr);
	printf("\tFlags={");
	if (madtp->flags & ACPI_APIC_FLAG_PCAT_COMPAT)
		printf("PC-AT");
	printf("}\n");
	madt_apicp = (struct MADT_APIC *)madtp->body;
	while (((uintptr_t)madt_apicp) - ((uintptr_t)sdp) < sdp->len) {
		printf("\n");
		acpi_print_apic(madt_apicp);
		madt_apicp = (struct MADT_APIC *) ((char *)madt_apicp +
		    madt_apicp->len);
	}
	printf(END_COMMENT);
}

static void
acpi_handle_hpet(struct ACPIsdt *sdp)
{
	struct HPETbody *hpetp;

	acpi_print_sdt(sdp, /*endcomment*/0);
	hpetp = (struct HPETbody *) sdp->body;
	printf("\tHPET Number=%d\n", hpetp->hpet_number);
	printf("\tADDR=0x%08x\n", hpetp->base_addr);
	printf("\tHW Rev=0x%x\n", hpetp->block_hwrev);
	printf("\tComparitors=%d\n", hpetp->block_comparitors);
	printf("\tCounter Size=%d\n", hpetp->block_counter_size);
	printf("\tLegacy IRQ routing capable={");
	if (hpetp->block_legacy_capable)
		printf("TRUE}\n");
	else
		printf("FALSE}\n");
	printf("\tPCI Vendor ID=0x%04x\n", hpetp->block_pcivendor);
	printf("\tMinimal Tick=%d\n", hpetp->clock_tick);
	printf(END_COMMENT);
}

static void
acpi_print_sdt(struct ACPIsdt *sdp, int endcomment)
{
	printf(BEGIN_COMMENT "  ");
	acpi_print_string(sdp->signature, 4);
	printf(": Length=%d, Revision=%d, Checksum=%d,\n",
	       sdp->len, sdp->rev, sdp->check);
	printf("\tOEMID=");
	acpi_print_string(sdp->oemid, 6);
	printf(", OEM Table ID=");
	acpi_print_string(sdp->oemtblid, 8);
	printf(", OEM Revision=0x%x,\n", sdp->oemrev);
	printf("\tCreator ID=");
	acpi_print_string(sdp->creator, 4);
	printf(", Creator Revision=0x%x\n", sdp->crerev);
	if (endcomment)
		printf(END_COMMENT);
}

static void
acpi_print_rsdt(struct ACPIsdt *rsdp)
{
	int	i, entries;

	acpi_print_sdt(rsdp, /*endcomment*/0);
	entries = (rsdp->len - SIZEOF_SDT_HDR) / sizeof(u_int32_t);
	printf("\tEntries={ ");
	for (i = 0; i < entries; i++) {
		if (i > 0)
			printf(", ");
		printf("0x%08x", rsdp->body[i]);
	}
	printf(" }\n");
	printf(END_COMMENT);
}

static const char *acpi_pm_profiles[] = {
	"Unspecified", "Desktop", "Mobile", "Workstation",
	"Enterprise Server", "SOHO Server", "Appliance PC"
};

static void
acpi_print_fadt(struct FADTbody *fadt)
{
	const char *pm;
	char	    sep;

	printf(BEGIN_COMMENT);
	printf("  FADT:\tFACS=0x%x, DSDT=0x%x\n", fadt->facs_ptr,
	       fadt->dsdt_ptr);
	printf("\tINT_MODEL=%s\n", fadt->int_model ? "APIC" : "PIC");
	if (fadt->pm_profile >= sizeof(acpi_pm_profiles) / sizeof(char *))
		pm = "Reserved";
	else
		pm = acpi_pm_profiles[fadt->pm_profile];
	printf("\tPreferred_PM_Profile=%s (%d)\n", pm, fadt->pm_profile);
	printf("\tSCI_INT=%d\n", fadt->sci_int);
	printf("\tSMI_CMD=0x%x, ", fadt->smi_cmd);
	printf("ACPI_ENABLE=0x%x, ", fadt->acpi_enable);
	printf("ACPI_DISABLE=0x%x, ", fadt->acpi_disable);
	printf("S4BIOS_REQ=0x%x\n", fadt->s4biosreq);
	printf("\tPSTATE_CNT=0x%x\n", fadt->pstate_cnt);
	if (fadt->pm1a_evt_blk != 0)
		printf("\tPM1a_EVT_BLK=0x%x-0x%x\n",
		       fadt->pm1a_evt_blk,
		       fadt->pm1a_evt_blk + fadt->pm1_evt_len - 1);
	if (fadt->pm1b_evt_blk != 0)
		printf("\tPM1b_EVT_BLK=0x%x-0x%x\n",
		       fadt->pm1b_evt_blk,
		       fadt->pm1b_evt_blk + fadt->pm1_evt_len - 1);
	if (fadt->pm1a_cnt_blk != 0)
		printf("\tPM1a_CNT_BLK=0x%x-0x%x\n",
		       fadt->pm1a_cnt_blk,
		       fadt->pm1a_cnt_blk + fadt->pm1_cnt_len - 1);
	if (fadt->pm1b_cnt_blk != 0)
		printf("\tPM1b_CNT_BLK=0x%x-0x%x\n",
		       fadt->pm1b_cnt_blk,
		       fadt->pm1b_cnt_blk + fadt->pm1_cnt_len - 1);
	if (fadt->pm2_cnt_blk != 0)
		printf("\tPM2_CNT_BLK=0x%x-0x%x\n",
		       fadt->pm2_cnt_blk,
		       fadt->pm2_cnt_blk + fadt->pm2_cnt_len - 1);
	if (fadt->pm_tmr_blk != 0)
		printf("\tPM2_TMR_BLK=0x%x-0x%x\n",
		       fadt->pm_tmr_blk,
		       fadt->pm_tmr_blk + fadt->pm_tmr_len - 1);
	if (fadt->gpe0_blk != 0)
		printf("\tGPE0_BLK=0x%x-0x%x\n",
		       fadt->gpe0_blk,
		       fadt->gpe0_blk + fadt->gpe0_len - 1);
	if (fadt->gpe1_blk != 0)
		printf("\tGPE1_BLK=0x%x-0x%x, GPE1_BASE=%d\n",
		       fadt->gpe1_blk,
		       fadt->gpe1_blk + fadt->gpe1_len - 1,
		       fadt->gpe1_base);
	if (fadt->cst_cnt != 0)
		printf("\tCST_CNT=0x%x\n", fadt->cst_cnt);
	printf("\tP_LVL2_LAT=%dms, P_LVL3_LAT=%dms\n",
	       fadt->p_lvl2_lat, fadt->p_lvl3_lat);
	printf("\tFLUSH_SIZE=%d, FLUSH_STRIDE=%d\n",
	       fadt->flush_size, fadt->flush_stride);
	printf("\tDUTY_OFFSET=%d, DUTY_WIDTH=%d\n",
	       fadt->duty_off, fadt->duty_width);
	printf("\tDAY_ALRM=%d, MON_ALRM=%d, CENTURY=%d\n",
	       fadt->day_alrm, fadt->mon_alrm, fadt->century);

#define PRINTFLAG(var, flag) do {			\
	if ((var) & FADT_FLAG_## flag) {		\
		printf("%c%s", sep, #flag); sep = ',';	\
	}						\
} while (0)

	printf("\tIAPC_BOOT_ARCH=");
	sep = '{';
	PRINTFLAG(fadt->iapc_boot_arch, LEGACY_DEV);
	PRINTFLAG(fadt->iapc_boot_arch, 8042);
	printf("}\n");

	printf("\tFlags=");
	sep = '{';
	PRINTFLAG(fadt->flags, WBINVD);
	PRINTFLAG(fadt->flags, WBINVD_FLUSH);
	PRINTFLAG(fadt->flags, PROC_C1);
	PRINTFLAG(fadt->flags, P_LVL2_UP);
	PRINTFLAG(fadt->flags, PWR_BUTTON);
	PRINTFLAG(fadt->flags, SLP_BUTTON);
	PRINTFLAG(fadt->flags, FIX_RTC);
	PRINTFLAG(fadt->flags, RTC_S4);
	PRINTFLAG(fadt->flags, TMR_VAL_EXT);
	PRINTFLAG(fadt->flags, DCK_CAP);
	PRINTFLAG(fadt->flags, RESET_REG);
	PRINTFLAG(fadt->flags, SEALED_CASE);
	PRINTFLAG(fadt->flags, HEADLESS);
	PRINTFLAG(fadt->flags, CPU_SW_SLP);
	printf("}\n");

#undef PRINTFLAG

	if (fadt->flags & FADT_FLAG_RESET_REG) {
		printf("\tRESET_REG=");
		acpi_print_gas(&fadt->reset_reg);
		printf(", RESET_VALUE=%#x\n", fadt->reset_value);
	}

	printf(END_COMMENT);
}

static void
acpi_print_facs(struct FACSbody *facs)
{
	printf(BEGIN_COMMENT);
	printf("  FACS:\tLength=%u, ", facs->len);
	printf("HwSig=0x%08x, ", facs->hw_sig);
	printf("Firm_Wake_Vec=0x%08x\n", facs->firm_wake_vec);

	printf("\tGlobal_Lock={");
	if (facs->global_lock != 0) {
		if (facs->global_lock & FACS_FLAG_LOCK_PENDING)
			printf("PENDING,");
		if (facs->global_lock & FACS_FLAG_LOCK_OWNED)
			printf("OWNED");
	}
	printf("}\n");

	printf("\tFlags={");
	if (facs->flags & FACS_FLAG_S4BIOS_F)
		printf("S4BIOS");
	printf("}\n");

	if (facs->x_firm_wake_vec != 0) {
		printf("\tX_Firm_Wake_Vec=%08lx\n",
		       (u_long)facs->x_firm_wake_vec);
	}

	printf(END_COMMENT);
}

static void
acpi_print_dsdt(struct ACPIsdt *dsdp)
{
	acpi_print_sdt(dsdp, /*endcomment*/1);
}

int
acpi_checksum(void *p, size_t length)
{
	u_int8_t	*bp;
	u_int8_t	sum;

	bp = p;
	sum = 0;
	while (length--)
		sum += *bp++;

	return (sum);
}

static struct ACPIsdt *
acpi_map_sdt(vm_offset_t pa)
{
	struct	ACPIsdt *sp;

	sp = acpi_map_physical(pa, sizeof(struct ACPIsdt));
	sp = acpi_map_physical(pa, sp->len);
	return (sp);
}

static void
acpi_print_rsd_ptr(struct ACPIrsdp *rp)
{

	printf(BEGIN_COMMENT);
	printf("  RSD PTR: Checksum=%d, OEMID=", rp->sum);
	acpi_print_string(rp->oem, 6);
	printf(", RsdtAddress=0x%08x\n", rp->rsdt_addr);
	printf(END_COMMENT);
}

static void
acpi_handle_rsdt(struct ACPIsdt *rsdp)
{
	int	i;
	int	entries;
	struct	ACPIsdt *sdp;

	entries = (rsdp->len - SIZEOF_SDT_HDR) / sizeof(u_int32_t);
	acpi_print_rsdt(rsdp);
	for (i = 0; i < entries; i++) {
		sdp = (struct ACPIsdt *)acpi_map_sdt(rsdp->body[i]);
		if (acpi_checksum(sdp, sdp->len))
			errx(1, "RSDT entry %d is corrupt", i);
		if (!memcmp(sdp->signature, "FACP", 4))
			acpi_handle_fadt((struct FADTbody *) sdp->body);
		else if (!memcmp(sdp->signature, "APIC", 4))
			acpi_handle_apic(sdp);
		else if (!memcmp(sdp->signature, "HPET", 4))
			acpi_handle_hpet(sdp);
		else
			acpi_print_sdt(sdp, /*endcomment*/1);
	}
}

struct ACPIsdt *
sdt_load_devmem()
{
	struct	ACPIrsdp *rp;
	struct	ACPIsdt *rsdp;

	rp = acpi_find_rsd_ptr();
	if (!rp)
		errx(1, "Can't find ACPI information");

	if (tflag)
		acpi_print_rsd_ptr(rp);
	rsdp = (struct ACPIsdt *)acpi_map_sdt(rp->rsdt_addr);
	if (memcmp(rsdp->signature, "RSDT", 4) != 0 ||
	    acpi_checksum(rsdp, rsdp->len) != 0)
		errx(1, "RSDT is corrupted");

	return (rsdp);
}

void
dsdt_save_file(char *outfile, struct ACPIsdt *dsdp)
{
	int	fd;
	mode_t	mode;

	assert(outfile != NULL);
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, mode);
	if (fd == -1) {
		perror("dsdt_save_file");
		return;
	}
	write(fd, dsdp, SIZEOF_SDT_HDR);
	write(fd, dsdp->body, dsdp->len - SIZEOF_SDT_HDR);
	close(fd);
}

void
aml_disassemble(struct ACPIsdt *dsdp)
{
	char tmpstr[32], buf[256];
	FILE *fp;
	int fd, len;

	strcpy(tmpstr, "/tmp/acpidump.XXXXXX");
	fd = mkstemp(tmpstr);
	if (fd < 0) {
		perror("iasl tmp file");
		return;
	}

	/* Dump DSDT to the temp file */
	write(fd, dsdp, SIZEOF_SDT_HDR);
	write(fd, dsdp->body, dsdp->len - SIZEOF_SDT_HDR);
	close(fd);

	/* Run iasl -d on the temp file */
	if (fork() == 0) {
		close(STDOUT_FILENO);
		if (vflag == 0)
			close(STDERR_FILENO);
		execl("/usr/sbin/iasl", "iasl", "-d", tmpstr, 0);
		err(1, "exec");
	}

	wait(NULL);
	unlink(tmpstr);

	/* Dump iasl's output to stdout */
	fp = fopen("acpidump.dsl", "r");
	unlink("acpidump.dsl");
	if (fp == NULL) {
		perror("iasl tmp file (read)");
		return;
	}
	while ((len = fread(buf, 1, sizeof(buf), fp)) > 0)
		fwrite(buf, 1, len, stdout);
	fclose(fp);
}

void
sdt_print_all(struct ACPIsdt *rsdp)
{
	acpi_handle_rsdt(rsdp);
}

/* Fetch a table matching the given signature via the RSDT */
struct ACPIsdt *
sdt_from_rsdt(struct ACPIsdt *rsdt, const char *sig)
{
	int	i;
	int	entries;
	struct	ACPIsdt *sdt;

	entries = (rsdt->len - SIZEOF_SDT_HDR) / sizeof(uint32_t);
	for (i = 0; i < entries; i++) {
		sdt = (struct ACPIsdt *)acpi_map_sdt(rsdt->body[i]);
		if (acpi_checksum(sdt, sdt->len))
			errx(1, "RSDT entry %d is corrupt", i);
		if (!memcmp(sdt->signature, sig, strlen(sig)))
			return (sdt);
	}

	return (NULL);
}

struct ACPIsdt *
dsdt_from_fadt(struct FADTbody *fadt)
{
	struct	ACPIsdt *sdt;

	sdt = (struct ACPIsdt *)acpi_map_sdt(fadt->dsdt_ptr);
	if (acpi_checksum(sdt, sdt->len))
		errx(1, "DSDT is corrupt\n");
	return (sdt);
}
