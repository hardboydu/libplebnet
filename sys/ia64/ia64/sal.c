/*-
 * Copyright (c) 2001 Doug Rabson
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
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <vm/vm.h>
#include <vm/vm_kern.h>
#include <machine/sal.h>
#include <machine/smp.h>

struct ia64_fdesc {
	u_int64_t	func;
	u_int64_t	gp;
};

int64_t		sal_info_size[SAL_INFO_TYPES];
vm_offset_t	sal_info_block;

static struct ia64_fdesc sal_fdesc;
static sal_entry_t	fake_sal;

extern u_int64_t	ia64_pal_entry;
sal_entry_t		*ia64_sal_entry = fake_sal;

static void ia64_sal_init_state(void *p);

void os_boot_rendez(void);

static struct ia64_sal_result
fake_sal(u_int64_t a1, u_int64_t a2, u_int64_t a3, u_int64_t a4,
	 u_int64_t a5, u_int64_t a6, u_int64_t a7, u_int64_t a8)
{
	struct ia64_sal_result res;
	res.sal_status = -3;
	res.sal_result[0] = 0;
	res.sal_result[1] = 0;
	res.sal_result[2] = 0;
	return res;
}

void
ia64_sal_init(struct sal_system_table *saltab)
{
	static int sizes[6] = {
		48, 32, 16, 32, 16, 16
	};
	u_int8_t *p;
	int i;

	if (memcmp(saltab->sal_signature, "SST_", 4)) {
		printf("Bad signature for SAL System Table\n");
		return;
	}

	p = (u_int8_t *) (saltab + 1);
	for (i = 0; i < saltab->sal_entry_count; i++) {
		switch (*p) {
		case 0: {
			struct sal_entrypoint_descriptor *dp;

			dp = (struct sal_entrypoint_descriptor*)p;
			ia64_pal_entry = IA64_PHYS_TO_RR7(dp->sale_pal_proc);
			if (bootverbose)
				printf("PAL Proc at 0x%lx\n", ia64_pal_entry);
			sal_fdesc.func = IA64_PHYS_TO_RR7(dp->sale_sal_proc);
			sal_fdesc.gp = IA64_PHYS_TO_RR7(dp->sale_sal_gp);
			if (bootverbose)
				printf("SAL Proc at 0x%lx, GP at 0x%lx\n",
				    sal_fdesc.func, sal_fdesc.gp);
			ia64_sal_entry = (sal_entry_t *) &sal_fdesc;
			break;
		}
		case 5: {
			struct sal_ap_wakeup_descriptor *dp;
#ifdef SMP
			struct ia64_sal_result result;
			struct ia64_fdesc *fptr = (void*)os_boot_rendez;
			int ipi;
#endif

			dp = (struct sal_ap_wakeup_descriptor*)p;
			KASSERT(dp->sale_mechanism == 0,
			    ("Unsupported AP wake-up mechanism"));
			if (bootverbose)
				printf("SMP: AP wake-up vector: 0x%lx\n",
				    dp->sale_vector);
#ifdef SMP
			for (ipi = 0; ipi < IPI_COUNT; ipi++)
				mp_ipi_vector[ipi] = dp->sale_vector + ipi;

			result = ia64_sal_entry(SAL_SET_VECTORS,
			    SAL_OS_BOOT_RENDEZ, ia64_tpa(fptr->func),
			    ia64_tpa(fptr->gp), 0, 0, 0, 0);

			mp_hardware = 1;
#endif
			break;
		}
		}
		p += sizes[*p];
	}
}

static void
ia64_sal_init_state(void *p)
{
	struct ia64_sal_result result;
	uint64_t max_size;
	int i;

	/*
	 * Get the sizes of the state information we can get from SAL and
	 * allocate a common block (forgive me my Fortran) for use by
	 * support functions. We create a region 7 address to make it
	 * easy on the OS_MCA or OS_INIT handlers.
	 */
	max_size = 0;
	for (i = 0; i <= SAL_INFO_TYPES; i++) {
		result = ia64_sal_entry(SAL_GET_STATE_INFO_SIZE, i, 0, 0, 0,
		    0, 0, 0);
		if (result.sal_status == 0) {
			sal_info_size[i] = result.sal_result[0];
			if (sal_info_size[i] > max_size)
				max_size = sal_info_size[i];
		} else
			sal_info_size[i] = -1;
	}
	max_size = round_page(max_size);
	p = contigmalloc(max_size, M_TEMP, M_WAITOK, 0ul, 256*1024*1024 - 1,
	    PAGE_SIZE, 256*1024*1024);
	sal_info_block = IA64_PHYS_TO_RR7(ia64_tpa((u_int64_t)p));

	if (bootverbose)
		printf("SAL: allocated %d bytes for state information\n",
		    max_size);
}

SYSINIT(sal_mca, SI_SUB_CPU, SI_ORDER_MIDDLE, ia64_sal_init_state, NULL);
