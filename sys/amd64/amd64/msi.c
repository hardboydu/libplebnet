/*-
 * Copyright (c) 2006 John Baldwin <jhb@FreeBSD.org>
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
 * 3. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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

/*
 * Support for PCI Message Signalled Interrupts (MSI).  MSI interrupts on
 * x86 are basically APIC messages that the northbridge delivers directly
 * to the local APICs as if they had come from an I/O APIC.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/systm.h>
#include <machine/apicreg.h>
#include <machine/md_var.h>
#include <machine/frame.h>
#include <machine/intr_machdep.h>
#include <machine/apicvar.h>
#include <dev/pci/pcivar.h>

/* Fields in address for Intel MSI messages. */
#define	MSI_INTEL_ADDR_DEST		0x000ff000
#define	MSI_INTEL_ADDR_RH		0x00000008
# define MSI_INTEL_ADDR_RH_ON		0x00000008
# define MSI_INTEL_ADDR_RH_OFF		0x00000000
#define	MSI_INTEL_ADDR_DM		0x00000004
# define MSI_INTEL_ADDR_DM_PHYSICAL	0x00000000
# define MSI_INTEL_ADDR_DM_LOGICAL	0x00000004

/* Fields in data for Intel MSI messages. */
#define	MSI_INTEL_DATA_TRGRMOD		IOART_TRGRMOD	/* Trigger mode. */
# define MSI_INTEL_DATA_TRGREDG		IOART_TRGREDG
# define MSI_INTEL_DATA_TRGRLVL		IOART_TRGRLVL
#define	MSI_INTEL_DATA_LEVEL		0x00004000	/* Polarity. */
# define MSI_INTEL_DATA_DEASSERT	0x00000000
# define MSI_INTEL_DATA_ASSERT		0x00004000
#define	MSI_INTEL_DATA_DELMOD		IOART_DELMOD	/* Delivery mode. */
# define MSI_INTEL_DATA_DELFIXED	IOART_DELFIXED
# define MSI_INTEL_DATA_DELLOPRI	IOART_DELLOPRI
# define MSI_INTEL_DATA_DELSMI		IOART_DELSMI
# define MSI_INTEL_DATA_DELNMI		IOART_DELNMI
# define MSI_INTEL_DATA_DELINIT		IOART_DELINIT
# define MSI_INTEL_DATA_DELEXINT	IOART_DELEXINT
#define	MSI_INTEL_DATA_INTVEC		IOART_INTVEC	/* Interrupt vector. */

/*
 * Build Intel MSI message and data values from a source.  AMD64 systems
 * seem to be compatible, so we use the same function for both.
 */
#define	INTEL_ADDR(msi)							\
	(MSI_INTEL_ADDR_BASE | (msi)->msi_cpu << 12 |			\
	    MSI_INTEL_ADDR_RH_OFF | MSI_INTEL_ADDR_DM_PHYSICAL)
#define	INTEL_DATA(msi)							\
	(MSI_INTEL_DATA_TRGREDG | MSI_INTEL_DATA_DELFIXED | (msi)->msi_vector)

static MALLOC_DEFINE(M_MSI, "msi", "PCI MSI");

/*
 * MSI sources are bunched into groups.  This is because MSI forces
 * all of the messages to share the address and data registers and
 * thus certain properties (such as the local APIC ID target on x86).
 * Each group has a 'first' source that contains information global to
 * the group.  These fields are marked with (g) below.
 *
 * Note that local APIC ID is kind of special.  Each message will be
 * assigned an ID by the system; however, a group will use the ID from
 * the first message.
 *
 * For MSI-X, each message is isolated, and msi_index indicates the
 * index of this message in the device's MSI-X table.
 */
struct msi_intsrc {
	struct intsrc msi_intsrc;
	device_t msi_dev;		/* Owning device. (g) */
	struct msi_intsrc *msi_first;	/* First source in group. */
	u_int msi_irq;			/* IRQ cookie. */
	u_int msi_index;		/* Index of this message. */
	u_int msi_msix;			/* MSI-X message. */
	u_int msi_vector:8;		/* IDT vector. */
	u_int msi_cpu:8;		/* Local APIC ID. (g) */
	u_int msi_count:8;		/* Messages in this group. (g) */
};

static void	msi_enable_source(struct intsrc *isrc);
static void	msi_disable_source(struct intsrc *isrc, int eoi);
static void	msi_eoi_source(struct intsrc *isrc);
static void	msi_enable_intr(struct intsrc *isrc);
static int	msi_vector(struct intsrc *isrc);
static int	msi_source_pending(struct intsrc *isrc);
static int	msi_config_intr(struct intsrc *isrc, enum intr_trigger trig,
		    enum intr_polarity pol);
static void	msi_assign_cpu(struct intsrc *isrc, u_int apic_id);
static void	msix_enable_intr(struct intsrc *isrc);
static int	msix_source_pending(struct intsrc *isrc);
static void	msix_assign_cpu(struct intsrc *isrc, u_int apic_id);

struct pic msi_pic = { msi_enable_source, msi_disable_source, msi_eoi_source,
		       msi_enable_intr, msi_vector, msi_source_pending,
		       NULL, NULL, msi_config_intr, msi_assign_cpu };
struct pic msix_pic = { msi_enable_source, msi_disable_source, msi_eoi_source,
			msix_enable_intr, msi_vector, msix_source_pending,
			NULL, NULL, msi_config_intr, msix_assign_cpu };

static int msi_enabled;
static struct sx msi_sx;

static void
msi_enable_source(struct intsrc *isrc)
{
}

static void
msi_disable_source(struct intsrc *isrc, int eoi)
{

	if (eoi == PIC_EOI)
		lapic_eoi();
}

static void
msi_eoi_source(struct intsrc *isrc)
{

	lapic_eoi();
}

static void
msi_enable_intr(struct intsrc *isrc)
{
	struct msi_intsrc *msi = (struct msi_intsrc *)isrc;

	/*
	 * Since we can only enable the entire group at once, go ahead and
	 * enable the messages when the first message is given a handler.
	 * Note that we assume all devices will register a handler for the
	 * first message.
	 */
	if (msi->msi_index == 0) {
		mtx_lock_spin(&icu_lock);
		pci_enable_msi(msi->msi_dev, INTEL_ADDR(msi), INTEL_DATA(msi));
		mtx_unlock_spin(&icu_lock);
	}
	apic_enable_vector(msi->msi_vector);
}

static int
msi_vector(struct intsrc *isrc)
{
	struct msi_intsrc *msi = (struct msi_intsrc *)isrc;

	return (msi->msi_irq);
}

static int
msi_source_pending(struct intsrc *isrc)
{

	return (0);
}

static int
msi_config_intr(struct intsrc *isrc, enum intr_trigger trig,
    enum intr_polarity pol)
{

	return (ENODEV);
}

static void
msi_assign_cpu(struct intsrc *isrc, u_int apic_id)
{
	struct msi_intsrc *msi = (struct msi_intsrc *)isrc;

	msi->msi_cpu = apic_id;
	if (bootverbose)
		printf("msi: Assigning MSI IRQ %d to local APIC %u\n",
		    msi->msi_irq, msi->msi_cpu);
	mtx_lock_spin(&icu_lock);
	if (isrc->is_enabled)
		pci_enable_msi(msi->msi_dev, INTEL_ADDR(msi), INTEL_DATA(msi));
	mtx_unlock_spin(&icu_lock);
}

static void
msix_enable_intr(struct intsrc *isrc)
{
	struct msi_intsrc *msi = (struct msi_intsrc *)isrc;

	mtx_lock_spin(&icu_lock);
	pci_enable_msix(msi->msi_dev, msi->msi_index, INTEL_ADDR(msi),
	    INTEL_DATA(msi));
	pci_unmask_msix(msi->msi_dev, msi->msi_index);
	mtx_unlock_spin(&icu_lock);
	apic_enable_vector(msi->msi_vector);
}

static int
msix_source_pending(struct intsrc *isrc)
{
	struct msi_intsrc *msi = (struct msi_intsrc *)isrc;

	return (pci_pending_msix(msi->msi_dev, msi->msi_index));
}

static void
msix_assign_cpu(struct intsrc *isrc, u_int apic_id)
{
	struct msi_intsrc *msi = (struct msi_intsrc *)isrc;

	msi->msi_cpu = apic_id;
	if (bootverbose)
		printf("msi: Assigning MSI-X IRQ %d to local APIC %u\n",
		    msi->msi_irq, msi->msi_cpu);
	mtx_lock_spin(&icu_lock);
	if (isrc->is_enabled)
		pci_enable_msix(msi->msi_dev, msi->msi_index, INTEL_ADDR(msi),
		    INTEL_DATA(msi));
	mtx_unlock_spin(&icu_lock);
}

void
msi_init(void)
{

	/* Check if we have a supported CPU. */
	if (!(strcmp(cpu_vendor, "GenuineIntel") == 0 ||
	      strcmp(cpu_vendor, "AuthenticAMD") == 0))
		return;

	msi_enabled = 1;
	intr_register_pic(&msi_pic);
	intr_register_pic(&msix_pic);
	sx_init(&msi_sx, "msi");
}

/*
 * Try to allocate 'count' interrupt sources with contiguous IDT values.  If
 * we allocate any new sources, then their IRQ values will be at the end of
 * the irqs[] array, with *newirq being the index of the first new IRQ value
 * and *newcount being the number of new IRQ values added.
 */
int
msi_alloc(device_t dev, int count, int maxcount, int *irqs, int *newirq,
    int *newcount)
{
	struct msi_intsrc *msi, *fsrc;
	int cnt, i, j, vector;

	*newirq = 0;
	*newcount = 0;
	if (!msi_enabled)
		return (ENXIO);

	sx_xlock(&msi_sx);

	/* Try to find 'count' free IRQs. */
	cnt = 0;
	for (i = FIRST_MSI_INT; i < FIRST_MSI_INT + NUM_MSI_INTS; i++) {
		msi = (struct msi_intsrc *)intr_lookup_source(i);

		/* End of allocated sources, so break. */
		if (msi == NULL)
			break;

		/* If this is a free one, save its IRQ in the array. */
		if (msi->msi_dev == NULL) {
			irqs[cnt] = i;
			cnt++;
			if (cnt == count)
				break;
		}
	}

	/* Do we need to create some new sources? */
	if (cnt < count) {
		/* If we would exceed the max, give up. */
		if (i + (count - cnt) > FIRST_MSI_INT + NUM_MSI_INTS) {
			sx_xunlock(&msi_sx);
			return (ENXIO);
		}

		/* We need count - cnt more sources starting at index 'cnt'. */
		*newirq = cnt;
		*newcount = count - cnt;
		for (j = 0; j < *newcount; j++) {

			/* Create a new MSI source. */
			msi = malloc(sizeof(struct msi_intsrc), M_MSI,
			    M_WAITOK | M_ZERO);
			msi->msi_intsrc.is_pic = &msi_pic;
			msi->msi_irq = i + j;
			intr_register_source(&msi->msi_intsrc);

			/* Add it to our array. */
			irqs[cnt] = i + j;
			cnt++;
		}
	}

	/* Ok, we now have the IRQs allocated. */
	KASSERT(cnt == count, ("count mismatch"));

	/* Allocate 'count' IDT vectors. */
	vector = apic_alloc_vectors(irqs, count, maxcount);
	if (vector == 0) {
		sx_xunlock(&msi_sx);
		return (ENOSPC);
	}

	/* Assign IDT vectors and make these messages owned by 'dev'. */
	fsrc = (struct msi_intsrc *)intr_lookup_source(irqs[0]);
	for (i = 0; i < count; i++) {
		msi = (struct msi_intsrc *)intr_lookup_source(irqs[i]);
		msi->msi_intsrc.is_pic = &msi_pic;
		msi->msi_dev = dev;
		msi->msi_vector = vector + i;
		msi->msi_index = i;
		msi->msi_first = fsrc;

		/* XXX: Somewhat gross. */
		msi->msi_intsrc.is_enabled = 0;
	}
	fsrc->msi_count = count;
	sx_xunlock(&msi_sx);

	return (0);
}

int
msi_release(int *irqs, int count)
{
	struct msi_intsrc *msi, *first;
	int i;

	sx_xlock(&msi_sx);
	first = (struct msi_intsrc *)intr_lookup_source(irqs[0]);
	if (first == NULL) {
		sx_xunlock(&msi_sx);
		return (ENOENT);
	}

	/* Make sure this isn't an MSI-X message. */
	if (first->msi_msix) {
		sx_xunlock(&msi_sx);
		return (EINVAL);
	}

	/* Make sure this message is allocated to a group. */
	if (first->msi_first == NULL) {
		sx_xunlock(&msi_sx);
		return (ENXIO);
	}

	/*
	 * Make sure this is the start of a group and that we are releasing
	 * the entire group.
	 */
	if (first->msi_first != first || first->msi_count != count) {
		sx_xunlock(&msi_sx);
		return (EINVAL);
	}
	KASSERT(first->msi_index == 0, ("index mismatch"));

	KASSERT(first->msi_dev != NULL, ("unowned group"));

	/* Clear all the extra messages in the group. */
	for (i = 1; i < count; i++) {
		msi = (struct msi_intsrc *)intr_lookup_source(irqs[i]);
		KASSERT(msi->msi_first == first, ("message not in group"));
		KASSERT(msi->msi_dev == first->msi_dev, ("owner mismatch"));
		msi->msi_first = NULL;
		msi->msi_dev = NULL;
		apic_free_vector(msi->msi_vector, msi->msi_irq);
		msi->msi_vector = 0;
		msi->msi_index = 0;
	}

	/* Clear out the first message. */
	first->msi_first = NULL;
	first->msi_dev = NULL;
	apic_free_vector(first->msi_vector, first->msi_irq);
	first->msi_vector = 0;
	first->msi_count = 0;

	sx_xunlock(&msi_sx);
	return (0);
}

int
msix_alloc(device_t dev, int index, int *irq, int *new)
{
	struct msi_intsrc *msi;
	int i, vector;

	*new = 0;
	if (!msi_enabled)
		return (ENXIO);

	sx_xlock(&msi_sx);

	/* Find a free IRQ. */
	for (i = FIRST_MSI_INT; i < FIRST_MSI_INT + NUM_MSI_INTS; i++) {
		msi = (struct msi_intsrc *)intr_lookup_source(i);

		/* End of allocated sources, so break. */
		if (msi == NULL)
			break;

		/* If this is a free one, start or continue a run. */
		if (msi->msi_dev == NULL)
			break;
	}

	/* Do we need to create a new source? */
	if (msi == NULL) {
		/* If we would exceed the max, give up. */
		if (i + 1 > FIRST_MSI_INT + NUM_MSI_INTS) {
			sx_xunlock(&msi_sx);
			return (ENXIO);
		}

		/* Create a new source. */
		*new = 1;
		msi = malloc(sizeof(struct msi_intsrc), M_MSI,
		    M_WAITOK | M_ZERO);
		msi->msi_intsrc.is_pic = &msix_pic;
		msi->msi_irq = i;
		intr_register_source(&msi->msi_intsrc);
	}

	/* Allocate an IDT vector. */
	vector = apic_alloc_vector(i);

	/* Setup source. */
	msi->msi_intsrc.is_pic = &msix_pic;
	msi->msi_dev = dev;
	msi->msi_vector = vector;
	msi->msi_index = index;
	msi->msi_msix = 1;

	/* XXX: Somewhat gross. */
	msi->msi_intsrc.is_enabled = 0;
	sx_xunlock(&msi_sx);

	*irq = i;
	return (0);
}

int
msix_remap(int index, int irq)
{
	struct msi_intsrc *msi;

	sx_xlock(&msi_sx);
	msi = (struct msi_intsrc *)intr_lookup_source(irq);
	if (msi == NULL) {
		sx_xunlock(&msi_sx);
		return (ENOENT);
	}

	/* Make sure this is an MSI-X message. */
	if (!msi->msi_msix) {
		sx_xunlock(&msi_sx);
		return (EINVAL);
	}

	KASSERT(msi->msi_dev != NULL, ("unowned message"));
	msi->msi_index = index;
	sx_xunlock(&msi_sx);
	return (0);
}

int
msix_release(int irq)
{
	struct msi_intsrc *msi;

	sx_xlock(&msi_sx);
	msi = (struct msi_intsrc *)intr_lookup_source(irq);
	if (msi == NULL) {
		sx_xunlock(&msi_sx);
		return (ENOENT);
	}

	/* Make sure this is an MSI-X message. */
	if (!msi->msi_msix) {
		sx_xunlock(&msi_sx);
		return (EINVAL);
	}

	KASSERT(msi->msi_dev != NULL, ("unowned message"));

	/* Clear out the message. */
	msi->msi_dev = NULL;
	apic_free_vector(msi->msi_vector, msi->msi_irq);
	msi->msi_vector = 0;
	msi->msi_index = 0;
	msi->msi_msix = 0;

	sx_xunlock(&msi_sx);
	return (0);
}
