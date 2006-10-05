/*-
 * Copyright (c) 2006 Kip Macy
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/smp.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#ifdef DEBUG
#include <sys/kdb.h>
#endif
#include <vm/vm.h> 
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_extern.h>
#include <vm/uma.h> 

#include <machine/cpufunc.h>
#include <machine/hypervisorvar.h>
#include <machine/smp.h>
#include <machine/mmu.h>
#include <machine/tte.h>
#include <machine/vmparam.h>
#include <machine/tlb.h>
#include <machine/tte_hash.h>

#define HASH_SIZE        (1 << HASH_ENTRY_SHIFT)
#define HASH_MASK(th)    ((th->th_size<<(PAGE_SHIFT-THE_SHIFT))-1)
#define NULL_TAG         0
#define MAGIC_VALUE      0xcafebabe

struct tte_hash_entry;
struct of_field;

#define MAX_FRAGMENT_ENTRIES ((PAGE_SIZE / sizeof(struct tte_hash_entry)) - 1)

typedef struct tte_hash_field_ {
	uint64_t tag;
	uint64_t data;
} tte_hash_field, *tte_hash_field_t;

struct of_field {
	int16_t          count;
	uint8_t          lock;
	uint8_t          pad;
	uint32_t         flags;
	struct tte_hash_entry *next;
};

typedef struct tte_hash_entry {
	tte_hash_field the_fields[HASH_ENTRIES];
	struct of_field of;
} *tte_hash_entry_t;

struct fragment_header {
	struct tte_hash_fragment *fh_next;
	uint8_t fh_count;
	uint8_t fh_free_head;
	uint8_t pad[sizeof(struct tte_hash_entry) - 10];
};

CTASSERT(sizeof(struct fragment_header) == sizeof(struct tte_hash_entry));

struct tte_hash {
	uint16_t th_size;               /* size in pages */
	uint16_t th_context;            /* TLB context   */
	uint32_t th_entries;            /* # pages held  */
	tte_hash_entry_t th_hashtable;   /* hash of TTEs  */
	struct tte_hash_fragment *th_fhhead;
	struct tte_hash_fragment *th_fhtail;
};

struct tte_hash_fragment {
	struct fragment_header thf_head;
	struct tte_hash_entry  thf_entries[MAX_FRAGMENT_ENTRIES];
};

CTASSERT(sizeof(struct tte_hash_fragment) == PAGE_SIZE);


static struct tte_hash kernel_tte_hash;
/*
 * Data for the tte_hash allocation mechanism
 */
static uma_zone_t thzone;
static struct vm_object thzone_obj;
static int tte_hash_count = 0, tte_hash_max = 0;

extern uint64_t hash_bucket_lock(tte_hash_field_t fields);
extern void hash_bucket_unlock(tte_hash_field_t fields, uint64_t s);

static tte_hash_t
get_tte_hash(void)
{
	tte_hash_t th;

	th = uma_zalloc(thzone, M_NOWAIT);

	KASSERT(th != NULL, ("tte_hash allocation failed"));
	tte_hash_count++;
	return th;

}

static __inline void
free_tte_hash(tte_hash_t th)
{
	tte_hash_count--;
	uma_zfree(thzone, th);
}

void 
tte_hash_init(void)
{
	thzone = uma_zcreate("TTE_HASH", sizeof(struct tte_hash), NULL, NULL, 
	    NULL, NULL, UMA_ALIGN_PTR, UMA_ZONE_VM | UMA_ZONE_NOFREE);
	tte_hash_max = maxproc;
	uma_zone_set_obj(thzone, &thzone_obj, tte_hash_max);
}

tte_hash_t
tte_hash_kernel_create(vm_offset_t va, uint64_t size, vm_paddr_t fragment_page)
{
	tte_hash_t th;
		
	th = &kernel_tte_hash;
	th->th_size = (size >> PAGE_SHIFT);
	th->th_entries = 0;
	th->th_context = 0;
	th->th_hashtable = (tte_hash_entry_t)va;
	th->th_fhtail = th->th_fhhead = (void *)TLB_PHYS_TO_DIRECT(fragment_page);

	return th;
}

static inline vm_page_t
alloc_zeroed_page(void)
{
	vm_page_t m;
	static int color;

	m = NULL;

	while (m == NULL) {
		m = vm_page_alloc(NULL, color++,
		    VM_ALLOC_NORMAL | VM_ALLOC_NOOBJ | VM_ALLOC_WIRED |
		    VM_ALLOC_ZERO);

		if (m == NULL) 
			VM_WAIT;
	}

	if ((m->flags & PG_ZERO) == 0)
		pmap_zero_page(m);

	return (m);
}

tte_hash_t
tte_hash_create(uint64_t context, uint64_t *scratchval)
{
	tte_hash_t th;
	vm_page_t m, tm;
	int i;
	
	th = get_tte_hash();
	
	th->th_size = HASH_SIZE;
	th->th_entries = 0;
	th->th_context = (uint16_t)context;
	m = NULL;

	while (m == NULL) {
		m = vm_page_alloc_contig(HASH_SIZE, phys_avail[0], 
					 phys_avail[1], PAGE_SIZE, (1UL<<34));
		if (m == NULL) {
			printf("vm_page_alloc_contig failed - waiting to retry\n");
			VM_WAIT;
		}
	}
	for (i = 0, tm = m; i < HASH_SIZE; i++, tm++) 
		if ((tm->flags & PG_ZERO) == 0)
			pmap_zero_page(tm);

	th->th_hashtable = (void *)TLB_PHYS_TO_DIRECT(VM_PAGE_TO_PHYS(m));
	m = alloc_zeroed_page();


	th->th_fhtail = th->th_fhhead = (void *)TLB_PHYS_TO_DIRECT(VM_PAGE_TO_PHYS(m));
	KASSERT(th->th_fhtail != NULL, ("th->th_fhtail == NULL"));

	*scratchval = (uint64_t)((vm_offset_t)th->th_hashtable) | ((vm_offset_t)th->th_size);

	return (th);
}

void
tte_hash_destroy(tte_hash_t th)
{
	panic("FIXME");

	free_tte_hash(th);
}

void
tte_hash_reset(tte_hash_t th)
{
	struct tte_hash_fragment *fh;
	vm_page_t m;

	for (fh = th->th_fhhead->thf_head.fh_next; fh != NULL; fh = fh->thf_head.fh_next) {
		m = PHYS_TO_VM_PAGE((vm_paddr_t)TLB_DIRECT_TO_PHYS((vm_offset_t)fh));
		m->wire_count--;
		vm_page_free(m);
	}
	fh = th->th_fhtail = th->th_fhhead;
	hwblkclr(th->th_fhhead, PAGE_SIZE); 

#ifdef UNMANAGED_PAGES_ARE_TRACKED
	if (th->th_entries != 0)
		panic("%d remaining entries", th->th_entries);
#else
	hwblkclr(th->th_hashtable, th->th_size*PAGE_SIZE); 	
#endif
}

static __inline void
tte_hash_set_field(tte_hash_field_t field, uint64_t tag, tte_t tte)
{
	field->tag = tag;
	field->data = tte | (field->data & VTD_LOCK);
}

static __inline tte_hash_entry_t 
find_entry(tte_hash_t th, vm_offset_t va, int page_shift)
{
	uint64_t hash_index;

	hash_index = (va >> page_shift) & HASH_MASK(th);
	return (&th->th_hashtable[hash_index]);
}

static __inline tte_hash_entry_t 
tte_hash_lookup_last_entry(tte_hash_entry_t entry)
{

	while (entry->of.next) 
		entry = entry->of.next;

	return (entry);
}

static tte_hash_entry_t 
tte_hash_allocate_fragment_entry(tte_hash_t th)
{
	struct tte_hash_fragment *fh;
	tte_hash_entry_t newentry;
	vm_page_t m;
	
	fh = th->th_fhtail;
	if (fh->thf_head.fh_free_head == MAX_FRAGMENT_ENTRIES) {
		m = alloc_zeroed_page();

		fh->thf_head.fh_next = (void *)TLB_PHYS_TO_DIRECT(VM_PAGE_TO_PHYS(m));
		fh = th->th_fhtail = (void *)TLB_PHYS_TO_DIRECT(VM_PAGE_TO_PHYS(m));
		fh->thf_head.fh_free_head = 1;
#ifdef NOISY_DEBUG
		printf("new fh=%p \n", fh);
#endif
	} 
	newentry = &fh->thf_entries[fh->thf_head.fh_free_head];

	fh->thf_head.fh_free_head++;
	fh->thf_head.fh_count++; 

	return (newentry);
}

/*
 * if a match for va is found the tte value is returned 
 * and if field is non-null field will point to that entry
 * 
 * 
 */
static __inline tte_t 
tte_hash_lookup_inline(tte_hash_entry_t entry, tte_t tte_tag, boolean_t insert)
{
	int i;
	tte_t tte_data;
	tte_hash_field_t fields;

	tte_data = 0;
	do { 
		fields = entry->the_fields;
		for (i = 0; i < entry->of.count; i++) {
			if (fields[i].tag == tte_tag) {
				tte_data = (fields[i].data & ~VTD_LOCK);
				PCPU_SET(lookup_field, (u_long)&fields[i]);
				goto done;
			}
		}
#ifdef DEBUG
	if (entry->of.next && entry->of.flags != MAGIC_VALUE)
		panic("overflow pointer not null without flags set entry= %p next=%p flags=0x%x count=%d", 
		      entry, entry->of.next, entry->of.flags, entry->of.count);
#endif
		entry = entry->of.next;
	} while (entry);

done:
	return (tte_data);
}


static __inline void
tte_hash_lookup_last_inline(tte_hash_entry_t entry)
{

	tte_hash_field_t fields;

	fields = entry->the_fields;

	while (entry->of.next && (entry->of.next->of.count > 1))
		entry = entry->of.next;

	if (entry->of.next && entry->of.next->of.count == 1) {
		PCPU_SET(last_field, (u_long)&entry->of.next->the_fields[0]);
		entry->of.next = NULL;
		entry->of.flags = 0;
	} else {
#ifdef DEBUG
		if (entry->of.count == 0)
			panic("count zero");
#endif
		PCPU_SET(last_field, (u_long)&entry->the_fields[--entry->of.count]);
	}
}

tte_t
tte_hash_clear_bits(tte_hash_t th, vm_offset_t va, uint64_t flags)
{
	uint64_t s;
	tte_hash_entry_t entry;
	tte_t otte_data, tte_tag;

	/* XXX - only handle 8K pages for now */
	entry = find_entry(th, va, PAGE_SHIFT);

	tte_tag = (((uint64_t)th->th_context << TTARGET_CTX_SHIFT)|(va >> TTARGET_VA_SHIFT));
	
	s = hash_bucket_lock(entry->the_fields);
	if((otte_data = tte_hash_lookup_inline(entry, tte_tag, FALSE)) != 0)
		tte_hash_set_field((tte_hash_field_t)PCPU_GET(lookup_field), 
				   ((tte_hash_field_t)PCPU_GET(lookup_field))->tag, 
				   ((tte_hash_field_t)PCPU_GET(lookup_field))->data & ~flags);

	hash_bucket_unlock(entry->the_fields, s);

	return (otte_data);
}

tte_t
tte_hash_delete(tte_hash_t th, vm_offset_t va)
{
	uint64_t s;
	tte_hash_entry_t entry;
	tte_t tte_data, tte_tag;

	/* XXX - only handle 8K pages for now */
	entry = find_entry(th, va, PAGE_SHIFT);

	tte_tag = (((uint64_t)th->th_context << TTARGET_CTX_SHIFT)|(va >> TTARGET_VA_SHIFT));

	s  = hash_bucket_lock(entry->the_fields);
	
	if ((tte_data = tte_hash_lookup_inline(entry, tte_tag, FALSE)) == 0) 
		goto done;

	tte_hash_lookup_last_inline(entry);

#ifdef DEBUG
	if (((tte_hash_field_t)PCPU_GET(last_field))->tag == 0) {
		hash_bucket_unlock(entry->the_fields, s);
		panic("lookup_last failed for va=0x%lx\n", va);
	}
#endif
	/* move last field's values in to the field we are deleting */
	if (PCPU_GET(lookup_field) != PCPU_GET(last_field)) 
		tte_hash_set_field((tte_hash_field_t)PCPU_GET(lookup_field), 
				   ((tte_hash_field_t)PCPU_GET(last_field))->tag, 
				   ((tte_hash_field_t)PCPU_GET(last_field))->data);
	
	tte_hash_set_field((tte_hash_field_t)PCPU_GET(last_field), 0, 0);
done:	
	hash_bucket_unlock(entry->the_fields, s);
	if (tte_data) 
		th->th_entries--;

	return (tte_data);
}

void
tte_hash_insert(tte_hash_t th, vm_offset_t va, tte_t tte_data)
{

	tte_hash_entry_t entry, lentry, newentry;
	tte_t tte_tag;
	uint64_t s;

#ifdef DEBUG
	if (tte_hash_lookup(th, va) != 0) 
		panic("mapping for va=0x%lx already exists", va);
#endif
	entry = find_entry(th, va, PAGE_SHIFT);
	tte_tag = (((uint64_t)th->th_context << TTARGET_CTX_SHIFT)|(va >> TTARGET_VA_SHIFT));

	s = hash_bucket_lock(entry->the_fields);
	lentry = tte_hash_lookup_last_entry(entry);

	if (lentry->of.count == HASH_ENTRIES) {
		hash_bucket_unlock(entry->the_fields, s);
		newentry = tte_hash_allocate_fragment_entry(th); 
		s = hash_bucket_lock(entry->the_fields);
		lentry->of.flags = MAGIC_VALUE;
		lentry->of.next = newentry;
		lentry = newentry;
	} 
	tte_hash_set_field(&lentry->the_fields[lentry->of.count++], 
			   tte_tag, tte_data);
	hash_bucket_unlock(entry->the_fields, s);

#ifdef DEBUG
	if (tte_hash_lookup(th, va) == 0) 
		panic("insert for va=0x%lx failed", va);
#endif
	th->th_entries++;
}

/* 
 * If leave_locked is true the tte's data field will be returned to
 * the caller with the hash bucket left locked
 */
tte_t 
tte_hash_lookup(tte_hash_t th, vm_offset_t va)
{
	uint64_t s;
	tte_hash_entry_t entry;
	tte_t tte_data, tte_tag;

	/* XXX - only handle 8K pages for now */
	entry = find_entry(th, va, PAGE_SHIFT);

	tte_tag = (((uint64_t)th->th_context << TTARGET_CTX_SHIFT)|(va >> TTARGET_VA_SHIFT));

	s = hash_bucket_lock(entry->the_fields);
	tte_data = tte_hash_lookup_inline(entry, tte_tag, FALSE);
	hash_bucket_unlock(entry->the_fields, s);
	
	return (tte_data);
}

uint64_t
tte_hash_set_scratchpad_kernel(tte_hash_t th)
{
	
	uint64_t hash_scratch;
	/* This breaks if a hash table grows above 32MB
	 */
	hash_scratch = ((vm_offset_t)th->th_hashtable) | ((vm_offset_t)th->th_size);
	set_hash_kernel_scratchpad(hash_scratch);
	
	return (hash_scratch);
}

uint64_t
tte_hash_set_scratchpad_user(tte_hash_t th, uint64_t context)
{

	uint64_t hash_scratch;
	/* This breaks if a hash table grows above 32MB
	 */
	th->th_context = (uint16_t)context;
	hash_scratch = ((vm_offset_t)th->th_hashtable) | ((vm_offset_t)th->th_size);
	set_hash_user_scratchpad(hash_scratch);
	
	return (hash_scratch);
}

tte_t
tte_hash_update(tte_hash_t th, vm_offset_t va, tte_t tte_data)
{

	uint64_t s;
	tte_hash_entry_t entry;
	tte_t otte_data, tte_tag;

	entry = find_entry(th, va, PAGE_SHIFT);

	tte_tag = (((uint64_t)th->th_context << TTARGET_CTX_SHIFT)|(va >> TTARGET_VA_SHIFT));

	s = hash_bucket_lock(entry->the_fields);
	otte_data = tte_hash_lookup_inline(entry, tte_tag, TRUE);

	if (otte_data == 0) {
		hash_bucket_unlock(entry->the_fields, s);
		tte_hash_insert(th, va, tte_data);
	} else {
		tte_hash_set_field((tte_hash_field_t)PCPU_GET(lookup_field), 
				   tte_tag, tte_data);
		hash_bucket_unlock(entry->the_fields, s);
	}

	return (otte_data);
}

