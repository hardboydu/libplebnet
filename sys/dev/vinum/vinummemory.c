/*-
 * Copyright (c) 1997, 1998
 *	Nan Yang Computer Services Limited.  All rights reserved.
 *
 *  This software is distributed under the so-called ``Berkeley
 *  License'':
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Nan Yang Computer
 *      Services Limited.
 * 4. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *  
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even if
 * advised of the possibility of such damage.
 *
 * $Id: memory.c,v 1.4 1998/12/28 04:56:23 peter Exp $
 */

#define REALLYKERNEL
#include "opt_vinum.h"
#define USES_VM
#include <dev/vinum/vinumhdr.h>

extern jmp_buf command_fail;				    /* return on a failed command */

#ifdef VINUMDEBUG
#include <dev/vinum/request.h>
extern struct rqinfo rqinfo[];
extern struct rqinfo *rqip;
#endif

#if __FreeBSD__ >= 3
/* Why aren't these declared anywhere? XXX */
int setjmp(jmp_buf);
void longjmp(jmp_buf, int);
#endif

void freedatabuf(struct mc *me);
caddr_t allocdatabuf(struct mc *me);

void 
expand_table(void **table, int oldsize, int newsize)
{
    if (newsize > oldsize) {
	int *temp;

	temp = (int *) Malloc(newsize);			    /* allocate a new table */
	CHECKALLOC(temp, "vinum: Can't expand table\n");
	if (*table != NULL) {				    /* already something there, */
	    bcopy((char *) *table, (char *) temp, oldsize); /* copy it to the old table */
	    Free(*table);
	}
	*table = temp;
    }
}

#if VINUMDEBUG						    /* XXX debug */
#define MALLOCENTRIES 16384
int malloccount = 0;
int highwater = 0;					    /* highest index ever allocated */
static struct mc malloced[MALLOCENTRIES];

static total_malloced;

caddr_t 
MMalloc(int size, char *file, int line)
{
    caddr_t result;
    int i;
    static int seq = 0;
    int s;
    struct mc me;					    /* information to pass to allocdatabuf */

    if (malloccount >= MALLOCENTRIES) {			    /* too many */
	printf("vinum: can't allocate table space to trace memory allocation");
	return 0;					    /* can't continue */
    }
    result = malloc(size, M_DEVBUF, M_WAITOK);		    /* use malloc for smaller and irregular stuff */
    if (result == NULL)
	printf("vinum: can't allocate %d bytes from %s:%d\n", size, file, line);
    else {
	me.flags = 0;					    /* allocation via malloc */
	s = splhigh();
	for (i = 0; i < malloccount; i++) {
	    if (((result + size) > malloced[i].address)
		&& (result < malloced[i].address + malloced[i].size)) /* overlap */
		Debugger("Malloc overlap");
	}
	if (result) {
	    char *f = index(file, '/');			    /* chop off dirname if present */

	    if (f == NULL)
		f = file;
	    i = malloccount++;
	    total_malloced += size;
	    malloced[i].address = result;
	    malloced[i].size = size;
	    malloced[i].line = line;
	    malloced[i].seq = seq++;
	    malloced[i].flags = me.flags;
	    malloced[i].databuf = me.databuf;		    /* only used with kva alloc */
	    bcopy(f, malloced[i].file, min(strlen(f) + 1, 16));
	}
	if (malloccount > highwater)
	    highwater = malloccount;
	splx(s);
    }
    return result;
}

void 
FFree(void *mem, char *file, int line)
{
    int i;
    int s;

    s = splhigh();
    for (i = 0; i < malloccount; i++) {
	if ((caddr_t) mem == malloced[i].address) {	    /* found it */
	    bzero(mem, malloced[i].size);		    /* XXX */
	    free(mem, M_DEVBUF);
	    malloccount--;
	    total_malloced -= malloced[i].size;
	    if (i < malloccount)			    /* more coming after */
		bcopy(&malloced[i + 1], &malloced[i], (malloccount - i) * sizeof(struct mc));
	    splx(s);
	    return;
	}
    }
    splx(s);
    printf("Freeing unallocated data at 0x%08x from %s, line %d\n", (int) mem, file, line);
    Debugger("Free");
}

void 
vinum_meminfo(caddr_t data)
{
    struct meminfo *m = (struct meminfo *) data;

    m->mallocs = malloccount;
    m->total_malloced = total_malloced;
    m->malloced = malloced;
    m->highwater = highwater;
}

int 
vinum_mallocinfo(caddr_t data)
{
    struct mc *m = (struct mc *) data;
    unsigned int ent = *(int *) data;			    /* 1st word is index */

    if (ent >= malloccount)
	return ENOENT;
    m->address = malloced[ent].address;
    m->size = malloced[ent].size;
    m->line = malloced[ent].line;
    m->seq = malloced[ent].seq;
    bcopy(malloced[ent].file, m->file, 16);
    return 0;
}

/* return the nth request trace buffer entry.  This
 * is indexed back from the current entry (which
 * has index 0) */
int 
vinum_rqinfo(caddr_t data)
{
    struct rqinfo *rq = (struct rqinfo *) data;
    int ent = *(int *) data;				    /* 1st word is index */
    int lastent = rqip - rqinfo;			    /* entry number of current entry */

    if (ent >= RQINFO_SIZE)				    /* out of the table */
	return ENOENT;
    if ((ent = lastent - ent - 1) < 0)
	ent += RQINFO_SIZE;				    /* roll over backwards */
    bcopy(&rqinfo[ent], rq, sizeof(struct rqinfo));
    return 0;
}
#endif
