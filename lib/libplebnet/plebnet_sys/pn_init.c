/*-
 * Copyright (c) 2010 Kip Macy
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
#include <sys/param.h>
#include <stdlib.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <string.h>

#include <pn_private.h>

extern void mi_startup(void);
extern void uma_startup(void *, int);
extern void uma_startup2(void);
caddr_t kern_timeout_callwheel_alloc(caddr_t v);
void kern_timeout_callwheel_init(void);
extern int ncallout;

extern void pn_init_thread0(void);

struct sx proctree_lock;

struct pcpu *pcpup;

extern int pn_veth_attach(void);

static int pn_init(void) __attribute__((constructor));

static int
pn_init(void)
{
	struct thread *td;

        /* vm_init bits */
        ncallout = 64;
        pcpup = malloc(sizeof(struct pcpu));
	bzero(pcpup, sizeof(struct pcpu));
        pcpu_init(pcpup, 0, sizeof(struct pcpu));
        kern_timeout_callwheel_alloc(malloc(512*1024));
        kern_timeout_callwheel_init();
	pn_init_thread0();
        uma_startup(malloc(40*4096), 40);
	uma_startup2();
        mi_startup();
	sx_init(&proctree_lock, "proctree");
	td = curthread;
	pn_fdused_range(td->td_proc->p_fd, 512);
	pn_veth_attach();
	start_server_syscalls();

	return (0);
}
