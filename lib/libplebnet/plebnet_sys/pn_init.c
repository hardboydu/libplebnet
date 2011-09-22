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
#include <sys/pcpu.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/sx.h>

#include <pn_private.h>

#include <vm/uma.h>
#include <vm/uma_int.h>
#include <pthread.h>
#include <spawn.h>

char *     getenv(const char *name);
pid_t     getpid(void);
char *strndup(const char *str, size_t len);
unsigned int     sleep(unsigned int seconds);



extern void mi_startup(void);
extern void uma_startup(void *, int);
extern void uma_startup2(void);


extern int ncallout;


struct sx proctree_lock;
struct pcpu *pcpup;

extern caddr_t kern_timeout_callwheel_alloc(caddr_t v);
extern void kern_timeout_callwheel_init(void);
extern void pn_init_thread0(void);
extern void mutex_init(void);

static int pn_init(void) __attribute__((constructor));
pthread_mutex_t init_lock;
pthread_cond_t init_cond;

static int
pn_init(void)
{
	struct thread *td;
	int needconfig, error;
	char *plebconf, *rcconf;
	char buf[512];
	char *envp[3];
	char *argv[3];

        /* vm_init bits */
        ncallout = 64;
	plebconf = getenv("PLEBCONF_PATH");
	rcconf = getenv("RC_CONF");
	
	needconfig = 1;
	if (plebconf == NULL || rcconf == NULL ||
	    strlen(plebconf) == 0 || strlen(rcconf) == 0) {
		printf("WARNING: PLEBCONF_PATH and RC_CONF need "
		    "to be set to configure the virtual interface automatically\n");
		needconfig = 0;
	}
        pcpup = malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO);
        pcpu_init(pcpup, 0, sizeof(struct pcpu));
        kern_timeout_callwheel_alloc(malloc(512*1024, M_DEVBUF, M_ZERO));
        kern_timeout_callwheel_init();
	pn_init_thread0();
        uma_startup(malloc(40*4096, M_DEVBUF, M_ZERO), 40);
	uma_startup2();
	/* XXX fix this magic 64 to something a bit more dynamic & sensible */
	uma_page_slab_hash = malloc(sizeof(struct uma_page)*64, M_DEVBUF, M_ZERO);
	uma_page_mask = 64-1;
	pthread_mutex_init(&init_lock, NULL);
	pthread_cond_init(&init_cond, NULL);
	mutex_init();
        mi_startup();
	sx_init(&proctree_lock, "proctree");
	td = curthread;
	fdused_range(td->td_proc->p_fd, 16);
	start_server_syscalls();
	if (needconfig) {
		posix_spawnattr_t pattr;
		pid_t targetpid, shpid;

		pthread_mutex_lock(&init_lock);
		pthread_cond_wait(&init_cond, &init_lock);
		pthread_mutex_unlock(&init_lock);
		targetpid = getpid();
		sprintf(buf, "TARGET_PID=%d", targetpid);
		envp[0] = strndup(buf, 128);
		sprintf(buf, "LD_PRELOAD=%s/libplebconf.so", plebconf);
		envp[1] = strndup(buf, 128);
		envp[2] = NULL;

		argv[0] = "/bin/sh";
		argv[1] = rcconf;
		argv[2] = NULL;
		posix_spawnattr_init(&pattr);
		posix_spawnattr_setflags(&pattr, POSIX_SPAWN_SETPGROUP);
		error = posix_spawn(&shpid, "/bin/sh", NULL, &pattr, argv, envp);
		if (error)
			printf("posix_spawn failed %d\n", error);
	}
	/* give all configuration threads time to complete initialization
	 * before continuing
	 */
	sleep(1);
	return (0);
}
