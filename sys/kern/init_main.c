/*
 * Copyright (c) 1995 Terrence R. Lambert
 * All rights reserved.
 *
 * Copyright (c) 1982, 1986, 1989, 1991, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)init_main.c	8.9 (Berkeley) 1/21/94
 * $Id: init_main.c,v 1.100 1998/12/19 02:55:33 julian Exp $
 */

#include "opt_devfs.h"

#include <sys/param.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/signalvar.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/sysent.h>
#include <sys/reboot.h>
#include <sys/sysproto.h>
#include <sys/vmmeter.h>
#include <sys/unistd.h>
#include <sys/malloc.h>

#include <machine/cpu.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_prot.h>
#include <sys/lock.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <sys/user.h>
#include <sys/copyright.h>

extern struct linker_set	sysinit_set;	/* XXX */

extern void __main __P((void));
extern void main __P((void *framep));

/* Components of the first process -- never freed. */
static struct session session0;
static struct pgrp pgrp0;
struct	proc proc0;
static struct pcred cred0;
#ifdef COMPAT_LINUX_THREADS
static struct procsig procsig0;
#endif /* COMPAT_LINUX_THREADS */
static struct filedesc0 filedesc0;
static struct plimit limit0;
static struct vmspace vmspace0;
struct	proc *initproc;

int cmask = CMASK;
extern	struct user *proc0paddr;

struct	vnode *rootvp;
int	boothowto = 0;		/* initialized so that it can be patched */

struct	timeval boottime;
SYSCTL_STRUCT(_kern, KERN_BOOTTIME, boottime,
	CTLFLAG_RD, &boottime, timeval, "");

static int shutdowntimeout = 120;
SYSCTL_INT(_kern, OID_AUTO, shutdown_timeout,
	CTLFLAG_RW, &shutdowntimeout, 0, "");

/*
 * Promiscuous argument pass for start_init()
 *
 * This is a kludge because we use a return from main() rather than a call
 * to a new routine in locore.s to kick the kernel alive from locore.s.
 */
static void	*init_framep;


#if __GNUC__ >= 2
void __main() {}
#endif


/*
 * This ensures that there is at least one entry so that the sysinit_set
 * symbol is not undefined.  A sybsystem ID of SI_SUB_DUMMY is never
 * executed.
 */
SYSINIT(placeholder, SI_SUB_DUMMY,SI_ORDER_ANY, NULL, NULL)

/*
 * The sysinit table itself.  Items are checked off as the are run.
 * If we want to register new sysinit types, add them to newsysinit.
 */
struct sysinit **sysinit = (struct sysinit **)sysinit_set.ls_items;
struct sysinit **newsysinit;

/*
 * Merge a new sysinit set into the current set, reallocating it if
 * necessary.  This can only be called after malloc is running.
 */
void
sysinit_add(set)
	struct sysinit **set;
{
	struct sysinit **newset;
	struct sysinit **sipp;
	struct sysinit **xipp;
	int count = 0;

	if (newsysinit)
		for (sipp = newsysinit; *sipp; sipp++)
			count++;
	else
		for (sipp = sysinit; *sipp; sipp++)
			count++;
	for (sipp = set; *sipp; sipp++)
		count++;
	count++;		/* Trailing NULL */
	newset = malloc(count * sizeof(*sipp), M_TEMP, M_NOWAIT);
	if (newset == NULL)
		panic("cannot malloc for sysinit");
	xipp = newset;
	if (newsysinit)
		for (sipp = newsysinit; *sipp; sipp++)
			*xipp++ = *sipp;
	else
		for (sipp = sysinit; *sipp; sipp++)
			*xipp++ = *sipp;
	for (sipp = set; *sipp; sipp++)
		*xipp++ = *sipp;
	*xipp = NULL;
	if (newsysinit)
		free(newsysinit, M_TEMP);
	newsysinit = newset;
}

/*
 * System startup; initialize the world, create process 0, mount root
 * filesystem, and fork to create init and pagedaemon.  Most of the
 * hard work is done in the lower-level initialization routines including
 * startup(), which does memory initialization and autoconfiguration.
 *
 * This allows simple addition of new kernel subsystems that require
 * boot time initialization.  It also allows substitution of subsystem
 * (for instance, a scheduler, kernel profiler, or VM system) by object
 * module.  Finally, it allows for optional "kernel threads".
 */
void
main(framep)
	void *framep;
{

	register struct sysinit **sipp;		/* system initialization*/
	register struct sysinit **xipp;		/* interior loop of sort*/
	register struct sysinit *save;		/* bubble*/

	/*
	 * Copy the locore.s frame pointer for proc0, this is forked into
	 * all other processes.
	 */
	init_framep = framep;

restart:
	/*
	 * Perform a bubble sort of the system initialization objects by
	 * their subsystem (primary key) and order (secondary key).
	 */
	for (sipp = sysinit; *sipp; sipp++) {
		for (xipp = sipp + 1; *xipp; xipp++) {
			if ((*sipp)->subsystem < (*xipp)->subsystem ||
			     ((*sipp)->subsystem == (*xipp)->subsystem &&
			      (*sipp)->order < (*xipp)->order))
				continue;	/* skip*/
			save = *sipp;
			*sipp = *xipp;
			*xipp = save;
		}
	}

	/*
	 * Traverse the (now) ordered list of system initialization tasks.
	 * Perform each task, and continue on to the next task.
	 *
	 * The last item on the list is expected to be the scheduler,
	 * which will not return.
	 */
	for (sipp = sysinit; *sipp; sipp++) {

		if ((*sipp)->subsystem == SI_SUB_DUMMY)
			continue;	/* skip dummy task(s)*/

		if ((*sipp)->subsystem == SI_SUB_DONE)
			continue;

		switch( (*sipp)->type) {
		case SI_TYPE_DEFAULT:
			/* no special processing*/
			(*((*sipp)->func))((*sipp)->udata);
			break;

		case SI_TYPE_KTHREAD:
#if !defined(SMP)
			/* kernel thread*/
			if (fork1(&proc0, RFMEM|RFFDG|RFPROC))
				panic("fork kernel thread");
			cpu_set_fork_handler(pfind(proc0.p_retval[0]),
			    (*sipp)->func, (*sipp)->udata);
			break;
#endif

		case SI_TYPE_KPROCESS:
			if (fork1(&proc0, RFFDG|RFPROC))
				panic("fork kernel process");
			cpu_set_fork_handler(pfind(proc0.p_retval[0]),
			    (*sipp)->func, (*sipp)->udata);
			break;

		default:
			panic("init_main: unrecognized init type");
		}

		/* Check off the one we're just done */
		(*sipp)->subsystem = SI_SUB_DONE;

		/* Check if we've installed more sysinit items via KLD */
		if (newsysinit != NULL) {
			if (sysinit != (struct sysinit **)sysinit_set.ls_items)
				free(sysinit, M_TEMP);
			sysinit = newsysinit;
			newsysinit = NULL;
			goto restart;
		}
	}

	panic("Shouldn't get here!");
	/* NOTREACHED*/
}


/*
 * Start a kernel process.  This is called after a fork() call in
 * main() in the file kern/init_main.c.
 *
 * This function is used to start "internal" daemons.
 */
/* ARGSUSED*/
void
kproc_start(udata)
	void *udata;
{
	struct kproc_desc	*kp = udata;
	struct proc		*p = curproc;

#ifdef DIAGNOSTIC
	printf("Start pid=%d <%s>\n",p->p_pid, kp->arg0);
#endif

	/* save a global descriptor, if desired*/
	if( kp->global_procpp != NULL)
		*kp->global_procpp	= p;

	/* this is a non-swapped system process*/
	p->p_flag |= P_INMEM | P_SYSTEM;

	/* set up arg0 for 'ps', et al*/
	strcpy( p->p_comm, kp->arg0);

	/* call the processes' main()...*/
	(*kp->func)();

	/* NOTREACHED */
	panic("kproc_start: %s", kp->arg0);
}


/*
 ***************************************************************************
 ****
 **** The following SYSINIT's belong elsewhere, but have not yet
 **** been moved.
 ****
 ***************************************************************************
 */
#ifdef OMIT
/*
 * Handled by vfs_mountroot (bad idea) at this time... should be
 * done the same as 4.4Lite2.
 */
SYSINIT(swapinit, SI_SUB_SWAP, SI_ORDER_FIRST, swapinit, NULL)
#endif	/* OMIT*/

static void print_caddr_t __P((void *data));
static void
print_caddr_t(data)
	void *data;
{
	printf("%s", (char *)data);
}
SYSINIT(announce, SI_SUB_COPYRIGHT, SI_ORDER_FIRST, print_caddr_t, copyright)


/*
 ***************************************************************************
 ****
 **** The two following SYSINT's are proc0 specific glue code.  I am not
 **** convinced that they can not be safely combined, but their order of
 **** operation has been maintained as the same as the original init_main.c
 **** for right now.
 ****
 **** These probably belong in init_proc.c or kern_proc.c, since they
 **** deal with proc0 (the fork template process).
 ****
 ***************************************************************************
 */
/* ARGSUSED*/
static void proc0_init __P((void *dummy));
static void
proc0_init(dummy)
	void *dummy;
{
	register struct proc		*p;
	register struct filedesc0	*fdp;
	register unsigned i;

	/*
	 * Initialize the current process pointer (curproc) before
	 * any possible traps/probes to simplify trap processing.
	 */
	p = &proc0;
	curproc = p;			/* XXX redundant*/

	/*
	 * Initialize process and pgrp structures.
	 */
	procinit();

	/*
	 * Initialize sleep queue hash table
	 */
	sleepinit();

	/*
	 * additional VM structures
	 */
	vm_init2();

	/*
	 * Create process 0 (the swapper).
	 */
	LIST_INSERT_HEAD(&allproc, p, p_list);
	p->p_pgrp = &pgrp0;
	LIST_INSERT_HEAD(PGRPHASH(0), &pgrp0, pg_hash);
	LIST_INIT(&pgrp0.pg_members);
	LIST_INSERT_HEAD(&pgrp0.pg_members, p, p_pglist);

	pgrp0.pg_session = &session0;
	session0.s_count = 1;
	session0.s_leader = p;

	p->p_sysent = &aout_sysvec;

	p->p_flag = P_INMEM | P_SYSTEM;
	p->p_stat = SRUN;
	p->p_nice = NZERO;
	p->p_rtprio.type = RTP_PRIO_NORMAL;
	p->p_rtprio.prio = 0;

/*
 * Link for kernel based threads
 */
	p->p_peers = 0;
	p->p_leader = p;

	bcopy("swapper", p->p_comm, sizeof ("swapper"));

	/* Create credentials. */
	cred0.p_refcnt = 1;
	p->p_cred = &cred0;
	p->p_ucred = crget();
	p->p_ucred->cr_ngroups = 1;	/* group 0 */

#ifdef COMPAT_LINUX_THREADS
	/* Create procsig. */
	p->p_procsig = &procsig0;
	p->p_procsig->ps_refcnt = 2;

#endif /* COMPAT_LINUX_THREADS */
	/* Create the file descriptor table. */
	fdp = &filedesc0;
	p->p_fd = &fdp->fd_fd;
	fdp->fd_fd.fd_refcnt = 1;
	fdp->fd_fd.fd_cmask = cmask;
	fdp->fd_fd.fd_ofiles = fdp->fd_dfiles;
	fdp->fd_fd.fd_ofileflags = fdp->fd_dfileflags;
	fdp->fd_fd.fd_nfiles = NDFILE;

	/* Create the limits structures. */
	p->p_limit = &limit0;
	for (i = 0; i < sizeof(p->p_rlimit)/sizeof(p->p_rlimit[0]); i++)
		limit0.pl_rlimit[i].rlim_cur =
		    limit0.pl_rlimit[i].rlim_max = RLIM_INFINITY;
	limit0.pl_rlimit[RLIMIT_NOFILE].rlim_cur =
	    limit0.pl_rlimit[RLIMIT_NOFILE].rlim_max = maxfiles;
	limit0.pl_rlimit[RLIMIT_NPROC].rlim_cur =
	    limit0.pl_rlimit[RLIMIT_NPROC].rlim_max = maxproc;
	i = ptoa(cnt.v_free_count);
	limit0.pl_rlimit[RLIMIT_RSS].rlim_max = i;
	limit0.pl_rlimit[RLIMIT_MEMLOCK].rlim_max = i;
	limit0.pl_rlimit[RLIMIT_MEMLOCK].rlim_cur = i / 3;
	limit0.p_cpulimit = RLIM_INFINITY;
	limit0.p_refcnt = 1;


	/* Allocate a prototype map so we have something to fork. */
	pmap_pinit0(&vmspace0.vm_pmap);
	p->p_vmspace = &vmspace0;
	vmspace0.vm_refcnt = 1;
	vm_map_init(&vmspace0.vm_map, round_page(VM_MIN_ADDRESS),
	    trunc_page(VM_MAXUSER_ADDRESS));
	vmspace0.vm_map.pmap = &vmspace0.vm_pmap;
	p->p_addr = proc0paddr;				/* XXX */

#ifndef __alpha__		/* XXX what is this? */
#define INCOMPAT_LITES2
#ifdef INCOMPAT_LITES2
	/*
	 * proc0 needs to have a coherent frame base in its stack.
	 */
	cpu_set_init_frame(p, init_framep);			/* XXX! */
#endif	/* INCOMPAT_LITES2*/
#endif

#ifndef COMPAT_LINUX_THREADS
	/*
	 * We continue to place resource usage info and signal
	 * actions in the user struct so they're pageable.
	 */
	p->p_stats = &p->p_addr->u_stats;
	p->p_sigacts = &p->p_addr->u_sigacts;
#else
	/*
	 * We continue to place resource usage info in the user struct so
	 * it's pageable.
	 */
	p->p_stats = &p->p_addr->u_stats;

	p->p_sigacts = &p->p_procsig->ps_sigacts;
#endif /* COMPAT_LINUX_THREADS */

	/*
	 * Charge root for one process.
	 */
	(void)chgproccnt(0, 1);

	/*
	 * Initialize the procfs flags (to 0, of course)
	 */
	p->p_stops = p->p_stype = p->p_step = 0;

}
SYSINIT(p0init, SI_SUB_INTRINSIC, SI_ORDER_FIRST, proc0_init, NULL)

/* ARGSUSED*/
static void proc0_post __P((void *dummy));
static void
proc0_post(dummy)
	void *dummy;
{
	struct timespec ts;

	/*
	 * Now can look at time, having had a chance to verify the time
	 * from the file system.  Reset p->p_runtime as it may have been
	 * munched in mi_switch() after the time got set.  Set
	 * p->p_switchtime to be consistent with this unmunching.
	 */
	microtime(&proc0.p_stats->p_start);
	proc0.p_runtime = 0;
	microuptime(&proc0.p_switchtime);

	/*
	 * Give the ``random'' number generator a thump.
	 * XXX: Does read_random() contain enough bits to be used here ?
	 */
	nanotime(&ts);
	srandom(ts.tv_sec ^ ts.tv_nsec);

	/* Initialize signal state for process 0. */
	siginit(&proc0);
}
SYSINIT(p0post, SI_SUB_INTRINSIC_POST, SI_ORDER_FIRST, proc0_post, NULL)




/*
 ***************************************************************************
 ****
 **** The following SYSINIT's and glue code should be moved to the
 **** respective files on a per subsystem basis.
 ****
 ***************************************************************************
 */

/* ARGSUSED */
static void root_conf __P((void *dummy));
static void
root_conf(dummy)
	void *dummy;
{
	cpu_rootconf();
}
SYSINIT(root_conf, SI_SUB_ROOT_CONF, SI_ORDER_FIRST, root_conf, NULL)

/* ARGSUSED*/
static void xxx_vfs_root_fdtab __P((void *dummy));
static void
xxx_vfs_root_fdtab(dummy)
	void *dummy;
{
	register struct filedesc0	*fdp = &filedesc0;

	/* Get the vnode for '/'.  Set fdp->fd_fd.fd_cdir to reference it. */
	if (VFS_ROOT(mountlist.cqh_first, &rootvnode))
		panic("cannot find root vnode");
	fdp->fd_fd.fd_cdir = rootvnode;
	VREF(fdp->fd_fd.fd_cdir);
	VOP_UNLOCK(rootvnode, 0, &proc0);
	fdp->fd_fd.fd_rdir = rootvnode;
}
SYSINIT(retrofit, SI_SUB_ROOT_FDTAB, SI_ORDER_FIRST, xxx_vfs_root_fdtab, NULL)


/*
 ***************************************************************************
 ****
 **** The following code probably belongs in another file, like
 **** kern/init_init.c.  It is here for two reasons only:
 ****
 ****	1)	This code returns to startup the system; this is
 ****		abnormal for a kernel thread.
 ****	2)	This code promiscuously uses init_frame
 ****
 ***************************************************************************
 */

static void kthread_init __P((void *dummy));
SYSINIT_KP(init,SI_SUB_KTHREAD_INIT, SI_ORDER_FIRST, kthread_init, NULL)


extern void prepare_usermode __P((void));
static void start_init __P((struct proc *p));

/* ARGSUSED*/
static void
kthread_init(dummy)
	void *dummy;
{
	/* Create process 1 (init(8)). */
	start_init(curproc);

	prepare_usermode();

	/*
	 * This returns to the fork trampoline, then to user mode.
	 */
	return;	
}


/*
 * List of paths to try when searching for "init".
 */
static char *initpaths[] = {
	"/sbin/init",
	"/sbin/oinit",
	"/sbin/init.bak",
	"/stand/sysinstall",
	NULL,
};

/*
 * Start the initial user process; try exec'ing each pathname in "initpaths".
 * The program is invoked with one argument containing the boot flags.
 */
static void
start_init(p)
	struct proc *p;
{
	vm_offset_t addr;
	struct execve_args args;
	int options, i, error;
	char **pathp, *path, *ucp, **uap, *arg0, *arg1;

	initproc = p;

	/*
	 * Need just enough stack to hold the faked-up "execve()" arguments.
	 */
	addr = trunc_page(VM_MAXUSER_ADDRESS - PAGE_SIZE);
	if (vm_map_find(&p->p_vmspace->vm_map, NULL, 0, &addr, PAGE_SIZE, FALSE, VM_PROT_ALL, VM_PROT_ALL, 0) != 0)
		panic("init: couldn't allocate argument space");
	p->p_vmspace->vm_maxsaddr = (caddr_t)addr;
	p->p_vmspace->vm_ssize = 1;

	for (pathp = &initpaths[0]; (path = *pathp) != NULL; pathp++) {
		/*
		 * Move out the boot flag argument.
		 */
		options = 0;
		ucp = (char *)USRSTACK;
		(void)subyte(--ucp, 0);		/* trailing zero */
		if (boothowto & RB_SINGLE) {
			(void)subyte(--ucp, 's');
			options = 1;
		}
#ifdef notyet
                if (boothowto & RB_FASTBOOT) {
			(void)subyte(--ucp, 'f');
			options = 1;
		}
#endif

#ifdef BOOTCDROM
		(void)subyte(--ucp, 'C');
		options = 1;
#endif
		if (options == 0)
			(void)subyte(--ucp, '-');
		(void)subyte(--ucp, '-');		/* leading hyphen */
		arg1 = ucp;

		/*
		 * Move out the file name (also arg 0).
		 */
		for (i = strlen(path) + 1; i >= 0; i--)
			(void)subyte(--ucp, path[i]);
		arg0 = ucp;

		/*
		 * Move out the arg pointers.
		 */
		uap = (char **)((intptr_t)ucp & ~(sizeof(intptr_t)-1));
		(void)suword((caddr_t)--uap, (long)0);	/* terminator */
		(void)suword((caddr_t)--uap, (long)(intptr_t)arg1);
		(void)suword((caddr_t)--uap, (long)(intptr_t)arg0);

		/*
		 * Point at the arguments.
		 */
		args.fname = arg0;
		args.argv = uap;
		args.envv = NULL;

		/*
		 * Now try to exec the program.  If can't for any reason
		 * other than it doesn't exist, complain.
		 *
		 * Otherwise return to main() which returns to btext
		 * which completes the system startup.
		 */
		if ((error = execve(p, &args)) == 0)
			return;
		if (error != ENOENT)
			printf("exec %s: error %d\n", path, error);
	}
	printf("init: not found\n");
	panic("no init");
}
