/*
 * Copyright (c) 1997, Stefan Esser <se@freebsd.org>
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
 *
 * $FreeBSD$
 *
 */


#include <sys/param.h>
#include <sys/bus.h>
#include <sys/rtprio.h>
#include <sys/systm.h>
#include <sys/ipl.h>
#include <sys/interrupt.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/ktr.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/random.h>
#include <sys/resourcevar.h>
#include <sys/unistd.h>
#include <sys/vmmeter.h>
#include <machine/atomic.h>
#include <machine/cpu.h>
#include <machine/md_var.h>
#include <machine/stdarg.h>

#include <net/netisr.h>		/* prototype for legacy_setsoftnet */

struct	int_entropy {
	struct	proc *proc;
	int	vector;
};

void	*net_ih;
void	*vm_ih;
void	*softclock_ih;
struct	ithd *clk_ithd;
struct	ithd *tty_ithd;

static struct	mtx ithread_list_lock;

static MALLOC_DEFINE(M_ITHREAD, "ithread", "Interrupt Threads");

static void	ithread_update(struct ithd *);
static void	ithread_loop(void *);
static void	ithread_init(void *);
static void	start_softintr(void *);
static void	swi_net(void *);

u_char
ithread_priority(enum intr_type flags)
{
	u_char pri;

	flags &= (INTR_TYPE_TTY | INTR_TYPE_BIO | INTR_TYPE_NET |
	    INTR_TYPE_CAM | INTR_TYPE_MISC | INTR_TYPE_CLK);
	switch (flags) {
	case INTR_TYPE_TTY:
		pri = PI_TTYLOW;
		break;
	case INTR_TYPE_BIO:
		/*
		 * XXX We need to refine this.  BSD/OS distinguishes
		 * between tape and disk priorities.
		 */
		pri = PI_DISK;
		break;
	case INTR_TYPE_NET:
		pri = PI_NET;
		break;
	case INTR_TYPE_CAM:
		pri = PI_DISK;          /* XXX or PI_CAM? */
		break;
	case INTR_TYPE_CLK:
		pri = PI_REALTIME;
		break;
	case INTR_TYPE_MISC:
		pri = PI_DULL;          /* don't care */
		break;
	default:
		/* We didn't specify an interrupt level. */
		panic("ithread_priority: no interrupt type in flags");
	}

	return pri;
}

/*
 * Regenerate the name (p_comm) and priority for a threaded interrupt thread.
 */
static void
ithread_update(struct ithd *ithd)
{
	struct intrhand *ih;
	struct proc *p;
	int entropy;

	p = ithd->it_proc;
	if (p == NULL)
		return;

	strncpy(p->p_comm, ithd->it_name, sizeof(ithd->it_name));
	ih = TAILQ_FIRST(&ithd->it_handlers);
	if (ih == NULL) {
		p->p_pri.pri_level = PRI_MAX_ITHD;
		ithd->it_flags &= ~IT_ENTROPY;
		return;
	}

	entropy = 0;
	p->p_pri.pri_level = ih->ih_pri;
	TAILQ_FOREACH(ih, &ithd->it_handlers, ih_next) {
		if (strlen(p->p_comm) + strlen(ih->ih_name) + 1 <
		    sizeof(p->p_comm)) {
			strcat(p->p_comm, " ");
			strcat(p->p_comm, ih->ih_name);
		} else if (strlen(p->p_comm) + 1 == sizeof(p->p_comm)) {
			if (p->p_comm[sizeof(p->p_comm) - 2] == '+')
				p->p_comm[sizeof(p->p_comm) - 2] = '*';
			else
				p->p_comm[sizeof(p->p_comm) - 2] = '+';
		} else
			strcat(p->p_comm, "+");
		if (ih->ih_flags & IH_ENTROPY)
			entropy++;
	}

	if (entropy)
		ithd->it_flags |= IT_ENTROPY;
	else
		ithd->it_flags &= ~IT_ENTROPY;
	
	CTR1(KTR_INTR, __func__ ": updated %s\n", p->p_comm);
}

int
ithread_create(struct ithd **ithread, int vector, int flags,
    void (*disable)(int), void (*enable)(int), const char *fmt, ...)
{
	struct ithd *ithd;
	struct proc *p;
	int error;
	va_list ap;

	/* The only valid flag during creation is IT_SOFT. */
	if ((flags & ~IT_SOFT) != 0)
		return (EINVAL);

	ithd = malloc(sizeof(struct ithd), M_ITHREAD, M_WAITOK | M_ZERO);
	ithd->it_vector = vector;
	ithd->it_disable = disable;
	ithd->it_enable = enable;
	ithd->it_flags = flags;
	TAILQ_INIT(&ithd->it_handlers);

	va_start(ap, fmt);
	vsnprintf(ithd->it_name, sizeof(ithd->it_name), fmt, ap);
	va_end(ap);

	error = kthread_create(ithread_loop, ithd, &p, RFSTOPPED | RFHIGHPID,
	    ithd->it_name);
	if (error) {
		free(ithd, M_ITHREAD);
		return (error);
	}
	p->p_pri.pri_class = PRI_ITHD;
	p->p_pri.pri_level = PRI_MAX_ITHD;
	p->p_stat = SWAIT;
	ithd->it_proc = p;
	p->p_ithd = ithd;
	if (ithread != NULL)
		*ithread = ithd;

	CTR1(KTR_INTR, __func__ ": created %s", ithd->it_name);
	return (0);
}

int
ithread_destroy(struct ithd *ithread)
{

	if (ithread == NULL || !TAILQ_EMPTY(&ithread->it_handlers))
		return (EINVAL);

	mtx_lock_spin(&sched_lock);
	ithread->it_flags |= IT_DEAD;
	if (ithread->it_proc->p_stat == SWAIT) {
		ithread->it_proc->p_stat = SRUN;
		setrunqueue(ithread->it_proc);
	}
	mtx_unlock_spin(&sched_lock);
	CTR1(KTR_INTR, __func__ ": killing %s", ithread->it_name);
	return (0);
}

int
ithread_add_handler(struct ithd* ithread, const char *name,
    driver_intr_t handler, void *arg, u_char pri, enum intr_type flags,
    void **cookiep)
{
	struct intrhand *ih, *temp_ih;

	if (ithread == NULL || name == NULL || handler == NULL)
		return (EINVAL);
	if ((flags & INTR_FAST) !=0)
		flags |= INTR_EXCL;

	ih = malloc(sizeof(struct intrhand), M_ITHREAD, M_WAITOK | M_ZERO);
	ih->ih_handler = handler;
	ih->ih_argument = arg;
	ih->ih_name = name;
	ih->ih_ithread = ithread;
	ih->ih_pri = pri;
	if (flags & INTR_FAST)
		ih->ih_flags = IH_FAST | IH_EXCLUSIVE;
	else if (flags & INTR_EXCL)
		ih->ih_flags = IH_EXCLUSIVE;
	if (flags & INTR_MPSAFE)
		ih->ih_flags |= IH_MPSAFE;
	if (flags & INTR_ENTROPY)
		ih->ih_flags |= IH_ENTROPY;

	mtx_lock_spin(&ithread_list_lock);
	if ((flags & INTR_EXCL) !=0 && !TAILQ_EMPTY(&ithread->it_handlers))
		goto fail;
	if (!TAILQ_EMPTY(&ithread->it_handlers) &&
	    (TAILQ_FIRST(&ithread->it_handlers)->ih_flags & IH_EXCLUSIVE) != 0)
		goto fail;

	TAILQ_FOREACH(temp_ih, &ithread->it_handlers, ih_next)
	    if (temp_ih->ih_pri > ih->ih_pri)
		    break;
	if (temp_ih == NULL)
		TAILQ_INSERT_TAIL(&ithread->it_handlers, ih, ih_next);
	else
		TAILQ_INSERT_BEFORE(temp_ih, ih, ih_next);
	ithread_update(ithread);
	mtx_unlock_spin(&ithread_list_lock);

	if (cookiep != NULL)
		*cookiep = ih;
	CTR2(KTR_INTR, __func__ ": added %s to %s", ih->ih_name,
	    ithread->it_name);
	return (0);

fail:
	mtx_unlock_spin(&ithread_list_lock);
	free(ih, M_ITHREAD);
	return (EINVAL);
}

int
ithread_remove_handler(void *cookie)
{
	struct intrhand *handler = (struct intrhand *)cookie;
	struct ithd *ithread;
#ifdef INVARIANTS
	struct intrhand *ih;
#endif

	if (handler == NULL)
		return (EINVAL);
	ithread = handler->ih_ithread;
	KASSERT(ithread != NULL,
	    ("interrupt handler \"%s\" has a NULL interrupt thread",
		handler->ih_name));
	CTR2(KTR_INTR, __func__ ": removing %s from %s", handler->ih_name,
	    ithread->it_name);
	mtx_lock_spin(&ithread_list_lock);
#ifdef INVARIANTS
	TAILQ_FOREACH(ih, &ithread->it_handlers, ih_next)
		if (ih == handler)
			goto ok;
	mtx_unlock_spin(&ithread_list_lock);
	panic("interrupt handler \"%s\" not found in interrupt thread \"%s\"",
	    ih->ih_name, ithread->it_name);
ok:
#endif
	/*
	 * If the interrupt thread is already running, then just mark this
	 * handler as being dead and let the ithread do the actual removal.
	 */
	mtx_lock_spin(&sched_lock);
	if (ithread->it_proc->p_stat != SWAIT) {
		handler->ih_flags |= IH_DEAD;

		/*
		 * Ensure that the thread will process the handler list
		 * again and remove this handler if it has already passed
		 * it on the list.
		 */
		ithread->it_need = 1;
	} else {
		TAILQ_REMOVE(&ithread->it_handlers, handler, ih_next);
		ithread_update(ithread);
	}
	mtx_unlock_spin(&sched_lock);
	mtx_unlock_spin(&ithread_list_lock);

	if ((handler->ih_flags & IH_DEAD) == 0)
		free(handler, M_ITHREAD);
	return (0);
}

int
ithread_schedule(struct ithd *ithread, int do_switch)
{
	struct int_entropy entropy;
	struct proc *p;
	intrmask_t saveintr;

	/*
	 * If no ithread or no handlers, then we have a stray interrupt.
	 */
	if ((ithread == NULL) || TAILQ_EMPTY(&ithread->it_handlers))
		return (EINVAL);

	/*
	 * If any of the handlers for this ithread claim to be good
	 * sources of entropy, then gather some.
	 */
	if (harvest.interrupt && ithread->it_flags & IT_ENTROPY) {
		entropy.vector = ithread->it_vector;
		entropy.proc = CURPROC;
		random_harvest(&entropy, sizeof(entropy), 2, 0,
		    RANDOM_INTERRUPT);
	}

	p = ithread->it_proc;
	CTR3(KTR_INTR, __func__ ": pid %d: (%s) need = %d", p->p_pid, p->p_comm,
	    ithread->it_need);

	/*
	 * Set it_need to tell the thread to keep running if it is already
	 * running.  Then, grab sched_lock and see if we actually need to
	 * put this thread on the runqueue.  If so and the do_switch flag is
	 * true, then switch to the ithread immediately.  Otherwise, use
	 * need_resched() to guarantee that this ithread will run before any
	 * userland processes.
	 */
	ithread->it_need = 1;
	mtx_lock_spin(&sched_lock);
	if (p->p_stat == SWAIT) {
		CTR1(KTR_INTR, __func__ ": setrunqueue %d", p->p_pid);
		p->p_stat = SRUN;
		setrunqueue(p);
		if (do_switch) {
			saveintr = sched_lock.mtx_saveintr;
			mtx_intr_enable(&sched_lock);
			if (curproc != PCPU_GET(idleproc))
				setrunqueue(curproc);
			curproc->p_stats->p_ru.ru_nvcsw++;
			mi_switch();
			sched_lock.mtx_saveintr = saveintr;
		} else
			need_resched();
	} else {
		CTR3(KTR_INTR, __func__ ": pid %d: it_need %d, state %d",
		    p->p_pid, ithread->it_need, p->p_stat);
	}
	mtx_unlock_spin(&sched_lock);

	return (0);
}

int
swi_add(struct ithd **ithdp, const char *name, driver_intr_t handler, 
	    void *arg, int pri, enum intr_type flags, void **cookiep)
{
	struct ithd *ithd;
	int error;

	if (flags & (INTR_FAST | INTR_ENTROPY))
		return (EINVAL);

	ithd = (ithdp != NULL) ? *ithdp : NULL;

	if (ithd != NULL) {
		if ((ithd->it_flags & IT_SOFT) == 0)
			return(EINVAL);
	} else {
		error = ithread_create(&ithd, pri, IT_SOFT, NULL, NULL,
		    "swi%d:", pri);
		if (error)
			return (error);

		if (ithdp != NULL)
			*ithdp = ithd;
	}
	return (ithread_add_handler(ithd, name, handler, arg,
		    (pri * RQ_PPQ) + PI_SOFT, flags, cookiep));
}


/*
 * Schedule a heavyweight software interrupt process. 
 */
void
swi_sched(void *cookie, int flags)
{
	struct intrhand *ih = (struct intrhand *)cookie;
	struct ithd *it = ih->ih_ithread;
	int error;

	atomic_add_int(&cnt.v_intr, 1); /* one more global interrupt */
		
	CTR3(KTR_INTR, "swi_sched pid %d(%s) need=%d",
		it->it_proc->p_pid, it->it_proc->p_comm, it->it_need);

	/*
	 * Set ih_need for this handler so that if the ithread is already
	 * running it will execute this handler on the next pass.  Otherwise,
	 * it will execute it the next time it runs.
	 */
	atomic_store_rel_int(&ih->ih_need, 1);
	if (!(flags & SWI_DELAY)) {
		error = ithread_schedule(it, !cold && flags & SWI_SWITCH);
		KASSERT(error == 0, ("stray software interrupt"));
	}
}

/*
 * This is the main code for interrupt threads.
 */
void
ithread_loop(void *arg)
{
	struct ithd *ithd;		/* our thread context */
	struct intrhand *ih;		/* and our interrupt handler chain */
	struct proc *p;
	
	p = curproc;
	ithd = (struct ithd *)arg;	/* point to myself */
	KASSERT(ithd->it_proc == p && p->p_ithd == ithd,
	    (__func__ ": ithread and proc linkage out of sync"));

	/*
	 * As long as we have interrupts outstanding, go through the
	 * list of handlers, giving each one a go at it.
	 */
	for (;;) {
		/*
		 * If we are an orphaned thread, then just die.
		 */
		if (ithd->it_flags & IT_DEAD) {
			CTR2(KTR_INTR, __func__ ": pid %d: (%s) exiting",
			    p->p_pid, p->p_comm);
			p->p_ithd = NULL;
			mtx_lock(&Giant);
			free(ithd, M_ITHREAD);
			kthread_exit(0);
		}

		CTR3(KTR_INTR, __func__ ": pid %d: (%s) need=%d",
		     p->p_pid, p->p_comm, ithd->it_need);
		while (ithd->it_need) {
			/*
			 * Service interrupts.  If another interrupt
			 * arrives while we are running, they will set
			 * it_need to denote that we should make
			 * another pass.
			 */
			atomic_store_rel_int(&ithd->it_need, 0);
restart:
			TAILQ_FOREACH(ih, &ithd->it_handlers, ih_next) {
				if (ithd->it_flags & IT_SOFT && !ih->ih_need)
					continue;
				atomic_store_rel_int(&ih->ih_need, 0);
				CTR5(KTR_INTR,
				    __func__ ": pid %d ih=%p: %p(%p) flg=%x",
				    p->p_pid, (void *)ih,
				    (void *)ih->ih_handler, ih->ih_argument,
				    ih->ih_flags);

				if ((ih->ih_flags & IH_MPSAFE) == 0)
					mtx_lock(&Giant);
				if ((ih->ih_flags & IH_DEAD) != 0) {
					mtx_lock_spin(&ithread_list_lock);
					TAILQ_REMOVE(&ithd->it_handlers, ih,
					    ih_next);
					ithread_update(ithd);
					mtx_unlock_spin(&ithread_list_lock);
					if (!mtx_owned(&Giant))
						mtx_lock(&Giant);
					free(ih, M_ITHREAD);
					mtx_unlock(&Giant);
					goto restart;
				}
				ih->ih_handler(ih->ih_argument);
				if ((ih->ih_flags & IH_MPSAFE) == 0)
					mtx_unlock(&Giant);
			}
		}

		/*
		 * Processed all our interrupts.  Now get the sched
		 * lock.  This may take a while and it_need may get
		 * set again, so we have to check it again.
		 */
		mtx_assert(&Giant, MA_NOTOWNED);
		mtx_lock_spin(&sched_lock);
		if (!ithd->it_need) {
			/*
			 * Should we call this earlier in the loop above?
			 */
			if (ithd->it_enable != NULL)
				ithd->it_enable(ithd->it_vector);
			p->p_stat = SWAIT; /* we're idle */
			CTR1(KTR_INTR, __func__ ": pid %d: done", p->p_pid);
			mi_switch();
			CTR1(KTR_INTR, __func__ ": pid %d: resumed", p->p_pid);
		}
		mtx_unlock_spin(&sched_lock);
	}
}

/*
 * Initialize mutex used to protect ithread handler lists.
 */
static void
ithread_init(void *dummy)
{

	mtx_init(&ithread_list_lock, "ithread list lock", MTX_SPIN);
}
SYSINIT(ithread_init, SI_SUB_INTR, SI_ORDER_FIRST, ithread_init, NULL);

/*
 * Start standard software interrupt threads
 */
static void
start_softintr(void *dummy)
{

	if (swi_add(NULL, "net", swi_net, NULL, SWI_NET, 0, &net_ih) ||
	    swi_add(&clk_ithd, "clock", softclock, NULL, SWI_CLOCK,
		INTR_MPSAFE, &softclock_ih) ||
	    swi_add(NULL, "vm", swi_vm, NULL, SWI_VM, 0, &vm_ih))
		panic("died while creating standard software ithreads");

	PROC_LOCK(clk_ithd->it_proc);
	clk_ithd->it_proc->p_flag |= P_NOLOAD;
	PROC_UNLOCK(clk_ithd->it_proc);
}
SYSINIT(start_softintr, SI_SUB_SOFTINTR, SI_ORDER_FIRST, start_softintr, NULL)

void
legacy_setsoftnet(void)
{
	swi_sched(net_ih, SWI_NOSWITCH);
}

/*
 * XXX: This should really be in the network code somewhere and installed
 * via a SI_SUB_SOFINTR, SI_ORDER_MIDDLE sysinit.
 */
void	(*netisrs[32]) __P((void));
u_int	netisr;

int
register_netisr(num, handler)
	int num;
	netisr_t *handler;
{
	
	if (num < 0 || num >= (sizeof(netisrs)/sizeof(*netisrs)) ) {
		printf("register_netisr: bad isr number: %d\n", num);
		return (EINVAL);
	}
	netisrs[num] = handler;
	return (0);
}

int
unregister_netisr(num)
	int num;
{
	
	if (num < 0 || num >= (sizeof(netisrs)/sizeof(*netisrs)) ) {
		printf("unregister_netisr: bad isr number: %d\n", num);
		return (EINVAL);
	}
	netisrs[num] = NULL;
	return (0);
}

static void
swi_net(void *dummy)
{
	u_int bits;
	int i;

	bits = atomic_readandclear_int(&netisr);
	while ((i = ffs(bits)) != 0) {
		i--;
		if (netisrs[i] != NULL)
			netisrs[i]();
		else
			printf("swi_net: unregistered isr number: %d.\n", i);
		bits &= ~(1 << i);
	}
}
