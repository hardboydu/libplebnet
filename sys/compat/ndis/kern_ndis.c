/*
 * Copyright (c) 2003
 *	Bill Paul <wpaul@windriver.com>.  All rights reserved.
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
 *	This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/unistd.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/callout.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/conf.h>

#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/kthread.h>
#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/bus.h>
#include <sys/rman.h>

#include <vm/uma.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_ioctl.h>

#include <compat/ndis/pe_var.h>
#include <compat/ndis/resource_var.h>
#include <compat/ndis/ntoskrnl_var.h>
#include <compat/ndis/ndis_var.h>
#include <compat/ndis/hal_var.h>
#include <compat/ndis/cfg_var.h>
#include <dev/if_ndis/if_ndisvar.h>

#define NDIS_DUMMY_PATH "\\\\some\\bogus\\path"

__stdcall static void ndis_status_func(ndis_handle, ndis_status,
	void *, uint32_t);
__stdcall static void ndis_statusdone_func(ndis_handle);
__stdcall static void ndis_setdone_func(ndis_handle, ndis_status);
__stdcall static void ndis_getdone_func(ndis_handle, ndis_status);
__stdcall static void ndis_resetdone_func(ndis_handle, ndis_status, uint8_t);
__stdcall static void ndis_sendrsrcavail_func(ndis_handle);

struct nd_head ndis_devhead;

struct ndis_req {
	void			(*nr_func)(void *);
	void			*nr_arg;
	int			nr_exit;
	STAILQ_ENTRY(ndis_req)	link;
};

struct ndisproc {
	struct ndisqhead	*np_q;
	struct proc		*np_p;
	int			np_state;
};

static void ndis_return(void *);
static int ndis_create_kthreads(void);
static void ndis_destroy_kthreads(void);
static void ndis_stop_thread(int);
static int ndis_enlarge_thrqueue(int);
static int ndis_shrink_thrqueue(int);
static void ndis_runq(void *);

static uma_zone_t ndis_packet_zone, ndis_buffer_zone;
struct mtx ndis_thr_mtx;
static STAILQ_HEAD(ndisqhead, ndis_req) ndis_ttodo;
struct ndisqhead ndis_itodo;
struct ndisqhead ndis_free;
static int ndis_jobs = 32;

static struct ndisproc ndis_tproc;
static struct ndisproc ndis_iproc;

/*
 * This allows us to export our symbols to other modules.
 * Note that we call ourselves 'ndisapi' to avoid a namespace
 * collision with if_ndis.ko, which internally calls itself
 * 'ndis.'
 */
static int
ndis_modevent(module_t mod, int cmd, void *arg)
{
	int			error = 0;

	switch (cmd) {
	case MOD_LOAD:
		/* Initialize subsystems */
		ndis_libinit();
		ntoskrnl_libinit();

		/* Initialize TX buffer UMA zone. */
		ndis_packet_zone = uma_zcreate("NDIS packet",
		    sizeof(ndis_packet), NULL, NULL, NULL,
		    NULL, UMA_ALIGN_PTR, 0);
		ndis_buffer_zone = uma_zcreate("NDIS buffer",
		    sizeof(ndis_buffer), NULL, NULL, NULL,
		    NULL, UMA_ALIGN_PTR, 0);

		ndis_create_kthreads();

		TAILQ_INIT(&ndis_devhead);

		break;
	case MOD_SHUTDOWN:
		/* stop kthreads */
		ndis_destroy_kthreads();
		if (TAILQ_FIRST(&ndis_devhead) == NULL) {
			/* Shut down subsystems */
			ndis_libfini();
			ntoskrnl_libfini();

			/* Remove zones */
			uma_zdestroy(ndis_packet_zone);
			uma_zdestroy(ndis_buffer_zone);
		}
		break;
	case MOD_UNLOAD:
		/* stop kthreads */
		ndis_destroy_kthreads();

		/* Shut down subsystems */
		ndis_libfini();
		ntoskrnl_libfini();

		/* Remove zones */
		uma_zdestroy(ndis_packet_zone);
		uma_zdestroy(ndis_buffer_zone);
		break;
	default:
		error = EINVAL;
		break;
	}

	return(error);
}
DEV_MODULE(ndisapi, ndis_modevent, NULL);
MODULE_VERSION(ndisapi, 1);

/*
 * We create two kthreads for the NDIS subsystem. One of them is a task
 * queue for performing various odd jobs. The other is an swi thread
 * reserved exclusively for running interrupt handlers. The reason we
 * have our own task queue is that there are some cases where we may
 * need to sleep for a significant amount of time, and if we were to
 * use one of the taskqueue threads, we might delay the processing
 * of other pending tasks which might need to run right away. We have
 * a separate swi thread because we don't want our interrupt handling
 * to be delayed either.
 *
 * By default there are 32 jobs available to start, and another 8
 * are added to the free list each time a new device is created.
 */

static void
ndis_runq(arg)
	void			*arg;
{
	struct ndis_req		*r = NULL, *die = NULL;
	struct ndisproc		*p;

	p = arg;

	while (1) {

		/* Sleep, but preserve our original priority. */
		ndis_thsuspend(p->np_p, 0);

		/* Look for any jobs on the work queue. */

		mtx_lock(&ndis_thr_mtx);
		p->np_state = NDIS_PSTATE_RUNNING;
		while(STAILQ_FIRST(p->np_q) != NULL) {
			r = STAILQ_FIRST(p->np_q);
			STAILQ_REMOVE_HEAD(p->np_q, link);
			mtx_unlock(&ndis_thr_mtx);

			/* Do the work. */

			if (r->nr_func != NULL)
				(*r->nr_func)(r->nr_arg);

			mtx_lock(&ndis_thr_mtx);
			STAILQ_INSERT_HEAD(&ndis_free, r, link);

			/* Check for a shutdown request */

			if (r->nr_exit == TRUE)
				die = r;
		}
		p->np_state = NDIS_PSTATE_SLEEPING;
		mtx_unlock(&ndis_thr_mtx);

		/* Bail if we were told to shut down. */

		if (die != NULL)
			break;
	}

	wakeup(die);
#if __FreeBSD_version < 502113
	mtx_lock(&Giant);
#endif
	kthread_exit(0);
	return; /* notreached */
}

static int
ndis_create_kthreads()
{
	struct ndis_req		*r;
	int			i, error = 0;

	mtx_init(&ndis_thr_mtx, "NDIS thread lock",
	   MTX_NDIS_LOCK, MTX_DEF);

	STAILQ_INIT(&ndis_ttodo);
	STAILQ_INIT(&ndis_itodo);
	STAILQ_INIT(&ndis_free);

	for (i = 0; i < ndis_jobs; i++) {
		r = malloc(sizeof(struct ndis_req), M_DEVBUF, M_WAITOK);
		if (r == NULL) {
			error = ENOMEM;
			break;
		}
		STAILQ_INSERT_HEAD(&ndis_free, r, link);
	}

	if (error == 0) {
		ndis_tproc.np_q = &ndis_ttodo;
		ndis_tproc.np_state = NDIS_PSTATE_SLEEPING;
		error = kthread_create(ndis_runq, &ndis_tproc,
		    &ndis_tproc.np_p, RFHIGHPID,
		    NDIS_KSTACK_PAGES, "ndis taskqueue");
	}

	if (error == 0) {
		ndis_iproc.np_q = &ndis_itodo;
		ndis_iproc.np_state = NDIS_PSTATE_SLEEPING;
		error = kthread_create(ndis_runq, &ndis_iproc,
		    &ndis_iproc.np_p, RFHIGHPID,
		    NDIS_KSTACK_PAGES, "ndis swi");
	}

	if (error) {
		while ((r = STAILQ_FIRST(&ndis_free)) != NULL) {
			STAILQ_REMOVE_HEAD(&ndis_free, link);
			free(r, M_DEVBUF);
		}
		return(error);
	}

	return(0);
}

static void
ndis_destroy_kthreads()
{
	struct ndis_req		*r;

	/* Stop the threads. */

	ndis_stop_thread(NDIS_TASKQUEUE);
	ndis_stop_thread(NDIS_SWI);

	/* Destroy request structures. */

	while ((r = STAILQ_FIRST(&ndis_free)) != NULL) {
		STAILQ_REMOVE_HEAD(&ndis_free, link);
		free(r, M_DEVBUF);
	}

	mtx_destroy(&ndis_thr_mtx);

	return;
}

static void
ndis_stop_thread(t)
	int			t;
{
	struct ndis_req		*r;
	struct ndisqhead	*q;
	struct proc		*p;

	if (t == NDIS_TASKQUEUE) {
		q = &ndis_ttodo;
		p = ndis_tproc.np_p;
	} else {
		q = &ndis_itodo;
		p = ndis_iproc.np_p;
	}

	/* Create and post a special 'exit' job. */

	mtx_lock(&ndis_thr_mtx);
	r = STAILQ_FIRST(&ndis_free);
	STAILQ_REMOVE_HEAD(&ndis_free, link);
	r->nr_func = NULL;
	r->nr_arg = NULL;
	r->nr_exit = TRUE;
	STAILQ_INSERT_TAIL(q, r, link);
	mtx_unlock(&ndis_thr_mtx);

	ndis_thresume(p);

	/* wait for thread exit */

	tsleep(r, curthread->td_priority|PCATCH, "ndisthexit", hz * 60);

	/* Now empty the job list. */

	mtx_lock(&ndis_thr_mtx);
	while ((r = STAILQ_FIRST(q)) != NULL) {
		STAILQ_REMOVE_HEAD(q, link);
		STAILQ_INSERT_HEAD(&ndis_free, r, link);
	}
	mtx_unlock(&ndis_thr_mtx);

	return;
}

static int
ndis_enlarge_thrqueue(cnt)
	int			cnt;
{
	struct ndis_req		*r;
	int			i;

	for (i = 0; i < cnt; i++) {
		r = malloc(sizeof(struct ndis_req), M_DEVBUF, M_WAITOK);
		if (r == NULL)
			return(ENOMEM);
		mtx_lock(&ndis_thr_mtx);
		STAILQ_INSERT_HEAD(&ndis_free, r, link);
		ndis_jobs++;
		mtx_unlock(&ndis_thr_mtx);
	}

	return(0);
}

static int
ndis_shrink_thrqueue(cnt)
	int			cnt;
{
	struct ndis_req		*r;
	int			i;

	for (i = 0; i < cnt; i++) {
		mtx_lock(&ndis_thr_mtx);
		r = STAILQ_FIRST(&ndis_free);
		if (r == NULL) {
			mtx_unlock(&ndis_thr_mtx);
			return(ENOMEM);
		}
		STAILQ_REMOVE_HEAD(&ndis_free, link);
		ndis_jobs--;
		mtx_unlock(&ndis_thr_mtx);
		free(r, M_DEVBUF);
	}

	return(0);
}

int
ndis_unsched(func, arg, t)
	void			(*func)(void *);
	void			*arg;
	int			t;
{
	struct ndis_req		*r;
	struct ndisqhead	*q;
	struct proc		*p;

	if (t == NDIS_TASKQUEUE) {
		q = &ndis_ttodo;
		p = ndis_tproc.np_p;
	} else {
		q = &ndis_itodo;
		p = ndis_iproc.np_p;
	}

	mtx_lock(&ndis_thr_mtx);
	STAILQ_FOREACH(r, q, link) {
		if (r->nr_func == func && r->nr_arg == arg) {
			STAILQ_REMOVE(q, r, ndis_req, link);
			STAILQ_INSERT_HEAD(&ndis_free, r, link);
			mtx_unlock(&ndis_thr_mtx);
			return(0);
		}
	}

	mtx_unlock(&ndis_thr_mtx);

	return(ENOENT);
}

int
ndis_sched(func, arg, t)
	void			(*func)(void *);
	void			*arg;
	int			t;
{
	struct ndis_req		*r;
	struct ndisqhead	*q;
	struct proc		*p;
	int			s;

	if (t == NDIS_TASKQUEUE) {
		q = &ndis_ttodo;
		p = ndis_tproc.np_p;
	} else {
		q = &ndis_itodo;
		p = ndis_iproc.np_p;
	}

	mtx_lock(&ndis_thr_mtx);
	/*
	 * Check to see if an instance of this job is already
	 * pending. If so, don't bother queuing it again.
	 */
	STAILQ_FOREACH(r, q, link) {
		if (r->nr_func == func && r->nr_arg == arg) {
			mtx_unlock(&ndis_thr_mtx);
			return(0);
		}
	}
	r = STAILQ_FIRST(&ndis_free);
	if (r == NULL) {
		mtx_unlock(&ndis_thr_mtx);
		return(EAGAIN);
	}
	STAILQ_REMOVE_HEAD(&ndis_free, link);
	r->nr_func = func;
	r->nr_arg = arg;
	r->nr_exit = FALSE;
	STAILQ_INSERT_TAIL(q, r, link);
	if (t == NDIS_TASKQUEUE)
		s = ndis_tproc.np_state;
	else
		s = ndis_iproc.np_state;
	mtx_unlock(&ndis_thr_mtx);

	/*
	 * Post the job, but only if the thread is actually blocked
	 * on its own suspend call. If a driver queues up a job with
	 * NdisScheduleWorkItem() which happens to do a KeWaitForObject(),
	 * it may suspend there, and in that case we don't want to wake
	 * it up until KeWaitForObject() gets woken up on its own.
	 */
	if (s == NDIS_PSTATE_SLEEPING)
		ndis_thresume(p);

	return(0);
}

int
ndis_thsuspend(p, timo)
	struct proc		*p;
	int			timo;
{
	int			error;

	PROC_LOCK(p);
	error = msleep(&p->p_siglist, &p->p_mtx,
	    curthread->td_priority|PDROP, "ndissp", timo);
	return(error);
}

void
ndis_thresume(p)
	struct proc		*p;
{
	wakeup(&p->p_siglist);
	return;
}

__stdcall static void
ndis_sendrsrcavail_func(adapter)
	ndis_handle		adapter;
{
	return;
}

__stdcall static void
ndis_status_func(adapter, status, sbuf, slen)
	ndis_handle		adapter;
	ndis_status		status;
	void			*sbuf;
	uint32_t		slen;
{
	ndis_miniport_block	*block;
	block = adapter;

	if (block->nmb_ifp->if_flags & IFF_DEBUG)
		device_printf (block->nmb_dev, "status: %x\n", status);
	return;
}

__stdcall static void
ndis_statusdone_func(adapter)
	ndis_handle		adapter;
{
	ndis_miniport_block	*block;
	block = adapter;
	
	if (block->nmb_ifp->if_flags & IFF_DEBUG)
		device_printf (block->nmb_dev, "status complete\n");
	return;
}

__stdcall static void
ndis_setdone_func(adapter, status)
	ndis_handle		adapter;
	ndis_status		status;
{
	ndis_miniport_block	*block;
	block = adapter;

	block->nmb_setstat = status;
	wakeup(&block->nmb_wkupdpctimer);
	return;
}

__stdcall static void
ndis_getdone_func(adapter, status)
	ndis_handle		adapter;
	ndis_status		status;
{
	ndis_miniport_block	*block;
	block = adapter;

	block->nmb_getstat = status;
	wakeup(&block->nmb_wkupdpctimer);
	return;
}

__stdcall static void
ndis_resetdone_func(adapter, status, addressingreset)
	ndis_handle		adapter;
	ndis_status		status;
	uint8_t			addressingreset;
{
	ndis_miniport_block	*block;
	block = adapter;

	if (block->nmb_ifp->if_flags & IFF_DEBUG)
		device_printf (block->nmb_dev, "reset done...\n");
	wakeup(block->nmb_ifp);
	return;
}

int
ndis_create_sysctls(arg)
	void			*arg;
{
	struct ndis_softc	*sc;
	ndis_cfg		*vals;
	char			buf[256];
	struct sysctl_oid	*oidp;
	struct sysctl_ctx_entry	*e;

	if (arg == NULL)
		return(EINVAL);

	sc = arg;
	vals = sc->ndis_regvals;

	TAILQ_INIT(&sc->ndis_cfglist_head);

#if __FreeBSD_version < 502113
	/* Create the sysctl tree. */

	sc->ndis_tree = SYSCTL_ADD_NODE(&sc->ndis_ctx,
	    SYSCTL_STATIC_CHILDREN(_hw), OID_AUTO,
	    device_get_nameunit(sc->ndis_dev), CTLFLAG_RD, 0,
	    device_get_desc(sc->ndis_dev));

#endif
	/* Add the driver-specific registry keys. */

	vals = sc->ndis_regvals;
	while(1) {
		if (vals->nc_cfgkey == NULL)
			break;
		if (vals->nc_idx != sc->ndis_devidx) {
			vals++;
			continue;
		}

		/* See if we already have a sysctl with this name */

		oidp = NULL;
#if __FreeBSD_version < 502113
		TAILQ_FOREACH(e, &sc->ndis_ctx, link) {
#else
		TAILQ_FOREACH(e, device_get_sysctl_ctx(sc->ndis_dev), link) {
#endif
                	oidp = e->entry;
			if (ndis_strcasecmp(oidp->oid_name,
			    vals->nc_cfgkey) == 0)
				break;
			oidp = NULL;
		}

		if (oidp != NULL) {
			vals++;
			continue;
		}

#if __FreeBSD_version < 502113
		SYSCTL_ADD_STRING(&sc->ndis_ctx,
		    SYSCTL_CHILDREN(sc->ndis_tree),
#else
		SYSCTL_ADD_STRING(device_get_sysctl_ctx(sc->ndis_dev),
		    SYSCTL_CHILDREN(device_get_sysctl_tree(sc->ndis_dev)),
#endif
		    OID_AUTO, vals->nc_cfgkey,
		    CTLFLAG_RW, vals->nc_val,
		    sizeof(vals->nc_val),
		    vals->nc_cfgdesc);
		vals++;
	}

	/* Now add a couple of builtin keys. */

	/*
	 * Environment can be either Windows (0) or WindowsNT (1).
	 * We qualify as the latter.
	 */
	ndis_add_sysctl(sc, "Environment",
	    "Windows environment", "1", CTLFLAG_RD);

	/* NDIS version should be 5.1. */
	ndis_add_sysctl(sc, "NdisVersion",
	    "NDIS API Version", "0x00050001", CTLFLAG_RD);

	/* Bus type (PCI, PCMCIA, etc...) */
	sprintf(buf, "%d", (int)sc->ndis_iftype);
	ndis_add_sysctl(sc, "BusType", "Bus Type", buf, CTLFLAG_RD);

	if (sc->ndis_res_io != NULL) {
		sprintf(buf, "0x%lx", rman_get_start(sc->ndis_res_io));
		ndis_add_sysctl(sc, "IOBaseAddress",
		    "Base I/O Address", buf, CTLFLAG_RD);
	}

	if (sc->ndis_irq != NULL) {
		sprintf(buf, "%lu", rman_get_start(sc->ndis_irq));
		ndis_add_sysctl(sc, "InterruptNumber",
		    "Interrupt Number", buf, CTLFLAG_RD);
	}

	return(0);
}

int
ndis_add_sysctl(arg, key, desc, val, flag)
	void			*arg;
	char			*key;
	char			*desc;
	char			*val;
	int			flag;
{
	struct ndis_softc	*sc;
	struct ndis_cfglist	*cfg;
	char			descstr[256];

	sc = arg;

	cfg = malloc(sizeof(struct ndis_cfglist), M_DEVBUF, M_NOWAIT|M_ZERO);

	if (cfg == NULL)
		return(ENOMEM);

	cfg->ndis_cfg.nc_cfgkey = strdup(key, M_DEVBUF);
	if (desc == NULL) {
		snprintf(descstr, sizeof(descstr), "%s (dynamic)", key);
		cfg->ndis_cfg.nc_cfgdesc = strdup(descstr, M_DEVBUF);
	} else
		cfg->ndis_cfg.nc_cfgdesc = strdup(desc, M_DEVBUF);
	strcpy(cfg->ndis_cfg.nc_val, val);

	TAILQ_INSERT_TAIL(&sc->ndis_cfglist_head, cfg, link);

#if __FreeBSD_version < 502113
	SYSCTL_ADD_STRING(&sc->ndis_ctx, SYSCTL_CHILDREN(sc->ndis_tree),
#else
	SYSCTL_ADD_STRING(device_get_sysctl_ctx(sc->ndis_dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(sc->ndis_dev)),
#endif
	    OID_AUTO, cfg->ndis_cfg.nc_cfgkey, flag,
	    cfg->ndis_cfg.nc_val, sizeof(cfg->ndis_cfg.nc_val),
	    cfg->ndis_cfg.nc_cfgdesc);

	return(0);
}

int
ndis_flush_sysctls(arg)
	void			*arg;
{
	struct ndis_softc	*sc;
	struct ndis_cfglist	*cfg;

	sc = arg;

	while (!TAILQ_EMPTY(&sc->ndis_cfglist_head)) {
		cfg = TAILQ_FIRST(&sc->ndis_cfglist_head);
		TAILQ_REMOVE(&sc->ndis_cfglist_head, cfg, link);
		free(cfg->ndis_cfg.nc_cfgkey, M_DEVBUF);
		free(cfg->ndis_cfg.nc_cfgdesc, M_DEVBUF);
		free(cfg, M_DEVBUF);
	}

	return(0);
}

static void
ndis_return(arg)
	void			*arg;
{
	struct ndis_softc	*sc;
	__stdcall ndis_return_handler	returnfunc;
	ndis_handle		adapter;
	ndis_packet		*p;
	uint8_t			irql;

	p = arg;
	sc = p->np_softc;
	adapter = sc->ndis_block.nmb_miniportadapterctx;

	if (adapter == NULL)
		return;

	returnfunc = sc->ndis_chars.nmc_return_packet_func;
	irql = ntoskrnl_raise_irql(DISPATCH_LEVEL);
	returnfunc(adapter, p);
	ntoskrnl_lower_irql(irql);

	return;
}

void
ndis_return_packet(buf, arg)
	void			*buf;	/* not used */
	void			*arg;
{
	ndis_packet		*p;

	if (arg == NULL)
		return;

	p = arg;

	/* Decrement refcount. */
	p->np_refcnt--;

	/* Release packet when refcount hits zero, otherwise return. */
	if (p->np_refcnt)
		return;

	ndis_sched(ndis_return, p, NDIS_SWI);

	return;
}

void
ndis_free_bufs(b0)
	ndis_buffer		*b0;
{
	ndis_buffer		*next;

	if (b0 == NULL)
		return;

	while(b0 != NULL) {
		next = b0->nb_next;
		uma_zfree (ndis_buffer_zone, b0);
		b0 = next;
	}

	return;
}

void
ndis_free_packet(p)
	ndis_packet		*p;
{
	if (p == NULL)
		return;

	ndis_free_bufs(p->np_private.npp_head);
	uma_zfree(ndis_packet_zone, p);

	return;
}

int
ndis_convert_res(arg)
	void			*arg;
{
	struct ndis_softc	*sc;
	ndis_resource_list	*rl = NULL;
	cm_partial_resource_desc	*prd = NULL;
	ndis_miniport_block	*block;
	device_t		dev;
	struct resource_list	*brl;
	struct resource_list	brl_rev;
	struct resource_list_entry	*brle, *n;
	int 			error = 0;

	sc = arg;
	block = &sc->ndis_block;
	dev = sc->ndis_dev;

	SLIST_INIT(&brl_rev);

	rl = malloc(sizeof(ndis_resource_list) +
	    (sizeof(cm_partial_resource_desc) * (sc->ndis_rescnt - 1)),
	    M_DEVBUF, M_NOWAIT|M_ZERO);

	if (rl == NULL)
		return(ENOMEM);

	rl->cprl_version = 5;
	rl->cprl_version = 1;
	rl->cprl_count = sc->ndis_rescnt;
	prd = rl->cprl_partial_descs;

	brl = BUS_GET_RESOURCE_LIST(dev, dev);

	if (brl != NULL) {

		/*
		 * We have a small problem. Some PCI devices have
		 * multiple I/O ranges. Windows orders them starting
		 * from lowest numbered BAR to highest. We discover
		 * them in that order too, but insert them into a singly
		 * linked list head first, which means when time comes
		 * to traverse the list, we enumerate them in reverse
		 * order. This screws up some drivers which expect the
		 * BARs to be in ascending order so that they can choose
		 * the "first" one as their register space. Unfortunately,
		 * in order to fix this, we have to create our own
		 * temporary list with the entries in reverse order.
		 */
		SLIST_FOREACH(brle, brl, link) {
			n = malloc(sizeof(struct resource_list_entry),
			    M_TEMP, M_NOWAIT);
			if (n == NULL) {
				error = ENOMEM;
				goto bad;
			}
			bcopy((char *)brle, (char *)n,
			    sizeof(struct resource_list_entry));
			SLIST_INSERT_HEAD(&brl_rev, n, link);
		}

		SLIST_FOREACH(brle, &brl_rev, link) {
			switch (brle->type) {
			case SYS_RES_IOPORT:
				prd->cprd_type = CmResourceTypePort;
				prd->cprd_flags = CM_RESOURCE_PORT_IO;
				prd->cprd_sharedisp =
				    CmResourceShareDeviceExclusive;
				prd->u.cprd_port.cprd_start.np_quad =
				    brle->start;
				prd->u.cprd_port.cprd_len = brle->count;
				break;
			case SYS_RES_MEMORY:
				prd->cprd_type = CmResourceTypeMemory;
				prd->cprd_flags =
				    CM_RESOURCE_MEMORY_READ_WRITE;
				prd->cprd_sharedisp =
				    CmResourceShareDeviceExclusive;
				prd->u.cprd_port.cprd_start.np_quad =
				    brle->start;
				prd->u.cprd_port.cprd_len = brle->count;
				break;
			case SYS_RES_IRQ:
				prd->cprd_type = CmResourceTypeInterrupt;
				prd->cprd_flags = 0;
				prd->cprd_sharedisp =
				    CmResourceShareDeviceExclusive;
				prd->u.cprd_intr.cprd_level = brle->start;
				prd->u.cprd_intr.cprd_vector = brle->start;
				prd->u.cprd_intr.cprd_affinity = 0;
				break;
			default:
				break;
			}
			prd++;
		}
	}

	block->nmb_rlist = rl;

bad:

	while (!SLIST_EMPTY(&brl_rev)) {
		n = SLIST_FIRST(&brl_rev);
		SLIST_REMOVE_HEAD(&brl_rev, link);
		free (n, M_TEMP);
	}

	return(error);
}

/*
 * Map an NDIS packet to an mbuf list. When an NDIS driver receives a
 * packet, it will hand it to us in the form of an ndis_packet,
 * which we need to convert to an mbuf that is then handed off
 * to the stack. Note: we configure the mbuf list so that it uses
 * the memory regions specified by the ndis_buffer structures in
 * the ndis_packet as external storage. In most cases, this will
 * point to a memory region allocated by the driver (either by
 * ndis_malloc_withtag() or ndis_alloc_sharedmem()). We expect
 * the driver to handle free()ing this region for is, so we set up
 * a dummy no-op free handler for it.
 */ 

int
ndis_ptom(m0, p)
	struct mbuf		**m0;
	ndis_packet		*p;
{
	struct mbuf		*m, *prev = NULL;
	ndis_buffer		*buf;
	ndis_packet_private	*priv;
	uint32_t		totlen = 0;

	if (p == NULL || m0 == NULL)
		return(EINVAL);

	priv = &p->np_private;
	buf = priv->npp_head;
	p->np_refcnt = 0;

	for (buf = priv->npp_head; buf != NULL; buf = buf->nb_next) {
		if (buf == priv->npp_head)
			MGETHDR(m, M_DONTWAIT, MT_HEADER);
		else
			MGET(m, M_DONTWAIT, MT_DATA);
		if (m == NULL) {
			m_freem(*m0);
			*m0 = NULL;
			return(ENOBUFS);
		}
		m->m_len = buf->nb_bytecount;
		m->m_data = MDL_VA(buf);
		MEXTADD(m, m->m_data, m->m_len, ndis_return_packet,
		    p, 0, EXT_NDIS);
		p->np_refcnt++;
		totlen += m->m_len;
		if (m->m_flags & MT_HEADER)
			*m0 = m;
		else
			prev->m_next = m;
		prev = m;
	}

	(*m0)->m_pkthdr.len = totlen;

	return(0);
}

/*
 * Create an mbuf chain from an NDIS packet chain.
 * This is used mainly when transmitting packets, where we need
 * to turn an mbuf off an interface's send queue and transform it
 * into an NDIS packet which will be fed into the NDIS driver's
 * send routine.
 *
 * NDIS packets consist of two parts: an ndis_packet structure,
 * which is vaguely analagous to the pkthdr portion of an mbuf,
 * and one or more ndis_buffer structures, which define the
 * actual memory segments in which the packet data resides.
 * We need to allocate one ndis_buffer for each mbuf in a chain,
 * plus one ndis_packet as the header.
 */

int
ndis_mtop(m0, p)
	struct mbuf		*m0;
	ndis_packet		**p;
{
	struct mbuf		*m;
	ndis_buffer		*buf = NULL, *prev = NULL;
	ndis_packet_private	*priv;

	if (p == NULL || m0 == NULL)
		return(EINVAL);

	/* If caller didn't supply a packet, make one. */
	if (*p == NULL) {
		*p = uma_zalloc(ndis_packet_zone, M_NOWAIT|M_ZERO);

		if (*p == NULL)
			return(ENOMEM);
	}
	
	priv = &(*p)->np_private;
	priv->npp_totlen = m0->m_pkthdr.len;
        priv->npp_packetooboffset = offsetof(ndis_packet, np_oob);
	priv->npp_ndispktflags = NDIS_PACKET_ALLOCATED_BY_NDIS;

	for (m = m0; m != NULL; m = m->m_next) {
		if (m->m_len == 0)
			continue;
		buf = uma_zalloc(ndis_buffer_zone, M_NOWAIT | M_ZERO);
		if (buf == NULL) {
			ndis_free_packet(*p);
			*p = NULL;
			return(ENOMEM);
		}

		MDL_INIT(buf, m->m_data, m->m_len);
		if (priv->npp_head == NULL)
			priv->npp_head = buf;
		else
			prev->nb_next = buf;
		prev = buf;
	}

	priv->npp_tail = buf;
	priv->npp_totlen = m0->m_pkthdr.len;

	return(0);
}

int
ndis_get_supported_oids(arg, oids, oidcnt)
	void			*arg;
	ndis_oid		**oids;
	int			*oidcnt;
{
	int			len, rval;
	ndis_oid		*o;

	if (arg == NULL || oids == NULL || oidcnt == NULL)
		return(EINVAL);
	len = 0;
	ndis_get_info(arg, OID_GEN_SUPPORTED_LIST, NULL, &len);

	o = malloc(len, M_DEVBUF, M_NOWAIT);
	if (o == NULL)
		return(ENOMEM);

	rval = ndis_get_info(arg, OID_GEN_SUPPORTED_LIST, o, &len);

	if (rval) {
		free(o, M_DEVBUF);
		return(rval);
	}

	*oids = o;
	*oidcnt = len / 4;

	return(0);
}

int
ndis_set_info(arg, oid, buf, buflen)
	void			*arg;
	ndis_oid		oid;
	void			*buf;
	int			*buflen;
{
	struct ndis_softc	*sc;
	ndis_status		rval;
	ndis_handle		adapter;
	__stdcall ndis_setinfo_handler	setfunc;
	uint32_t		byteswritten = 0, bytesneeded = 0;
	int			error;
	uint8_t			irql;

	sc = arg;
	NDIS_LOCK(sc);
	setfunc = sc->ndis_chars.nmc_setinfo_func;
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	NDIS_UNLOCK(sc);

	if (adapter == NULL || setfunc == NULL)
		return(ENXIO);

	irql = ntoskrnl_raise_irql(DISPATCH_LEVEL);
	rval = setfunc(adapter, oid, buf, *buflen,
	    &byteswritten, &bytesneeded);
	ntoskrnl_lower_irql(irql);

	if (rval == NDIS_STATUS_PENDING) {
		PROC_LOCK(curthread->td_proc);
		error = msleep(&sc->ndis_block.nmb_wkupdpctimer,
		    &curthread->td_proc->p_mtx,
		    curthread->td_priority|PDROP,
		    "ndisset", 5 * hz);
		rval = sc->ndis_block.nmb_setstat;
	}

	if (byteswritten)
		*buflen = byteswritten;
	if (bytesneeded)
		*buflen = bytesneeded;

	if (rval == NDIS_STATUS_INVALID_LENGTH)
		return(ENOSPC);

	if (rval == NDIS_STATUS_INVALID_OID)
		return(EINVAL);

	if (rval == NDIS_STATUS_NOT_SUPPORTED ||
	    rval == NDIS_STATUS_NOT_ACCEPTED)
		return(ENOTSUP);

	if (rval != NDIS_STATUS_SUCCESS)
		return(ENODEV);

	return(0);
}

typedef void (*ndis_senddone_func)(ndis_handle, ndis_packet *, ndis_status);

int
ndis_send_packets(arg, packets, cnt)
	void			*arg;
	ndis_packet		**packets;
	int			cnt;
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	__stdcall ndis_sendmulti_handler	sendfunc;
	__stdcall ndis_senddone_func		senddonefunc;
	int			i;
	ndis_packet		*p;
	uint8_t			irql;

	sc = arg;
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	if (adapter == NULL)
		return(ENXIO);
	sendfunc = sc->ndis_chars.nmc_sendmulti_func;
	senddonefunc = sc->ndis_block.nmb_senddone_func;
	irql = ntoskrnl_raise_irql(DISPATCH_LEVEL);
	sendfunc(adapter, packets, cnt);
	ntoskrnl_lower_irql(irql);

	for (i = 0; i < cnt; i++) {
		p = packets[i];
		/*
		 * Either the driver already handed the packet to
		 * ndis_txeof() due to a failure, or it wants to keep
		 * it and release it asynchronously later. Skip to the
		 * next one.
		 */
		if (p == NULL || p->np_oob.npo_status == NDIS_STATUS_PENDING)
			continue;
		senddonefunc(&sc->ndis_block, p, p->np_oob.npo_status);
	}

	return(0);
}

int
ndis_send_packet(arg, packet)
	void			*arg;
	ndis_packet		*packet;
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	ndis_status		status;
	__stdcall ndis_sendsingle_handler	sendfunc;
	__stdcall ndis_senddone_func		senddonefunc;
	uint8_t			irql;

	sc = arg;
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	if (adapter == NULL)
		return(ENXIO);
	sendfunc = sc->ndis_chars.nmc_sendsingle_func;
	senddonefunc = sc->ndis_block.nmb_senddone_func;

	irql = ntoskrnl_raise_irql(DISPATCH_LEVEL);
	status = sendfunc(adapter, packet, packet->np_private.npp_flags);
	ntoskrnl_lower_irql(irql);

	if (status == NDIS_STATUS_PENDING)
		return(0);

	senddonefunc(&sc->ndis_block, packet, status);

	return(0);
}

int
ndis_init_dma(arg)
	void			*arg;
{
	struct ndis_softc	*sc;
	int			i, error;

	sc = arg;

	sc->ndis_tmaps = malloc(sizeof(bus_dmamap_t) * sc->ndis_maxpkts,
	    M_DEVBUF, M_NOWAIT|M_ZERO);

	if (sc->ndis_tmaps == NULL)
		return(ENOMEM);

	for (i = 0; i < sc->ndis_maxpkts; i++) {
		error = bus_dmamap_create(sc->ndis_ttag, 0,
		    &sc->ndis_tmaps[i]);
		if (error) {
			free(sc->ndis_tmaps, M_DEVBUF);
			return(ENODEV);
		}
	}

	return(0);
}

int
ndis_destroy_dma(arg)
	void			*arg;
{
	struct ndis_softc	*sc;
	struct mbuf		*m;
	ndis_packet		*p = NULL;
	int			i;

	sc = arg;

	for (i = 0; i < sc->ndis_maxpkts; i++) {
		if (sc->ndis_txarray[i] != NULL) {
			p = sc->ndis_txarray[i];
			m = (struct mbuf *)p->np_rsvd[1];
			if (m != NULL)
				m_freem(m);
			ndis_free_packet(sc->ndis_txarray[i]);
		}
		bus_dmamap_destroy(sc->ndis_ttag, sc->ndis_tmaps[i]);
	}

	free(sc->ndis_tmaps, M_DEVBUF);

	bus_dma_tag_destroy(sc->ndis_ttag);

	return(0);
}

int
ndis_reset_nic(arg)
	void			*arg;
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	__stdcall ndis_reset_handler	resetfunc;
	uint8_t			addressing_reset;
	struct ifnet		*ifp;
	int			rval;
	uint8_t			irql;

	sc = arg;
	ifp = &sc->arpcom.ac_if;
	NDIS_LOCK(sc);
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	resetfunc = sc->ndis_chars.nmc_reset_func;
	NDIS_UNLOCK(sc);
	if (adapter == NULL || resetfunc == NULL)
		return(EIO);

	irql = ntoskrnl_raise_irql(DISPATCH_LEVEL);
	rval = resetfunc(&addressing_reset, adapter);
	ntoskrnl_lower_irql(irql);

	if (rval == NDIS_STATUS_PENDING) {
		PROC_LOCK(curthread->td_proc);
		msleep(sc, &curthread->td_proc->p_mtx,
		    curthread->td_priority|PDROP, "ndisrst", 0);
	}

	return(0);
}

int
ndis_halt_nic(arg)
	void			*arg;
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	__stdcall ndis_halt_handler	haltfunc;
	struct ifnet		*ifp;

	sc = arg;
	ifp = &sc->arpcom.ac_if;

	NDIS_LOCK(sc);
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	if (adapter == NULL) {
		NDIS_UNLOCK(sc);
		return(EIO);
	}

	/*
	 * The adapter context is only valid after the init
	 * handler has been called, and is invalid once the
	 * halt handler has been called.
	 */

	haltfunc = sc->ndis_chars.nmc_halt_func;
	NDIS_UNLOCK(sc);

	haltfunc(adapter);

	NDIS_LOCK(sc);
	sc->ndis_block.nmb_miniportadapterctx = NULL;
	NDIS_UNLOCK(sc);

	return(0);
}

int
ndis_shutdown_nic(arg)
	void			*arg;
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	__stdcall ndis_shutdown_handler	shutdownfunc;

	sc = arg;
	NDIS_LOCK(sc);
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	shutdownfunc = sc->ndis_chars.nmc_shutdown_handler;
	NDIS_UNLOCK(sc);
	if (adapter == NULL || shutdownfunc == NULL)
		return(EIO);

	if (sc->ndis_chars.nmc_rsvd0 == NULL)
		shutdownfunc(adapter);
	else
		shutdownfunc(sc->ndis_chars.nmc_rsvd0);

	ndis_shrink_thrqueue(8);
	TAILQ_REMOVE(&ndis_devhead, &sc->ndis_block, link);

	return(0);
}

int
ndis_init_nic(arg)
	void			*arg;
{
	struct ndis_softc	*sc;
	ndis_miniport_block	*block;
        __stdcall ndis_init_handler	initfunc;
	ndis_status		status, openstatus = 0;
	ndis_medium		mediumarray[NdisMediumMax];
	uint32_t		chosenmedium, i;

	if (arg == NULL)
		return(EINVAL);

	sc = arg;
	NDIS_LOCK(sc);
	block = &sc->ndis_block;
	initfunc = sc->ndis_chars.nmc_init_func;
	NDIS_UNLOCK(sc);

	TAILQ_INIT(&block->nmb_timerlist);

	for (i = 0; i < NdisMediumMax; i++)
		mediumarray[i] = i;

        status = initfunc(&openstatus, &chosenmedium,
            mediumarray, NdisMediumMax, block, block);

	/*
	 * If the init fails, blow away the other exported routines
	 * we obtained from the driver so we can't call them later.
	 * If the init failed, none of these will work.
	 */
	if (status != NDIS_STATUS_SUCCESS) {
		NDIS_LOCK(sc);
		sc->ndis_block.nmb_miniportadapterctx = NULL;
		NDIS_UNLOCK(sc);
		return(ENXIO);
	}

	return(0);
}

void
ndis_enable_intr(arg)
	void			*arg;
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	__stdcall ndis_enable_interrupts_handler	intrenbfunc;

	sc = arg;
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	intrenbfunc = sc->ndis_chars.nmc_enable_interrupts_func;
	if (adapter == NULL || intrenbfunc == NULL)
		return;
	intrenbfunc(adapter);

	return;
}

void
ndis_disable_intr(arg)
	void			*arg;
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	__stdcall ndis_disable_interrupts_handler	intrdisfunc;

	sc = arg;
	NDIS_LOCK(sc);
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	intrdisfunc = sc->ndis_chars.nmc_disable_interrupts_func;
	NDIS_UNLOCK(sc);
	if (adapter == NULL || intrdisfunc == NULL)
	    return;
	intrdisfunc(adapter);

	return;
}

int
ndis_isr(arg, ourintr, callhandler)
	void			*arg;
	int			*ourintr;
	int			*callhandler;
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	__stdcall ndis_isr_handler	isrfunc;
	uint8_t			accepted, queue;

	if (arg == NULL || ourintr == NULL || callhandler == NULL)
		return(EINVAL);

	sc = arg;
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	isrfunc = sc->ndis_chars.nmc_isr_func;
	if (adapter == NULL || isrfunc == NULL)
		return(ENXIO);

	isrfunc(&accepted, &queue, adapter);
	*ourintr = accepted;
	*callhandler = queue;

	return(0);
}

int
ndis_intrhand(arg)
	void			*arg;
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	__stdcall ndis_interrupt_handler	intrfunc;

	if (arg == NULL)
		return(EINVAL);

	sc = arg;
	NDIS_LOCK(sc);
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	intrfunc = sc->ndis_chars.nmc_interrupt_func;
	NDIS_UNLOCK(sc);
	if (adapter == NULL || intrfunc == NULL)
		return(EINVAL);

	intrfunc(adapter);

	return(0);
}

int
ndis_get_info(arg, oid, buf, buflen)
	void			*arg;
	ndis_oid		oid;
	void			*buf;
	int			*buflen;
{
	struct ndis_softc	*sc;
	ndis_status		rval;
	ndis_handle		adapter;
	__stdcall ndis_queryinfo_handler	queryfunc;
	uint32_t		byteswritten = 0, bytesneeded = 0;
	int			error;
	uint8_t			irql;

	sc = arg;
	NDIS_LOCK(sc);
	queryfunc = sc->ndis_chars.nmc_queryinfo_func;
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	NDIS_UNLOCK(sc);

	if (adapter == NULL || queryfunc == NULL)
		return(ENXIO);

	irql = ntoskrnl_raise_irql(DISPATCH_LEVEL);
	rval = queryfunc(adapter, oid, buf, *buflen,
	    &byteswritten, &bytesneeded);
	ntoskrnl_lower_irql(irql);

	/* Wait for requests that block. */

	if (rval == NDIS_STATUS_PENDING) {
		PROC_LOCK(curthread->td_proc);
		error = msleep(&sc->ndis_block.nmb_wkupdpctimer,
		    &curthread->td_proc->p_mtx,
		    curthread->td_priority|PDROP,
		    "ndisget", 5 * hz);
		rval = sc->ndis_block.nmb_getstat;
	}

	if (byteswritten)
		*buflen = byteswritten;
	if (bytesneeded)
		*buflen = bytesneeded;

	if (rval == NDIS_STATUS_INVALID_LENGTH ||
	    rval == NDIS_STATUS_BUFFER_TOO_SHORT)
		return(ENOSPC);

	if (rval == NDIS_STATUS_INVALID_OID)
		return(EINVAL);

	if (rval == NDIS_STATUS_NOT_SUPPORTED ||
	    rval == NDIS_STATUS_NOT_ACCEPTED)
		return(ENOTSUP);

	if (rval != NDIS_STATUS_SUCCESS)
		return(ENODEV);

	return(0);
}

int
ndis_unload_driver(arg)
	void			*arg;
{
	struct ndis_softc	*sc;

	sc = arg;

	free(sc->ndis_block.nmb_rlist, M_DEVBUF);

	ndis_flush_sysctls(sc);

	ndis_shrink_thrqueue(8);
	TAILQ_REMOVE(&ndis_devhead, &sc->ndis_block, link);

	return(0);
}

#define NDIS_LOADED		htonl(0x42534F44)

int
ndis_load_driver(img, arg)
	vm_offset_t		img;
	void			*arg;
{
	__stdcall driver_entry	entry;
	image_optional_header	opt_hdr;
	image_import_descriptor imp_desc;
	ndis_unicode_string	dummystr;
        ndis_miniport_block     *block;
	ndis_status		status;
	int			idx;
	uint32_t		*ptr;
	struct ndis_softc	*sc;

	sc = arg;

	/*
	 * Only perform the relocation/linking phase once
	 * since the binary image may be shared among multiple
	 * device instances.
	 */

	ptr = (uint32_t *)(img + 8);
	if (*ptr != NDIS_LOADED) {
		/* Perform text relocation */
		if (pe_relocate(img))
			return(ENOEXEC);

		/* Dynamically link the NDIS.SYS routines -- required. */
		if (pe_patch_imports(img, "NDIS", ndis_functbl))
			return(ENOEXEC);

		/* Dynamically link the HAL.dll routines -- also required. */
		if (pe_patch_imports(img, "HAL", hal_functbl))
			return(ENOEXEC);

		/* Dynamically link ntoskrnl.exe -- optional. */
		if (pe_get_import_descriptor(img,
		    &imp_desc, "ntoskrnl") == 0) {
			if (pe_patch_imports(img,
			    "ntoskrnl", ntoskrnl_functbl))
				return(ENOEXEC);
		}
		*ptr = NDIS_LOADED;
	}

        /* Locate the driver entry point */
	pe_get_optional_header(img, &opt_hdr);
	entry = (driver_entry)pe_translate_addr(img, opt_hdr.ioh_entryaddr);

	dummystr.nus_len = strlen(NDIS_DUMMY_PATH) * 2;
	dummystr.nus_maxlen = strlen(NDIS_DUMMY_PATH) * 2;
	dummystr.nus_buf = NULL;
	ndis_ascii_to_unicode(NDIS_DUMMY_PATH, &dummystr.nus_buf);

	/*
	 * Now that we have the miniport driver characteristics,
	 * create an NDIS block and call the init handler.
	 * This will cause the driver to try to probe for
	 * a device.
	 */

	block = &sc->ndis_block;

	ptr = (uint32_t *)block;
	for (idx = 0; idx < sizeof(ndis_miniport_block) / 4; idx++) {
		*ptr = idx | 0xdead0000;
		ptr++;
	}

	block->nmb_signature = (void *)0xcafebabe;
	block->nmb_setdone_func = ndis_setdone_func;
	block->nmb_querydone_func = ndis_getdone_func;
	block->nmb_status_func = ndis_status_func;
	block->nmb_statusdone_func = ndis_statusdone_func;
	block->nmb_resetdone_func = ndis_resetdone_func;
	block->nmb_sendrsrc_func = ndis_sendrsrcavail_func;

	block->nmb_ifp = &sc->arpcom.ac_if;
	block->nmb_dev = sc->ndis_dev;
	block->nmb_img = img;
	block->nmb_devobj.do_rsvd = block;

	/*
	 * Now call the DriverEntry() routine. This will cause
	 * a callout to the NdisInitializeWrapper() and
	 * NdisMRegisterMiniport() routines.
	 */
	status = entry(&block->nmb_devobj, &dummystr);

	free (dummystr.nus_buf, M_DEVBUF);

	if (status != NDIS_STATUS_SUCCESS)
		return(ENODEV);

	ndis_enlarge_thrqueue(8);

	TAILQ_INSERT_TAIL(&ndis_devhead, block, link);

	return(0);
}
