/*-
 * Copyright (c) 2002 Poul-Henning Kamp
 * Copyright (c) 2002 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by Poul-Henning Kamp
 * and NAI Labs, the Security Research Division of Network Associates, Inc.
 * under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the
 * DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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

#ifndef _GEOM_GEOM_H_
#define _GEOM_GEOM_H_

#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/queue.h>
#include <sys/ioccom.h>
#include <sys/sbuf.h>

#ifdef KERNELSIM
/*
 * The GEOM subsystem makes a few concessions in order to be able to run as a
 * user-land simulation as well as a kernel component.
 */
#include <geom_sim.h>
#endif

struct g_class;
struct g_geom;
struct g_consumer;
struct g_provider;
struct g_event;
struct g_stat;
struct thread;
struct bio;
struct sbuf;
struct gctl_req;
struct g_configargs;

typedef int g_config_t (struct g_configargs *ca);
typedef int g_ctl_create_geom_t (struct gctl_req *, struct g_class *cp, struct g_provider *pp);
typedef int g_ctl_destroy_geom_t (struct gctl_req *, struct g_class *cp, struct g_geom *gp);
typedef struct g_geom * g_taste_t (struct g_class *, struct g_provider *,
    int flags);
#define G_TF_NORMAL		0
#define G_TF_INSIST		1
#define G_TF_TRANSPARENT	2
typedef int g_access_t (struct g_provider *, int, int, int);
/* XXX: not sure about the thread arg */
typedef void g_orphan_t (struct g_consumer *);

typedef void g_start_t (struct bio *);
typedef void g_spoiled_t (struct g_consumer *);
typedef void g_dumpconf_t (struct sbuf *, const char *indent, struct g_geom *,
    struct g_consumer *, struct g_provider *);

/*
 * The g_class structure describes a transformation class.  In other words
 * all BSD disklabel handlers share one g_class, all MBR handlers share
 * one common g_class and so on.
 * Certain operations are instantiated on the class, most notably the
 * taste and config_geom functions.
 */
struct g_class {
	const char		*name;
	g_taste_t		*taste;
	g_config_t		*config;
	g_ctl_create_geom_t	*create_geom;
	g_ctl_destroy_geom_t	*destroy_geom;
	/*
	 * The remaning elements are private and classes should use
	 * the G_CLASS_INITIALIZER macro to initialize them.
         */
	LIST_ENTRY(g_class)	class;
	LIST_HEAD(,g_geom)	geom;
	struct g_event		*event;
	u_int			protect;
};

#define G_CLASS_INITIALIZER 	\
	.class = { 0, 0 },	\
	.geom = { 0 },		\
	.event = 0,		\
	.protect = 0	

/*
 * The g_geom is an instance of a g_class.
 */
struct g_geom {
	u_int			protect;
	char			*name;
	struct g_class		*class;
	LIST_ENTRY(g_geom)	geom;
	LIST_HEAD(,g_consumer)	consumer;
	LIST_HEAD(,g_provider)	provider;
	TAILQ_ENTRY(g_geom)	geoms;	/* XXX: better name */
	int			rank;
	g_start_t		*start;
	g_spoiled_t		*spoiled;
	g_dumpconf_t		*dumpconf;
	g_access_t		*access;
	g_orphan_t		*orphan;
	void			*softc;
	struct g_event		*event;
	unsigned		flags;
#define	G_GEOM_WITHER		1
};

/*
 * The g_bioq is a queue of struct bio's.
 * XXX: possibly collection point for statistics.
 * XXX: should (possibly) be collapsed with sys/bio.h::bio_queue_head.
 */
struct g_bioq {
	TAILQ_HEAD(, bio)	bio_queue;
	struct mtx		bio_queue_lock;
	int			bio_queue_length;
};

/*
 * A g_consumer is an attachment point for a g_provider.  One g_consumer
 * can only be attached to one g_provider, but multiple g_consumers
 * can be attached to one g_provider.
 */

struct g_consumer {
	u_int			protect;
	struct g_geom		*geom;
	LIST_ENTRY(g_consumer)	consumer;
	struct g_provider	*provider;
	LIST_ENTRY(g_consumer)	consumers;	/* XXX: better name */
	int			acr, acw, ace;
	struct g_event		*event;
	int			spoiled;
	struct devstat		*stat;
	u_int			nstart, nend;
};

/*
 * A g_provider is a "logical disk".
 */
struct g_provider {
	u_int			protect;
	char			*name;
	LIST_ENTRY(g_provider)	provider;
	struct g_geom		*geom;
	LIST_HEAD(,g_consumer)	consumers;
	int			acr, acw, ace;
	int			error;
	struct g_event		*event;
	TAILQ_ENTRY(g_provider)	orphan;
	u_int			index;
	off_t			mediasize;
	u_int			sectorsize;
	u_int			stripesize;
	u_int			stripeoffset;
	struct devstat		*stat;
	u_int			nstart, nend;
	u_int			flags;
#define G_PF_CANDELETE		0x1
};

/*
 * This gadget is used by userland to pinpoint a particular instance of
 * something in the kernel.  The name is unreadable on purpose, people
 * should not encounter it directly but use library functions to deal
 * with it.
 * If len is zero, "id" contains a cast of the kernel pointer where the
 * entity is located, (likely derived from the "id=" attribute in the
 * XML config) and the g_id*() functions will validate this before allowing
 * it to be used.
 * If len is non-zero, it is the strlen() of the name which is pointed to
 * by "name".
 */
struct geomidorname {
	u_int len;
	union {
		const char	*name;
		uintptr_t	id;
	} u;
};

/* geom_dev.c */
int g_dev_print(void);

/* geom_dump.c */
void g_hexdump(void *ptr, int length);
void g_trace(int level, const char *, ...);
#	define G_T_TOPOLOGY	1
#	define G_T_BIO		2
#	define G_T_ACCESS	4


/* geom_event.c */
typedef void g_call_me_t(void *, int flag);
#define EV_CANCEL	1
int g_call_me(g_call_me_t *func, void *arg, ...);
void g_cancel_event(void *ref);
void g_orphan_provider(struct g_provider *pp, int error);
void g_waitidle(void);

/* geom_subr.c */
int g_access_abs(struct g_consumer *cp, int nread, int nwrite, int nexcl);
int g_access_rel(struct g_consumer *cp, int nread, int nwrite, int nexcl);
void g_add_class(struct g_class *mp);
int g_attach(struct g_consumer *cp, struct g_provider *pp);
void g_destroy_consumer(struct g_consumer *cp);
void g_destroy_geom(struct g_geom *pp);
void g_destroy_provider(struct g_provider *pp);
void g_detach(struct g_consumer *cp);
void g_error_provider(struct g_provider *pp, int error);
int g_getattr__(const char *attr, struct g_consumer *cp, void *var, int len);
#define g_getattr(a, c, v) g_getattr__((a), (c), (v), sizeof *(v))
int g_handleattr(struct bio *bp, const char *attribute, void *val, int len);
int g_handleattr_int(struct bio *bp, const char *attribute, int val);
int g_handleattr_off_t(struct bio *bp, const char *attribute, off_t val);
struct g_consumer * g_new_consumer(struct g_geom *gp);
struct g_geom * g_new_geomf(struct g_class *mp, const char *fmt, ...);
struct g_provider * g_new_providerf(struct g_geom *gp, const char *fmt, ...);
void g_sanity(void *ptr);
void g_spoil(struct g_provider *pp, struct g_consumer *cp);
int g_std_access(struct g_provider *pp, int dr, int dw, int de);
void g_std_done(struct bio *bp);
void g_std_spoiled(struct g_consumer *cp);
struct g_class *g_idclass(struct geomidorname *);
struct g_geom *g_idgeom(struct geomidorname *);
struct g_provider *g_idprovider(struct geomidorname *);


/* geom_io.c */
struct bio * g_clone_bio(struct bio *);
void g_destroy_bio(struct bio *);
void g_io_deliver(struct bio *bp, int error);
int g_io_getattr(const char *attr, struct g_consumer *cp, int *len, void *ptr);
void g_io_request(struct bio *bp, struct g_consumer *cp);
int g_io_setattr(const char *attr, struct g_consumer *cp, int len, void *ptr);
struct bio *g_new_bio(void);
void * g_read_data(struct g_consumer *cp, off_t offset, off_t length, int *error);
int g_write_data(struct g_consumer *cp, off_t offset, void *ptr, off_t length);

/* geom_kern.c / geom_kernsim.c */

#ifndef _SYS_CONF_H_
typedef int d_ioctl_t(dev_t dev, u_long cmd, caddr_t data,
		      int fflag, struct thread *td);
#endif

struct g_ioctl {
	u_long		cmd;
	void		*data;
	int		fflag;
	struct thread	*td;
	d_ioctl_t	*func;
	void		*dev;
};

#ifdef _KERNEL

struct g_kerneldump {
	off_t		offset;
	off_t		length;
};

MALLOC_DECLARE(M_GEOM);

static __inline void *
g_malloc(int size, int flags)
{
	void *p;

	p = malloc(size, M_GEOM, flags);
	g_sanity(p);
	/* printf("malloc(%d, %x) -> %p\n", size, flags, p); */
	return (p);
}

static __inline void
g_free(void *ptr)
{
	g_sanity(ptr);
	/* printf("free(%p)\n", ptr); */
	free(ptr, M_GEOM);
}

extern struct sx topology_lock;

#define g_topology_lock() 					\
	do {							\
		mtx_assert(&Giant, MA_NOTOWNED);		\
		sx_xlock(&topology_lock);			\
	} while (0)

#define g_topology_unlock()					\
	do {							\
		g_sanity(NULL);					\
		sx_xunlock(&topology_lock);			\
	} while (0)

#define g_topology_assert()					\
	do {							\
		g_sanity(NULL);					\
		sx_assert(&topology_lock, SX_XLOCKED);		\
	} while (0)

#define DECLARE_GEOM_CLASS_INIT(class, name, init) 	\
	SYSINIT(name, SI_SUB_DRIVERS, SI_ORDER_FIRST, init, NULL);

#define DECLARE_GEOM_CLASS(class, name) 	\
	static void				\
	name##init(void)			\
	{					\
		mtx_unlock(&Giant);		\
		g_add_class(&class);		\
		mtx_lock(&Giant);		\
	}					\
	DECLARE_GEOM_CLASS_INIT(class, name, name##init);

#endif /* _KERNEL */

/* geom_ctl.c */
void *gctl_get_param(struct gctl_req *req, const char *param, int *len);
int gctl_error(struct gctl_req *req, const char *errtxt);

/* geom_enc.c */
uint16_t g_dec_be2(const u_char *p);
uint32_t g_dec_be4(const u_char *p);
uint16_t g_dec_le2(const u_char *p);
uint32_t g_dec_le4(const u_char *p);
uint64_t g_dec_le8(const u_char *p);
void g_enc_le2(u_char *p, uint16_t u);
void g_enc_le4(u_char *p, uint32_t u);
void g_enc_le8(u_char *p, uint64_t u);

#endif /* _GEOM_GEOM_H_ */
