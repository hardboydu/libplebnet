/*-
 * Copyright (c) 1997-2000 Doug Rabson
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/linker.h>
#include <sys/fcntl.h>
#include <sys/jail.h>
#include <sys/libkern.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>

#include <net/vnet.h>

#include <security/mac/mac_framework.h>

#include "linker_if.h"

#ifdef HWPMC_HOOKS
#include <sys/pmckern.h>
#endif

#ifdef KLD_DEBUG
int kld_debug = 0;
SYSCTL_INT(_debug, OID_AUTO, kld_debug, CTLFLAG_RW,
        &kld_debug, 0, "Set various levels of KLD debug");
#endif

#define	KLD_LOCK()		sx_xlock(&kld_sx)
#define	KLD_UNLOCK()		sx_xunlock(&kld_sx)
#define	KLD_DOWNGRADE()		sx_downgrade(&kld_sx)
#define	KLD_LOCK_READ()		sx_slock(&kld_sx)
#define	KLD_UNLOCK_READ()	sx_sunlock(&kld_sx)
#define	KLD_LOCKED()		sx_xlocked(&kld_sx)
#define	KLD_LOCK_ASSERT() do {						\
	if (!cold)							\
		sx_assert(&kld_sx, SX_XLOCKED);				\
} while (0)



/* Metadata from the static kernel */
SET_DECLARE(modmetadata_set, struct mod_metadata);

MALLOC_DEFINE(M_LINKER, "linker", "kernel linker");

linker_file_t linker_kernel_file;

static struct sx kld_sx;	/* kernel linker lock */

/*
 * Load counter used by clients to determine if a linker file has been
 * re-loaded. This counter is incremented for each file load.
 */
static int loadcnt;

static linker_class_list_t classes;
static linker_file_list_t linker_files;
static int next_file_id = 1;
static int linker_no_more_classes = 0;

#define	LINKER_GET_NEXT_FILE_ID(a) do {					\
	linker_file_t lftmp;						\
									\
	KLD_LOCK_ASSERT();						\
retry:									\
	TAILQ_FOREACH(lftmp, &linker_files, link) {			\
		if (next_file_id == lftmp->id) {			\
			next_file_id++;					\
			goto retry;					\
		}							\
	}								\
	(a) = next_file_id;						\
} while(0)


/* XXX wrong name; we're looking at version provision tags here, not modules */
typedef TAILQ_HEAD(, modlist) modlisthead_t;
struct modlist {
	TAILQ_ENTRY(modlist) link;	/* chain together all modules */
	linker_file_t   container;
	const char 	*name;
	int             version;
};
typedef struct modlist *modlist_t;
static modlisthead_t found_modules;

static char *
linker_strdup(const char *str)
{
	char *result;

	if ((result = malloc((strlen(str) + 1), M_LINKER, M_WAITOK)) != NULL)
		strcpy(result, str);
	return (result);
}

static void
linker_init(void *arg)
{

	sx_init(&kld_sx, "kernel linker");
	TAILQ_INIT(&classes);
	TAILQ_INIT(&linker_files);
}

SYSINIT(linker, SI_SUB_KLD, SI_ORDER_FIRST, linker_init, 0);

static void
linker_stop_class_add(void *arg)
{

	linker_no_more_classes = 1;
}

SYSINIT(linker_class, SI_SUB_KLD, SI_ORDER_ANY, linker_stop_class_add, NULL);

int
linker_add_class(linker_class_t lc)
{

	/*
	 * We disallow any class registration past SI_ORDER_ANY
	 * of SI_SUB_KLD.  We bump the reference count to keep the
	 * ops from being freed.
	 */
	if (linker_no_more_classes == 1)
		return (EPERM);
	kobj_class_compile((kobj_class_t) lc);
	((kobj_class_t)lc)->refs++;	/* XXX: kobj_mtx */
	TAILQ_INSERT_TAIL(&classes, lc, link);
	return (0);
}

static int
linker_file_register_modules(linker_file_t lf)
{
	struct mod_metadata **start, **stop, **mdp;
	const moduledata_t *moddata;
	int first_error, error;

	KLD_DPF(FILE, ("linker_file_register_modules: registering modules"
	    " in %s\n", lf->filename));

#if 0
	if (linker_file_lookup_set(lf, "modmetadata_set", &start,
	    &stop, NULL) != 0) {
		/*
		 * This fallback should be unnecessary, but if we get booted
		 * from boot2 instead of loader and we are missing our
		 * metadata then we have to try the best we can.
		 */
		if (lf == linker_kernel_file) {
			start = SET_BEGIN(modmetadata_set);
			stop = SET_LIMIT(modmetadata_set);
		} else
			return (0);
	}
#endif
	start = SET_BEGIN(modmetadata_set);
	stop = SET_LIMIT(modmetadata_set);

	first_error = 0;
	for (mdp = start; mdp < stop; mdp++) {
		if ((*mdp)->md_type != MDT_MODULE)
			continue;
		moddata = (*mdp)->md_data;
		KLD_DPF(FILE, ("Registering module %s in %s\n",
		    moddata->name, lf->filename));
		error = module_register(moddata, lf);
		if (error) {
			printf("Module %s failed to register: %d\n",
			    moddata->name, error);
			if (first_error == 0)
				first_error = error;
		}
	}
	return (first_error);
}

static void
linker_init_kernel_modules(void)
{

	linker_file_register_modules(linker_kernel_file);
}

SYSINIT(linker_kernel, SI_SUB_KLD, SI_ORDER_ANY, linker_init_kernel_modules,
    0);

/*
 * Locate a linker set and its contents.  This is a helper function to avoid
 * linker_if.h exposure elsewhere.  Note: firstp and lastp are really void **.
 * This function is used in this file so we can avoid having lots of (void **)
 * casts.
 */
int
linker_file_lookup_set(linker_file_t file, const char *name,
    void *firstp, void *lastp, int *countp)
{
	int error, locked;

	locked = KLD_LOCKED();
	if (!locked)
		KLD_LOCK();
	error = LINKER_LOOKUP_SET(file, name, firstp, lastp, countp);
	if (!locked)
		KLD_UNLOCK();
	return (error);
}

static const char *
linker_basename(const char *path)
{
	const char *filename;

	filename = rindex(path, '/');
	if (filename == NULL)
		return path;
	if (filename[1])
		filename++;
	return (filename);
}

linker_file_t
linker_make_file(const char *pathname, linker_class_t lc)
{
	linker_file_t lf;
	const char *filename;

	KLD_LOCK_ASSERT();
	filename = linker_basename(pathname);

	KLD_DPF(FILE, ("linker_make_file: new file, filename='%s' for pathname='%s'\n", filename, pathname));
	lf = (linker_file_t)kobj_create((kobj_class_t)lc, M_LINKER, M_WAITOK);
	if (lf == NULL)
		return (NULL);
	lf->refs = 1;
	lf->userrefs = 0;
	lf->flags = 0;
	lf->filename = linker_strdup(filename);
	lf->pathname = linker_strdup(pathname);
	LINKER_GET_NEXT_FILE_ID(lf->id);
	lf->ndeps = 0;
	lf->deps = NULL;
	lf->loadcnt = ++loadcnt;
	lf->sdt_probes = NULL;
	lf->sdt_nprobes = 0;
	STAILQ_INIT(&lf->common);
	TAILQ_INIT(&lf->modules);
	TAILQ_INSERT_TAIL(&linker_files, lf, link);
	return (lf);
}
