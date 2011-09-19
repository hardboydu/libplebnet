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

static int	linker_load_module(const char *kldname,
		    const char *modname, struct linker_file *parent,
		    struct mod_depend *verinfo, struct linker_file **lfpp);

static char *	linker_search_kld(const char *name);

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

static linker_file_t
linker_find_file_by_name(const char *filename)
{
	linker_file_t lf;
	char *koname;

	koname = malloc(strlen(filename) + 4, M_LINKER, M_WAITOK);
	sprintf(koname, "%s.ko", filename);

	KLD_LOCK_ASSERT();
	TAILQ_FOREACH(lf, &linker_files, link) {
		if (strcmp(lf->filename, koname) == 0)
			break;
		if (strcmp(lf->filename, filename) == 0)
			break;
	}
	free(koname, M_LINKER);
	return (lf);
}

static linker_file_t
linker_find_file_by_id(int fileid)
{
	linker_file_t lf;

	KLD_LOCK_ASSERT();
	TAILQ_FOREACH(lf, &linker_files, link)
		if (lf->id == fileid && lf->flags & LINKER_FILE_LINKED)
			break;
	return (lf);
}

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

static void
linker_file_sysinit(linker_file_t lf)
{
	struct sysinit **start, **stop, **sipp, **xipp, *save;

	KLD_DPF(FILE, ("linker_file_sysinit: calling SYSINITs for %s\n",
	    lf->filename));

	if (linker_file_lookup_set(lf, "sysinit_set", &start, &stop, NULL) != 0)
		return;
	/*
	 * Perform a bubble sort of the system initialization objects by
	 * their subsystem (primary key) and order (secondary key).
	 *
	 * Since some things care about execution order, this is the operation
	 * which ensures continued function.
	 */
	for (sipp = start; sipp < stop; sipp++) {
		for (xipp = sipp + 1; xipp < stop; xipp++) {
			if ((*sipp)->subsystem < (*xipp)->subsystem ||
			    ((*sipp)->subsystem == (*xipp)->subsystem &&
			    (*sipp)->order <= (*xipp)->order))
				continue;	/* skip */
			save = *sipp;
			*sipp = *xipp;
			*xipp = save;
		}
	}

	/*
	 * Traverse the (now) ordered list of system initialization tasks.
	 * Perform each task, and continue on to the next task.
	 */
	mtx_lock(&Giant);
	for (sipp = start; sipp < stop; sipp++) {
		if ((*sipp)->subsystem == SI_SUB_DUMMY)
			continue;	/* skip dummy task(s) */

		/* Call function */
		(*((*sipp)->func)) ((*sipp)->udata);
	}
	mtx_unlock(&Giant);
}

static void
linker_file_sysuninit(linker_file_t lf)
{
	struct sysinit **start, **stop, **sipp, **xipp, *save;

	KLD_DPF(FILE, ("linker_file_sysuninit: calling SYSUNINITs for %s\n",
	    lf->filename));

	if (linker_file_lookup_set(lf, "sysuninit_set", &start, &stop,
	    NULL) != 0)
		return;

	/*
	 * Perform a reverse bubble sort of the system initialization objects
	 * by their subsystem (primary key) and order (secondary key).
	 *
	 * Since some things care about execution order, this is the operation
	 * which ensures continued function.
	 */
	for (sipp = start; sipp < stop; sipp++) {
		for (xipp = sipp + 1; xipp < stop; xipp++) {
			if ((*sipp)->subsystem > (*xipp)->subsystem ||
			    ((*sipp)->subsystem == (*xipp)->subsystem &&
			    (*sipp)->order >= (*xipp)->order))
				continue;	/* skip */
			save = *sipp;
			*sipp = *xipp;
			*xipp = save;
		}
	}

	/*
	 * Traverse the (now) ordered list of system initialization tasks.
	 * Perform each task, and continue on to the next task.
	 */
	mtx_lock(&Giant);
	for (sipp = start; sipp < stop; sipp++) {
		if ((*sipp)->subsystem == SI_SUB_DUMMY)
			continue;	/* skip dummy task(s) */

		/* Call function */
		(*((*sipp)->func)) ((*sipp)->udata);
	}
	mtx_unlock(&Giant);
}

static void
linker_file_register_sysctls(linker_file_t lf)
{
	struct sysctl_oid **start, **stop, **oidp;

	KLD_DPF(FILE,
	    ("linker_file_register_sysctls: registering SYSCTLs for %s\n",
	    lf->filename));

	if (linker_file_lookup_set(lf, "sysctl_set", &start, &stop, NULL) != 0)
		return;

	sysctl_lock();
	for (oidp = start; oidp < stop; oidp++)
		sysctl_register_oid(*oidp);
	sysctl_unlock();
}

static void
linker_file_unregister_sysctls(linker_file_t lf)
{
	struct sysctl_oid **start, **stop, **oidp;

	KLD_DPF(FILE, ("linker_file_unregister_sysctls: registering SYSCTLs"
	    " for %s\n", lf->filename));

	if (linker_file_lookup_set(lf, "sysctl_set", &start, &stop, NULL) != 0)
		return;

	sysctl_lock();
	for (oidp = start; oidp < stop; oidp++)
		sysctl_unregister_oid(*oidp);
	sysctl_unlock();
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

static int
linker_load_file(const char *filename, linker_file_t *result)
{
	linker_class_t lc;
	linker_file_t lf;
	int foundfile, error;

	/* Refuse to load modules if securelevel raised */
	if (prison0.pr_securelevel > 0)
		return (EPERM);

	KLD_LOCK_ASSERT();
	lf = linker_find_file_by_name(filename);
	if (lf) {
		KLD_DPF(FILE, ("linker_load_file: file %s is already loaded,"
		    " incrementing refs\n", filename));
		*result = lf;
		lf->refs++;
		return (0);
	}
	foundfile = 0;
	error = 0;

	/*
	 * We do not need to protect (lock) classes here because there is
	 * no class registration past startup (SI_SUB_KLD, SI_ORDER_ANY)
	 * and there is no class deregistration mechanism at this time.
	 */
	TAILQ_FOREACH(lc, &classes, link) {
		KLD_DPF(FILE, ("linker_load_file: trying to load %s\n",
		    filename));
		error = LINKER_LOAD_FILE(lc, filename, &lf);
		/*
		 * If we got something other than ENOENT, then it exists but
		 * we cannot load it for some other reason.
		 */
		if (error != ENOENT)
			foundfile = 1;
		if (lf) {
			error = linker_file_register_modules(lf);
			if (error == EEXIST) {
				linker_file_unload(lf, LINKER_UNLOAD_FORCE);
				return (error);
			}
			KLD_UNLOCK();
			linker_file_register_sysctls(lf);
			linker_file_sysinit(lf);
			KLD_LOCK();
			lf->flags |= LINKER_FILE_LINKED;
			*result = lf;
			return (0);
		}
	}
	/*
	 * Less than ideal, but tells the user whether it failed to load or
	 * the module was not found.
	 */
	if (foundfile) {

		/*
		 * If the file type has not been recognized by the last try
		 * printout a message before to fail.
		 */
		if (error == ENOSYS)
			printf("linker_load_file: Unsupported file type\n");

		/*
		 * Format not recognized or otherwise unloadable.
		 * When loading a module that is statically built into
		 * the kernel EEXIST percolates back up as the return
		 * value.  Preserve this so that apps like sysinstall
		 * can recognize this special case and not post bogus
		 * dialog boxes.
		 */
		if (error != EEXIST)
			error = ENOEXEC;
	} else
		error = ENOENT;		/* Nothing found */
	return (error);
}

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

static int
linker_file_add_dependency(linker_file_t file, linker_file_t dep)
{
	linker_file_t *newdeps;

	KLD_LOCK_ASSERT();
	newdeps = malloc((file->ndeps + 1) * sizeof(linker_file_t *),
	    M_LINKER, M_WAITOK | M_ZERO);
	if (newdeps == NULL)
		return (ENOMEM);

	if (file->deps) {
		bcopy(file->deps, newdeps,
		    file->ndeps * sizeof(linker_file_t *));
		free(file->deps, M_LINKER);
	}
	file->deps = newdeps;
	file->deps[file->ndeps] = dep;
	file->ndeps++;
	KLD_DPF(FILE, ("linker_file_add_dependency:"
	    " adding %s as dependency for %s\n", 
	    dep->filename, file->filename));
	return (0);
}

int
linker_file_unload(linker_file_t file, int flags)
{
	module_t mod, next;
	modlist_t ml, nextml;
	struct common_symbol *cp;
	int error, i;

	/* Refuse to unload modules if securelevel raised. */
	if (prison0.pr_securelevel > 0)
		return (EPERM);

	KLD_LOCK_ASSERT();
	KLD_DPF(FILE, ("linker_file_unload: lf->refs=%d\n", file->refs));

	/* Easy case of just dropping a reference. */
	if (file->refs > 1) {
		file->refs--;
		return (0);
	}

	KLD_DPF(FILE, ("linker_file_unload: file is unloading,"
	    " informing modules\n"));

	/*
	 * Quiesce all the modules to give them a chance to veto the unload.
	 */
	MOD_SLOCK;
	for (mod = TAILQ_FIRST(&file->modules); mod;
	     mod = module_getfnext(mod)) {

		error = module_quiesce(mod);
		if (error != 0 && flags != LINKER_UNLOAD_FORCE) {
			KLD_DPF(FILE, ("linker_file_unload: module %s"
			    " vetoed unload\n", module_getname(mod)));
			/*
			 * XXX: Do we need to tell all the quiesced modules
			 * that they can resume work now via a new module
			 * event?
			 */
			MOD_SUNLOCK;
			return (error);
		}
	}
	MOD_SUNLOCK;

	/*
	 * Inform any modules associated with this file that they are
	 * being be unloaded.
	 */
	MOD_XLOCK;
	for (mod = TAILQ_FIRST(&file->modules); mod; mod = next) {
		next = module_getfnext(mod);
		MOD_XUNLOCK;

		/*
		 * Give the module a chance to veto the unload.
		 */
		if ((error = module_unload(mod)) != 0) {
			KLD_DPF(FILE, ("linker_file_unload: module %s"
			    " failed unload\n", module_getname(mod)));
			return (error);
		}
		MOD_XLOCK;
		module_release(mod);
	}
	MOD_XUNLOCK;

	TAILQ_FOREACH_SAFE(ml, &found_modules, link, nextml) {
		if (ml->container == file) {
			TAILQ_REMOVE(&found_modules, ml, link);
			free(ml, M_LINKER);
		}
	}

	/*
	 * Don't try to run SYSUNINITs if we are unloaded due to a
	 * link error.
	 */
	if (file->flags & LINKER_FILE_LINKED) {
		file->flags &= ~LINKER_FILE_LINKED;
		KLD_UNLOCK();
		linker_file_sysuninit(file);
		linker_file_unregister_sysctls(file);
		KLD_LOCK();
	}
	TAILQ_REMOVE(&linker_files, file, link);

	if (file->deps) {
		for (i = 0; i < file->ndeps; i++)
			linker_file_unload(file->deps[i], flags);
		free(file->deps, M_LINKER);
		file->deps = NULL;
	}
	while ((cp = STAILQ_FIRST(&file->common)) != NULL) {
		STAILQ_REMOVE_HEAD(&file->common, link);
		free(cp, M_LINKER);
	}

	LINKER_UNLOAD(file);
	if (file->filename) {
		free(file->filename, M_LINKER);
		file->filename = NULL;
	}
	if (file->pathname) {
		free(file->pathname, M_LINKER);
		file->pathname = NULL;
	}
	kobj_delete((kobj_t) file, M_LINKER);
	return (0);
}

/*
 * Syscalls.
 */
int
kern_kldload(struct thread *td, const char *file, int *fileid)
{
#ifdef HWPMC_HOOKS
	struct pmckern_map_in pkm;
#endif
	const char *kldname, *modname;
	linker_file_t lf;
	int error;

	if ((error = securelevel_gt(td->td_ucred, 0)) != 0)
		return (error);

	if ((error = priv_check(td, PRIV_KLD_LOAD)) != 0)
		return (error);

	/*
	 * It is possible that kldloaded module will attach a new ifnet,
	 * so vnet context must be set when this ocurs.
	 */
	CURVNET_SET(TD_TO_VNET(td));

	/*
	 * If file does not contain a qualified name or any dot in it
	 * (kldname.ko, or kldname.ver.ko) treat it as an interface
	 * name.
	 */
	if (index(file, '/') || index(file, '.')) {
		kldname = file;
		modname = NULL;
	} else {
		kldname = NULL;
		modname = file;
	}

	KLD_LOCK();
	error = linker_load_module(kldname, modname, NULL, NULL, &lf);
	if (error) {
		KLD_UNLOCK();
		goto done;
	}
	lf->userrefs++;
	if (fileid != NULL)
		*fileid = lf->id;
#ifdef HWPMC_HOOKS
	KLD_DOWNGRADE();
	pkm.pm_file = lf->filename;
	pkm.pm_address = (uintptr_t) lf->address;
	PMC_CALL_HOOK(td, PMC_FN_KLD_LOAD, (void *) &pkm);
	KLD_UNLOCK_READ();
#else
	KLD_UNLOCK();
#endif

done:
	CURVNET_RESTORE();
	return (error);
}

int
sys_kldload(struct thread *td, struct kldload_args *uap)
{
	char *pathname = NULL;
	int error, fileid;

	td->td_retval[0] = -1;

	pathname = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	error = copyinstr(uap->file, pathname, MAXPATHLEN, NULL);
	if (error == 0) {
		error = kern_kldload(td, pathname, &fileid);
		if (error == 0)
			td->td_retval[0] = fileid;
	}
	free(pathname, M_TEMP);
	return (error);
}

int
kern_kldunload(struct thread *td, int fileid, int flags)
{
#ifdef HWPMC_HOOKS
	struct pmckern_map_out pkm;
#endif
	linker_file_t lf;
	int error = 0;

	if ((error = securelevel_gt(td->td_ucred, 0)) != 0)
		return (error);

	if ((error = priv_check(td, PRIV_KLD_UNLOAD)) != 0)
		return (error);

	CURVNET_SET(TD_TO_VNET(td));
	KLD_LOCK();
	lf = linker_find_file_by_id(fileid);
	if (lf) {
		KLD_DPF(FILE, ("kldunload: lf->userrefs=%d\n", lf->userrefs));

		/* Check if there are DTrace probes enabled on this file. */
		if (lf->nenabled > 0) {
			printf("kldunload: attempt to unload file that has"
			    " DTrace probes enabled\n");
			error = EBUSY;
		} else if (lf->userrefs == 0) {
			/*
			 * XXX: maybe LINKER_UNLOAD_FORCE should override ?
			 */
			printf("kldunload: attempt to unload file that was"
			    " loaded by the kernel\n");
			error = EBUSY;
		} else {
#ifdef HWPMC_HOOKS
			/* Save data needed by hwpmc(4) before unloading. */
			pkm.pm_address = (uintptr_t) lf->address;
			pkm.pm_size = lf->size;
#endif
			lf->userrefs--;
			error = linker_file_unload(lf, flags);
			if (error)
				lf->userrefs++;
		}
	} else
		error = ENOENT;

#ifdef HWPMC_HOOKS
	if (error == 0) {
		KLD_DOWNGRADE();
		PMC_CALL_HOOK(td, PMC_FN_KLD_UNLOAD, (void *) &pkm);
		KLD_UNLOCK_READ();
	} else
		KLD_UNLOCK();
#else
	KLD_UNLOCK();
#endif
	CURVNET_RESTORE();
	return (error);
}

int
sys_kldunload(struct thread *td, struct kldunload_args *uap)
{

	return (kern_kldunload(td, uap->fileid, LINKER_UNLOAD_NORMAL));
}

int
sys_kldunloadf(struct thread *td, struct kldunloadf_args *uap)
{

	if (uap->flags != LINKER_UNLOAD_NORMAL &&
	    uap->flags != LINKER_UNLOAD_FORCE)
		return (EINVAL);
	return (kern_kldunload(td, uap->fileid, uap->flags));
}

int
sys_kldfind(struct thread *td, struct kldfind_args *uap)
{
	char *pathname;
	const char *filename;
	linker_file_t lf;
	int error;

#ifdef MAC
	error = mac_kld_check_stat(td->td_ucred);
	if (error)
		return (error);
#endif

	td->td_retval[0] = -1;

	pathname = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	if ((error = copyinstr(uap->file, pathname, MAXPATHLEN, NULL)) != 0)
		goto out;

	filename = linker_basename(pathname);
	KLD_LOCK();
	lf = linker_find_file_by_name(filename);
	if (lf)
		td->td_retval[0] = lf->id;
	else
		error = ENOENT;
	KLD_UNLOCK();
out:
	free(pathname, M_TEMP);
	return (error);
}

int
sys_kldnext(struct thread *td, struct kldnext_args *uap)
{
	linker_file_t lf;
	int error = 0;

#ifdef MAC
	error = mac_kld_check_stat(td->td_ucred);
	if (error)
		return (error);
#endif

	KLD_LOCK();
	if (uap->fileid == 0)
		lf = TAILQ_FIRST(&linker_files);
	else {
		lf = linker_find_file_by_id(uap->fileid);
		if (lf == NULL) {
			error = ENOENT;
			goto out;
		}
		lf = TAILQ_NEXT(lf, link);
	}

	/* Skip partially loaded files. */
	while (lf != NULL && !(lf->flags & LINKER_FILE_LINKED))
		lf = TAILQ_NEXT(lf, link);

	if (lf)
		td->td_retval[0] = lf->id;
	else
		td->td_retval[0] = 0;
out:
	KLD_UNLOCK();
	return (error);
}

int
sys_kldstat(struct thread *td, struct kldstat_args *uap)
{
	struct kld_file_stat stat;
	int error, version;

	/*
	 * Check the version of the user's structure.
	 */
	if ((error = copyin(&uap->stat->version, &version, sizeof(version)))
	    != 0)
		return (error);
	if (version != sizeof(struct kld_file_stat_1) &&
	    version != sizeof(struct kld_file_stat))
		return (EINVAL);

	error = kern_kldstat(td, uap->fileid, &stat);
	if (error != 0)
		return (error);
	return (copyout(&stat, uap->stat, version));
}

int
kern_kldstat(struct thread *td, int fileid, struct kld_file_stat *stat)
{
	linker_file_t lf;
	int namelen;
#ifdef MAC
	int error;

	error = mac_kld_check_stat(td->td_ucred);
	if (error)
		return (error);
#endif

	KLD_LOCK();
	lf = linker_find_file_by_id(fileid);
	if (lf == NULL) {
		KLD_UNLOCK();
		return (ENOENT);
	}

	/* Version 1 fields: */
	namelen = strlen(lf->filename) + 1;
	if (namelen > MAXPATHLEN)
		namelen = MAXPATHLEN;
	bcopy(lf->filename, &stat->name[0], namelen);
	stat->refs = lf->refs;
	stat->id = lf->id;
	stat->address = lf->address;
	stat->size = lf->size;
	/* Version 2 fields: */
	namelen = strlen(lf->pathname) + 1;
	if (namelen > MAXPATHLEN)
		namelen = MAXPATHLEN;
	bcopy(lf->pathname, &stat->pathname[0], namelen);
	KLD_UNLOCK();

	td->td_retval[0] = 0;
	return (0);
}

static modlist_t
modlist_lookup(const char *name, int ver)
{
	modlist_t mod;

	TAILQ_FOREACH(mod, &found_modules, link) {
		if (strcmp(mod->name, name) == 0 &&
		    (ver == 0 || mod->version == ver))
			return (mod);
	}
	return (NULL);
}

static modlist_t
modlist_lookup2(const char *name, struct mod_depend *verinfo)
{
	modlist_t mod, bestmod;
	int ver;

	if (verinfo == NULL)
		return (modlist_lookup(name, 0));
	bestmod = NULL;
	TAILQ_FOREACH(mod, &found_modules, link) {
		if (strcmp(mod->name, name) != 0)
			continue;
		ver = mod->version;
		if (ver == verinfo->md_ver_preferred)
			return (mod);
		if (ver >= verinfo->md_ver_minimum &&
		    ver <= verinfo->md_ver_maximum &&
		    (bestmod == NULL || ver > bestmod->version))
			bestmod = mod;
	}
	return (bestmod);
}

static char linker_path[MAXPATHLEN] = "/boot/kernel;/boot/modules";

SYSCTL_STRING(_kern, OID_AUTO, module_path, CTLFLAG_RW, linker_path,
    sizeof(linker_path), "module load search path");


static char *
linker_lookup_file(const char *path, int pathlen, const char *name,
    int namelen, struct vattr *vap)
{

	return (NULL);
}

/*
 * Lookup KLD which contains requested module in the all directories.
 */
static char *
linker_search_module(const char *modname, int modnamelen,
    struct mod_depend *verinfo)
{
	char *cp, *ep, *result;

	/*
	 * traverse the linker path
	 */
	for (cp = linker_path; *cp; cp = ep + 1) {
		/* find the end of this component */
		for (ep = cp; (*ep != 0) && (*ep != ';'); ep++);
#ifdef notyet
		result = linker_hints_lookup(cp, ep - cp, modname,
		    modnamelen, verinfo);
		if (result != NULL)
			return (result);
#else
		result = NULL;
#endif
		if (*ep == 0)
			break;
	}
	return (NULL);
}

/*
 * Search for module in all directories listed in the linker_path.
 */
static char *
linker_search_kld(const char *name)
{
	char *cp, *ep, *result;
	int len;

	/* qualified at all? */
	if (index(name, '/'))
		return (linker_strdup(name));

	/* traverse the linker path */
	len = strlen(name);
	for (ep = linker_path; *ep; ep++) {
		cp = ep;
		/* find the end of this component */
		for (; *ep != 0 && *ep != ';'; ep++);
		result = linker_lookup_file(cp, ep - cp, name, len, NULL);
		if (result != NULL)
			return (result);
	}
	return (NULL);
}

/*
 * Find a file which contains given module and load it, if "parent" is not
 * NULL, register a reference to it.
 */
static int
linker_load_module(const char *kldname, const char *modname,
    struct linker_file *parent, struct mod_depend *verinfo,
    struct linker_file **lfpp)
{
	linker_file_t lfdep;
	const char *filename;
	char *pathname;
	int error;

	KLD_LOCK_ASSERT();
	if (modname == NULL) {
		/*
 		 * We have to load KLD
 		 */
		KASSERT(verinfo == NULL, ("linker_load_module: verinfo"
		    " is not NULL"));
		pathname = linker_search_kld(kldname);
	} else {
		if (modlist_lookup2(modname, verinfo) != NULL)
			return (EEXIST);
		if (kldname != NULL)
			pathname = linker_strdup(kldname);
		else if (rootvnode == NULL)
			pathname = NULL;
		else
			/*
			 * Need to find a KLD with required module
			 */
			pathname = linker_search_module(modname,
			    strlen(modname), verinfo);
	}
	if (pathname == NULL)
		return (ENOENT);

	/*
	 * Can't load more than one file with the same basename XXX:
	 * Actually it should be possible to have multiple KLDs with
	 * the same basename but different path because they can
	 * provide different versions of the same modules.
	 */
	filename = linker_basename(pathname);
	if (linker_find_file_by_name(filename))
		error = EEXIST;
	else do {
		error = linker_load_file(pathname, &lfdep);
		if (error)
			break;
		if (modname && verinfo &&
		    modlist_lookup2(modname, verinfo) == NULL) {
			linker_file_unload(lfdep, LINKER_UNLOAD_FORCE);
			error = ENOENT;
			break;
		}
		if (parent) {
			error = linker_file_add_dependency(parent, lfdep);
			if (error)
				break;
		}
		if (lfpp)
			*lfpp = lfdep;
	} while (0);
	free(pathname, M_LINKER);
	return (error);
}
