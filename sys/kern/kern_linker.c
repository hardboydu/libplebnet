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
 *
 * $FreeBSD$
 */

#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/linker.h>
#include <sys/fcntl.h>
#include <sys/libkern.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/sysctl.h>


#include "linker_if.h"

#ifdef KLD_DEBUG
int kld_debug = 0;
#endif

static char *linker_search_path(const char *name);
static const char *linker_basename(const char* path);

/* Metadata from the static kernel */
SET_DECLARE(modmetadata_set, struct mod_metadata);

MALLOC_DEFINE(M_LINKER, "linker", "kernel linker");

linker_file_t linker_kernel_file;

static struct lock lock;	/* lock for the file list */
static linker_class_list_t classes;
static linker_file_list_t linker_files;
static int next_file_id = 1;

/* XXX wrong name; we're looking at version provision tags here, not modules */
typedef TAILQ_HEAD(, modlist) modlisthead_t;
struct modlist {
    TAILQ_ENTRY(modlist) link;		/* chain together all modules */
    linker_file_t	container;
    const char		*name;
    int			version;
};
typedef struct modlist	*modlist_t;
static modlisthead_t	found_modules;

static char *
linker_strdup(const char *str)
{
    char	*result;

    if ((result = malloc((strlen(str) + 1), M_LINKER, M_WAITOK)) != NULL)
	strcpy(result, str);
    return(result);
}

static void
linker_init(void* arg)
{
    lockinit(&lock, PVM, "klink", 0, 0);
    TAILQ_INIT(&classes);
    TAILQ_INIT(&linker_files);
}

SYSINIT(linker, SI_SUB_KLD, SI_ORDER_FIRST, linker_init, 0);

int
linker_add_class(linker_class_t lc)
{
    kobj_class_compile((kobj_class_t) lc);
    TAILQ_INSERT_TAIL(&classes, lc, link);
    return 0;
}

static void
linker_file_sysinit(linker_file_t lf)
{
    struct sysinit** start, ** stop;
    struct sysinit** sipp;
    struct sysinit** xipp;
    struct sysinit* save;

    KLD_DPF(FILE, ("linker_file_sysinit: calling SYSINITs for %s\n",
		   lf->filename));

    if (linker_file_lookup_set(lf, "sysinit_set", &start, &stop, NULL) != 0)
	return;
    /*
     * Perform a bubble sort of the system initialization objects by
     * their subsystem (primary key) and order (secondary key).
     *
     * Since some things care about execution order, this is the
     * operation which ensures continued function.
     */
    for (sipp = start; sipp < stop; sipp++) {
	for (xipp = sipp + 1; xipp < stop; xipp++) {
	    if ((*sipp)->subsystem < (*xipp)->subsystem ||
		 ((*sipp)->subsystem == (*xipp)->subsystem &&
		  (*sipp)->order <= (*xipp)->order))
		continue;	/* skip*/
	    save = *sipp;
	    *sipp = *xipp;
	    *xipp = save;
	}
    }


    /*
     * Traverse the (now) ordered list of system initialization tasks.
     * Perform each task, and continue on to the next task.
     */
    for (sipp = start; sipp < stop; sipp++) {
	if ((*sipp)->subsystem == SI_SUB_DUMMY)
	    continue;	/* skip dummy task(s)*/

	/* Call function */
	(*((*sipp)->func))((*sipp)->udata);
    }
}

static void
linker_file_sysuninit(linker_file_t lf)
{
    struct sysinit** start, ** stop;
    struct sysinit** sipp;
    struct sysinit** xipp;
    struct sysinit* save;

    KLD_DPF(FILE, ("linker_file_sysuninit: calling SYSUNINITs for %s\n",
		   lf->filename));

    if (linker_file_lookup_set(lf, "sysuninit_set", &start, &stop, NULL) != 0)
	return;

    /*
     * Perform a reverse bubble sort of the system initialization objects
     * by their subsystem (primary key) and order (secondary key).
     *
     * Since some things care about execution order, this is the
     * operation which ensures continued function.
     */
    for (sipp = start; sipp < stop; sipp++) {
	for (xipp = sipp + 1; xipp < stop; xipp++) {
	    if ((*sipp)->subsystem > (*xipp)->subsystem ||
		 ((*sipp)->subsystem == (*xipp)->subsystem &&
		  (*sipp)->order >= (*xipp)->order))
		continue;	/* skip*/
	    save = *sipp;
	    *sipp = *xipp;
	    *xipp = save;
	}
    }

    /*
     * Traverse the (now) ordered list of system initialization tasks.
     * Perform each task, and continue on to the next task.
     */
    for (sipp = start; sipp < stop; sipp++) {
	if ((*sipp)->subsystem == SI_SUB_DUMMY)
	    continue;	/* skip dummy task(s)*/

	/* Call function */
	(*((*sipp)->func))((*sipp)->udata);
    }
}

static void
linker_file_register_sysctls(linker_file_t lf)
{
    struct sysctl_oid **start, **stop, **oidp;

    KLD_DPF(FILE, ("linker_file_register_sysctls: registering SYSCTLs for %s\n",
		   lf->filename));

    if (linker_file_lookup_set(lf, "sysctl_set", &start, &stop, NULL) != 0)
	return;

    for (oidp = start; oidp < stop; oidp++)
	sysctl_register_oid(*oidp);
}

static void
linker_file_unregister_sysctls(linker_file_t lf)
{
    struct sysctl_oid **start, **stop, **oidp;

    KLD_DPF(FILE, ("linker_file_unregister_sysctls: registering SYSCTLs for %s\n",
		   lf->filename));

    if (linker_file_lookup_set(lf, "sysctl_set", &start, &stop, NULL) != 0)
	return;

    for (oidp = start; oidp < stop; oidp++)
	sysctl_unregister_oid(*oidp);
}

static int
linker_file_register_modules(linker_file_t lf)
{
    int error;
    struct mod_metadata **start, **stop;
    struct mod_metadata **mdp;
    const moduledata_t *moddata;

    KLD_DPF(FILE, ("linker_file_register_modules: registering modules in %s\n",
		   lf->filename));

    if (linker_file_lookup_set(lf, "modmetadata_set", &start, &stop, 0) != 0) {
	/*
	 * This fallback should be unnecessary, but if we get booted from
	 * boot2 instead of loader and we are missing our metadata then
	 * we have to try the best we can.
	 */
	if (lf == linker_kernel_file) {
	    start = SET_BEGIN(modmetadata_set);
	    stop = SET_LIMIT(modmetadata_set);
	} else {
	    return 0;
	}
    }
    for (mdp = start; mdp < stop; mdp++) {
	if ((*mdp)->md_type != MDT_MODULE)
	    continue;
	moddata = (*mdp)->md_data;
	KLD_DPF(FILE, ("Registering module %s in %s\n",
             moddata->name, lf->filename));
	if (module_lookupbyname(moddata->name) != NULL) {
	    printf("Warning: module %s already exists\n", moddata->name);
	    continue;	/* or return a error ? */
	}
	error = module_register(moddata, lf);
	if (error)
	    printf("Module %s failed to register: %d\n", moddata->name, error);
    }
    return 0;
}

static void
linker_init_kernel_modules(void)
{
    linker_file_register_modules(linker_kernel_file);
}

SYSINIT(linker_kernel, SI_SUB_KLD, SI_ORDER_ANY, linker_init_kernel_modules, 0);

int
linker_load_file(const char* filename, linker_file_t* result)
{
    linker_class_t lc;
    linker_file_t lf;
    int foundfile, error = 0;

    /* Refuse to load modules if securelevel raised */
    if (securelevel > 0)
	return EPERM; 

    lf = linker_find_file_by_name(filename);
    if (lf) {
	KLD_DPF(FILE, ("linker_load_file: file %s is already loaded, incrementing refs\n", filename));
	*result = lf;
	lf->refs++;
	goto out;
    }

    lf = NULL;
    foundfile = 0;
    TAILQ_FOREACH(lc, &classes, link) {
	KLD_DPF(FILE, ("linker_load_file: trying to load %s\n",
		       filename));
	error = LINKER_LOAD_FILE(lc, filename, &lf);
	/*
	 * If we got something other than ENOENT, then it exists but we cannot
	 * load it for some other reason.
	 */
	if (error != ENOENT)
	    foundfile = 1;
	if (lf) {
	    linker_file_register_modules(lf);
	    linker_file_register_sysctls(lf);
	    linker_file_sysinit(lf);
	    lf->flags |= LINKER_FILE_LINKED;

	    *result = lf;
	    error = 0;
	    goto out;
	}
    }
    /*
     * Less than ideal, but tells the user whether it failed to load or
     * the module was not found.
     */
    if (foundfile)
	error = ENOEXEC;	/* Format not recognised (or unloadable) */
    else
	error = ENOENT;		/* Nothing found */

out:
    return error;
}

int
linker_reference_module(const char *modname, linker_file_t *result)
{
    char *pathname;
    int res;

    /*
     * There will be a system to look up or guess a file name from
     * a module name.
     * For now we just try to load a file with the same name.
     */
    if ((pathname = linker_search_path(modname)) == NULL)
	return (ENOENT);

    /*
     * If the module is already loaded or built into the kernel,
     * linker_load_file() simply bumps it's refcount.
     */
    res = linker_load_file(pathname, result);

    free(pathname, M_LINKER);

    return (res);
}

linker_file_t
linker_find_file_by_name(const char* filename)
{
    linker_file_t lf = 0;
    char *koname;

    koname = malloc(strlen(filename) + 4, M_LINKER, M_WAITOK);
    if (koname == NULL)
	goto out;
    sprintf(koname, "%s.ko", filename);

    lockmgr(&lock, LK_SHARED, 0, curproc);
    TAILQ_FOREACH(lf, &linker_files, link) {
	if (!strcmp(lf->filename, koname))
	    break;
	if (!strcmp(lf->filename, filename))
	    break;
    }
    lockmgr(&lock, LK_RELEASE, 0, curproc);

out:
    if (koname)
	free(koname, M_LINKER);
    return lf;
}

linker_file_t
linker_find_file_by_id(int fileid)
{
    linker_file_t lf = 0;

    lockmgr(&lock, LK_SHARED, 0, curproc);
    TAILQ_FOREACH(lf, &linker_files, link)
	if (lf->id == fileid)
	    break;
    lockmgr(&lock, LK_RELEASE, 0, curproc);

    return lf;
}

linker_file_t
linker_make_file(const char* pathname, linker_class_t lc)
{
    linker_file_t lf = 0;
    const char *filename;

    filename = linker_basename(pathname);

    KLD_DPF(FILE, ("linker_make_file: new file, filename=%s\n", filename));
    lockmgr(&lock, LK_EXCLUSIVE, 0, curproc);
    lf = (linker_file_t) kobj_create((kobj_class_t) lc, M_LINKER, M_WAITOK);
    if (!lf)
	goto out;

    lf->refs = 1;
    lf->userrefs = 0;
    lf->flags = 0;
    lf->filename = linker_strdup(filename);
    lf->id = next_file_id++;
    lf->ndeps = 0;
    lf->deps = NULL;
    STAILQ_INIT(&lf->common);
    TAILQ_INIT(&lf->modules);

    TAILQ_INSERT_TAIL(&linker_files, lf, link);

out:
    lockmgr(&lock, LK_RELEASE, 0, curproc);
    return lf;
}

int
linker_file_unload(linker_file_t file)
{
    module_t mod, next;
    modlist_t ml, nextml;
    struct common_symbol* cp;
    int error = 0;
    int i;

    /* Refuse to unload modules if securelevel raised */
    if (securelevel > 0)
	return EPERM; 

    KLD_DPF(FILE, ("linker_file_unload: lf->refs=%d\n", file->refs));
    lockmgr(&lock, LK_EXCLUSIVE, 0, curproc);
    if (file->refs == 1) {
	KLD_DPF(FILE, ("linker_file_unload: file is unloading, informing modules\n"));
	/*
	 * Inform any modules associated with this file.
	 */
	for (mod = TAILQ_FIRST(&file->modules); mod; mod = next) {
	    next = module_getfnext(mod);

	    /*
	     * Give the module a chance to veto the unload.
	     */
	    if ((error = module_unload(mod)) != 0) {
		KLD_DPF(FILE, ("linker_file_unload: module %x vetoes unload\n",
			       mod));
		lockmgr(&lock, LK_RELEASE, 0, curproc);
		goto out;
	    }

	    module_release(mod);
	}
    }

    file->refs--;
    if (file->refs > 0) {
	lockmgr(&lock, LK_RELEASE, 0, curproc);
	goto out;
    }

    for (ml = TAILQ_FIRST(&found_modules); ml; ml = nextml) {
	nextml = TAILQ_NEXT(ml, link);
	if (ml->container == file) {
	    TAILQ_REMOVE(&found_modules, ml, link);
	}
    }

    /* Don't try to run SYSUNINITs if we are unloaded due to a link error */
    if (file->flags & LINKER_FILE_LINKED) {
	linker_file_sysuninit(file);
	linker_file_unregister_sysctls(file);
    }

    TAILQ_REMOVE(&linker_files, file, link);
    lockmgr(&lock, LK_RELEASE, 0, curproc);

    if (file->deps) {
	for (i = 0; i < file->ndeps; i++)
	    linker_file_unload(file->deps[i]);
	free(file->deps, M_LINKER);
	file->deps = NULL;
    }

    for (cp = STAILQ_FIRST(&file->common); cp;
	 cp = STAILQ_FIRST(&file->common)) {
	STAILQ_REMOVE(&file->common, cp, common_symbol, link);
	free(cp, M_LINKER);
    }

    LINKER_UNLOAD(file);
    if (file->filename) {
	free(file->filename, M_LINKER);
	file->filename = NULL;
    }
    kobj_delete((kobj_t) file, M_LINKER);

out:
    return error;
}

int
linker_file_add_dependancy(linker_file_t file, linker_file_t dep)
{
    linker_file_t* newdeps;

    newdeps = malloc((file->ndeps + 1) * sizeof(linker_file_t*),
		     M_LINKER, M_WAITOK | M_ZERO);
    if (newdeps == NULL)
	return ENOMEM;

    if (file->deps) {
	bcopy(file->deps, newdeps, file->ndeps * sizeof(linker_file_t*));
	free(file->deps, M_LINKER);
    }
    file->deps = newdeps;
    file->deps[file->ndeps] = dep;
    file->ndeps++;

    return 0;
}

/*
 * Locate a linker set and its contents.
 * This is a helper function to avoid linker_if.h exposure elsewhere.
 * Note: firstp and lastp are really void ***
 */
int
linker_file_lookup_set(linker_file_t file, const char *name,
		       void *firstp, void *lastp, int *countp)
{

    return LINKER_LOOKUP_SET(file, name, firstp, lastp, countp);
}

caddr_t
linker_file_lookup_symbol(linker_file_t file, const char* name, int deps)
{
    c_linker_sym_t sym;
    linker_symval_t symval;
    caddr_t address;
    size_t common_size = 0;
    int i;

    KLD_DPF(SYM, ("linker_file_lookup_symbol: file=%x, name=%s, deps=%d\n",
		  file, name, deps));

    if (LINKER_LOOKUP_SYMBOL(file, name, &sym) == 0) {
	LINKER_SYMBOL_VALUES(file, sym, &symval);
	if (symval.value == 0)
	    /*
	     * For commons, first look them up in the dependancies and
	     * only allocate space if not found there.
	     */
	    common_size = symval.size;
	else {
	    KLD_DPF(SYM, ("linker_file_lookup_symbol: symbol.value=%x\n", symval.value));
	    return symval.value;
	}
    }

    if (deps) {
	for (i = 0; i < file->ndeps; i++) {
	    address = linker_file_lookup_symbol(file->deps[i], name, 0);
	    if (address) {
		KLD_DPF(SYM, ("linker_file_lookup_symbol: deps value=%x\n", address));
		return address;
	    }
	}
    }

    if (common_size > 0) {
	/*
	 * This is a common symbol which was not found in the
	 * dependancies.  We maintain a simple common symbol table in
	 * the file object.
	 */
	struct common_symbol* cp;

	STAILQ_FOREACH(cp, &file->common, link)
	    if (!strcmp(cp->name, name)) {
		KLD_DPF(SYM, ("linker_file_lookup_symbol: old common value=%x\n", cp->address));
		return cp->address;
	    }

	/*
	 * Round the symbol size up to align.
	 */
	common_size = (common_size + sizeof(int) - 1) & -sizeof(int);
	cp = malloc(sizeof(struct common_symbol)
		    + common_size
		    + strlen(name) + 1,
		    M_LINKER, M_WAITOK | M_ZERO);
	if (!cp) {
	    KLD_DPF(SYM, ("linker_file_lookup_symbol: nomem\n"));
	    return 0;
	}

	cp->address = (caddr_t) (cp + 1);
	cp->name = cp->address + common_size;
	strcpy(cp->name, name);
	bzero(cp->address, common_size);
	STAILQ_INSERT_TAIL(&file->common, cp, link);

	KLD_DPF(SYM, ("linker_file_lookup_symbol: new common value=%x\n", cp->address));
	return cp->address;
    }

    KLD_DPF(SYM, ("linker_file_lookup_symbol: fail\n"));
    return 0;
}

#ifdef DDB
/*
 * DDB Helpers.  DDB has to look across multiple files with their own
 * symbol tables and string tables.
 *
 * Note that we do not obey list locking protocols here.  We really don't
 * need DDB to hang because somebody's got the lock held.  We'll take the
 * chance that the files list is inconsistant instead.
 */

int
linker_ddb_lookup(const char *symstr, c_linker_sym_t *sym)
{
    linker_file_t lf;

    TAILQ_FOREACH(lf, &linker_files, link) {
	if (LINKER_LOOKUP_SYMBOL(lf, symstr, sym) == 0)
	    return 0;
    }
    return ENOENT;
}

int
linker_ddb_search_symbol(caddr_t value, c_linker_sym_t *sym, long *diffp)
{
    linker_file_t lf;
    u_long off = (uintptr_t)value;
    u_long diff, bestdiff;
    c_linker_sym_t best;
    c_linker_sym_t es;

    best = 0;
    bestdiff = off;
    TAILQ_FOREACH(lf, &linker_files, link) {
	if (LINKER_SEARCH_SYMBOL(lf, value, &es, &diff) != 0)
	    continue;
	if (es != 0 && diff < bestdiff) {
	    best = es;
	    bestdiff = diff;
	}
	if (bestdiff == 0)
	    break;
    }
    if (best) {
	*sym = best;
	*diffp = bestdiff;
	return 0;
    } else {
	*sym = 0;
	*diffp = off;
	return ENOENT;
    }
}

int
linker_ddb_symbol_values(c_linker_sym_t sym, linker_symval_t *symval)
{
    linker_file_t lf;

    TAILQ_FOREACH(lf, &linker_files, link) {
	if (LINKER_SYMBOL_VALUES(lf, sym, symval) == 0)
	    return 0;
    }
    return ENOENT;
}

#endif

/*
 * Syscalls.
 */

int
kldload(struct proc* p, struct kldload_args* uap)
{
    char* pathname, *realpath;
    const char *filename;
    linker_file_t lf;
    int error = 0;

    p->p_retval[0] = -1;

    if (securelevel > 0)	/* redundant, but that's OK */
	return EPERM;

    if ((error = suser(p)) != 0)
	return error;

    realpath = NULL;
    pathname = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
    if ((error = copyinstr(SCARG(uap, file), pathname, MAXPATHLEN, NULL)) != 0)
	goto out;

    realpath = linker_search_path(pathname);
    if (realpath == NULL) {
	error = ENOENT;
	goto out;
    }
    /* Can't load more than one file with the same name */
    filename = linker_basename(realpath);
    if (linker_find_file_by_name(filename)) {
	error = EEXIST;
	goto out;
    }

    if ((error = linker_load_file(realpath, &lf)) != 0)
	goto out;

    lf->userrefs++;
    p->p_retval[0] = lf->id;

out:
    if (pathname)
	free(pathname, M_TEMP);
    if (realpath)
	free(realpath, M_LINKER);
    return error;
}

int
kldunload(struct proc* p, struct kldunload_args* uap)
{
    linker_file_t lf;
    int error = 0;

    if (securelevel > 0)	/* redundant, but that's OK */
	return EPERM;

    if ((error = suser(p)) != 0)
	return error;

    lf = linker_find_file_by_id(SCARG(uap, fileid));
    if (lf) {
	KLD_DPF(FILE, ("kldunload: lf->userrefs=%d\n", lf->userrefs));
	if (lf->userrefs == 0) {
	    printf("kldunload: attempt to unload file that was loaded by the kernel\n");
	    error = EBUSY;
	    goto out;
	}
	lf->userrefs--;
	error = linker_file_unload(lf);
	if (error)
	    lf->userrefs++;
    } else
	error = ENOENT;

out:
    return error;
}

int
kldfind(struct proc* p, struct kldfind_args* uap)
{
    char* pathname;
    const char *filename;
    linker_file_t lf;
    int error = 0;

    p->p_retval[0] = -1;

    pathname = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
    if ((error = copyinstr(SCARG(uap, file), pathname, MAXPATHLEN, NULL)) != 0)
	goto out;

    filename = linker_basename(pathname);

    lf = linker_find_file_by_name(filename);
    if (lf)
	p->p_retval[0] = lf->id;
    else
	error = ENOENT;

out:
    if (pathname)
	free(pathname, M_TEMP);
    return error;
}

int
kldnext(struct proc* p, struct kldnext_args* uap)
{
    linker_file_t lf;
    int error = 0;

    if (SCARG(uap, fileid) == 0) {
	if (TAILQ_FIRST(&linker_files))
	    p->p_retval[0] = TAILQ_FIRST(&linker_files)->id;
	else
	    p->p_retval[0] = 0;
	return 0;
    }

    lf = linker_find_file_by_id(SCARG(uap, fileid));
    if (lf) {
	if (TAILQ_NEXT(lf, link))
	    p->p_retval[0] = TAILQ_NEXT(lf, link)->id;
	else
	    p->p_retval[0] = 0;
    } else
	error = ENOENT;

    return error;
}

int
kldstat(struct proc* p, struct kldstat_args* uap)
{
    linker_file_t lf;
    int error = 0;
    int version;
    struct kld_file_stat* stat;
    int namelen;

    lf = linker_find_file_by_id(SCARG(uap, fileid));
    if (!lf) {
	error = ENOENT;
	goto out;
    }

    stat = SCARG(uap, stat);

    /*
     * Check the version of the user's structure.
     */
    if ((error = copyin(&stat->version, &version, sizeof(version))) != 0)
	goto out;
    if (version != sizeof(struct kld_file_stat)) {
	error = EINVAL;
	goto out;
    }

    namelen = strlen(lf->filename) + 1;
    if (namelen > MAXPATHLEN)
	namelen = MAXPATHLEN;
    if ((error = copyout(lf->filename, &stat->name[0], namelen)) != 0)
	goto out;
    if ((error = copyout(&lf->refs, &stat->refs, sizeof(int))) != 0)
	goto out;
    if ((error = copyout(&lf->id, &stat->id, sizeof(int))) != 0)
	goto out;
    if ((error = copyout(&lf->address, &stat->address, sizeof(caddr_t))) != 0)
	goto out;
    if ((error = copyout(&lf->size, &stat->size, sizeof(size_t))) != 0)
	goto out;

    p->p_retval[0] = 0;

out:
    return error;
}

int
kldfirstmod(struct proc* p, struct kldfirstmod_args* uap)
{
    linker_file_t lf;
    int error = 0;

    lf = linker_find_file_by_id(SCARG(uap, fileid));
    if (lf) {
	if (TAILQ_FIRST(&lf->modules))
	    p->p_retval[0] = module_getid(TAILQ_FIRST(&lf->modules));
	else
	    p->p_retval[0] = 0;
    } else
	error = ENOENT;

    return error;
}

int
kldsym(struct proc *p, struct kldsym_args *uap)
{
    char *symstr = NULL;
    c_linker_sym_t sym;
    linker_symval_t symval;
    linker_file_t lf;
    struct kld_sym_lookup lookup;
    int error = 0;

    if ((error = copyin(SCARG(uap, data), &lookup, sizeof(lookup))) != 0)
	goto out;
    if (lookup.version != sizeof(lookup) || SCARG(uap, cmd) != KLDSYM_LOOKUP) {
	error = EINVAL;
	goto out;
    }

    symstr = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
    if ((error = copyinstr(lookup.symname, symstr, MAXPATHLEN, NULL)) != 0)
	goto out;

    if (SCARG(uap, fileid) != 0) {
	lf = linker_find_file_by_id(SCARG(uap, fileid));
	if (lf == NULL) {
	    error = ENOENT;
	    goto out;
	}
	if (LINKER_LOOKUP_SYMBOL(lf, symstr, &sym) == 0 &&
	    LINKER_SYMBOL_VALUES(lf, sym, &symval) == 0) {
	    lookup.symvalue = (uintptr_t)symval.value;
	    lookup.symsize = symval.size;
	    error = copyout(&lookup, SCARG(uap, data), sizeof(lookup));
	} else
	    error = ENOENT;
    } else {
	TAILQ_FOREACH(lf, &linker_files, link) {
	    if (LINKER_LOOKUP_SYMBOL(lf, symstr, &sym) == 0 &&
		LINKER_SYMBOL_VALUES(lf, sym, &symval) == 0) {
		lookup.symvalue = (uintptr_t)symval.value;
		lookup.symsize = symval.size;
		error = copyout(&lookup, SCARG(uap, data), sizeof(lookup));
		break;
	    }
	}
	if (!lf)
	    error = ENOENT;
    }
out:
    if (symstr)
	free(symstr, M_TEMP);
    return error;
}

/*
 * Preloaded module support
 */

static modlist_t
modlist_lookup(const char *name, int ver)
{
    modlist_t mod;

    TAILQ_FOREACH(mod, &found_modules, link) {
	if (strcmp(mod->name, name) == 0 && (ver == 0 || mod->version == ver))
	    return mod;
    }
    return NULL;
}

static modlist_t
modlist_newmodule(const char *modname, int version, linker_file_t container)
{
    modlist_t mod;

    mod = malloc(sizeof(struct modlist), M_LINKER, M_NOWAIT);
    if (mod == NULL)
	panic("no memory for module list");
    bzero(mod, sizeof(*mod));
    mod->container = container;
    mod->name = modname;
    mod->version = version;
    TAILQ_INSERT_TAIL(&found_modules, mod, link);
    return mod;
}

/*
 * This routine is cheap and nasty but will work for data pointers.
 */
static void *
linker_reloc_ptr(linker_file_t lf, const void *offset)
{
	return lf->address + (uintptr_t)offset;
}

/*
 * Dereference MDT_VERSION metadata into module name and version
 */
static void
linker_mdt_version(linker_file_t lf, struct mod_metadata *mp,
	const char **modname, int *version)
{
    struct mod_version *mvp;

    if (modname)
	*modname = linker_reloc_ptr(lf, mp->md_cval);
    if (version) {
	mvp = linker_reloc_ptr(lf, mp->md_data);
	*version = mvp->mv_version;
    }
}

/*
 * Dereference MDT_DEPEND metadata into module name and mod_depend structure
 */
static void
linker_mdt_depend(linker_file_t lf, struct mod_metadata *mp,
	const char **modname, struct mod_depend **verinfo)
{

    if (modname)
	*modname = linker_reloc_ptr(lf, mp->md_cval);
    if (verinfo)
	*verinfo = linker_reloc_ptr(lf, mp->md_data);
}

static void
linker_addmodules(linker_file_t lf, struct mod_metadata **start,
	struct mod_metadata **stop, int preload)
{
    struct mod_metadata	*mp, **mdp;
    const char *modname;
    int ver;

    for (mdp = start; mdp < stop; mdp++) {
	if (preload)
	    mp = *mdp;
	else
	    mp = linker_reloc_ptr(lf, *mdp);
	if (mp->md_type != MDT_VERSION)
	    continue;
	if (preload) {
	    modname = mp->md_cval;
	    ver = ((struct mod_version*)mp->md_data)->mv_version;
	} else
	    linker_mdt_version(lf, mp, &modname, &ver);
	if (modlist_lookup(modname, ver) != NULL) {
	    printf("module %s already present!\n", modname);
	    /* XXX what can we do? this is a build error. :-( */
	    continue;
	}
	modlist_newmodule(modname, ver, lf);
    }
}

static void
linker_preload(void* arg)
{
    caddr_t		modptr;
    const char		*modname, *nmodname;
    char		*modtype;
    linker_file_t	lf;
    linker_class_t	lc;
    int			error;
    linker_file_list_t	loaded_files;
    linker_file_list_t	depended_files;
    struct mod_metadata	*mp, *nmp;
    struct mod_metadata **start, **stop, **mdp, **nmdp;
    struct mod_depend	*verinfo;
    int			nver;
    int			resolves;
    modlist_t		mod;
    struct sysinit	**si_start, **si_stop;

    TAILQ_INIT(&loaded_files);
    TAILQ_INIT(&depended_files);
    TAILQ_INIT(&found_modules);
    error = 0;

    modptr = NULL;
    while ((modptr = preload_search_next_name(modptr)) != NULL) {
	modname = (char *)preload_search_info(modptr, MODINFO_NAME);
	modtype = (char *)preload_search_info(modptr, MODINFO_TYPE);
	if (modname == NULL) {
	    printf("Preloaded module at %p does not have a name!\n", modptr);
	    continue;
	}
	if (modtype == NULL) {
	    printf("Preloaded module at %p does not have a type!\n", modptr);
	    continue;
	}
	printf("Preloaded %s \"%s\" at %p.\n", modtype, modname, modptr);
	lf = NULL;
	TAILQ_FOREACH(lc, &classes, link) {
	    error = LINKER_LINK_PRELOAD(lc, modname, &lf);
	    if (error) {
		lf = NULL;
		break;
	    }
	}
	if (lf)
	    TAILQ_INSERT_TAIL(&loaded_files, lf, loaded);
    }

    /*
     * First get a list of stuff in the kernel.
     */
    if (linker_file_lookup_set(linker_kernel_file, MDT_SETNAME, &start, &stop,
			       NULL) == 0)
	linker_addmodules(linker_kernel_file, start, stop, 1);

    /*
     * this is a once-off kinky bubble sort
     * resolve relocation dependency requirements
     */
restart:
    TAILQ_FOREACH(lf, &loaded_files, loaded) {
	error = linker_file_lookup_set(lf, MDT_SETNAME, &start, &stop, NULL);
	/*
	 * First, look to see if we would successfully link with this stuff.
	 */
	resolves = 1;	/* unless we know otherwise */
	if (!error) {
	    for (mdp = start; mdp < stop; mdp++) {
		mp = linker_reloc_ptr(lf, *mdp);
		if (mp->md_type != MDT_DEPEND)
		    continue;
		linker_mdt_depend(lf, mp, &modname, &verinfo);
		for (nmdp = start; nmdp < stop; nmdp++) {
		    nmp = linker_reloc_ptr(lf, *nmdp);
		    if (nmp->md_type != MDT_VERSION)
			continue;
		    linker_mdt_version(lf, nmp, &nmodname, NULL);
		    nmodname = linker_reloc_ptr(lf, nmp->md_cval);
		    if (strcmp(modname, nmodname) == 0)
			break;
		}
		if (nmdp < stop)		/* it's a self reference */
		    continue;
		if (modlist_lookup(modname, 0) == NULL) {
		    /* ok, the module isn't here yet, we are not finished */
		    resolves = 0;
		}
	    }
	}
	/*
	 * OK, if we found our modules, we can link.  So, "provide" the
	 * modules inside and add it to the end of the link order list.
	 */
	if (resolves) {
	    if (!error) {
		for (mdp = start; mdp < stop; mdp++) {
		    mp = linker_reloc_ptr(lf, *mdp);
		    if (mp->md_type != MDT_VERSION)
			continue;
		    linker_mdt_version(lf, mp, &modname, &nver);
		    if (modlist_lookup(modname, nver) != NULL) {
			printf("module %s already present!\n", modname);
			linker_file_unload(lf);
			TAILQ_REMOVE(&loaded_files, lf, loaded);
			goto restart;	/* we changed the tailq next ptr */
		    }
		    modlist_newmodule(modname, nver, lf);
		}
	    }
	    TAILQ_REMOVE(&loaded_files, lf, loaded);
	    TAILQ_INSERT_TAIL(&depended_files, lf, loaded);
	    /*
	     * Since we provided modules, we need to restart the sort so
	     * that the previous files that depend on us have a chance.
	     * Also, we've busted the tailq next pointer with the REMOVE.
	     */
	    goto restart;
	}
    }

    /*
     * At this point, we check to see what could not be resolved..
     */
    TAILQ_FOREACH(lf, &loaded_files, loaded) {
	printf("KLD file %s is missing dependencies\n", lf->filename);
	linker_file_unload(lf);
	TAILQ_REMOVE(&loaded_files, lf, loaded);
    }

    /*
     * We made it. Finish off the linking in the order we determined.
     */
    TAILQ_FOREACH(lf, &depended_files, loaded) {
	if (linker_kernel_file) {
	    linker_kernel_file->refs++;
	    error = linker_file_add_dependancy(lf, linker_kernel_file);
	    if (error)
		panic("cannot add dependency");
	}
	lf->userrefs++;		/* so we can (try to) kldunload it */
	error = linker_file_lookup_set(lf, MDT_SETNAME, &start, &stop, NULL);
	if (!error) {
	    for (mdp = start; mdp < stop; mdp++) {
		mp = linker_reloc_ptr(lf, *mdp);
		if (mp->md_type != MDT_DEPEND)
		    continue;
		linker_mdt_depend(lf, mp, &modname, &verinfo);
		mod = modlist_lookup(modname, 0);
		mod->container->refs++;
		error = linker_file_add_dependancy(lf, mod->container);
		if (error)
		    panic("cannot add dependency");
	    }
	}

	/*
	 * Now do relocation etc using the symbol search paths established by
	 * the dependencies
	 */
	error = LINKER_LINK_PRELOAD_FINISH(lf);
	if (error) {
	    printf("KLD file %s - could not finalize loading\n", lf->filename);
	    linker_file_unload(lf);
	    continue;
	}

	linker_file_register_modules(lf);
	if (linker_file_lookup_set(lf, "sysinit_set", &si_start, &si_stop, NULL) == 0)
	    sysinit_add(si_start, si_stop);
	linker_file_register_sysctls(lf);
	lf->flags |= LINKER_FILE_LINKED;
    }
    /* woohoo! we made it! */
}

SYSINIT(preload, SI_SUB_KLD, SI_ORDER_MIDDLE, linker_preload, 0);

/*
 * Search for a not-loaded module by name.
 *
 * Modules may be found in the following locations:
 *
 * - preloaded (result is just the module name)
 * - on disk (result is full path to module)
 *
 * If the module name is qualified in any way (contains path, etc.)
 * the we simply return a copy of it.
 *
 * The search path can be manipulated via sysctl.  Note that we use the ';'
 * character as a separator to be consistent with the bootloader.
 */

static char linker_path[MAXPATHLEN] = "/boot/modules/;/modules/;/boot/kernel/";

SYSCTL_STRING(_kern, OID_AUTO, module_path, CTLFLAG_RW, linker_path,
	      sizeof(linker_path), "module load search path");

TUNABLE_STR("module_path", linker_path, sizeof(linker_path));

static char *linker_ext_list[] = {
	".ko",
	"",
	NULL
};

static char *
linker_search_path(const char *name)
{
    struct nameidata	nd;
    struct proc		*p = curproc;	/* XXX */
    char		*cp, *ep, *result, **cpp;
    int			error, extlen, len, flags;
    enum vtype		type;

    /* qualified at all? */
    if (index(name, '/'))
	return(linker_strdup(name));

    extlen = 0;
    for (cpp = linker_ext_list; *cpp; cpp++) {
	len = strlen(*cpp);
	if (len > extlen)
	    extlen = len;
    }
    extlen++;	/* trailing '\0' */

    /* traverse the linker path */
    cp = linker_path;
    len = strlen(name);
    for (;;) {

	/* find the end of this component */
	for (ep = cp; (*ep != 0) && (*ep != ';'); ep++)
	    ;
	result = malloc((len + (ep - cp) + extlen + 1), M_LINKER, M_WAITOK);
	if (result == NULL)	/* actually ENOMEM */
	    return(NULL);
	for (cpp = linker_ext_list; *cpp; cpp++) {
	    strncpy(result, cp, ep - cp);
	    strcpy(result + (ep - cp), "/");
	    strcat(result, name);
	    strcat(result, *cpp);
	    /*
	     * Attempt to open the file, and return the path if we succeed
	     * and it's a regular file.
	     */
	    NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, result, p);
	    flags = FREAD;
	    error = vn_open(&nd, &flags, 0);
	    if (error == 0) {
		NDFREE(&nd, NDF_ONLY_PNBUF);
		type = nd.ni_vp->v_type;
		VOP_UNLOCK(nd.ni_vp, 0, p);
		vn_close(nd.ni_vp, FREAD, p->p_ucred, p);
		if (type == VREG)
		    return(result);
	    }
	}
	free(result, M_LINKER);

	if (*ep == 0)
	    break;
	cp = ep + 1;
    }
    return(NULL);
}

static const char *
linker_basename(const char* path)
{
    const char *filename;

    filename = rindex(path, '/');
    if (filename == NULL)
	return path;
    if (filename[1])
	filename++;
    return filename;
}

/*
 * Find a file which contains given module and load it,
 * if "parent" is not NULL, register a reference to it.
 */
static int
linker_load_module(const char *modname, struct linker_file *parent)
{
    linker_file_t lfdep;
    const char *filename;
    char *pathname;
    int error;

    /*
     * There will be a system to look up or guess a file name from
     * a module name.
     * For now we just try to load a file with the same name.
     */
    pathname = linker_search_path(modname);
    if (pathname == NULL)
	return ENOENT;

    /* Can't load more than one file with the same basename */
    filename = linker_basename(pathname);
    if (linker_find_file_by_name(filename)) {
	error = EEXIST;
	goto out;
    }

    do {
	error = linker_load_file(pathname, &lfdep);
	if (error)
	    break;
	if (parent) {
	    error = linker_file_add_dependancy(parent, lfdep);
	    if (error)
		break;
	}
    } while(0);
out:
    if (pathname)
	free(pathname, M_LINKER);
    return error;
}

/*
 * This routine is responsible for finding dependencies of userland
 * initiated kldload(2)'s of files.
 */
int
linker_load_dependancies(linker_file_t lf)
{
    linker_file_t lfdep;
    struct mod_metadata **start, **stop, **mdp, **nmdp;
    struct mod_metadata *mp, *nmp;
    modlist_t mod;
    const char *modname, *nmodname;
    int ver, error = 0, count;

    /*
     * All files are dependant on /kernel.
     */
    if (linker_kernel_file) {
	linker_kernel_file->refs++;
	error = linker_file_add_dependancy(lf, linker_kernel_file);
	if (error)
	    return error;
    }

    if (linker_file_lookup_set(lf, MDT_SETNAME, &start, &stop, &count) != 0)
	return 0;
    for (mdp = start; mdp < stop; mdp++) {
	mp = linker_reloc_ptr(lf, *mdp);
	if (mp->md_type != MDT_VERSION)
	    continue;
	linker_mdt_version(lf, mp, &modname, &ver);
	mod = modlist_lookup(modname, ver);
	if (mod != NULL) {
	    printf("interface %s.%d already present in the KLD '%s'!\n",
		modname, ver, mod->container->filename);
	    return EEXIST;
	}
    }

    for (mdp = start; mdp < stop; mdp++) {
	mp = linker_reloc_ptr(lf, *mdp);
	if (mp->md_type != MDT_DEPEND)
	    continue;
	modname = linker_reloc_ptr(lf, mp->md_cval);
	nmodname = NULL;
	for (nmdp = start; nmdp < stop; nmdp++) {
	    nmp = linker_reloc_ptr(lf, *nmdp);
	    if (nmp->md_type != MDT_VERSION)
		continue;
	    nmodname = linker_reloc_ptr(lf, nmp->md_cval);
	    if (strcmp(modname, nmodname) == 0)
		break;
	}
	if (nmdp < stop)	/* early exit, it's a self reference */
	    continue;
	mod = modlist_lookup(modname, 0);
	if (mod) {		/* woohoo, it's loaded already */
	    lfdep = mod->container;
	    lfdep->refs++;
	    error = linker_file_add_dependancy(lf, lfdep);
	    if (error)
		break;
	    continue;
	}
	error = linker_load_module(modname, lf);
	if (error) {
	    printf("KLD %s: depends on %s - not available\n",
		lf->filename, modname);
	    break;
	}
    }

    if (error)
	return error;
    linker_addmodules(lf, start, stop, 0);
    return error;
}
