/*-
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Karels at Berkeley Software Design, Inc.
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
 *	@(#)kern_sysctl.c	8.4 (Berkeley) 4/14/94
 * $Id: kern_sysctl.c,v 1.28 1995/07/31 10:07:31 mpp Exp $
 */

/*
 * sysctl system call.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/unistd.h>
#include <sys/buf.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/conf.h>
#include <vm/vm.h>
#include <sys/sysctl.h>
#include <sys/user.h>

/* BEGIN_MIB */
SYSCTL_NODE(,CTL_KERN,		kern,	0,	"High kernel, proc, limits &c");
SYSCTL_NODE(,CTL_VM,		vm,	0,	"Virtual memory");
SYSCTL_NODE(,CTL_FS,		fs,	0,	"File system");
SYSCTL_NODE(,CTL_NET,		net,	0,	"Network, (see socket.h)");
SYSCTL_NODE(,CTL_DEBUG,		debug,	0,	"Debugging");
SYSCTL_NODE(,CTL_HW,		hw,	0,	"hardware");
SYSCTL_NODE(,CTL_MACHDEP,	machdep,0,	"machine dependent");
SYSCTL_NODE(,CTL_USER,		user,	0,	"user-level");

SYSCTL_STRING(_kern,KERN_OSTYPE, ostype,
	CTLFLAG_RD, ostype, 0, "");

SYSCTL_STRING(_kern,KERN_OSRELEASE, osrelease,
	CTLFLAG_RD, osrelease, 0, "");

SYSCTL_INT(_kern,KERN_OSREV, osrevision,
	CTLFLAG_RD, 0, BSD, "");

SYSCTL_STRING(_kern,KERN_VERSION, version,
	CTLFLAG_RD, version, 0, "");

extern int osreldate;
SYSCTL_INT(_kern,KERN_OSRELDATE, osreldate,
	CTLFLAG_RD, &osreldate, 0, "");

SYSCTL_INT(_kern,KERN_MAXVNODES, maxvnodes,
	CTLFLAG_RD, &desiredvnodes, 0, "");

SYSCTL_INT(_kern,KERN_MAXPROC, maxproc,
	CTLFLAG_RD, &maxproc, 0, "");

SYSCTL_INT(_kern,KERN_MAXPROCPERUID,maxprocperuid,
	CTLFLAG_RD, &maxprocperuid, 0, "");

SYSCTL_INT(_kern,KERN_MAXFILESPERPROC, maxfilesperproc,
	CTLFLAG_RD, &maxfilesperproc, 0, "");

SYSCTL_INT(_kern,KERN_ARGMAX, argmax,
	CTLFLAG_RD, 0, ARG_MAX, "");

SYSCTL_INT(_kern,KERN_POSIX1, posix1version,
	CTLFLAG_RD, 0, _POSIX_VERSION, "");

SYSCTL_INT(_kern,KERN_NGROUPS, ngroups,
	CTLFLAG_RD, 0, NGROUPS_MAX, "");

SYSCTL_INT(_kern,KERN_JOB_CONTROL, job_control,
	CTLFLAG_RD, 0, 1, "");

SYSCTL_INT(_kern,KERN_MAXFILES, maxfiles,
	CTLFLAG_RW, &maxfiles, 0, "");

#ifdef _POSIX_SAVED_IDS
SYSCTL_INT(_kern,KERN_SAVED_IDS, saved_ids,
	CTLFLAG_RD, 0, 1, "");
#else 
SYSCTL_INT(_kern,KERN_SAVED_IDS, saved_ids,
	CTLFLAG_RD, 0, 0, "");
#endif

char kernelname[MAXPATHLEN] = "/kernel";	/* XXX bloat */

SYSCTL_STRING(_kern,KERN_BOOTFILE, bootfile,
	CTLFLAG_RW, kernelname, sizeof kernelname, "");

SYSCTL_STRUCT(_kern,KERN_BOOTTIME, boottime,
	CTLFLAG_RW, &boottime, timeval, "");

SYSCTL_STRING(_hw,HW_MACHINE, machine,
	CTLFLAG_RD, machine, 0, "");

SYSCTL_STRING(_hw,HW_MACHINE, model,
	CTLFLAG_RD, cpu_model, 0, "");

SYSCTL_INT(_hw,HW_NCPU, ncpu,
	CTLFLAG_RD, 0, 1, "");

SYSCTL_INT(_hw,HW_BYTEORDER, byteorder,
	CTLFLAG_RD, 0, BYTE_ORDER, "");

SYSCTL_INT(_hw,HW_PAGESIZE, pagesize,
	CTLFLAG_RD, 0, PAGE_SIZE, "");

/* END_MIB */

extern int vfs_update_wakeup;
extern int vfs_update_interval;
static int
sysctl_kern_updateinterval SYSCTL_HANDLER_ARGS
{
	int error = sysctl_handle_int(oidp,
		oidp->oid_arg1,oidp->oid_arg2,
		oldp,oldlenp,newp,newlen);
	if (!error)
		wakeup(&vfs_update_wakeup);
	return error;
}

SYSCTL_PROC(_kern,KERN_UPDATEINTERVAL, update, CTLTYPE_INT|CTLFLAG_RD,
	&vfs_update_interval, 0, sysctl_kern_updateinterval,"");

int
sysctl_handle_int SYSCTL_HANDLER_ARGS
{
	int error = 0;

	/* If there isn't sufficient space to return */
	if (oldp && *oldlenp < sizeof(int))
		return (ENOMEM);

	/* If it is a constant, don't write */
	if (newp && !arg1)
		return (EPERM);

	/* If we get more than an int */
	if (newp && newlen != sizeof(int))
		return (EINVAL);

	*oldlenp = sizeof(int);
	if (oldp && arg1 )
		error = copyout(arg1, oldp, sizeof(int));
	else if (oldp)
		error = copyout(&arg2, oldp, sizeof(int));
	if (error == 0 && newp)
		error = copyin(newp, arg1, sizeof(int));
	return (error);
}

int
sysctl_handle_string SYSCTL_HANDLER_ARGS
{
	int len, error = 0, rval = 0;
	char *str = (char *)arg1;

	len = strlen(str) + 1;

	if (oldp && *oldlenp < len) {
		len = *oldlenp;
		rval = ENOMEM;
	}

	if (newp && newlen >= arg2)
		return (EINVAL);

	if (oldp) {
		*oldlenp = len;
		error = copyout(str, oldp, len);
		if (error)
			rval = error;
	}
	if ((error == 0 || error == ENOMEM) && newp) {
		error = copyin(newp, str, newlen);
		if (error)
			rval = error;
		str[newlen] = 0;
	}
	return (rval);
}

int
sysctl_handle_opaque SYSCTL_HANDLER_ARGS
{
	int error = 0, rval = 0;

	if (oldp && *oldlenp < arg2) {
		return (ENOMEM);
	}

	if (newp && newlen != arg2)
		return (EINVAL);

	if (oldp) {
		*oldlenp = arg2;
		error = copyout(arg1, oldp, arg2);
		if (error)
			rval = error;
	}
	if ((error == 0 || error == ENOMEM) && newp) {
		error = copyin(newp, arg1, arg2);
		if (error)
			rval = error;
	}
	return (rval);
}

#ifdef DEBUG
static sysctlfn debug_sysctl;
#endif

/*
 * Locking and stats
 */
static struct sysctl_lock {
	int	sl_lock;
	int	sl_want;
	int	sl_locked;
} memlock;

struct sysctl_args {
	int	*name;
	u_int	namelen;
	void	*old;
	size_t	*oldlenp;
	void	*new;
	size_t	newlen;
};

extern struct linker_set sysctl_;

int
__sysctl(p, uap, retval)
	struct proc *p;
	register struct sysctl_args *uap;
	int *retval;
{
	int error, dolock = 1, i;
	u_int savelen = 0, oldlen = 0;
	sysctlfn *fn;
	int name[CTL_MAXNAME];
        struct linker_set *lsp;
	struct sysctl_oid **oidp;

	if (uap->new != NULL && (error = suser(p->p_ucred, &p->p_acflag)))
		return (error);

	/*
	 * all top-level sysctl names are non-terminal
	 */

	if (uap->namelen > CTL_MAXNAME || uap->namelen < 2)
		return (EINVAL);

 	error = copyin(uap->name, &name, uap->namelen * sizeof(int));
 	if (error)
		return (error);

	oidp = (struct sysctl_oid **) &sysctl_.ls_items[0];

	for (i=0; *oidp && i < CTL_MAXNAME; oidp++) {
		if ((*oidp)->oid_arg1 == (void *) *oidp)
			continue;
		if ((*oidp)->oid_number != name[i])
			continue;
		i++;
		if (((*oidp)->oid_kind & CTLTYPE) == CTLTYPE_NODE) {
			if (i == uap->namelen) 
				/* XXX fail when "old" goes away */
				goto old;
	                lsp = (struct linker_set*)(*oidp)->oid_arg1;
	                oidp = (struct sysctl_oid **) &lsp->ls_items[0];
		} else {
			if (i != uap->namelen) 
				/* XXX fail when "old" goes away */
				goto old;
			goto found;
		}
	}
	/* XXX fail when "old" goes away */
	goto old;
found:
#if 0
	printf("Found <%s> %x %p\n",
		(*oidp)->oid_name, (*oidp)->oid_kind, (*oidp)->oid_arg1);
#endif

	if ((*oidp)->oid_kind & CTLFLAG_NOLOCK)
		dolock = 0;

	if (uap->oldlenp &&
	    (error = copyin(uap->oldlenp, &oldlen, sizeof(oldlen))))
		return (error);

	if (uap->old != NULL) {
		if (!useracc(uap->old, oldlen, B_WRITE))
			return (EFAULT);
		while (memlock.sl_lock) {
			memlock.sl_want = 1;
			(void) tsleep((caddr_t)&memlock, PRIBIO+1, "sysctl", 0);
			memlock.sl_locked++;
		}
		memlock.sl_lock = 1;
		if (dolock)
			vslock(uap->old, oldlen);
		savelen = oldlen;
	}

	/* If writing isn't allowed */
	if (uap->new && !((*oidp)->oid_kind & CTLFLAG_WR))
		return (EPERM);

	if ((*oidp)->oid_handler) {
		i = ((*oidp)->oid_handler) (*oidp,
					(*oidp)->oid_arg1, (*oidp)->oid_arg2,
					uap->old,&oldlen,uap->new,uap->newlen);
		if (i)
			error = i;
	} else
		return EINVAL;
	goto over_and_out;

    old:
	switch (name[0]) {
	case CTL_KERN:
		fn = kern_sysctl;
		if (name[1] != KERN_VNODE)      /* XXX */
			dolock = 0;
		break;
	case CTL_HW:
		fn = hw_sysctl;
		break;
	case CTL_VM:
		fn = vm_sysctl;
		break;
	case CTL_NET:
		fn = net_sysctl;
		break;
	case CTL_FS:
		fn = fs_sysctl;
		break;
	case CTL_MACHDEP:
		fn = cpu_sysctl;
		break;
#ifdef DEBUG
	case CTL_DEBUG:
		fn = debug_sysctl;
		break;
#endif
	default:
		return (EOPNOTSUPP);
	}
	if (uap->oldlenp &&
	    (error = copyin(uap->oldlenp, &oldlen, sizeof(oldlen))))
		return (error);

	if (uap->old != NULL) {
		if (!useracc(uap->old, oldlen, B_WRITE))
			return (EFAULT);
		while (memlock.sl_lock) {
			memlock.sl_want = 1;
			(void) tsleep((caddr_t)&memlock, PRIBIO+1, "sysctl", 0);
			memlock.sl_locked++;
		}
		memlock.sl_lock = 1;
		if (dolock)
			vslock(uap->old, oldlen);
		savelen = oldlen;
	}


	error = (*fn)(name + 1, uap->namelen - 1, uap->old, &oldlen,
	    uap->new, uap->newlen, p);
     over_and_out:
	if (uap->old != NULL) {
		if (dolock)
			vsunlock(uap->old, savelen, B_WRITE);
		memlock.sl_lock = 0;
		if (memlock.sl_want) {
			memlock.sl_want = 0;
			wakeup((caddr_t)&memlock);
		}
	}
	if (error)
		return (error);
	if (uap->oldlenp)
		error = copyout(&oldlen, uap->oldlenp, sizeof(oldlen));
	*retval = oldlen;
	return (0);
}

/*
 * Attributes stored in the kernel.
 */
char hostname[MAXHOSTNAMELEN];
int hostnamelen;
char domainname[MAXHOSTNAMELEN];
int domainnamelen;
long hostid;
int securelevel = -1;

/*
 * kernel related system variables.
 */
int
kern_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{
	int error, level, inthostid;
	dev_t ndumpdev;

	/* all sysctl names at this level are terminal */
	if (namelen != 1 && !(name[0] == KERN_PROC || name[0] == KERN_PROF
			      || name[0] == KERN_NTP_PLL))
		return (ENOTDIR);		/* overloaded */

	switch (name[0]) {

	case KERN_SECURELVL:
		level = securelevel;
		if ((error = sysctl_int(oldp, oldlenp, newp, newlen, &level)) ||
		    newp == NULL)
			return (error);
		if (level < securelevel && p->p_pid != 1)
			return (EPERM);
		securelevel = level;
		return (0);
	case KERN_HOSTNAME:
		error = sysctl_string(oldp, oldlenp, newp, newlen,
		    hostname, sizeof(hostname));
		if (newp)
			if (error == 0 || error == ENOMEM)
				hostnamelen = newlen;
		return (error);
	case KERN_DOMAINNAME:
		error = sysctl_string(oldp, oldlenp, newp, newlen,
		    domainname, sizeof(domainname));
		if (newp)
			if (error == 0 || error == ENOMEM)
				domainnamelen = newlen;
		return (error);
	case KERN_HOSTID:
		inthostid = hostid;  /* XXX assumes sizeof long <= sizeof int */
		error =  sysctl_int(oldp, oldlenp, newp, newlen, &inthostid);
		hostid = inthostid;
		return (error);
	case KERN_CLOCKRATE:
		return (sysctl_clockrate(oldp, oldlenp));
	case KERN_VNODE:
		return (sysctl_vnode(oldp, oldlenp));
	case KERN_PROC:
		return (sysctl_doproc(name + 1, namelen - 1, oldp, oldlenp));
	case KERN_FILE:
		return (sysctl_file(oldp, oldlenp));
#ifdef GPROF
	case KERN_PROF:
		return (sysctl_doprof(name + 1, namelen - 1, oldp, oldlenp,
		    newp, newlen));
#endif
	case KERN_NTP_PLL:
		return (ntp_sysctl(name + 1, namelen - 1, oldp, oldlenp,
				   newp, newlen, p));
	case KERN_DUMPDEV:
		ndumpdev = dumpdev;
		error = sysctl_struct(oldp, oldlenp, newp, newlen, &ndumpdev,
				      sizeof ndumpdev);
		if (!error && ndumpdev != dumpdev) {
			error = setdumpdev(ndumpdev);
		}
		return error;
	default:
		return (EOPNOTSUPP);
	}
	/* NOTREACHED */
}

/*
 * hardware related system variables.
 */
int
hw_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{
	/* almost all sysctl names at this level are terminal */
	if (namelen != 1 && name[0] != HW_DEVCONF)
		return (ENOTDIR);		/* overloaded */

	switch (name[0]) {
	case HW_PHYSMEM:
		return (sysctl_rdint(oldp, oldlenp, newp, ctob(physmem)));
	case HW_USERMEM:
		return (sysctl_rdint(oldp, oldlenp, newp,
		    ctob(physmem - cnt.v_wire_count)));
	case HW_DEVCONF:
		return (dev_sysctl(name + 1, namelen - 1, oldp, oldlenp,
				   newp, newlen, p));
	default:
		return (EOPNOTSUPP);
	}
	/* NOTREACHED */
}

#ifdef DEBUG
/*
 * Debugging related system variables.
 */
struct ctldebug debug0, debug1, debug2, debug3, debug4;
struct ctldebug debug5, debug6, debug7, debug8, debug9;
struct ctldebug debug10, debug11, debug12, debug13, debug14;
struct ctldebug debug15, debug16, debug17, debug18, debug19;
static struct ctldebug *debugvars[CTL_DEBUG_MAXID] = {
	&debug0, &debug1, &debug2, &debug3, &debug4,
	&debug5, &debug6, &debug7, &debug8, &debug9,
	&debug10, &debug11, &debug12, &debug13, &debug14,
	&debug15, &debug16, &debug17, &debug18, &debug19,
};
static int
debug_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{
	struct ctldebug *cdp;

	/* all sysctl names at this level are name and field */
	if (namelen != 2)
		return (ENOTDIR);		/* overloaded */
	cdp = debugvars[name[0]];
	if (cdp->debugname == 0)
		return (EOPNOTSUPP);
	switch (name[1]) {
	case CTL_DEBUG_NAME:
		return (sysctl_rdstring(oldp, oldlenp, newp, cdp->debugname));
	case CTL_DEBUG_VALUE:
		return (sysctl_int(oldp, oldlenp, newp, newlen, cdp->debugvar));
	default:
		return (EOPNOTSUPP);
	}
	/* NOTREACHED */
}
#endif /* DEBUG */

/*
 * Validate parameters and get old / set new parameters
 * for an integer-valued sysctl function.
 */
int
sysctl_int(oldp, oldlenp, newp, newlen, valp)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	int *valp;
{
	int error = 0;

	if (oldp && *oldlenp < sizeof(int))
		return (ENOMEM);
	if (newp && newlen != sizeof(int))
		return (EINVAL);
	*oldlenp = sizeof(int);
	if (oldp)
		error = copyout(valp, oldp, sizeof(int));
	if (error == 0 && newp)
		error = copyin(newp, valp, sizeof(int));
	return (error);
}

/*
 * As above, but read-only.
 */
int
sysctl_rdint(oldp, oldlenp, newp, val)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	int val;
{
	int error = 0;

	if (oldp && *oldlenp < sizeof(int))
		return (ENOMEM);
	if (newp)
		return (EPERM);
	*oldlenp = sizeof(int);
	if (oldp)
		error = copyout((caddr_t)&val, oldp, sizeof(int));
	return (error);
}

/*
 * Validate parameters and get old / set new parameters
 * for a string-valued sysctl function.
 */
int
sysctl_string(oldp, oldlenp, newp, newlen, str, maxlen)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	char *str;
	int maxlen;
{
	int len, error = 0, rval = 0;

	len = strlen(str) + 1;
	if (oldp && *oldlenp < len) {
		len = *oldlenp;
		rval = ENOMEM;
	}
	if (newp && newlen >= maxlen)
		return (EINVAL);
	if (oldp) {
		*oldlenp = len;
		error = copyout(str, oldp, len);
		if (error)
			rval = error;
	}
	if ((error == 0 || error == ENOMEM) && newp) {
		error = copyin(newp, str, newlen);
		if (error)
			rval = error;
		str[newlen] = 0;
	}
	return (rval);
}

/*
 * As above, but read-only.
 */
int
sysctl_rdstring(oldp, oldlenp, newp, str)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	char *str;
{
	int len, error = 0, rval = 0;

	len = strlen(str) + 1;
	if (oldp && *oldlenp < len) {
		len = *oldlenp;
		rval = ENOMEM;
	}
	if (newp)
		return (EPERM);
	*oldlenp = len;
	if (oldp)
		error = copyout(str, oldp, len);
		if (error)
			rval = error;
	return (rval);
}

/*
 * Validate parameters and get old / set new parameters
 * for a structure oriented sysctl function.
 */
int
sysctl_struct(oldp, oldlenp, newp, newlen, sp, len)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	void *sp;
	int len;
{
	int error = 0;

	if (oldp && *oldlenp < len)
		return (ENOMEM);
	if (newp && newlen > len)
		return (EINVAL);
	if (oldp) {
		*oldlenp = len;
		error = copyout(sp, oldp, len);
	}
	if (error == 0 && newp)
		error = copyin(newp, sp, len);
	return (error);
}

/*
 * Validate parameters and get old parameters
 * for a structure oriented sysctl function.
 */
int
sysctl_rdstruct(oldp, oldlenp, newp, sp, len)
	void *oldp;
	size_t *oldlenp;
	void *newp, *sp;
	int len;
{
	int error = 0;

	if (oldp && *oldlenp < len)
		return (ENOMEM);
	if (newp)
		return (EPERM);
	*oldlenp = len;
	if (oldp)
		error = copyout(sp, oldp, len);
	return (error);
}

/*
 * Get file structures.
 */
int
sysctl_file(where, sizep)
	char *where;
	size_t *sizep;
{
	int buflen, error;
	struct file *fp;
	char *start = where;

	buflen = *sizep;
	if (where == NULL) {
		/*
		 * overestimate by 10 files
		 */
		*sizep = sizeof(filehead) + (nfiles + 10) * sizeof(struct file);
		return (0);
	}

	/*
	 * first copyout filehead
	 */
	if (buflen < sizeof(filehead)) {
		*sizep = 0;
		return (0);
	}
	error = copyout((caddr_t)&filehead, where, sizeof(filehead));
	if (error)
		return (error);
	buflen -= sizeof(filehead);
	where += sizeof(filehead);

	/*
	 * followed by an array of file structures
	 */
	for (fp = filehead; fp != NULL; fp = fp->f_filef) {
		if (buflen < sizeof(struct file)) {
			*sizep = where - start;
			return (ENOMEM);
		}
		error = copyout((caddr_t)fp, where, sizeof (struct file));
		if (error)
			return (error);
		buflen -= sizeof(struct file);
		where += sizeof(struct file);
	}
	*sizep = where - start;
	return (0);
}

/*
 * try over estimating by 5 procs
 */
#define KERN_PROCSLOP	(5 * sizeof (struct kinfo_proc))

int
sysctl_doproc(name, namelen, where, sizep)
	int *name;
	u_int namelen;
	char *where;
	size_t *sizep;
{
	register struct proc *p;
	register struct kinfo_proc *dp = (struct kinfo_proc *)where;
	register int needed = 0;
	int buflen = where != NULL ? *sizep : 0;
	int doingzomb;
	struct eproc eproc;
	int error = 0;

	if (namelen != 2 && !(namelen == 1 && name[0] == KERN_PROC_ALL))
		return (EINVAL);
	p = (struct proc *)allproc;
	doingzomb = 0;
again:
	for (; p != NULL; p = p->p_next) {
		/*
		 * Skip embryonic processes.
		 */
		if (p->p_stat == SIDL)
			continue;
		/*
		 * TODO - make more efficient (see notes below).
		 * do by session.
		 */
		switch (name[0]) {

		case KERN_PROC_PID:
			/* could do this with just a lookup */
			if (p->p_pid != (pid_t)name[1])
				continue;
			break;

		case KERN_PROC_PGRP:
			/* could do this by traversing pgrp */
			if (p->p_pgrp == NULL || p->p_pgrp->pg_id != (pid_t)name[1])
				continue;
			break;

		case KERN_PROC_TTY:
			if ((p->p_flag & P_CONTROLT) == 0 ||
			    p->p_session == NULL ||
			    p->p_session->s_ttyp == NULL ||
			    p->p_session->s_ttyp->t_dev != (dev_t)name[1])
				continue;
			break;

		case KERN_PROC_UID:
			if (p->p_ucred == NULL || p->p_ucred->cr_uid != (uid_t)name[1])
				continue;
			break;

		case KERN_PROC_RUID:
			if (p->p_ucred == NULL || p->p_cred->p_ruid != (uid_t)name[1])
				continue;
			break;
		}
		if (buflen >= sizeof(struct kinfo_proc)) {
			fill_eproc(p, &eproc);
			error = copyout((caddr_t)p, &dp->kp_proc,
			    sizeof(struct proc));
			if (error)
				return (error);
			error = copyout((caddr_t)&eproc, &dp->kp_eproc,
			    sizeof(eproc));
			if (error)
				return (error);
			dp++;
			buflen -= sizeof(struct kinfo_proc);
		}
		needed += sizeof(struct kinfo_proc);
	}
	if (doingzomb == 0) {
		p = zombproc;
		doingzomb++;
		goto again;
	}
	if (where != NULL) {
		*sizep = (caddr_t)dp - where;
		if (needed > *sizep)
			return (ENOMEM);
	} else {
		needed += KERN_PROCSLOP;
		*sizep = needed;
	}
	return (0);
}

/*
 * Fill in an eproc structure for the specified process.
 */
void
fill_eproc(p, ep)
	register struct proc *p;
	register struct eproc *ep;
{
	register struct tty *tp;

	bzero(ep, sizeof(*ep));

	ep->e_paddr = p;
	if (p->p_cred) {
		ep->e_pcred = *p->p_cred;
		if (p->p_ucred)
			ep->e_ucred = *p->p_ucred;
	}
	if (p->p_stat != SIDL && p->p_stat != SZOMB && p->p_vmspace != NULL) {
		register struct vmspace *vm = p->p_vmspace;

#ifdef pmap_resident_count
		ep->e_vm.vm_rssize = pmap_resident_count(&vm->vm_pmap); /*XXX*/
#else
		ep->e_vm.vm_rssize = vm->vm_rssize;
#endif
		ep->e_vm.vm_tsize = vm->vm_tsize;
		ep->e_vm.vm_dsize = vm->vm_dsize;
		ep->e_vm.vm_ssize = vm->vm_ssize;
#ifndef sparc
		ep->e_vm.vm_pmap = vm->vm_pmap;
#endif
	}
	if (p->p_pptr)
		ep->e_ppid = p->p_pptr->p_pid;
	if (p->p_pgrp) {
		ep->e_sess = p->p_pgrp->pg_session;
		ep->e_pgid = p->p_pgrp->pg_id;
		ep->e_jobc = p->p_pgrp->pg_jobc;
	}
	if ((p->p_flag & P_CONTROLT) &&
	    (ep->e_sess != NULL) &&
	    ((tp = ep->e_sess->s_ttyp) != NULL)) {
		ep->e_tdev = tp->t_dev;
		ep->e_tpgid = tp->t_pgrp ? tp->t_pgrp->pg_id : NO_PID;
		ep->e_tsess = tp->t_session;
	} else
		ep->e_tdev = NODEV;
	if (ep->e_sess && ep->e_sess->s_ttyvp)
		ep->e_flag = EPROC_CTTY;
	if (SESS_LEADER(p))
		ep->e_flag |= EPROC_SLEADER;
	if (p->p_wmesg) {
		strncpy(ep->e_wmesg, p->p_wmesg, WMESGLEN);
		ep->e_wmesg[WMESGLEN] = 0;
	}
}

#ifdef COMPAT_43
#include <sys/socket.h>
#define	KINFO_PROC		(0<<8)
#define	KINFO_RT		(1<<8)
#define	KINFO_VNODE		(2<<8)
#define	KINFO_FILE		(3<<8)
#define	KINFO_METER		(4<<8)
#define	KINFO_LOADAVG		(5<<8)
#define	KINFO_CLOCKRATE		(6<<8)

/* Non-standard BSDI extension - only present on their 4.3 net-2 releases */
#define	KINFO_BSDI_SYSINFO	(101<<8)

/*
 * XXX this is bloat, but I hope it's better here than on the potentially
 * limited kernel stack...  -Peter
 */

struct {
	int	bsdi_machine;		/* "i386" on BSD/386 */
/*      ^^^ this is an offset to the string, relative to the struct start */
	char	*pad0;
	long	pad1;
	long	pad2;
	long	pad3;
	u_long	pad4;
	u_long	pad5;
	u_long	pad6;

	int	bsdi_ostype;		/* "BSD/386" on BSD/386 */
	int	bsdi_osrelease;		/* "1.1" on BSD/386 */
	long	pad7;
	long	pad8;
	char	*pad9;

	long	pad10;
	long	pad11;
	int	pad12;
	long	pad13;
	quad_t	pad14;
	long	pad15;

	struct	timeval pad16;
	/* we dont set this, because BSDI's uname used gethostname() instead */
	int	bsdi_hostname;		/* hostname on BSD/386 */

	/* the actual string data is appended here */

} bsdi_si;
/*
 * this data is appended to the end of the bsdi_si structure during copyout.
 * The "char *" offsets are relative to the base of the bsdi_si struct.
 * This contains "FreeBSD\02.0-BUILT-nnnnnn\0i386\0", and these strings
 * should not exceed the length of the buffer here... (or else!! :-)
 */
char bsdi_strings[80];	/* It had better be less than this! */

struct getkerninfo_args {
	int	op;
	char	*where;
	int	*size;
	int	arg;
};

int
ogetkerninfo(p, uap, retval)
	struct proc *p;
	register struct getkerninfo_args *uap;
	int *retval;
{
	int error, name[5];
	u_int size;

	if (uap->size &&
	    (error = copyin((caddr_t)uap->size, (caddr_t)&size, sizeof(size))))
		return (error);

	switch (uap->op & 0xff00) {

	case KINFO_RT:
		name[0] = PF_ROUTE;
		name[1] = 0;
		name[2] = (uap->op & 0xff0000) >> 16;
		name[3] = uap->op & 0xff;
		name[4] = uap->arg;
		error = net_sysctl(name, 5, uap->where, &size, NULL, 0, p);
		break;

	case KINFO_VNODE:
		name[0] = KERN_VNODE;
		error = kern_sysctl(name, 1, uap->where, &size, NULL, 0, p);
		break;

	case KINFO_PROC:
		name[0] = KERN_PROC;
		name[1] = uap->op & 0xff;
		name[2] = uap->arg;
		error = kern_sysctl(name, 3, uap->where, &size, NULL, 0, p);
		break;

	case KINFO_FILE:
		name[0] = KERN_FILE;
		error = kern_sysctl(name, 1, uap->where, &size, NULL, 0, p);
		break;

	case KINFO_METER:
		name[0] = VM_METER;
		error = vm_sysctl(name, 1, uap->where, &size, NULL, 0, p);
		break;

	case KINFO_LOADAVG:
		name[0] = VM_LOADAVG;
		error = vm_sysctl(name, 1, uap->where, &size, NULL, 0, p);
		break;

	case KINFO_CLOCKRATE:
		name[0] = KERN_CLOCKRATE;
		error = kern_sysctl(name, 1, uap->where, &size, NULL, 0, p);
		break;

	case KINFO_BSDI_SYSINFO: {
		/*
		 * this is pretty crude, but it's just enough for uname()
		 * from BSDI's 1.x libc to work.
		 *
		 * In particular, it doesn't return the same results when
		 * the supplied buffer is too small.  BSDI's version apparently
		 * will return the amount copied, and set the *size to how
		 * much was needed.  The emulation framework here isn't capable
		 * of that, so we just set both to the amount copied.
		 * BSDI's 2.x product apparently fails with ENOMEM in this
		 * scenario.
		 */

		u_int needed;
		u_int left;
		char *s;

		bzero((char *)&bsdi_si, sizeof(bsdi_si));
		bzero(bsdi_strings, sizeof(bsdi_strings));

		s = bsdi_strings;

		bsdi_si.bsdi_ostype = (s - bsdi_strings) + sizeof(bsdi_si);
		strcpy(s, ostype);
		s += strlen(s) + 1;

		bsdi_si.bsdi_osrelease = (s - bsdi_strings) + sizeof(bsdi_si);
		strcpy(s, osrelease);
		s += strlen(s) + 1;

		bsdi_si.bsdi_machine = (s - bsdi_strings) + sizeof(bsdi_si);
		strcpy(s, machine);
		s += strlen(s) + 1;

		needed = sizeof(bsdi_si) + (s - bsdi_strings);

		if (uap->where == NULL) {
			/* process is asking how much buffer to supply.. */
			size = needed;
			error = 0;
			break;
		}


		/* if too much buffer supplied, trim it down */
		if (size > needed)
			size = needed;

		/* how much of the buffer is remaining */
		left = size;

		if ((error = copyout((char *)&bsdi_si, uap->where, left)) != 0)
			break;

		/* is there any point in continuing? */
		if (left > sizeof(bsdi_si)) {
			left -= sizeof(bsdi_si);
			error = copyout(&bsdi_strings,
					uap->where + sizeof(bsdi_si), left);
		}
		break;
	}

	default:
		return (EOPNOTSUPP);
	}
	if (error)
		return (error);
	*retval = size;
	if (uap->size)
		error = copyout((caddr_t)&size, (caddr_t)uap->size,
		    sizeof(size));
	return (error);
}
#endif /* COMPAT_43 */
