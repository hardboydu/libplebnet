/*
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)kern_xxx.c	8.2 (Berkeley) 11/14/93
 * $Id$
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/reboot.h>
#include <vm/vm.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>

char domainname[MAXHOSTNAMELEN];
int domainnamelen;

struct reboot_args {
	int	opt;
};
/* ARGSUSED */
int
reboot(p, uap, retval)
	struct proc *p;
	struct reboot_args *uap;
	int *retval;
{
	int error;

	if (error = suser(p->p_ucred, &p->p_acflag))
		return (error);
	boot(uap->opt);
	return (0);
}

#if defined(COMPAT_43) || defined(COMPAT_SUNOS)

struct gethostname_args {
	char	*hostname;
	u_int	len;
};
/* ARGSUSED */
int
ogethostname(p, uap, retval)
	struct proc *p;
	struct gethostname_args *uap;
	int *retval;
{
	int name;

	name = KERN_HOSTNAME;
	return (kern_sysctl(&name, 1, uap->hostname, &uap->len, 0, 0));
}

struct sethostname_args {
	char	*hostname;
	u_int	len;
};
/* ARGSUSED */
int
osethostname(p, uap, retval)
	struct proc *p;
	register struct sethostname_args *uap;
	int *retval;
{
	int name;
	int error;

	if (error = suser(p->p_ucred, &p->p_acflag))
		return (error);
	name = KERN_HOSTNAME;
	return (kern_sysctl(&name, 1, 0, 0, uap->hostname, uap->len));
}

extern long hostid;

struct gethostid_args {
	int	dummy;
};
/* ARGSUSED */
int
ogethostid(p, uap, retval)
	struct proc *p;
	struct gethostid_args *uap;
	int *retval;
{

	*(long *)retval = hostid;
	return (0);
}
#endif /* COMPAT_43 || COMPAT_SUNOS */

#ifdef COMPAT_43
struct sethostid_args {
	long	hostid;
};
/* ARGSUSED */
int
osethostid(p, uap, retval)
	struct proc *p;
	struct sethostid_args *uap;
	int *retval;
{
	int error;

	if (error = suser(p->p_ucred, &p->p_acflag))
		return (error);
	hostid = uap->hostid;
	return (0);
}

int
oquota()
{

	return (ENOSYS);
}
#endif /* COMPAT_43 */

void
shutdown_nice(void)
{
	register struct proc *p;

	/* Send a signal to init(8) and have it shutdown the world */
	p = pfind(1);
	psignal(p, SIGINT);

	return;
}


struct uname_args {
        struct utsname  *name;
};

/* ARGSUSED */
int
uname(p, uap, retval)
	struct proc *p;
	struct uname_args *uap;
	int *retval;
{
	int name;
	int len;
	int rtval;
	char *s, *us;

	name = KERN_OSTYPE;
	len = sizeof uap->name->sysname;
	rtval = kern_sysctl(&name, 1, uap->name->sysname, &len, 0, 0, p);
	if( rtval) return rtval;
	subyte( uap->name->sysname + sizeof(uap->name->sysname) - 1, 0);

	name = KERN_HOSTNAME;
	len = sizeof uap->name->nodename;
	rtval = kern_sysctl(&name, 1, uap->name->nodename, &len, 0, 0, p);
	if( rtval) return rtval;
	subyte( uap->name->nodename + sizeof(uap->name->nodename) - 1, 0);

	name = KERN_OSRELEASE;
	len = sizeof uap->name->release;
	rtval = kern_sysctl(&name, 1, uap->name->release, &len, 0, 0, p);
	if( rtval) return rtval;
	subyte( uap->name->release + sizeof(uap->name->release) - 1, 0);

/*
	name = KERN_VERSION;
	len = sizeof uap->name->version;
	rtval = kern_sysctl(&name, 1, uap->name->version, &len, 0, 0, p);
	if( rtval) return rtval;
	subyte( uap->name->version + sizeof(uap->name->version) - 1, 0);
*/

/*
 * this stupid hackery to make the version field look like FreeBSD 1.1
 */
	for(s = version; *s && *s != '#'; s++);

	for(us = uap->name->version; *s && *s != ':'; s++) {
		rtval = subyte( us++, *s);
		if( rtval)
			return rtval;
	}
	rtval = subyte( us++, 0);
	if( rtval)
		return rtval;

	name = HW_MACHINE;
	len = sizeof uap->name->machine;
	rtval = hw_sysctl(&name, 1, uap->name->machine, &len, 0, 0, p);
	if( rtval) return rtval;
	subyte( uap->name->machine + sizeof(uap->name->machine) - 1, 0);

	return 0;
}

struct getdomainname_args {
        char    *domainname;
        u_int   len;
};

/* ARGSUSED */
int
getdomainname(p, uap, retval)
        struct proc *p;
        struct getdomainname_args *uap;
        int *retval;
{
	if (uap->len > domainnamelen + 1)
		uap->len = domainnamelen + 1;
	return (copyout((caddr_t)domainname, (caddr_t)uap->domainname, uap->len));
}

struct setdomainname_args {
        char    *domainname;
        u_int   len;
};

/* ARGSUSED */
int
setdomainname(p, uap, retval)
        struct proc *p;
        struct setdomainname_args *uap;
        int *retval;
{
        int error;

        if (error = suser(p->p_ucred, &p->p_acflag))
                return (error);
        if (uap->len > sizeof (domainname) - 1)
                return EINVAL;
        domainnamelen = uap->len;
        error = copyin((caddr_t)uap->domainname, domainname, uap->len);
        domainname[domainnamelen] = 0;
        return (error);
}

