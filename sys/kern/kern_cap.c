/*-
 * Copyright (c) 1999 Ilmar S. Habibulin
 * Copyright (c) 2000-2001 Robert N. M. Watson
 * Copyright (c) 2001 Thomas Moestl
 * All rights reserved.
 *
 * This software was developed by Robert Watson, Thomas Moestl, and Ilmar
 * Habibulin for the TrustedBSD Project.
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
/*
 * Developed by the TrustedBSD Project.
 * Support for POSIX.1e process capabilities.
 *
 * XXX: Currently just syscall stubs.
 */

#include "opt_cap.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/acct.h>
#include <sys/capability.h>
#include <sys/extattr.h>
#include <sys/jail.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/sysctl.h>

#ifdef CAPABILITIES

static int	capabilities_enabled = 0;

SYSCTL_NODE(_kern_security, OID_AUTO, capabilities, CTLFLAG_RW, 0,
    "POSIX.1e Capabilities");
SYSCTL_INT(_kern_security_capabilities, OID_AUTO, enabled, CTLFLAG_RW,
    &capabilities_enabled, 0, "POSIX.1e Capabilities enabled");
#endif

/*
 * Syscall to allow a process to get it's currently capability set
 */
int
__cap_get_proc(struct thread *td, struct __cap_get_proc_args *uap)
{

	return (ENOSYS);
}

/*
 * Syscall to allow a process to set it's current capability set, if
 * permitted.
 */
int
__cap_set_proc(struct thread *td, struct __cap_set_proc_args *uap)
{

	return (ENOSYS);
}

/*
 * Syscalls to allow a process to retrieve capabilities associated with
 * files, if permitted.
 */
int
__cap_get_fd(struct thread *td, struct __cap_get_fd_args *uap)
{

	return (ENOSYS);
}

int
__cap_get_file(struct thread *td, struct __cap_get_file_args *uap)
{

	return (ENOSYS);
}

/*
 * Syscalls to allow a process to set capabilities associated with files,
 * if permitted.
 */
int
__cap_set_fd(struct thread *td, struct __cap_set_fd_args *uap)
{

	return (ENOSYS);
}

int
__cap_set_file(struct thread *td, struct __cap_set_file_args *uap)
{

	return (ENOSYS);
}
