/*-
 * Copyright (c) 2001 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by ThinkSec AS and
 * NAI Labs, the Security Research Division of Network Associates, Inc.
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
 * 3. The name of the author may not be used to endorse or promote
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/openpam.h>

static int
_pam_exec(pam_handle_t *pamh __unused, int flags __unused,
    int argc, const char *argv[])
{
	int childerr, status;
	pid_t pid;

	if (argc < 1)
		return (PAM_SERVICE_ERR);

	/*
	 * XXX For additional credit, divert child's stdin/stdout/stderr
	 * to the conversation function.
	 */
	childerr = 0;
	if ((pid = vfork()) == 0) {
		execv(argv[0], argv);
		childerr = errno;
		_exit(1);
	} else if (pid == -1) {
		openpam_log(PAM_LOG_ERROR, "vfork(): %m");
		return (PAM_SYSTEM_ERR);
	}
	if (waitpid(pid, &status, 0) == -1) {
		openpam_log(PAM_LOG_ERROR, "waitpid(): %m");
		return (PAM_SYSTEM_ERR);
	}
	if (childerr != 0) {
		openpam_log(PAM_LOG_ERROR, "execv(): %m");
		return (PAM_SYSTEM_ERR);
	}
	if (WIFSIGNALED(status)) {
		openpam_log(PAM_LOG_ERROR, "%s caught signal %d%s",
		    argv[0], WTERMSIG(status),
		    WCOREDUMP(status) ? " (core dumped)" : "");
		return (PAM_SYSTEM_ERR);
	}
	if (!WIFEXITED(status)) {
		openpam_log(PAM_LOG_ERROR, "unknown status 0x%x", status);
		return (PAM_SYSTEM_ERR);
	}
	if (WEXITSTATUS(status) != 0) {
		openpam_log(PAM_LOG_ERROR, "%s returned code %d",
		    argv[0], WEXITSTATUS(status));
		return (PAM_SYSTEM_ERR);
	}
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

	return (_pam_exec(pamh, flags, argc, argv));
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

	return (_pam_exec(pamh, flags, argc, argv));
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

	return (_pam_exec(pamh, flags, argc, argv));
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

	return (_pam_exec(pamh, flags, argc, argv));
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

	return (_pam_exec(pamh, flags, argc, argv));
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

	return (_pam_exec(pamh, flags, argc, argv));
}

PAM_MODULE_ENTRY("pam_exec");
