/*-
 * APM (Advanced Power Management) Event Dispatcher
 *
 * Copyright (c) 1999 Mitsuru IWASAKI <iwasaki@FreeBSD.org>
 * Copyright (c) 1999 KOIE Hidetaka <koie@suri.co.jp>
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

#ifndef lint
static const char rcsid[] =
  "$FreeBSD$";
#endif /* not lint */

#include <assert.h>
#include <bitstring.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <machine/apm_bios.h>

#include "apmd.h"

extern int	yyparse(void);

int		debug_level = 0;
int		verbose = 0;
const char	*apmd_configfile = APMD_CONFIGFILE;
const char	*apmd_pidfile = APMD_PIDFILE;
int             apmctl_fd = -1;

/*
 * table of event handlers
 */
#define EVENT_CONFIG_INITIALIZER(EV,R) { #EV, NULL, R },
struct event_config events[EVENT_MAX] = {
	EVENT_CONFIG_INITIALIZER(NOEVENT, 0)
	EVENT_CONFIG_INITIALIZER(STANDBYREQ, 1)
	EVENT_CONFIG_INITIALIZER(SUSPENDREQ, 1)
	EVENT_CONFIG_INITIALIZER(NORMRESUME, 0)
	EVENT_CONFIG_INITIALIZER(CRITRESUME, 0)
	EVENT_CONFIG_INITIALIZER(BATTERYLOW, 0)
	EVENT_CONFIG_INITIALIZER(POWERSTATECHANGE, 0)
	EVENT_CONFIG_INITIALIZER(UPDATETIME, 0)
	EVENT_CONFIG_INITIALIZER(CRITSUSPEND, 1)
	EVENT_CONFIG_INITIALIZER(USERSTANDBYREQ, 1)
	EVENT_CONFIG_INITIALIZER(USERSUSPENDREQ, 1)
	EVENT_CONFIG_INITIALIZER(STANDBYRESUME, 0)
	EVENT_CONFIG_INITIALIZER(CAPABILITIESCHANGE, 0)
};

/*
 * default procedure
 */
struct event_cmd *
event_cmd_default_clone(void *this)
{
	struct event_cmd * oldone = this;
	struct event_cmd * newone = malloc(oldone->len);

	newone->next = NULL;
	newone->len = oldone->len;
	newone->name = oldone->name;
	newone->op = oldone->op;
	return newone;
}

/*
 * exec command
 */
int
event_cmd_exec_act(void *this)
{
	struct event_cmd_exec * p = this;
	int status = -1;
	pid_t pid;

	switch ((pid = fork())) {
	case -1:
		(void) warn("cannot fork");
		goto out;
	case 0:
		/* child process */
		execl(_PATH_BSHELL, "sh", "-c", p->line, (char *)NULL);
		_exit(127);
	default:
		/* parent process */
		do {
			pid = waitpid(pid, &status, 0);
		} while (pid == -1 && errno == EINTR);
		break;
	}
 out:
	return status;
}
void
event_cmd_exec_dump(void *this, FILE *fp)
{
	fprintf(fp, " \"%s\"", ((struct event_cmd_exec *)this)->line);
}
struct event_cmd *
event_cmd_exec_clone(void *this)
{
	struct event_cmd_exec * newone = (struct event_cmd_exec *) event_cmd_default_clone(this);
	struct event_cmd_exec * oldone = this;

	newone->evcmd.next = NULL;
	newone->evcmd.len = oldone->evcmd.len;
	newone->evcmd.name = oldone->evcmd.name;
	newone->evcmd.op = oldone->evcmd.op;
	newone->line = strdup(oldone->line);
	return (struct event_cmd *) newone;
}
void
event_cmd_exec_free(void *this)
{
	free(((struct event_cmd_exec *)this)->line);
}
struct event_cmd_op event_cmd_exec_ops = {
	event_cmd_exec_act,
	event_cmd_exec_dump,
	event_cmd_exec_clone,
	event_cmd_exec_free
};

/*
 * reject commad
 */
int
event_cmd_reject_act(void *this)
{
	int rc = -1;

	if (ioctl(apmctl_fd, APMIO_REJECTLASTREQ, NULL)) {
		syslog(LOG_NOTICE, "fail to reject\n");
		goto out;
	}
	rc = 0;
 out:
	return rc;
}
struct event_cmd_op event_cmd_reject_ops = {
	event_cmd_reject_act,
	NULL,
	event_cmd_default_clone,
	NULL
};

/*
 * manipulate event_config
 */
struct event_cmd *
clone_event_cmd_list(struct event_cmd *p)
{
	struct event_cmd dummy;
	struct event_cmd *q = &dummy;
	for ( ;p; p = p->next) {
		assert(p->op->clone);
		if ((q->next = p->op->clone(p)) == NULL)
			(void) err(1, "out of memory");
		q = q->next;
	}
	q->next = NULL;
	return dummy.next;
}
void
free_event_cmd_list(struct event_cmd *p)
{
	struct event_cmd * q;
	for ( ; p ; p = q) {
		q = p->next;
		if (p->op->free)
			p->op->free(p);
		free(p);
	}
}
int
register_apm_event_handlers(
	bitstr_t bit_decl(evlist, EVENT_MAX),
	struct event_cmd *cmdlist)
{
	if (cmdlist) {
		bitstr_t bit_decl(tmp, EVENT_MAX);
		memcpy(&tmp, evlist, bitstr_size(EVENT_MAX));

		for (;;) {
			int n;
			struct event_cmd *p;
			struct event_cmd *q;
			bit_ffs(tmp, EVENT_MAX, &n);
			if (n < 0)
				break;
			p = events[n].cmdlist;
			if ((q = clone_event_cmd_list(cmdlist)) == NULL)
				(void) err(1, "out of memory");
			if (p) {
				while (p->next != NULL)
					p = p->next;
				p->next = q;
			} else {
				events[n].cmdlist = q;
			}
			bit_clear(tmp, n);
		}
	}
	return 0;
}

/*
 * execute command
 */
int
exec_event_cmd(struct event_config *ev)
{
	int status = 0;

	struct event_cmd *p = ev->cmdlist;
	for (; p; p = p->next) {
		assert(p->op->act);
		if (verbose)
			syslog(LOG_INFO, "action: %s", p->name);
		status = p->op->act(p);
		if (status) {
			syslog(LOG_NOTICE, "command finished with %d\n", status);
			if (ev->rejectable) {
				syslog(LOG_ERR, "canceled");
				(void) event_cmd_reject_act(NULL);
			}
			break;
		}
	}
	return status;
}

/*
 * read config file
 */
extern FILE * yyin;
extern int yydebug;

void
read_config(void)
{
	int i;

	if ((yyin = fopen(apmd_configfile, "r")) == NULL) {
		(void) err(1, "cannot open config file");
	}

#ifdef DEBUG
	yydebug = debug_level;
#endif

	if (yyparse() != 0)
		(void) err(1, "cannot parse config file");

	fclose(yyin);

	/* enable events */
	for (i = 0; i < EVENT_MAX; i++) {
		if (events[i].cmdlist) {
			u_int event_type = i;
			if (write(apmctl_fd, &event_type, sizeof(u_int)) == -1) {
				(void) err(1, "cannot enable event 0x%x", event_type);
			}
		}
	}
}

void
dump_config()
{
	int i;

	for (i = 0; i < EVENT_MAX; i++) {
		struct event_cmd * p;
		if ((p = events[i].cmdlist)) {
			fprintf(stderr, "apm_event %s {\n", events[i].name);
			for ( ; p ; p = p->next) {
				fprintf(stderr, "\t%s", p->name);
				if (p->op->dump)
					p->op->dump(p, stderr);
				fprintf(stderr, ";\n");
			}
			fprintf(stderr, "}\n");
		}
	}
}

void
destroy_config()
{
	int i;

	/* disable events */
	for (i = 0; i < EVENT_MAX; i++) {
		if (events[i].cmdlist) {
			u_int event_type = i;
			if (write(apmctl_fd, &event_type, sizeof(u_int)) == -1) {
				(void) err(1, "cannot disable event 0x%x", event_type);
			}
		}
	}

	for (i = 0; i < EVENT_MAX; i++) {
		struct event_cmd * p;
		if ((p = events[i].cmdlist))
			free_event_cmd_list(p);
		events[i].cmdlist = NULL;
	}
}

void
restart()
{
	destroy_config();
	read_config();
	if (verbose)
		dump_config();
}

/*
 * write pid file
 */
static void
write_pid()
{
	FILE *fp = fopen(apmd_pidfile, "w");

	if (fp) {
		fprintf(fp, "%d\n", getpid());
		fclose(fp);
	}
}

/*
 * handle signals
 */
static int signal_fd[2];

void
enque_signal(int sig)
{
	if (write(signal_fd[1], &sig, sizeof sig) != sizeof sig)
		(void) err(1, "cannot process signal.");
}

void
wait_child()
{
	int status;
	while (waitpid(-1, &status, WNOHANG) > 0)
		;
}

int
proc_signal(int fd)
{
	int rc = -1;
	int sig;

	while (read(fd, &sig, sizeof sig) == sizeof sig) {
		syslog(LOG_INFO, "caught signal: %d", sig);
		switch (sig) {
		case SIGHUP:
			syslog(LOG_NOTICE, "restart by SIG");
			restart();
			break;
		case SIGTERM:
			syslog(LOG_NOTICE, "going down on signal %d", sig);
			rc = 1;
			goto out;
		case SIGCHLD:
			wait_child();
			break;
		default:
			(void) warn("unexpected signal(%d) received.", sig);
			break;
		}
	}
	rc = 0;
 out:
	return rc;
}
void
proc_apmevent(int fd)
{
	struct apm_event_info apmevent;

	while (ioctl(fd, APMIO_NEXTEVENT, &apmevent) == 0) {
		int status;
		syslog(LOG_NOTICE, "apmevent %04x index %d\n",
			apmevent.type, apmevent.index);
		syslog(LOG_INFO, "apm event: %s", events[apmevent.type].name);
		if (fork() == 0) {
			status = exec_event_cmd(&events[apmevent.type]);
			exit(status);
		}
	}
}
void
event_loop(void)
{
	int		fdmax = 0;
	struct sigaction nsa;
	fd_set          master_rfds;
	sigset_t	sigmask, osigmask;

	FD_ZERO(&master_rfds);
	FD_SET(apmctl_fd, &master_rfds);
	fdmax = apmctl_fd > fdmax ? apmctl_fd : fdmax;

	FD_SET(signal_fd[0], &master_rfds);
	fdmax = signal_fd[0] > fdmax ? signal_fd[0] : fdmax;

	memset(&nsa, 0, sizeof nsa);
	nsa.sa_handler = enque_signal;
	sigfillset(&nsa.sa_mask);
	nsa.sa_flags = SA_RESTART;
	sigaction(SIGHUP, &nsa, NULL);
	sigaction(SIGCHLD, &nsa, NULL);
	sigaction(SIGTERM, &nsa, NULL);

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGHUP);
	sigaddset(&sigmask, SIGCHLD);
	sigaddset(&sigmask, SIGTERM);
	sigprocmask(SIG_SETMASK, &sigmask, &osigmask);

	while (1) {
		fd_set rfds;

		memcpy(&rfds, &master_rfds, sizeof rfds);
		sigprocmask(SIG_SETMASK, &osigmask, NULL);
		if (select(fdmax + 1, &rfds, 0, 0, 0) < 0) {
			if (errno != EINTR)
				(void) err(1, "select");
		}
		sigprocmask(SIG_SETMASK, &sigmask, NULL);

		if (FD_ISSET(signal_fd[0], &rfds)) {
			if (proc_signal(signal_fd[0]) < 0)
				goto out;
		}
		if (FD_ISSET(apmctl_fd, &rfds))
			proc_apmevent(apmctl_fd);
	}
out:
	return;
}

int
main(int ac, char* av[])
{
	int	ch;
	int	daemonize = 1;
	char	*prog;
	int	logopt = LOG_NDELAY | LOG_PID;

	while ((ch = getopt(ac, av, "df:v")) != EOF) {
		switch (ch) {
		case 'd':
			daemonize = 0;
			debug_level++;
			break;
		case 'f':
			apmd_configfile = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			(void) err(1, "unknown option `%c'", ch);
		}
	}

	if (daemonize)
		daemon(0, 0);

#ifdef NICE_INCR
	(void) nice(NICE_INCR);
#endif

	if (!daemonize)
		logopt |= LOG_PERROR;

	prog = strrchr(av[0], '/');
	openlog(prog ? prog+1 : av[0], logopt, LOG_DAEMON);

	syslog(LOG_NOTICE, "start");

	if (pipe(signal_fd) < 0)
		(void) err(1, "pipe");
	if (fcntl(signal_fd[0], F_SETFL, O_NONBLOCK) < 0)
		(void) err(1, "fcntl");

	if ((apmctl_fd = open(APM_CTL_DEVICEFILE, O_RDWR)) == -1) {
		(void) err(1, "cannot open device file `%s'", APM_CTL_DEVICEFILE);
	}

	restart();
	write_pid();
	event_loop();
 	exit(EXIT_SUCCESS);
}

