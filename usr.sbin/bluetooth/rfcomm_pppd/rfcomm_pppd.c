/*
 * rfcomm_pppd.c
 *
 * Copyright (c) 2001-2003 Maksim Yevmenkin <m_evmenkin@yahoo.com>
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: rfcomm_pppd.c,v 1.3 2003/04/26 23:59:49 max Exp $
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <bitstring.h>
#include <errno.h>
#include <fcntl.h>
#include <ng_hci.h>
#include <ng_l2cap.h>
#include <ng_btsocket.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define RFCOMM_PPPD	"rfcomm_pppd"

static void	exec_ppp	(int s, char *label);
static void	sighandler	(int s);
static void	usage		(void);

static int	done;

/* Main */
int
main(int argc, char *argv[])
{
	struct sockaddr_rfcomm   sock_addr;
	char			*label = NULL;
	bdaddr_t		 addr;
	int			 s, channel, detach, server;
	pid_t			 pid;

	memcpy(&addr, NG_HCI_BDADDR_ANY, sizeof(addr));
	channel = 0;
	detach = 1;
	server = 0;

	/* Parse command line arguments */
	while ((s = getopt(argc, argv, "a:cC:dhl:s")) != -1) {
		switch (s) {
		case 'a': { /* BDADDR */
			int	a0, a1, a2, a3, a4, a5;

			if (sscanf(optarg, "%x:%x:%x:%x:%x:%x",
					&a5, &a4, &a3, &a2, &a1, &a0) != 6)
				usage();
				/* NOT REACHED */

			addr.b[0] = a0 & 0xff;
			addr.b[1] = a1 & 0xff;
			addr.b[2] = a2 & 0xff;
			addr.b[3] = a3 & 0xff;
			addr.b[4] = a4 & 0xff;
			addr.b[5] = a5 & 0xff;
			} break;

		case 'c': /* client */
			server = 0;
			break;

		case 'C': /* RFCOMM channel */
			channel = atoi(optarg);
			break;

		case 'd': /* do not detach */
			detach = 0;
			break;

		case 'l': /* PPP label */
			label = optarg;
			break;

		case 's':
			server = 1;
			break;

		case 'h':
		default:
			usage();
			/* NOT REACHED */
		}
	}

	/* Check if we got everything we wanted */
	if ((channel <= 0 || channel > 30) || label == NULL ||
	    (!server && memcmp(&addr, NG_HCI_BDADDR_ANY, sizeof(addr)) == 0))
		usage();
		/* NOT REACHED */

	openlog(RFCOMM_PPPD, LOG_PID | LOG_PERROR | LOG_NDELAY, LOG_USER);

	if (detach) {
		pid = fork();
		if (pid == (pid_t) -1) {
			syslog(LOG_ERR, "Could not fork(). %s (%d)",
				strerror(errno), errno);
			exit(1);
		}

		if (pid != 0)
			exit(0);

		if (daemon(0, 0) < 0) {
			syslog(LOG_ERR, "Could not daemon(0, 0). %s (%d)",
				strerror(errno), errno);
			exit(1);
		}
	}

	s = socket(PF_BLUETOOTH, SOCK_STREAM, BLUETOOTH_PROTO_RFCOMM);
	if (s < 0) {
		syslog(LOG_ERR, "Could not create socket. %s (%d)",
			strerror(errno), errno);
		exit(1);
	}

	if (server) {
		struct sigaction	sa;

		/* Install signal handler */
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = sighandler;

		if (sigaction(SIGTERM, &sa, NULL) < 0) {
			syslog(LOG_ERR, "Could not sigaction(SIGTERM). %s (%d)",
				strerror(errno), errno);
			exit(1);
		}

		if (sigaction(SIGHUP, &sa, NULL) < 0) {
			syslog(LOG_ERR, "Could not sigaction(SIGHUP). %s (%d)",
				strerror(errno), errno);
			exit(1);
		}

		if (sigaction(SIGINT, &sa, NULL) < 0) {
			syslog(LOG_ERR, "Could not sigaction(SIGINT). %s (%d)",
				strerror(errno), errno);
			exit(1);
		}

		sa.sa_handler = SIG_IGN;
		sa.sa_flags = SA_NOCLDWAIT;

		if (sigaction(SIGCHLD, &sa, NULL) < 0) {
			syslog(LOG_ERR, "Could not sigaction(SIGCHLD). %s (%d)",
				strerror(errno), errno);
			exit(1);
		}

		/* bind socket and listen for incoming connections */
		sock_addr.rfcomm_len = sizeof(sock_addr);
		sock_addr.rfcomm_family = AF_BLUETOOTH;
		memcpy(&sock_addr.rfcomm_bdaddr, &addr,
			sizeof(sock_addr.rfcomm_bdaddr));
		sock_addr.rfcomm_channel = channel;

		if (bind(s, (struct sockaddr *) &sock_addr,
				sizeof(sock_addr)) < 0) {
			syslog(LOG_ERR, "Could not bind socket. %s (%d)",
				strerror(errno), errno);
			exit(1);
		}

		if (listen(s, 10) < 0) {
			syslog(LOG_ERR, "Could not listen on socket. %s (%d)",
				strerror(errno), errno);
			exit(1);
		}

		for (done = 0; !done; ) {
			int	len = sizeof(sock_addr);
			int	s1 = accept(s, (struct sockaddr *) &sock_addr, &len);

			if (s1 < 0) {
				syslog(LOG_ERR, "Could not accept connection " \
					"on socket. %s (%d)", strerror(errno),
					errno);
				exit(1);
			}
				
			pid = fork();
			if (pid == (pid_t) -1) {
				syslog(LOG_ERR, "Could not fork(). %s (%d)",
					strerror(errno), errno);
				exit(1);
			}

			if (pid == 0) {
				close(s);

				/* Reset signal handler */
				memset(&sa, 0, sizeof(sa));
				sa.sa_handler = SIG_DFL;

				sigaction(SIGTERM, &sa, NULL);
				sigaction(SIGHUP, &sa, NULL);
				sigaction(SIGINT, &sa, NULL);
				sigaction(SIGCHLD, &sa, NULL);

				/* Become daemon */
				daemon(0, 0);

				exec_ppp(s1, label);
			} else
				close(s1);
		}
	} else {
		sock_addr.rfcomm_len = sizeof(sock_addr);
		sock_addr.rfcomm_family = AF_BLUETOOTH;
		memcpy(&sock_addr.rfcomm_bdaddr, NG_HCI_BDADDR_ANY,
			sizeof(sock_addr.rfcomm_bdaddr));
		sock_addr.rfcomm_channel = 0;

		if (bind(s, (struct sockaddr *) &sock_addr,
				sizeof(sock_addr)) < 0) {
			syslog(LOG_ERR, "Could not bind socket. %s (%d)",
				strerror(errno), errno);
			exit(1);
		}

		memcpy(&sock_addr.rfcomm_bdaddr, &addr,
			sizeof(sock_addr.rfcomm_bdaddr));
		sock_addr.rfcomm_channel = channel;

		if (connect(s, (struct sockaddr *) &sock_addr,
				sizeof(sock_addr)) < 0) {
			syslog(LOG_ERR, "Could not connect socket. %s (%d)",
				strerror(errno), errno);
			exit(1);
		}

		exec_ppp(s, label);
	}

	exit(0);
} /* main */

/* 
 * Redirects stdin/stdout to s, stderr to /dev/null and exec ppp -direct label.
 * Never retruns.
 */

static void
exec_ppp(int s, char *label)
{
	char	 ppp[] = "/usr/sbin/ppp";
	char	*ppp_args[] = { ppp, "-direct", NULL, NULL };

	close(0);
	if (dup(s) < 0) {
		syslog(LOG_ERR, "Could not dup(0). %s (%d)",
			strerror(errno), errno);
		exit(1);
	}

	close(1);
	if (dup(s) < 0) {
		syslog(LOG_ERR, "Could not dup(1). %s (%d)",
			strerror(errno), errno);
		exit(1);
	}

	close(2);
	open("/dev/null", O_RDWR);

	ppp_args[2] = label;
	if (execv(ppp, ppp_args) < 0) {
		syslog(LOG_ERR, "Could not exec(%s -direct %s). %s (%d)",
			ppp, label, strerror(errno), errno);
		exit(1);
	}
} /* run_ppp */

/* Signal handler */
static void
sighandler(int s)
{
	done = 1;
} /* sighandler */

/* Display usage and exit */
static void
usage(void)
{
	fprintf(stdout,
"Usage: %s options\n" \
"Where options are:\n" \
"\t-a bdaddr    BDADDR to listen on or connect to (required for client)\n" \
"\t-c           Act as a clinet (default)\n" \
"\t-C channel   RFCOMM channel to listen on or connect to (required)\n" \
"\t-d           Run in foreground\n" \
"\t-l label     Use PPP label (required)\n" \
"\t-s           Act as a server\n" \
"\t-h           Display this message\n", RFCOMM_PPPD);

	exit(255);
} /* usage */

