/*-
 * Copyright (c) 2008-2009 Robert N. M. Watson
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

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "tcpp.h"

#define	BYTES_DEFAULT	10*1024*1024	/* Data per connection. */
#define	MAXTCPS_DEFAULT	32		/* Number of TCPs at a time per proc. */
#define	PROCS_DEFAULT	1		/* Processes used in run. */
#define	TCPS_DEFAULT	1		/* Number of connections per process. */
#define	BASEPORT_DEFAULT	10000

struct sockaddr_in remoteip; 		/* Base target address. */
struct sockaddr_in localipbase;		/* Base local address, if -l. */
int cflag, lflag, mflag, pflag, sflag, tflag, Cflag, Mflag, Tflag;
uint64_t bflag;
u_short rflag;

static void
usage(void)
{

	fprintf(stderr, "client: tcpp"
	    " -c remoteIP"
	    " [-CT]"
	    " [-M localIPcount]"
	    " [-l localIPbase]"
	    " [-b bytespertcp]"
	    " [-m maxtcpsatonce]"
	    "\n"
	    "\t"
	    " [-p procs]"
	    " [-t tcpsperproc]"
	    " [-r baseport]"
	    "\n");

	fprintf(stderr, "server: tcpp"
	    " -s"
	    " [-T]"
	    " [-l localIPbase]"
	    " [-m maxtcpsatonce]"
	    " [-p procs]"
	    " [-r baseport]"
	    "\n");
	exit(EX_USAGE);
}

int
main(int argc, char *argv[])
{
	long long ll;
	char *dummy;
	int ch;

	bzero(&localipbase, sizeof(localipbase));
	localipbase.sin_len = sizeof(localipbase);
	localipbase.sin_family = AF_INET;
	localipbase.sin_addr.s_addr = htonl(INADDR_ANY);	/* Default. */
	localipbase.sin_port = htons(0);				/* Default. */

	bzero(&remoteip, sizeof(remoteip));
	remoteip.sin_len = sizeof(remoteip);
	remoteip.sin_family = AF_INET;
	remoteip.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* Default. */
	remoteip.sin_port = htons(0);				/* Default. */

	bflag = BYTES_DEFAULT;
	mflag = MAXTCPS_DEFAULT;
	pflag = PROCS_DEFAULT;
	rflag = BASEPORT_DEFAULT;
	tflag = TCPS_DEFAULT;
	Mflag = 1;
	while ((ch = getopt(argc, argv, "b:c:l:m:p:r:st:CM:T")) != -1) {
		switch (ch) {
		case 'b':
			ll = strtoll(optarg, &dummy, 10);
			if (*dummy != '\0' || ll <= 0)
				usage();
			bflag = ll;
			break;

		case 'c':
			cflag++;
			if (inet_aton(optarg, &remoteip.sin_addr) != 1)
				err(-1, "inet_aton: %s", optarg);
			break;

		case 'l':
			lflag++;
			if (inet_aton(optarg, &localipbase.sin_addr) != 1)
				err(-1, "inet_aton: %s", optarg);
			break;

		case 'm':
			ll = strtoll(optarg, &dummy, 10);
			if (*dummy != '\0' || ll <= 0)
				usage();
			mflag = ll;
			break;

		case 'p':
			ll = strtoll(optarg, &dummy, 10);
			if (*dummy != '\0' || ll <= 0)
				usage();
			pflag = ll;
			break;

		case 'r':
			ll = strtol(optarg, &dummy, 10);
			if (*dummy != '\0' || ll < 1 || ll > 65535)
				usage();
			rflag = ll;
			break;

		case 's':
			sflag++;
			break;

		case 't':
			ll = strtoll(optarg, &dummy, 10);
			if (*dummy != '\0' || ll <= 0)
				usage();
			tflag = ll;
			break;

		case 'C':
			Cflag++;
			break;

		case 'M':
			ll = strtoll(optarg, &dummy, 10);
			if (*dummy != '\0' || ll <= 1)
				usage();
			Mflag = ll;
			break;

		case 'T':
			Tflag++;
			break;

		default:
			usage();
		}
	}

	/* Exactly one of client and server. */
	if (cflag > 1 || sflag > 1)
		usage();
	if ((cflag && sflag) || (!cflag && !sflag))
		usage();

	/* If Mflag is specified, we must have the lflag for a local IP. */
	if (Mflag > 1 && !lflag)
		usage();

	/* Several flags are valid only on the client, disallow if server. */
	if (sflag && (Cflag || Mflag > 1))
		usage();

	if (cflag)
		tcpp_client();
	else
		tcpp_server();
	exit(0);
}
