/*
 * Copyright (c) 1995 Andrew McRae.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id$
 */

/*
 * Code cleanup, bug-fix and extension
 * by:
 *     Tatsumi Hosokawa <hosokawa@jp.FreeBSD.org>
 *     Nate Williams <nate@FreeBSD.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <syslog.h>
#ifdef	SYSINSTALL
#include <dialog.h>
#endif
#include "cardd.h"

static int do_log = 0;

void
log_setup(void)
{
#ifndef SYSINSTALL
	do_log = 1;
	openlog("pccardd", LOG_PID, LOG_DAEMON);
#endif
}

void
log_1s(const char *fmt, ...)
{
	va_list ap;
	char s[256];

	va_start(ap, fmt);
	vsprintf(s, fmt, ap);

	if (do_log)
		syslog(LOG_ERR, s);
	else {
#ifdef SYSINSTALL
		dialog_clear();
		msgConfirm(s);
#else
		fprintf(stderr, "cardd: %s\n", s);
#endif
	}
}

void
logerr(char *msg)
{
	if (do_log)
		syslog(LOG_ERR, "%s: %m", msg);
	else {
#ifdef	SYSINSTALL
		dialog_clear();
		msgConfirm(msg);
#else
		perror(msg);
#endif
	}
}

/*
 *	Deliver last will and testament, and die.
 */
void
die(char *msg)
{
	if (do_log)
		syslog(LOG_CRIT, "fatal error: %s", msg);
	else {
#ifdef SYSINSTALL		
		char s[256];

		sprintf(s, "cardd fatal error: %s\n", msg);
		dialog_clear();
		msgConfirm(s);
#else
		fprintf(stderr, "cardd fatal error: %s\n", msg);
#endif
	}
	closelog();
	exit(1);
}

void   *
xmalloc(int sz)
{
	void   *p;

	p = malloc(sz);
	if (p)
		bzero(p, sz);
	else
		die("malloc failed");
	return (p);
}

char   *
newstr(char *p)
{
	char   *s;

	s = strdup(p);
	if (s == 0)
		die("strdup failed");
	return (s);
}

/*
 *	Find contiguous bit string (all set) of at
 *	least count number.
 */
int
bit_fns(bitstr_t *nm, int nbits, int count)
{
	int     i;
	int     found = 0;

	for (i = 0; i < nbits; i++)
		if (bit_test(nm, i)) {
			if (++found == count)
				return (i - count + 1);
		} else
			found = 0;
	return (-1);
}

/*
 *	Allocate a block of memory and return the address.
 */
unsigned long
alloc_memory(int size)
{
	int     i;

	i = bit_fns(mem_avail, MEMBLKS, size / MEMUNIT);
	if (i < 0)
		return (0);
	bit_nclear(mem_avail, i, size / MEMUNIT);
	return (BIT2MEM(i));
}

/*
 *	reset_slot - Power has been applied to the card.
 *	Now reset the card.
 */
void
reset_slot(struct slot *sp)
{
	char    c;
	off_t   offs;
	struct mem_desc mem;
	struct io_desc io;
	int     rw_flags;

	rw_flags = MDF_ATTR;
	ioctl(sp->fd, PIOCRWFLAG, &rw_flags);
#ifdef	DEBUG
	printf("Resetting card, writing 0x80 to offs 0x%x\n",
	    sp->cis->reg_addr);
#endif
	offs = sp->cis->reg_addr;
	lseek(sp->fd, offs, SEEK_SET);
	c = 0x80;
	write(sp->fd, &c, sizeof(c));
	usleep(10 * 1000);
	c = 0;
	lseek(sp->fd, offs, SEEK_SET);
	write(sp->fd, &c, sizeof(c));

	/* Reset all the memory and I/O windows. */
	bzero((caddr_t) & mem, sizeof(mem));
	bzero((caddr_t) & io, sizeof(io));
	for (mem.window = 0; mem.window < NUM_MEM_WINDOWS; mem.window++)
		ioctl(sp->fd, PIOCSMEM, &mem);
	for (io.window = 0; io.window < NUM_IO_WINDOWS; io.window++)
		ioctl(sp->fd, PIOCSIO, &io);
}

/*
 *	execute - Execute the command strings.
 *	For the current slot (if any) perform macro
 *	substitutions.
 */
void
execute(struct cmd *cmdp)
{
	char    cmd[1024];
	char   *p, *cp, *lp;

	for (; cmdp; cmdp = cmdp->next) {
		cp = cmd;
		lp = cmdp->line;
		if (*lp == 0)
			continue;
		while ((p = strchr(lp, '$')) != 0) {
			/* copy over preceding string. */
			while (lp != p)
				*cp++ = *lp++;
			/* stringify ethernet address and place here. */
			if (strncmp(p, "$ether", 6) == 0) {
				sprintf(cp, "%x:%x:%x:%x:%x:%x",
				    current_slot->eaddr[0],
				    current_slot->eaddr[1],
				    current_slot->eaddr[2],
				    current_slot->eaddr[3],
				    current_slot->eaddr[4],
				    current_slot->eaddr[5]);
				while (*++cp)
					continue;
				lp += 6;
			} else
				/* replace device name */
				if (strncmp(p, "$device", 7) == 0) {
					sprintf(cp, "%s%d",
					    current_slot->config->driver->kernel,
					    current_slot->config->driver->unit);
					while (*cp)
						cp++;
					lp += 7;
				} else
					/* Copy the `$' and rescan. */
					*cp++ = *lp++;
		}
		/* No more replacements. Copy rest of string. */
		while ((*cp++ = *lp++) != 0)
			continue;
#ifdef	DEBUG
		fprintf(stderr, "Executing [%s]\n", cmd);
#endif
		system(cmd);
	}
}
