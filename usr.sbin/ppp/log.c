/*
 *	            PPP logging facility
 *
 *	    Written by Toshiharu OHNO (tony-o@iij.ad.jp)
 *
 *   Copyright (C) 1993, Internet Initiative Japan, Inc. All rights reserverd.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the Internet Initiative Japan, Inc.  The name of the
 * IIJ may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * $Id:$
 * 
 */
#include "defs.h"
#include <time.h>
#include <netdb.h>
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#ifdef NO_VSPRINTF
#include <stdio.h>
#endif

#include "hdlc.h"

#define	MAXLOG	70

#define USELOGFILE

#ifdef USELOGFILE
static FILE *logfile;
#endif
static char logbuff[2000];
static char *logptr;
static struct mbuf *logtop;
static struct mbuf *lognext;
static int  logcnt;
static int  mypid;

int loglevel = (1 << LOG_LCP)| (1 << LOG_PHASE);

void
ListLog()
{
  struct mbuf *bp;

  for (bp = logtop; bp; bp = bp->next) {
    write(1, MBUF_CTOP(bp), bp->cnt);
    usleep(10);
  }
}

int
LogOpen()
{
#ifdef USELOGFILE
  logfile = fopen(LOGFILE, "a");
  if (logfile == NULL) {
    fprintf(stderr, "can't open %s.\r\n", LOGFILE);
    return(1);
  }
#endif
  fprintf(stderr, "Log level is %02x\r\n", loglevel);
  logptr = logbuff;
  logcnt = 0;
  logtop = lognext = NULL;
  return(0);
}

void
LogFlush()
{
  struct mbuf *bp;
  int cnt;

#ifdef USELOGFILE
  *logptr = 0;
  fprintf(logfile, "%s", logbuff);
  fflush(logfile);
#endif
  cnt = logptr - logbuff + 1;
  bp = mballoc(cnt, MB_LOG);
  bcopy(logbuff, MBUF_CTOP(bp), cnt);
  bp->cnt = cnt;
  if (lognext) {
    lognext->next = bp;
    lognext = bp;
    if (++logcnt > MAXLOG) {
      logcnt--;
      logtop = mbfree(logtop);
    }
  } else {
    lognext = logtop = bp;
  }
  logptr = logbuff;
}

void
DupLog()
{
  mypid = 0;
#ifdef USELOGFILE
  dup2(fileno(logfile), 2);
#endif
}

void
LogClose()
{
  LogFlush();
#ifdef USELOGFILE
  fclose(logfile);
#endif
}

#ifdef NO_VSPRINTF
void
vsprintf(buf, fmt, av)
char *buf;
char *fmt;
va_list av;
{
  FILE foo;

  foo._cnt = BUFSIZ;
  foo._base = foo._ptr = buf; /* may have to cast(unsigned char *) */
  foo._flag = _IOWRT+_IOSTRG;
  (void) _doprnt(fmt, (va_list)av, &foo);
  *foo._ptr = '\0'; /* plant terminating null character */
}
#endif

static void
vlogprintf(format, ap)
char *format;
va_list ap;
{
  vsprintf(logptr, format, ap);
  logptr += strlen(logptr);
  LogFlush();
}

void
#ifdef __STDC__
logprintf(char *format, ...)
#else
logprintf(va_alist)
va_dcl
#endif
{
  va_list ap;
#ifdef __STDC__
  va_start(ap, format);
#else
  char *format;

  va_start(ap);
  format = va_arg(ap, char *);
#endif
  vlogprintf(format, ap);
  va_end(ap);
}

void
LogDumpBp(level, header, bp)
int level;
char *header;
struct mbuf *bp;
{
  u_char *cp;
  int cnt, loc;

  if (!(loglevel & (1 << level)))
    return;
  LogTimeStamp();
  sprintf(logptr, "%s\n", header);
  logptr += strlen(logptr);
  loc = 0;
  LogTimeStamp();
  while (bp) {
    cp = MBUF_CTOP(bp);
    cnt = bp->cnt;
    while (cnt-- > 0) {
      sprintf(logptr, " %02x", *cp++);
      logptr += strlen(logptr);
      if (++loc == 16) {
	loc = 0;
	*logptr++ = '\n';
	if (logptr - logbuff > 1500)
	  LogFlush();
  	if (cnt) LogTimeStamp();
      }
    }
    bp = bp->next;
  }
  if (loc) *logptr++ = '\n';
  LogFlush();
}

void
LogDumpBuff(level, header, ptr, cnt)
int level;
char *header;
u_char *ptr;
int cnt;
{
  int loc;

  if (cnt < 1) return;
  if (!(loglevel & (1 << level)))
    return;
  LogTimeStamp();
  sprintf(logptr, "%s\n", header);
  logptr += strlen(logptr);
  LogTimeStamp();
  loc = 0;
  while (cnt-- > 0) {
    sprintf(logptr, " %02x", *ptr++);
    logptr += strlen(logptr);
    if (++loc == 16) {
      loc = 0;
      *logptr++ = '\n';
      if (cnt) LogTimeStamp();
    }
  }
  if (loc) *logptr++ = '\n';
  LogFlush();
}

void
LogTimeStamp()
{
  struct tm *ptm;
  time_t ltime;

  if (mypid == 0)
    mypid = getpid();
  ltime = time(0);
  ptm = localtime(&ltime);
  sprintf(logptr, "%02d-%02d %02d:%02d:%02d [%d] ", 
    ptm->tm_mon + 1, ptm->tm_mday,
	ptm->tm_hour, ptm->tm_min, ptm->tm_sec, mypid);
  logptr += strlen(logptr);
}

void
#ifdef __STDC__
LogPrintf(int level, char *format, ...)
#else
LogPrintf(va_alist)
va_dcl
#endif
{
  va_list ap;
#ifdef __STDC__
  va_start(ap, format);
#else
  int level;
  char *format;

  va_start(ap);
  int = va_arg(ap, int);
  format = va_arg(ap, char *);
#endif
  if (!(loglevel & (1 << level)))
    return;
  LogTimeStamp();
  vlogprintf(format, ap);
  va_end(ap);
}
