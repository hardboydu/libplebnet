/*
 *	    Written by Toshiharu OHNO (tony-o@iij.ad.jp)
 *
 *   Copyright (C) 1993, Internet Initiative Japan, Inc. All rights reserverd.
 *
 *  Most of codes are derived from chat.c by Karl Fox (karl@MorningStar.Com).
 *
 *	Chat -- a program for automatic session establishment (i.e. dial
 *		the phone and log in).
 *
 *	This software is in the public domain.
 *
 *	Please send all bug reports, requests for information, etc. to:
 *
 *		Karl Fox <karl@MorningStar.Com>
 *		Morning Star Technologies, Inc.
 *		1760 Zollinger Road
 *		Columbus, OH  43221
 *		(614)451-1883
 *
 * $Id: chat.c,v 1.12 1996/12/15 20:39:29 pst Exp $
 *
 *  TODO:
 *	o Support more UUCP compatible control sequences.
 *	o Dialing shoud not block monitor process.
 *	o Reading modem by select should be unified into main.c
 */
#include "defs.h"
#include <ctype.h>
#include <sys/uio.h>
#ifndef isblank
#define	isblank(c)	((c) == '\t' || (c) == ' ')
#endif
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include "timeout.h"
#include "vars.h"

#define	IBSIZE 200

static int TimeoutSec;
static int abort_next, timeout_next;
static int numaborts;
char *AbortStrings[50];
char inbuff[IBSIZE*2+1];

extern int ChangeParity(char *);

#define	MATCH	1
#define	NOMATCH	0
#define	ABORT	-1

static char *
findblank(p, instring)
char *p;
int instring;
{
  if (instring) {
    while (*p) {
      if (*p == '\\') {
	strcpy(p, p + 1);
	if (!*p)
	  break;
      } else if (*p == '"')
	return(p);
      p++;
    }
  } else {
    while (*p) {
      if (isblank(*p))
	return(p);
      p++;
    }
  }
  return p;
}

int
MakeArgs(script, pvect)
char *script;
char **pvect;
{
  int nargs, nb;
  int instring;

  nargs = 0;
  while (*script) {
    nb = strspn(script, " \t");
    script += nb;
    if (*script) {
      if (*script == '"') {
	instring = 1;
	script++;
	if (*script == '\0')
	  return(nargs);
      } else
	instring = 0;
      *pvect++ = script;
      nargs++;
      script = findblank(script, instring);
      if (*script)
	*script++ = '\0';
    }
  }
  *pvect = NULL;
  return nargs;
}

/*
 *  \c	don't add a cr
 *  \d  Sleep a little (delay 2 seconds
 *  \n  Line feed character
 *  \P  Auth Key password
 *  \p  pause 0.25 sec
 *  \r	Carrige return character
 *  \s  Space character
 *  \T  Telephone number(s) (defined via `set phone')
 *  \t  Tab character
 *  \U  Auth User
 */
char *
ExpandString(str, result, reslen, sendmode)
char *str;
char *result;
int reslen;
int sendmode;
{
  int addcr = 0;
  char *phone;

  result[--reslen] = '\0';
  if (sendmode)
    addcr = 1;
  while (*str && reslen > 0) {
    switch (*str) {
    case '\\':
      str++;
      switch (*str) {
      case 'c':
	if (sendmode)
	  addcr = 0;
	break;
      case 'd':		/* Delay 2 seconds */
        sleep(2); break;
      case 'p':
        usleep(250000); break;	/* Pause 0.25 sec */
      case 'n':
	*result++ = '\n'; reslen--; break;
      case 'r':
	*result++ = '\r'; reslen--; break;
      case 's':
	*result++ = ' '; reslen--; break;
      case 't':
	*result++ = '\t'; reslen--; break;
      case 'P':
        strncpy(result, VarAuthKey, reslen);
	reslen -= strlen(result);
	result += strlen(result);
	break;
      case 'T':
	if (VarNextPhone == NULL) {
	  strcpy(VarPhoneCopy, VarPhoneList);
	  VarNextPhone = VarPhoneCopy;
	}
	phone = strsep(&VarNextPhone, ":");
	strncpy(result, phone, reslen);
	reslen -= strlen(result);
	result += strlen(result);
	if ((mode & (MODE_INTER|MODE_AUTO)) == MODE_INTER)
	  fprintf(stderr, "Phone: %s\n", phone);
	LogPrintf(LOG_PHASE_BIT, "Phone: %s\n", phone);
	break;
      case 'U':
	strncpy(result, VarAuthName, reslen);
	reslen -= strlen(result);
	result += strlen(result);
	break;
      default:
	reslen--;
	*result++ = *str; 
	break;
      }
      if (*str) 
          str++;
      break;
    case '^':
      str++;
      if (*str) {
	*result++ = *str++ & 0x1f;
	reslen--;
      }
      break;
    default:
      *result++ = *str++;
      reslen--;
      break;
    }
  }
  if (--reslen > 0) {
    if (addcr)
      *result++ = '\r';
  }
  if (--reslen > 0)
    *result++ = '\0';
  return(result);
}

#define MAXLOGBUFF 200
static char logbuff[MAXLOGBUFF];
static int loglen = 0;

static void clear_log() {
  memset(logbuff,0,MAXLOGBUFF);
  loglen = 0;
}

static void flush_log() {
  if ((loglevel & LOG_CONNECT_BIT) 
      || ((loglevel & LOG_CARRIER_BIT) 
	  && strstr(logbuff,"CARRIER"))) {
    LogPrintf(LOG_CONNECT_BIT|LOG_CARRIER_BIT,"Chat: %s\n",logbuff);
  }
  clear_log();
}

static void connect_log(char *str, int single_p) {
  int space = MAXLOGBUFF - loglen - 1;
  
  while (space--) {
    if (*str == '\n') {
      flush_log();
    } else {
      logbuff[loglen++] = *str;
    }
    if (single_p || !*++str) break;
  }
  if (!space) flush_log();
}



int
WaitforString(estr)
char *estr;
{
  struct timeval timeout;
  char *s, *str, ch;
  char *inp;
  fd_set rfds;
  int i, nfds, nb, msg;
  char buff[200];


#ifdef SIGALRM
  int omask;
  omask = sigblock(sigmask(SIGALRM));
#endif
  clear_log();
  (void) ExpandString(estr, buff, sizeof(buff), 0);
  LogPrintf(LOG_CHAT_BIT, "Wait for (%d): %s --> %s\n", TimeoutSec, estr, buff);
  str = buff;
  inp = inbuff;

  if (strlen(str)>=IBSIZE){
    str[IBSIZE]=0;
    LogPrintf(LOG_CHAT_BIT, "Truncating String to %d character: %s\n", IBSIZE, str);
  }

  nfds = modem + 1;
  s = str;
  msg = FALSE;
  for (;;) {
    FD_ZERO(&rfds);
    FD_SET(modem, &rfds);
    /*
     *  Because it is not clear whether select() modifies timeout value,
     *  it is better to initialize timeout values everytime.
     */
    timeout.tv_sec = TimeoutSec;
    timeout.tv_usec = 0;
    i = select(nfds, &rfds, NULL, NULL, &timeout);
#ifdef notdef
    TimerService();
#endif
    if (i < 0) {
#ifdef SIGALRM
      if (errno == EINTR)
	continue;
      sigsetmask(omask);
#endif
      perror("select");
      *inp = 0;
      return(NOMATCH);
    } else if (i == 0) { 	/* Timeout reached! */
      *inp = 0;
      if (inp != inbuff)
      LogPrintf(LOG_CHAT_BIT, "got: %s\n", inbuff);
      LogPrintf(LOG_CHAT_BIT, "can't get (%d).\n", timeout.tv_sec);
#ifdef SIGALRM
      sigsetmask(omask);
#endif
      return(NOMATCH);
    }
    if (FD_ISSET(modem, &rfds)) {	/* got something */
      if (DEV_IS_SYNC) {
	int length;
	if ((length=strlen(inbuff))>IBSIZE){
	  bcopy(&(inbuff[IBSIZE]),inbuff,IBSIZE+1); /* shuffle down next part*/
	  length=strlen(inbuff);
	}
	nb = read(modem, &(inbuff[length]), IBSIZE);
	inbuff[nb + length] = 0;
	connect_log(inbuff,0);
	if (strstr(inbuff, str)) {
#ifdef SIGALRM
          sigsetmask(omask);
#endif
	  flush_log();
	  return(MATCH);
	}
	for (i = 0; i < numaborts; i++) {
	  if (strstr(inbuff, AbortStrings[i])) {
	    LogPrintf(LOG_CHAT_BIT, "Abort: %s\n", AbortStrings[i]);
#ifdef SIGALRM
            sigsetmask(omask);
#endif
	    flush_log();
	    return(ABORT);
	  }
	}
      } else {
        read(modem, &ch, 1);
	connect_log(&ch,1);
        *inp++ = ch;
        if (ch == *s) {
	  s++;
	  if (*s == '\0') {
#ifdef SIGALRM
            sigsetmask(omask);
#endif
	    *inp = 0;
	    flush_log();
	    return(MATCH);
	  }
        } else {
	  s = str;
	  if (inp == inbuff+ IBSIZE) {
	    bcopy(inp - 100, inbuff, 100);
	    inp = inbuff + 100;
	  }
	  for (i = 0; i < numaborts; i++) {	/* Look for Abort strings */
	    int len;
	    char *s1;

	    s1 = AbortStrings[i];
	    len = strlen(s1);
	    if ((len <= inp - inbuff) && (strncmp(inp - len, s1, len) == 0)) {
	      LogPrintf(LOG_CHAT_BIT, "Abort: %s\n", s1);
	      *inp = 0;
#ifdef SIGALRM
      	      sigsetmask(omask);
#endif
	      flush_log();
	      return(ABORT);
	    }
	  }
        }
      }
    }
  }
#ifdef SIGALRM
  sigsetmask(omask);
#endif
}

void
ExecStr(command, out)
char *command, *out;
{
  int pid;
  int fids[2];
  char *vector[20];
  int stat, nb;
  char *cp;
  char tmp[300];
  extern int errno;

  cp = inbuff + strlen(inbuff) - 1;
  while (cp > inbuff) {
    if (*cp < ' ' && *cp != '\t') {
      cp++;
      break;
    }
    cp--;
  }
  snprintf(tmp, sizeof tmp, "%s %s", command, cp);
  (void) MakeArgs(tmp, &vector);

  pipe(fids);
  pid = fork();
  if (pid == 0) {
    signal(SIGINT, SIG_DFL);
    signal(SIGQUIT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
    close(fids[0]);
    dup2(fids[1], 1);
    close(fids[1]);
    nb = open("/dev/tty", O_RDWR);
    dup2(nb, 0);
LogPrintf(LOG_CHAT_BIT, "exec: %s\n", command);
    /* switch back to original privileges */
    if (setgid(getgid()) < 0) {
      LogPrintf(LOG_CHAT_BIT, "setgid: %s\n", strerror(errno));
      exit(1);
    }
    if (setuid(getuid()) < 0) {
      LogPrintf(LOG_CHAT_BIT, "setuid: %s\n", strerror(errno));
      exit(1);
    }
    pid = execvp(command, vector);
    LogPrintf(LOG_CHAT_BIT, "execvp failed for (%d/%d): %s\n", pid, errno, command);
    exit(127);
  } else {
    close(fids[1]);
    for (;;) {
      nb = read(fids[0], out, 1);
      if (nb <= 0)
	break;
      out++;
    }
    *out = '\0';
    close(fids[0]);
    close(fids[1]);
    waitpid(pid, &stat, WNOHANG);
  }
}

void
SendString(str)
char *str;
{
  char *cp;
  int nb, on;
  char buff[200];

  if (abort_next) {
    abort_next = 0;
    ExpandString(str, buff, sizeof(buff), 0);
    AbortStrings[numaborts++] = strdup(buff);
  } else if (timeout_next) {
    timeout_next = 0;
    TimeoutSec = atoi(str);
    if (TimeoutSec <= 0)
      TimeoutSec = 30;
  } else {
    if (*str == '!') {
      (void) ExpandString(str+1, buff+2, sizeof(buff)-2, 0);
      ExecStr(buff + 2, buff + 2);
    } else {
      (void) ExpandString(str, buff+2, sizeof(buff)-2, 1);
    }
    if (strstr(str, "\\P")) { /* Do not log the password itself. */
      LogPrintf(LOG_CHAT_BIT, "sending: %s\n", str);
    } else {
      LogPrintf(LOG_CHAT_BIT, "sending: %s\n", buff+2);
    }
    cp = buff;
    if (DEV_IS_SYNC)
      bcopy("\377\003", buff, 2);	/* Prepend HDLC header */
    else
      cp += 2;
    on = strlen(cp);
    nb = write(modem, cp, on);
  }
}

int
ExpectString(str)
char *str;
{
  char *minus;
  int state;

  if (strcmp(str, "ABORT") == 0) {
    ++abort_next;
    return(MATCH);
  }
  if (strcmp(str, "TIMEOUT") == 0) {
    ++timeout_next;
    return(MATCH);
  }
  LogPrintf(LOG_CHAT_BIT, "Expecting %s\n", str);
  while (*str) {
    /*
     *  Check whether if string contains sub-send-expect.
     */
    for (minus = str; *minus; minus++) {
      if (*minus == '-') {
	if (minus == str || minus[-1] != '\\')
	  break;
      }
    }
    if (*minus == '-') {      /* We have sub-send-expect. */
      *minus++ = '\0';
      state = WaitforString(str);
      if (state != NOMATCH)
	return(state);
      /*
       * Can't get expect string. Sendout send part.
       */
      str = minus;
      for (minus = str; *minus; minus++) {
	if (*minus == '-') {
	  if (minus == str || minus[-1] != '\\')
	    break;
	}
      }
      if (*minus == '-') {
	*minus++ = '\0';
	SendString(str);
	str = minus;
      } else {
	SendString(str);
	return(MATCH);
      }
    } else {
      /*
       *  Simple case. Wait for string.
       */
      return(WaitforString(str));
    }
  }
  return(MATCH);
}

int
DoChat(script)
char *script;
{
  char *vector[20];
  char **argv;
  int argc, n, state;
#ifdef DEBUG
  int i;
#endif

  timeout_next = abort_next = 0;
  for (n = 0; AbortStrings[n]; n++) {
    free(AbortStrings[n]);
    AbortStrings[n] = NULL;
  }
  numaborts = 0;

  bzero(vector, sizeof(vector));
  n = MakeArgs(script, &vector);
#ifdef DEBUG
  logprintf("n = %d\n", n);
  for (i = 0; i < n; i++)
    logprintf("  %s\n", vector[i]);
#endif
  argc = n;
  argv = vector;
  TimeoutSec = 30;
  while (*argv) {
    if (strcmp(*argv, "P_ZERO") == 0 ||
	strcmp(*argv, "P_ODD") == 0 || strcmp(*argv, "P_EVEN") == 0) {
      ChangeParity(*argv++);
      continue;
    }
    state = ExpectString(*argv++);
    switch (state) {
    case MATCH:
      if (*argv)
	SendString(*argv++);
      break;
    case ABORT:
#ifdef notdef
      HangupModem();
#endif
    case NOMATCH:
      return(NOMATCH);
    }
  }
  return(MATCH);
}
