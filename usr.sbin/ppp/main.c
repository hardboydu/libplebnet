/*
 *			User Process PPP
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
 * $Id: main.c,v 1.79 1997/09/18 00:15:25 brian Exp $
 *
 *	TODO:
 *		o Add commands for traffic summary, version display, etc.
 *		o Add signal handler for misc controls.
 */
#include "fsm.h"
#include <fcntl.h>
#include <paths.h>
#include <sys/time.h>
#include <termios.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <sysexits.h>
#include "modem.h"
#include "os.h"
#include "hdlc.h"
#include "ccp.h"
#include "lcp.h"
#include "ipcp.h"
#include "loadalias.h"
#include "vars.h"
#include "auth.h"
#include "filter.h"
#include "systems.h"
#include "ip.h"
#include "sig.h"
#include "server.h"
#include "lcpproto.h"

#ifndef O_NONBLOCK
#ifdef O_NDELAY
#define	O_NONBLOCK O_NDELAY
#endif
#endif

extern void VjInit(), AsyncInit();
extern void AsyncInput();
extern int SelectSystem();

extern void DecodeCommand(), Prompt();
extern int aft_cmd;
extern int IsInteractive();
static void DoLoop(void);
static void TerminalStop();
static char *ex_desc();

static struct termios oldtio;	/* Original tty mode */
static struct termios comtio;	/* Command level tty mode */
int TermMode;
static pid_t BGPid = 0;
static char pid_filename[MAXPATHLEN];
static char if_filename[MAXPATHLEN];
int tunno;
static int dial_up;

static void
TtyInit(int DontWantInt)
{
  struct termios newtio;
  int stat;

  stat = fcntl(0, F_GETFL, 0);
  if (stat > 0) {
    stat |= O_NONBLOCK;
    (void) fcntl(0, F_SETFL, stat);
  }
  newtio = oldtio;
  newtio.c_lflag &= ~(ECHO | ISIG | ICANON);
  newtio.c_iflag = 0;
  newtio.c_oflag &= ~OPOST;
  newtio.c_cc[VEOF] = _POSIX_VDISABLE;
  if (DontWantInt)
    newtio.c_cc[VINTR] = _POSIX_VDISABLE;
  newtio.c_cc[VMIN] = 1;
  newtio.c_cc[VTIME] = 0;
  newtio.c_cflag |= CS8;
  tcsetattr(0, TCSADRAIN, &newtio);
  comtio = newtio;
}

/*
 *  Set tty into command mode. We allow canonical input and echo processing.
 */
void
TtyCommandMode(int prompt)
{
  struct termios newtio;
  int stat;

  if (!(mode & MODE_INTER))
    return;
  tcgetattr(0, &newtio);
  newtio.c_lflag |= (ECHO | ISIG | ICANON);
  newtio.c_iflag = oldtio.c_iflag;
  newtio.c_oflag |= OPOST;
  tcsetattr(0, TCSADRAIN, &newtio);
  stat = fcntl(0, F_GETFL, 0);
  if (stat > 0) {
    stat |= O_NONBLOCK;
    (void) fcntl(0, F_SETFL, stat);
  }
  TermMode = 0;
  if (prompt)
    Prompt();
}

/*
 * Set tty into terminal mode which is used while we invoke term command.
 */
void
TtyTermMode()
{
  int stat;

  tcsetattr(0, TCSADRAIN, &comtio);
  stat = fcntl(0, F_GETFL, 0);
  if (stat > 0) {
    stat &= ~O_NONBLOCK;
    (void) fcntl(0, F_SETFL, stat);
  }
  TermMode = 1;
}

void
TtyOldMode()
{
  int stat;

  stat = fcntl(0, F_GETFL, 0);
  if (stat > 0) {
    stat &= ~O_NONBLOCK;
    (void) fcntl(0, F_SETFL, stat);
  }
  tcsetattr(0, TCSANOW, &oldtio);
}

void
Cleanup(int excode)
{
  OsLinkdown();
  OsCloseLink(1);
  sleep(1);
  if (mode & MODE_AUTO)
    DeleteIfRoutes(1);
  (void) unlink(pid_filename);
  (void) unlink(if_filename);
  OsInterfaceDown(1);
  if (mode & MODE_BACKGROUND && BGFiledes[1] != -1) {
    char c = EX_ERRDEAD;

    if (write(BGFiledes[1], &c, 1) == 1)
      LogPrintf(LogPHASE, "Parent notified of failure.\n");
    else
      LogPrintf(LogPHASE, "Failed to notify parent of failure.\n");
    close(BGFiledes[1]);
  }
  LogPrintf(LogPHASE, "PPP Terminated (%s).\n", ex_desc(excode));
  LogClose();
  ServerClose();
  TtyOldMode();

  exit(excode);
}

static void
CloseConnection(int signo)
{
  /* NOTE, these are manual, we've done a setsid() */
  LogPrintf(LogPHASE, "Caught signal %d, abort connection\n", signo);
  reconnectState = RECON_FALSE;
  reconnectCount = 0;
  DownConnection();
  dial_up = FALSE;
}

static void
CloseSession(int signo)
{
  if (BGPid) {
    kill(BGPid, SIGINT);
    exit(EX_TERM);
  }
  LogPrintf(LogPHASE, "Signal %d, terminate.\n", signo);
  reconnect(RECON_FALSE);
  LcpClose();
  Cleanup(EX_TERM);
}

static void
TerminalCont()
{
  pending_signal(SIGCONT, SIG_DFL);
  pending_signal(SIGTSTP, TerminalStop);
  TtyCommandMode(getpgrp() == tcgetpgrp(0));
}

static void
TerminalStop(int signo)
{
  pending_signal(SIGCONT, TerminalCont);
  TtyOldMode();
  pending_signal(SIGTSTP, SIG_DFL);
  kill(getpid(), signo);
}

static void
SetUpServer(int signo)
{
  int res;

  if ((res = ServerTcpOpen(SERVER_PORT + tunno)) != 0)
    LogPrintf(LogERROR, "SIGUSR1: Failed %d to open port %d\n",
	      res, SERVER_PORT + tunno);
}

static char *
ex_desc(int ex)
{
  static char num[12];
  static char *desc[] = {"normal", "start", "sock",
    "modem", "dial", "dead", "done", "reboot", "errdead",
  "hangup", "term", "nodial", "nologin"};

  if (ex >= 0 && ex < sizeof(desc) / sizeof(*desc))
    return desc[ex];
  snprintf(num, sizeof num, "%d", ex);
  return num;
}

void
Usage()
{
  fprintf(stderr,
	  "Usage: ppp [-auto | -background | -direct | -dedicated | -ddial ] [ -alias ] [system]\n");
  exit(EX_START);
}

void
ProcessArgs(int argc, char **argv)
{
  int optc;
  char *cp;

  optc = 0;
  while (argc > 0 && **argv == '-') {
    cp = *argv + 1;
    if (strcmp(cp, "auto") == 0)
      mode |= MODE_AUTO;
    else if (strcmp(cp, "background") == 0)
      mode |= MODE_BACKGROUND | MODE_AUTO;
    else if (strcmp(cp, "direct") == 0)
      mode |= MODE_DIRECT;
    else if (strcmp(cp, "dedicated") == 0)
      mode |= MODE_DEDICATED;
    else if (strcmp(cp, "ddial") == 0)
      mode |= MODE_DDIAL | MODE_AUTO;
    else if (strcmp(cp, "alias") == 0) {
      if (loadAliasHandlers(&VarAliasHandlers) == 0)
	mode |= MODE_ALIAS;
      else
	LogPrintf(LogWARN, "Cannot load alias library\n");
      optc--;			/* this option isn't exclusive */
    } else
      Usage();
    optc++;
    argv++;
    argc--;
  }
  if (argc > 1) {
    fprintf(stderr, "specify only one system label.\n");
    exit(EX_START);
  }
  if (argc == 1)
    dstsystem = *argv;

  if (optc > 1) {
    fprintf(stderr, "specify only one mode.\n");
    exit(EX_START);
  }
}

static void
Greetings()
{
  if (VarTerm) {
    fprintf(VarTerm, "User Process PPP. Written by Toshiharu OHNO.\n");
    fflush(VarTerm);
  }
}

int
main(int argc, char **argv)
{
  FILE *lockfile;
  char *name;

  VarTerm = 0;
  name = rindex(argv[0], '/');
  LogOpen(name ? name + 1 : argv[0]);

  argc--;
  argv++;
  mode = MODE_INTER;		/* default operation is interactive mode */
  netfd = modem = tun_in = -1;
  server = -2;
  ProcessArgs(argc, argv);
  if (!(mode & MODE_DIRECT)) {
    if (getuid() != 0) {
      fprintf(stderr, "You may only run ppp in client mode as user id 0\n");
      LogClose();
      return EX_NOPERM;
    }
    VarTerm = stdout;
  }
  Greetings();
  GetUid();
  IpcpDefAddress();
  LocalAuthInit();

  if (SelectSystem("default", CONFFILE) < 0 && VarTerm)
    fprintf(VarTerm, "Warning: No default entry is given in config file.\n");

  if (OpenTunnel(&tunno) < 0) {
    LogPrintf(LogWARN, "open_tun: %s\n", strerror(errno));
    return EX_START;
  }
  if (mode & (MODE_AUTO | MODE_DIRECT | MODE_DEDICATED))
    mode &= ~MODE_INTER;
  if (mode & MODE_INTER) {
    fprintf(VarTerm, "Interactive mode\n");
    netfd = STDOUT_FILENO;
  } else if (mode & MODE_AUTO) {
    fprintf(VarTerm, "Automatic Dialer mode\n");
    if (dstsystem == NULL) {
      if (VarTerm)
	fprintf(VarTerm, "Destination system must be specified in"
		" auto, background or ddial mode.\n");
      return EX_START;
    }
  }
  tcgetattr(0, &oldtio);	/* Save original tty mode */

  pending_signal(SIGHUP, CloseSession);
  pending_signal(SIGTERM, CloseSession);
  pending_signal(SIGINT, CloseConnection);
  pending_signal(SIGQUIT, CloseSession);
#ifdef SIGPIPE
  signal(SIGPIPE, SIG_IGN);
#endif
#ifdef SIGALRM
  pending_signal(SIGALRM, SIG_IGN);
#endif
  if (mode & MODE_INTER) {
#ifdef SIGTSTP
    pending_signal(SIGTSTP, TerminalStop);
#endif
#ifdef SIGTTIN
    pending_signal(SIGTTIN, TerminalStop);
#endif
#ifdef SIGTTOU
    pending_signal(SIGTTOU, SIG_IGN);
#endif
  }
#ifdef SIGUSR1
  if (mode != MODE_INTER)
    pending_signal(SIGUSR1, SetUpServer);
#endif

  if (dstsystem) {
    if (SelectSystem(dstsystem, CONFFILE) < 0) {
      LogPrintf(LogWARN, "Destination system not found in conf file.\n");
      Cleanup(EX_START);
    }
    if ((mode & MODE_AUTO) && DefHisAddress.ipaddr.s_addr == INADDR_ANY) {
      LogPrintf(LogWARN, "Must specify dstaddr with"
		" auto, background or ddial mode.\n");
      Cleanup(EX_START);
    }
  }

  if (!(mode & MODE_INTER)) {
    if (mode & MODE_BACKGROUND) {
      if (pipe(BGFiledes)) {
	LogPrintf(LogERROR, "pipe: %s\n", strerror(errno));
	Cleanup(EX_SOCK);
      }
    }
    /* Create server socket and listen. */
    if (server == -2)
      ServerTcpOpen(SERVER_PORT + tunno);

    if (!(mode & MODE_DIRECT)) {
      pid_t bgpid;

      bgpid = fork();
      if (bgpid == -1) {
	LogPrintf(LogERROR, "fork: %s\n", strerror(errno));
	Cleanup(EX_SOCK);
      }
      if (bgpid) {
	char c = EX_NORMAL;

	if (mode & MODE_BACKGROUND) {
	  /* Wait for our child to close its pipe before we exit. */
	  BGPid = bgpid;
	  close(BGFiledes[1]);
	  if (read(BGFiledes[0], &c, 1) != 1) {
	    fprintf(VarTerm, "Child exit, no status.\n");
	    LogPrintf(LogPHASE, "Parent: Child exit, no status.\n");
	  } else if (c == EX_NORMAL) {
	    fprintf(VarTerm, "PPP enabled.\n");
	    LogPrintf(LogPHASE, "Parent: PPP enabled.\n");
	  } else {
	    fprintf(VarTerm, "Child failed (%s).\n", ex_desc((int) c));
	    LogPrintf(LogPHASE, "Parent: Child failed (%s).\n",
		      ex_desc((int) c));
	  }
	  close(BGFiledes[0]);
	}
	return c;
      } else if (mode & MODE_BACKGROUND)
	close(BGFiledes[0]);
    }
    snprintf(pid_filename, sizeof(pid_filename), "%stun%d.pid",
	     _PATH_VARRUN, tunno);
    (void) unlink(pid_filename);

    if ((lockfile = fopen(pid_filename, "w")) != NULL) {
      fprintf(lockfile, "%d\n", (int) getpid());
      fclose(lockfile);
    } else
      LogPrintf(LogALERT, "Warning: Can't create %s: %s\n",
		pid_filename, strerror(errno));

    snprintf(if_filename, sizeof if_filename, "%s%s.if",
	     _PATH_VARRUN, VarBaseDevice);
    (void) unlink(if_filename);

    if ((lockfile = fopen(if_filename, "w")) != NULL) {
      fprintf(lockfile, "tun%d\n", tunno);
      fclose(lockfile);
    } else
      LogPrintf(LogALERT, "Warning: Can't create %s: %s\n",
		if_filename, strerror(errno));

    VarTerm = 0;		/* We know it's currently stdout */
    close(1);
    close(2);

#ifdef DOTTYINIT
    if (mode & (MODE_DIRECT | MODE_DEDICATED))
#else
    if (mode & MODE_DIRECT)
#endif
      TtyInit(1);
    else {
      setsid();
      close(0);
    }
  } else {
    TtyInit(0);
    TtyCommandMode(1);
  }
  LogPrintf(LogPHASE, "PPP Started.\n");


  do
    DoLoop();
  while (mode & MODE_DEDICATED);

  Cleanup(EX_DONE);
  return 0;
}

/*
 *  Turn into packet mode, where we speak PPP.
 */
void
PacketMode()
{
  if (RawModem(modem) < 0) {
    LogPrintf(LogWARN, "PacketMode: Not connected.\n");
    return;
  }
  AsyncInit();
  VjInit();
  LcpInit();
  IpcpInit();
  CcpInit();
  LcpUp();

  LcpOpen(VarOpenMode);
  if ((mode & (MODE_INTER | MODE_AUTO)) == MODE_INTER) {
    TtyCommandMode(1);
    if (VarTerm) {
      fprintf(VarTerm, "Packet mode.\n");
      aft_cmd = 1;
    }
  }
}

static void
ShowHelp()
{
  fprintf(stderr, "The following commands are available:\r\n");
  fprintf(stderr, " ~p\tEnter Packet mode\r\n");
  fprintf(stderr, " ~-\tDecrease log level\r\n");
  fprintf(stderr, " ~+\tIncrease log level\r\n");
  fprintf(stderr, " ~t\tShow timers (only in \"log debug\" mode)\r\n");
  fprintf(stderr, " ~m\tShow memory map (only in \"log debug\" mode)\r\n");
  fprintf(stderr, " ~.\tTerminate program\r\n");
  fprintf(stderr, " ~?\tThis help\r\n");
}

static void
ReadTty()
{
  int n;
  char ch;
  static int ttystate;
  FILE *oVarTerm;

#define MAXLINESIZE 200
  char linebuff[MAXLINESIZE];

  LogPrintf(LogDEBUG, "termode = %d, netfd = %d, mode = %d\n",
	    TermMode, netfd, mode);
  if (!TermMode) {
    n = read(netfd, linebuff, sizeof(linebuff) - 1);
    if (n > 0) {
      aft_cmd = 1;
      DecodeCommand(linebuff, n, 1);
    } else {
      LogPrintf(LogPHASE, "client connection closed.\n");
      VarLocalAuth = LOCAL_NO_AUTH;
      mode &= ~MODE_INTER;
      oVarTerm = VarTerm;
      VarTerm = 0;
      if (oVarTerm && oVarTerm != stdout)
	fclose(oVarTerm);
      close(netfd);
      netfd = -1;
    }
    return;
  }

  /*
   * We are in terminal mode, decode special sequences
   */
  n = read(fileno(VarTerm), &ch, 1);
  LogPrintf(LogDEBUG, "Got %d bytes (reading from the terminal)\n", n);

  if (n > 0) {
    switch (ttystate) {
    case 0:
      if (ch == '~')
	ttystate++;
      else
	write(modem, &ch, n);
      break;
    case 1:
      switch (ch) {
      case '?':
	ShowHelp();
	break;
      case 'p':

	/*
	 * XXX: Should check carrier.
	 */
	if (LcpFsm.state <= ST_CLOSED) {
	  VarOpenMode = OPEN_ACTIVE;
	  PacketMode();
	}
	break;
      case '.':
	TermMode = 1;
	aft_cmd = 1;
	TtyCommandMode(1);
	break;
      case 't':
	if (LogIsKept(LogDEBUG)) {
	  ShowTimers();
	  break;
	}
      case 'm':
	if (LogIsKept(LogDEBUG)) {
	  ShowMemMap();
	  break;
	}
      default:
	if (write(modem, &ch, n) < 0)
	  LogPrintf(LogERROR, "error writing to modem.\n");
	break;
      }
      ttystate = 0;
      break;
    }
  }
}


/*
 *  Here, we'll try to detect HDLC frame
 */

static char *FrameHeaders[] = {
  "\176\377\003\300\041",
  "\176\377\175\043\300\041",
  "\176\177\175\043\100\041",
  "\176\175\337\175\043\300\041",
  "\176\175\137\175\043\100\041",
  NULL,
};

u_char *
HdlcDetect(u_char * cp, int n)
{
  char *ptr, *fp, **hp;

  cp[n] = '\0';			/* be sure to null terminated */
  ptr = NULL;
  for (hp = FrameHeaders; *hp; hp++) {
    fp = *hp;
    if (DEV_IS_SYNC)
      fp++;
    ptr = strstr((char *) cp, fp);
    if (ptr)
      break;
  }
  return ((u_char *) ptr);
}

static struct pppTimer RedialTimer;

static void
RedialTimeout()
{
  StopTimer(&RedialTimer);
  LogPrintf(LogPHASE, "Redialing timer expired.\n");
}

static void
StartRedialTimer(int Timeout)
{
  StopTimer(&RedialTimer);

  if (Timeout) {
    RedialTimer.state = TIMER_STOPPED;

    if (Timeout > 0)
      RedialTimer.load = Timeout * SECTICKS;
    else
      RedialTimer.load = (random() % REDIAL_PERIOD) * SECTICKS;

    LogPrintf(LogPHASE, "Enter pause (%d) for redialing.\n",
	      RedialTimer.load / SECTICKS);

    RedialTimer.func = RedialTimeout;
    StartTimer(&RedialTimer);
  }
}


static void
DoLoop()
{
  fd_set rfds, wfds, efds;
  int pri, i, n, wfd, nfds;
  struct sockaddr_in hisaddr;
  struct timeval timeout, *tp;
  int ssize = sizeof(hisaddr);
  u_char *cp;
  u_char rbuff[MAX_MRU];
  int tries;
  int qlen;
  int res;
  pid_t pgroup;

  pgroup = getpgrp();

  if (mode & MODE_DIRECT) {
    LogPrintf(LogDEBUG, "Opening modem\n");
    if (OpenModem(mode) < 0)
      return;
    LogPrintf(LogPHASE, "Packet mode enabled\n");
    PacketMode();
  } else if (mode & MODE_DEDICATED) {
    if (modem < 0)
      while (OpenModem(mode) < 0)
	sleep(VarReconnectTimer);
  }
  fflush(VarTerm);

  timeout.tv_sec = 0;
  timeout.tv_usec = 0;
  reconnectState = RECON_UNKNOWN;

  if (mode & MODE_BACKGROUND)
    dial_up = TRUE;		/* Bring the line up */
  else
    dial_up = FALSE;		/* XXXX */
  tries = 0;
  for (;;) {
    nfds = 0;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);

    /*
     * If the link is down and we're in DDIAL mode, bring it back up.
     */
    if (mode & MODE_DDIAL && LcpFsm.state <= ST_CLOSED)
      dial_up = TRUE;

    /*
     * If we lost carrier and want to re-establish the connection due to the
     * "set reconnect" value, we'd better bring the line back up.
     */
    if (LcpFsm.state <= ST_CLOSED) {
      if (dial_up != TRUE && reconnectState == RECON_TRUE) {
	if (++reconnectCount <= VarReconnectTries) {
	  LogPrintf(LogPHASE, "Connection lost, re-establish (%d/%d)\n",
		    reconnectCount, VarReconnectTries);
	  StartRedialTimer(VarReconnectTimer);
	  dial_up = TRUE;
	} else {
	  if (VarReconnectTries)
	    LogPrintf(LogPHASE, "Connection lost, maximum (%d) times\n",
		      VarReconnectTries);
	  reconnectCount = 0;
	  if (mode & MODE_BACKGROUND)
	    Cleanup(EX_DEAD);
	}
	reconnectState = RECON_ENVOKED;
      }
    }

    /*
     * If Ip packet for output is enqueued and require dial up, Just do it!
     */
    if (dial_up && RedialTimer.state != TIMER_RUNNING) {
      LogPrintf(LogDEBUG, "going to dial: modem = %d\n", modem);
      if (OpenModem(mode) < 0) {
	tries++;
	if (!(mode & MODE_DDIAL) && VarDialTries)
	  LogPrintf(LogCHAT, "Failed to open modem (attempt %u of %d)\n",
		    tries, VarDialTries);
	else
	  LogPrintf(LogCHAT, "Failed to open modem (attempt %u)\n", tries);

	if (!(mode & MODE_DDIAL) && VarDialTries && tries >= VarDialTries) {
	  if (mode & MODE_BACKGROUND)
	    Cleanup(EX_DIAL);	/* Can't get the modem */
	  dial_up = FALSE;
	  reconnectState = RECON_UNKNOWN;
	  reconnectCount = 0;
	  tries = 0;
	} else
	  StartRedialTimer(VarRedialTimeout);
      } else {
	tries++;		/* Tries are per number, not per list of
				 * numbers. */
	if (!(mode & MODE_DDIAL) && VarDialTries)
	  LogPrintf(LogCHAT, "Dial attempt %u of %d\n", tries, VarDialTries);
	else
	  LogPrintf(LogCHAT, "Dial attempt %u\n", tries);

	if ((res = DialModem()) == EX_DONE) {
	  sleep(1);		/* little pause to allow peer starts */
	  ModemTimeout();
	  PacketMode();
	  dial_up = FALSE;
	  reconnectState = RECON_UNKNOWN;
	  tries = 0;
	} else {
	  CloseModem();
	  if (mode & MODE_BACKGROUND) {
	    if (VarNextPhone == NULL || res == EX_SIG)
	      Cleanup(EX_DIAL);	/* Tried all numbers - no luck */
	    else
	      /* Try all numbers in background mode */
	      StartRedialTimer(VarRedialNextTimeout);
	  } else if (!(mode & MODE_DDIAL) &&
		     ((VarDialTries && tries >= VarDialTries) ||
		      res == EX_SIG)) {
	    /* I give up !  Can't get through :( */
	    StartRedialTimer(VarRedialTimeout);
	    dial_up = FALSE;
	    reconnectState = RECON_UNKNOWN;
	    reconnectCount = 0;
	    tries = 0;
	  } else if (VarNextPhone == NULL)
	    /* Dial failed. Keep quite during redial wait period. */
	    StartRedialTimer(VarRedialTimeout);
	  else
	    StartRedialTimer(VarRedialNextTimeout);
	}
      }
    }
    qlen = ModemQlen();

    if (qlen == 0) {
      IpStartOutput();
      qlen = ModemQlen();
    }
    if (modem >= 0) {
      if (modem + 1 > nfds)
	nfds = modem + 1;
      FD_SET(modem, &rfds);
      FD_SET(modem, &efds);
      if (qlen > 0) {
	FD_SET(modem, &wfds);
      }
    }
    if (server >= 0) {
      if (server + 1 > nfds)
	nfds = server + 1;
      FD_SET(server, &rfds);
    }

    /*
     * *** IMPORTANT ***
     * 
     * CPU is serviced every TICKUNIT micro seconds. This value must be chosen
     * with great care. If this values is too big, it results loss of
     * characters from modem and poor responce. If this values is too small,
     * ppp process eats many CPU time.
     */
#ifndef SIGALRM
    usleep(TICKUNIT);
    TimerService();
#else
    handle_signals();
#endif

    /* If there are aren't many packets queued, look for some more. */
    if (qlen < 20 && tun_in >= 0) {
      if (tun_in + 1 > nfds)
	nfds = tun_in + 1;
      FD_SET(tun_in, &rfds);
    }
    if (netfd >= 0) {
      if (netfd + 1 > nfds)
	nfds = netfd + 1;
      FD_SET(netfd, &rfds);
      FD_SET(netfd, &efds);
    }
#ifndef SIGALRM

    /*
     * Normally, select() will not block because modem is writable. In AUTO
     * mode, select will block until we find packet from tun
     */
    tp = (RedialTimer.state == TIMER_RUNNING) ? &timeout : NULL;
    i = select(nfds, &rfds, &wfds, &efds, tp);
#else

    /*
     * When SIGALRM timer is running, a select function will be return -1 and
     * EINTR after a Time Service signal hundler is done.  If the redial
     * timer is not running and we are trying to dial, poll with a 0 value
     * timer.
     */
    tp = (dial_up && RedialTimer.state != TIMER_RUNNING) ? &timeout : NULL;
    i = select(nfds, &rfds, &wfds, &efds, tp);
#endif

    if (i == 0) {
      continue;
    }
    if (i < 0) {
      if (errno == EINTR) {
	handle_signals();
	continue;
      }
      LogPrintf(LogERROR, "DoLoop: select(): %s\n", strerror(errno));
      break;
    }
    if ((netfd >= 0 && FD_ISSET(netfd, &efds)) || (modem >= 0 && FD_ISSET(modem, &efds))) {
      LogPrintf(LogALERT, "Exception detected.\n");
      break;
    }
    if (server >= 0 && FD_ISSET(server, &rfds)) {
      LogPrintf(LogPHASE, "connected to client.\n");
      wfd = accept(server, (struct sockaddr *) & hisaddr, &ssize);
      if (wfd < 0) {
	LogPrintf(LogERROR, "DoLoop: accept(): %s\n", strerror(errno));
	continue;
      }
      if (netfd >= 0) {
	write(wfd, "already in use.\n", 16);
	close(wfd);
	continue;
      } else
	netfd = wfd;
      VarTerm = fdopen(netfd, "a+");
      mode |= MODE_INTER;
      Greetings();
      (void) IsInteractive();
      Prompt();
    }
    if ((mode & MODE_INTER) && (netfd >= 0 && FD_ISSET(netfd, &rfds)) &&
	((mode & MODE_AUTO) || pgroup == tcgetpgrp(0))) {
      /* something to read from tty */
      ReadTty();
    }
    if (modem >= 0) {
      if (FD_ISSET(modem, &wfds)) {	/* ready to write into modem */
	ModemStartOutput(modem);
      }
      if (FD_ISSET(modem, &rfds)) {	/* something to read from modem */
	if (LcpFsm.state <= ST_CLOSED)
	  usleep(10000);
	n = read(modem, rbuff, sizeof(rbuff));
	if ((mode & MODE_DIRECT) && n <= 0) {
	  DownConnection();
	} else
	  LogDumpBuff(LogASYNC, "ReadFromModem", rbuff, n);

	if (LcpFsm.state <= ST_CLOSED) {

	  /*
	   * In dedicated mode, we just discard input until LCP is started.
	   */
	  if (!(mode & MODE_DEDICATED)) {
	    cp = HdlcDetect(rbuff, n);
	    if (cp) {

	      /*
	       * LCP packet is detected. Turn ourselves into packet mode.
	       */
	      if (cp != rbuff) {
		write(modem, rbuff, cp - rbuff);
		write(modem, "\r\n", 2);
	      }
	      PacketMode();
	    } else
	      write(fileno(VarTerm), rbuff, n);
	  }
	} else {
	  if (n > 0)
	    AsyncInput(rbuff, n);
	}
      }
    }
    if (tun_in >= 0 && FD_ISSET(tun_in, &rfds)) {	/* something to read
							 * from tun */
      n = read(tun_in, rbuff, sizeof(rbuff));
      if (n < 0) {
	LogPrintf(LogERROR, "read from tun: %s\n", strerror(errno));
	continue;
      }
      if (((struct ip *) rbuff)->ip_dst.s_addr == IpcpInfo.want_ipaddr.s_addr) {
	/* we've been asked to send something addressed *to* us :( */
	if (VarLoopback) {
	  pri = PacketCheck(rbuff, n, FL_IN);
	  if (pri >= 0) {
	    struct mbuf *bp;

	    if (mode & MODE_ALIAS) {
	      VarPacketAliasIn(rbuff, sizeof rbuff);
	      n = ntohs(((struct ip *) rbuff)->ip_len);
	    }
	    bp = mballoc(n, MB_IPIN);
	    bcopy(rbuff, MBUF_CTOP(bp), n);
	    IpInput(bp);
	    LogPrintf(LogDEBUG, "Looped back packet addressed to myself\n");
	  }
	  continue;
	} else
	  LogPrintf(LogDEBUG, "Oops - forwarding packet addressed to myself\n");
      }

      /*
       * Process on-demand dialup. Output packets are queued within tunnel
       * device until IPCP is opened.
       */
      if (LcpFsm.state <= ST_CLOSED && (mode & MODE_AUTO)) {
	pri = PacketCheck(rbuff, n, FL_DIAL);
	if (pri >= 0) {
	  if (mode & MODE_ALIAS) {
	    VarPacketAliasOut(rbuff, sizeof rbuff);
	    n = ntohs(((struct ip *) rbuff)->ip_len);
	  }
	  IpEnqueue(pri, rbuff, n);
	  dial_up = TRUE;	/* XXX */
	}
	continue;
      }
      pri = PacketCheck(rbuff, n, FL_OUT);
      if (pri >= 0) {
	if (mode & MODE_ALIAS) {
	  VarPacketAliasOut(rbuff, sizeof rbuff);
	  n = ntohs(((struct ip *) rbuff)->ip_len);
	}
	IpEnqueue(pri, rbuff, n);
      }
    }
  }
  LogPrintf(LogDEBUG, "Job (DoLoop) done.\n");
}
