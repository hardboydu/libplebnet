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
 * $Id: main.c,v 1.3 1995/02/27 10:57:50 amurai Exp $
 * 
 *	TODO:
 *		o Add commands for traffic summary, version display, etc.
 *		o Add signal handler for misc controls.
 */
#include "fsm.h"
#include <fcntl.h>
#include <sys/time.h>
#include <termios.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "modem.h"
#include "os.h"
#include "hdlc.h"
#include "lcp.h"
#include "ipcp.h"
#include "vars.h"
#include "auth.h"
#include "filter.h"

#define LAUTH_M1 "Warning: No password entry for this host in ppp.secret\n"
#define LAUTH_M2 "Warning: All manipulation is allowed by anyone in a world\n"

#ifndef O_NONBLOCK
#ifdef O_NDELAY
#define	O_NONBLOCK O_NDELAY
#endif
#endif

extern void VjInit(), AsyncInit();
extern void AsyncInput(), IpOutput();
extern int  SelectSystem();

extern void DecodeCommand(), Prompt();
extern int IsInteractive();
extern struct in_addr ifnetmask;
static void DoLoop(void);

static struct termios oldtio;		/* Original tty mode */
static struct termios comtio;		/* Command level tty mode */
static int TermMode;
static int server, update;
struct sockaddr_in ifsin;

static void
TtyInit()
{
  struct termios newtio;
  int stat;

  stat = fcntl(0, F_GETFL, 0);
  stat |= O_NONBLOCK;
  fcntl(0, F_SETFL, stat);
  newtio = oldtio;
  newtio.c_lflag &= ~(ECHO|ISIG|ICANON);
  newtio.c_iflag = 0;
  newtio.c_oflag &= ~OPOST;
  newtio.c_cc[VEOF] = _POSIX_VDISABLE;
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
static void
TtyCommandMode()
{
  struct termios newtio;
  int stat;

  if (!(mode & MODE_INTER))
    return;
  tcgetattr(0, &newtio);
  newtio.c_lflag |= (ECHO|ICANON);
  newtio.c_iflag = oldtio.c_iflag;
  newtio.c_oflag |= OPOST;
  tcsetattr(0, TCSADRAIN, &newtio);
  stat = fcntl(0, F_GETFL, 0);
  stat |= O_NONBLOCK;
  fcntl(0, F_SETFL, stat);
  TermMode = 0;
  Prompt(0);
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
  stat &= ~O_NONBLOCK;
  fcntl(0, F_SETFL, stat);
  TermMode = 1;
}

void
Cleanup(excode)
int excode;
{
  int stat;

  OsLinkdown();
#ifdef notdef
  stat = fcntl(0, F_GETFL, 0);
  stat &= ~O_NONBLOCK;
  fcntl(0, F_SETFL, stat);
  tcsetattr(0, TCSANOW, &oldtio);
#endif
  OsCloseLink(1);
  sleep(1);
  if (mode & MODE_AUTO)
    DeleteIfRoutes(1);
  OsInterfaceDown(1);
  LogPrintf(LOG_PHASE, "PPP Terminated.\n");
  LogClose();
  if (server > 0)
    close(server);
#ifndef notdef
  stat = fcntl(0, F_GETFL, 0);
  stat &= ~O_NONBLOCK;
  fcntl(0, F_SETFL, stat);
  tcsetattr(0, TCSANOW, &oldtio);
#endif

  exit(excode);
}

static void
Hangup()
{
  LogPrintf(LOG_PHASE, "SIGHUP\n");
  signal(SIGHUP, Hangup);
  Cleanup(EX_HANGUP);
}

static void
CloseSession()
{
  LogPrintf(LOG_PHASE, "SIGTERM\n");
  LcpClose();
  Cleanup(EX_TERM);
}

void
Usage()
{
  fprintf(stderr, "Usage: ppp [-auto | -direct -dedicated] [system]\n");
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
    else if (strcmp(cp, "direct") == 0)
      mode |= MODE_DIRECT;
    else if (strcmp(cp, "dedicated") == 0)
      mode |= MODE_DEDICATED;
    else
      Usage();
    optc++;
    argv++; argc--;
  }
  if (argc > 1) {
    fprintf(stderr, "specify only one system label.\n");
    exit(EX_START);
  }
  if (argc == 1) dstsystem = *argv;

  if (optc > 1) {
    fprintf(stderr, "specify only one mode.\n");
    exit(EX_START);
  }
}

static void
Greetings()
{
  printf("User Process PPP. Written by Toshiharu OHNO.\r\n");
  fflush(stdout);
}

void
main(argc, argv)
int argc;
char **argv;
{
  int tunno;
  int on = 1;

  argc--; argv++;

  mode = MODE_INTER;		/* default operation is interactive mode */
  netfd = -1;
  ProcessArgs(argc, argv);
  Greetings();
  GetUid();
  IpcpDefAddress();

  if (SelectSystem("default", CONFFILE) < 0) {
    fprintf(stderr, "Warning: No default entry is given in config file.\n");
  }

  if (LogOpen())
    exit(EX_START);

  switch ( LocalAuthInit() ) {
    case NOT_FOUND:
    	fprintf(stderr,LAUTH_M1);
    	fprintf(stderr,LAUTH_M2);
	fflush (stderr);
	/* Fall down */
    case VALID:
	VarLocalAuth = LOCAL_AUTH;
	break;
    default:
	break;
  }

  if (OpenTunnel(&tunno) < 0) {
    perror("open_tun");
    exit(EX_START);
  }

  if (mode & (MODE_AUTO|MODE_DIRECT|MODE_DEDICATED))
    mode &= ~MODE_INTER;
  if (mode & MODE_INTER) {
    printf("Interactive mode\n");
    netfd = 0;
  } else if (mode & MODE_AUTO) {
    printf("Automatic mode\n");
    if (dstsystem == NULL) {
      fprintf(stderr, "Destination system must be specified in auto mode.\n");
      exit(EX_START);
    }
  }

  tcgetattr(0, &oldtio);		/* Save original tty mode */

  signal(SIGHUP, Hangup);
  signal(SIGTERM, CloseSession);
  signal(SIGINT, CloseSession);
#ifdef SIGSEGV
  signal(SIGSEGV, Hangup);
#endif
#ifdef SIGPIPE
  signal(SIGPIPE, Hangup);
#endif
#ifdef SIGALRM
  signal(SIGALRM, SIG_IGN);
#endif

  if (dstsystem) {
    if (SelectSystem(dstsystem, CONFFILE) < 0) {
      fprintf(stderr, "Destination system not found in conf file.\n");
      Cleanup(EX_START);
    }
    if ((mode & MODE_AUTO) && DefHisAddress.ipaddr.s_addr == INADDR_ANY) {
      fprintf(stderr, "Must specify dstaddr with auto mode.\n");
      Cleanup(EX_START);
    }
  }
  if (mode & MODE_DIRECT)
    printf("Packet mode enabled.\n");

#ifdef notdef
  if (mode & MODE_AUTO) {
    OsSetIpaddress(IpcpInfo.want_ipaddr, IpcpInfo.his_ipaddr, ifnetmask);
  }
#endif

  if (!(mode & MODE_INTER)) {
     int port = SERVER_PORT + tunno;
    /*
     *  Create server socket and listen at there.
     */
    server = socket(PF_INET, SOCK_STREAM, 0);
    if (server < 0) {
      perror("socket");
      Cleanup(EX_SOCK);
    }
    ifsin.sin_family = AF_INET;
    ifsin.sin_addr.s_addr = INADDR_ANY;
    ifsin.sin_port = htons(port);
    if (bind(server, (struct sockaddr *) &ifsin, sizeof(ifsin)) < 0) {
      perror("bind");
      if (errno == EADDRINUSE)
	fprintf(stderr, "Wait for a while, then try again.\n");
      Cleanup(EX_SOCK);
    }
    listen(server, 5);

    DupLog();
    if (!(mode & MODE_DIRECT)) {
      if (fork())
        exit(0);
    }
    LogPrintf(LOG_PHASE, "Listening at %d.\n", port);
#ifdef DOTTYINIT
    if (mode & (MODE_DIRECT|MODE_DEDICATED)) { /* } */
#else
    if (mode & MODE_DIRECT) {
#endif
      TtyInit();
    } else {
      setsid();			/* detach control tty */
    }
  } else {
    server = -1;
    TtyInit();
    TtyCommandMode();
  }
  LogPrintf(LOG_PHASE, "PPP Started.\n");


  do
   DoLoop();
  while (mode & MODE_DEDICATED);

  Cleanup(EX_DONE);
}

/*
 *  Turn into packet mode, where we speek PPP.
 */
void
PacketMode()
{
  if (RawModem(modem) < 0) {
    fprintf(stderr, "Not connected.\r\n");
    return;
  }

  AsyncInit();
  VjInit();
  LcpInit();
  IpcpInit();
  CcpInit();
  LcpUp();

  if (mode & (MODE_DIRECT|MODE_DEDICATED))
    LcpOpen(OPEN_ACTIVE);
  else
    LcpOpen(VarOpenMode);
  if ((mode & (MODE_INTER|MODE_AUTO)) == MODE_INTER) {
    TtyCommandMode();
    fprintf(stderr, "Packet mode.\r\n");
  }
}

static void
ShowHelp()
{
  fprintf(stderr, "Following commands are available\r\n");
  fprintf(stderr, " ~p\tEnter to Packet mode\r\n");
  fprintf(stderr, " ~.\tTerminate program\r\n");
}

static void
ReadTty()
{
  int n;
  char ch;
  static int ttystate;
#define MAXLINESIZE 200
  char linebuff[MAXLINESIZE];

#ifdef DEBUG
  logprintf("termode = %d, netfd = %d, mode = %d\n", TermMode, netfd, mode);
#endif
  if (!TermMode) {
    n = read(netfd, linebuff, sizeof(linebuff)-1);
    if (n > 0) {
      DecodeCommand(linebuff, n, 1);
    } else {
#ifdef DEBUG
      logprintf("connection closed.\n");
#endif
      close(netfd);
      netfd = -1;
      mode &= ~MODE_INTER;
    }
    return;
  }

  /*
   *  We are in terminal mode, decode special sequences
   */
  n = read(0, &ch, 1);
#ifdef DEBUG
  logprintf("got %d bytes\n", n);
#endif

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
      case '-':
	if (loglevel > 0) {
	  loglevel--;
	  fprintf(stderr, "New loglevel is %d\r\n", loglevel);
	}
	break;
      case '+':
	loglevel++;
	fprintf(stderr, "New loglevel is %d\r\n", loglevel);
	break;
#ifdef DEBUG
      case 'm':
	ShowMemMap();
	break;
#endif
      case 'p':
	/*
	 * XXX: Should check carrier.
	 */
	if (LcpFsm.state <= ST_CLOSED) {
	  VarOpenMode = OPEN_ACTIVE;
	  PacketMode();
	}
	break;
#ifdef DEBUG
      case 't':
	ShowTimers();
	break;
#endif
      case '.':
	TermMode = 1;
	TtyCommandMode();
	break;
      default:
	if (write(modem, &ch, n) < 0)
	  fprintf(stderr, "err in write.\r\n");
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
HdlcDetect(cp, n)
u_char *cp;
int n;
{
  char *ptr, *fp, **hp;

  cp[n] = '\0';	/* be sure to null terminated */
  ptr = NULL;
  for (hp = FrameHeaders; *hp; hp++) {
    fp = *hp;
    if (DEV_IS_SYNC)
      fp++;
    if (ptr = strstr((char *)cp, fp))
      break;
  }
  return((u_char *)ptr);
}

static struct pppTimer RedialTimer;

static void
RedialTimeout()
{
  StopTimer(&RedialTimer);
  LogPrintf(LOG_PHASE, "Redialing timer expired.\n");
}

static void
StartRedialTimer()
{
  LogPrintf(LOG_PHASE, "Enter pause for redialing.\n");
  StopTimer(&RedialTimer);
  RedialTimer.state = TIMER_STOPPED;
  RedialTimer.load = REDIAL_PERIOD * SECTICKS;
  RedialTimer.func = RedialTimeout;
  StartTimer(&RedialTimer);
}


static void
DoLoop()
{
  fd_set rfds, wfds, efds;
  int pri, i, n, wfd;
  struct sockaddr_in hisaddr;
  struct timeval timeout, *tp;
  int ssize = sizeof(hisaddr);
  u_char *cp;
  u_char rbuff[MAX_MRU];
  int dial_up;

  if (mode & MODE_DIRECT) {
    modem = OpenModem(mode);
    fprintf(stderr, "Packet mode enabled\n");
    PacketMode();
  } else if (mode & MODE_DEDICATED) {
    if (!modem)
      modem = OpenModem(mode);
  }

  fflush(stdout);

#ifdef SIGALRM
  timeout.tv_sec = 0;
#else
  timeout.tv_usec = 0;
#endif

  dial_up = FALSE;			/* XXXX */
  for (;;) {
    if ( modem ) 
	IpStartOutput();
    FD_ZERO(&rfds); FD_ZERO(&wfds); FD_ZERO(&efds);

   /*
    * If Ip packet for output is enqueued and require dial up,
    * Just do it!
    */
    if ( dial_up && RedialTimer.state != TIMER_RUNNING ) { /* XXX */
#ifdef DEBUG
      logprintf("going to dial: modem = %d\n", modem);
#endif
       modem = OpenModem(mode);
       if (modem < 0) {
         modem = 0;	       /* Set intial value for next OpenModem */
         StartRedialTimer();
       } else {
         if (DialModem()) {
           sleep(1);	       /* little pause to allow peer starts */
           ModemTimeout();
           PacketMode();
           dial_up = FALSE;
         } else {
           CloseModem();
           /* Dial failed. Keep quite during redial wait period. */
           StartRedialTimer();
         }
       }
    }
    if (modem) {
      FD_SET(modem, &rfds);
      FD_SET(modem, &efds);
      if (ModemQlen() > 0) {
	FD_SET(modem, &wfds);
      }
    }
    if (server > 0) FD_SET(server, &rfds);

    /*  *** IMPORTANT ***
     *
     *  CPU is serviced every TICKUNIT micro seconds.
     *	This value must be chosen with great care. If this values is
     *  too big, it results loss of characters from modem and poor responce.
     *  If this values is too small, ppp process eats many CPU time.
     */
#ifndef SIGALRM
    usleep(TICKUNIT);
    TimerService();
#endif

    FD_SET(tun_in, &rfds);
    if (netfd > -1) {
      FD_SET(netfd, &rfds);
      FD_SET(netfd, &efds);
    }


#ifndef SIGALRM
    /*
     *  Normally, select() will not block because modem is writable.
     *  In AUTO mode, select will block until we find packet from tun
     */
    tp = (RedialTimer.state == TIMER_RUNNING)? &timeout : NULL;
    i = select(tun_in+10, &rfds, &wfds, &efds, tp);
#else
    /* 
     * When SIGALRM timer is running, a select function will be
     * return -1 and EINTR after a Time Service signal hundler 
     * is done. 
     */
    i = select(tun_in+10, &rfds, &wfds, &efds, NULL);
#endif
    if ( i == 0 ) {
        continue;
    }

    if ( i < 0 ) {
       if ( errno == EINTR ) {
          continue;            /* Got SIGALRM, Do check a queue for dailing */
       }
       perror("select");
       break;
    } 

    if ((netfd > 0 && FD_ISSET(netfd, &efds)) || FD_ISSET(modem, &efds)) {
      logprintf("Exception detected.\n");
      break;
    }

    if (server > 0 && FD_ISSET(server, &rfds)) {
#ifdef DEBUG
      logprintf("connected to client.\n");
#endif
      wfd = accept(server, (struct sockaddr *)&hisaddr, &ssize);
      if (netfd > 0) {
	write(wfd, "already in use.\n", 16);
	close(wfd);
	continue;
      } else
	netfd = wfd;
      if (dup2(netfd, 1) < 0)
	perror("dup2");
      mode |= MODE_INTER;
      Greetings();
      switch ( LocalAuthInit() ) {
         case NOT_FOUND:
    	    fprintf(stdout,LAUTH_M1);
    	    fprintf(stdout,LAUTH_M2);
            fflush(stdout);
	    /* Fall down */
         case VALID:
	    VarLocalAuth = LOCAL_AUTH;
	    break;
         default:
	    break;
      }
      (void) IsInteractive();
      Prompt(0);
    }

    if ((mode & MODE_INTER) && FD_ISSET(netfd, &rfds)) {
      /* something to read from tty */
      ReadTty();
    }
    if (modem) {
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
          LogDumpBuff(LOG_ASYNC, "ReadFromModem", rbuff, n);

	if (LcpFsm.state <= ST_CLOSED) {
	  /*
	   *  In dedicated mode, we just discard input until LCP is started.
	   */
	  if (!(mode & MODE_DEDICATED)) {
	    cp = HdlcDetect(rbuff, n);
	    if (cp) {
	      /*
	       * LCP packet is detected. Turn ourselves into packet mode.
	       */
	      if (cp != rbuff) {
	        write(1, rbuff, cp - rbuff);
	        write(1, "\r\n", 2);
	      }
	      PacketMode();
#ifdef notdef
	      AsyncInput(cp, n - (cp - rbuff));
#endif
	    } else
	      write(1, rbuff, n);
	  }
	} else {
	  if (n > 0)
	    AsyncInput(rbuff, n);
#ifdef notdef
	  continue;			/* THIS LINE RESULT AS POOR PERFORMANCE */
#endif
	}
      }
    }

    if (FD_ISSET(tun_in, &rfds)) {	/* something to read from tun */
      /*
       *  If there are many packets queued, wait until they are drained.
       */
      if (ModemQlen() > 5)
	continue;
      
      n = read(tun_in, rbuff, sizeof(rbuff));
      if (n < 0) {
	perror("read from tun");
	continue;
      }
      /*
       *  Process on-demand dialup. Output packets are queued within tunnel
       *  device until IPCP is opened.
       */
      if (LcpFsm.state <= ST_CLOSED && (mode & MODE_AUTO)) {
	pri = PacketCheck(rbuff, n, FL_DIAL);
	if (pri >= 0) {
	  IpEnqueue(pri, rbuff, n);
          dial_up = TRUE;		/* XXX */
	}
	continue;
      }
      pri = PacketCheck(rbuff, n, FL_OUT);
      if (pri >= 0)
	IpEnqueue(pri, rbuff, n);
    }
  }
  logprintf("job done.\n");
}
