/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * Major Changelog:
 *
 * Jordan K. Hubbard
 * 17 Jan 1996
 *
 * Turned inside out. Now returns xfers as new file ids, not as a special
 * `state' of FTP_t
 *
 * $Id: ftpio.c,v 1.5 1996/06/17 22:10:15 jkh Exp $
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ftpio.h>

#define SUCCESS		 0
#define FAILURE		-1

#ifndef TRUE
#define TRUE	(1)
#define FALSE	(0)
#endif

/* How to see by a given code whether or not the connection has timed out */
#define FTP_TIMEOUT(code)	(code == 421)

/* Internal routines - deal only with internal FTP_t type */
static FTP_t	ftp_new(void);
static int	ftp_read_method(void *n, char *buf, int nbytes);
static int	ftp_write_method(void *n, const char *buf, int nbytes);
static int	ftp_close_method(void *n);
static int	writes(int fd, char *s);
static __inline char *get_a_line(FTP_t ftp);
static int	get_a_number(FTP_t ftp, char **q);
static int	botch(char *func, char *botch_state);
static int	cmd(FTP_t ftp, const char *fmt, ...);
static int	ftp_login_session(FTP_t ftp, char *host, char *user, char *passwd, int port);
static int	ftp_file_op(FTP_t ftp, char *operation, char *file, FILE **fp, char *mode, int *seekto);
static int	ftp_close(FTP_t ftp);
static int	get_url_info(char *url_in, char *host_ret, int *port_ret, char *name_ret);

/* Global status variable - ick */
int FtpTimedOut;

/* FTP status codes */
#define FTP_BINARY_HAPPY	200
#define FTP_PORT_HAPPY		200
#define FTP_QUIT_HAPPY		221
#define FTP_TRANSFER_HAPPY	226
#define FTP_PASSIVE_HAPPY	227
#define FTP_CHDIR_HAPPY		250

/*
 * XXX
 * gross!  evil!  bad!  We really need an access primitive for cookie in stdio itself.
 * it's too convenient a hook to bury and it's already exported through funopen as it is, so...
 * XXX
 */
#define fcookie(fp)	((fp)->_cookie)

/* Placeholder in case we want to do any pre-init stuff at some point */ 
int
networkInit()
{
    return SUCCESS;	/* XXX dummy function for now XXX */
}

/* Check a return code with some lenience for back-dated garbage that might be in the buffer */
static int
check_code(FTP_t ftp, int var, int preferred)
{
    ftp->errno = 0;
    while (1) {
	if (var == preferred)
	    return 0;
	else if (var == 226)	/* last operation succeeded */
	    var = get_a_number(ftp, NULL);
	else if (var == 220)	/* chit-chat */
	    var = get_a_number(ftp, NULL);
	else if (var == 200)	/* success codes */
	    var = get_a_number(ftp, NULL);
	else {
	    ftp->errno = var;
	    return 1;
	}
    }
}
	    
/* Returns a standard FILE pointer type representing an open control connection */
FILE *
ftpLogin(char *host, char *user, char *passwd, int port)
{
    FTP_t n;
    FILE *fp;

    if (networkInit() != SUCCESS)
	return NULL;

    n = ftp_new();
    fp = NULL;
    if (n && ftp_login_session(n, host, user, passwd, port) == SUCCESS) {
	fp = funopen(n, ftp_read_method, ftp_write_method, NULL, ftp_close_method);	/* BSD 4.4 function! */
	fp->_file = n->fd_ctrl;
    }
    return fp;
}

int
ftpChdir(FILE *fp, char *dir)
{
    int i;
    FTP_t ftp = fcookie(fp);

    i = cmd(ftp, "CWD %s", dir);
    if (i < 0 || check_code(ftp, i, FTP_CHDIR_HAPPY))
	return i;
    return SUCCESS;
}

int
ftpErrno(FILE *fp)
{
    FTP_t ftp = fcookie(fp);
    return ftp->errno;
}

size_t
ftpGetSize(FILE *fp, char *name)
{
    int i;
    char p[BUFSIZ], *cp;
    FTP_t ftp = fcookie(fp);

    sprintf(p, "SIZE %s\r\n", name);
    i = writes(ftp->fd_ctrl, p);
    if (i)
	return (size_t)-1;
    i = get_a_number(ftp, &cp);
    if (check_code(ftp, i, 213))
	return (size_t)-1;
    return (size_t)atoi(cp);
}

time_t
ftpGetModtime(FILE *fp, char *name)
{
    char p[BUFSIZ], *cp;
    struct tm t;
    time_t t0 = time (0);
    FTP_t ftp = fcookie(fp);
    int i;

    sprintf(p, "MDTM %s\r\n", name);
    i = writes(ftp->fd_ctrl, p);
    if (i)
	return (time_t)0;
    i = get_a_number(ftp, &cp);
    if (check_code(ftp, i, 213))
	return (time_t)0;
    while (*cp && !isdigit(*cp))
	cp++;
    if (!*cp)
	return (time_t)0;
    t0 = localtime (&t0)->tm_gmtoff;
    sscanf(cp, "%04d%02d%02d%02d%02d%02d", &t.tm_year, &t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min, &t.tm_sec);
    t.tm_mon--;
    t.tm_year -= 1900;
    t.tm_isdst=-1;
    t.tm_gmtoff = 0;
    t0 += mktime (&t);
    return t0;
}

FILE *
ftpGet(FILE *fp, char *file, int *seekto)
{
    FILE *fp2;
    FTP_t ftp = fcookie(fp);

    if (ftp_file_op(ftp, "RETR", file, &fp2, "r", seekto) == SUCCESS)
	return fp2;
    return NULL;
}

FILE *
ftpPut(FILE *fp, char *file)
{
    FILE *fp2;
    FTP_t ftp = fcookie(fp);

    if (ftp_file_op(ftp, "STOR", file, &fp2, "w", NULL) == SUCCESS)
	return fp2;
    return NULL;
}

int
ftpBinary(FILE *fp, int st)
{
    FTP_t ftp = fcookie(fp);

    ftp->binary = st;
    return SUCCESS;
}

int
ftpPassive(FILE *fp, int st)
{
    FTP_t ftp = fcookie(fp);

    ftp->passive = st;
    return SUCCESS;
}

FILE *
ftpGetURL(char *url, char *user, char *passwd)
{
    char host[255], name[255];
    int port;
    static FILE *fp = NULL;
    FILE *fp2;

    if (fp) {	/* Close previous managed connection */
	fclose(fp);
	fp = NULL;
    }
    if (get_url_info(url, host, &port, name) == SUCCESS) {
	fp = ftpLogin(host, user, passwd, port);
	if (fp) {
	    fp2 = ftpGet(fp, name, NULL);
	    return fp2;
	}
    }
    return NULL;
}

FILE *
ftpPutURL(char *url, char *user, char *passwd)
{
    char host[255], name[255];
    int port;
    static FILE *fp = NULL;
    FILE *fp2;

    if (fp) {	/* Close previous managed connection */
	fclose(fp);
	fp = NULL;
    }
    if (get_url_info(url, host, &port, name) == SUCCESS) {
	fp = ftpLogin(host, user, passwd, port);
	if (fp) {
	    fp2 = ftpPut(fp, name);
	    return fp2;
	}
    }
    return NULL;
}

/* Internal workhorse function for dissecting URLs.  Takes a URL as the first argument and returns the
   result of such disection in the host, user, passwd, port and name variables. */
static int
get_url_info(char *url_in, char *host_ret, int *port_ret, char *name_ret)
{
    char *name, *host, *cp, url[BUFSIZ];
    int port;

    name = host = NULL;
    /* XXX add http:// here or somewhere reasonable at some point XXX */
    if (strncmp("ftp://", url_in, 6) != NULL)
	return FAILURE;
    /* We like to stomp a lot on the URL string in dissecting it, so copy it first */
    strncpy(url, url_in, BUFSIZ);
    host = url + 6;
    if ((cp = index(host, ':')) != NULL) {
	*(cp++) = '\0';
	port = strtol(cp, 0, 0);
    }
    else
	port = 0;	/* use default */
    if (port_ret)
	*port_ret = port;
    
    if ((name = index(cp ? cp : host, '/')) != NULL)
	*(name++) = '\0';
    if (host_ret)
	strcpy(host_ret, host);
    if (name && name_ret)
	strcpy(name_ret, name);
    return SUCCESS;
}

static FTP_t
ftp_new(void)
{
    FTP_t ftp;

    ftp = (FTP_t)malloc(sizeof *ftp);
    if (!ftp)
	return NULL;
    memset(ftp, 0, sizeof *ftp);
    ftp->fd_ctrl = -1;
    ftp->con_state = init;
    ftp->errno = 0;
    ftp->binary = TRUE;
    if (getenv("FTP_PASSIVE_MODE"))
	ftp->passive = 1;
    return ftp;
}

static int
ftp_read_method(void *vp, char *buf, int nbytes)
{
    int i, fd;
    FTP_t n = (FTP_t)vp;

    fd = n->fd_ctrl;
    i = (fd >= 0) ? read(fd, buf, nbytes) : EOF;
    return i;
}

static int
ftp_write_method(void *vp, const char *buf, int nbytes)
{
    int i, fd;
    FTP_t n = (FTP_t)vp;

    fd = n->fd_ctrl;
    i = (fd >= 0) ? write(fd, buf, nbytes) : EOF;
    return i;
}

static int
ftp_close_method(void *n)
{
    int i;

    i = ftp_close((FTP_t)n);
    free(n);
    return i;
}

static void
ftp_timeout()
{
    FtpTimedOut = TRUE;
    /* Debug("ftp_pkg: ftp_timeout called - operation timed out"); */
}

static int
writes(int fd, char *s)
{
    int n, i = strlen(s);

    /* Set the timer */
    FtpTimedOut = FALSE;
    signal(SIGALRM, ftp_timeout);
    alarm(120);
    /* Debug("ftp_pkg: writing \"%s\" to ftp connection %d", s, fd); */
    n = write(fd, s, i);
    alarm(0);
    if (i != n)
	return FAILURE;
    return SUCCESS;
}

static __inline char *
get_a_line(FTP_t ftp)
{
    static char buf[BUFSIZ];
    int i,j;

    /* Set the timer */
    FtpTimedOut = FALSE;
    signal(SIGALRM, ftp_timeout);

    /* Debug("ftp_pkg: trying to read a line from %d", ftp->fd_ctrl); */
    for(i = 0; i < BUFSIZ;) {
	alarm(120);
	j = read(ftp->fd_ctrl, buf + i, 1);
	alarm(0);
	if (j != 1)
	    return NULL;
	if (buf[i] == '\r' || buf[i] == '\n') {
	    if (!i)
		continue;
	    buf[i] = '\0';
	    return buf;
	}
	i++;
    }
    /* Debug("ftp_pkg: read string \"%s\" from %d", buf, ftp->fd_ctrl); */
    return buf;
}

static int
get_a_number(FTP_t ftp, char **q)
{
    char *p;
    int i = -1, j;

    while(1) {
	p = get_a_line(ftp);
	if (!p) {
	    ftp_close(ftp);
	    return FAILURE;
	}
	if (!(isdigit(p[0]) && isdigit(p[1]) && isdigit(p[2])))
	    continue;
	if (i == -1 && p[3] == '-') {
	    i = strtol(p, 0, 0);
	    continue;
	}
	if (p[3] != ' ' && p[3] != '\t')
	    continue;
	j = strtol(p, 0, 0);
	if (i == -1) {
	    if (q) *q = p+4;
	    /* Debug("ftp_pkg: read reply %d from server (%s)", j, p); */
	    return j;
	} else if (j == i) {
	    if (q) *q = p+4;
	    /* Debug("ftp_pkg: read reply %d from server (%s)", j, p); */
	    return j;
	}
    }
}

static int
ftp_close(FTP_t ftp)
{
    int i;

    if (ftp->con_state == isopen) {
	/* Debug("ftp_pkg: in ftp_close(), sending QUIT"); */
	i = cmd(ftp, "QUIT");
	close(ftp->fd_ctrl);
	ftp->fd_ctrl = -1;
	ftp->con_state = init;
	if (check_code(ftp, i, FTP_QUIT_HAPPY)) {
	    ftp->errno = i;
	    return FAILURE;
	}
	/* Debug("ftp_pkg: ftp_close() - proper shutdown"); */
	return SUCCESS;
    }
    /* Debug("ftp_pkg: ftp_close() - improper shutdown"); */
    return FAILURE;
}

static int
botch(char *func, char *botch_state)
{
    /* Debug("ftp_pkg: botch: %s(%s)", func, botch_state); */
    return FAILURE;
}

static int
cmd(FTP_t ftp, const char *fmt, ...)
{
    char p[BUFSIZ];
    int i;

    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(p, sizeof p, fmt, ap);
    va_end(ap);

    if (ftp->con_state != isopen)
	return botch("cmd", "open");

    strcat(p, "\r\n");
    i = writes(ftp->fd_ctrl, p);
    if (i)
	return FAILURE;
    while ((i = get_a_number(ftp, NULL)) == 220);
    return i;
}

static int
ftp_login_session(FTP_t ftp, char *host, char *user, char *passwd, int port)
{
    struct hostent	*he = NULL;
    struct sockaddr_in 	sin;
    int 		s;
    unsigned long 	temp;
    int			i;

    if (networkInit() != SUCCESS)
	return FAILURE;

    if (ftp->con_state != init) {
	ftp_close(ftp);
	return FAILURE;
    }

    if (!user)
	user = "ftp";

    if (!passwd)
	passwd = "setup@";

    if (!port)
	port = 21;

    temp = inet_addr(host);
    if (temp != INADDR_NONE) {
	ftp->addrtype = sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = temp;
    }
    else {
	he = gethostbyname(host);
	if (!he)
	    return FAILURE;
	ftp->addrtype = sin.sin_family = he->h_addrtype;
	bcopy(he->h_addr, (char *)&sin.sin_addr, he->h_length);
    }

    sin.sin_port = htons(port);

    if ((s = socket(ftp->addrtype, SOCK_STREAM, 0)) < 0)
	return FAILURE;

    if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
	(void)close(s);
	return FAILURE;
    }

    ftp->fd_ctrl = s;
    ftp->con_state = isopen;

    i = cmd(ftp, "USER %s", user);
    if (i >= 300 && i < 400)
	i = cmd(ftp, "PASS %s", passwd);
    if (i >= 299 || i < 0) {
	ftp_close(ftp);
	return FAILURE;
    }
    return SUCCESS;
}

static int
ftp_file_op(FTP_t ftp, char *operation, char *file, FILE **fp, char *mode, int *seekto)
{
    int i,s;
    char *q;
    unsigned char addr[64];
    struct sockaddr_in sin;
    u_long a;

    if (!fp)
	return FAILURE;
    *fp = NULL;

    if (ftp->con_state != isopen)
	return botch("ftp_file_op", "open");

    if (ftp->binary) {
	i = cmd(ftp, "TYPE I");
	if (check_code(ftp, i, FTP_BINARY_HAPPY)) {
	    ftp_close(ftp);
	    return i;
	}
    }

    if ((s = socket(ftp->addrtype, SOCK_STREAM, 0)) < 0)
	return FAILURE;

    if (ftp->passive) {
	if (writes(ftp->fd_ctrl, "PASV\r\n")) {
	    ftp_close(ftp);
	    return FAILURE;
	}
	i = get_a_number(ftp, &q);
	if (check_code(ftp, i, FTP_PASSIVE_HAPPY)) {
	    ftp_close(ftp);
	    return i;
	}
	while (*q && !isdigit(*q))
	    q++;
	if (!*q) {
	    ftp_close(ftp);
	    return FAILURE;
	}
	q--;
	for (i = 0; i < 6; i++) {
	    q++;
	    addr[i] = strtol(q, &q, 10);
	}

	sin.sin_family = ftp->addrtype;
	bcopy(addr, (char *)&sin.sin_addr, 4);
	bcopy(addr + 4, (char *)&sin.sin_port, 2);
	if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
	    (void)close(s);
	    return FAILURE;
	}
	if (seekto && *seekto) {
	    i = cmd(ftp, "RETR %d", *seekto);
	    if (i < 0 || FTP_TIMEOUT(i)) {
		close(s);
		ftp->errno = i;
		return i;
	    }
	    else if (i != 350)
		*seekto = 0;
	}
	i = cmd(ftp, "%s %s", operation, file);
	if (i < 0 || i > 299) {
	    close(s);
	    ftp->errno = i;
	    return i;
	}
	*fp = fdopen(s, mode);
    }
    else {
	int fd;

	i = sizeof sin;
	getsockname(ftp->fd_ctrl, (struct sockaddr *)&sin, &i);
	sin.sin_port = 0;
	i = sizeof sin;
	if (bind(s, (struct sockaddr *)&sin, i) < 0) {
	    close (s);	
	    return FAILURE;
	}
	getsockname(s,(struct sockaddr *)&sin,&i);
	if (listen(s, 1) < 0) {
	    close(s);	
	    return FAILURE;
	}
	a = ntohl(sin.sin_addr.s_addr);
	i = cmd(ftp, "PORT %d,%d,%d,%d,%d,%d",
		(a                   >> 24) & 0xff,
		(a                   >> 16) & 0xff,
		(a                   >>  8) & 0xff,
		a                           & 0xff,
		(ntohs(sin.sin_port) >>  8) & 0xff,
		ntohs(sin.sin_port)         & 0xff);
	if (check_code(ftp, i, FTP_PORT_HAPPY)) {
	    close(s);
	    return i;
	}
	if (seekto && *seekto) {
	    i = cmd(ftp, "RETR %d", *seekto);
	    if (i < 0 || FTP_TIMEOUT(i)) {
		close(s);
		ftp->errno = i;
		return i;
	    }
	    else if (i != 350)
		*seekto = 0;
	}
	i = cmd(ftp, "%s %s", operation, file);
	if (i < 0 || i > 299) {
	    close(s);
	    ftp->errno = i;
	    return FAILURE;
	}
	fd = accept(s, 0, 0);
	if (fd < 0) {
	    close(s);
	    ftp->errno = 401;
	    return FAILURE;
	}
	close(s);
	*fp = fdopen(fd, mode);
    }
    if (*fp)
	return SUCCESS;
    else
	return FAILURE;
}
