/* msgcat.c -
   X/Open message catalogue functions and gencat utility.

     Written by James Clark (jjc@jclark.com).
*/

#include "config.h"

#ifndef HAVE_CAT

/* In this implementation the message catalogue format is the same as the
message text source file format (see pp 42-43 of the X/Open
Portability Guide, Issue 3, Volume 3.)  This means that you don't have
to use the gencat utility, but it is still useful for checking and
merging catalogues. */

/* Compile this with -DGENCAT to get the gencat utility. */

#include "std.h"
#include "msgcat.h"

#ifdef USE_PROTOTYPES
#define P(parms) parms
#else
#define P(parms) ()
#endif

/* Default message set. */
#define NL_SETD 1

#ifndef PATH_FILE_SEP
#define PATH_FILE_SEP ':'
#endif

#ifndef DEFAULT_NLSPATH
#define DEFAULT_NLSPATH ""
#endif

#ifndef DEFAULT_LANG
#define DEFAULT_LANG "default"
#endif

#define HASH_TAB_SIZE 251

struct message {
     struct message *next;
     unsigned msgnum;
     unsigned setnum;
     char *text;
};
     
struct cat {
     char *name;
     int loaded;
     int bad;
     struct message *table[HASH_TAB_SIZE];
};

static char *read_buf = 0;
static unsigned read_buf_len = 0;

/* Errors that can be generated by read_catalog. */

enum cat_err {
     E_ZERO,			/* not an error */
     E_BADARG,
     E_NOMEM,
     E_NOSUCHCOMMAND,
     E_INPUT,
     E_EOF,
     E_BADSEP,
     E_BADLINE
};

#ifdef GENCAT
/* These must match enum cat_err. */
static char *cat_errlist[] = {
     "Error 0",
     "Invalid argument to command",
     "Out of memory",
     "Unrecognized command",
     "Input error",
     "Unexpected end of file",
     "Space or tab expected after message number",
     "Invalid line",
};
#endif /* GENCAT */

#ifndef GENCAT
/* The value of NLSPATH. */
static char *nlspath = 0;
/* The value of LANG. */
static char *lang = 0;
#endif /* not GENCAT */

static int current_lineno = -1;
static enum cat_err cat_errno = E_ZERO;

#ifndef GENCAT
static void load_catalog P((struct cat *));
static FILE *find_catalog P((char *, char **));
#endif
static int read_catalog P((FILE *, struct message **));
static void delete_set P((struct message **, unsigned));
static void delete_message P((struct message **, unsigned, unsigned));
static int hash P((unsigned setnum, unsigned msgnum));
static char *parse_text P((FILE *, int));

#ifndef GENCAT

nl_catd catopen(name, oflag)
char *name;
int oflag;
{
     struct cat *catp;
     int i;

     if (!name)
	  return 0;
     
     catp = (struct cat *)malloc(sizeof *catp);
     if (!catp)
	  return 0;
     for (i = 0; i < HASH_TAB_SIZE; i++)
	  catp->table[i] = 0;
     catp->name = malloc(strlen(name) + 1);
     catp->loaded = 0;
     catp->bad = 0;
     strcpy(catp->name, name);
     return (nl_catd)catp;
}

int catclose(catd)
nl_catd catd;
{
     int i;
     struct cat *catp = (struct cat *)catd;

     if (!catp)
	  return 0;

     for (i = 0; i < HASH_TAB_SIZE; i++) {
	  struct message *p, *nextp;
	  for (p = catp->table[i]; p; p = nextp) {
	       nextp = p->next;
	       free(p->text);
	       free((char *)p);
	  }
     }
     if (catp->name)
	  free(catp->name);
     free((char *)catp);
     return 0;
}

char *catgets(catd, setnum, msgnum, dflt)
nl_catd catd;
int setnum, msgnum;
char *dflt;
{
     struct message *p;
     struct cat *catp;

     /* setnum and msgnum are required to be >= 1. */
     if (!catd || setnum <= 0 || msgnum <= 0)
	  return dflt;
     catp = (struct cat *)catd;
     if (!catp->loaded)
	  load_catalog(catp);
     if (catp->bad)
	  return dflt;
     for (p = catp->table[hash(setnum, msgnum)]; p; p = p->next)
	  if (p->msgnum == msgnum && p->setnum == setnum)
	       break;
     if (!p)
	  return dflt;
     return p->text;
}

static
VOID load_catalog(catp)
struct cat *catp;
{
     FILE *fp;
     char *path;

     catp->loaded = 1;
     fp = find_catalog(catp->name, &path);
     if (!fp) {
	  catp->bad = 1;
	  return;
     }
     current_lineno = 0;
     if (read_catalog(fp, catp->table) < 0)
	  catp->bad = 1;
     fclose(fp);
     if (read_buf) {
	  free(read_buf);
	  read_buf = 0;
     }
     read_buf_len = 0;
     free(path);
}

static
FILE *find_catalog(name, pathp)
char *name;
char **pathp;
{
     char *path;

     if (!name)
	  return 0;
     if (!nlspath) {
	  nlspath = getenv("NLSPATH");
	  if (!nlspath)
	       nlspath = DEFAULT_NLSPATH;
     }
     if (!lang) {
	  lang = getenv("LANG");
	  if (!lang)
	       lang = DEFAULT_LANG;
     }
     path = nlspath;
     for (;;) {
	  char *p;
	  unsigned len = 0;

	  for (p = path; *p != '\0' && *p != PATH_FILE_SEP; p++) {
	       if (*p == '%') {
		    if (p[1] == 'N') {
			 p++;
			 len += strlen(name);
		    }
		    else if (p[1] == 'L') {
			 p++;
			 len += strlen(lang);
		    }
		    else if (p[1] == '%') {
			 p++;
			 len++;
		    }
		    else
			 len++;

	       }
	       else
		    len++;
	  }
	  if (len > 0) {
	       char *s, *try;
	       FILE *fp;
	       s = try = malloc(len + 1);
	       if (!s)
		    return 0;
	       for (p = path; *p != '\0' && *p != PATH_FILE_SEP; p++) {
		    if (*p == '%') {
			 if (p[1] == 'N') {
			      p++;
			      strcpy(s, name);
			      s += strlen(name);
			 }
			 else if (p[1] == 'L') {
			      p++;
			      strcpy(s, lang);
			      s += strlen(lang);
			 }
			 else if (p[1] == '%') {
			      p++;
			      *s++ = '%';
			 }
			 else
			      *s++ = *p;
		    }
		    else
			 *s++ = *p;
	       }
	       *s++ = '\0';
	       fp = fopen(try, "r");
	       if (fp) {
		    *pathp = try;
		    return fp;
	       }
	       free(try);
	  }
	  if (*p == '\0')
	       break;
	  path = ++p;
     }
     return 0;
}

#endif /* not GENCAT */

/* 0 success, -1 error */

static
int parse_message(c, fp, table, setnum, quote)
int c;
FILE *fp;
struct message **table;
unsigned setnum;
int quote;
{
     unsigned msgnum;
     struct message *msgp;
     char *text;
     int hc;

     msgnum = c - '0';
     for (;;) {
	  c = getc(fp);
	  if (!isdigit(c))
	       break;
	  msgnum = msgnum*10 + (c - '0');
     }
     if (c == '\n') {
	  delete_message(table, setnum, msgnum);
	  return 0;
     }
     if (c != ' ' && c != '\t') {
	  cat_errno = E_BADSEP;
	  return -1;
     }
     text = parse_text(fp, quote);
     if (!text)
	  return -1;
     hc = hash(setnum, msgnum);
     for (msgp = table[hc]; msgp; msgp = msgp->next)
	  if (msgp->setnum == setnum && msgp->msgnum == msgnum)
	       break;
     if (msgp)
	  free(msgp->text);
     else {
	  msgp = (struct message *)malloc(sizeof *msgp);
	  if (!msgp) {
	       cat_errno = E_NOMEM;
	       return -1;
	  }
	  msgp->next = table[hc];
	  table[hc] = msgp;
	  msgp->msgnum = msgnum;
	  msgp->setnum = setnum;
     }
     msgp->text = text;
     return 0;
}

static
char *parse_text(fp, quote)
FILE *fp;
int quote;
{
     unsigned i = 0;
     char *p;
     int c;
     int quoted;

     c = getc(fp);
     if (c == quote) {
	  quoted = 1;
	  c = getc(fp);
     }
     else
	  quoted = 0;
     for (;; c = getc(fp)) {
	  if (c == EOF) {
	       if (ferror(fp)) {
		    cat_errno = E_INPUT;
		    return 0;
	       }
	       break;
	  }
	  if (c == '\n')
	       break;
	  /* XXX

	     Can quotes be used in quoted message text if protected by \ ?

	     Is it illegal to omit the closing quote if there's an opening
	     quote?

	     Is it illegal to have anything after a closing quote?

	  */

	  if (quoted && c == quote) {
	       /* Skip the rest of the line. */
	       while ((c = getc(fp)) != '\n')
		    if (c == EOF) {
			 if (ferror(fp)) {
			      cat_errno = E_INPUT;
			      return 0;
			 }
			 break;
		    }
	       break;
	  }
	  if (c == '\\') {
	       int d;

	       c = getc(fp);
	       if (c == EOF)
		    break;
	       switch (c) {
	       case '\n':
		    current_lineno++;
		    continue;
	       case 'n':
		    c = '\n';
		    break;
	       case 'b':
		    c = '\b';
		    break;
	       case 'f':
		    c = '\f';
		    break;
	       case 't':
		    c = '\t';
		    break;
	       case 'v':
		    c = '\v';
		    break;
	       case 'r':
		    c = '\r';
		    break;
	       case '\\':
		    c = '\\';
		    break;
	       case '0':
	       case '1':
	       case '2':
	       case '3':
	       case '4':
	       case '5':
	       case '6':
	       case '7':
		    c -= '0';
		    d = getc(fp);
		    if (d >= '0' && d <= '7') {
			 c = c*8 + d - '0';
			 d = getc(fp);
			 if (d >= '0' && d <= '7')
			      c = c*8 + d - '0';
			 else if (d != EOF)
			      ungetc(d,fp);
		    }
		    else if (d != EOF)
			 ungetc(d, fp);
		    if (c == '\0')
			 continue; /* XXX */
		    break;
	       default:
		    /* Ignore the quote. */
		    break;
	       }
	  }
	  if (i >= read_buf_len) {
	       if (!read_buf)
		    read_buf = malloc(read_buf_len = 40);
	       else
		    read_buf = realloc(read_buf, read_buf_len *= 2);
	       if (!read_buf) {
		    cat_errno = E_NOMEM;
		    return 0;
	       }
	  }
	  read_buf[i++] = c;
     }
     p = malloc(i + 1);
     if (!p) {
	  cat_errno = E_NOMEM;
	  return 0;
     }
     memcpy(p, read_buf, i);
     p[i] = '\0';
     return p;
}
	  
/* 0 success, -1 error */

static
int parse_command(fp, table, setnump, quotep)
FILE *fp;
struct message **table;
unsigned *setnump;
int *quotep;
{
     char buf[128];
     if (fgets(buf, 128, fp) == NULL) {
	  cat_errno = ferror(fp) ? E_INPUT : E_EOF;
	  return -1;
     }
     if (buf[0] == ' ' || buf[0] == '\t' || buf[0] == '\n')
	  /* a comment */;
     else if (strncmp(buf, "set", 3) == 0) {
	  if (sscanf(buf + 3, "%u", setnump) != 1) {
	       cat_errno = E_BADARG;
	       return -1;
	  }

     }
     else if (strncmp(buf, "delset", 6) == 0) {
	  unsigned num;
	  if (sscanf(buf + 6, "%u", &num) != 1) {
	       cat_errno = E_BADARG;
	       return -1;
	  }
	  delete_set(table, num);
	  *setnump = NL_SETD;
     }
     else if (strncmp(buf, "quote", 5) == 0) {
	  char *p = buf + 5;
	  while (*p == ' ' || *p == '\t')
	       p++;
	  /* XXX should \ be allowed as the quote character? */
	  if (*p == '\0' || *p == '\n')
	       *quotep = -1;
	  else
	       *quotep = *p;
     }
     else {
	  cat_errno = E_NOSUCHCOMMAND;
	  return -1;
     }
     if (strchr(buf, '\n') == 0) {
	  int c;
	  while ((c = getc(fp)) != '\n' && c != EOF)
	       ;
     }
     return 0;
}


static
VOID delete_set(table, setnum)
struct message **table;
unsigned setnum;
{
     int i;

     for (i = 0; i < HASH_TAB_SIZE; i++) {
	  struct message *p, *nextp;
	  for (p = table[i], table[i] = 0; p; p = nextp) {
	       nextp = p->next;
	       if (p->setnum == setnum)
		    free((char *)p);
	       else {
		    p->next = table[i];
		    table[i] = p;
	       }
	  }
     }
}

static
VOID delete_message(table, setnum, msgnum)
struct message **table;
unsigned setnum, msgnum;
{
     struct message **pp;
     
     for (pp = &table[hash(setnum, msgnum)]; *pp; pp = &(*pp)->next)
	  if ((*pp)->setnum == setnum && (*pp)->msgnum == msgnum) {
	       struct message *p = *pp;
	       *pp = p->next;
	       free(p->text);
	       free((char *)p);
	       break;
	  }
}

/* 0 success, -1 error. On error cat_errno is set to the error number. */

static
int read_catalog(fp, table)
FILE *fp;
struct message **table;
{
     int c;
     unsigned setnum = NL_SETD;
     int quote_char = -1;

     for (;;) {
	  /* start of line */
	  c = getc(fp);
	  if (c == EOF)
	       break;
	  ++current_lineno;
	  if (isdigit(c)) {
	       if (parse_message(c, fp, table, setnum, quote_char) < 0)
		    return -1;
	  }
	  else if (c == '$') {
	       if (parse_command(fp, table, &setnum, &quote_char) < 0)
		    return -1;
	  }
	  else if (c != '\n') {
	       while ((c = getc(fp)) != '\n' && c != EOF)
		    if (c != ' ' && c != '\t') {
			 cat_errno = E_BADLINE;
			 return -1;
		    }
	       if (c == EOF)
		    break;
	  }
     }
     return 0;
}

static
int hash(setnum, msgnum)
unsigned setnum, msgnum;
{
     return ((setnum << 8) + msgnum) % HASH_TAB_SIZE;
}

#ifdef GENCAT

static char *program_name;

static int message_compare P((UNIV, UNIV));
static void print_text P((char *, FILE *));
static void usage P((void));

#ifdef VARARGS
static void fatal();
#else
static void fatal P((char *,...));
#endif

int main(argc, argv)
int argc;
char **argv;
{
     FILE *fp;
     int i, j, nmessages;
     struct message **list;
     unsigned setnum;
     struct message *table[HASH_TAB_SIZE];
    
     program_name = argv[0];
     
     if (argc < 3)
	  usage();

     for (i = 0; i < HASH_TAB_SIZE; i++)
	  table[i] = 0;
     for (i = 1; i < argc; i++) {
	  errno = 0;
	  fp = fopen(argv[i], "r");
	  if (!fp) {
	       if (i > 1)
		    fatal("can't open `%s': %s", argv[i], strerror(errno));
	  }
	  else {
	       current_lineno = 0;
	       cat_errno = E_ZERO;
	       if (read_catalog(fp, table) < 0) {
		    assert(cat_errno != E_ZERO);
		    assert(cat_errno
			   < sizeof(cat_errlist)/sizeof(cat_errlist[0]));
		    fatal("%s:%d: %s", argv[i], current_lineno,
			  cat_errlist[cat_errno]);
	       }
	       fclose(fp);
	  }
     }
     
     errno = 0;
     fp = fopen(argv[1], "w");
     if (!fp)
	  fatal("can't open `%s' for output: %s", argv[1], strerror(errno));
     nmessages = 0;
     for (i = 0; i < HASH_TAB_SIZE; i++) {
	  struct message *p;
	  for (p = table[i]; p; p = p->next)
	       nmessages++;
     }
     list = (struct message **)malloc(nmessages*sizeof(struct message *));
     if (!list)
	  fatal("out of memory");
     j = 0;
     for (i = 0; i < HASH_TAB_SIZE; i++) {
	  struct message *p;
	  for (p = table[i]; p; p = p->next)
	       list[j++] = p;
     }
     assert(j == nmessages);
     
     qsort((UNIV)list, nmessages, sizeof(struct message *), message_compare);

     setnum = NL_SETD;
     for (i = 0; i < nmessages; i++) {
	  struct message *p = list[i];
	  if (p->setnum != setnum) {
	       setnum = p->setnum;
	       fprintf(fp, "$set %u\n", setnum);
	  }
	  fprintf(fp, "%u ", p->msgnum);
	  print_text(p->text, fp);
	  putc('\n', fp);
     }
     if (fclose(fp) == EOF)
	  fatal("error closing `%s'", argv[1]);
     return 0;
}

static
VOID usage()
{
     fprintf(stderr, "usage: %s catfile msgfile...\n", program_name);
     exit(1);
}

static
#ifdef VARARGS
VOID fatal(va_alist) va_dcl
#else /* not VARARGS */
VOID fatal(char *message,...)
#endif /* not VARARGS */
{
     va_list ap;

#ifdef VARARGS
     char *message;
     va_start(ap);
     message = va_arg(ap, char *);
#else /* not VARARGS */
     va_start(ap, message);
#endif /* not VARARGS */ 
     
     fprintf(stderr, "%s: ", program_name);
     vfprintf(stderr, message, ap);
     putc('\n', stderr);
     va_end(ap);
     exit(1);
}

static
int message_compare(p1, p2)
UNIV p1, UNIV p2;
{
     struct message *m1 = *(struct message **)p1;
     struct message *m2 = *(struct message **)p2;

     if (m1->setnum < m2->setnum)
	  return -1;
     if (m1->setnum > m2->setnum)
	  return 1;
     if (m1->msgnum < m2->msgnum)
	  return -1;
     if (m1->msgnum > m2->msgnum)
	  return 1;
     return 0;
}

static
VOID print_text(s, fp)
char *s;
FILE *fp;
{
     for (; *s; s++) {
	  if (*s == '\\')
	       fputs("\\\\", fp);
	  else if (ISASCII(*s) && isprint((UNCH)*s))
	       putc(*s, fp);
	  else {
	       switch (*s) {
	       case '\n':
		    fputs("\\n", fp);
		    break;
	       case '\b':
		    fputs("\\b", fp);
		    break;
	       case '\f':
		    fputs("\\f", fp);
		    break;
	       case '\t':
		    fputs("\\t", fp);
		    break;
	       case '\v':
		    fputs("\\v", fp);
		    break;
	       case '\r':
		    fputs("\\r", fp);
		    break;
	       default:
		    fprintf(fp, "\\%03o", (unsigned char)*s);
		    break;
	       }
	  }
     }
}

#endif /* GENCAT */

#ifdef TEST

int main(argc, argv)
int argc;
char **argv;
{
     nl_catd catd;
     int msgnum, setnum;
     
     if (argc != 2) {
	  fprintf(stderr, "usage: %s catalogue\n", argv[0]);
	  exit(1);
     }
     catd = catopen(argv[1], 0);
     fprintf(stderr, "Enter set number, message number pairs:\n");
     fflush(stderr);
     while (scanf("%d %d", &setnum, &msgnum) == 2) {
	  char *msg = catgets(catd, setnum, msgnum, "<default>");
	  fprintf(stderr, "Returned \"%s\"\n", msg);
	  fflush(stderr);
     }
     return 0;
}

#endif /* TEST */

#endif /* not HAVE_CAT */
/*
Local Variables:
c-indent-level: 5
c-continued-statement-offset: 5
c-brace-offset: -5
c-argdecl-indent: 0
c-label-offset: -5
End:
*/
