#if defined(LIBC_RCS) && !defined(lint)
static const char rcsid[] =
  "$FreeBSD$";
#endif /* LIBC_RCS and not lint */

#include <stdlib.h>
#include <string.h>

extern const char *__progname;

void
setprogname(const char *progname)
{
	const char *p;

	p = strrchr(progname, '/');
	__progname = p != NULL ? p + 1 : progname;
}
