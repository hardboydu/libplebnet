/*******************************************************************
** s y s d e p . c
** Forth Inspired Command Language
** Author: John Sadler (john_sadler@alum.mit.edu)
** Created: 16 Oct 1997
** Implementations of FICL external interface functions... 
**
*******************************************************************/

#include <stand.h>
#include "ficl.h"

/*
*******************  FreeBSD  P O R T   B E G I N S   H E R E ******************** Michael Smith
*/

UNS64 ficlLongMul(UNS32 x, UNS32 y)
{
    UNS64 q;
    u_int64_t qx;

    qx = (u_int64_t)x * (u_int64_t) y;

    q.hi = (u_int32_t)( qx >> 32 );
    q.lo = (u_int32_t)( qx & 0xFFFFFFFFL);

    return q;
}

UNSQR ficlLongDiv(UNS64 q, UNS32 y)
{
    UNSQR result;
    u_int64_t qx, qh;

    qh = q.hi;
    qx = (qh << 32) | q.lo;

    result.quot = qx / y;
    result.rem  = qx % y;

    return result;
}

void  ficlTextOut(FICL_VM *pVM, char *msg, int fNewline)
{
    IGNORE(pVM);

    while(*msg != 0)
	putchar(*(msg++));
    if (fNewline)
	putchar('\n');

   return;
}

void *ficlMalloc (size_t size)
{
    return malloc(size);
}

void  ficlFree   (void *p)
{
    free(p);
}

/*
** Stub function for dictionary access control - does nothing
** by default, user can redefine to guarantee exclusive dict
** access to a single thread for updates. All dict update code
** is guaranteed to be bracketed as follows:
** ficlLockDictionary(TRUE);
** <code that updates dictionary>
** ficlLockDictionary(FALSE);
**
** Returns zero if successful, nonzero if unable to acquire lock
** befor timeout (optional - could also block forever)
*/
#if FICL_MULTITHREAD
int ficlLockDictionary(short fLock)
{
	IGNORE(fLock);
	return 0;
}
#endif /* FICL_MULTITHREAD */


