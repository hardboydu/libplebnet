/*
 * MD header for contrib/gdtoa
 *
 * This file can be generated by compiling and running contrib/gdtoa/qnan.c
 * on the target architecture after arith.h has been generated.
 *
 * $FreeBSD$
 */


#include <machine/endian.h>

#if BYTE_ORDER == BIG_ENDIAN
/* These values were gained on a running
 * Octeon in Big Endian order. They were gotten
 * by running ./qnan after arithchk was ran and
 * got us the proper values for arith.h.
 */
#define f_QNAN 0x7f900000
#define d_QNAN0 0x7ff80000
#define d_QNAN1 0x0
#define ld_QNAN0 0x7ff80000
#define ld_QNAN1 0x0
#define ld_QNAN2 0x0
#define ld_QNAN3 0x0
#define ldus_QNAN0 0x7ff8
#define ldus_QNAN1 0x0
#define ldus_QNAN2 0x0
#define ldus_QNAN3 0x0
#define ldus_QNAN4 0x0
#else
/* FIX FIX, need to run this on a Little Endian
 * machine and get the proper values, these here
 * were stolen fromn i386/gd_qnan.h
 */
#define f_QNAN 0x7fc00000
#define d_QNAN0 0x0
#define d_QNAN1 0x7ff80000
#define ld_QNAN0 0x0
#define ld_QNAN1 0xc0000000
#define ld_QNAN2 0x7fff
#define ld_QNAN3 0x0
#define ldus_QNAN0 0x0
#define ldus_QNAN1 0x0
#define ldus_QNAN2 0x0
#define ldus_QNAN3 0xc000
#define ldus_QNAN4 0x7fff
#endif
