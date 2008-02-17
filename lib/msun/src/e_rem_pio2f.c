/* e_rem_pio2f.c -- float version of e_rem_pio2.c
 * Conversion to float by Ian Lance Taylor, Cygnus Support, ian@cygnus.com.
 * Debugged and optimized by Bruce D. Evans.
 */

/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunPro, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 */

#ifndef lint
static char rcsid[] = "$FreeBSD$";
#endif

/* __ieee754_rem_pio2f(x,y)
 *
 * return the remainder of x rem pi/2 in y[0]+y[1]
 * use double precision internally
 * use __kernel_rem_pio2() for large x
 */

#include "math.h"
#include "math_private.h"

/*
 * invpio2:  53 bits of 2/pi
 * pio2_1:   first  33 bit of pi/2
 * pio2_1t:  pi/2 - pio2_1
 */

static const double
zero =  0.00000000000000000000e+00, /* 0x00000000, 0x00000000 */
half =  5.00000000000000000000e-01, /* 0x3FE00000, 0x00000000 */
two24 =  1.67772160000000000000e+07, /* 0x41700000, 0x00000000 */
invpio2 =  6.36619772367581382433e-01, /* 0x3FE45F30, 0x6DC9C883 */
pio2_1  =  1.57079632673412561417e+00, /* 0x3FF921FB, 0x54400000 */
pio2_1t =  6.07710050650619224932e-11; /* 0x3DD0B461, 0x1A626331 */

	int32_t __ieee754_rem_pio2f(float x, float *y)
{
	double w,t,r,fn;
	double tx[1],ty[2];
	float z;
	int32_t e0,n,ix,hx;

	GET_FLOAT_WORD(hx,x);
	ix = hx&0x7fffffff;
    /* 33+53 bit pi is good enough for medium size */
	if(ix<=0x49490f80) {		/* |x| ~<= 2^19*(pi/2), medium size */
	    t  = fabsf(x);
	    n  = (int32_t) (t*invpio2+half);
	    fn = (double)n;
	    r  = t-fn*pio2_1;
	    w  = fn*pio2_1t;
	    y[0] = r-w;
	    y[1] = (r-y[0])-w;
	    if(hx<0) 	{y[0] = -y[0]; y[1] = -y[1]; return -n;}
	    else	 return n;
	}
    /*
     * all other (large) arguments
     */
	if(ix>=0x7f800000) {		/* x is inf or NaN */
	    y[0]=y[1]=x-x; return 0;
	}
    /* set z = scalbn(|x|,ilogb(|x|)-23) */
	e0 = (ix>>23)-150;		/* e0 = ilogb(|x|)-23; */
	SET_FLOAT_WORD(z, ix - ((int32_t)(e0<<23)));
	tx[0] = z;
	n  =  __kernel_rem_pio2(tx,ty,e0,1,1);
	y[0] = ty[0];
	y[1] = ty[0] - y[0];
	if(hx<0) {y[0] = -y[0]; y[1] = -y[1]; return -n;}
	return n;
}
