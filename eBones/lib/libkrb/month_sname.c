/*
 * Copyright 1985, 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 * For copying and distribution information, please see the file
 * <Copyright.MIT>.
 *
 *	from: month_sname.c,v 4.4 88/11/15 16:39:32 jtkohl Exp $
 *	$Id: month_sname.c,v 1.3 1995/07/18 16:39:19 mark Exp $
 */

#if 0
#ifndef lint
static char *rcsid =
"$Id: month_sname.c,v 1.3 1995/07/18 16:39:19 mark Exp $";
#endif /* lint */
#endif


/*
 * Given an integer 1-12, month_sname() returns a string
 * containing the first three letters of the corresponding
 * month.  Returns 0 if the argument is out of range.
 */

char *month_sname(int n)
{
    static char *name[] = {
        "Jan","Feb","Mar","Apr","May","Jun",
        "Jul","Aug","Sep","Oct","Nov","Dec"
    };
    return((n < 1 || n > 12) ? 0 : name [n-1]);
}
