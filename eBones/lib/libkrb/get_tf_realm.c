/*
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
 * For copying and distribution information, please see the file
 * <Copyright.MIT>.
 *
 *	from: get_tf_realm.c,v 4.2 90/01/02 13:40:19 jtkohl Exp $
 *	$Id: get_tf_realm.c,v 1.1.1.1 1994/09/30 14:50:00 csgr Exp $
 */

#ifndef lint
static char rcsid[] =
"$Id: get_tf_realm.c,v 1.1.1.1 1994/09/30 14:50:00 csgr Exp $";
#endif /* lint */

#include <krb.h>
#include <strings.h>

/*
 * This file contains a routine to extract the realm of a kerberos
 * ticket file.
 */

/*
 * krb_get_tf_realm() takes two arguments: the name of a ticket
 * and a variable to store the name of the realm in.
 *
 */

krb_get_tf_realm(ticket_file, realm)
  char *ticket_file;
  char *realm;
{
    return(krb_get_tf_fullname(ticket_file, 0, 0, realm));
}
