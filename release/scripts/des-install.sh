#!/bin/sh
#
if [ "`id -u`" != "0" ]; then
	echo "Sorry, this must be done as root."
	exit 1
fi
_DEST=${DESTDIR:-/}
echo "You are about to extract the DES distribution into ${_DEST} - are you SURE"
echo "you want to do this over your installed system?  If not, hit ^C now,"
echo -n "otherwise hit return to continue. "
read junk
cat des.?? | tar --unlink -xpzf - -C ${_DEST}
cat krb.?? | tar --unlink -xpzf - -C ${_DEST}
echo -n "Do you want to install the DES sources (y/n)? "
read ans
if [ "$ans" = "y" ]; then
	cat scrypto.?? | tar --unlink -xpzf - -C ${_DEST}/usr/src
	cat skerbero.?? | tar --unlink -xpzf - -C ${_DEST}/usr/src
	cat ssecure.?? | tar --unlink -xpzf - -C ${_DEST}/usr/src
fi
exit 0
