#!/bin/sh
# $Id: extract_src.sh,v 1.6 1995/03/21 21:44:54 jkh Exp $
PATH=/stand:$PATH
DDIR=/usr/src

for DIST in base srcbin etc games gnu include lib libexec release sbin lkm \
	release share sys usrbin usrsbin; do
	if [ -f ${DIST}/${DIST}.aa ]; then
		echo "Extracting ${DIST} sources"
		cat ${DIST}/${DIST}.?? 
			| gzip -c -d | ( cd $DDIR; cpio -H tar -imdu )
	fi
done
ln -fs /usr/src/sys /sys
