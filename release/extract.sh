#!/bin/sh
# $Id: extract.sh,v 1.10 1994/11/12 09:55:29 jkh Exp $
PATH=/stand:$PATH
DDIR=/

if [ -f bin_tgz.aa ] ; then
	# Temporary kludge for pathological bindist.
	if [ -f $DDIR/etc/myname ]; then
		cp $DDIR/etc/hosts $DDIR/etc/myname $DDIR/stand/etc
	fi
	echo; echo "Extracting bindist, please wait." 
	cat bin_tgz.?? | gzip -c -d | tar --unlink -xvf - -C $DDIR
	if [ -f $DDIR/stand/etc/myname ]; then
		# Add back what the bindist nuked.
		cp $DDIR/stand/etc/myname $DDIR/etc
		cat $DDIR/stand/etc/hosts >> $DDIR/etc/hosts
	fi
fi

for i in *.aa
do
	b=`basename $i .aa`
	if [ "$b" != bin_tgz ] ; then
		if [ "$b" = des_tgz ] ; then
			# We cannot replace /sbin/init while it runs
			# so move it out of the way for now
			mv /sbin/init /sbin/nondes_init
		fi
		echo "Extracting $b"
		cat $b.?? | gzip -c -d | tar --unlink -xvf - -C $DDIR
	fi
done
