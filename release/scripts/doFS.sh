#!/bin/sh
#
# $FreeBSD$
#
set -e

export BLOCKSIZE=512

if [ "$1" = "-s" ]; then
	do_size="yes"; shift
else
	do_size=""
fi

FSIMG=$1; shift
RD=$1 ; shift
MNT=$1 ; shift
FSSIZE=$1 ; shift
FSPROTO=$1 ; shift
FSINODE=$1 ; shift
FSLABEL=$1 ; shift

deadlock=20

while true 
do
	rm -f ${FSIMG}

	if [ "x${MDDEVICE}" != "x" ] ; then
		umount /dev/${MDDEVICE} 2>/dev/null || true
		umount ${MNT} 2>/dev/null || true
		mdconfig -d -u ${MDDEVICE} 2>/dev/null || true
	fi

	dd of=${FSIMG} if=/dev/zero count=${FSSIZE} bs=1k 2>/dev/null
	# this suppresses the `invalid primary partition table: no magic'
	awk 'BEGIN {printf "%c%c", 85, 170}' |\
	    dd of=${FSIMG} obs=1 seek=510 conv=notrunc 2>/dev/null

	MDDEVICE=`mdconfig -a -t vnode -f ${FSIMG}`
	if [ ! -c /dev/${MDDEVICE} ] ; then
		if [ -f /dev/MAKEDEV ] ; then
			( cd /dev && sh MAKEDEV ${MDDEVICE} )
		else
			echo "No /dev/$MDDEVICE and no MAKEDEV" 1>&2
			exit 1
		fi
	fi
	disklabel -Brw /dev/${MDDEVICE} ${FSLABEL}
	newfs -i ${FSINODE} -T ${FSLABEL} -o space -m 1 /dev/${MDDEVICE}c

	mount /dev/${MDDEVICE}c ${MNT}

	if [ -d ${FSPROTO} ]; then
		(set -e && cd ${FSPROTO} && find . -print | cpio -dump ${MNT})
	else
		cp -p ${FSPROTO} ${MNT}
	fi

	df -ki ${MNT}

	set `df -ki ${MNT} | tail -1`

	umount ${MNT}
	mdconfig -d -u ${MDDEVICE} 2>/dev/null || true

	echo "*** Filesystem is ${FSSIZE} K, $4 left"
	echo "***     ${FSINODE} bytes/inode, $7 left"
	if [ "${do_size}" ]; then
		echo ${FSSIZE} > ${FSIMG}.size
	fi
	break;
done
