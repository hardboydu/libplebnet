#!/bin/sh
#
# $FreeBSD$
#

# Move all the manpages out to their own dist, using the base dist as a
# starting point.
if [ -d ${RD}/trees/base/usr/share/man ]; then
	( cd ${RD}/trees/base/usr/share/man;
	find . | cpio -dumpl ${RD}/trees/manpages/usr/share/man > /dev/null 2>&1) &&
	rm -rf ${RD}/trees/base/usr/share/man;
fi
if [ -d ${RD}/trees/base/usr/share/perl/man ]; then
	( cd ${RD}/trees/base/usr/share/perl/man;
	find . | cpio -dumpl ${RD}/trees/manpages/usr/share/perl/man > /dev/null 2>&1) &&
	rm -rf ${RD}/trees/base/usr/share/perl/man;
fi
