#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#ident	"%Z%%M%	%I%	%E% SMI"

##
#
# ASSERTION:
# Using -G option with dtrace utility produces an ELF file containing a
# DTrace program. If the filename used with the -s option does not end
# with .d, and the -o option is not used, then the output ELF file is
# in d.out.
#
# SECTION: dtrace Utility/-G Option
#
##

script()
{
	$dtrace -G -s /dev/stdin <<EOF
	BEGIN
	{
		printf("This test should compile.\n");
		exit(0);
	}
EOF
}

if [ $# != 1 ]; then
	echo expected one argument: '<'dtrace-path'>'
	exit 2
fi

dtrace=$1
script
status=$?

if [ "$status" -ne 0 ]; then
	echo $tst: dtrace failed
	exit $status
fi

if [ ! -a "d.out" ]; then
	echo $tst: file not generated
	exit 1
fi

/usr/bin/rm -f "d.out"
exit 0
