#!/bin/sh 
#
# Copyright (c) 1994 Geoffrey M. Rehmet, Rhodes University
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#	This product includes software developed by Geoffrey M. Rehmet
# 4. Neither the name of Geoffrey M. Rehmet nor that of Rhodes University
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL GEOFFREY M. REHMET OR RHODES UNIVERSITY BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $Id: manctl,v 1.3 1994/04/17 21:01:18 g89r4222 Exp $
#
# manctl: 
#	a utility for manipulating manual pages
# functions:
#	compress uncompressed man pages (elliminating .so's)
#	uncompress compressed man pages
#	purge old formatted man pages (not implemented yet)
# Things to watch out for:
#	Hard links - careful with g(un)zipping!
#	.so's - throw everything through soelim before gzip!
#	symlinks - ignore these - eg: expn is its own man page:
#			don't want to compress this!
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin

#
# purge cat? directories
#
do_purge()
{
	echo "purge $@" 2>&1
	echo "not implemented yet\n" 2>&1
}


#
# Uncompress one page
#
uncompress_page()
{
	local	pname
	local	fname
	local	sect
	local	ext

	# break up file name
	pname=$1
	IFS='.' ; set $pname
	# less than 3 fields - don't know what to do with this
	if [ $# -lt 3 ] ; then 
		IFS=" 	" ; echo ignoring $pname 1>&2 ; return 0 ; 
	fi
	# construct name and section
	fname=$1 ; shift
	while [ $# -gt 2 ] ; do
		fname=$fname.$1
		shift
	done
	sect=$1
	ext=$2

	IFS=" 	"
	case "$ext" in
	gz|Z) 	{ 
		IFS=" 	" ; set `file $pname`
		if [ $2 != "gzip" ] ; then 
			echo moving hard link $pname 1>&2
			mv $pname $fname.$ext	# link
		else
			if [ $2 != "symbolic" ] ; then
				echo gunzipping page $pname 1>&2
				gunzip -c $pname > /tmp/manager.$$
				chmod u+w $pname
				cp /tmp/manager.$$ $pname
				chmod 444 $pname
				mv $pname $fname.$sect
				rm /tmp/manager.$$
			else
				# skip symlinks - this can be
				# a program like expn, which is
				# its own man page !
				echo skipping symlink $pname 1>&2
			fi
		fi };;
	*)	{
		IFS=" 	"
		echo skipping file $pname 1>&2
		} ;;
	esac
	# reset IFS - this is important!
	IFS=" 	"
}


#
# Uncompress manpages in paths
#
do_uncompress()
{
	local	i
	local	dir

	while [ $# != 0 ] ; do
		if [ -d $1 ] ; then
			dir=$1
			for i in $dir/* ; do
				case $i in
				*cat?)	;; # ignore cat directories
				*)	{
					if [ -d $i ] ; then 
						do_uncompress $i
					else
						if [ -e $i ] ; then
							uncompress_page $i
						fi
					fi } ;;
				esac
			done
		else
			echo "directory $1 not found" 1>&2
		fi
		shift
	done
}

#
# compress one page
#	We need to watch out for hard links here.
#
compress_page()
{
	local	pname
	local	fname
	local	sect

	# break up file name
	pname=$1
	IFS='.' ; set $pname
	if [ $# -lt 2 ] ; then 
		IFS=" 	" ; echo ignoring $pname 1>&2 ; return 0 ; 
	fi
	# construct name and section
	fname=$1 ; shift
	while [ $# -gt 1 ] ; do
		fname=$fname.$1
		shift
	done
	sect=$1

	IFS=" 	"
	case "$sect" in
	gz) 	{ echo file $pname already gzipped 1>&2 ; } ;;
	Z)	{ echo file $pname already compressed 1>&2 ; } ;;
	[12345678ln]*){
		IFS=" 	" ; set `file $pname`
		if [ $2 = "gzip" ] ; then 
			echo moving hard link $pname 1>&2
			mv $pname $pname.gz	# link
		else
			if [ $2 != "symbolic" ] ; then
				echo gzipping page $pname 1>&2
				soelim $pname | gzip -c -- > /tmp/manager.$$
				chmod u+w $pname
				cp /tmp/manager.$$ $pname
				chmod 444 $pname
				mv $pname $pname.gz
				rm /tmp/manager.$$
			else
				# skip symlink - this can be
				# a program like expn, which is
				# its own man page !
				echo skipping symlink $pname 1>&2
			fi
		fi };;
	*)	{
		IFS=" 	"
		echo skipping file $pname 1>&2
		} ;;
	esac
	# reset IFS - this is important!
	IFS=" 	"
}

#
# Compress man pages in paths
#
do_compress()
{
	local	i
	local	dir

	while [ $# != 0 ] ; do
		if [ -d $1 ] ; then
			dir=$1
			for i in $dir/* ; do
				case $i in
				*cat?)	;; # ignore cat directories
				*)	{
					if [ -d $i ] ; then 
						do_compress $i
					else 
						if [ -e $i ] ; then
							compress_page $i
						fi
					fi } ;;
				esac
			done
		else
			echo "directory $1 not found" 1>&2
		fi
		shift
	done
}

#
# Display a usage message
#
ctl_usage()
{
	echo "usage : 	$1 -compress <path> ... " 1>&2
	echo "	 	$1 -uncompress <path> ... " 1>&2
	echo "	 	$1 -purge <days> <path> ... " 1>&2
	echo "	 	$1 -purge expire <path> ... " 1>&2
	exit 1
}


#
# dispatch options
#
if [ $# = 0 ] ; then ; ctl_usage $0 ; fi ;

case "$1" in
	-compress)	shift ; do_compress "$@" ;;
	-uncompress)	shift ; do_uncompress "$@" ;;
	-purge)		shift ; do_purge "$@" ;;
	*)		ctl_usage $0 ;;
esac
