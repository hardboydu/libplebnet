#!/bin/sh
# $Id: update.pl,v 1.4 1998/08/10 19:07:53 abial Exp $
pwd=`pwd`
echo -n "Uaktualniam katalog /etc na dyskietce...  "
mount /dev/fd0a /start_floppy
if [ "X$?" != "X0" ]
then
	echo ""
	echo "B��d podczas montowania read/write dyskietki!"
	echo "Sprawd�, czy nie jest zabezpieczona przed zapisem..."
	exit 1
fi
cd /etc
cp -Rp . /start_floppy/etc/
echo " Zrobione."
echo -n "Uaktualniam parametry j�dra..."
kget -incore /start_floppy/kernel.config /stand/vanilla
umount /dev/fd0a
cd /etc
cd ${pwd}
echo " Zrobione."
