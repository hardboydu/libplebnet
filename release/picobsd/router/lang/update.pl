#!/bin/sh
# $FreeBSD$
echo -n "Uaktualniam katalog /etc na dyskietce...  "
mount /dev/fd0a /start_floppy
cd /etc
cp -Rp . /start_floppy/etc/
echo " Zrobione."
echo -n "Uaktualniam parametry jadra..."
kget /start_floppy/boot/kernel.conf
umount /dev/fd0a
echo " Zrobione."
