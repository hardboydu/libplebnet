#!/bin/sh
#
# $Id: rc.pl,v 1.3 1998/08/10 19:07:53 abial Exp $
#
############################################
### Special setup for one floppy PICOBSD ###
### THIS IS NOT THE NORMAL /etc/rc !!!!! ###
############################################
mount -a -t nonfs
if [ -f /etc/rc.conf ]; then
    . /etc/rc.conf
fi
# configure serial devices
if [ -f /etc/rc.serial ]; then
	. /etc/rc.serial
fi
# start up the initial network configuration.
if [ -f /etc/rc.network ]; then
	. /etc/rc.network
	network_pass1
fi
if [ -n "$network_pass1_done" ]; then
    network_pass2
fi
if [ -n "$network_pass2_done" ]; then
    network_pass3
fi

# stdin must be redirected because it might be for a serial console
kbddev=/dev/ttyv0
viddev=/dev/ttyv0

echo -n "Konfigurowanie konsoli:"

# keymap
if [ "X${keymap}" != X"NO" ]; then
	echo -n '  mapa klawiatury';	kbdcontrol <${kbddev} -l /usr/share/syscons/${keymap}
fi

# keyrate
if [ "X${keyrate}" != X"NO" ]; then
	echo -n ' keyrate';	kbdcontrol <${kbddev} -r ${keyrate}
fi

# keybell
if [ "X${keybell}" != X"NO" ]; then
	echo -n ' keybell';	kbdcontrol <${kbddev} -b ${keybell}
fi

# change function keys
if [ "X${keychange}" != X"NO" ]; then
	echo -n " keychange"
	set - ${keychange}
	while [ $# -gt 0 ]
	do
		kbdcontrol <${kbddev} -f "$1" "$2"
		shift; shift
	done
fi

# cursor type
if [ "X${cursor}" != X"NO" ]; then
	echo -n '  kursor';	vidcontrol <${viddev} -c ${cursor}
fi

# font 8x16
if [ "X${font8x16}" != X"NO" ]; then
	echo -n ' font8x16';	vidcontrol <${viddev} -f 8x16 /usr/share/syscons/${font8x16}
fi

# font 8x14
if [ "X${font8x14}" != X"NO" ]; then
	echo -n ' font8x14';	vidcontrol <${viddev} -f 8x14 /usr/share/syscons/${font8x14}
fi

# font 8x8
if [ "X${font8x8}" != X"NO" ]; then
	echo -n ' font8x8';	vidcontrol <${viddev} -f 8x8 /usr/share/syscons/${font8x8}
fi

# blank time
if [ "X${blanktime}" != X"NO" ]; then
	echo -n ' wygaszacz';	vidcontrol <${viddev} -t ${blanktime}
fi

# mouse daemon
if [ "X${moused_enable}" = X"YES" ] ; then
	echo -n ' moused'
	moused ${moused_flags} -p ${moused_port} -t ${moused_type}
	vidcontrol <${viddev} -m on
fi

echo ''
echo ''
echo '+----------- PicoBSD 0.4 (DIALUP) -------------+'
echo '|                                              |'
echo '| Zaloguj sie jako "root" (brak hasla).        |'
echo '|                                              |'
echo '| PicoBSD podlega licencji BSD (z wyjatkiem    |'
echo '| SSH). Po wiecej szczegolow zajrzyj na        |'
echo '| http://www.freebsd.org/~picobsd, lub         |'
echo '| skontaktuj sie z autorem.                    |'
echo '|                                              |'
echo '|                     abial@nask.pl            |'
echo '|                                              |'
echo '+----------------------------------------------+'
exit 0
