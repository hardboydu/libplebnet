#!/bin/sh
# $Id: rc.conf.pl,v 1.1.1.1 1998/07/14 07:30:46 abial Exp $
swapfile="NO"		# Set to name of swapfile if aux swapfile desired.
###  Network configuration sub-section  ######################
### Basic network options: ###
hostname="pico.mydomain.org.pl"	# Set this!
firewall="NO"			# firewall type (see /etc/rc.firewall) or NO
tcp_extensions="NO"		# Allow RFC1323 & RFC1644 extensions (or NO).
network_interfaces="lo0"	# List of network interfaces (lo0 is loopback).
ifconfig_lo0="inet 127.0.0.1"	# default loopback device configuration.
#ifconfig_lo0_alias0="inet 127.0.0.254 netmask 0xffffffff" # Sample alias entry.
### Network daemons options: ###
inetd_enable="YES"		# Run the network daemon dispatcher (or NO)
inetd_flags=""			# Optional flags to inetd
snmpd_enable="YES"		# Run the SNMP daemon (or NO)
snmpd_flags="-C -c /etc/snmpd.conf"	# Optional flags to snmpd
### Network routing options: ###
defaultrouter="NO"		# Set to default gateway (or NO).
static_routes=""		# Set to static route list (or leave empty).
gateway_enable="NO"		# Set to YES if this host will be a gateway.
arpproxy_all=""			# replaces obsolete kernel option ARP_PROXYALL.
### Allow local configuration override at the very end here ##
if [ -f /etc/rc.conf.local ]; then
	. /etc/rc.conf.local
fi
