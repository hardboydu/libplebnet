#!/bin/sh
#-
# Copyright (c) 2010 iXsystems, Inc.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $FreeBSD$

# Functions which perform our networking setup

# Function which creates a kde4 .desktop file for the PC-BSD net tray
create_desktop_nettray()
{
  NIC="${1}"
  echo "#!/usr/bin/env xdg-open
[Desktop Entry]
Exec=/usr/local/kde4/bin/pc-nettray ${NIC}
Icon=network
StartupNotify=false
Type=Application" > ${FSMNT}/usr/share/skel/.kde4/Autostart/tray-${NIC}.desktop
  chmod 744 ${FSMNT}/usr/share/skel/.kde4/Autostart/tray-${NIC}.desktop

};

# Function which checks is a nic is wifi or not
check_is_wifi()
{
  NIC="$1"
  ifconfig ${NIC} | grep -q "802.11" 2>/dev/null
  if [ $? -eq 0 ]
  then
    return 0
  else 
    return 1
  fi
};

# Function to get the first available wired nic, used for setup
get_first_wired_nic()
{
  rm ${TMPDIR}/.niclist >/dev/null 2>/dev/null
  # start by getting a list of nics on this system
  ${QUERYDIR}/detect-nics.sh > ${TMPDIR}/.niclist
  if [ -e "${TMPDIR}/.niclist" ]
  then
    while read line
    do
      NIC="`echo $line | cut -d ':' -f 1`"
      check_is_wifi ${NIC}
      if [ $? -ne 0 ]
      then
        export VAL="${NIC}"
        return
      fi
    done < ${TMPDIR}/.niclist
  fi

  export VAL=""
  return
};


# Function which simply enables plain dhcp on all detected nics
enable_dhcp_all()
{
  rm ${TMPDIR}/.niclist >/dev/null 2>/dev/null
  # start by getting a list of nics on this system
  ${QUERYDIR}/detect-nics.sh > ${TMPDIR}/.niclist
  if [ -e "${TMPDIR}/.niclist" ]
  then
    echo "# Auto-Enabled NICs from pc-sysinstall" >>${FSMNT}/etc/rc.conf
    WLANCOUNT="0"
    while read line
    do
      NIC="`echo $line | cut -d ':' -f 1`"
      DESC="`echo $line | cut -d ':' -f 2`"
      echo_log "Setting $NIC to DHCP on the system."
      check_is_wifi ${NIC}
      if [ $? -eq 0 ]
      then
        # We have a wifi device, setup a wlan* entry for it
        WLAN="wlan${WLANCOUNT}"
        echo "wlans_${NIC}=\"${WLAN}\"" >>${FSMNT}/etc/rc.conf
        echo "ifconfig_${WLAN}=\"DHCP\"" >>${FSMNT}/etc/rc.conf
        CNIC="${WLAN}"
        WLANCOUNT=$((WLANCOUNT+1))
      else
        echo "ifconfig_${NIC}=\"DHCP\"" >>${FSMNT}/etc/rc.conf
        CNIC="${NIC}"
      fi
 
    done < ${TMPDIR}/.niclist 
  fi
};


# Function which detects available nics, and enables dhcp on them
save_auto_dhcp()
{
  enable_dhcp_all
};


# Function which saves a manual nic setup to the installed system
save_manual_nic()
{
  # Get the target nic
  NIC="$1"

  get_value_from_cfg netSaveIP
  NETIP="${VAL}"
 
  if [ "$NETIP" = "DHCP" ]
  then
    echo_log "Setting $NIC to DHCP on the system."
    echo "ifconfig_${NIC}=\"DHCP\"" >>${FSMNT}/etc/rc.conf
    return 0
  fi

  # If we get here, we have a manual setup, lets do so now

  # Set the manual IP
  IFARGS="inet ${NETIP}"

  # Check if we have a netmask to set
  get_value_from_cfg netSaveMask
  NETMASK="${VAL}"
  if [ -n "${NETMASK}" ]
  then
    IFARGS="${IFARGS} netmask ${NETMASK}"
  fi


  echo "# Auto-Enabled NICs from pc-sysinstall" >>${FSMNT}/etc/rc.conf
  echo "ifconfig_${NIC}=\"${IFARGS}\"" >>${FSMNT}/etc/rc.conf

  # Check if we have a default router to set
  get_value_from_cfg netSaveDefaultRouter
  NETROUTE="${VAL}"
  if [ -n "${NETROUTE}" ]
  then
    echo "defaultrouter=\"${NETROUTE}\"" >>${FSMNT}/etc/rc.conf
  fi

  # Check if we have a nameserver to enable
  get_value_from_cfg netSaveNameServer
  NAMESERVER="${VAL}"
  if [ -n "${NAMESERVER}" ]
  then
    echo "nameserver ${NAMESERVER}" >${FSMNT}/etc/resolv.conf
  fi
 
};

# Function which determines if a nic is active / up
is_nic_active()
{
  ifconfig ${1} | grep -q "status: active" 2>/dev/null
  if [ $? -eq 0 ] ; then
    return 0
  else
    return 1
  fi
};


# Function which detects available nics, and runs DHCP on them until
# a success is found
enable_auto_dhcp()
{
  # start by getting a list of nics on this system
  ${QUERYDIR}/detect-nics.sh > ${TMPDIR}/.niclist
  while read line
  do
    NIC="`echo $line | cut -d ':' -f 1`"
    DESC="`echo $line | cut -d ':' -f 2`"

    is_nic_active "${NIC}"
    if [ $? -eq 0 ] ; then
      echo_log "Trying DHCP on $NIC $DESC"
      dhclient ${NIC} >/dev/null 2>/dev/null
      if [ $? -eq 0 ] ; then
        # Got a valid DHCP IP, we can return now
	    export WRKNIC="$NIC"
   	    return 0
	  fi
    fi
  done < ${TMPDIR}/.niclist 

};

# Get the mac address of a target NIC
get_nic_mac()
{
  FOUNDMAC="`ifconfig ${1} | grep 'ether' | tr -d '\t' | cut -d ' ' -f 2`"
  export FOUNDMAC
}

# Function which performs the manual setup of a target nic in the cfg
enable_manual_nic()
{
  # Get the target nic
  NIC="$1"

  # Check that this NIC exists
  rc_halt "ifconfig ${NIC}"

  get_value_from_cfg netIP
  NETIP="${VAL}"
  
  if [ "$NETIP" = "DHCP" ]
  then
    echo_log "Enabling DHCP on $NIC"
    rc_halt "dhclient ${NIC}"
    return 0
  fi

  # If we get here, we have a manual setup, lets do so now

  # Set the manual IP
  rc_halt "ifconfig ${NIC} ${NETIP}"

  # Check if we have a netmask to set
  get_value_from_cfg netMask
  NETMASK="${VAL}"
  if [ -n "${NETMASK}" ]
  then
    rc_halt "ifconfig ${NIC} netmask ${NETMASK}"
  fi

  # Check if we have a default router to set
  get_value_from_cfg netDefaultRouter
  NETROUTE="${VAL}"
  if [ -n "${NETROUTE}" ]
  then
    rc_halt "route add default ${NETROUTE}"
  fi

  # Check if we have a nameserver to enable
  get_value_from_cfg netNameServer
  NAMESERVER="${VAL}"
  if [ -n "${NAMESERVER}" ]
  then
    echo "nameserver ${NAMESERVER}" >/etc/resolv.conf
  fi
  
  
};


# Function which parses the cfg and enables networking per specified
start_networking()
{
  # Check if we have any networking requested
  get_value_from_cfg netDev
  if [ -z "${VAL}" ]
  then
    return 0
  fi

  NETDEV="${VAL}"
  if [ "$NETDEV" = "AUTO-DHCP" ]
  then
    enable_auto_dhcp
  else
    enable_manual_nic ${NETDEV}
  fi

};


# Function which checks the cfg and enables the specified networking on
# the installed system
save_networking_install()
{

  # Check if we have any networking requested to save
  get_value_from_cfg netSaveDev
  if [ -z "${VAL}" ]
  then
    return 0
  fi

  NETDEV="${VAL}"
  if [ "$NETDEV" = "AUTO-DHCP" ]
  then
    save_auto_dhcp
  else
    save_manual_nic ${NETDEV}
  fi

};
