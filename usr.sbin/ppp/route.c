/*
 *	      PPP Routing related Module
 *
 *	    Written by Toshiharu OHNO (tony-o@iij.ad.jp)
 *
 *   Copyright (C) 1994, Internet Initiative Japan, Inc. All rights reserverd.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the Internet Initiative Japan, Inc.  The name of the
 * IIJ may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * $Id:$
 * 
 */
#include <sys/types.h>
#include <machine/endian.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#if (BSD >= 199306)
#include <sys/sysctl.h>
#else
#include <sys/kinfo.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int IfIndex;

struct rtmsg {
  struct rt_msghdr m_rtm;
  char m_space[64];
};

static int seqno;

void
OsSetRoute(cmd, dst, gateway, mask)
int cmd;
struct in_addr dst;
struct in_addr gateway;
struct in_addr mask;
{
  struct rtmsg rtmes;
  int s, nb, wb;
  char *cp;
  u_long *lp;
  struct sockaddr_in rtdata;

  s = socket(PF_ROUTE, SOCK_RAW, 0);
  if (s < 0)
    logprintf("socket\n");

  bzero(&rtmes, sizeof(rtmes));
  rtmes.m_rtm.rtm_version = RTM_VERSION;
  rtmes.m_rtm.rtm_type = cmd;
  rtmes.m_rtm.rtm_addrs = RTA_DST | RTA_NETMASK;
  if (cmd == RTM_ADD) rtmes.m_rtm.rtm_addrs |= RTA_GATEWAY;
  rtmes.m_rtm.rtm_seq = ++seqno;
  rtmes.m_rtm.rtm_pid = getpid();
  rtmes.m_rtm.rtm_flags = RTF_UP | RTF_GATEWAY;

  bzero(&rtdata, sizeof(rtdata));
  rtdata.sin_len = 16;
  rtdata.sin_family = AF_INET;
  rtdata.sin_port = 0;
  rtdata.sin_addr = dst;

  cp = rtmes.m_space;
  bcopy(&rtdata, cp, 16);
  cp += 16;
  if (gateway.s_addr) {
    rtdata.sin_addr = gateway;
    bcopy(&rtdata, cp, 16);
    cp += 16;
  }

  if (dst.s_addr == INADDR_ANY)
    mask.s_addr = INADDR_ANY;

  lp = (u_long *)cp;

  if (mask.s_addr) {
    *lp++ = 8;
    cp += sizeof(int);
    *lp = mask.s_addr;
  } else
    *lp = 0;
  cp += sizeof(u_long);

  nb = cp - (char *)&rtmes;
  rtmes.m_rtm.rtm_msglen = nb;
  wb = write(s, &rtmes, nb);
  if (wb < 0) {
    perror("write");
  }
#ifdef DEBUG
  logprintf("wrote %d: dst = %x, gateway = %x\n", nb, dst.s_addr, gateway.s_addr);
#endif
  close(s);
}

static void
p_sockaddr(sa, width)
struct sockaddr *sa;
int width;
{
  register char *cp;
  register struct sockaddr_in *sin = (struct sockaddr_in *)sa;

  cp = (sin->sin_addr.s_addr == 0) ? "default" :
	   inet_ntoa(sin->sin_addr);
  printf("%-*.*s ", width, width, cp);
}

struct bits {
  short b_mask;
  char  b_val;
} bits[] = {
  { RTF_UP,	  'U' },
  { RTF_GATEWAY,  'G' },
  { RTF_HOST,	  'H' },
  { RTF_DYNAMIC,  'D' },
  { RTF_MODIFIED, 'M' },
  { RTF_CLONING,  'C' },
  { RTF_XRESOLVE, 'X' },
  { RTF_LLINFO,   'L' },
  { RTF_REJECT,   'R' },
  { 0 }
};

static void
p_flags(f, format)
register int f;
char *format;
{
  char name[33], *flags;
  register struct bits *p = bits;

  for (flags = name; p->b_mask; p++)
    if (p->b_mask & f)
      *flags++ = p->b_val;
  *flags = '\0';
  printf(format, name);
}

int
ShowRoute()
{
  struct rt_msghdr *rtm;
  struct sockaddr *sa;
  char *sp, *ep, *cp;
  u_char *wp;
  int *lp;
  int needed, nb;
  u_long mask;
#if (BSD >= 199306)
  int mib[6];
#endif

#if (BSD >= 199306)
  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = 0;
  mib[4] = NET_RT_DUMP;
  mib[5] = 0;
  if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
    perror("sysctl-estimate");
    return(1);
  }
#else
  needed = getkerninfo(KINFO_RT_DUMP, 0, 0, 0);
#endif
  if (needed < 0)
    return(1);
  sp = malloc(needed);
  if (sp == NULL)
    return(1);
#if (BSD >= 199306)
  if (sysctl(mib, 6, sp, &needed, NULL, 0) < 0) {
    perror("sysctl-getroute");
    return(1);
  }
#else
  if (getkerninfo(KINFO_RT_DUMP, sp, &needed, 0) < 0)
    return(1);
#endif
  ep = sp + needed;

  for (cp = sp; cp < ep; cp += rtm->rtm_msglen) {
    rtm = (struct rt_msghdr *)cp;
    sa = (struct sockaddr *)(rtm + 1);
    mask = 0xffffffff;
    if (rtm->rtm_addrs == RTA_DST)
      p_sockaddr(sa, 36);
    else {
      wp = (u_char *)cp + rtm->rtm_msglen;
      p_sockaddr(sa, 16);
      if (sa->sa_len == 0)
	sa->sa_len = sizeof(long);
      sa = (struct sockaddr *)(sa->sa_len + (char *)sa);
      p_sockaddr(sa, 18);
      lp = (int *)(sa->sa_len + (char *)sa);
      if ((char *)lp < (char *)wp && *lp) {
#ifdef DEBUG
	logprintf(" flag = %x, rest = %d", rtm->rtm_flags, *lp);
#endif
	wp = (u_char *)(lp + 1);
	mask = 0;
	for (nb = *lp; nb > 4; nb--) {
	  mask <<= 8;
	  mask |= *wp++;
	}
	for (nb = 8 - *lp; nb > 0; nb--)
	  mask <<= 8;
      }
    }
    printf("%08x  ", mask);
    p_flags(rtm->rtm_flags & (RTF_UP|RTF_GATEWAY|RTF_HOST), "%-6.6s ");
    printf("(%d)\n", rtm->rtm_index);
  }

  return(1);
}

/*
 *  Delete routes associated with our interface
 */
void
DeleteIfRoutes(all)
int all;
{
  struct rt_msghdr *rtm;
  struct sockaddr *sa;
  struct in_addr dstnet, gateway;
  int needed;
  char *sp, *cp, *ep;
  u_long mask;
  int *lp, nb;
  u_char *wp;
#if (BSD >= 199306)
  int mib[6];
#endif

#ifdef DEBUG
  logprintf("DeleteIfRoutes (%d)\n", IfIndex);
#endif
#if (BSD >= 199306)
  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = 0;
  mib[4] = NET_RT_DUMP;
  mib[5] = 0;
  if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
    perror("sysctl-estimate");
    return;
  }
#else
  needed = getkerninfo(KINFO_RT_DUMP, 0, 0, 0);
#endif

  if (needed < 0)
    return;

  sp = malloc(needed);
  if (sp == NULL)
    return;

#if (BSD >= 199306)
  if (sysctl(mib, 6, sp, &needed, NULL, 0) < 0) {
    free(sp);
    perror("sysctl-getroute");
    return;
  }
#else
  if (getkerninfo(KINFO_RT_DUMP, sp, &needed, 0) < 0) {
    free(sp);
    return;
  }
#endif
  ep = sp + needed;

  for (cp = sp; cp < ep; cp += rtm->rtm_msglen) {
    rtm = (struct rt_msghdr *)cp;
    sa = (struct sockaddr *)(rtm + 1);
#ifdef DEBUG
    logprintf("addrs: %x, index: %d, flags: %x, dstnet: %x\n",
	rtm->rtm_addrs, rtm->rtm_index, rtm->rtm_flags,
	((struct sockaddr_in *)sa)->sin_addr);
#endif
    if (rtm->rtm_addrs != RTA_DST &&
       (rtm->rtm_index == IfIndex) &&
       (all || (rtm->rtm_flags & RTF_GATEWAY))) {
      dstnet = ((struct sockaddr_in *)sa)->sin_addr;
      wp = (u_char *)cp + rtm->rtm_msglen;
      if (sa->sa_len == 0)
	sa->sa_len = sizeof(long);
      sa = (struct sockaddr *)(sa->sa_len + (char *)sa);
      gateway = ((struct sockaddr_in *)sa)->sin_addr;
      lp = (int *)(sa->sa_len + (char *)sa);
      mask = 0;
      if ((char *)lp < (char *)wp && *lp) {
#ifdef DEBUG
	printf(" flag = %x, rest = %d", rtm->rtm_flags, *lp);
#endif
	wp = (u_char *)(lp + 1);
	for (nb = *lp; nb > 4; nb--) {
	  mask <<= 8;
	  mask |= *wp++;
	}
	for (nb = 8 - *lp; nb > 0; nb--)
	  mask <<= 8;
      }
#ifdef DEBUG
      logprintf("## %s ", inet_ntoa(dstnet));
      logprintf(" %s  %d\n", inet_ntoa(gateway), rtm->rtm_index);
#endif
      if (dstnet.s_addr == INADDR_ANY) {
        gateway.s_addr = INADDR_ANY;
        mask = INADDR_ANY;
      }
      OsSetRoute(RTM_DELETE, dstnet, gateway, htonl(mask));
    }
#ifdef DEBUG
    else if (rtm->rtm_index == IfIndex) {
      logprintf("??? addrs: %x, flags = %x\n", rtm->rtm_addrs, rtm->rtm_flags);
    }
#endif
  }
  free(sp);
}

int
GetIfIndex(name)
char *name;
{
  struct ifreq *ifrp;
  int s, len, elen, index;
  struct ifconf ifconfs;
  struct ifreq reqbuf[32];

  s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    perror("socket");
    return(-1);
  }

  ifconfs.ifc_len = sizeof(reqbuf);
  ifconfs.ifc_buf = (caddr_t)reqbuf;
  if (ioctl(s, SIOCGIFCONF, &ifconfs) < 0) {
    perror("IFCONF");
    return(-1);
  }

  ifrp = ifconfs.ifc_req;

  index = 1;
  for (len = ifconfs.ifc_len; len > 0; len -= sizeof(struct ifreq)) {
    elen = ifrp->ifr_addr.sa_len - sizeof(struct sockaddr);
    if (ifrp->ifr_addr.sa_family == AF_LINK) {
#ifdef DEBUG
      logprintf("%d: %-*.*s, %d, %d\n", index, IFNAMSIZ, IFNAMSIZ, ifrp->ifr_name,
	   ifrp->ifr_addr.sa_family, elen);
#endif
      if (strcmp(ifrp->ifr_name, name) == 0) {
        IfIndex = index;
        return(index);
      }
      index++;
    }

    len -= elen;
    ifrp = (struct ifreq *)((char *)ifrp + elen);
    ifrp++;
  }

  close(s);
  return(-1);
}
