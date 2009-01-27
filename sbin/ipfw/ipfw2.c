/*
 * Copyright (c) 2002-2003 Luigi Rizzo
 * Copyright (c) 1996 Alex Nash, Paul Traina, Poul-Henning Kamp
 * Copyright (c) 1994 Ugen J.S.Antsilevich
 *
 * Idea and grammar partially left from:
 * Copyright (c) 1993 Daniel Boulet
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 *
 * NEW command line interface for IP firewall facility
 *
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>

#include "ipfw2.h"

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <timeconv.h>	/* _long_to_time */
#include <unistd.h>
#include <fcntl.h>

#define IPFW_INTERNAL	/* Access to protected structures in ip_fw.h. */

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/pfvar.h>
#include <net/route.h> /* def. of struct route */
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip_fw.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <alias.h>

struct cmdline_opts co;	/* global options */

int resvd_set_number = RESVD_SET;

#define GET_UINT_ARG(arg, min, max, tok, s_x) do {			\
	if (!ac)							\
		errx(EX_USAGE, "%s: missing argument", match_value(s_x, tok)); \
	if (_substrcmp(*av, "tablearg") == 0) {				\
		arg = IP_FW_TABLEARG;					\
		break;							\
	}								\
									\
	{								\
	long val;							\
	char *end;							\
									\
	val = strtol(*av, &end, 10);					\
									\
	if (!isdigit(**av) || *end != '\0' || (val == 0 && errno == EINVAL)) \
		errx(EX_DATAERR, "%s: invalid argument: %s",		\
		    match_value(s_x, tok), *av);			\
									\
	if (errno == ERANGE || val < min || val > max)			\
		errx(EX_DATAERR, "%s: argument is out of range (%u..%u): %s", \
		    match_value(s_x, tok), min, max, *av);		\
									\
	if (val == IP_FW_TABLEARG)					\
		errx(EX_DATAERR, "%s: illegal argument value: %s",	\
		    match_value(s_x, tok), *av);			\
	arg = val;							\
	}								\
} while (0)

static void
PRINT_UINT_ARG(const char *str, uint32_t arg)
{
	if (str != NULL)
		printf("%s",str);
	if (arg == IP_FW_TABLEARG)
		printf("tablearg");
	else
		printf("%u", arg);
}

static struct _s_x f_tcpflags[] = {
	{ "syn", TH_SYN },
	{ "fin", TH_FIN },
	{ "ack", TH_ACK },
	{ "psh", TH_PUSH },
	{ "rst", TH_RST },
	{ "urg", TH_URG },
	{ "tcp flag", 0 },
	{ NULL,	0 }
};

static struct _s_x f_tcpopts[] = {
	{ "mss",	IP_FW_TCPOPT_MSS },
	{ "maxseg",	IP_FW_TCPOPT_MSS },
	{ "window",	IP_FW_TCPOPT_WINDOW },
	{ "sack",	IP_FW_TCPOPT_SACK },
	{ "ts",		IP_FW_TCPOPT_TS },
	{ "timestamp",	IP_FW_TCPOPT_TS },
	{ "cc",		IP_FW_TCPOPT_CC },
	{ "tcp option",	0 },
	{ NULL,	0 }
};

/*
 * IP options span the range 0 to 255 so we need to remap them
 * (though in fact only the low 5 bits are significant).
 */
static struct _s_x f_ipopts[] = {
	{ "ssrr",	IP_FW_IPOPT_SSRR},
	{ "lsrr",	IP_FW_IPOPT_LSRR},
	{ "rr",		IP_FW_IPOPT_RR},
	{ "ts",		IP_FW_IPOPT_TS},
	{ "ip option",	0 },
	{ NULL,	0 }
};

static struct _s_x f_iptos[] = {
	{ "lowdelay",	IPTOS_LOWDELAY},
	{ "throughput",	IPTOS_THROUGHPUT},
	{ "reliability", IPTOS_RELIABILITY},
	{ "mincost",	IPTOS_MINCOST},
	{ "congestion",	IPTOS_ECN_CE},
	{ "ecntransport", IPTOS_ECN_ECT0},
	{ "ip tos option", 0},
	{ NULL,	0 }
};

static struct _s_x limit_masks[] = {
	{"all",		DYN_SRC_ADDR|DYN_SRC_PORT|DYN_DST_ADDR|DYN_DST_PORT},
	{"src-addr",	DYN_SRC_ADDR},
	{"src-port",	DYN_SRC_PORT},
	{"dst-addr",	DYN_DST_ADDR},
	{"dst-port",	DYN_DST_PORT},
	{NULL,		0}
};

/*
 * we use IPPROTO_ETHERTYPE as a fake protocol id to call the print routines
 * This is only used in this code.
 */
#define IPPROTO_ETHERTYPE	0x1000
static struct _s_x ether_types[] = {
    /*
     * Note, we cannot use "-:&/" in the names because they are field
     * separators in the type specifications. Also, we use s = NULL as
     * end-delimiter, because a type of 0 can be legal.
     */
	{ "ip",		0x0800 },
	{ "ipv4",	0x0800 },
	{ "ipv6",	0x86dd },
	{ "arp",	0x0806 },
	{ "rarp",	0x8035 },
	{ "vlan",	0x8100 },
	{ "loop",	0x9000 },
	{ "trail",	0x1000 },
	{ "at",		0x809b },
	{ "atalk",	0x809b },
	{ "aarp",	0x80f3 },
	{ "pppoe_disc",	0x8863 },
	{ "pppoe_sess",	0x8864 },
	{ "ipx_8022",	0x00E0 },
	{ "ipx_8023",	0x0000 },
	{ "ipx_ii",	0x8137 },
	{ "ipx_snap",	0x8137 },
	{ "ipx",	0x8137 },
	{ "ns",		0x0600 },
	{ NULL,		0 }
};


static struct _s_x nat_params[] = {
	{ "ip",	                TOK_IP },
	{ "if",	                TOK_IF },
 	{ "log",                TOK_ALOG },
 	{ "deny_in",	        TOK_DENY_INC },
 	{ "same_ports",	        TOK_SAME_PORTS },
 	{ "unreg_only",	        TOK_UNREG_ONLY },
 	{ "reset",	        TOK_RESET_ADDR },
 	{ "reverse",	        TOK_ALIAS_REV },	
 	{ "proxy_only",	        TOK_PROXY_ONLY },
	{ "redirect_addr",	TOK_REDIR_ADDR },
	{ "redirect_port",	TOK_REDIR_PORT },
	{ "redirect_proto",	TOK_REDIR_PROTO },
 	{ NULL, 0 }	/* terminator */
};

static struct _s_x rule_actions[] = {
	{ "accept",		TOK_ACCEPT },
	{ "pass",		TOK_ACCEPT },
	{ "allow",		TOK_ACCEPT },
	{ "permit",		TOK_ACCEPT },
	{ "count",		TOK_COUNT },
	{ "pipe",		TOK_PIPE },
	{ "queue",		TOK_QUEUE },
	{ "divert",		TOK_DIVERT },
	{ "tee",		TOK_TEE },
	{ "netgraph",		TOK_NETGRAPH },
	{ "ngtee",		TOK_NGTEE },
	{ "fwd",		TOK_FORWARD },
	{ "forward",		TOK_FORWARD },
	{ "skipto",		TOK_SKIPTO },
	{ "deny",		TOK_DENY },
	{ "drop",		TOK_DENY },
	{ "reject",		TOK_REJECT },
	{ "reset6",		TOK_RESET6 },
	{ "reset",		TOK_RESET },
	{ "unreach6",		TOK_UNREACH6 },
	{ "unreach",		TOK_UNREACH },
	{ "check-state",	TOK_CHECKSTATE },
	{ "//",			TOK_COMMENT },
	{ "nat",                TOK_NAT },
	{ "setfib",		TOK_SETFIB },
	{ NULL, 0 }	/* terminator */
};

static struct _s_x rule_action_params[] = {
	{ "altq",		TOK_ALTQ },
	{ "log",		TOK_LOG },
	{ "tag",		TOK_TAG },
	{ "untag",		TOK_UNTAG },
	{ NULL, 0 }	/* terminator */
};

static struct _s_x rule_options[] = {
	{ "tagged",		TOK_TAGGED },
	{ "uid",		TOK_UID },
	{ "gid",		TOK_GID },
	{ "jail",		TOK_JAIL },
	{ "in",			TOK_IN },
	{ "limit",		TOK_LIMIT },
	{ "keep-state",		TOK_KEEPSTATE },
	{ "bridged",		TOK_LAYER2 },
	{ "layer2",		TOK_LAYER2 },
	{ "out",		TOK_OUT },
	{ "diverted",		TOK_DIVERTED },
	{ "diverted-loopback",	TOK_DIVERTEDLOOPBACK },
	{ "diverted-output",	TOK_DIVERTEDOUTPUT },
	{ "xmit",		TOK_XMIT },
	{ "recv",		TOK_RECV },
	{ "via",		TOK_VIA },
	{ "fragment",		TOK_FRAG },
	{ "frag",		TOK_FRAG },
	{ "fib",		TOK_FIB },
	{ "ipoptions",		TOK_IPOPTS },
	{ "ipopts",		TOK_IPOPTS },
	{ "iplen",		TOK_IPLEN },
	{ "ipid",		TOK_IPID },
	{ "ipprecedence",	TOK_IPPRECEDENCE },
	{ "iptos",		TOK_IPTOS },
	{ "ipttl",		TOK_IPTTL },
	{ "ipversion",		TOK_IPVER },
	{ "ipver",		TOK_IPVER },
	{ "estab",		TOK_ESTAB },
	{ "established",	TOK_ESTAB },
	{ "setup",		TOK_SETUP },
	{ "tcpdatalen",		TOK_TCPDATALEN },
	{ "tcpflags",		TOK_TCPFLAGS },
	{ "tcpflgs",		TOK_TCPFLAGS },
	{ "tcpoptions",		TOK_TCPOPTS },
	{ "tcpopts",		TOK_TCPOPTS },
	{ "tcpseq",		TOK_TCPSEQ },
	{ "tcpack",		TOK_TCPACK },
	{ "tcpwin",		TOK_TCPWIN },
	{ "icmptype",		TOK_ICMPTYPES },
	{ "icmptypes",		TOK_ICMPTYPES },
	{ "dst-ip",		TOK_DSTIP },
	{ "src-ip",		TOK_SRCIP },
	{ "dst-port",		TOK_DSTPORT },
	{ "src-port",		TOK_SRCPORT },
	{ "proto",		TOK_PROTO },
	{ "MAC",		TOK_MAC },
	{ "mac",		TOK_MAC },
	{ "mac-type",		TOK_MACTYPE },
	{ "verrevpath",		TOK_VERREVPATH },
	{ "versrcreach",	TOK_VERSRCREACH },
	{ "antispoof",		TOK_ANTISPOOF },
	{ "ipsec",		TOK_IPSEC },
	{ "icmp6type",		TOK_ICMP6TYPES },
	{ "icmp6types",		TOK_ICMP6TYPES },
	{ "ext6hdr",		TOK_EXT6HDR},
	{ "flow-id",		TOK_FLOWID},
	{ "ipv6",		TOK_IPV6},
	{ "ip6",		TOK_IPV6},
	{ "ipv4",		TOK_IPV4},
	{ "ip4",		TOK_IPV4},
	{ "dst-ipv6",		TOK_DSTIP6},
	{ "dst-ip6",		TOK_DSTIP6},
	{ "src-ipv6",		TOK_SRCIP6},
	{ "src-ip6",		TOK_SRCIP6},
	{ "//",			TOK_COMMENT },

	{ "not",		TOK_NOT },		/* pseudo option */
	{ "!", /* escape ? */	TOK_NOT },		/* pseudo option */
	{ "or",			TOK_OR },		/* pseudo option */
	{ "|", /* escape */	TOK_OR },		/* pseudo option */
	{ "{",			TOK_STARTBRACE },	/* pseudo option */
	{ "(",			TOK_STARTBRACE },	/* pseudo option */
	{ "}",			TOK_ENDBRACE },		/* pseudo option */
	{ ")",			TOK_ENDBRACE },		/* pseudo option */
	{ NULL, 0 }	/* terminator */
};

static __inline uint64_t
align_uint64(uint64_t *pll) {
	uint64_t ret;

	bcopy (pll, &ret, sizeof(ret));
	return ret;
}

void *
safe_calloc(size_t number, size_t size)
{
	void *ret = calloc(number, size);

	if (ret == NULL)
		err(EX_OSERR, "calloc");
	return ret;
}

void *
safe_realloc(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);

	if (ret == NULL)
		err(EX_OSERR, "realloc");
	return ret;
}

/*
 * conditionally runs the command.
 */
int
do_cmd(int optname, void *optval, uintptr_t optlen)
{
	static int s = -1;	/* the socket */
	int i;

	if (co.test_only)
		return 0;

	if (s == -1)
		s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (s < 0)
		err(EX_UNAVAILABLE, "socket");

	if (optname == IP_FW_GET || optname == IP_DUMMYNET_GET ||
	    optname == IP_FW_ADD || optname == IP_FW_TABLE_LIST ||
	    optname == IP_FW_TABLE_GETSIZE || 
	    optname == IP_FW_NAT_GET_CONFIG || 
	    optname == IP_FW_NAT_GET_LOG)
		i = getsockopt(s, IPPROTO_IP, optname, optval,
			(socklen_t *)optlen);
	else
		i = setsockopt(s, IPPROTO_IP, optname, optval, optlen);
	return i;
}

/**
 * match_token takes a table and a string, returns the value associated
 * with the string (-1 in case of failure).
 */
int
match_token(struct _s_x *table, char *string)
{
	struct _s_x *pt;
	uint i = strlen(string);

	for (pt = table ; i && pt->s != NULL ; pt++)
		if (strlen(pt->s) == i && !bcmp(string, pt->s, i))
			return pt->x;
	return -1;
}

/**
 * match_value takes a table and a value, returns the string associated
 * with the value (NULL in case of failure).
 */
static char const *
match_value(struct _s_x *p, int value)
{
	for (; p->s != NULL; p++)
		if (p->x == value)
			return p->s;
	return NULL;
}

/*
 * _substrcmp takes two strings and returns 1 if they do not match,
 * and 0 if they match exactly or the first string is a sub-string
 * of the second.  A warning is printed to stderr in the case that the
 * first string is a sub-string of the second.
 *
 * This function will be removed in the future through the usual
 * deprecation process.
 */
int
_substrcmp(const char *str1, const char* str2)
{
	
	if (strncmp(str1, str2, strlen(str1)) != 0)
		return 1;

	if (strlen(str1) != strlen(str2))
		warnx("DEPRECATED: '%s' matched '%s' as a sub-string",
		    str1, str2);
	return 0;
}

/*
 * _substrcmp2 takes three strings and returns 1 if the first two do not match,
 * and 0 if they match exactly or the second string is a sub-string
 * of the first.  A warning is printed to stderr in the case that the
 * first string does not match the third.
 *
 * This function exists to warn about the bizzare construction
 * strncmp(str, "by", 2) which is used to allow people to use a shotcut
 * for "bytes".  The problem is that in addition to accepting "by",
 * "byt", "byte", and "bytes", it also excepts "by_rabid_dogs" and any
 * other string beginning with "by".
 *
 * This function will be removed in the future through the usual
 * deprecation process.
 */
int
_substrcmp2(const char *str1, const char* str2, const char* str3)
{
	
	if (strncmp(str1, str2, strlen(str2)) != 0)
		return 1;

	if (strcmp(str1, str3) != 0)
		warnx("DEPRECATED: '%s' matched '%s'",
		    str1, str3);
	return 0;
}

/*
 * prints one port, symbolic or numeric
 */
static void
print_port(int proto, uint16_t port)
{

	if (proto == IPPROTO_ETHERTYPE) {
		char const *s;

		if (co.do_resolv && (s = match_value(ether_types, port)) )
			printf("%s", s);
		else
			printf("0x%04x", port);
	} else {
		struct servent *se = NULL;
		if (co.do_resolv) {
			struct protoent *pe = getprotobynumber(proto);

			se = getservbyport(htons(port), pe ? pe->p_name : NULL);
		}
		if (se)
			printf("%s", se->s_name);
		else
			printf("%d", port);
	}
}

static struct _s_x _port_name[] = {
	{"dst-port",	O_IP_DSTPORT},
	{"src-port",	O_IP_SRCPORT},
	{"ipid",	O_IPID},
	{"iplen",	O_IPLEN},
	{"ipttl",	O_IPTTL},
	{"mac-type",	O_MAC_TYPE},
	{"tcpdatalen",	O_TCPDATALEN},
	{"tagged",	O_TAGGED},
	{NULL,		0}
};

/*
 * Print the values in a list 16-bit items of the types above.
 * XXX todo: add support for mask.
 */
static void
print_newports(ipfw_insn_u16 *cmd, int proto, int opcode)
{
	uint16_t *p = cmd->ports;
	int i;
	char const *sep;

	if (opcode != 0) {
		sep = match_value(_port_name, opcode);
		if (sep == NULL)
			sep = "???";
		printf (" %s", sep);
	}
	sep = " ";
	for (i = F_LEN((ipfw_insn *)cmd) - 1; i > 0; i--, p += 2) {
		printf(sep);
		print_port(proto, p[0]);
		if (p[0] != p[1]) {
			printf("-");
			print_port(proto, p[1]);
		}
		sep = ",";
	}
}

/*
 * Like strtol, but also translates service names into port numbers
 * for some protocols.
 * In particular:
 *	proto == -1 disables the protocol check;
 *	proto == IPPROTO_ETHERTYPE looks up an internal table
 *	proto == <some value in /etc/protocols> matches the values there.
 * Returns *end == s in case the parameter is not found.
 */
static int
strtoport(char *s, char **end, int base, int proto)
{
	char *p, *buf;
	char *s1;
	int i;

	*end = s;		/* default - not found */
	if (*s == '\0')
		return 0;	/* not found */

	if (isdigit(*s))
		return strtol(s, end, base);

	/*
	 * find separator. '\\' escapes the next char.
	 */
	for (s1 = s; *s1 && (isalnum(*s1) || *s1 == '\\') ; s1++)
		if (*s1 == '\\' && s1[1] != '\0')
			s1++;

	buf = safe_calloc(s1 - s + 1, 1);

	/*
	 * copy into a buffer skipping backslashes
	 */
	for (p = s, i = 0; p != s1 ; p++)
		if (*p != '\\')
			buf[i++] = *p;
	buf[i++] = '\0';

	if (proto == IPPROTO_ETHERTYPE) {
		i = match_token(ether_types, buf);
		free(buf);
		if (i != -1) {	/* found */
			*end = s1;
			return i;
		}
	} else {
		struct protoent *pe = NULL;
		struct servent *se;

		if (proto != 0)
			pe = getprotobynumber(proto);
		setservent(1);
		se = getservbyname(buf, pe ? pe->p_name : NULL);
		free(buf);
		if (se != NULL) {
			*end = s1;
			return ntohs(se->s_port);
		}
	}
	return 0;	/* not found */
}

/*
 * Map between current altq queue id numbers and names.
 */
static int altq_fetched = 0;
static TAILQ_HEAD(, pf_altq) altq_entries = 
	TAILQ_HEAD_INITIALIZER(altq_entries);

static void
altq_set_enabled(int enabled)
{
	int pffd;

	pffd = open("/dev/pf", O_RDWR);
	if (pffd == -1)
		err(EX_UNAVAILABLE,
		    "altq support opening pf(4) control device");
	if (enabled) {
		if (ioctl(pffd, DIOCSTARTALTQ) != 0 && errno != EEXIST)
			err(EX_UNAVAILABLE, "enabling altq");
	} else {
		if (ioctl(pffd, DIOCSTOPALTQ) != 0 && errno != ENOENT)
			err(EX_UNAVAILABLE, "disabling altq");
	}
	close(pffd);
}

static void
altq_fetch(void)
{
	struct pfioc_altq pfioc;
	struct pf_altq *altq;
	int pffd;
	unsigned int mnr;

	if (altq_fetched)
		return;
	altq_fetched = 1;
	pffd = open("/dev/pf", O_RDONLY);
	if (pffd == -1) {
		warn("altq support opening pf(4) control device");
		return;
	}
	bzero(&pfioc, sizeof(pfioc));
	if (ioctl(pffd, DIOCGETALTQS, &pfioc) != 0) {
		warn("altq support getting queue list");
		close(pffd);
		return;
	}
	mnr = pfioc.nr;
	for (pfioc.nr = 0; pfioc.nr < mnr; pfioc.nr++) {
		if (ioctl(pffd, DIOCGETALTQ, &pfioc) != 0) {
			if (errno == EBUSY)
				break;
			warn("altq support getting queue list");
			close(pffd);
			return;
		}
		if (pfioc.altq.qid == 0)
			continue;
		altq = safe_calloc(1, sizeof(*altq));
		*altq = pfioc.altq;
		TAILQ_INSERT_TAIL(&altq_entries, altq, entries);
	}
	close(pffd);
}

static u_int32_t
altq_name_to_qid(const char *name)
{
	struct pf_altq *altq;

	altq_fetch();
	TAILQ_FOREACH(altq, &altq_entries, entries)
		if (strcmp(name, altq->qname) == 0)
			break;
	if (altq == NULL)
		errx(EX_DATAERR, "altq has no queue named `%s'", name);
	return altq->qid;
}

static const char *
altq_qid_to_name(u_int32_t qid)
{
	struct pf_altq *altq;

	altq_fetch();
	TAILQ_FOREACH(altq, &altq_entries, entries)
		if (qid == altq->qid)
			break;
	if (altq == NULL)
		return NULL;
	return altq->qname;
}

static void
fill_altq_qid(u_int32_t *qid, const char *av)
{
	*qid = altq_name_to_qid(av);
}

/*
 * Fill the body of the command with the list of port ranges.
 */
static int
fill_newports(ipfw_insn_u16 *cmd, char *av, int proto)
{
	uint16_t a, b, *p = cmd->ports;
	int i = 0;
	char *s = av;

	while (*s) {
		a = strtoport(av, &s, 0, proto);
		if (s == av) 			/* empty or invalid argument */
			return (0);

		switch (*s) {
		case '-':			/* a range */
			av = s + 1;
			b = strtoport(av, &s, 0, proto);
			/* Reject expressions like '1-abc' or '1-2-3'. */
			if (s == av || (*s != ',' && *s != '\0'))
				return (0);
			p[0] = a;
			p[1] = b;
			break;
		case ',':			/* comma separated list */
		case '\0':
			p[0] = p[1] = a;
			break;
		default:
			warnx("port list: invalid separator <%c> in <%s>",
				*s, av);
			return (0);
		}

		i++;
		p += 2;
		av = s + 1;
	}
	if (i > 0) {
		if (i + 1 > F_LEN_MASK)
			errx(EX_DATAERR, "too many ports/ranges\n");
		cmd->o.len |= i + 1;	/* leave F_NOT and F_OR untouched */
	}
	return (i);
}

static struct _s_x icmpcodes[] = {
      { "net",			ICMP_UNREACH_NET },
      { "host",			ICMP_UNREACH_HOST },
      { "protocol",		ICMP_UNREACH_PROTOCOL },
      { "port",			ICMP_UNREACH_PORT },
      { "needfrag",		ICMP_UNREACH_NEEDFRAG },
      { "srcfail",		ICMP_UNREACH_SRCFAIL },
      { "net-unknown",		ICMP_UNREACH_NET_UNKNOWN },
      { "host-unknown",		ICMP_UNREACH_HOST_UNKNOWN },
      { "isolated",		ICMP_UNREACH_ISOLATED },
      { "net-prohib",		ICMP_UNREACH_NET_PROHIB },
      { "host-prohib",		ICMP_UNREACH_HOST_PROHIB },
      { "tosnet",		ICMP_UNREACH_TOSNET },
      { "toshost",		ICMP_UNREACH_TOSHOST },
      { "filter-prohib",	ICMP_UNREACH_FILTER_PROHIB },
      { "host-precedence",	ICMP_UNREACH_HOST_PRECEDENCE },
      { "precedence-cutoff",	ICMP_UNREACH_PRECEDENCE_CUTOFF },
      { NULL, 0 }
};

static void
fill_reject_code(u_short *codep, char *str)
{
	int val;
	char *s;

	val = strtoul(str, &s, 0);
	if (s == str || *s != '\0' || val >= 0x100)
		val = match_token(icmpcodes, str);
	if (val < 0)
		errx(EX_DATAERR, "unknown ICMP unreachable code ``%s''", str);
	*codep = val;
	return;
}

static void
print_reject_code(uint16_t code)
{
	char const *s = match_value(icmpcodes, code);

	if (s != NULL)
		printf("unreach %s", s);
	else
		printf("unreach %u", code);
}

static struct _s_x icmp6codes[] = {
      { "no-route",		ICMP6_DST_UNREACH_NOROUTE },
      { "admin-prohib",		ICMP6_DST_UNREACH_ADMIN },
      { "address",		ICMP6_DST_UNREACH_ADDR },
      { "port",			ICMP6_DST_UNREACH_NOPORT },
      { NULL, 0 }
};

static void
fill_unreach6_code(u_short *codep, char *str)
{
	int val;
	char *s;

	val = strtoul(str, &s, 0);
	if (s == str || *s != '\0' || val >= 0x100)
		val = match_token(icmp6codes, str);
	if (val < 0)
		errx(EX_DATAERR, "unknown ICMPv6 unreachable code ``%s''", str);
	*codep = val;
	return;
}

static void
print_unreach6_code(uint16_t code)
{
	char const *s = match_value(icmp6codes, code);

	if (s != NULL)
		printf("unreach6 %s", s);
	else
		printf("unreach6 %u", code);
}

/*
 * Returns the number of bits set (from left) in a contiguous bitmask,
 * or -1 if the mask is not contiguous.
 * XXX this needs a proper fix.
 * This effectively works on masks in big-endian (network) format.
 * when compiled on little endian architectures.
 *
 * First bit is bit 7 of the first byte -- note, for MAC addresses,
 * the first bit on the wire is bit 0 of the first byte.
 * len is the max length in bits.
 */
static int
contigmask(uint8_t *p, int len)
{
	int i, n;

	for (i=0; i<len ; i++)
		if ( (p[i/8] & (1 << (7 - (i%8)))) == 0) /* first bit unset */
			break;
	for (n=i+1; n < len; n++)
		if ( (p[n/8] & (1 << (7 - (n%8)))) != 0)
			return -1; /* mask not contiguous */
	return i;
}

/*
 * print flags set/clear in the two bitmasks passed as parameters.
 * There is a specialized check for f_tcpflags.
 */
static void
print_flags(char const *name, ipfw_insn *cmd, struct _s_x *list)
{
	char const *comma = "";
	int i;
	uint8_t set = cmd->arg1 & 0xff;
	uint8_t clear = (cmd->arg1 >> 8) & 0xff;

	if (list == f_tcpflags && set == TH_SYN && clear == TH_ACK) {
		printf(" setup");
		return;
	}

	printf(" %s ", name);
	for (i=0; list[i].x != 0; i++) {
		if (set & list[i].x) {
			set &= ~list[i].x;
			printf("%s%s", comma, list[i].s);
			comma = ",";
		}
		if (clear & list[i].x) {
			clear &= ~list[i].x;
			printf("%s!%s", comma, list[i].s);
			comma = ",";
		}
	}
}

/*
 * Print the ip address contained in a command.
 */
static void
print_ip(ipfw_insn_ip *cmd, char const *s)
{
	struct hostent *he = NULL;
	int len = F_LEN((ipfw_insn *)cmd);
	uint32_t *a = ((ipfw_insn_u32 *)cmd)->d;

	printf("%s%s ", cmd->o.len & F_NOT ? " not": "", s);

	if (cmd->o.opcode == O_IP_SRC_ME || cmd->o.opcode == O_IP_DST_ME) {
		printf("me");
		return;
	}
	if (cmd->o.opcode == O_IP_SRC_LOOKUP ||
	    cmd->o.opcode == O_IP_DST_LOOKUP) {
		printf("table(%u", ((ipfw_insn *)cmd)->arg1);
		if (len == F_INSN_SIZE(ipfw_insn_u32))
			printf(",%u", *a);
		printf(")");
		return;
	}
	if (cmd->o.opcode == O_IP_SRC_SET || cmd->o.opcode == O_IP_DST_SET) {
		uint32_t x, *map = (uint32_t *)&(cmd->mask);
		int i, j;
		char comma = '{';

		x = cmd->o.arg1 - 1;
		x = htonl( ~x );
		cmd->addr.s_addr = htonl(cmd->addr.s_addr);
		printf("%s/%d", inet_ntoa(cmd->addr),
			contigmask((uint8_t *)&x, 32));
		x = cmd->addr.s_addr = htonl(cmd->addr.s_addr);
		x &= 0xff; /* base */
		/*
		 * Print bits and ranges.
		 * Locate first bit set (i), then locate first bit unset (j).
		 * If we have 3+ consecutive bits set, then print them as a
		 * range, otherwise only print the initial bit and rescan.
		 */
		for (i=0; i < cmd->o.arg1; i++)
			if (map[i/32] & (1<<(i & 31))) {
				for (j=i+1; j < cmd->o.arg1; j++)
					if (!(map[ j/32] & (1<<(j & 31))))
						break;
				printf("%c%d", comma, i+x);
				if (j>i+2) { /* range has at least 3 elements */
					printf("-%d", j-1+x);
					i = j-1;
				}
				comma = ',';
			}
		printf("}");
		return;
	}
	/*
	 * len == 2 indicates a single IP, whereas lists of 1 or more
	 * addr/mask pairs have len = (2n+1). We convert len to n so we
	 * use that to count the number of entries.
	 */
    for (len = len / 2; len > 0; len--, a += 2) {
	int mb =	/* mask length */
	    (cmd->o.opcode == O_IP_SRC || cmd->o.opcode == O_IP_DST) ?
		32 : contigmask((uint8_t *)&(a[1]), 32);
	if (mb == 32 && co.do_resolv)
		he = gethostbyaddr((char *)&(a[0]), sizeof(u_long), AF_INET);
	if (he != NULL)		/* resolved to name */
		printf("%s", he->h_name);
	else if (mb == 0)	/* any */
		printf("any");
	else {		/* numeric IP followed by some kind of mask */
		printf("%s", inet_ntoa( *((struct in_addr *)&a[0]) ) );
		if (mb < 0)
			printf(":%s", inet_ntoa( *((struct in_addr *)&a[1]) ) );
		else if (mb < 32)
			printf("/%d", mb);
	}
	if (len > 1)
		printf(",");
    }
}

/*
 * prints a MAC address/mask pair
 */
static void
print_mac(uint8_t *addr, uint8_t *mask)
{
	int l = contigmask(mask, 48);

	if (l == 0)
		printf(" any");
	else {
		printf(" %02x:%02x:%02x:%02x:%02x:%02x",
		    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
		if (l == -1)
			printf("&%02x:%02x:%02x:%02x:%02x:%02x",
			    mask[0], mask[1], mask[2],
			    mask[3], mask[4], mask[5]);
		else if (l < 48)
			printf("/%d", l);
	}
}

static void
fill_icmptypes(ipfw_insn_u32 *cmd, char *av)
{
	uint8_t type;

	cmd->d[0] = 0;
	while (*av) {
		if (*av == ',')
			av++;

		type = strtoul(av, &av, 0);

		if (*av != ',' && *av != '\0')
			errx(EX_DATAERR, "invalid ICMP type");

		if (type > 31)
			errx(EX_DATAERR, "ICMP type out of range");

		cmd->d[0] |= 1 << type;
	}
	cmd->o.opcode = O_ICMPTYPE;
	cmd->o.len |= F_INSN_SIZE(ipfw_insn_u32);
}

static void
print_icmptypes(ipfw_insn_u32 *cmd)
{
	int i;
	char sep= ' ';

	printf(" icmptypes");
	for (i = 0; i < 32; i++) {
		if ( (cmd->d[0] & (1 << (i))) == 0)
			continue;
		printf("%c%d", sep, i);
		sep = ',';
	}
}

/* 
 * Print the ip address contained in a command.
 */
static void
print_ip6(ipfw_insn_ip6 *cmd, char const *s)
{
       struct hostent *he = NULL;
       int len = F_LEN((ipfw_insn *) cmd) - 1;
       struct in6_addr *a = &(cmd->addr6);
       char trad[255];

       printf("%s%s ", cmd->o.len & F_NOT ? " not": "", s);

       if (cmd->o.opcode == O_IP6_SRC_ME || cmd->o.opcode == O_IP6_DST_ME) {
               printf("me6");
               return;
       }
       if (cmd->o.opcode == O_IP6) {
               printf(" ip6");
               return;
       }

       /*
        * len == 4 indicates a single IP, whereas lists of 1 or more
        * addr/mask pairs have len = (2n+1). We convert len to n so we
        * use that to count the number of entries.
        */

       for (len = len / 4; len > 0; len -= 2, a += 2) {
           int mb =        /* mask length */
               (cmd->o.opcode == O_IP6_SRC || cmd->o.opcode == O_IP6_DST) ?
               128 : contigmask((uint8_t *)&(a[1]), 128);

           if (mb == 128 && co.do_resolv)
               he = gethostbyaddr((char *)a, sizeof(*a), AF_INET6);
           if (he != NULL)             /* resolved to name */
               printf("%s", he->h_name);
           else if (mb == 0)           /* any */
               printf("any");
           else {          /* numeric IP followed by some kind of mask */
               if (inet_ntop(AF_INET6,  a, trad, sizeof( trad ) ) == NULL)
                   printf("Error ntop in print_ip6\n");
               printf("%s",  trad );
               if (mb < 0)     /* XXX not really legal... */
                   printf(":%s",
                       inet_ntop(AF_INET6, &a[1], trad, sizeof(trad)));
               else if (mb < 128)
                   printf("/%d", mb);
           }
           if (len > 2)
               printf(",");
       }
}

static void
fill_icmp6types(ipfw_insn_icmp6 *cmd, char *av)
{
       uint8_t type;

       bzero(cmd, sizeof(*cmd));
       while (*av) {
           if (*av == ',')
               av++;
           type = strtoul(av, &av, 0);
           if (*av != ',' && *av != '\0')
               errx(EX_DATAERR, "invalid ICMP6 type");
	   /*
	    * XXX: shouldn't this be 0xFF?  I can't see any reason why
	    * we shouldn't be able to filter all possiable values
	    * regardless of the ability of the rest of the kernel to do
	    * anything useful with them.
	    */
           if (type > ICMP6_MAXTYPE)
               errx(EX_DATAERR, "ICMP6 type out of range");
           cmd->d[type / 32] |= ( 1 << (type % 32));
       }
       cmd->o.opcode = O_ICMP6TYPE;
       cmd->o.len |= F_INSN_SIZE(ipfw_insn_icmp6);
}


static void
print_icmp6types(ipfw_insn_u32 *cmd)
{
       int i, j;
       char sep= ' ';

       printf(" ip6 icmp6types");
       for (i = 0; i < 7; i++)
               for (j=0; j < 32; ++j) {
                       if ( (cmd->d[i] & (1 << (j))) == 0)
                               continue;
                       printf("%c%d", sep, (i*32 + j));
                       sep = ',';
               }
}

static void
print_flow6id( ipfw_insn_u32 *cmd)
{
       uint16_t i, limit = cmd->o.arg1;
       char sep = ',';

       printf(" flow-id ");
       for( i=0; i < limit; ++i) {
               if (i == limit - 1)
                       sep = ' ';
               printf("%d%c", cmd->d[i], sep);
       }
}

/* structure and define for the extension header in ipv6 */
static struct _s_x ext6hdrcodes[] = {
       { "frag",       EXT_FRAGMENT },
       { "hopopt",     EXT_HOPOPTS },
       { "route",      EXT_ROUTING },
       { "dstopt",     EXT_DSTOPTS },
       { "ah",         EXT_AH },
       { "esp",        EXT_ESP },
       { "rthdr0",     EXT_RTHDR0 },
       { "rthdr2",     EXT_RTHDR2 },
       { NULL,         0 }
};

/* fills command for the extension header filtering */
static int
fill_ext6hdr( ipfw_insn *cmd, char *av)
{
       int tok;
       char *s = av;

       cmd->arg1 = 0;

       while(s) {
           av = strsep( &s, ",") ;
           tok = match_token(ext6hdrcodes, av);
           switch (tok) {
           case EXT_FRAGMENT:
               cmd->arg1 |= EXT_FRAGMENT;
               break;

           case EXT_HOPOPTS:
               cmd->arg1 |= EXT_HOPOPTS;
               break;

           case EXT_ROUTING:
               cmd->arg1 |= EXT_ROUTING;
               break;

           case EXT_DSTOPTS:
               cmd->arg1 |= EXT_DSTOPTS;
               break;

           case EXT_AH:
               cmd->arg1 |= EXT_AH;
               break;

           case EXT_ESP:
               cmd->arg1 |= EXT_ESP;
               break;

           case EXT_RTHDR0:
               cmd->arg1 |= EXT_RTHDR0;
               break;

           case EXT_RTHDR2:
               cmd->arg1 |= EXT_RTHDR2;
               break;

           default:
               errx( EX_DATAERR, "invalid option for ipv6 exten header" );
               break;
           }
       }
       if (cmd->arg1 == 0 )
           return 0;
       cmd->opcode = O_EXT_HDR;
       cmd->len |= F_INSN_SIZE( ipfw_insn );
       return 1;
}

static void
print_ext6hdr( ipfw_insn *cmd )
{
       char sep = ' ';

       printf(" extension header:");
       if (cmd->arg1 & EXT_FRAGMENT ) {
           printf("%cfragmentation", sep);
           sep = ',';
       }
       if (cmd->arg1 & EXT_HOPOPTS ) {
           printf("%chop options", sep);
           sep = ',';
       }
       if (cmd->arg1 & EXT_ROUTING ) {
           printf("%crouting options", sep);
           sep = ',';
       }
       if (cmd->arg1 & EXT_RTHDR0 ) {
           printf("%crthdr0", sep);
           sep = ',';
       }
       if (cmd->arg1 & EXT_RTHDR2 ) {
           printf("%crthdr2", sep);
           sep = ',';
       }
       if (cmd->arg1 & EXT_DSTOPTS ) {
           printf("%cdestination options", sep);
           sep = ',';
       }
       if (cmd->arg1 & EXT_AH ) {
           printf("%cauthentication header", sep);
           sep = ',';
       }
       if (cmd->arg1 & EXT_ESP ) {
           printf("%cencapsulated security payload", sep);
       }
}

/*
 * show_ipfw() prints the body of an ipfw rule.
 * Because the standard rule has at least proto src_ip dst_ip, we use
 * a helper function to produce these entries if not provided explicitly.
 * The first argument is the list of fields we have, the second is
 * the list of fields we want to be printed.
 *
 * Special cases if we have provided a MAC header:
 *   + if the rule does not contain IP addresses/ports, do not print them;
 *   + if the rule does not contain an IP proto, print "all" instead of "ip";
 *
 * Once we have 'have_options', IP header fields are printed as options.
 */
#define	HAVE_PROTO	0x0001
#define	HAVE_SRCIP	0x0002
#define	HAVE_DSTIP	0x0004
#define	HAVE_PROTO4	0x0008
#define	HAVE_PROTO6	0x0010
#define	HAVE_OPTIONS	0x8000

#define	HAVE_IP		(HAVE_PROTO | HAVE_SRCIP | HAVE_DSTIP)
static void
show_prerequisites(int *flags, int want, int cmd __unused)
{
	if (co.comment_only)
		return;
	if ( (*flags & HAVE_IP) == HAVE_IP)
		*flags |= HAVE_OPTIONS;

	if ( !(*flags & HAVE_OPTIONS)) {
		if ( !(*flags & HAVE_PROTO) && (want & HAVE_PROTO)) {
			if ( (*flags & HAVE_PROTO4))
				printf(" ip4");
			else if ( (*flags & HAVE_PROTO6))
				printf(" ip6");
			else
				printf(" ip");
		}
		if ( !(*flags & HAVE_SRCIP) && (want & HAVE_SRCIP))
			printf(" from any");
		if ( !(*flags & HAVE_DSTIP) && (want & HAVE_DSTIP))
			printf(" to any");
	}
	*flags |= want;
}

static void
show_ipfw(struct ip_fw *rule, int pcwidth, int bcwidth)
{
	static int twidth = 0;
	int l;
	ipfw_insn *cmd, *tagptr = NULL;
	const char *comment = NULL;	/* ptr to comment if we have one */
	int proto = 0;		/* default */
	int flags = 0;	/* prerequisites */
	ipfw_insn_log *logptr = NULL; /* set if we find an O_LOG */
	ipfw_insn_altq *altqptr = NULL; /* set if we find an O_ALTQ */
	int or_block = 0;	/* we are in an or block */
	uint32_t set_disable;

	bcopy(&rule->next_rule, &set_disable, sizeof(set_disable));

	if (set_disable & (1 << rule->set)) { /* disabled */
		if (!co.show_sets)
			return;
		else
			printf("# DISABLED ");
	}
	printf("%05u ", rule->rulenum);

	if (pcwidth>0 || bcwidth>0)
		printf("%*llu %*llu ", pcwidth, align_uint64(&rule->pcnt),
		    bcwidth, align_uint64(&rule->bcnt));

	if (co.do_time == 2)
		printf("%10u ", rule->timestamp);
	else if (co.do_time == 1) {
		char timestr[30];
		time_t t = (time_t)0;

		if (twidth == 0) {
			strcpy(timestr, ctime(&t));
			*strchr(timestr, '\n') = '\0';
			twidth = strlen(timestr);
		}
		if (rule->timestamp) {
			t = _long_to_time(rule->timestamp);

			strcpy(timestr, ctime(&t));
			*strchr(timestr, '\n') = '\0';
			printf("%s ", timestr);
		} else {
			printf("%*s", twidth, " ");
		}
	}

	if (co.show_sets)
		printf("set %d ", rule->set);

	/*
	 * print the optional "match probability"
	 */
	if (rule->cmd_len > 0) {
		cmd = rule->cmd ;
		if (cmd->opcode == O_PROB) {
			ipfw_insn_u32 *p = (ipfw_insn_u32 *)cmd;
			double d = 1.0 * p->d[0];

			d = (d / 0x7fffffff);
			printf("prob %f ", d);
		}
	}

	/*
	 * first print actions
	 */
        for (l = rule->cmd_len - rule->act_ofs, cmd = ACTION_PTR(rule);
			l > 0 ; l -= F_LEN(cmd), cmd += F_LEN(cmd)) {
		switch(cmd->opcode) {
		case O_CHECK_STATE:
			printf("check-state");
			flags = HAVE_IP; /* avoid printing anything else */
			break;

		case O_ACCEPT:
			printf("allow");
			break;

		case O_COUNT:
			printf("count");
			break;

		case O_DENY:
			printf("deny");
			break;

		case O_REJECT:
			if (cmd->arg1 == ICMP_REJECT_RST)
				printf("reset");
			else if (cmd->arg1 == ICMP_UNREACH_HOST)
				printf("reject");
			else
				print_reject_code(cmd->arg1);
			break;

		case O_UNREACH6:
			if (cmd->arg1 == ICMP6_UNREACH_RST)
				printf("reset6");
			else
				print_unreach6_code(cmd->arg1);
			break;

		case O_SKIPTO:
			PRINT_UINT_ARG("skipto ", cmd->arg1);
			break;

		case O_PIPE:
			PRINT_UINT_ARG("pipe ", cmd->arg1);
			break;

		case O_QUEUE:
			PRINT_UINT_ARG("queue ", cmd->arg1);
			break;

		case O_DIVERT:
			PRINT_UINT_ARG("divert ", cmd->arg1);
			break;

		case O_TEE:
			PRINT_UINT_ARG("tee ", cmd->arg1);
			break;

		case O_NETGRAPH:
			PRINT_UINT_ARG("netgraph ", cmd->arg1);
			break;

		case O_NGTEE:
			PRINT_UINT_ARG("ngtee ", cmd->arg1);
			break;

		case O_FORWARD_IP:
		    {
			ipfw_insn_sa *s = (ipfw_insn_sa *)cmd;

			if (s->sa.sin_addr.s_addr == INADDR_ANY) {
				printf("fwd tablearg");
			} else {
				printf("fwd %s", inet_ntoa(s->sa.sin_addr));
			}
			if (s->sa.sin_port)
				printf(",%d", s->sa.sin_port);
		    }
			break;

		case O_LOG: /* O_LOG is printed last */
			logptr = (ipfw_insn_log *)cmd;
			break;

		case O_ALTQ: /* O_ALTQ is printed after O_LOG */
			altqptr = (ipfw_insn_altq *)cmd;
			break;

		case O_TAG:
			tagptr = cmd;
			break;

		case O_NAT:
			PRINT_UINT_ARG("nat ", cmd->arg1);
 			break;
			
		case O_SETFIB:
			PRINT_UINT_ARG("setfib ", cmd->arg1);
 			break;
			
		default:
			printf("** unrecognized action %d len %d ",
				cmd->opcode, cmd->len);
		}
	}
	if (logptr) {
		if (logptr->max_log > 0)
			printf(" log logamount %d", logptr->max_log);
		else
			printf(" log");
	}
	if (altqptr) {
		const char *qname;

		qname = altq_qid_to_name(altqptr->qid);
		if (qname == NULL)
			printf(" altq ?<%u>", altqptr->qid);
		else
			printf(" altq %s", qname);
	}
	if (tagptr) {
		if (tagptr->len & F_NOT)
			PRINT_UINT_ARG(" untag ", tagptr->arg1);
		else
			PRINT_UINT_ARG(" tag ", tagptr->arg1);
	}

	/*
	 * then print the body.
	 */
        for (l = rule->act_ofs, cmd = rule->cmd ;
			l > 0 ; l -= F_LEN(cmd) , cmd += F_LEN(cmd)) {
		if ((cmd->len & F_OR) || (cmd->len & F_NOT))
			continue;
		if (cmd->opcode == O_IP4) {
			flags |= HAVE_PROTO4;
			break;
		} else if (cmd->opcode == O_IP6) {
			flags |= HAVE_PROTO6;
			break;
		}			
	}
	if (rule->_pad & 1) {	/* empty rules before options */
		if (!co.do_compact) {
			show_prerequisites(&flags, HAVE_PROTO, 0);
			printf(" from any to any");
		}
		flags |= HAVE_IP | HAVE_OPTIONS;
	}

	if (co.comment_only)
		comment = "...";

        for (l = rule->act_ofs, cmd = rule->cmd ;
			l > 0 ; l -= F_LEN(cmd) , cmd += F_LEN(cmd)) {
		/* useful alias */
		ipfw_insn_u32 *cmd32 = (ipfw_insn_u32 *)cmd;

		if (co.comment_only) {
			if (cmd->opcode != O_NOP)
				continue;
			printf(" // %s\n", (char *)(cmd + 1));
			return;
		}

		show_prerequisites(&flags, 0, cmd->opcode);

		switch(cmd->opcode) {
		case O_PROB:
			break;	/* done already */

		case O_PROBE_STATE:
			break; /* no need to print anything here */

		case O_IP_SRC:
		case O_IP_SRC_LOOKUP:
		case O_IP_SRC_MASK:
		case O_IP_SRC_ME:
		case O_IP_SRC_SET:
			show_prerequisites(&flags, HAVE_PROTO, 0);
			if (!(flags & HAVE_SRCIP))
				printf(" from");
			if ((cmd->len & F_OR) && !or_block)
				printf(" {");
			print_ip((ipfw_insn_ip *)cmd,
				(flags & HAVE_OPTIONS) ? " src-ip" : "");
			flags |= HAVE_SRCIP;
			break;

		case O_IP_DST:
		case O_IP_DST_LOOKUP:
		case O_IP_DST_MASK:
		case O_IP_DST_ME:
		case O_IP_DST_SET:
			show_prerequisites(&flags, HAVE_PROTO|HAVE_SRCIP, 0);
			if (!(flags & HAVE_DSTIP))
				printf(" to");
			if ((cmd->len & F_OR) && !or_block)
				printf(" {");
			print_ip((ipfw_insn_ip *)cmd,
				(flags & HAVE_OPTIONS) ? " dst-ip" : "");
			flags |= HAVE_DSTIP;
			break;

		case O_IP6_SRC:
		case O_IP6_SRC_MASK:
		case O_IP6_SRC_ME:
			show_prerequisites(&flags, HAVE_PROTO, 0);
			if (!(flags & HAVE_SRCIP))
				printf(" from");
			if ((cmd->len & F_OR) && !or_block)
				printf(" {");
			print_ip6((ipfw_insn_ip6 *)cmd,
			    (flags & HAVE_OPTIONS) ? " src-ip6" : "");
			flags |= HAVE_SRCIP | HAVE_PROTO;
			break;

		case O_IP6_DST:
		case O_IP6_DST_MASK:
		case O_IP6_DST_ME:
			show_prerequisites(&flags, HAVE_PROTO|HAVE_SRCIP, 0);
			if (!(flags & HAVE_DSTIP))
				printf(" to");
			if ((cmd->len & F_OR) && !or_block)
				printf(" {");
			print_ip6((ipfw_insn_ip6 *)cmd,
			    (flags & HAVE_OPTIONS) ? " dst-ip6" : "");
			flags |= HAVE_DSTIP;
			break;

		case O_FLOW6ID:
		print_flow6id( (ipfw_insn_u32 *) cmd );
		flags |= HAVE_OPTIONS;
		break;

		case O_IP_DSTPORT:
			show_prerequisites(&flags, HAVE_IP, 0);
		case O_IP_SRCPORT:
			show_prerequisites(&flags, HAVE_PROTO|HAVE_SRCIP, 0);
			if ((cmd->len & F_OR) && !or_block)
				printf(" {");
			if (cmd->len & F_NOT)
				printf(" not");
			print_newports((ipfw_insn_u16 *)cmd, proto,
				(flags & HAVE_OPTIONS) ? cmd->opcode : 0);
			break;

		case O_PROTO: {
			struct protoent *pe = NULL;

			if ((cmd->len & F_OR) && !or_block)
				printf(" {");
			if (cmd->len & F_NOT)
				printf(" not");
			proto = cmd->arg1;
			pe = getprotobynumber(cmd->arg1);
			if ((flags & (HAVE_PROTO4 | HAVE_PROTO6)) &&
			    !(flags & HAVE_PROTO))
				show_prerequisites(&flags,
				    HAVE_IP | HAVE_OPTIONS, 0);
			if (flags & HAVE_OPTIONS)
				printf(" proto");
			if (pe)
				printf(" %s", pe->p_name);
			else
				printf(" %u", cmd->arg1);
			}
			flags |= HAVE_PROTO;
			break;

		default: /*options ... */
			if (!(cmd->len & (F_OR|F_NOT)))
				if (((cmd->opcode == O_IP6) &&
				    (flags & HAVE_PROTO6)) ||
				    ((cmd->opcode == O_IP4) &&
				    (flags & HAVE_PROTO4)))
					break;
			show_prerequisites(&flags, HAVE_IP | HAVE_OPTIONS, 0);
			if ((cmd->len & F_OR) && !or_block)
				printf(" {");
			if (cmd->len & F_NOT && cmd->opcode != O_IN)
				printf(" not");
			switch(cmd->opcode) {
			case O_MACADDR2: {
				ipfw_insn_mac *m = (ipfw_insn_mac *)cmd;

				printf(" MAC");
				print_mac(m->addr, m->mask);
				print_mac(m->addr + 6, m->mask + 6);
				}
				break;

			case O_MAC_TYPE:
				print_newports((ipfw_insn_u16 *)cmd,
						IPPROTO_ETHERTYPE, cmd->opcode);
				break;


			case O_FRAG:
				printf(" frag");
				break;

			case O_FIB:
				printf(" fib %u", cmd->arg1 );
				break;

			case O_IN:
				printf(cmd->len & F_NOT ? " out" : " in");
				break;

			case O_DIVERTED:
				switch (cmd->arg1) {
				case 3:
					printf(" diverted");
					break;
				case 1:
					printf(" diverted-loopback");
					break;
				case 2:
					printf(" diverted-output");
					break;
				default:
					printf(" diverted-?<%u>", cmd->arg1);
					break;
				}
				break;

			case O_LAYER2:
				printf(" layer2");
				break;
			case O_XMIT:
			case O_RECV:
			case O_VIA:
			    {
				char const *s;
				ipfw_insn_if *cmdif = (ipfw_insn_if *)cmd;

				if (cmd->opcode == O_XMIT)
					s = "xmit";
				else if (cmd->opcode == O_RECV)
					s = "recv";
				else /* if (cmd->opcode == O_VIA) */
					s = "via";
				if (cmdif->name[0] == '\0')
					printf(" %s %s", s,
					    inet_ntoa(cmdif->p.ip));
				else
					printf(" %s %s", s, cmdif->name);

				break;
			    }
			case O_IPID:
				if (F_LEN(cmd) == 1)
				    printf(" ipid %u", cmd->arg1 );
				else
				    print_newports((ipfw_insn_u16 *)cmd, 0,
					O_IPID);
				break;

			case O_IPTTL:
				if (F_LEN(cmd) == 1)
				    printf(" ipttl %u", cmd->arg1 );
				else
				    print_newports((ipfw_insn_u16 *)cmd, 0,
					O_IPTTL);
				break;

			case O_IPVER:
				printf(" ipver %u", cmd->arg1 );
				break;

			case O_IPPRECEDENCE:
				printf(" ipprecedence %u", (cmd->arg1) >> 5 );
				break;

			case O_IPLEN:
				if (F_LEN(cmd) == 1)
				    printf(" iplen %u", cmd->arg1 );
				else
				    print_newports((ipfw_insn_u16 *)cmd, 0,
					O_IPLEN);
				break;

			case O_IPOPT:
				print_flags("ipoptions", cmd, f_ipopts);
				break;

			case O_IPTOS:
				print_flags("iptos", cmd, f_iptos);
				break;

			case O_ICMPTYPE:
				print_icmptypes((ipfw_insn_u32 *)cmd);
				break;

			case O_ESTAB:
				printf(" established");
				break;

			case O_TCPDATALEN:
				if (F_LEN(cmd) == 1)
				    printf(" tcpdatalen %u", cmd->arg1 );
				else
				    print_newports((ipfw_insn_u16 *)cmd, 0,
					O_TCPDATALEN);
				break;

			case O_TCPFLAGS:
				print_flags("tcpflags", cmd, f_tcpflags);
				break;

			case O_TCPOPTS:
				print_flags("tcpoptions", cmd, f_tcpopts);
				break;

			case O_TCPWIN:
				printf(" tcpwin %d", ntohs(cmd->arg1));
				break;

			case O_TCPACK:
				printf(" tcpack %d", ntohl(cmd32->d[0]));
				break;

			case O_TCPSEQ:
				printf(" tcpseq %d", ntohl(cmd32->d[0]));
				break;

			case O_UID:
			    {
				struct passwd *pwd = getpwuid(cmd32->d[0]);

				if (pwd)
					printf(" uid %s", pwd->pw_name);
				else
					printf(" uid %u", cmd32->d[0]);
			    }
				break;

			case O_GID:
			    {
				struct group *grp = getgrgid(cmd32->d[0]);

				if (grp)
					printf(" gid %s", grp->gr_name);
				else
					printf(" gid %u", cmd32->d[0]);
			    }
				break;

			case O_JAIL:
				printf(" jail %d", cmd32->d[0]);
				break;

			case O_VERREVPATH:
				printf(" verrevpath");
				break;

			case O_VERSRCREACH:
				printf(" versrcreach");
				break;

			case O_ANTISPOOF:
				printf(" antispoof");
				break;

			case O_IPSEC:
				printf(" ipsec");
				break;

			case O_NOP:
				comment = (char *)(cmd + 1);
				break;

			case O_KEEP_STATE:
				printf(" keep-state");
				break;

			case O_LIMIT: {
				struct _s_x *p = limit_masks;
				ipfw_insn_limit *c = (ipfw_insn_limit *)cmd;
				uint8_t x = c->limit_mask;
				char const *comma = " ";

				printf(" limit");
				for (; p->x != 0 ; p++)
					if ((x & p->x) == p->x) {
						x &= ~p->x;
						printf("%s%s", comma, p->s);
						comma = ",";
					}
				PRINT_UINT_ARG(" ", c->conn_limit);
				break;
			}

			case O_IP6:
				printf(" ip6");
				break;

			case O_IP4:
				printf(" ip4");
				break;

			case O_ICMP6TYPE:
				print_icmp6types((ipfw_insn_u32 *)cmd);
				break;

			case O_EXT_HDR:
				print_ext6hdr( (ipfw_insn *) cmd );
				break;

			case O_TAGGED:
				if (F_LEN(cmd) == 1)
					PRINT_UINT_ARG(" tagged ", cmd->arg1);
				else
					print_newports((ipfw_insn_u16 *)cmd, 0,
					    O_TAGGED);
				break;

			default:
				printf(" [opcode %d len %d]",
				    cmd->opcode, cmd->len);
			}
		}
		if (cmd->len & F_OR) {
			printf(" or");
			or_block = 1;
		} else if (or_block) {
			printf(" }");
			or_block = 0;
		}
	}
	show_prerequisites(&flags, HAVE_IP, 0);
	if (comment)
		printf(" // %s", comment);
	printf("\n");
}

static void
show_dyn_ipfw(ipfw_dyn_rule *d, int pcwidth, int bcwidth)
{
	struct protoent *pe;
	struct in_addr a;
	uint16_t rulenum;
	char buf[INET6_ADDRSTRLEN];

	if (!co.do_expired) {
		if (!d->expire && !(d->dyn_type == O_LIMIT_PARENT))
			return;
	}
	bcopy(&d->rule, &rulenum, sizeof(rulenum));
	printf("%05d", rulenum);
	if (pcwidth>0 || bcwidth>0)
	    printf(" %*llu %*llu (%ds)", pcwidth,
		align_uint64(&d->pcnt), bcwidth,
		align_uint64(&d->bcnt), d->expire);
	switch (d->dyn_type) {
	case O_LIMIT_PARENT:
		printf(" PARENT %d", d->count);
		break;
	case O_LIMIT:
		printf(" LIMIT");
		break;
	case O_KEEP_STATE: /* bidir, no mask */
		printf(" STATE");
		break;
	}

	if ((pe = getprotobynumber(d->id.proto)) != NULL)
		printf(" %s", pe->p_name);
	else
		printf(" proto %u", d->id.proto);

	if (d->id.addr_type == 4) {
		a.s_addr = htonl(d->id.src_ip);
		printf(" %s %d", inet_ntoa(a), d->id.src_port);

		a.s_addr = htonl(d->id.dst_ip);
		printf(" <-> %s %d", inet_ntoa(a), d->id.dst_port);
	} else if (d->id.addr_type == 6) {
		printf(" %s %d", inet_ntop(AF_INET6, &d->id.src_ip6, buf,
		    sizeof(buf)), d->id.src_port);
		printf(" <-> %s %d", inet_ntop(AF_INET6, &d->id.dst_ip6, buf,
		    sizeof(buf)), d->id.dst_port);
	} else
		printf(" UNKNOWN <-> UNKNOWN\n");
	
	printf("\n");
}

/*
 * This one handles all set-related commands
 * 	ipfw set { show | enable | disable }
 * 	ipfw set swap X Y
 * 	ipfw set move X to Y
 * 	ipfw set move rule X to Y
 */
void
ipfw_sets_handler(int ac, char *av[])
{
	uint32_t set_disable, masks[2];
	int i, nbytes;
	uint16_t rulenum;
	uint8_t cmd, new_set;

	ac--;
	av++;

	if (!ac)
		errx(EX_USAGE, "set needs command");
	if (_substrcmp(*av, "show") == 0) {
		void *data;
		char const *msg;

		nbytes = sizeof(struct ip_fw);
		data = safe_calloc(1, nbytes);
		if (do_cmd(IP_FW_GET, data, (uintptr_t)&nbytes) < 0)
			err(EX_OSERR, "getsockopt(IP_FW_GET)");
		bcopy(&((struct ip_fw *)data)->next_rule,
			&set_disable, sizeof(set_disable));

		for (i = 0, msg = "disable" ; i < RESVD_SET; i++)
			if ((set_disable & (1<<i))) {
				printf("%s %d", msg, i);
				msg = "";
			}
		msg = (set_disable) ? " enable" : "enable";
		for (i = 0; i < RESVD_SET; i++)
			if (!(set_disable & (1<<i))) {
				printf("%s %d", msg, i);
				msg = "";
			}
		printf("\n");
	} else if (_substrcmp(*av, "swap") == 0) {
		ac--; av++;
		if (ac != 2)
			errx(EX_USAGE, "set swap needs 2 set numbers\n");
		rulenum = atoi(av[0]);
		new_set = atoi(av[1]);
		if (!isdigit(*(av[0])) || rulenum > RESVD_SET)
			errx(EX_DATAERR, "invalid set number %s\n", av[0]);
		if (!isdigit(*(av[1])) || new_set > RESVD_SET)
			errx(EX_DATAERR, "invalid set number %s\n", av[1]);
		masks[0] = (4 << 24) | (new_set << 16) | (rulenum);
		i = do_cmd(IP_FW_DEL, masks, sizeof(uint32_t));
	} else if (_substrcmp(*av, "move") == 0) {
		ac--; av++;
		if (ac && _substrcmp(*av, "rule") == 0) {
			cmd = 2;
			ac--; av++;
		} else
			cmd = 3;
		if (ac != 3 || _substrcmp(av[1], "to") != 0)
			errx(EX_USAGE, "syntax: set move [rule] X to Y\n");
		rulenum = atoi(av[0]);
		new_set = atoi(av[2]);
		if (!isdigit(*(av[0])) || (cmd == 3 && rulenum > RESVD_SET) ||
			(cmd == 2 && rulenum == IPFW_DEFAULT_RULE) )
			errx(EX_DATAERR, "invalid source number %s\n", av[0]);
		if (!isdigit(*(av[2])) || new_set > RESVD_SET)
			errx(EX_DATAERR, "invalid dest. set %s\n", av[1]);
		masks[0] = (cmd << 24) | (new_set << 16) | (rulenum);
		i = do_cmd(IP_FW_DEL, masks, sizeof(uint32_t));
	} else if (_substrcmp(*av, "disable") == 0 ||
		   _substrcmp(*av, "enable") == 0 ) {
		int which = _substrcmp(*av, "enable") == 0 ? 1 : 0;

		ac--; av++;
		masks[0] = masks[1] = 0;

		while (ac) {
			if (isdigit(**av)) {
				i = atoi(*av);
				if (i < 0 || i > RESVD_SET)
					errx(EX_DATAERR,
					    "invalid set number %d\n", i);
				masks[which] |= (1<<i);
			} else if (_substrcmp(*av, "disable") == 0)
				which = 0;
			else if (_substrcmp(*av, "enable") == 0)
				which = 1;
			else
				errx(EX_DATAERR,
					"invalid set command %s\n", *av);
			av++; ac--;
		}
		if ( (masks[0] & masks[1]) != 0 )
			errx(EX_DATAERR,
			    "cannot enable and disable the same set\n");

		i = do_cmd(IP_FW_DEL, masks, sizeof(masks));
		if (i)
			warn("set enable/disable: setsockopt(IP_FW_DEL)");
	} else
		errx(EX_USAGE, "invalid set command %s\n", *av);
}

void
ipfw_sysctl_handler(int ac, char *av[], int which)
{
	ac--;
	av++;

	if (ac == 0) {
		warnx("missing keyword to enable/disable\n");
	} else if (_substrcmp(*av, "firewall") == 0) {
		sysctlbyname("net.inet.ip.fw.enable", NULL, 0,
		    &which, sizeof(which));
	} else if (_substrcmp(*av, "one_pass") == 0) {
		sysctlbyname("net.inet.ip.fw.one_pass", NULL, 0,
		    &which, sizeof(which));
	} else if (_substrcmp(*av, "debug") == 0) {
		sysctlbyname("net.inet.ip.fw.debug", NULL, 0,
		    &which, sizeof(which));
	} else if (_substrcmp(*av, "verbose") == 0) {
		sysctlbyname("net.inet.ip.fw.verbose", NULL, 0,
		    &which, sizeof(which));
	} else if (_substrcmp(*av, "dyn_keepalive") == 0) {
		sysctlbyname("net.inet.ip.fw.dyn_keepalive", NULL, 0,
		    &which, sizeof(which));
	} else if (_substrcmp(*av, "altq") == 0) {
		altq_set_enabled(which);
	} else {
		warnx("unrecognize enable/disable keyword: %s\n", *av);
	}
}

void
ipfw_list(int ac, char *av[], int show_counters)
{
	struct ip_fw *r;
	ipfw_dyn_rule *dynrules, *d;

#define NEXT(r)	((struct ip_fw *)((char *)r + RULESIZE(r)))
	char *lim;
	void *data = NULL;
	int bcwidth, n, nbytes, nstat, ndyn, pcwidth, width;
	int exitval = EX_OK;
	int lac;
	char **lav;
	u_long rnum, last;
	char *endptr;
	int seen = 0;
	uint8_t set;

	const int ocmd = co.do_pipe ? IP_DUMMYNET_GET : IP_FW_GET;
	int nalloc = 1024;	/* start somewhere... */

	last = 0;

	if (co.test_only) {
		fprintf(stderr, "Testing only, list disabled\n");
		return;
	}

	ac--;
	av++;

	/* get rules or pipes from kernel, resizing array as necessary */
	nbytes = nalloc;

	while (nbytes >= nalloc) {
		nalloc = nalloc * 2 + 200;
		nbytes = nalloc;
		data = safe_realloc(data, nbytes);
		if (do_cmd(ocmd, data, (uintptr_t)&nbytes) < 0)
			err(EX_OSERR, "getsockopt(IP_%s_GET)",
				co.do_pipe ? "DUMMYNET" : "FW");
	}

	if (co.do_pipe) {
		ipfw_list_pipes(data, nbytes, ac, av);
		goto done;
	}

	/*
	 * Count static rules. They have variable size so we
	 * need to scan the list to count them.
	 */
	for (nstat = 1, r = data, lim = (char *)data + nbytes;
		    r->rulenum < IPFW_DEFAULT_RULE && (char *)r < lim;
		    ++nstat, r = NEXT(r) )
		; /* nothing */

	/*
	 * Count dynamic rules. This is easier as they have
	 * fixed size.
	 */
	r = NEXT(r);
	dynrules = (ipfw_dyn_rule *)r ;
	n = (char *)r - (char *)data;
	ndyn = (nbytes - n) / sizeof *dynrules;

	/* if showing stats, figure out column widths ahead of time */
	bcwidth = pcwidth = 0;
	if (show_counters) {
		for (n = 0, r = data; n < nstat; n++, r = NEXT(r)) {
			/* skip rules from another set */
			if (co.use_set && r->set != co.use_set - 1)
				continue;

			/* packet counter */
			width = snprintf(NULL, 0, "%llu",
			    align_uint64(&r->pcnt));
			if (width > pcwidth)
				pcwidth = width;

			/* byte counter */
			width = snprintf(NULL, 0, "%llu",
			    align_uint64(&r->bcnt));
			if (width > bcwidth)
				bcwidth = width;
		}
	}
	if (co.do_dynamic && ndyn) {
		for (n = 0, d = dynrules; n < ndyn; n++, d++) {
			if (co.use_set) {
				/* skip rules from another set */
				bcopy((char *)&d->rule + sizeof(uint16_t),
				      &set, sizeof(uint8_t));
				if (set != co.use_set - 1)
					continue;
			}
			width = snprintf(NULL, 0, "%llu",
			    align_uint64(&d->pcnt));
			if (width > pcwidth)
				pcwidth = width;

			width = snprintf(NULL, 0, "%llu",
			    align_uint64(&d->bcnt));
			if (width > bcwidth)
				bcwidth = width;
		}
	}
	/* if no rule numbers were specified, list all rules */
	if (ac == 0) {
		for (n = 0, r = data; n < nstat; n++, r = NEXT(r)) {
			if (co.use_set && r->set != co.use_set - 1)
				continue;
			show_ipfw(r, pcwidth, bcwidth);
		}

		if (co.do_dynamic && ndyn) {
			printf("## Dynamic rules (%d):\n", ndyn);
			for (n = 0, d = dynrules; n < ndyn; n++, d++) {
				if (co.use_set) {
					bcopy((char *)&d->rule + sizeof(uint16_t),
					      &set, sizeof(uint8_t));
					if (set != co.use_set - 1)
						continue;
				}
				show_dyn_ipfw(d, pcwidth, bcwidth);
		}
		}
		goto done;
	}

	/* display specific rules requested on command line */

	for (lac = ac, lav = av; lac != 0; lac--) {
		/* convert command line rule # */
		last = rnum = strtoul(*lav++, &endptr, 10);
		if (*endptr == '-')
			last = strtoul(endptr+1, &endptr, 10);
		if (*endptr) {
			exitval = EX_USAGE;
			warnx("invalid rule number: %s", *(lav - 1));
			continue;
		}
		for (n = seen = 0, r = data; n < nstat; n++, r = NEXT(r) ) {
			if (r->rulenum > last)
				break;
			if (co.use_set && r->set != co.use_set - 1)
				continue;
			if (r->rulenum >= rnum && r->rulenum <= last) {
				show_ipfw(r, pcwidth, bcwidth);
				seen = 1;
			}
		}
		if (!seen) {
			/* give precedence to other error(s) */
			if (exitval == EX_OK)
				exitval = EX_UNAVAILABLE;
			warnx("rule %lu does not exist", rnum);
		}
	}

	if (co.do_dynamic && ndyn) {
		printf("## Dynamic rules:\n");
		for (lac = ac, lav = av; lac != 0; lac--) {
			last = rnum = strtoul(*lav++, &endptr, 10);
			if (*endptr == '-')
				last = strtoul(endptr+1, &endptr, 10);
			if (*endptr)
				/* already warned */
				continue;
			for (n = 0, d = dynrules; n < ndyn; n++, d++) {
				uint16_t rulenum;

				bcopy(&d->rule, &rulenum, sizeof(rulenum));
				if (rulenum > rnum)
					break;
				if (co.use_set) {
					bcopy((char *)&d->rule + sizeof(uint16_t),
					      &set, sizeof(uint8_t));
					if (set != co.use_set - 1)
						continue;
				}
				if (r->rulenum >= rnum && r->rulenum <= last)
					show_dyn_ipfw(d, pcwidth, bcwidth);
			}
		}
	}

	ac = 0;

done:
	free(data);

	if (exitval != EX_OK)
		exit(exitval);
#undef NEXT
}

static int
lookup_host (char *host, struct in_addr *ipaddr)
{
	struct hostent *he;

	if (!inet_aton(host, ipaddr)) {
		if ((he = gethostbyname(host)) == NULL)
			return(-1);
		*ipaddr = *(struct in_addr *)he->h_addr_list[0];
	}
	return(0);
}

/*
 * fills the addr and mask fields in the instruction as appropriate from av.
 * Update length as appropriate.
 * The following formats are allowed:
 *	me	returns O_IP_*_ME
 *	1.2.3.4		single IP address
 *	1.2.3.4:5.6.7.8	address:mask
 *	1.2.3.4/24	address/mask
 *	1.2.3.4/26{1,6,5,4,23}	set of addresses in a subnet
 * We can have multiple comma-separated address/mask entries.
 */
static void
fill_ip(ipfw_insn_ip *cmd, char *av)
{
	int len = 0;
	uint32_t *d = ((ipfw_insn_u32 *)cmd)->d;

	cmd->o.len &= ~F_LEN_MASK;	/* zero len */

	if (_substrcmp(av, "any") == 0)
		return;

	if (_substrcmp(av, "me") == 0) {
		cmd->o.len |= F_INSN_SIZE(ipfw_insn);
		return;
	}

	if (strncmp(av, "table(", 6) == 0) {
		char *p = strchr(av + 6, ',');

		if (p)
			*p++ = '\0';
		cmd->o.opcode = O_IP_DST_LOOKUP;
		cmd->o.arg1 = strtoul(av + 6, NULL, 0);
		if (p) {
			cmd->o.len |= F_INSN_SIZE(ipfw_insn_u32);
			d[0] = strtoul(p, NULL, 0);
		} else
			cmd->o.len |= F_INSN_SIZE(ipfw_insn);
		return;
	}

    while (av) {
	/*
	 * After the address we can have '/' or ':' indicating a mask,
	 * ',' indicating another address follows, '{' indicating a
	 * set of addresses of unspecified size.
	 */
	char *t = NULL, *p = strpbrk(av, "/:,{");
	int masklen;
	char md, nd = '\0';

	if (p) {
		md = *p;
		*p++ = '\0';
		if ((t = strpbrk(p, ",{")) != NULL) {
			nd = *t;
			*t = '\0';
		}
	} else
		md = '\0';

	if (lookup_host(av, (struct in_addr *)&d[0]) != 0)
		errx(EX_NOHOST, "hostname ``%s'' unknown", av);
	switch (md) {
	case ':':
		if (!inet_aton(p, (struct in_addr *)&d[1]))
			errx(EX_DATAERR, "bad netmask ``%s''", p);
		break;
	case '/':
		masklen = atoi(p);
		if (masklen == 0)
			d[1] = htonl(0);	/* mask */
		else if (masklen > 32)
			errx(EX_DATAERR, "bad width ``%s''", p);
		else
			d[1] = htonl(~0 << (32 - masklen));
		break;
	case '{':	/* no mask, assume /24 and put back the '{' */
		d[1] = htonl(~0 << (32 - 24));
		*(--p) = md;
		break;

	case ',':	/* single address plus continuation */
		*(--p) = md;
		/* FALLTHROUGH */
	case 0:		/* initialization value */
	default:
		d[1] = htonl(~0);	/* force /32 */
		break;
	}
	d[0] &= d[1];		/* mask base address with mask */
	if (t)
		*t = nd;
	/* find next separator */
	if (p)
		p = strpbrk(p, ",{");
	if (p && *p == '{') {
		/*
		 * We have a set of addresses. They are stored as follows:
		 *   arg1	is the set size (powers of 2, 2..256)
		 *   addr	is the base address IN HOST FORMAT
		 *   mask..	is an array of arg1 bits (rounded up to
		 *		the next multiple of 32) with bits set
		 *		for each host in the map.
		 */
		uint32_t *map = (uint32_t *)&cmd->mask;
		int low, high;
		int i = contigmask((uint8_t *)&(d[1]), 32);

		if (len > 0)
			errx(EX_DATAERR, "address set cannot be in a list");
		if (i < 24 || i > 31)
			errx(EX_DATAERR, "invalid set with mask %d\n", i);
		cmd->o.arg1 = 1<<(32-i);	/* map length		*/
		d[0] = ntohl(d[0]);		/* base addr in host format */
		cmd->o.opcode = O_IP_DST_SET;	/* default */
		cmd->o.len |= F_INSN_SIZE(ipfw_insn_u32) + (cmd->o.arg1+31)/32;
		for (i = 0; i < (cmd->o.arg1+31)/32 ; i++)
			map[i] = 0;	/* clear map */

		av = p + 1;
		low = d[0] & 0xff;
		high = low + cmd->o.arg1 - 1;
		/*
		 * Here, i stores the previous value when we specify a range
		 * of addresses within a mask, e.g. 45-63. i = -1 means we
		 * have no previous value.
		 */
		i = -1;	/* previous value in a range */
		while (isdigit(*av)) {
			char *s;
			int a = strtol(av, &s, 0);

			if (s == av) { /* no parameter */
			    if (*av != '}')
				errx(EX_DATAERR, "set not closed\n");
			    if (i != -1)
				errx(EX_DATAERR, "incomplete range %d-", i);
			    break;
			}
			if (a < low || a > high)
			    errx(EX_DATAERR, "addr %d out of range [%d-%d]\n",
				a, low, high);
			a -= low;
			if (i == -1)	/* no previous in range */
			    i = a;
			else {		/* check that range is valid */
			    if (i > a)
				errx(EX_DATAERR, "invalid range %d-%d",
					i+low, a+low);
			    if (*s == '-')
				errx(EX_DATAERR, "double '-' in range");
			}
			for (; i <= a; i++)
			    map[i/32] |= 1<<(i & 31);
			i = -1;
			if (*s == '-')
			    i = a;
			else if (*s == '}')
			    break;
			av = s+1;
		}
		return;
	}
	av = p;
	if (av)			/* then *av must be a ',' */
		av++;

	/* Check this entry */
	if (d[1] == 0) { /* "any", specified as x.x.x.x/0 */
		/*
		 * 'any' turns the entire list into a NOP.
		 * 'not any' never matches, so it is removed from the
		 * list unless it is the only item, in which case we
		 * report an error.
		 */
		if (cmd->o.len & F_NOT) {	/* "not any" never matches */
			if (av == NULL && len == 0) /* only this entry */
				errx(EX_DATAERR, "not any never matches");
		}
		/* else do nothing and skip this entry */
		return;
	}
	/* A single IP can be stored in an optimized format */
	if (d[1] == ~0 && av == NULL && len == 0) {
		cmd->o.len |= F_INSN_SIZE(ipfw_insn_u32);
		return;
	}
	len += 2;	/* two words... */
	d += 2;
    } /* end while */
    if (len + 1 > F_LEN_MASK)
	errx(EX_DATAERR, "address list too long");
    cmd->o.len |= len+1;
}


/* Try to find ipv6 address by hostname */
static int
lookup_host6 (char *host, struct in6_addr *ip6addr)
{
	struct hostent *he;

	if (!inet_pton(AF_INET6, host, ip6addr)) {
		if ((he = gethostbyname2(host, AF_INET6)) == NULL)
			return(-1);
		memcpy(ip6addr, he->h_addr_list[0], sizeof( struct in6_addr));
	}
	return(0);
}


/* n2mask sets n bits of the mask */
void
n2mask(struct in6_addr *mask, int n)
{
	static int	minimask[9] =
	    { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };
	u_char		*p;

	memset(mask, 0, sizeof(struct in6_addr));
	p = (u_char *) mask;
	for (; n > 0; p++, n -= 8) {
		if (n >= 8)
			*p = 0xff;
		else
			*p = minimask[n];
	}
	return;
}
 

/*
 * fill the addr and mask fields in the instruction as appropriate from av.
 * Update length as appropriate.
 * The following formats are allowed:
 *     any     matches any IP6. Actually returns an empty instruction.
 *     me      returns O_IP6_*_ME
 *
 *     03f1::234:123:0342                single IP6 addres
 *     03f1::234:123:0342/24            address/mask
 *     03f1::234:123:0342/24,03f1::234:123:0343/               List of address
 *
 * Set of address (as in ipv6) not supported because ipv6 address
 * are typically random past the initial prefix.
 * Return 1 on success, 0 on failure.
 */
static int
fill_ip6(ipfw_insn_ip6 *cmd, char *av)
{
	int len = 0;
	struct in6_addr *d = &(cmd->addr6);
	/*
	 * Needed for multiple address.
	 * Note d[1] points to struct in6_add r mask6 of cmd
	 */

       cmd->o.len &= ~F_LEN_MASK;	/* zero len */

       if (strcmp(av, "any") == 0)
	       return (1);


       if (strcmp(av, "me") == 0) {	/* Set the data for "me" opt*/
	       cmd->o.len |= F_INSN_SIZE(ipfw_insn);
	       return (1);
       }

       if (strcmp(av, "me6") == 0) {	/* Set the data for "me" opt*/
	       cmd->o.len |= F_INSN_SIZE(ipfw_insn);
	       return (1);
       }

       av = strdup(av);
       while (av) {
		/*
		 * After the address we can have '/' indicating a mask,
		 * or ',' indicating another address follows.
		 */

		char *p;
		int masklen;
		char md = '\0';

		if ((p = strpbrk(av, "/,")) ) {
			md = *p;	/* save the separator */
			*p = '\0';	/* terminate address string */
			p++;		/* and skip past it */
		}
		/* now p points to NULL, mask or next entry */

		/* lookup stores address in *d as a side effect */
		if (lookup_host6(av, d) != 0) {
			/* XXX: failed. Free memory and go */
			errx(EX_DATAERR, "bad address \"%s\"", av);
		}
		/* next, look at the mask, if any */
		masklen = (md == '/') ? atoi(p) : 128;
		if (masklen > 128 || masklen < 0)
			errx(EX_DATAERR, "bad width \"%s\''", p);
		else
			n2mask(&d[1], masklen);

		APPLY_MASK(d, &d[1])   /* mask base address with mask */

		/* find next separator */

		if (md == '/') {	/* find separator past the mask */
			p = strpbrk(p, ",");
			if (p != NULL)
				p++;
		}
		av = p;

		/* Check this entry */
		if (masklen == 0) {
			/*
			 * 'any' turns the entire list into a NOP.
			 * 'not any' never matches, so it is removed from the
			 * list unless it is the only item, in which case we
			 * report an error.
			 */
			if (cmd->o.len & F_NOT && av == NULL && len == 0)
				errx(EX_DATAERR, "not any never matches");
			continue;
		}

		/*
		 * A single IP can be stored alone
		 */
		if (masklen == 128 && av == NULL && len == 0) {
			len = F_INSN_SIZE(struct in6_addr);
			break;
		}

		/* Update length and pointer to arguments */
		len += F_INSN_SIZE(struct in6_addr)*2;
		d += 2;
	} /* end while */

	/*
	 * Total length of the command, remember that 1 is the size of
	 * the base command.
	 */
	if (len + 1 > F_LEN_MASK)
		errx(EX_DATAERR, "address list too long");
	cmd->o.len |= len+1;
	free(av);
	return (1);
}

/*
 * fills command for ipv6 flow-id filtering
 * note that the 20 bit flow number is stored in a array of u_int32_t
 * it's supported lists of flow-id, so in the o.arg1 we store how many
 * additional flow-id we want to filter, the basic is 1
 */
static void
fill_flow6( ipfw_insn_u32 *cmd, char *av )
{
	u_int32_t type;	 /* Current flow number */
	u_int16_t nflow = 0;    /* Current flow index */
	char *s = av;
	cmd->d[0] = 0;	  /* Initializing the base number*/

	while (s) {
		av = strsep( &s, ",") ;
		type = strtoul(av, &av, 0);
		if (*av != ',' && *av != '\0')
			errx(EX_DATAERR, "invalid ipv6 flow number %s", av);
		if (type > 0xfffff)
			errx(EX_DATAERR, "flow number out of range %s", av);
		cmd->d[nflow] |= type;
		nflow++;
	}
	if( nflow > 0 ) {
		cmd->o.opcode = O_FLOW6ID;
		cmd->o.len |= F_INSN_SIZE(ipfw_insn_u32) + nflow;
		cmd->o.arg1 = nflow;
	}
	else {
		errx(EX_DATAERR, "invalid ipv6 flow number %s", av);
	}
}

static ipfw_insn *
add_srcip6(ipfw_insn *cmd, char *av)
{

	fill_ip6((ipfw_insn_ip6 *)cmd, av);
	if (F_LEN(cmd) == 0) {				/* any */
	} else if (F_LEN(cmd) == F_INSN_SIZE(ipfw_insn)) {	/* "me" */
		cmd->opcode = O_IP6_SRC_ME;
	} else if (F_LEN(cmd) ==
	    (F_INSN_SIZE(struct in6_addr) + F_INSN_SIZE(ipfw_insn))) {
		/* single IP, no mask*/
		cmd->opcode = O_IP6_SRC;
	} else {					/* addr/mask opt */
		cmd->opcode = O_IP6_SRC_MASK;
	}
	return cmd;
}

static ipfw_insn *
add_dstip6(ipfw_insn *cmd, char *av)
{

	fill_ip6((ipfw_insn_ip6 *)cmd, av);
	if (F_LEN(cmd) == 0) {				/* any */
	} else if (F_LEN(cmd) == F_INSN_SIZE(ipfw_insn)) {	/* "me" */
		cmd->opcode = O_IP6_DST_ME;
	} else if (F_LEN(cmd) ==
	    (F_INSN_SIZE(struct in6_addr) + F_INSN_SIZE(ipfw_insn))) {
		/* single IP, no mask*/
		cmd->opcode = O_IP6_DST;
	} else {					/* addr/mask opt */
		cmd->opcode = O_IP6_DST_MASK;
	}
	return cmd;
}


/*
 * helper function to process a set of flags and set bits in the
 * appropriate masks.
 */
static void
fill_flags(ipfw_insn *cmd, enum ipfw_opcodes opcode,
	struct _s_x *flags, char *p)
{
	uint8_t set=0, clear=0;

	while (p && *p) {
		char *q;	/* points to the separator */
		int val;
		uint8_t *which;	/* mask we are working on */

		if (*p == '!') {
			p++;
			which = &clear;
		} else
			which = &set;
		q = strchr(p, ',');
		if (q)
			*q++ = '\0';
		val = match_token(flags, p);
		if (val <= 0)
			errx(EX_DATAERR, "invalid flag %s", p);
		*which |= (uint8_t)val;
		p = q;
	}
        cmd->opcode = opcode;
        cmd->len =  (cmd->len & (F_NOT | F_OR)) | 1;
        cmd->arg1 = (set & 0xff) | ( (clear & 0xff) << 8);
}


void
ipfw_delete(int ac, char *av[])
{
	uint32_t rulenum;
	int i;
	int exitval = EX_OK;
	int do_set = 0;


	av++; ac--;
	NEED1("missing rule specification");
	if (ac > 0 && _substrcmp(*av, "set") == 0) {
		/* Do not allow using the following syntax:
		 *	ipfw set N delete set M
		 */
		if (co.use_set)
			errx(EX_DATAERR, "invalid syntax");
		do_set = 1;	/* delete set */
		ac--; av++;
	}

	/* Rule number */
	while (ac && isdigit(**av)) {
		i = atoi(*av); av++; ac--;
		if (co.do_nat) {
			exitval = do_cmd(IP_FW_NAT_DEL, &i, sizeof i);
			if (exitval) {
				exitval = EX_UNAVAILABLE;
				warn("rule %u not available", i);
			}
 		} else if (co.do_pipe) {
			exitval = ipfw_delete_pipe(co.do_pipe, i);
		} else {
			if (co.use_set)
				rulenum = (i & 0xffff) | (5 << 24) |
				    ((co.use_set - 1) << 16);
			else
			rulenum =  (i & 0xffff) | (do_set << 24);
			i = do_cmd(IP_FW_DEL, &rulenum, sizeof rulenum);
			if (i) {
				exitval = EX_UNAVAILABLE;
				warn("rule %u: setsockopt(IP_FW_DEL)",
				    rulenum);
			}
		}
	}
	if (exitval != EX_OK)
		exit(exitval);
}


/*
 * fill the interface structure. We do not check the name as we can
 * create interfaces dynamically, so checking them at insert time
 * makes relatively little sense.
 * Interface names containing '*', '?', or '[' are assumed to be shell 
 * patterns which match interfaces.
 */
static void
fill_iface(ipfw_insn_if *cmd, char *arg)
{
	cmd->name[0] = '\0';
	cmd->o.len |= F_INSN_SIZE(ipfw_insn_if);

	/* Parse the interface or address */
	if (strcmp(arg, "any") == 0)
		cmd->o.len = 0;		/* effectively ignore this command */
	else if (!isdigit(*arg)) {
		strlcpy(cmd->name, arg, sizeof(cmd->name));
		cmd->p.glob = strpbrk(arg, "*?[") != NULL ? 1 : 0;
	} else if (!inet_aton(arg, &cmd->p.ip))
		errx(EX_DATAERR, "bad ip address ``%s''", arg);
}

/* 
 * Search for interface with name "ifn", and fill n accordingly:
 *
 * n->ip        ip address of interface "ifn"
 * n->if_name   copy of interface name "ifn"
 */
static void
set_addr_dynamic(const char *ifn, struct cfg_nat *n)
{
	size_t needed;
	int mib[6];
	char *buf, *lim, *next;
	struct if_msghdr *ifm;
	struct ifa_msghdr *ifam;
	struct sockaddr_dl *sdl;
	struct sockaddr_in *sin;
	int ifIndex, ifMTU;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;	
	mib[4] = NET_RT_IFLIST;
	mib[5] = 0;		
/*
 * Get interface data.
 */
	if (sysctl(mib, 6, NULL, &needed, NULL, 0) == -1)
		err(1, "iflist-sysctl-estimate");
	buf = safe_calloc(1, needed);
	if (sysctl(mib, 6, buf, &needed, NULL, 0) == -1)
		err(1, "iflist-sysctl-get");
	lim = buf + needed;
/*
 * Loop through interfaces until one with
 * given name is found. This is done to
 * find correct interface index for routing
 * message processing.
 */
	ifIndex	= 0;
	next = buf;
	while (next < lim) {
		ifm = (struct if_msghdr *)next;
		next += ifm->ifm_msglen;
		if (ifm->ifm_version != RTM_VERSION) {
			if (co.verbose)
				warnx("routing message version %d "
				    "not understood", ifm->ifm_version);
			continue;
		}
		if (ifm->ifm_type == RTM_IFINFO) {
			sdl = (struct sockaddr_dl *)(ifm + 1);
			if (strlen(ifn) == sdl->sdl_nlen &&
			    strncmp(ifn, sdl->sdl_data, sdl->sdl_nlen) == 0) {
				ifIndex = ifm->ifm_index;
				ifMTU = ifm->ifm_data.ifi_mtu;
				break;
			}
		}
	}
	if (!ifIndex)
		errx(1, "unknown interface name %s", ifn);
/*
 * Get interface address.
 */
	sin = NULL;
	while (next < lim) {
		ifam = (struct ifa_msghdr *)next;
		next += ifam->ifam_msglen;
		if (ifam->ifam_version != RTM_VERSION) {
			if (co.verbose)
				warnx("routing message version %d "
				    "not understood", ifam->ifam_version);
			continue;
		}
		if (ifam->ifam_type != RTM_NEWADDR)
			break;
		if (ifam->ifam_addrs & RTA_IFA) {
			int i;
			char *cp = (char *)(ifam + 1);

			for (i = 1; i < RTA_IFA; i <<= 1) {
				if (ifam->ifam_addrs & i)
					cp += SA_SIZE((struct sockaddr *)cp);
			}
			if (((struct sockaddr *)cp)->sa_family == AF_INET) {
				sin = (struct sockaddr_in *)cp;
				break;
			}
		}
	}
	if (sin == NULL)
		errx(1, "%s: cannot get interface address", ifn);

	n->ip = sin->sin_addr;
	strncpy(n->if_name, ifn, IF_NAMESIZE);

	free(buf);
}

/* 
 * XXX - The following functions, macros and definitions come from natd.c:
 * it would be better to move them outside natd.c, in a file 
 * (redirect_support.[ch]?) shared by ipfw and natd, but for now i can live 
 * with it.
 */

/*
 * Definition of a port range, and macros to deal with values.
 * FORMAT:  HI 16-bits == first port in range, 0 == all ports.
 *          LO 16-bits == number of ports in range
 * NOTES:   - Port values are not stored in network byte order.
 */

#define port_range u_long

#define GETLOPORT(x)     ((x) >> 0x10)
#define GETNUMPORTS(x)   ((x) & 0x0000ffff)
#define GETHIPORT(x)     (GETLOPORT((x)) + GETNUMPORTS((x)))

/* Set y to be the low-port value in port_range variable x. */
#define SETLOPORT(x,y)   ((x) = ((x) & 0x0000ffff) | ((y) << 0x10))

/* Set y to be the number of ports in port_range variable x. */
#define SETNUMPORTS(x,y) ((x) = ((x) & 0xffff0000) | (y))

static void 
StrToAddr (const char* str, struct in_addr* addr)
{
	struct hostent* hp;

	if (inet_aton (str, addr))
		return;

	hp = gethostbyname (str);
	if (!hp)
		errx (1, "unknown host %s", str);

	memcpy (addr, hp->h_addr, sizeof (struct in_addr));
}

static int 
StrToPortRange (const char* str, const char* proto, port_range *portRange)
{
	char*           sep;
	struct servent*	sp;
	char*		end;
	u_short         loPort;
	u_short         hiPort;
	
	/* First see if this is a service, return corresponding port if so. */
	sp = getservbyname (str,proto);
	if (sp) {
	        SETLOPORT(*portRange, ntohs(sp->s_port));
		SETNUMPORTS(*portRange, 1);
		return 0;
	}
	        
	/* Not a service, see if it's a single port or port range. */
	sep = strchr (str, '-');
	if (sep == NULL) {
	        SETLOPORT(*portRange, strtol(str, &end, 10));
		if (end != str) {
		        /* Single port. */
		        SETNUMPORTS(*portRange, 1);
			return 0;
		}

		/* Error in port range field. */
		errx (EX_DATAERR, "%s/%s: unknown service", str, proto);
	}

	/* Port range, get the values and sanity check. */
	sscanf (str, "%hu-%hu", &loPort, &hiPort);
	SETLOPORT(*portRange, loPort);
	SETNUMPORTS(*portRange, 0);	/* Error by default */
	if (loPort <= hiPort)
	        SETNUMPORTS(*portRange, hiPort - loPort + 1);

	if (GETNUMPORTS(*portRange) == 0)
	        errx (EX_DATAERR, "invalid port range %s", str);

	return 0;
}

static int 
StrToProto (const char* str)
{
	if (!strcmp (str, "tcp"))
		return IPPROTO_TCP;

	if (!strcmp (str, "udp"))
		return IPPROTO_UDP;

	errx (EX_DATAERR, "unknown protocol %s. Expected tcp or udp", str);
}

static int 
StrToAddrAndPortRange (const char* str, struct in_addr* addr, char* proto, 
		       port_range *portRange)
{
	char*	ptr;

	ptr = strchr (str, ':');
	if (!ptr)
		errx (EX_DATAERR, "%s is missing port number", str);

	*ptr = '\0';
	++ptr;

	StrToAddr (str, addr);
	return StrToPortRange (ptr, proto, portRange);
}

/* End of stuff taken from natd.c. */

#define INC_ARGCV() do {        \
	(*_av)++;               \
	(*_ac)--;               \
	av = *_av;              \
	ac = *_ac;              \
} while(0)

/* 
 * The next 3 functions add support for the addr, port and proto redirect and 
 * their logic is loosely based on SetupAddressRedirect(), SetupPortRedirect() 
 * and SetupProtoRedirect() from natd.c.
 *
 * Every setup_* function fills at least one redirect entry 
 * (struct cfg_redir) and zero or more server pool entry (struct cfg_spool) 
 * in buf.
 * 
 * The format of data in buf is:
 * 
 *
 *     cfg_nat    cfg_redir    cfg_spool    ......  cfg_spool 
 *
 *    -------------------------------------        ------------
 *   |          | .....X ... |          |         |           |  .....
 *    ------------------------------------- ...... ------------
 *                     ^          
 *                spool_cnt       n=0       ......   n=(X-1)
 *
 * len points to the amount of available space in buf
 * space counts the memory consumed by every function
 *
 * XXX - Every function get all the argv params so it 
 * has to check, in optional parameters, that the next
 * args is a valid option for the redir entry and not 
 * another token. Only redir_port and redir_proto are 
 * affected by this.
 */

static int
setup_redir_addr(char *spool_buf, int len,
		 int *_ac, char ***_av) 
{
	char **av, *sep; /* Token separator. */
	/* Temporary buffer used to hold server pool ip's. */
	char tmp_spool_buf[NAT_BUF_LEN]; 
	int ac, space, lsnat;
	struct cfg_redir *r;	
	struct cfg_spool *tmp;		

	av = *_av;
	ac = *_ac;
	space = 0;
	lsnat = 0;
	if (len >= SOF_REDIR) {
		r = (struct cfg_redir *)spool_buf;
		/* Skip cfg_redir at beginning of buf. */
		spool_buf = &spool_buf[SOF_REDIR];
		space = SOF_REDIR;
		len -= SOF_REDIR;
	} else 
		goto nospace; 
	r->mode = REDIR_ADDR;
	/* Extract local address. */
	if (ac == 0) 
		errx(EX_DATAERR, "redirect_addr: missing local address");
	sep = strchr(*av, ',');
	if (sep) {		/* LSNAT redirection syntax. */
		r->laddr.s_addr = INADDR_NONE;
		/* Preserve av, copy spool servers to tmp_spool_buf. */
		strncpy(tmp_spool_buf, *av, strlen(*av)+1);
		lsnat = 1;
	} else 
		StrToAddr(*av, &r->laddr);		
	INC_ARGCV();

	/* Extract public address. */
	if (ac == 0) 
		errx(EX_DATAERR, "redirect_addr: missing public address");
	StrToAddr(*av, &r->paddr);
	INC_ARGCV();

	/* Setup LSNAT server pool. */
	if (sep) {
		sep = strtok(tmp_spool_buf, ",");		
		while (sep != NULL) {
			tmp = (struct cfg_spool *)spool_buf;		
			if (len < SOF_SPOOL)
				goto nospace;
			len -= SOF_SPOOL;
			space += SOF_SPOOL;			
			StrToAddr(sep, &tmp->addr);
			tmp->port = ~0;
			r->spool_cnt++;
			/* Point to the next possible cfg_spool. */
			spool_buf = &spool_buf[SOF_SPOOL];
			sep = strtok(NULL, ",");
		}
	}
	return(space);
nospace:
	errx(EX_DATAERR, "redirect_addr: buf is too small\n");
}

static int
setup_redir_port(char *spool_buf, int len,
		 int *_ac, char ***_av) 
{
	char **av, *sep, *protoName;
	char tmp_spool_buf[NAT_BUF_LEN];
	int ac, space, lsnat;
	struct cfg_redir *r;
	struct cfg_spool *tmp;
	u_short numLocalPorts;
	port_range portRange;	

	av = *_av;
	ac = *_ac;
	space = 0;
	lsnat = 0;
	numLocalPorts = 0;	

	if (len >= SOF_REDIR) {
		r = (struct cfg_redir *)spool_buf;
		/* Skip cfg_redir at beginning of buf. */
		spool_buf = &spool_buf[SOF_REDIR];
		space = SOF_REDIR;
		len -= SOF_REDIR;
	} else 
		goto nospace; 
	r->mode = REDIR_PORT;
	/*
	 * Extract protocol.
	 */
	if (ac == 0)
		errx (EX_DATAERR, "redirect_port: missing protocol");
	r->proto = StrToProto(*av);
	protoName = *av;	
	INC_ARGCV();

	/*
	 * Extract local address.
	 */
	if (ac == 0)
		errx (EX_DATAERR, "redirect_port: missing local address");

	sep = strchr(*av, ',');
	/* LSNAT redirection syntax. */
	if (sep) {
		r->laddr.s_addr = INADDR_NONE;
		r->lport = ~0;
		numLocalPorts = 1;
		/* Preserve av, copy spool servers to tmp_spool_buf. */
		strncpy(tmp_spool_buf, *av, strlen(*av)+1);
		lsnat = 1;
	} else {
		if (StrToAddrAndPortRange (*av, &r->laddr, protoName, 
		    &portRange) != 0)
			errx(EX_DATAERR, "redirect_port:"
			    "invalid local port range");

		r->lport = GETLOPORT(portRange);
		numLocalPorts = GETNUMPORTS(portRange);
	}
	INC_ARGCV();	

	/*
	 * Extract public port and optionally address.
	 */
	if (ac == 0)
		errx (EX_DATAERR, "redirect_port: missing public port");

	sep = strchr (*av, ':');
	if (sep) {
	        if (StrToAddrAndPortRange (*av, &r->paddr, protoName, 
		    &portRange) != 0)
		        errx(EX_DATAERR, "redirect_port:" 
			    "invalid public port range");
	} else {
		r->paddr.s_addr = INADDR_ANY;
		if (StrToPortRange (*av, protoName, &portRange) != 0)
		        errx(EX_DATAERR, "redirect_port:"
			    "invalid public port range");
	}

	r->pport = GETLOPORT(portRange);
	r->pport_cnt = GETNUMPORTS(portRange);
	INC_ARGCV();

	/*
	 * Extract remote address and optionally port.
	 */	
	/* 
	 * NB: isalpha(**av) => we've to check that next parameter is really an
	 * option for this redirect entry, else stop here processing arg[cv].
	 */
	if (ac != 0 && !isalpha(**av)) { 
		sep = strchr (*av, ':');
		if (sep) {
		        if (StrToAddrAndPortRange (*av, &r->raddr, protoName, 
			    &portRange) != 0)
				errx(EX_DATAERR, "redirect_port:"
				    "invalid remote port range");
		} else {
		        SETLOPORT(portRange, 0);
			SETNUMPORTS(portRange, 1);
			StrToAddr (*av, &r->raddr);
		}
		INC_ARGCV();
	} else {
		SETLOPORT(portRange, 0);
		SETNUMPORTS(portRange, 1);
		r->raddr.s_addr = INADDR_ANY;
	}
	r->rport = GETLOPORT(portRange);
	r->rport_cnt = GETNUMPORTS(portRange);

	/* 
	 * Make sure port ranges match up, then add the redirect ports.
	 */
	if (numLocalPorts != r->pport_cnt)
	        errx(EX_DATAERR, "redirect_port:"
		    "port ranges must be equal in size");

	/* Remote port range is allowed to be '0' which means all ports. */
	if (r->rport_cnt != numLocalPorts && 
	    (r->rport_cnt != 1 || r->rport != 0))
	        errx(EX_DATAERR, "redirect_port: remote port must"
		    "be 0 or equal to local port range in size");

	/*
	 * Setup LSNAT server pool.
	 */
	if (lsnat) {
		sep = strtok(tmp_spool_buf, ",");
		while (sep != NULL) {
			tmp = (struct cfg_spool *)spool_buf;
			if (len < SOF_SPOOL)
				goto nospace;
			len -= SOF_SPOOL;
			space += SOF_SPOOL;
			if (StrToAddrAndPortRange(sep, &tmp->addr, protoName, 
			    &portRange) != 0)
				errx(EX_DATAERR, "redirect_port:"
				    "invalid local port range");
			if (GETNUMPORTS(portRange) != 1)
				errx(EX_DATAERR, "redirect_port: local port"
				    "must be single in this context");
			tmp->port = GETLOPORT(portRange);
			r->spool_cnt++;	
			/* Point to the next possible cfg_spool. */
			spool_buf = &spool_buf[SOF_SPOOL];
			sep = strtok(NULL, ",");
		}
	}
	return (space);
nospace:
	errx(EX_DATAERR, "redirect_port: buf is too small\n");
}

static int
setup_redir_proto(char *spool_buf, int len,
		 int *_ac, char ***_av) 
{
	char **av;
	int ac, space;
	struct protoent *protoent;
	struct cfg_redir *r;
	
	av = *_av;
	ac = *_ac;
	if (len >= SOF_REDIR) {
		r = (struct cfg_redir *)spool_buf;
		/* Skip cfg_redir at beginning of buf. */
		spool_buf = &spool_buf[SOF_REDIR];
		space = SOF_REDIR;
		len -= SOF_REDIR;
	} else 
		goto nospace;
	r->mode = REDIR_PROTO;
	/*
	 * Extract protocol.
	 */	
	if (ac == 0)
		errx(EX_DATAERR, "redirect_proto: missing protocol");

	protoent = getprotobyname(*av);
	if (protoent == NULL)
		errx(EX_DATAERR, "redirect_proto: unknown protocol %s", *av);
	else
		r->proto = protoent->p_proto;

	INC_ARGCV();
	
	/*
	 * Extract local address.
	 */
	if (ac == 0)
		errx(EX_DATAERR, "redirect_proto: missing local address");
	else
		StrToAddr(*av, &r->laddr);

	INC_ARGCV();
	
	/*
	 * Extract optional public address.
	 */
	if (ac == 0) {
		r->paddr.s_addr = INADDR_ANY;		
		r->raddr.s_addr = INADDR_ANY;	
	} else {
		/* see above in setup_redir_port() */
		if (!isalpha(**av)) {
			StrToAddr(*av, &r->paddr);			
			INC_ARGCV();
		
			/*
			 * Extract optional remote address.
			 */	
			/* see above in setup_redir_port() */
			if (ac!=0 && !isalpha(**av)) {
				StrToAddr(*av, &r->raddr);
				INC_ARGCV();
			}
		}		
	}
	return (space);
nospace:
	errx(EX_DATAERR, "redirect_proto: buf is too small\n");
}

static void
print_nat_config(unsigned char *buf)
{
	struct cfg_nat *n;
	int i, cnt, flag, off;
	struct cfg_redir *t;
	struct cfg_spool *s;
	struct protoent *p;

	n = (struct cfg_nat *)buf;
	flag = 1;
	off  = sizeof(*n);
	printf("ipfw nat %u config", n->id);
	if (strlen(n->if_name) != 0)
		printf(" if %s", n->if_name);
	else if (n->ip.s_addr != 0)
		printf(" ip %s", inet_ntoa(n->ip));
	while (n->mode != 0) {
		if (n->mode & PKT_ALIAS_LOG) {
			printf(" log");
			n->mode &= ~PKT_ALIAS_LOG;
		} else if (n->mode & PKT_ALIAS_DENY_INCOMING) {
			printf(" deny_in");
			n->mode &= ~PKT_ALIAS_DENY_INCOMING;
		} else if (n->mode & PKT_ALIAS_SAME_PORTS) {
			printf(" same_ports");
			n->mode &= ~PKT_ALIAS_SAME_PORTS;
		} else if (n->mode & PKT_ALIAS_UNREGISTERED_ONLY) {
			printf(" unreg_only");
			n->mode &= ~PKT_ALIAS_UNREGISTERED_ONLY;
		} else if (n->mode & PKT_ALIAS_RESET_ON_ADDR_CHANGE) {
			printf(" reset");
			n->mode &= ~PKT_ALIAS_RESET_ON_ADDR_CHANGE;
		} else if (n->mode & PKT_ALIAS_REVERSE) {
			printf(" reverse");
			n->mode &= ~PKT_ALIAS_REVERSE;
		} else if (n->mode & PKT_ALIAS_PROXY_ONLY) {
			printf(" proxy_only");
			n->mode &= ~PKT_ALIAS_PROXY_ONLY;
		}
	}
	/* Print all the redirect's data configuration. */
	for (cnt = 0; cnt < n->redir_cnt; cnt++) {
		t = (struct cfg_redir *)&buf[off];
		off += SOF_REDIR;
		switch (t->mode) {
		case REDIR_ADDR:
			printf(" redirect_addr");
			if (t->spool_cnt == 0)
				printf(" %s", inet_ntoa(t->laddr));
			else
				for (i = 0; i < t->spool_cnt; i++) {
					s = (struct cfg_spool *)&buf[off];
					if (i)
						printf(",");
					else 
						printf(" ");
					printf("%s", inet_ntoa(s->addr));
					off += SOF_SPOOL;
				}
			printf(" %s", inet_ntoa(t->paddr));
			break;
		case REDIR_PORT:
			p = getprotobynumber(t->proto);
			printf(" redirect_port %s ", p->p_name);
			if (!t->spool_cnt) {
				printf("%s:%u", inet_ntoa(t->laddr), t->lport);
				if (t->pport_cnt > 1)
					printf("-%u", t->lport + 
					    t->pport_cnt - 1);
			} else
				for (i=0; i < t->spool_cnt; i++) {
					s = (struct cfg_spool *)&buf[off];
					if (i)
						printf(",");
					printf("%s:%u", inet_ntoa(s->addr), 
					    s->port);
					off += SOF_SPOOL;
				}

			printf(" ");
			if (t->paddr.s_addr)
				printf("%s:", inet_ntoa(t->paddr)); 
			printf("%u", t->pport);
			if (!t->spool_cnt && t->pport_cnt > 1)
				printf("-%u", t->pport + t->pport_cnt - 1);

			if (t->raddr.s_addr) {
				printf(" %s", inet_ntoa(t->raddr));
				if (t->rport) {
					printf(":%u", t->rport);
					if (!t->spool_cnt && t->rport_cnt > 1)
						printf("-%u", t->rport + 
						    t->rport_cnt - 1);
				}
			}
			break;
		case REDIR_PROTO:
			p = getprotobynumber(t->proto);
			printf(" redirect_proto %s %s", p->p_name, 
			    inet_ntoa(t->laddr));
			if (t->paddr.s_addr != 0) {
				printf(" %s", inet_ntoa(t->paddr));
				if (t->raddr.s_addr)
					printf(" %s", inet_ntoa(t->raddr));
			}
			break;
		default:
			errx(EX_DATAERR, "unknown redir mode");
			break;
		}
	}
	printf("\n");
}

void
ipfw_config_nat(int ac, char **av)
{
	struct cfg_nat *n;              /* Nat instance configuration. */
	int i, len, off, tok;
	char *id, buf[NAT_BUF_LEN]; 	/* Buffer for serialized data. */
	
	len = NAT_BUF_LEN;
	/* Offset in buf: save space for n at the beginning. */
	off = sizeof(*n);
	memset(buf, 0, sizeof(buf));
	n = (struct cfg_nat *)buf;

	av++; ac--;
	/* Nat id. */
	if (ac && isdigit(**av)) {
		id = *av;
		i = atoi(*av); 
		ac--; av++;		
		n->id = i;
	} else 
		errx(EX_DATAERR, "missing nat id");
	if (ac == 0) 
		errx(EX_DATAERR, "missing option");

	while (ac > 0) {
		tok = match_token(nat_params, *av);
		ac--; av++;
		switch (tok) {
		case TOK_IP:
			if (ac == 0) 
				errx(EX_DATAERR, "missing option");
			if (!inet_aton(av[0], &(n->ip)))
				errx(EX_DATAERR, "bad ip address ``%s''", 
				    av[0]);
			ac--; av++;
			break;	    
		case TOK_IF:
			if (ac == 0) 
				errx(EX_DATAERR, "missing option");
			set_addr_dynamic(av[0], n);
			ac--; av++;
			break;
		case TOK_ALOG:
			n->mode |= PKT_ALIAS_LOG;
			break;
		case TOK_DENY_INC:
			n->mode |= PKT_ALIAS_DENY_INCOMING;
			break;
		case TOK_SAME_PORTS:
			n->mode |= PKT_ALIAS_SAME_PORTS;
			break;
		case TOK_UNREG_ONLY:
			n->mode |= PKT_ALIAS_UNREGISTERED_ONLY;
			break;
		case TOK_RESET_ADDR:
			n->mode |= PKT_ALIAS_RESET_ON_ADDR_CHANGE;
			break;
		case TOK_ALIAS_REV:
			n->mode |= PKT_ALIAS_REVERSE;
			break;
		case TOK_PROXY_ONLY:
			n->mode |= PKT_ALIAS_PROXY_ONLY;
			break;
			/* 
			 * All the setup_redir_* functions work directly in the final 
			 * buffer, see above for details.
			 */
		case TOK_REDIR_ADDR:
		case TOK_REDIR_PORT:
		case TOK_REDIR_PROTO:
			switch (tok) {
			case TOK_REDIR_ADDR:
				i = setup_redir_addr(&buf[off], len, &ac, &av);
				break;			  
			case TOK_REDIR_PORT:
				i = setup_redir_port(&buf[off], len, &ac, &av);
				break;			  
			case TOK_REDIR_PROTO:
				i = setup_redir_proto(&buf[off], len, &ac, &av);
				break;
			}
			n->redir_cnt++;
			off += i;
			len -= i;
			break;
		default:
			errx(EX_DATAERR, "unrecognised option ``%s''", av[-1]);
		}
	}

	i = do_cmd(IP_FW_NAT_CFG, buf, off);
	if (i)
		err(1, "setsockopt(%s)", "IP_FW_NAT_CFG");

	if (!co.do_quiet) {
		/* After every modification, we show the resultant rule. */
		int _ac = 3;
		char *_av[] = {"show", "config", id};
		ipfw_show_nat(_ac, _av);
	}
}

static void
get_mac_addr_mask(const char *p, uint8_t *addr, uint8_t *mask)
{
	int i, l;
	char *ap, *ptr, *optr;
	struct ether_addr *mac;
	const char *macset = "0123456789abcdefABCDEF:";

	if (strcmp(p, "any") == 0) {
		for (i = 0; i < ETHER_ADDR_LEN; i++)
			addr[i] = mask[i] = 0;
		return;
	}

	optr = ptr = strdup(p);
	if ((ap = strsep(&ptr, "&/")) != NULL && *ap != 0) {
		l = strlen(ap);
		if (strspn(ap, macset) != l || (mac = ether_aton(ap)) == NULL)
			errx(EX_DATAERR, "Incorrect MAC address");
		bcopy(mac, addr, ETHER_ADDR_LEN);
	} else
		errx(EX_DATAERR, "Incorrect MAC address");

	if (ptr != NULL) { /* we have mask? */
		if (p[ptr - optr - 1] == '/') { /* mask len */
			l = strtol(ptr, &ap, 10);
			if (*ap != 0 || l > ETHER_ADDR_LEN * 8 || l < 0)
				errx(EX_DATAERR, "Incorrect mask length");
			for (i = 0; l > 0 && i < ETHER_ADDR_LEN; l -= 8, i++)
				mask[i] = (l >= 8) ? 0xff: (~0) << (8 - l);
		} else { /* mask */
			l = strlen(ptr);
			if (strspn(ptr, macset) != l ||
			    (mac = ether_aton(ptr)) == NULL)
				errx(EX_DATAERR, "Incorrect mask");
			bcopy(mac, mask, ETHER_ADDR_LEN);
		}
	} else { /* default mask: ff:ff:ff:ff:ff:ff */
		for (i = 0; i < ETHER_ADDR_LEN; i++)
			mask[i] = 0xff;
	}
	for (i = 0; i < ETHER_ADDR_LEN; i++)
		addr[i] &= mask[i];

	free(optr);
}

/*
 * helper function, updates the pointer to cmd with the length
 * of the current command, and also cleans up the first word of
 * the new command in case it has been clobbered before.
 */
static ipfw_insn *
next_cmd(ipfw_insn *cmd)
{
	cmd += F_LEN(cmd);
	bzero(cmd, sizeof(*cmd));
	return cmd;
}

/*
 * Takes arguments and copies them into a comment
 */
static void
fill_comment(ipfw_insn *cmd, int ac, char **av)
{
	int i, l;
	char *p = (char *)(cmd + 1);

	cmd->opcode = O_NOP;
	cmd->len =  (cmd->len & (F_NOT | F_OR));

	/* Compute length of comment string. */
	for (i = 0, l = 0; i < ac; i++)
		l += strlen(av[i]) + 1;
	if (l == 0)
		return;
	if (l > 84)
		errx(EX_DATAERR,
		    "comment too long (max 80 chars)");
	l = 1 + (l+3)/4;
	cmd->len =  (cmd->len & (F_NOT | F_OR)) | l;
	for (i = 0; i < ac; i++) {
		strcpy(p, av[i]);
		p += strlen(av[i]);
		*p++ = ' ';
	}
	*(--p) = '\0';
}

/*
 * A function to fill simple commands of size 1.
 * Existing flags are preserved.
 */
static void
fill_cmd(ipfw_insn *cmd, enum ipfw_opcodes opcode, int flags, uint16_t arg)
{
	cmd->opcode = opcode;
	cmd->len =  ((cmd->len | flags) & (F_NOT | F_OR)) | 1;
	cmd->arg1 = arg;
}

/*
 * Fetch and add the MAC address and type, with masks. This generates one or
 * two microinstructions, and returns the pointer to the last one.
 */
static ipfw_insn *
add_mac(ipfw_insn *cmd, int ac, char *av[])
{
	ipfw_insn_mac *mac;

	if (ac < 2)
		errx(EX_DATAERR, "MAC dst src");

	cmd->opcode = O_MACADDR2;
	cmd->len = (cmd->len & (F_NOT | F_OR)) | F_INSN_SIZE(ipfw_insn_mac);

	mac = (ipfw_insn_mac *)cmd;
	get_mac_addr_mask(av[0], mac->addr, mac->mask);	/* dst */
	get_mac_addr_mask(av[1], &(mac->addr[ETHER_ADDR_LEN]),
	    &(mac->mask[ETHER_ADDR_LEN])); /* src */
	return cmd;
}

static ipfw_insn *
add_mactype(ipfw_insn *cmd, int ac, char *av)
{
	if (ac < 1)
		errx(EX_DATAERR, "missing MAC type");
	if (strcmp(av, "any") != 0) { /* we have a non-null type */
		fill_newports((ipfw_insn_u16 *)cmd, av, IPPROTO_ETHERTYPE);
		cmd->opcode = O_MAC_TYPE;
		return cmd;
	} else
		return NULL;
}

static ipfw_insn *
add_proto0(ipfw_insn *cmd, char *av, u_char *protop)
{
	struct protoent *pe;
	char *ep;
	int proto;

	proto = strtol(av, &ep, 10);
	if (*ep != '\0' || proto <= 0) {
		if ((pe = getprotobyname(av)) == NULL)
			return NULL;
		proto = pe->p_proto;
	}

	fill_cmd(cmd, O_PROTO, 0, proto);
	*protop = proto;
	return cmd;
}

static ipfw_insn *
add_proto(ipfw_insn *cmd, char *av, u_char *protop)
{
	u_char proto = IPPROTO_IP;

	if (_substrcmp(av, "all") == 0 || strcmp(av, "ip") == 0)
		; /* do not set O_IP4 nor O_IP6 */
	else if (strcmp(av, "ip4") == 0)
		/* explicit "just IPv4" rule */
		fill_cmd(cmd, O_IP4, 0, 0);
	else if (strcmp(av, "ip6") == 0) {
		/* explicit "just IPv6" rule */
		proto = IPPROTO_IPV6;
		fill_cmd(cmd, O_IP6, 0, 0);
	} else
		return add_proto0(cmd, av, protop);

	*protop = proto;
	return cmd;
}

static ipfw_insn *
add_proto_compat(ipfw_insn *cmd, char *av, u_char *protop)
{
	u_char proto = IPPROTO_IP;

	if (_substrcmp(av, "all") == 0 || strcmp(av, "ip") == 0)
		; /* do not set O_IP4 nor O_IP6 */
	else if (strcmp(av, "ipv4") == 0 || strcmp(av, "ip4") == 0)
		/* explicit "just IPv4" rule */
		fill_cmd(cmd, O_IP4, 0, 0);
	else if (strcmp(av, "ipv6") == 0 || strcmp(av, "ip6") == 0) {
		/* explicit "just IPv6" rule */
		proto = IPPROTO_IPV6;
		fill_cmd(cmd, O_IP6, 0, 0);
	} else
		return add_proto0(cmd, av, protop);

	*protop = proto;
	return cmd;
}

static ipfw_insn *
add_srcip(ipfw_insn *cmd, char *av)
{
	fill_ip((ipfw_insn_ip *)cmd, av);
	if (cmd->opcode == O_IP_DST_SET)			/* set */
		cmd->opcode = O_IP_SRC_SET;
	else if (cmd->opcode == O_IP_DST_LOOKUP)		/* table */
		cmd->opcode = O_IP_SRC_LOOKUP;
	else if (F_LEN(cmd) == F_INSN_SIZE(ipfw_insn))		/* me */
		cmd->opcode = O_IP_SRC_ME;
	else if (F_LEN(cmd) == F_INSN_SIZE(ipfw_insn_u32))	/* one IP */
		cmd->opcode = O_IP_SRC;
	else							/* addr/mask */
		cmd->opcode = O_IP_SRC_MASK;
	return cmd;
}

static ipfw_insn *
add_dstip(ipfw_insn *cmd, char *av)
{
	fill_ip((ipfw_insn_ip *)cmd, av);
	if (cmd->opcode == O_IP_DST_SET)			/* set */
		;
	else if (cmd->opcode == O_IP_DST_LOOKUP)		/* table */
		;
	else if (F_LEN(cmd) == F_INSN_SIZE(ipfw_insn))		/* me */
		cmd->opcode = O_IP_DST_ME;
	else if (F_LEN(cmd) == F_INSN_SIZE(ipfw_insn_u32))	/* one IP */
		cmd->opcode = O_IP_DST;
	else							/* addr/mask */
		cmd->opcode = O_IP_DST_MASK;
	return cmd;
}

static ipfw_insn *
add_ports(ipfw_insn *cmd, char *av, u_char proto, int opcode)
{
	if (_substrcmp(av, "any") == 0) {
		return NULL;
	} else if (fill_newports((ipfw_insn_u16 *)cmd, av, proto)) {
		/* XXX todo: check that we have a protocol with ports */
		cmd->opcode = opcode;
		return cmd;
	}
	return NULL;
}

static ipfw_insn *
add_src(ipfw_insn *cmd, char *av, u_char proto)
{
	struct in6_addr a;
	char *host, *ch;
	ipfw_insn *ret = NULL;

	if ((host = strdup(av)) == NULL)
		return NULL;
	if ((ch = strrchr(host, '/')) != NULL)
		*ch = '\0';

	if (proto == IPPROTO_IPV6  || strcmp(av, "me6") == 0 ||
	    inet_pton(AF_INET6, host, &a))
		ret = add_srcip6(cmd, av);
	/* XXX: should check for IPv4, not !IPv6 */
	if (ret == NULL && (proto == IPPROTO_IP || strcmp(av, "me") == 0 ||
	    !inet_pton(AF_INET6, host, &a)))
		ret = add_srcip(cmd, av);
	if (ret == NULL && strcmp(av, "any") != 0)
		ret = cmd;

	free(host);
	return ret;
}

static ipfw_insn *
add_dst(ipfw_insn *cmd, char *av, u_char proto)
{
	struct in6_addr a;
	char *host, *ch;
	ipfw_insn *ret = NULL;

	if ((host = strdup(av)) == NULL)
		return NULL;
	if ((ch = strrchr(host, '/')) != NULL)
		*ch = '\0';

	if (proto == IPPROTO_IPV6  || strcmp(av, "me6") == 0 ||
	    inet_pton(AF_INET6, host, &a))
		ret = add_dstip6(cmd, av);
	/* XXX: should check for IPv4, not !IPv6 */
	if (ret == NULL && (proto == IPPROTO_IP || strcmp(av, "me") == 0 ||
	    !inet_pton(AF_INET6, host, &a)))
		ret = add_dstip(cmd, av);
	if (ret == NULL && strcmp(av, "any") != 0)
		ret = cmd;

	free(host);
	return ret;
}

/*
 * Parse arguments and assemble the microinstructions which make up a rule.
 * Rules are added into the 'rulebuf' and then copied in the correct order
 * into the actual rule.
 *
 * The syntax for a rule starts with the action, followed by
 * optional action parameters, and the various match patterns.
 * In the assembled microcode, the first opcode must be an O_PROBE_STATE
 * (generated if the rule includes a keep-state option), then the
 * various match patterns, log/altq actions, and the actual action.
 *
 */
void
ipfw_add(int ac, char *av[])
{
	/*
	 * rules are added into the 'rulebuf' and then copied in
	 * the correct order into the actual rule.
	 * Some things that need to go out of order (prob, action etc.)
	 * go into actbuf[].
	 */
	static uint32_t rulebuf[255], actbuf[255], cmdbuf[255];

	ipfw_insn *src, *dst, *cmd, *action, *prev=NULL;
	ipfw_insn *first_cmd;	/* first match pattern */

	struct ip_fw *rule;

	/*
	 * various flags used to record that we entered some fields.
	 */
	ipfw_insn *have_state = NULL;	/* check-state or keep-state */
	ipfw_insn *have_log = NULL, *have_altq = NULL, *have_tag = NULL;
	size_t len;

	int i;

	int open_par = 0;	/* open parenthesis ( */

	/* proto is here because it is used to fetch ports */
	u_char proto = IPPROTO_IP;	/* default protocol */

	double match_prob = 1; /* match probability, default is always match */

	bzero(actbuf, sizeof(actbuf));		/* actions go here */
	bzero(cmdbuf, sizeof(cmdbuf));
	bzero(rulebuf, sizeof(rulebuf));

	rule = (struct ip_fw *)rulebuf;
	cmd = (ipfw_insn *)cmdbuf;
	action = (ipfw_insn *)actbuf;

	av++; ac--;

	/* [rule N]	-- Rule number optional */
	if (ac && isdigit(**av)) {
		rule->rulenum = atoi(*av);
		av++;
		ac--;
	}

	/* [set N]	-- set number (0..RESVD_SET), optional */
	if (ac > 1 && _substrcmp(*av, "set") == 0) {
		int set = strtoul(av[1], NULL, 10);
		if (set < 0 || set > RESVD_SET)
			errx(EX_DATAERR, "illegal set %s", av[1]);
		rule->set = set;
		av += 2; ac -= 2;
	}

	/* [prob D]	-- match probability, optional */
	if (ac > 1 && _substrcmp(*av, "prob") == 0) {
		match_prob = strtod(av[1], NULL);

		if (match_prob <= 0 || match_prob > 1)
			errx(EX_DATAERR, "illegal match prob. %s", av[1]);
		av += 2; ac -= 2;
	}

	/* action	-- mandatory */
	NEED1("missing action");
	i = match_token(rule_actions, *av);
	ac--; av++;
	action->len = 1;	/* default */
	switch(i) {
	case TOK_CHECKSTATE:
		have_state = action;
		action->opcode = O_CHECK_STATE;
		break;

	case TOK_ACCEPT:
		action->opcode = O_ACCEPT;
		break;

	case TOK_DENY:
		action->opcode = O_DENY;
		action->arg1 = 0;
		break;

	case TOK_REJECT:
		action->opcode = O_REJECT;
		action->arg1 = ICMP_UNREACH_HOST;
		break;

	case TOK_RESET:
		action->opcode = O_REJECT;
		action->arg1 = ICMP_REJECT_RST;
		break;

	case TOK_RESET6:
		action->opcode = O_UNREACH6;
		action->arg1 = ICMP6_UNREACH_RST;
		break;

	case TOK_UNREACH:
		action->opcode = O_REJECT;
		NEED1("missing reject code");
		fill_reject_code(&action->arg1, *av);
		ac--; av++;
		break;

	case TOK_UNREACH6:
		action->opcode = O_UNREACH6;
		NEED1("missing unreach code");
		fill_unreach6_code(&action->arg1, *av);
		ac--; av++;
		break;

	case TOK_COUNT:
		action->opcode = O_COUNT;
		break;

	case TOK_NAT:
 		action->opcode = O_NAT;
 		action->len = F_INSN_SIZE(ipfw_insn_nat);
		goto chkarg;

	case TOK_QUEUE:
		action->opcode = O_QUEUE;
		goto chkarg;
	case TOK_PIPE:
		action->opcode = O_PIPE;
		goto chkarg;
	case TOK_SKIPTO:
		action->opcode = O_SKIPTO;
		goto chkarg;
	case TOK_NETGRAPH:
		action->opcode = O_NETGRAPH;
		goto chkarg;
	case TOK_NGTEE:
		action->opcode = O_NGTEE;
		goto chkarg;
	case TOK_DIVERT:
		action->opcode = O_DIVERT;
		goto chkarg;
	case TOK_TEE:
		action->opcode = O_TEE;
chkarg:	
		if (!ac)
			errx(EX_USAGE, "missing argument for %s", *(av - 1));
		if (isdigit(**av)) {
			action->arg1 = strtoul(*av, NULL, 10);
			if (action->arg1 <= 0 || action->arg1 >= IP_FW_TABLEARG)
				errx(EX_DATAERR, "illegal argument for %s",
				    *(av - 1));
		} else if (_substrcmp(*av, "tablearg") == 0) {
			action->arg1 = IP_FW_TABLEARG;
		} else if (i == TOK_DIVERT || i == TOK_TEE) {
			struct servent *s;
			setservent(1);
			s = getservbyname(av[0], "divert");
			if (s != NULL)
				action->arg1 = ntohs(s->s_port);
			else
				errx(EX_DATAERR, "illegal divert/tee port");
		} else
			errx(EX_DATAERR, "illegal argument for %s", *(av - 1));
		ac--; av++;
		break;

	case TOK_FORWARD: {
		ipfw_insn_sa *p = (ipfw_insn_sa *)action;
		char *s, *end;

		NEED1("missing forward address[:port]");

		action->opcode = O_FORWARD_IP;
		action->len = F_INSN_SIZE(ipfw_insn_sa);

		p->sa.sin_len = sizeof(struct sockaddr_in);
		p->sa.sin_family = AF_INET;
		p->sa.sin_port = 0;
		/*
		 * locate the address-port separator (':' or ',')
		 */
		s = strchr(*av, ':');
		if (s == NULL)
			s = strchr(*av, ',');
		if (s != NULL) {
			*(s++) = '\0';
			i = strtoport(s, &end, 0 /* base */, 0 /* proto */);
			if (s == end)
				errx(EX_DATAERR,
				    "illegal forwarding port ``%s''", s);
			p->sa.sin_port = (u_short)i;
		}
		if (_substrcmp(*av, "tablearg") == 0) 
			p->sa.sin_addr.s_addr = INADDR_ANY;
		else
			lookup_host(*av, &(p->sa.sin_addr));
		ac--; av++;
		break;
	    }
	case TOK_COMMENT:
		/* pretend it is a 'count' rule followed by the comment */
		action->opcode = O_COUNT;
		ac++; av--;	/* go back... */
		break;

	case TOK_SETFIB:
	    {
		int numfibs;
		size_t intsize = sizeof(int);

		action->opcode = O_SETFIB;
 		NEED1("missing fib number");
 	        action->arg1 = strtoul(*av, NULL, 10);
		if (sysctlbyname("net.fibs", &numfibs, &intsize, NULL, 0) == -1)
			errx(EX_DATAERR, "fibs not suported.\n");
		if (action->arg1 >= numfibs)  /* Temporary */
			errx(EX_DATAERR, "fib too large.\n");
 		ac--; av++;
 		break;
	    }
		
	default:
		errx(EX_DATAERR, "invalid action %s\n", av[-1]);
	}
	action = next_cmd(action);

	/*
	 * [altq queuename] -- altq tag, optional
	 * [log [logamount N]]	-- log, optional
	 *
	 * If they exist, it go first in the cmdbuf, but then it is
	 * skipped in the copy section to the end of the buffer.
	 */
	while (ac != 0 && (i = match_token(rule_action_params, *av)) != -1) {
		ac--; av++;
		switch (i) {
		case TOK_LOG:
		    {
			ipfw_insn_log *c = (ipfw_insn_log *)cmd;
			int l;

			if (have_log)
				errx(EX_DATAERR,
				    "log cannot be specified more than once");
			have_log = (ipfw_insn *)c;
			cmd->len = F_INSN_SIZE(ipfw_insn_log);
			cmd->opcode = O_LOG;
			if (ac && _substrcmp(*av, "logamount") == 0) {
				ac--; av++;
				NEED1("logamount requires argument");
				l = atoi(*av);
				if (l < 0)
					errx(EX_DATAERR,
					    "logamount must be positive");
				c->max_log = l;
				ac--; av++;
			} else {
				len = sizeof(c->max_log);
				if (sysctlbyname("net.inet.ip.fw.verbose_limit",
				    &c->max_log, &len, NULL, 0) == -1)
					errx(1, "sysctlbyname(\"%s\")",
					    "net.inet.ip.fw.verbose_limit");
			}
		    }
			break;

		case TOK_ALTQ:
		    {
			ipfw_insn_altq *a = (ipfw_insn_altq *)cmd;

			NEED1("missing altq queue name");
			if (have_altq)
				errx(EX_DATAERR,
				    "altq cannot be specified more than once");
			have_altq = (ipfw_insn *)a;
			cmd->len = F_INSN_SIZE(ipfw_insn_altq);
			cmd->opcode = O_ALTQ;
			fill_altq_qid(&a->qid, *av);
			ac--; av++;
		    }
			break;

		case TOK_TAG:
		case TOK_UNTAG: {
			uint16_t tag;

			if (have_tag)
				errx(EX_USAGE, "tag and untag cannot be "
				    "specified more than once");
			GET_UINT_ARG(tag, 1, IPFW_DEFAULT_RULE - 1, i,
			   rule_action_params);
			have_tag = cmd;
			fill_cmd(cmd, O_TAG, (i == TOK_TAG) ? 0: F_NOT, tag);
			ac--; av++;
			break;
		}

		default:
			abort();
		}
		cmd = next_cmd(cmd);
	}

	if (have_state)	/* must be a check-state, we are done */
		goto done;

#define OR_START(target)					\
	if (ac && (*av[0] == '(' || *av[0] == '{')) {		\
		if (open_par)					\
			errx(EX_USAGE, "nested \"(\" not allowed\n"); \
		prev = NULL;					\
		open_par = 1;					\
		if ( (av[0])[1] == '\0') {			\
			ac--; av++;				\
		} else						\
			(*av)++;				\
	}							\
	target:							\


#define	CLOSE_PAR						\
	if (open_par) {						\
		if (ac && (					\
		    strcmp(*av, ")") == 0 ||			\
		    strcmp(*av, "}") == 0)) {			\
			prev = NULL;				\
			open_par = 0;				\
			ac--; av++;				\
		} else						\
			errx(EX_USAGE, "missing \")\"\n");	\
	}

#define NOT_BLOCK						\
	if (ac && _substrcmp(*av, "not") == 0) {		\
		if (cmd->len & F_NOT)				\
			errx(EX_USAGE, "double \"not\" not allowed\n"); \
		cmd->len |= F_NOT;				\
		ac--; av++;					\
	}

#define OR_BLOCK(target)					\
	if (ac && _substrcmp(*av, "or") == 0) {		\
		if (prev == NULL || open_par == 0)		\
			errx(EX_DATAERR, "invalid OR block");	\
		prev->len |= F_OR;				\
		ac--; av++;					\
		goto target;					\
	}							\
	CLOSE_PAR;

	first_cmd = cmd;

#if 0
	/*
	 * MAC addresses, optional.
	 * If we have this, we skip the part "proto from src to dst"
	 * and jump straight to the option parsing.
	 */
	NOT_BLOCK;
	NEED1("missing protocol");
	if (_substrcmp(*av, "MAC") == 0 ||
	    _substrcmp(*av, "mac") == 0) {
		ac--; av++;	/* the "MAC" keyword */
		add_mac(cmd, ac, av); /* exits in case of errors */
		cmd = next_cmd(cmd);
		ac -= 2; av += 2;	/* dst-mac and src-mac */
		NOT_BLOCK;
		NEED1("missing mac type");
		if (add_mactype(cmd, ac, av[0]))
			cmd = next_cmd(cmd);
		ac--; av++;	/* any or mac-type */
		goto read_options;
	}
#endif

	/*
	 * protocol, mandatory
	 */
    OR_START(get_proto);
	NOT_BLOCK;
	NEED1("missing protocol");
	if (add_proto_compat(cmd, *av, &proto)) {
		av++; ac--;
		if (F_LEN(cmd) != 0) {
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	} else if (first_cmd != cmd) {
		errx(EX_DATAERR, "invalid protocol ``%s''", *av);
	} else
		goto read_options;
    OR_BLOCK(get_proto);

	/*
	 * "from", mandatory
	 */
	if (!ac || _substrcmp(*av, "from") != 0)
		errx(EX_USAGE, "missing ``from''");
	ac--; av++;

	/*
	 * source IP, mandatory
	 */
    OR_START(source_ip);
	NOT_BLOCK;	/* optional "not" */
	NEED1("missing source address");
	if (add_src(cmd, *av, proto)) {
		ac--; av++;
		if (F_LEN(cmd) != 0) {	/* ! any */
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	} else
		errx(EX_USAGE, "bad source address %s", *av);
    OR_BLOCK(source_ip);

	/*
	 * source ports, optional
	 */
	NOT_BLOCK;	/* optional "not" */
	if (ac) {
		if (_substrcmp(*av, "any") == 0 ||
		    add_ports(cmd, *av, proto, O_IP_SRCPORT)) {
			ac--; av++;
			if (F_LEN(cmd) != 0)
				cmd = next_cmd(cmd);
		}
	}

	/*
	 * "to", mandatory
	 */
	if (!ac || _substrcmp(*av, "to") != 0)
		errx(EX_USAGE, "missing ``to''");
	av++; ac--;

	/*
	 * destination, mandatory
	 */
    OR_START(dest_ip);
	NOT_BLOCK;	/* optional "not" */
	NEED1("missing dst address");
	if (add_dst(cmd, *av, proto)) {
		ac--; av++;
		if (F_LEN(cmd) != 0) {	/* ! any */
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	} else
		errx( EX_USAGE, "bad destination address %s", *av);
    OR_BLOCK(dest_ip);

	/*
	 * dest. ports, optional
	 */
	NOT_BLOCK;	/* optional "not" */
	if (ac) {
		if (_substrcmp(*av, "any") == 0 ||
		    add_ports(cmd, *av, proto, O_IP_DSTPORT)) {
			ac--; av++;
			if (F_LEN(cmd) != 0)
				cmd = next_cmd(cmd);
		}
	}

read_options:
	if (ac && first_cmd == cmd) {
		/*
		 * nothing specified so far, store in the rule to ease
		 * printout later.
		 */
		 rule->_pad = 1;
	}
	prev = NULL;
	while (ac) {
		char *s;
		ipfw_insn_u32 *cmd32;	/* alias for cmd */

		s = *av;
		cmd32 = (ipfw_insn_u32 *)cmd;

		if (*s == '!') {	/* alternate syntax for NOT */
			if (cmd->len & F_NOT)
				errx(EX_USAGE, "double \"not\" not allowed\n");
			cmd->len = F_NOT;
			s++;
		}
		i = match_token(rule_options, s);
		ac--; av++;
		switch(i) {
		case TOK_NOT:
			if (cmd->len & F_NOT)
				errx(EX_USAGE, "double \"not\" not allowed\n");
			cmd->len = F_NOT;
			break;

		case TOK_OR:
			if (open_par == 0 || prev == NULL)
				errx(EX_USAGE, "invalid \"or\" block\n");
			prev->len |= F_OR;
			break;

		case TOK_STARTBRACE:
			if (open_par)
				errx(EX_USAGE, "+nested \"(\" not allowed\n");
			open_par = 1;
			break;

		case TOK_ENDBRACE:
			if (!open_par)
				errx(EX_USAGE, "+missing \")\"\n");
			open_par = 0;
			prev = NULL;
        		break;

		case TOK_IN:
			fill_cmd(cmd, O_IN, 0, 0);
			break;

		case TOK_OUT:
			cmd->len ^= F_NOT; /* toggle F_NOT */
			fill_cmd(cmd, O_IN, 0, 0);
			break;

		case TOK_DIVERTED:
			fill_cmd(cmd, O_DIVERTED, 0, 3);
			break;

		case TOK_DIVERTEDLOOPBACK:
			fill_cmd(cmd, O_DIVERTED, 0, 1);
			break;

		case TOK_DIVERTEDOUTPUT:
			fill_cmd(cmd, O_DIVERTED, 0, 2);
			break;

		case TOK_FRAG:
			fill_cmd(cmd, O_FRAG, 0, 0);
			break;

		case TOK_LAYER2:
			fill_cmd(cmd, O_LAYER2, 0, 0);
			break;

		case TOK_XMIT:
		case TOK_RECV:
		case TOK_VIA:
			NEED1("recv, xmit, via require interface name"
				" or address");
			fill_iface((ipfw_insn_if *)cmd, av[0]);
			ac--; av++;
			if (F_LEN(cmd) == 0)	/* not a valid address */
				break;
			if (i == TOK_XMIT)
				cmd->opcode = O_XMIT;
			else if (i == TOK_RECV)
				cmd->opcode = O_RECV;
			else if (i == TOK_VIA)
				cmd->opcode = O_VIA;
			break;

		case TOK_ICMPTYPES:
			NEED1("icmptypes requires list of types");
			fill_icmptypes((ipfw_insn_u32 *)cmd, *av);
			av++; ac--;
			break;
		
		case TOK_ICMP6TYPES:
			NEED1("icmptypes requires list of types");
			fill_icmp6types((ipfw_insn_icmp6 *)cmd, *av);
			av++; ac--;
			break;

		case TOK_IPTTL:
			NEED1("ipttl requires TTL");
			if (strpbrk(*av, "-,")) {
			    if (!add_ports(cmd, *av, 0, O_IPTTL))
				errx(EX_DATAERR, "invalid ipttl %s", *av);
			} else
			    fill_cmd(cmd, O_IPTTL, 0, strtoul(*av, NULL, 0));
			ac--; av++;
			break;

		case TOK_IPID:
			NEED1("ipid requires id");
			if (strpbrk(*av, "-,")) {
			    if (!add_ports(cmd, *av, 0, O_IPID))
				errx(EX_DATAERR, "invalid ipid %s", *av);
			} else
			    fill_cmd(cmd, O_IPID, 0, strtoul(*av, NULL, 0));
			ac--; av++;
			break;

		case TOK_IPLEN:
			NEED1("iplen requires length");
			if (strpbrk(*av, "-,")) {
			    if (!add_ports(cmd, *av, 0, O_IPLEN))
				errx(EX_DATAERR, "invalid ip len %s", *av);
			} else
			    fill_cmd(cmd, O_IPLEN, 0, strtoul(*av, NULL, 0));
			ac--; av++;
			break;

		case TOK_IPVER:
			NEED1("ipver requires version");
			fill_cmd(cmd, O_IPVER, 0, strtoul(*av, NULL, 0));
			ac--; av++;
			break;

		case TOK_IPPRECEDENCE:
			NEED1("ipprecedence requires value");
			fill_cmd(cmd, O_IPPRECEDENCE, 0,
			    (strtoul(*av, NULL, 0) & 7) << 5);
			ac--; av++;
			break;

		case TOK_IPOPTS:
			NEED1("missing argument for ipoptions");
			fill_flags(cmd, O_IPOPT, f_ipopts, *av);
			ac--; av++;
			break;

		case TOK_IPTOS:
			NEED1("missing argument for iptos");
			fill_flags(cmd, O_IPTOS, f_iptos, *av);
			ac--; av++;
			break;

		case TOK_UID:
			NEED1("uid requires argument");
		    {
			char *end;
			uid_t uid;
			struct passwd *pwd;

			cmd->opcode = O_UID;
			uid = strtoul(*av, &end, 0);
			pwd = (*end == '\0') ? getpwuid(uid) : getpwnam(*av);
			if (pwd == NULL)
				errx(EX_DATAERR, "uid \"%s\" nonexistent", *av);
			cmd32->d[0] = pwd->pw_uid;
			cmd->len |= F_INSN_SIZE(ipfw_insn_u32);
			ac--; av++;
		    }
			break;

		case TOK_GID:
			NEED1("gid requires argument");
		    {
			char *end;
			gid_t gid;
			struct group *grp;

			cmd->opcode = O_GID;
			gid = strtoul(*av, &end, 0);
			grp = (*end == '\0') ? getgrgid(gid) : getgrnam(*av);
			if (grp == NULL)
				errx(EX_DATAERR, "gid \"%s\" nonexistent", *av);
			cmd32->d[0] = grp->gr_gid;
			cmd->len |= F_INSN_SIZE(ipfw_insn_u32);
			ac--; av++;
		    }
			break;

		case TOK_JAIL:
			NEED1("jail requires argument");
		    {
			char *end;
			int jid;

			cmd->opcode = O_JAIL;
			jid = (int)strtol(*av, &end, 0);
			if (jid < 0 || *end != '\0')
				errx(EX_DATAERR, "jail requires prison ID");
			cmd32->d[0] = (uint32_t)jid;
			cmd->len |= F_INSN_SIZE(ipfw_insn_u32);
			ac--; av++;
		    }
			break;

		case TOK_ESTAB:
			fill_cmd(cmd, O_ESTAB, 0, 0);
			break;

		case TOK_SETUP:
			fill_cmd(cmd, O_TCPFLAGS, 0,
				(TH_SYN) | ( (TH_ACK) & 0xff) <<8 );
			break;

		case TOK_TCPDATALEN:
			NEED1("tcpdatalen requires length");
			if (strpbrk(*av, "-,")) {
			    if (!add_ports(cmd, *av, 0, O_TCPDATALEN))
				errx(EX_DATAERR, "invalid tcpdata len %s", *av);
			} else
			    fill_cmd(cmd, O_TCPDATALEN, 0,
				    strtoul(*av, NULL, 0));
			ac--; av++;
			break;

		case TOK_TCPOPTS:
			NEED1("missing argument for tcpoptions");
			fill_flags(cmd, O_TCPOPTS, f_tcpopts, *av);
			ac--; av++;
			break;

		case TOK_TCPSEQ:
		case TOK_TCPACK:
			NEED1("tcpseq/tcpack requires argument");
			cmd->len = F_INSN_SIZE(ipfw_insn_u32);
			cmd->opcode = (i == TOK_TCPSEQ) ? O_TCPSEQ : O_TCPACK;
			cmd32->d[0] = htonl(strtoul(*av, NULL, 0));
			ac--; av++;
			break;

		case TOK_TCPWIN:
			NEED1("tcpwin requires length");
			fill_cmd(cmd, O_TCPWIN, 0,
			    htons(strtoul(*av, NULL, 0)));
			ac--; av++;
			break;

		case TOK_TCPFLAGS:
			NEED1("missing argument for tcpflags");
			cmd->opcode = O_TCPFLAGS;
			fill_flags(cmd, O_TCPFLAGS, f_tcpflags, *av);
			ac--; av++;
			break;

		case TOK_KEEPSTATE:
			if (open_par)
				errx(EX_USAGE, "keep-state cannot be part "
				    "of an or block");
			if (have_state)
				errx(EX_USAGE, "only one of keep-state "
					"and limit is allowed");
			have_state = cmd;
			fill_cmd(cmd, O_KEEP_STATE, 0, 0);
			break;

		case TOK_LIMIT: {
			ipfw_insn_limit *c = (ipfw_insn_limit *)cmd;
			int val;

			if (open_par)
				errx(EX_USAGE,
				    "limit cannot be part of an or block");
			if (have_state)
				errx(EX_USAGE, "only one of keep-state and "
				    "limit is allowed");
			have_state = cmd;

			cmd->len = F_INSN_SIZE(ipfw_insn_limit);
			cmd->opcode = O_LIMIT;
			c->limit_mask = c->conn_limit = 0;

			while (ac > 0) {
				if ((val = match_token(limit_masks, *av)) <= 0)
					break;
				c->limit_mask |= val;
				ac--; av++;
			}

			if (c->limit_mask == 0)
				errx(EX_USAGE, "limit: missing limit mask");

			GET_UINT_ARG(c->conn_limit, 1, IPFW_DEFAULT_RULE - 1,
			    TOK_LIMIT, rule_options);

			ac--; av++;
			break;
		}

		case TOK_PROTO:
			NEED1("missing protocol");
			if (add_proto(cmd, *av, &proto)) {
				ac--; av++;
			} else
				errx(EX_DATAERR, "invalid protocol ``%s''",
				    *av);
			break;

		case TOK_SRCIP:
			NEED1("missing source IP");
			if (add_srcip(cmd, *av)) {
				ac--; av++;
			}
			break;

		case TOK_DSTIP:
			NEED1("missing destination IP");
			if (add_dstip(cmd, *av)) {
				ac--; av++;
			}
			break;

		case TOK_SRCIP6:
			NEED1("missing source IP6");
			if (add_srcip6(cmd, *av)) {
				ac--; av++;
			}
			break;
				
		case TOK_DSTIP6:
			NEED1("missing destination IP6");
			if (add_dstip6(cmd, *av)) {
				ac--; av++;
			}
			break;

		case TOK_SRCPORT:
			NEED1("missing source port");
			if (_substrcmp(*av, "any") == 0 ||
			    add_ports(cmd, *av, proto, O_IP_SRCPORT)) {
				ac--; av++;
			} else
				errx(EX_DATAERR, "invalid source port %s", *av);
			break;

		case TOK_DSTPORT:
			NEED1("missing destination port");
			if (_substrcmp(*av, "any") == 0 ||
			    add_ports(cmd, *av, proto, O_IP_DSTPORT)) {
				ac--; av++;
			} else
				errx(EX_DATAERR, "invalid destination port %s",
				    *av);
			break;

		case TOK_MAC:
			if (add_mac(cmd, ac, av)) {
				ac -= 2; av += 2;
			}
			break;

		case TOK_MACTYPE:
			NEED1("missing mac type");
			if (!add_mactype(cmd, ac, *av))
				errx(EX_DATAERR, "invalid mac type %s", *av);
			ac--; av++;
			break;

		case TOK_VERREVPATH:
			fill_cmd(cmd, O_VERREVPATH, 0, 0);
			break;

		case TOK_VERSRCREACH:
			fill_cmd(cmd, O_VERSRCREACH, 0, 0);
			break;

		case TOK_ANTISPOOF:
			fill_cmd(cmd, O_ANTISPOOF, 0, 0);
			break;

		case TOK_IPSEC:
			fill_cmd(cmd, O_IPSEC, 0, 0);
			break;

		case TOK_IPV6:
			fill_cmd(cmd, O_IP6, 0, 0);
			break;

		case TOK_IPV4:
			fill_cmd(cmd, O_IP4, 0, 0);
			break;

		case TOK_EXT6HDR:
			fill_ext6hdr( cmd, *av );
			ac--; av++;
			break;

		case TOK_FLOWID:
			if (proto != IPPROTO_IPV6 )
				errx( EX_USAGE, "flow-id filter is active "
				    "only for ipv6 protocol\n");
			fill_flow6( (ipfw_insn_u32 *) cmd, *av );
			ac--; av++;
			break;

		case TOK_COMMENT:
			fill_comment(cmd, ac, av);
			av += ac;
			ac = 0;
			break;

		case TOK_TAGGED:
			if (ac > 0 && strpbrk(*av, "-,")) {
				if (!add_ports(cmd, *av, 0, O_TAGGED))
					errx(EX_DATAERR, "tagged: invalid tag"
					    " list: %s", *av);
			}
			else {
				uint16_t tag;

				GET_UINT_ARG(tag, 1, IPFW_DEFAULT_RULE - 1,
				    TOK_TAGGED, rule_options);
				fill_cmd(cmd, O_TAGGED, 0, tag);
			}
			ac--; av++;
			break;

		case TOK_FIB:
			NEED1("fib requires fib number");
			fill_cmd(cmd, O_FIB, 0, strtoul(*av, NULL, 0));
			ac--; av++;
			break;

		default:
			errx(EX_USAGE, "unrecognised option [%d] %s\n", i, s);
		}
		if (F_LEN(cmd) > 0) {	/* prepare to advance */
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	}

done:
	/*
	 * Now copy stuff into the rule.
	 * If we have a keep-state option, the first instruction
	 * must be a PROBE_STATE (which is generated here).
	 * If we have a LOG option, it was stored as the first command,
	 * and now must be moved to the top of the action part.
	 */
	dst = (ipfw_insn *)rule->cmd;

	/*
	 * First thing to write into the command stream is the match probability.
	 */
	if (match_prob != 1) { /* 1 means always match */
		dst->opcode = O_PROB;
		dst->len = 2;
		*((int32_t *)(dst+1)) = (int32_t)(match_prob * 0x7fffffff);
		dst += dst->len;
	}

	/*
	 * generate O_PROBE_STATE if necessary
	 */
	if (have_state && have_state->opcode != O_CHECK_STATE) {
		fill_cmd(dst, O_PROBE_STATE, 0, 0);
		dst = next_cmd(dst);
	}

	/* copy all commands but O_LOG, O_KEEP_STATE, O_LIMIT, O_ALTQ, O_TAG */
	for (src = (ipfw_insn *)cmdbuf; src != cmd; src += i) {
		i = F_LEN(src);

		switch (src->opcode) {
		case O_LOG:
		case O_KEEP_STATE:
		case O_LIMIT:
		case O_ALTQ:
		case O_TAG:
			break;
		default:
			bcopy(src, dst, i * sizeof(uint32_t));
			dst += i;
		}
	}

	/*
	 * put back the have_state command as last opcode
	 */
	if (have_state && have_state->opcode != O_CHECK_STATE) {
		i = F_LEN(have_state);
		bcopy(have_state, dst, i * sizeof(uint32_t));
		dst += i;
	}
	/*
	 * start action section
	 */
	rule->act_ofs = dst - rule->cmd;

	/* put back O_LOG, O_ALTQ, O_TAG if necessary */
	if (have_log) {
		i = F_LEN(have_log);
		bcopy(have_log, dst, i * sizeof(uint32_t));
		dst += i;
	}
	if (have_altq) {
		i = F_LEN(have_altq);
		bcopy(have_altq, dst, i * sizeof(uint32_t));
		dst += i;
	}
	if (have_tag) {
		i = F_LEN(have_tag);
		bcopy(have_tag, dst, i * sizeof(uint32_t));
		dst += i;
	}
	/*
	 * copy all other actions
	 */
	for (src = (ipfw_insn *)actbuf; src != action; src += i) {
		i = F_LEN(src);
		bcopy(src, dst, i * sizeof(uint32_t));
		dst += i;
	}

	rule->cmd_len = (uint32_t *)dst - (uint32_t *)(rule->cmd);
	i = (char *)dst - (char *)rule;
	if (do_cmd(IP_FW_ADD, rule, (uintptr_t)&i) == -1)
		err(EX_UNAVAILABLE, "getsockopt(%s)", "IP_FW_ADD");
	if (!co.do_quiet)
		show_ipfw(rule, 0, 0);
}

/*
 * clear the counters or the log counters.
 */
void
ipfw_zero(int ac, char *av[], int optname /* 0 = IP_FW_ZERO, 1 = IP_FW_RESETLOG */)
{
	uint32_t arg, saved_arg;
	int failed = EX_OK;
	char const *errstr;
	char const *name = optname ? "RESETLOG" : "ZERO";

	optname = optname ? IP_FW_RESETLOG : IP_FW_ZERO;

	av++; ac--;

	if (!ac) {
		/* clear all entries */
		if (do_cmd(optname, NULL, 0) < 0)
			err(EX_UNAVAILABLE, "setsockopt(IP_FW_%s)", name);
		if (!co.do_quiet)
			printf("%s.\n", optname == IP_FW_ZERO ?
			    "Accounting cleared":"Logging counts reset");

		return;
	}

	while (ac) {
		/* Rule number */
		if (isdigit(**av)) {
			arg = strtonum(*av, 0, 0xffff, &errstr);
			if (errstr)
				errx(EX_DATAERR,
				    "invalid rule number %s\n", *av);
			saved_arg = arg;
			if (co.use_set)
				arg |= (1 << 24) | ((co.use_set - 1) << 16);
			av++;
			ac--;
			if (do_cmd(optname, &arg, sizeof(arg))) {
				warn("rule %u: setsockopt(IP_FW_%s)",
				    saved_arg, name);
				failed = EX_UNAVAILABLE;
			} else if (!co.do_quiet)
				printf("Entry %d %s.\n", saved_arg,
				    optname == IP_FW_ZERO ?
					"cleared" : "logging count reset");
		} else {
			errx(EX_USAGE, "invalid rule number ``%s''", *av);
		}
	}
	if (failed != EX_OK)
		exit(failed);
}

void
ipfw_flush(int force)
{
	int cmd = co.do_pipe ? IP_DUMMYNET_FLUSH : IP_FW_FLUSH;

	if (!force && !co.do_quiet) { /* need to ask user */
		int c;

		printf("Are you sure? [yn] ");
		fflush(stdout);
		do {
			c = toupper(getc(stdin));
			while (c != '\n' && getc(stdin) != '\n')
				if (feof(stdin))
					return; /* and do not flush */
		} while (c != 'Y' && c != 'N');
		printf("\n");
		if (c == 'N')	/* user said no */
			return;
	}
	/* `ipfw set N flush` - is the same that `ipfw delete set N` */
	if (co.use_set) {
		uint32_t arg = ((co.use_set - 1) & 0xffff) | (1 << 24);
		if (do_cmd(IP_FW_DEL, &arg, sizeof(arg)) < 0)
			err(EX_UNAVAILABLE, "setsockopt(IP_FW_DEL)");
	} else if (do_cmd(cmd, NULL, 0) < 0)
		err(EX_UNAVAILABLE, "setsockopt(IP_%s_FLUSH)",
		    co.do_pipe ? "DUMMYNET" : "FW");
	if (!co.do_quiet)
		printf("Flushed all %s.\n", co.do_pipe ? "pipes" : "rules");
}


static void table_list(ipfw_table_entry ent, int need_header);

/*
 * This one handles all table-related commands
 * 	ipfw table N add addr[/masklen] [value]
 * 	ipfw table N delete addr[/masklen]
 * 	ipfw table {N | all} flush
 * 	ipfw table {N | all} list
 */
void
ipfw_table_handler(int ac, char *av[])
{
	ipfw_table_entry ent;
	int do_add;
	int is_all;
	size_t len;
	char *p;
	uint32_t a;
	uint32_t tables_max;

	len = sizeof(tables_max);
	if (sysctlbyname("net.inet.ip.fw.tables_max", &tables_max, &len,
		NULL, 0) == -1) {
#ifdef IPFW_TABLES_MAX
		warn("Warn: Failed to get the max tables number via sysctl. "
		     "Using the compiled in defaults. \nThe reason was");
		tables_max = IPFW_TABLES_MAX;
#else
		errx(1, "Failed sysctlbyname(\"net.inet.ip.fw.tables_max\")");
#endif
	}

	ac--; av++;
	if (ac && isdigit(**av)) {
		ent.tbl = atoi(*av);
		is_all = 0;
		ac--; av++;
	} else if (ac && _substrcmp(*av, "all") == 0) {
		ent.tbl = 0;
		is_all = 1;
		ac--; av++;
	} else
		errx(EX_USAGE, "table number or 'all' keyword required");
	if (ent.tbl >= tables_max)
		errx(EX_USAGE, "The table number exceeds the maximum allowed "
			"value (%d)", tables_max - 1);
	NEED1("table needs command");
	if (is_all && _substrcmp(*av, "list") != 0
		   && _substrcmp(*av, "flush") != 0)
		errx(EX_USAGE, "table number required");

	if (_substrcmp(*av, "add") == 0 ||
	    _substrcmp(*av, "delete") == 0) {
		do_add = **av == 'a';
		ac--; av++;
		if (!ac)
			errx(EX_USAGE, "IP address required");
		p = strchr(*av, '/');
		if (p) {
			*p++ = '\0';
			ent.masklen = atoi(p);
			if (ent.masklen > 32)
				errx(EX_DATAERR, "bad width ``%s''", p);
		} else
			ent.masklen = 32;
		if (lookup_host(*av, (struct in_addr *)&ent.addr) != 0)
			errx(EX_NOHOST, "hostname ``%s'' unknown", *av);
		ac--; av++;
		if (do_add && ac) {
			unsigned int tval;
			/* isdigit is a bit of a hack here.. */
			if (strchr(*av, (int)'.') == NULL && isdigit(**av))  {
				ent.value = strtoul(*av, NULL, 0);
			} else {
		        	if (lookup_host(*av, (struct in_addr *)&tval) == 0) {
					/* The value must be stored in host order	 *
					 * so that the values < 65k can be distinguished */
		       			ent.value = ntohl(tval); 
				} else {
					errx(EX_NOHOST, "hostname ``%s'' unknown", *av);
				}
			}
		} else
			ent.value = 0;
		if (do_cmd(do_add ? IP_FW_TABLE_ADD : IP_FW_TABLE_DEL,
		    &ent, sizeof(ent)) < 0) {
			/* If running silent, don't bomb out on these errors. */
			if (!(co.do_quiet && (errno == (do_add ? EEXIST : ESRCH))))
				err(EX_OSERR, "setsockopt(IP_FW_TABLE_%s)",
				    do_add ? "ADD" : "DEL");
			/* In silent mode, react to a failed add by deleting */
			if (do_add) {
				do_cmd(IP_FW_TABLE_DEL, &ent, sizeof(ent));
				if (do_cmd(IP_FW_TABLE_ADD,
				    &ent, sizeof(ent)) < 0)
					err(EX_OSERR,
				            "setsockopt(IP_FW_TABLE_ADD)");
			}
		}
	} else if (_substrcmp(*av, "flush") == 0) {
		a = is_all ? tables_max : (ent.tbl + 1);
		do {
			if (do_cmd(IP_FW_TABLE_FLUSH, &ent.tbl,
			    sizeof(ent.tbl)) < 0)
				err(EX_OSERR, "setsockopt(IP_FW_TABLE_FLUSH)");
		} while (++ent.tbl < a);
	} else if (_substrcmp(*av, "list") == 0) {
		a = is_all ? tables_max : (ent.tbl + 1);
		do {
			table_list(ent, is_all);
		} while (++ent.tbl < a);
	} else
		errx(EX_USAGE, "invalid table command %s", *av);
}

static void
table_list(ipfw_table_entry ent, int need_header)
{
	ipfw_table *tbl;
	socklen_t l;
	uint32_t a;

	a = ent.tbl;
	l = sizeof(a);
	if (do_cmd(IP_FW_TABLE_GETSIZE, &a, (uintptr_t)&l) < 0)
		err(EX_OSERR, "getsockopt(IP_FW_TABLE_GETSIZE)");

	/* If a is zero we have nothing to do, the table is empty. */
	if (a == 0)
		return;

	l = sizeof(*tbl) + a * sizeof(ipfw_table_entry);
	tbl = safe_calloc(1, l);
	tbl->tbl = ent.tbl;
	if (do_cmd(IP_FW_TABLE_LIST, tbl, (uintptr_t)&l) < 0)
		err(EX_OSERR, "getsockopt(IP_FW_TABLE_LIST)");
	if (tbl->cnt && need_header)
		printf("---table(%d)---\n", tbl->tbl);
	for (a = 0; a < tbl->cnt; a++) {
		unsigned int tval;
		tval = tbl->ent[a].value;
		if (co.do_value_as_ip) {
			char tbuf[128];
			strncpy(tbuf, inet_ntoa(*(struct in_addr *)
				&tbl->ent[a].addr), 127);
			/* inet_ntoa expects network order */
			tval = htonl(tval);
			printf("%s/%u %s\n", tbuf, tbl->ent[a].masklen,
				inet_ntoa(*(struct in_addr *)&tval));
		} else {
			printf("%s/%u %u\n",
				inet_ntoa(*(struct in_addr *)&tbl->ent[a].addr),
				tbl->ent[a].masklen, tval);
		}
	}
	free(tbl);
}

void
ipfw_show_nat(int ac, char **av)
{
	struct cfg_nat *n;
	struct cfg_redir *e;
	int cmd, i, nbytes, do_cfg, do_rule, frule, lrule, nalloc, size;
	int nat_cnt, redir_cnt, r;
	uint8_t *data, *p;
	char *endptr;

	do_rule = 0;
	nalloc = 1024;
	size = 0;
	data = NULL;
	frule = 0;
	lrule = IPFW_DEFAULT_RULE; /* max ipfw rule number */
	ac--; av++;

	if (co.test_only)
		return;

	/* Parse parameters. */
	for (cmd = IP_FW_NAT_GET_LOG, do_cfg = 0; ac != 0; ac--, av++) {
		if (!strncmp(av[0], "config", strlen(av[0]))) {
			cmd = IP_FW_NAT_GET_CONFIG, do_cfg = 1; 
			continue;
		}
		/* Convert command line rule #. */
		frule = lrule = strtoul(av[0], &endptr, 10);
		if (*endptr == '-')
			lrule = strtoul(endptr+1, &endptr, 10);
		if (lrule == 0)			
			err(EX_USAGE, "invalid rule number: %s", av[0]);
		do_rule = 1;
	}

	nbytes = nalloc;
	while (nbytes >= nalloc) {
		nalloc = nalloc * 2;
		nbytes = nalloc;
		data = safe_realloc(data, nbytes);
		if (do_cmd(cmd, data, (uintptr_t)&nbytes) < 0)
			err(EX_OSERR, "getsockopt(IP_FW_GET_%s)",
			    (cmd == IP_FW_NAT_GET_LOG) ? "LOG" : "CONFIG");
	}
	if (nbytes == 0)
		exit(0);
	if (do_cfg) {
		nat_cnt = *((int *)data);
		for (i = sizeof(nat_cnt); nat_cnt; nat_cnt--) {
			n = (struct cfg_nat *)&data[i];
			if (frule <= n->id && lrule >= n->id)
				print_nat_config(&data[i]);
			i += sizeof(struct cfg_nat);
			for (redir_cnt = 0; redir_cnt < n->redir_cnt; redir_cnt++) {
				e = (struct cfg_redir *)&data[i];
				i += sizeof(struct cfg_redir) + e->spool_cnt * 
				    sizeof(struct cfg_spool);
			}
		}
	} else {
		for (i = 0; 1; i += LIBALIAS_BUF_SIZE + sizeof(int)) {
			p = &data[i];
			if (p == data + nbytes)
				break;
			bcopy(p, &r, sizeof(int));
			if (do_rule) {
				if (!(frule <= r && lrule >= r))
					continue;
			}
			printf("nat %u: %s\n", r, p+sizeof(int));
		}
	}
}
