/*
 * Copyright (c) 1997-1999 Kungliga Tekniska H�gskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#include "kdc_locl.h"

RCSID("$Id: connect.c,v 1.68 1999/12/02 17:04:58 joda Exp $");

struct port_desc{
    int family;
    int type;
    int port;
};

static struct port_desc *ports;
static int num_ports;

static void
add_port(int family, int port, const char *protocol)
{
    int type;
    int i;

    if(strcmp(protocol, "udp") == 0)
	type = SOCK_DGRAM;
    else if(strcmp(protocol, "tcp") == 0)
	type = SOCK_STREAM;
    else
	return;
    for(i = 0; i < num_ports; i++){
	if(ports[i].type == type
	   && ports[i].port == port
	   && ports[i].family == family)
	    return;
    }
    ports = realloc(ports, (num_ports + 1) * sizeof(*ports));
    ports[num_ports].family = family;
    ports[num_ports].type   = type;
    ports[num_ports].port   = port;
    num_ports++;
}

static void
add_port_service(int family, const char *service, int port,
		 const char *protocol)
{
    port = krb5_getportbyname (context, service, protocol, port);
    add_port (family, port, protocol);
}

static void
add_port_string (int family, const char *port_str, const char *protocol)
{
    struct servent *sp;
    int port;

    sp = roken_getservbyname (port_str, protocol);
    if (sp != NULL) {
	port = sp->s_port;
    } else {
	char *end;

	port = htons(strtol(port_str, &end, 0));
	if (end == port_str)
	    return;
    }
    add_port (family, port, protocol);
}

static void
add_standard_ports (int family)
{
    add_port_service(family, "kerberos", 88, "udp");
    add_port_service(family, "kerberos", 88, "tcp");
    add_port_service(family, "kerberos-sec", 88, "udp");
    add_port_service(family, "kerberos-sec", 88, "tcp");
    add_port_service(family, "kerberos-iv", 750, "udp");
    add_port_service(family, "kerberos-iv", 750, "tcp");
    if(enable_http)
	add_port_service(family, "http", 80, "tcp");
#ifdef KASERVER
    if (enable_kaserver)
	add_port_service(family, "afs3-kaserver", 7004, "udp");
#endif
}

static void
parse_ports(const char *str)
{
    char *pos = NULL;
    char *p;
    char *str_copy = strdup (str);

    p = strtok_r(str_copy, " \t", &pos);
    while(p != NULL) {
	if(strcmp(p, "+") == 0) {
#ifdef HAVE_IPV6
	    add_standard_ports(AF_INET6);
#endif
	    add_standard_ports(AF_INET);
	} else {
	    char *q = strchr(p, '/');
	    if(q){
		*q++ = 0;
#ifdef HAVE_IPV6
		add_port_string(AF_INET6, p, q);
#endif
		add_port_string(AF_INET, p, q);
	    }else {
#ifdef HAVE_IPV6
		add_port_string(AF_INET6, p, "udp");
		add_port_string(AF_INET6, p, "tcp");
#endif
		add_port_string(AF_INET, p, "udp");
		add_port_string(AF_INET, p, "tcp");
	    }
	}
	    
	p = strtok_r(NULL, " \t", &pos);
    }
    free (str_copy);
}

struct descr {
    int s;
    int type;
    unsigned char *buf;
    size_t size;
    size_t len;
    time_t timeout;
};

/*
 * Create the socket (family, type, port) in `d'
 */

static void 
init_socket(struct descr *d, krb5_address *a, int family, int type, int port)
{
    krb5_error_code ret;
    struct sockaddr_storage __ss;
    struct sockaddr *sa = (struct sockaddr *)&__ss;
    int sa_size;

    memset(d, 0, sizeof(*d));
    d->s = -1;

    ret = krb5_addr2sockaddr (a, sa, &sa_size, port);
    if (ret) {
	krb5_warn(context, ret, "krb5_anyaddr");
	close(d->s);
	d->s = -1;
	return;
    }

    if (sa->sa_family != family)
	return;

    d->s = socket(family, type, 0);
    if(d->s < 0){
	krb5_warn(context, errno, "socket(%d, %d, 0)", family, type);
	d->s = -1;
	return;
    }
#if defined(HAVE_SETSOCKOPT) && defined(SOL_SOCKET) && defined(SO_REUSEADDR)
    {
	int one = 1;
	setsockopt(d->s, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one));
    }
#endif
    d->type = type;

    if(bind(d->s, sa, sa_size) < 0){
	krb5_warn(context, errno, "bind(%d)", ntohs(port));
	close(d->s);
	d->s = -1;
	return;
    }
    if(type == SOCK_STREAM && listen(d->s, SOMAXCONN) < 0){
	krb5_warn(context, errno, "listen");
	close(d->s);
	return;
    }
}

/*
 * Allocate descriptors for all the sockets that we should listen on
 * and return the number of them.
 */

static int
init_sockets(struct descr **desc)
{
    krb5_error_code ret;
    int i, j;
    struct descr *d;
    int num = 0;
    krb5_addresses addresses;

    ret = krb5_get_all_server_addrs (context, &addresses);
    if (ret)
	krb5_err (context, 1, ret, "krb5_get_all_server_addrs");
    parse_ports(port_str);
    d = malloc(addresses.len * num_ports * sizeof(*d));
    if (d == NULL)
	krb5_errx(context, 1, "malloc(%u) failed", num_ports * sizeof(*d));

    for (i = 0; i < num_ports; i++){
	for (j = 0; j < addresses.len; ++j) {
	    init_socket(&d[num], &addresses.val[j],
			ports[i].family, ports[i].type, ports[i].port);
	    if(d[num].s != -1){
		char a_str[80];
		size_t len;

		krb5_print_address (&addresses.val[j], a_str,
				    sizeof(a_str), &len);

		kdc_log(5, "listening on %s port %u/%s",
			a_str,
			ntohs(ports[i].port), 
			(ports[i].type == SOCK_STREAM) ? "tcp" : "udp");
		/* XXX */
		num++;
	    }
	}
    }
    krb5_free_addresses (context, &addresses);
    d = realloc(d, num * sizeof(*d));
    if (d == NULL && num != 0)
	krb5_errx(context, 1, "realloc(%u) failed", num * sizeof(*d));
    *desc = d;
    return num;
}

    
static int
process_request(unsigned char *buf, 
		size_t len, 
		krb5_data *reply,
		int *sendlength,
		const char *from,
		struct sockaddr *addr)
{
    KDC_REQ req;
#ifdef KRB4
    Ticket ticket;
#endif
    krb5_error_code ret;
    size_t i;

    gettimeofday(&now, NULL);
    if(decode_AS_REQ(buf, len, &req, &i) == 0){
	ret = as_rep(&req, reply, from, addr);
	free_AS_REQ(&req);
	return ret;
    }else if(decode_TGS_REQ(buf, len, &req, &i) == 0){
	ret = tgs_rep(&req, reply, from, addr);
	free_TGS_REQ(&req);
	return ret;
    }
#ifdef KRB4
    else if(maybe_version4(buf, len)){
	*sendlength = 0; /* elbitapmoc sdrawkcab XXX */
	do_version4(buf, len, reply, from, (struct sockaddr_in*)addr);
	return 0;
    }else if(decode_Ticket(buf, len, &ticket, &i) == 0){
	ret = do_524(&ticket, reply, from, addr);
	free_Ticket(&ticket);
	return ret;
    }
#endif
#ifdef KASERVER
    else if (enable_kaserver) {
	ret = do_kaserver (buf, len, reply, from, (struct sockaddr_in*)addr);
	return ret;
    }
#endif
			  
    return -1;
}

static void
addr_to_string(struct sockaddr *addr, size_t addr_len, char *str, size_t len)
{
    krb5_address a;
    krb5_sockaddr2address(addr, &a);
    if(krb5_print_address(&a, str, len, &len) == 0) {
	krb5_free_address(context, &a);
	return;
    }
    krb5_free_address(context, &a);
    snprintf(str, len, "<family=%d>", addr->sa_family);
}

static void
do_request(void *buf, size_t len, int sendlength,
	   int socket, struct sockaddr *from, size_t from_len)
{
    krb5_error_code ret;
    krb5_data reply;
    char addr[128];
    
    addr_to_string(from, from_len, addr, sizeof(addr));
    
    reply.length = 0;
    ret = process_request(buf, len, &reply, &sendlength, addr, from);
    if(reply.length){
	kdc_log(5, "sending %d bytes to %s", reply.length, addr);
	if(sendlength){
	    unsigned char len[4];
	    len[0] = (reply.length >> 24) & 0xff;
	    len[1] = (reply.length >> 16) & 0xff;
	    len[2] = (reply.length >> 8) & 0xff;
	    len[3] = reply.length & 0xff;
	    if(sendto(socket, len, sizeof(len), 0, from, from_len) < 0) {
		kdc_log (0, "sendto(%s): %s", addr, strerror(errno));
		krb5_data_free(&reply);
		return;
	    }
	}
	if(sendto(socket, reply.data, reply.length, 0, from, from_len) < 0) {
	    kdc_log (0, "sendto(%s): %s", addr, strerror(errno));
	    krb5_data_free(&reply);
	    return;
	}
	krb5_data_free(&reply);
    }
    if(ret)
	kdc_log(0, "Failed processing %lu byte request from %s", 
		(unsigned long)len, addr);
}

static void
handle_udp(struct descr *d)
{
    unsigned char *buf;
    struct sockaddr_storage __ss;
    struct sockaddr *sa = (struct sockaddr *)&__ss;
    int from_len;
    int n;

    buf = malloc(max_request);
    if(buf == NULL){
	kdc_log(0, "Failed to allocate %u bytes", max_request);
	return;
    }

    from_len = sizeof(__ss);
    n = recvfrom(d->s, buf, max_request, 0, 
		 sa, &from_len);
    if(n < 0){
	krb5_warn(context, errno, "recvfrom");
	goto out;
    }
    if(n == 0) {
	goto out;
    }
    do_request(buf, n, 0, d->s, sa, from_len);
out:
    free (buf);
}

static void
clear_descr(struct descr *d)
{
    if(d->buf)
	memset(d->buf, 0, d->size);
    d->len = 0;
    if(d->s != -1)
	close(d->s);
    d->s = -1;
}


/* remove HTTP %-quoting from buf */
static int
de_http(char *buf)
{
    char *p, *q;
    for(p = q = buf; *p; p++, q++) {
	if(*p == '%') {
	    unsigned int x;
	    if(sscanf(p + 1, "%2x", &x) != 1)
		return -1;
	    *q = x;
	    p += 2;
	} else
	    *q = *p;
    }
    *q = '\0';
    return 0;
}

#define TCP_TIMEOUT 4

/*
 * accept a new TCP connection on `d[index]'
 */

static void
add_new_tcp (struct descr *d, int index, int min_free)
{
    struct sockaddr_storage __ss;
    struct sockaddr *sa = (struct sockaddr *)&__ss;
    int s;
    int from_len;

    from_len = sizeof(__ss);
    s = accept(d[index].s, sa, &from_len);
    if(s < 0){
	krb5_warn(context, errno, "accept");
	return;
    }
    if(min_free == -1){
	close(s);
	return;
    }
	    
    d[min_free].s = s;
    d[min_free].timeout = time(NULL) + TCP_TIMEOUT;
    d[min_free].type = SOCK_STREAM;
}

/*
 * Grow `d' to handle at least `n'.
 * Return != 0 if fails
 */

static int
grow_descr (struct descr *d, size_t n)
{
    if (d->size - d->len < n) {
	unsigned char *tmp;

	d->size += max(1024, d->len + n);
	if (d->size >= max_request) {
	    kdc_log(0, "Request exceeds max request size (%u bytes).",
		    d->size);
	    clear_descr(d);
	    return -1;
	}
	tmp = realloc (d->buf, d->size);
	if (tmp == NULL) {
	    kdc_log(0, "Failed to re-allocate %u bytes.", d->size);
	    clear_descr(d);
	    return -1;
	}
	d->buf = tmp;
    }
    return 0;
}

/*
 * Try to handle the TCP data at `d->buf, d->len'.
 * Return -1 if failed, 0 if succesful, and 1 if data is complete.
 */

static int
handle_vanilla_tcp (struct descr *d)
{
    krb5_storage *sp;
    int32_t len;

    sp = krb5_storage_from_mem(d->buf, d->len);
    if (sp == NULL) {
	kdc_log (0, "krb5_storage_from_mem failed");
	return -1;
    }
    krb5_ret_int32(sp, &len);
    krb5_storage_free(sp);
    if(d->len - 4 >= len) {
	memcpy(d->buf, d->buf + 4, d->len - 4);
	return 1;
    }
    return 0;
}

/*
 * Try to handle the TCP/HTTP data at `d->buf, d->len'.
 * Return -1 if failed, 0 if succesful, and 1 if data is complete.
 */

static int
handle_http_tcp (struct descr *d, const char *addr)
{
    char *s, *p, *t;
    void *data;
    char *proto;
    int len;

    s = (char *)d->buf;

    p = strstr(s, "\r\n");
    if (p == NULL) {
	kdc_log(0, "Malformed HTTP request from %s", addr);
	return -1;
    }
    *p = 0;

    p = NULL;
    t = strtok_r(s, " \t", &p);
    if (t == NULL) {
	kdc_log(0, "Malformed HTTP request from %s", addr);
	return -1;
    }
    t = strtok_r(NULL, " \t", &p);
    if(t == NULL) {
	kdc_log(0, "Malformed HTTP request from %s", addr);
	return -1;
    }
    data = malloc(strlen(t));
    if (data == NULL) {
	kdc_log(0, "Failed to allocate %u bytes", strlen(t));
	return -1;
    }
    if(*t == '/')
	t++;
    if(de_http(t) != 0) {
	kdc_log(0, "Malformed HTTP request from %s", addr);
	kdc_log(5, "Request: %s", t);
	free(data);
	return -1;
    }
    proto = strtok_r(NULL, " \t", &p);
    if (proto == NULL) {
	kdc_log(0, "Malformed HTTP request from %s", addr);
	free(data);
	return -1;
    }
    len = base64_decode(t, data);
    if(len <= 0){
	const char *msg = 
	    " 404 Not found\r\n"
	    "Server: Heimdal/" VERSION "\r\n"
	    "Content-type: text/html\r\n"
	    "Content-transfer-encoding: 8bit\r\n\r\n"
	    "<TITLE>404 Not found</TITLE>\r\n"
	    "<H1>404 Not found</H1>\r\n"
	    "That page doesn't exist, maybe you are looking for "
	    "<A HREF=\"http://www.pdc.kth.se/heimdal\">Heimdal</A>?\r\n";
	write(d->s, proto, strlen(proto));
	write(d->s, msg, strlen(msg));
	kdc_log(0, "HTTP request from %s is non KDC request", addr);
	kdc_log(5, "Request: %s", t);
	free(data);
	return -1;
    }
    {
	const char *msg = 
	    " 200 OK\r\n"
	    "Server: Heimdal/" VERSION "\r\n"
	    "Content-type: application/octet-stream\r\n"
	    "Content-transfer-encoding: binary\r\n\r\n";
	write(d->s, proto, strlen(proto));
	write(d->s, msg, strlen(msg));
    }
    memcpy(d->buf, data, len);
    d->len = len;
    free(data);
    return 1;
}

/*
 * Handle incoming data to the TCP socket in `d[index]'
 */

static void
handle_tcp(struct descr *d, int index, int min_free)
{
    unsigned char buf[1024];
    char addr[32];
    struct sockaddr_storage __ss;
    struct sockaddr *sa = (struct sockaddr *)&__ss;
    int from_len;
    int n;
    int ret = 0;

    if (d[index].timeout == 0) {
	add_new_tcp (d, index, min_free);
	return;
    }

    /*
     * We can't trust recvfrom to return an address so we always call
     * getpeername.
     */

    n = recvfrom(d[index].s, buf, sizeof(buf), 0, NULL, NULL);
    if(n < 0){
	krb5_warn(context, errno, "recvfrom");
	return;
    }
    from_len = sizeof(__ss);
    if (getpeername(d[index].s, sa, &from_len) < 0) {
	krb5_warn(context, errno, "getpeername");
	return;
    }
    addr_to_string(sa, from_len, addr, sizeof(addr));
    if (grow_descr (&d[index], n))
	return;
    memcpy(d[index].buf + d[index].len, buf, n);
    d[index].len += n;
    if(d[index].len > 4 && d[index].buf[0] == 0) {
	ret = handle_vanilla_tcp (&d[index]);
    } else if(enable_http &&
	      d[index].len >= 4 &&
	      strncmp((char *)d[index].buf, "GET ", 4) == 0 && 
	      strncmp((char *)d[index].buf + d[index].len - 4,
		      "\r\n\r\n", 4) == 0) {
	ret = handle_http_tcp (&d[index], addr);
	if (ret < 0)
	    clear_descr (d + index);
    } else if (d[index].len > 4) {
	kdc_log (0, "TCP data of strange type from %s", addr);
	return;
    }
    if (ret < 0)
	return;
    else if (ret == 1) {
	do_request(d[index].buf, d[index].len, 1,
		   d[index].s, sa, from_len);
	clear_descr(d + index);
    }
}

void
loop(void)
{
    struct descr *d;
    int ndescr;

    ndescr = init_sockets(&d);
    if(ndescr <= 0)
	krb5_errx(context, 1, "No sockets!");
    while(exit_flag == 0){
	struct timeval tmout;
	fd_set fds;
	int min_free = -1;
	int max_fd = 0;
	int i;
	FD_ZERO(&fds);
	for(i = 0; i < ndescr; i++){
	    if(d[i].s >= 0){
		if(d[i].type == SOCK_STREAM && 
		   d[i].timeout && d[i].timeout < time(NULL)){
		    struct sockaddr sa;
		    int salen = sizeof(sa);
		    char addr[32];

		    getpeername(d[i].s, &sa, &salen);
		    addr_to_string(&sa, salen, addr, sizeof(addr));
		    kdc_log(1, "TCP-connection from %s expired after %u bytes",
			    addr, d[i].len);
		    clear_descr(&d[i]);
		    continue;
		}
		if(max_fd < d[i].s)
		    max_fd = d[i].s;
		FD_SET(d[i].s, &fds);
	    }else if(min_free < 0 || i < min_free)
		min_free = i;
	}
	if(min_free == -1){
	    struct descr *tmp;
	    tmp = realloc(d, (ndescr + 4) * sizeof(*d));
	    if(tmp == NULL)
		krb5_warnx(context, "No memory");
	    else{
		d = tmp;
		memset(d + ndescr, 0, 4 * sizeof(*d));
		for(i = ndescr; i < ndescr + 4; i++)
		    d[i].s = -1;
		min_free = ndescr;
		ndescr += 4;
	    }
	}
    
	tmout.tv_sec = TCP_TIMEOUT;
	tmout.tv_usec = 0;
	switch(select(max_fd + 1, &fds, 0, 0, &tmout)){
	case 0:
	    break;
	case -1:
	    krb5_warn(context, errno, "select");
	    break;
	default:
	    for(i = 0; i < ndescr; i++)
		if(d[i].s >= 0 && FD_ISSET(d[i].s, &fds)) {
		    if(d[i].type == SOCK_DGRAM)
			handle_udp(&d[i]);
		    else if(d[i].type == SOCK_STREAM)
			handle_tcp(d, i, min_free);
		}
	}
    }
    free (d);
}
