/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@FreeBSD.ORG> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * $FreeBSD$
 *
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

MALLOC_DEFINE(M_PRISON, "prison", "Prison structures");

int
jail(p, uap)
        struct proc *p;
        struct jail_args /* {
                syscallarg(struct jail *) jail;
        } */ *uap;
{
	int error;
	struct prison *pr;
	struct jail j;
	struct chroot_args ca;

	error = suser(p);
	if (error)
		return (error);
	error = copyin(uap->jail, &j, sizeof j);
	if (error)
		return (error);
	if (j.version != 0)
		return (EINVAL);
	MALLOC(pr, struct prison *, sizeof *pr , M_PRISON, M_WAITOK);
	bzero((caddr_t)pr, sizeof *pr);
	error = copyinstr(j.hostname, &pr->pr_host, sizeof pr->pr_host, 0);
	if (error) 
		goto bail;
	pr->pr_ip = j.ip_number;

	ca.path = j.path;
	error = chroot(p, &ca);
	if (error)
		goto bail;

	pr->pr_ref++;
	p->p_prison = pr;
	p->p_flag |= P_JAILED;
	return (0);

bail:
	FREE(pr, M_PRISON);
	return (error);
}

int
prison_ip(struct proc *p, int flag, u_int32_t *ip)
{
	u_int32_t tmp;

	if (!p->p_prison)
		return (0);
	if (flag) 
		tmp = *ip;
	else
		tmp = ntohl(*ip);
	if (tmp == INADDR_ANY) {
		if (flag) 
			*ip = p->p_prison->pr_ip;
		else
			*ip = htonl(p->p_prison->pr_ip);
		return (0);
	}
	if (p->p_prison->pr_ip != tmp)
		return (1);
	return (0);
}

void
prison_remote_ip(struct proc *p, int flag, u_int32_t *ip)
{
	u_int32_t tmp;

	if (!p || !p->p_prison)
		return;
	if (flag)
		tmp = *ip;
	else
		tmp = ntohl(*ip);
	if (tmp == 0x7f000001) {
		if (flag)
			*ip = p->p_prison->pr_ip;
		else
			*ip = htonl(p->p_prison->pr_ip);
		return;
	}
	return;
}

int
prison_if(struct proc *p, struct sockaddr *sa)
{
	struct sockaddr_in *sai = (struct sockaddr_in*) sa;
	int ok;

	if (sai->sin_family != AF_INET)
		ok = 0;
	else if (p->p_prison->pr_ip != ntohl(sai->sin_addr.s_addr))
		ok = 1;
	else
		ok = 0;
	return (ok);
}
