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
#include <sys/sysctl.h>
#include <net/if.h>
#include <netinet/in.h>

MALLOC_DEFINE(M_PRISON, "prison", "Prison structures");

SYSCTL_NODE(, OID_AUTO, jail, CTLFLAG_RW, 0,
    "Jail rules");

int	jail_set_hostname_allowed = 1;
SYSCTL_INT(_jail, OID_AUTO, set_hostname_allowed, CTLFLAG_RW,
    &jail_set_hostname_allowed, 0,
    "Processes in jail can set their hostnames");

int	jail_socket_unixiproute_only = 1;
SYSCTL_INT(_jail, OID_AUTO, socket_unixiproute_only, CTLFLAG_RW,
    &jail_socket_unixiproute_only, 0,
    "Processes in jail are limited to creating UNIX/IPv4/route sockets only");

int	jail_sysvipc_allowed = 0;
SYSCTL_INT(_jail, OID_AUTO, sysvipc_allowed, CTLFLAG_RW,
    &jail_sysvipc_allowed, 0,
    "Processes in jail can use System V IPC primitives");

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

	/* Implicitly fail if already in jail.  */
	error = suser(p);
	if (error)
		return (error);
	error = copyin(uap->jail, &j, sizeof j);
	if (error)
		return (error);
	if (j.version != 0)
		return (EINVAL);
	MALLOC(pr, struct prison *, sizeof *pr , M_PRISON, M_WAITOK | M_ZERO);
	error = copyinstr(j.hostname, &pr->pr_host, sizeof pr->pr_host, 0);
	if (error) 
		goto bail;
	pr->pr_ip = j.ip_number;

	ca.path = j.path;
	error = chroot(p, &ca);
	if (error)
		goto bail;

	p->p_ucred = crcopy(p->p_ucred);
	p->p_ucred->cr_prison = pr;
	pr->pr_ref = 1;
	return (0);

bail:
	FREE(pr, M_PRISON);
	return (error);
}

void
prison_free(struct prison *pr)
{

	pr->pr_ref--;
	if (pr->pr_ref == 0) {
		if (pr->pr_linux != NULL)
			FREE(pr->pr_linux, M_PRISON);
		FREE(pr, M_PRISON);
	}
}

void
prison_hold(struct prison *pr)
{

	pr->pr_ref++;
}

int
prison_ip(struct ucred *cred, int flag, u_int32_t *ip)
{
	u_int32_t tmp;

	if (!jailed(cred))
		return (0);
	if (flag) 
		tmp = *ip;
	else
		tmp = ntohl(*ip);
	if (tmp == INADDR_ANY) {
		if (flag) 
			*ip = cred->cr_prison->pr_ip;
		else
			*ip = htonl(cred->cr_prison->pr_ip);
		return (0);
	}
	if (cred->cr_prison->pr_ip != tmp)
		return (1);
	return (0);
}

void
prison_remote_ip(struct ucred *cred, int flag, u_int32_t *ip)
{
	u_int32_t tmp;

	if (!jailed(cred))
		return;
	if (flag)
		tmp = *ip;
	else
		tmp = ntohl(*ip);
	if (tmp == 0x7f000001) {
		if (flag)
			*ip = cred->cr_prison->pr_ip;
		else
			*ip = htonl(cred->cr_prison->pr_ip);
		return;
	}
	return;
}

int
prison_if(struct ucred *cred, struct sockaddr *sa)
{
	struct sockaddr_in *sai = (struct sockaddr_in*) sa;
	int ok;

	if ((sai->sin_family != AF_INET) && jail_socket_unixiproute_only)
		ok = 1;
	else if (sai->sin_family != AF_INET)
		ok = 0;
	else if (cred->cr_prison->pr_ip != ntohl(sai->sin_addr.s_addr))
		ok = 1;
	else
		ok = 0;
	return (ok);
}

/*
 * Return 0 if jails permit p1 to frob p2, otherwise ESRCH.
 */
int
prison_check(cred1, cred2)
	struct ucred *cred1, *cred2;
{

	if (jailed(cred1)) {
		if (!jailed(cred2))
			return (ESRCH);
		if (cred2->cr_prison != cred1->cr_prison)
			return (ESRCH);
	}

	return (0);
}

/*
 * Return 1 if the passed credential is in a jail, otherwise 0.
 */
int
jailed(cred)
	struct ucred *cred;
{

	return (cred->cr_prison != NULL);
}
