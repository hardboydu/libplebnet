/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@FreeBSD.org> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * $FreeBSD$
 *
 */

#ifndef _SYS_JAIL_H_
#define _SYS_JAIL_H_

struct jail {
	u_int32_t	version;
	char		*path;
	char		*hostname;
	u_int32_t	ip_number;
};

#ifndef _KERNEL

int jail __P((struct jail *));

#else /* _KERNEL */

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_PRISON);
#endif

/*
 * This structure describes a prison.  It is pointed to by all struct
 * ucreds's of the inmates.  pr_ref keeps track of them and is used to
 * delete the struture when the last inmate is dead.
 *
 * XXX: Note: this structure needs a mutex to protect the reference count
 * and other mutable fields (pr_host, pr_linux).
 */

struct prison {
	int		pr_ref;
	char 		pr_host[MAXHOSTNAMELEN];
	u_int32_t	pr_ip;
	void		*pr_linux;
	int		pr_securelevel;
};

/*
 * Sysctl-set variables that determine global jail policy
 */
extern int	jail_set_hostname_allowed;
extern int	jail_socket_unixiproute_only;
extern int	jail_sysvipc_allowed;

/*
 * Kernel support functions for jail().
 */
struct ucred;
struct sockaddr;
int jailed __P((struct ucred *cred));
int prison_check __P((struct ucred *cred1, struct ucred *cred2));
void prison_free __P((struct prison *pr));
void prison_hold __P((struct prison *pr));
int prison_if __P((struct ucred *cred, struct sockaddr *sa));
int prison_ip __P((struct ucred *cred, int flag, u_int32_t *ip));
void prison_remote_ip __P((struct ucred *cred, int flags, u_int32_t *ip));

#endif /* !_KERNEL */
#endif /* !_SYS_JAIL_H_ */
