/*
 * System call prototypes.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * $FreeBSD$
 * created from FreeBSD: src/sys/compat/svr4/syscalls.master,v 1.15 2004/02/06 20:07:33 jhb Exp 
 */

#ifndef _SVR4_SYSPROTO_H_
#define	_SVR4_SYSPROTO_H_

#include <sys/signal.h>
#include <sys/acl.h>
#include <sys/thr.h>
#include <sys/umtx.h>
#include <posix4/_semaphore.h>

#include <sys/ucontext.h>

struct proc;

struct thread;

#define	PAD_(t)	(sizeof(register_t) <= sizeof(t) ? \
		0 : sizeof(register_t) - sizeof(t))

#if BYTE_ORDER == LITTLE_ENDIAN
#define	PADL_(t)	0
#define	PADR_(t)	PAD_(t)
#else
#define	PADL_(t)	PAD_(t)
#define	PADR_(t)	0
#endif

struct svr4_sys_open_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char mode_l_[PADL_(int)]; int mode; char mode_r_[PADR_(int)];
};
struct svr4_sys_wait_args {
	char status_l_[PADL_(int *)]; int * status; char status_r_[PADR_(int *)];
};
struct svr4_sys_creat_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char mode_l_[PADL_(int)]; int mode; char mode_r_[PADR_(int)];
};
struct svr4_sys_execv_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char argp_l_[PADL_(char **)]; char ** argp; char argp_r_[PADR_(char **)];
};
struct svr4_sys_time_args {
	char t_l_[PADL_(time_t *)]; time_t * t; char t_r_[PADR_(time_t *)];
};
struct svr4_sys_mknod_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char mode_l_[PADL_(int)]; int mode; char mode_r_[PADR_(int)];
	char dev_l_[PADL_(int)]; int dev; char dev_r_[PADR_(int)];
};
struct svr4_sys_break_args {
	char nsize_l_[PADL_(caddr_t)]; caddr_t nsize; char nsize_r_[PADR_(caddr_t)];
};
struct svr4_sys_stat_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char ub_l_[PADL_(struct svr4_stat *)]; struct svr4_stat * ub; char ub_r_[PADR_(struct svr4_stat *)];
};
struct svr4_sys_alarm_args {
	char sec_l_[PADL_(unsigned)]; unsigned sec; char sec_r_[PADR_(unsigned)];
};
struct svr4_sys_fstat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char sb_l_[PADL_(struct svr4_stat *)]; struct svr4_stat * sb; char sb_r_[PADR_(struct svr4_stat *)];
};
struct svr4_sys_pause_args {
	register_t dummy;
};
struct svr4_sys_utime_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char ubuf_l_[PADL_(struct svr4_utimbuf *)]; struct svr4_utimbuf * ubuf; char ubuf_r_[PADR_(struct svr4_utimbuf *)];
};
struct svr4_sys_access_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct svr4_sys_nice_args {
	char prio_l_[PADL_(int)]; int prio; char prio_r_[PADR_(int)];
};
struct svr4_sys_kill_args {
	char pid_l_[PADL_(int)]; int pid; char pid_r_[PADR_(int)];
	char signum_l_[PADL_(int)]; int signum; char signum_r_[PADR_(int)];
};
struct svr4_sys_pgrpsys_args {
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char pid_l_[PADL_(int)]; int pid; char pid_r_[PADR_(int)];
	char pgid_l_[PADL_(int)]; int pgid; char pgid_r_[PADR_(int)];
};
struct svr4_sys_times_args {
	char tp_l_[PADL_(struct tms *)]; struct tms * tp; char tp_r_[PADR_(struct tms *)];
};
struct svr4_sys_signal_args {
	char signum_l_[PADL_(int)]; int signum; char signum_r_[PADR_(int)];
	char handler_l_[PADL_(svr4_sig_t)]; svr4_sig_t handler; char handler_r_[PADR_(svr4_sig_t)];
};
#if defined(NOTYET)
struct svr4_sys_msgsys_args {
	char what_l_[PADL_(int)]; int what; char what_r_[PADR_(int)];
	char a2_l_[PADL_(int)]; int a2; char a2_r_[PADR_(int)];
	char a3_l_[PADL_(int)]; int a3; char a3_r_[PADR_(int)];
	char a4_l_[PADL_(int)]; int a4; char a4_r_[PADR_(int)];
	char a5_l_[PADL_(int)]; int a5; char a5_r_[PADR_(int)];
};
#else
#endif
struct svr4_sys_sysarch_args {
	char op_l_[PADL_(int)]; int op; char op_r_[PADR_(int)];
	char a1_l_[PADL_(void *)]; void * a1; char a1_r_[PADR_(void *)];
};
struct svr4_sys_ioctl_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char com_l_[PADL_(u_long)]; u_long com; char com_r_[PADR_(u_long)];
	char data_l_[PADL_(caddr_t)]; caddr_t data; char data_r_[PADR_(caddr_t)];
};
struct svr4_sys_utssys_args {
	char a1_l_[PADL_(void *)]; void * a1; char a1_r_[PADR_(void *)];
	char a2_l_[PADL_(void *)]; void * a2; char a2_r_[PADR_(void *)];
	char sel_l_[PADL_(int)]; int sel; char sel_r_[PADR_(int)];
	char a3_l_[PADL_(void *)]; void * a3; char a3_r_[PADR_(void *)];
};
struct svr4_sys_execve_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char argp_l_[PADL_(char **)]; char ** argp; char argp_r_[PADR_(char **)];
	char envp_l_[PADL_(char **)]; char ** envp; char envp_r_[PADR_(char **)];
};
struct svr4_sys_fcntl_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char arg_l_[PADL_(char *)]; char * arg; char arg_r_[PADR_(char *)];
};
struct svr4_sys_ulimit_args {
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char newlimit_l_[PADL_(long)]; long newlimit; char newlimit_r_[PADR_(long)];
};
struct svr4_sys_getdents_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(char *)]; char * buf; char buf_r_[PADR_(char *)];
	char nbytes_l_[PADL_(int)]; int nbytes; char nbytes_r_[PADR_(int)];
};
struct svr4_sys_getmsg_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char ctl_l_[PADL_(struct svr4_strbuf *)]; struct svr4_strbuf * ctl; char ctl_r_[PADR_(struct svr4_strbuf *)];
	char dat_l_[PADL_(struct svr4_strbuf *)]; struct svr4_strbuf * dat; char dat_r_[PADR_(struct svr4_strbuf *)];
	char flags_l_[PADL_(int *)]; int * flags; char flags_r_[PADR_(int *)];
};
struct svr4_sys_putmsg_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char ctl_l_[PADL_(struct svr4_strbuf *)]; struct svr4_strbuf * ctl; char ctl_r_[PADR_(struct svr4_strbuf *)];
	char dat_l_[PADL_(struct svr4_strbuf *)]; struct svr4_strbuf * dat; char dat_r_[PADR_(struct svr4_strbuf *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct svr4_sys_poll_args {
	char fds_l_[PADL_(struct pollfd *)]; struct pollfd * fds; char fds_r_[PADR_(struct pollfd *)];
	char nfds_l_[PADL_(unsigned int)]; unsigned int nfds; char nfds_r_[PADR_(unsigned int)];
	char timeout_l_[PADL_(int)]; int timeout; char timeout_r_[PADR_(int)];
};
struct svr4_sys_lstat_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char ub_l_[PADL_(struct svr4_stat *)]; struct svr4_stat * ub; char ub_r_[PADR_(struct svr4_stat *)];
};
struct svr4_sys_sigprocmask_args {
	char how_l_[PADL_(int)]; int how; char how_r_[PADR_(int)];
	char set_l_[PADL_(svr4_sigset_t *)]; svr4_sigset_t * set; char set_r_[PADR_(svr4_sigset_t *)];
	char oset_l_[PADL_(svr4_sigset_t *)]; svr4_sigset_t * oset; char oset_r_[PADR_(svr4_sigset_t *)];
};
struct svr4_sys_sigsuspend_args {
	char ss_l_[PADL_(svr4_sigset_t *)]; svr4_sigset_t * ss; char ss_r_[PADR_(svr4_sigset_t *)];
};
struct svr4_sys_sigaltstack_args {
	char nss_l_[PADL_(struct svr4_sigaltstack *)]; struct svr4_sigaltstack * nss; char nss_r_[PADR_(struct svr4_sigaltstack *)];
	char oss_l_[PADL_(struct svr4_sigaltstack *)]; struct svr4_sigaltstack * oss; char oss_r_[PADR_(struct svr4_sigaltstack *)];
};
struct svr4_sys_sigaction_args {
	char signum_l_[PADL_(int)]; int signum; char signum_r_[PADR_(int)];
	char nsa_l_[PADL_(struct svr4_sigaction *)]; struct svr4_sigaction * nsa; char nsa_r_[PADR_(struct svr4_sigaction *)];
	char osa_l_[PADL_(struct svr4_sigaction *)]; struct svr4_sigaction * osa; char osa_r_[PADR_(struct svr4_sigaction *)];
};
struct svr4_sys_sigpending_args {
	char what_l_[PADL_(int)]; int what; char what_r_[PADR_(int)];
	char mask_l_[PADL_(svr4_sigset_t *)]; svr4_sigset_t * mask; char mask_r_[PADR_(svr4_sigset_t *)];
};
struct svr4_sys_context_args {
	char func_l_[PADL_(int)]; int func; char func_r_[PADR_(int)];
	char uc_l_[PADL_(struct svr4_ucontext *)]; struct svr4_ucontext * uc; char uc_r_[PADR_(struct svr4_ucontext *)];
};
struct svr4_sys_statvfs_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char fs_l_[PADL_(struct svr4_statvfs *)]; struct svr4_statvfs * fs; char fs_r_[PADR_(struct svr4_statvfs *)];
};
struct svr4_sys_fstatvfs_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char fs_l_[PADL_(struct svr4_statvfs *)]; struct svr4_statvfs * fs; char fs_r_[PADR_(struct svr4_statvfs *)];
};
struct svr4_sys_waitsys_args {
	char grp_l_[PADL_(int)]; int grp; char grp_r_[PADR_(int)];
	char id_l_[PADL_(int)]; int id; char id_r_[PADR_(int)];
	char info_l_[PADL_(union svr4_siginfo *)]; union svr4_siginfo * info; char info_r_[PADR_(union svr4_siginfo *)];
	char options_l_[PADL_(int)]; int options; char options_r_[PADR_(int)];
};
struct svr4_sys_hrtsys_args {
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char fun_l_[PADL_(int)]; int fun; char fun_r_[PADR_(int)];
	char sub_l_[PADL_(int)]; int sub; char sub_r_[PADR_(int)];
	char rv1_l_[PADL_(void *)]; void * rv1; char rv1_r_[PADR_(void *)];
	char rv2_l_[PADL_(void *)]; void * rv2; char rv2_r_[PADR_(void *)];
};
struct svr4_sys_pathconf_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char name_l_[PADL_(int)]; int name; char name_r_[PADR_(int)];
};
struct svr4_sys_mmap_args {
	char addr_l_[PADL_(caddr_t)]; caddr_t addr; char addr_r_[PADR_(caddr_t)];
	char len_l_[PADL_(svr4_size_t)]; svr4_size_t len; char len_r_[PADR_(svr4_size_t)];
	char prot_l_[PADL_(int)]; int prot; char prot_r_[PADR_(int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char pos_l_[PADL_(svr4_off_t)]; svr4_off_t pos; char pos_r_[PADR_(svr4_off_t)];
};
struct svr4_sys_fpathconf_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char name_l_[PADL_(int)]; int name; char name_r_[PADR_(int)];
};
struct svr4_sys_xstat_args {
	char two_l_[PADL_(int)]; int two; char two_r_[PADR_(int)];
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char ub_l_[PADL_(struct svr4_xstat *)]; struct svr4_xstat * ub; char ub_r_[PADR_(struct svr4_xstat *)];
};
struct svr4_sys_lxstat_args {
	char two_l_[PADL_(int)]; int two; char two_r_[PADR_(int)];
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char ub_l_[PADL_(struct svr4_xstat *)]; struct svr4_xstat * ub; char ub_r_[PADR_(struct svr4_xstat *)];
};
struct svr4_sys_fxstat_args {
	char two_l_[PADL_(int)]; int two; char two_r_[PADR_(int)];
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char sb_l_[PADL_(struct svr4_xstat *)]; struct svr4_xstat * sb; char sb_r_[PADR_(struct svr4_xstat *)];
};
struct svr4_sys_xmknod_args {
	char two_l_[PADL_(int)]; int two; char two_r_[PADR_(int)];
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char mode_l_[PADL_(svr4_mode_t)]; svr4_mode_t mode; char mode_r_[PADR_(svr4_mode_t)];
	char dev_l_[PADL_(svr4_dev_t)]; svr4_dev_t dev; char dev_r_[PADR_(svr4_dev_t)];
};
struct svr4_sys_setrlimit_args {
	char which_l_[PADL_(int)]; int which; char which_r_[PADR_(int)];
	char rlp_l_[PADL_(const struct svr4_rlimit *)]; const struct svr4_rlimit * rlp; char rlp_r_[PADR_(const struct svr4_rlimit *)];
};
struct svr4_sys_getrlimit_args {
	char which_l_[PADL_(int)]; int which; char which_r_[PADR_(int)];
	char rlp_l_[PADL_(struct svr4_rlimit *)]; struct svr4_rlimit * rlp; char rlp_r_[PADR_(struct svr4_rlimit *)];
};
struct svr4_sys_memcntl_args {
	char addr_l_[PADL_(void *)]; void * addr; char addr_r_[PADR_(void *)];
	char len_l_[PADL_(svr4_size_t)]; svr4_size_t len; char len_r_[PADR_(svr4_size_t)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char arg_l_[PADL_(void *)]; void * arg; char arg_r_[PADR_(void *)];
	char attr_l_[PADL_(int)]; int attr; char attr_r_[PADR_(int)];
	char mask_l_[PADL_(int)]; int mask; char mask_r_[PADR_(int)];
};
struct svr4_sys_uname_args {
	char name_l_[PADL_(struct svr4_utsname *)]; struct svr4_utsname * name; char name_r_[PADR_(struct svr4_utsname *)];
	char dummy_l_[PADL_(int)]; int dummy; char dummy_r_[PADR_(int)];
};
struct svr4_sys_sysconfig_args {
	char name_l_[PADL_(int)]; int name; char name_r_[PADR_(int)];
};
struct svr4_sys_systeminfo_args {
	char what_l_[PADL_(int)]; int what; char what_r_[PADR_(int)];
	char buf_l_[PADL_(char *)]; char * buf; char buf_r_[PADR_(char *)];
	char len_l_[PADL_(long)]; long len; char len_r_[PADR_(long)];
};
struct svr4_sys_fchroot_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
};
struct svr4_sys_utimes_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char tptr_l_[PADL_(struct timeval *)]; struct timeval * tptr; char tptr_r_[PADR_(struct timeval *)];
};
struct svr4_sys_vhangup_args {
	register_t dummy;
};
struct svr4_sys_gettimeofday_args {
	char tp_l_[PADL_(struct timeval *)]; struct timeval * tp; char tp_r_[PADR_(struct timeval *)];
};
struct svr4_sys_llseek_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char offset1_l_[PADL_(long)]; long offset1; char offset1_r_[PADR_(long)];
	char offset2_l_[PADL_(long)]; long offset2; char offset2_r_[PADR_(long)];
	char whence_l_[PADL_(int)]; int whence; char whence_r_[PADR_(int)];
};
struct svr4_sys_acl_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char num_l_[PADL_(int)]; int num; char num_r_[PADR_(int)];
	char buf_l_[PADL_(struct svr4_aclent *)]; struct svr4_aclent * buf; char buf_r_[PADR_(struct svr4_aclent *)];
};
struct svr4_sys_auditsys_args {
	char code_l_[PADL_(int)]; int code; char code_r_[PADR_(int)];
	char a1_l_[PADL_(int)]; int a1; char a1_r_[PADR_(int)];
	char a2_l_[PADL_(int)]; int a2; char a2_r_[PADR_(int)];
	char a3_l_[PADL_(int)]; int a3; char a3_r_[PADR_(int)];
	char a4_l_[PADL_(int)]; int a4; char a4_r_[PADR_(int)];
	char a5_l_[PADL_(int)]; int a5; char a5_r_[PADR_(int)];
};
struct svr4_sys_facl_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char num_l_[PADL_(int)]; int num; char num_r_[PADR_(int)];
	char buf_l_[PADL_(struct svr4_aclent *)]; struct svr4_aclent * buf; char buf_r_[PADR_(struct svr4_aclent *)];
};
struct svr4_sys_resolvepath_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char buf_l_[PADL_(char *)]; char * buf; char buf_r_[PADR_(char *)];
	char bufsiz_l_[PADL_(size_t)]; size_t bufsiz; char bufsiz_r_[PADR_(size_t)];
};
struct svr4_sys_getdents64_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char dp_l_[PADL_(struct svr4_dirent64 *)]; struct svr4_dirent64 * dp; char dp_r_[PADR_(struct svr4_dirent64 *)];
	char nbytes_l_[PADL_(int)]; int nbytes; char nbytes_r_[PADR_(int)];
};
struct svr4_sys_mmap64_args {
	char addr_l_[PADL_(void *)]; void * addr; char addr_r_[PADR_(void *)];
	char len_l_[PADL_(svr4_size_t)]; svr4_size_t len; char len_r_[PADR_(svr4_size_t)];
	char prot_l_[PADL_(int)]; int prot; char prot_r_[PADR_(int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char pos_l_[PADL_(svr4_off64_t)]; svr4_off64_t pos; char pos_r_[PADR_(svr4_off64_t)];
};
struct svr4_sys_stat64_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char sb_l_[PADL_(struct svr4_stat64 *)]; struct svr4_stat64 * sb; char sb_r_[PADR_(struct svr4_stat64 *)];
};
struct svr4_sys_lstat64_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char sb_l_[PADL_(struct svr4_stat64 *)]; struct svr4_stat64 * sb; char sb_r_[PADR_(struct svr4_stat64 *)];
};
struct svr4_sys_fstat64_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char sb_l_[PADL_(struct svr4_stat64 *)]; struct svr4_stat64 * sb; char sb_r_[PADR_(struct svr4_stat64 *)];
};
struct svr4_sys_statvfs64_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char fs_l_[PADL_(struct svr4_statvfs64 *)]; struct svr4_statvfs64 * fs; char fs_r_[PADR_(struct svr4_statvfs64 *)];
};
struct svr4_sys_fstatvfs64_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char fs_l_[PADL_(struct svr4_statvfs64 *)]; struct svr4_statvfs64 * fs; char fs_r_[PADR_(struct svr4_statvfs64 *)];
};
struct svr4_sys_setrlimit64_args {
	char which_l_[PADL_(int)]; int which; char which_r_[PADR_(int)];
	char rlp_l_[PADL_(const struct svr4_rlimit64 *)]; const struct svr4_rlimit64 * rlp; char rlp_r_[PADR_(const struct svr4_rlimit64 *)];
};
struct svr4_sys_getrlimit64_args {
	char which_l_[PADL_(int)]; int which; char which_r_[PADR_(int)];
	char rlp_l_[PADL_(struct svr4_rlimit64 *)]; struct svr4_rlimit64 * rlp; char rlp_r_[PADR_(struct svr4_rlimit64 *)];
};
struct svr4_sys_creat64_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char mode_l_[PADL_(int)]; int mode; char mode_r_[PADR_(int)];
};
struct svr4_sys_open64_args {
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char mode_l_[PADL_(int)]; int mode; char mode_r_[PADR_(int)];
};
struct svr4_sys_socket_args {
	char domain_l_[PADL_(int)]; int domain; char domain_r_[PADR_(int)];
	char type_l_[PADL_(int)]; int type; char type_r_[PADR_(int)];
	char protocol_l_[PADL_(int)]; int protocol; char protocol_r_[PADR_(int)];
};
struct svr4_sys_recv_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char buf_l_[PADL_(caddr_t)]; caddr_t buf; char buf_r_[PADR_(caddr_t)];
	char len_l_[PADL_(int)]; int len; char len_r_[PADR_(int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct svr4_sys_send_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char buf_l_[PADL_(caddr_t)]; caddr_t buf; char buf_r_[PADR_(caddr_t)];
	char len_l_[PADL_(int)]; int len; char len_r_[PADR_(int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct svr4_sys_sendto_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char buf_l_[PADL_(void *)]; void * buf; char buf_r_[PADR_(void *)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char to_l_[PADL_(struct sockaddr *)]; struct sockaddr * to; char to_r_[PADR_(struct sockaddr *)];
	char tolen_l_[PADL_(int)]; int tolen; char tolen_r_[PADR_(int)];
};
int	svr4_sys_open(struct thread *, struct svr4_sys_open_args *);
int	svr4_sys_wait(struct thread *, struct svr4_sys_wait_args *);
int	svr4_sys_creat(struct thread *, struct svr4_sys_creat_args *);
int	svr4_sys_execv(struct thread *, struct svr4_sys_execv_args *);
int	svr4_sys_time(struct thread *, struct svr4_sys_time_args *);
int	svr4_sys_mknod(struct thread *, struct svr4_sys_mknod_args *);
int	svr4_sys_break(struct thread *, struct svr4_sys_break_args *);
int	svr4_sys_stat(struct thread *, struct svr4_sys_stat_args *);
int	svr4_sys_alarm(struct thread *, struct svr4_sys_alarm_args *);
int	svr4_sys_fstat(struct thread *, struct svr4_sys_fstat_args *);
int	svr4_sys_pause(struct thread *, struct svr4_sys_pause_args *);
int	svr4_sys_utime(struct thread *, struct svr4_sys_utime_args *);
int	svr4_sys_access(struct thread *, struct svr4_sys_access_args *);
int	svr4_sys_nice(struct thread *, struct svr4_sys_nice_args *);
int	svr4_sys_kill(struct thread *, struct svr4_sys_kill_args *);
int	svr4_sys_pgrpsys(struct thread *, struct svr4_sys_pgrpsys_args *);
int	svr4_sys_times(struct thread *, struct svr4_sys_times_args *);
int	svr4_sys_signal(struct thread *, struct svr4_sys_signal_args *);
#if defined(NOTYET)
int	svr4_sys_msgsys(struct thread *, struct svr4_sys_msgsys_args *);
#else
#endif
int	svr4_sys_sysarch(struct thread *, struct svr4_sys_sysarch_args *);
int	svr4_sys_ioctl(struct thread *, struct svr4_sys_ioctl_args *);
int	svr4_sys_utssys(struct thread *, struct svr4_sys_utssys_args *);
int	svr4_sys_execve(struct thread *, struct svr4_sys_execve_args *);
int	svr4_sys_fcntl(struct thread *, struct svr4_sys_fcntl_args *);
int	svr4_sys_ulimit(struct thread *, struct svr4_sys_ulimit_args *);
int	svr4_sys_getdents(struct thread *, struct svr4_sys_getdents_args *);
int	svr4_sys_getmsg(struct thread *, struct svr4_sys_getmsg_args *);
int	svr4_sys_putmsg(struct thread *, struct svr4_sys_putmsg_args *);
int	svr4_sys_poll(struct thread *, struct svr4_sys_poll_args *);
int	svr4_sys_lstat(struct thread *, struct svr4_sys_lstat_args *);
int	svr4_sys_sigprocmask(struct thread *, struct svr4_sys_sigprocmask_args *);
int	svr4_sys_sigsuspend(struct thread *, struct svr4_sys_sigsuspend_args *);
int	svr4_sys_sigaltstack(struct thread *, struct svr4_sys_sigaltstack_args *);
int	svr4_sys_sigaction(struct thread *, struct svr4_sys_sigaction_args *);
int	svr4_sys_sigpending(struct thread *, struct svr4_sys_sigpending_args *);
int	svr4_sys_context(struct thread *, struct svr4_sys_context_args *);
int	svr4_sys_statvfs(struct thread *, struct svr4_sys_statvfs_args *);
int	svr4_sys_fstatvfs(struct thread *, struct svr4_sys_fstatvfs_args *);
int	svr4_sys_waitsys(struct thread *, struct svr4_sys_waitsys_args *);
int	svr4_sys_hrtsys(struct thread *, struct svr4_sys_hrtsys_args *);
int	svr4_sys_pathconf(struct thread *, struct svr4_sys_pathconf_args *);
int	svr4_sys_mmap(struct thread *, struct svr4_sys_mmap_args *);
int	svr4_sys_fpathconf(struct thread *, struct svr4_sys_fpathconf_args *);
int	svr4_sys_xstat(struct thread *, struct svr4_sys_xstat_args *);
int	svr4_sys_lxstat(struct thread *, struct svr4_sys_lxstat_args *);
int	svr4_sys_fxstat(struct thread *, struct svr4_sys_fxstat_args *);
int	svr4_sys_xmknod(struct thread *, struct svr4_sys_xmknod_args *);
int	svr4_sys_setrlimit(struct thread *, struct svr4_sys_setrlimit_args *);
int	svr4_sys_getrlimit(struct thread *, struct svr4_sys_getrlimit_args *);
int	svr4_sys_memcntl(struct thread *, struct svr4_sys_memcntl_args *);
int	svr4_sys_uname(struct thread *, struct svr4_sys_uname_args *);
int	svr4_sys_sysconfig(struct thread *, struct svr4_sys_sysconfig_args *);
int	svr4_sys_systeminfo(struct thread *, struct svr4_sys_systeminfo_args *);
int	svr4_sys_fchroot(struct thread *, struct svr4_sys_fchroot_args *);
int	svr4_sys_utimes(struct thread *, struct svr4_sys_utimes_args *);
int	svr4_sys_vhangup(struct thread *, struct svr4_sys_vhangup_args *);
int	svr4_sys_gettimeofday(struct thread *, struct svr4_sys_gettimeofday_args *);
int	svr4_sys_llseek(struct thread *, struct svr4_sys_llseek_args *);
int	svr4_sys_acl(struct thread *, struct svr4_sys_acl_args *);
int	svr4_sys_auditsys(struct thread *, struct svr4_sys_auditsys_args *);
int	svr4_sys_facl(struct thread *, struct svr4_sys_facl_args *);
int	svr4_sys_resolvepath(struct thread *, struct svr4_sys_resolvepath_args *);
int	svr4_sys_getdents64(struct thread *, struct svr4_sys_getdents64_args *);
int	svr4_sys_mmap64(struct thread *, struct svr4_sys_mmap64_args *);
int	svr4_sys_stat64(struct thread *, struct svr4_sys_stat64_args *);
int	svr4_sys_lstat64(struct thread *, struct svr4_sys_lstat64_args *);
int	svr4_sys_fstat64(struct thread *, struct svr4_sys_fstat64_args *);
int	svr4_sys_statvfs64(struct thread *, struct svr4_sys_statvfs64_args *);
int	svr4_sys_fstatvfs64(struct thread *, struct svr4_sys_fstatvfs64_args *);
int	svr4_sys_setrlimit64(struct thread *, struct svr4_sys_setrlimit64_args *);
int	svr4_sys_getrlimit64(struct thread *, struct svr4_sys_getrlimit64_args *);
int	svr4_sys_creat64(struct thread *, struct svr4_sys_creat64_args *);
int	svr4_sys_open64(struct thread *, struct svr4_sys_open64_args *);
int	svr4_sys_socket(struct thread *, struct svr4_sys_socket_args *);
int	svr4_sys_recv(struct thread *, struct svr4_sys_recv_args *);
int	svr4_sys_send(struct thread *, struct svr4_sys_send_args *);
int	svr4_sys_sendto(struct thread *, struct svr4_sys_sendto_args *);

#ifdef COMPAT_43

#if defined(NOTYET)
#else
#endif

#endif /* COMPAT_43 */


#ifdef COMPAT_FREEBSD4

#if defined(NOTYET)
#else
#endif

#endif /* COMPAT_FREEBSD4 */

#undef PAD_
#undef PADL_
#undef PADR_

#endif /* !_SVR4_SYSPROTO_H_ */
