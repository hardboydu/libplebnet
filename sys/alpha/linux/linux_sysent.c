/*
 * System call switch table.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * $FreeBSD$
 * created from FreeBSD: src/sys/alpha/linux/syscalls.master,v 1.66 2006/02/06 01:13:47 rwatson Exp 
 */

#include <bsm/audit_kevents.h>
#include "opt_compat.h"
#include <sys/param.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <compat/linux/linux_sysproto.h>
#include <alpha/linux/linux.h>
#include <alpha/linux/linux_proto.h>

#define AS(name) (sizeof(struct name) / sizeof(register_t))

/* The casts are bogus but will do for now. */
struct sysent linux_sysent[] = {
#define	nosys	linux_nosys
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 0 =  */
	{ SYF_MPSAFE | AS(sys_exit_args), (sy_call_t *)sys_exit, AUE_EXIT },	/* 1 = exit */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_fork, AUE_FORK },	/* 2 = linux_fork */
	{ SYF_MPSAFE | AS(read_args), (sy_call_t *)read, AUE_READ },	/* 3 = read */
	{ SYF_MPSAFE | AS(write_args), (sy_call_t *)write, AUE_WRITE },	/* 4 = write */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 5 =  */
	{ SYF_MPSAFE | AS(close_args), (sy_call_t *)close, AUE_CLOSE },	/* 6 = close */
	{ SYF_MPSAFE | AS(osf1_wait4_args), (sy_call_t *)osf1_wait4, AUE_WAIT4 },	/* 7 = osf1_wait4 */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 8 =  */
	{ SYF_MPSAFE | AS(linux_link_args), (sy_call_t *)linux_link, AUE_LINK },	/* 9 = linux_link */
	{ SYF_MPSAFE | AS(linux_unlink_args), (sy_call_t *)linux_unlink, AUE_UNLINK },	/* 10 = linux_unlink */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 11 =  */
	{ SYF_MPSAFE | AS(linux_chdir_args), (sy_call_t *)linux_chdir, AUE_CHDIR },	/* 12 = linux_chdir */
	{ SYF_MPSAFE | AS(fchdir_args), (sy_call_t *)fchdir, AUE_FCHDIR },	/* 13 = fchdir */
	{ SYF_MPSAFE | AS(linux_mknod_args), (sy_call_t *)linux_mknod, AUE_MKNOD },	/* 14 = linux_mknod */
	{ SYF_MPSAFE | AS(linux_chmod_args), (sy_call_t *)linux_chmod, AUE_CHMOD },	/* 15 = linux_chmod */
	{ SYF_MPSAFE | AS(linux_chown_args), (sy_call_t *)linux_chown, AUE_CHOWN },	/* 16 = linux_chown */
	{ AS(linux_brk_args), (sy_call_t *)linux_brk, AUE_NULL },	/* 17 = linux_brk */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 18 =  */
	{ SYF_MPSAFE | AS(linux_lseek_args), (sy_call_t *)linux_lseek, AUE_LSEEK },	/* 19 = linux_lseek */
	{ SYF_MPSAFE | 0, (sy_call_t *)getpid, AUE_GETPID },	/* 20 = getpid */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 21 = osf1_mount */
	{ AS(linux_umount_args), (sy_call_t *)linux_umount, AUE_UNMOUNT },	/* 22 = linux_umount */
	{ SYF_MPSAFE | AS(setuid_args), (sy_call_t *)setuid, AUE_SETUID },	/* 23 = setuid */
	{ SYF_MPSAFE | 0, (sy_call_t *)getuid, AUE_GETUID },	/* 24 = getuid */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 25 =  */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_ptrace, AUE_PTRACE },	/* 26 = linux_ptrace */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 27 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 28 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 29 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 30 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 31 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 32 =  */
	{ SYF_MPSAFE | AS(linux_access_args), (sy_call_t *)linux_access, AUE_ACCESS },	/* 33 = linux_access */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 34 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 35 =  */
	{ SYF_MPSAFE | 0, (sy_call_t *)sync, AUE_SYNC },	/* 36 = sync */
	{ SYF_MPSAFE | AS(linux_kill_args), (sy_call_t *)linux_kill, AUE_KILL },	/* 37 = linux_kill */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 38 =  */
	{ SYF_MPSAFE | AS(setpgid_args), (sy_call_t *)setpgid, AUE_SETPGRP },	/* 39 = setpgid */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 40 =  */
	{ SYF_MPSAFE | AS(dup_args), (sy_call_t *)dup, AUE_DUP },	/* 41 = dup */
	{ SYF_MPSAFE | 0, (sy_call_t *)pipe, AUE_PIPE },	/* 42 = pipe */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 43 = osf_set_program_attributes */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 44 =  */
	{ SYF_MPSAFE | AS(linux_open_args), (sy_call_t *)linux_open, AUE_OPEN_RWTC },	/* 45 = linux_open */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 46 =  */
	{ SYF_MPSAFE | 0, (sy_call_t *)getgid, AUE_GETGID },	/* 47 = getgid */
	{ SYF_MPSAFE | AS(osf1_sigprocmask_args), (sy_call_t *)osf1_sigprocmask, AUE_SIGPROCMASK },	/* 48 = osf1_sigprocmask */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 49 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 50 =  */
	{ SYF_MPSAFE | AS(acct_args), (sy_call_t *)acct, AUE_ACCT },	/* 51 = acct */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_sigpending, AUE_SIGPENDING },	/* 52 = linux_sigpending */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 53 =  */
	{ AS(linux_ioctl_args), (sy_call_t *)linux_ioctl, AUE_IOCTL },	/* 54 = linux_ioctl */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 55 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 56 =  */
	{ SYF_MPSAFE | AS(linux_symlink_args), (sy_call_t *)linux_symlink, AUE_SYMLINK },	/* 57 = linux_symlink */
	{ SYF_MPSAFE | AS(linux_readlink_args), (sy_call_t *)linux_readlink, AUE_READLINK },	/* 58 = linux_readlink */
	{ SYF_MPSAFE | AS(linux_execve_args), (sy_call_t *)linux_execve, AUE_EXECVE },	/* 59 = linux_execve */
	{ SYF_MPSAFE | AS(umask_args), (sy_call_t *)umask, AUE_UMASK },	/* 60 = umask */
	{ SYF_MPSAFE | AS(chroot_args), (sy_call_t *)chroot, AUE_CHROOT },	/* 61 = chroot */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 62 =  */
	{ SYF_MPSAFE | 0, (sy_call_t *)getpgrp, AUE_GETPGRP },	/* 63 = getpgrp */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_getpagesize, AUE_O_GETPAGESIZE },	/* 64 = linux_getpagesize */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 65 =  */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_vfork, AUE_VFORK },	/* 66 = linux_vfork */
	{ SYF_MPSAFE | AS(linux_newstat_args), (sy_call_t *)linux_newstat, AUE_STAT },	/* 67 = linux_newstat */
	{ SYF_MPSAFE | AS(linux_newlstat_args), (sy_call_t *)linux_newlstat, AUE_LSTAT },	/* 68 = linux_newlstat */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 69 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 70 =  */
	{ SYF_MPSAFE | AS(linux_mmap_args), (sy_call_t *)linux_mmap, AUE_MMAP },	/* 71 = linux_mmap */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 72 =  */
	{ SYF_MPSAFE | AS(linux_munmap_args), (sy_call_t *)linux_munmap, AUE_MUNMAP },	/* 73 = linux_munmap */
	{ SYF_MPSAFE | AS(linux_mprotect_args), (sy_call_t *)linux_mprotect, AUE_MPROTECT },	/* 74 = linux_mprotect */
	{ SYF_MPSAFE | AS(madvise_args), (sy_call_t *)madvise, AUE_MADVISE },	/* 75 = madvise */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_vhangup, AUE_O_VHANGUP },	/* 76 = linux_vhangup */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 77 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 78 =  */
	{ SYF_MPSAFE | AS(linux_setgroups_args), (sy_call_t *)linux_setgroups, AUE_SETGROUPS },	/* 79 = linux_setgroups */
	{ SYF_MPSAFE | AS(linux_getgroups_args), (sy_call_t *)linux_getgroups, AUE_GETGROUPS },	/* 80 = linux_getgroups */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 81 =  */
	{ SYF_MPSAFE | AS(setpgid_args), (sy_call_t *)setpgid, AUE_NULL },	/* 82 = setpgid */
	{ SYF_MPSAFE | AS(osf1_setitimer_args), (sy_call_t *)osf1_setitimer, AUE_SETITIMER },	/* 83 = osf1_setitimer */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 84 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 85 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 86 = osf_getitimer */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_gethostname, AUE_SYSCTL },	/* 87 = linux_gethostname */
	{ SYF_MPSAFE | AS(sethostname_args), (sy_call_t *)osethostname, AUE_SYSCTL },	/* 88 = osethostname */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_getdtablesize, AUE_GETDTABLESIZE },	/* 89 = linux_getdtablesize */
	{ SYF_MPSAFE | AS(dup2_args), (sy_call_t *)dup2, AUE_DUP2 },	/* 90 = dup2 */
	{ SYF_MPSAFE | AS(linux_newfstat_args), (sy_call_t *)linux_newfstat, AUE_FSTAT },	/* 91 = linux_newfstat */
	{ SYF_MPSAFE | AS(linux_fcntl_args), (sy_call_t *)linux_fcntl, AUE_FCNTL },	/* 92 = linux_fcntl */
	{ SYF_MPSAFE | AS(osf1_select_args), (sy_call_t *)osf1_select, AUE_SELECT },	/* 93 = osf1_select */
	{ SYF_MPSAFE | AS(poll_args), (sy_call_t *)poll, AUE_POLL },	/* 94 = poll */
	{ SYF_MPSAFE | AS(fsync_args), (sy_call_t *)fsync, AUE_FSYNC },	/* 95 = fsync */
	{ SYF_MPSAFE | AS(setpriority_args), (sy_call_t *)setpriority, AUE_SETPRIORITY },	/* 96 = setpriority */
	{ SYF_MPSAFE | AS(osf1_socket_args), (sy_call_t *)osf1_socket, AUE_SOCKET },	/* 97 = osf1_socket */
	{ SYF_MPSAFE | AS(linux_connect_args), (sy_call_t *)linux_connect, AUE_CONNECT },	/* 98 = linux_connect */
	{ SYF_MPSAFE | AS(accept_args), (sy_call_t *)oaccept, AUE_ACCEPT },	/* 99 = accept */
	{ SYF_MPSAFE | AS(linux_getpriority_args), (sy_call_t *)linux_getpriority, AUE_GETPRIORITY },	/* 100 = linux_getpriority */
	{ SYF_MPSAFE | AS(osend_args), (sy_call_t *)osend, AUE_SEND },	/* 101 = osend */
	{ SYF_MPSAFE | AS(orecv_args), (sy_call_t *)orecv, AUE_RECV },	/* 102 = orecv */
	{ SYF_MPSAFE | AS(osf1_sigreturn_args), (sy_call_t *)osf1_sigreturn, AUE_NULL },	/* 103 = osf1_sigreturn */
	{ SYF_MPSAFE | AS(bind_args), (sy_call_t *)bind, AUE_BIND },	/* 104 = bind */
	{ SYF_MPSAFE | AS(setsockopt_args), (sy_call_t *)setsockopt, AUE_SETSOCKOPT },	/* 105 = setsockopt */
	{ SYF_MPSAFE | AS(listen_args), (sy_call_t *)listen, AUE_LISTEN },	/* 106 = listen */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 107 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 108 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 109 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 110 =  */
	{ SYF_MPSAFE | AS(osf1_sigsuspend_args), (sy_call_t *)osf1_sigsuspend, AUE_NULL },	/* 111 = osf1_sigsuspend */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 112 = osf_sigstack */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_recvmsg, AUE_RECVMSG },	/* 113 = linux_recvmsg */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_sendmsg, AUE_SENDMSG },	/* 114 = linux_sendmsg */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 115 =  */
	{ SYF_MPSAFE | AS(osf1_gettimeofday_args), (sy_call_t *)osf1_gettimeofday, AUE_NULL },	/* 116 = osf1_gettimeofday */
	{ SYF_MPSAFE | AS(osf1_getrusage_args), (sy_call_t *)osf1_getrusage, AUE_GETRUSAGE },	/* 117 = osf1_getrusage */
	{ SYF_MPSAFE | AS(getsockopt_args), (sy_call_t *)getsockopt, AUE_GETSOCKOPT },	/* 118 = getsockopt */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 119 =  */
	{ SYF_MPSAFE | AS(readv_args), (sy_call_t *)readv, AUE_READV },	/* 120 = readv */
	{ SYF_MPSAFE | AS(writev_args), (sy_call_t *)writev, AUE_WRITEV },	/* 121 = writev */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 122 = osf_settimeofday */
	{ AS(fchown_args), (sy_call_t *)fchown, AUE_FCHOWN },	/* 123 = fchown */
	{ AS(fchmod_args), (sy_call_t *)fchmod, AUE_FCHMOD },	/* 124 = fchmod */
	{ AS(recvfrom_args), (sy_call_t *)orecvfrom, AUE_RECVFROM },	/* 125 = recvfrom */
	{ SYF_MPSAFE | AS(setreuid_args), (sy_call_t *)setreuid, AUE_SETREUID },	/* 126 = setreuid */
	{ SYF_MPSAFE | AS(setregid_args), (sy_call_t *)setregid, AUE_SETREGID },	/* 127 = setregid */
	{ SYF_MPSAFE | AS(linux_rename_args), (sy_call_t *)linux_rename, AUE_RENAME },	/* 128 = linux_rename */
	{ SYF_MPSAFE | AS(linux_truncate_args), (sy_call_t *)linux_truncate, AUE_TRUNCATE },	/* 129 = linux_truncate */
	{ SYF_MPSAFE | AS(oftruncate_args), (sy_call_t *)oftruncate, AUE_FTRUNCATE },	/* 130 = oftruncate */
	{ SYF_MPSAFE | AS(flock_args), (sy_call_t *)flock, AUE_FLOCK },	/* 131 = flock */
	{ SYF_MPSAFE | AS(setgid_args), (sy_call_t *)setgid, AUE_SETGID },	/* 132 = setgid */
	{ SYF_MPSAFE | AS(osf1_sendto_args), (sy_call_t *)osf1_sendto, AUE_SENDTO },	/* 133 = osf1_sendto */
	{ SYF_MPSAFE | AS(shutdown_args), (sy_call_t *)shutdown, AUE_SHUTDOWN },	/* 134 = shutdown */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_socketpair, AUE_SOCKETPAIR },	/* 135 = linux_socketpair */
	{ SYF_MPSAFE | AS(linux_mkdir_args), (sy_call_t *)linux_mkdir, AUE_MKDIR },	/* 136 = linux_mkdir */
	{ SYF_MPSAFE | AS(linux_rmdir_args), (sy_call_t *)linux_rmdir, AUE_RMDIR },	/* 137 = linux_rmdir */
	{ SYF_MPSAFE | AS(utimes_args), (sy_call_t *)utimes, AUE_UTIMES },	/* 138 = utimes */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 139 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 140 =  */
	{ SYF_MPSAFE | AS(ogetpeername_args), (sy_call_t *)ogetpeername, AUE_GETPEERNAME },	/* 141 = ogetpeername */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 142 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 143 =  */
	{ SYF_MPSAFE | AS(linux_getrlimit_args), (sy_call_t *)linux_getrlimit, AUE_GETRLIMIT },	/* 144 = linux_getrlimit */
	{ SYF_MPSAFE | AS(linux_setrlimit_args), (sy_call_t *)linux_setrlimit, AUE_SETRLIMIT },	/* 145 = linux_setrlimit */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 146 =  */
	{ SYF_MPSAFE | 0, (sy_call_t *)setsid, AUE_SETSID },	/* 147 = setsid */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_quotactl, AUE_QUOTACTL },	/* 148 = linux_quotactl */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 149 =  */
	{ SYF_MPSAFE | AS(getsockname_args), (sy_call_t *)ogetsockname, AUE_GETSOCKNAME },	/* 150 = getsockname */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 151 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 152 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 153 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 154 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 155 =  */
	{ SYF_MPSAFE | AS(osf1_sigaction_args), (sy_call_t *)osf1_sigaction, AUE_NULL },	/* 156 = osf1_sigaction */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 157 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 158 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 159 = osf_getdirentries */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 160 = osf_statfs */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 161 = osf_fstatfs */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 162 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 163 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 164 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 165 = osf_getdomainname */
	{ SYF_MPSAFE | AS(setdomainname_args), (sy_call_t *)setdomainname, AUE_SYSCTL },	/* 166 = setdomainname */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 167 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 168 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 169 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 170 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 171 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 172 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 173 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 174 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 175 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 176 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 177 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 178 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 179 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 180 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 181 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 182 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 183 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 184 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 185 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 186 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 187 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 188 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 189 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 190 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 191 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 192 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 193 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 194 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 195 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 196 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 197 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 198 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 199 = osf_swapon */
	{ SYF_MPSAFE | AS(linux_msgctl_args), (sy_call_t *)linux_msgctl, AUE_MSGCTL },	/* 200 = linux_msgctl */
	{ SYF_MPSAFE | AS(linux_msgget_args), (sy_call_t *)linux_msgget, AUE_MSGGET },	/* 201 = linux_msgget */
	{ SYF_MPSAFE | AS(linux_msgrcv_args), (sy_call_t *)linux_msgrcv, AUE_MSGRCV },	/* 202 = linux_msgrcv */
	{ SYF_MPSAFE | AS(linux_msgsnd_args), (sy_call_t *)linux_msgsnd, AUE_MSGSND },	/* 203 = linux_msgsnd */
	{ AS(linux_semctl_args), (sy_call_t *)linux_semctl, AUE_SEMCTL },	/* 204 = linux_semctl */
	{ SYF_MPSAFE | AS(linux_semget_args), (sy_call_t *)linux_semget, AUE_SEMGET },	/* 205 = linux_semget */
	{ SYF_MPSAFE | AS(linux_semop_args), (sy_call_t *)linux_semop, AUE_SEMOP },	/* 206 = linux_semop */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 207 = osf_utsname */
	{ SYF_MPSAFE | AS(linux_lchown_args), (sy_call_t *)linux_lchown, AUE_LCHOWN },	/* 208 = linux_lchown */
	{ SYF_MPSAFE | AS(linux_shmat_args), (sy_call_t *)linux_shmat, AUE_SHMAT },	/* 209 = linux_shmat */
	{ SYF_MPSAFE | AS(linux_shmctl_args), (sy_call_t *)linux_shmctl, AUE_SHMCTL },	/* 210 = linux_shmctl */
	{ SYF_MPSAFE | AS(linux_shmdt_args), (sy_call_t *)linux_shmdt, AUE_SHMDT },	/* 211 = linux_shmdt */
	{ SYF_MPSAFE | AS(linux_shmget_args), (sy_call_t *)linux_shmget, AUE_SHMGET },	/* 212 = linux_shmget */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 213 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 214 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 215 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 216 =  */
	{ SYF_MPSAFE | AS(linux_msync_args), (sy_call_t *)linux_msync, AUE_MSYNC },	/* 217 = linux_msync */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 218 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 219 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 220 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 221 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 222 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 223 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 224 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 225 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 226 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 227 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 228 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 229 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 230 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 231 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 232 =  */
	{ SYF_MPSAFE | AS(getpgid_args), (sy_call_t *)getpgid, AUE_GETPPID },	/* 233 = getpgid */
	{ SYF_MPSAFE | AS(linux_getsid_args), (sy_call_t *)linux_getsid, AUE_GETSID },	/* 234 = linux_getsid */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_sigaltstack, AUE_NULL },	/* 235 = linux_sigaltstack */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 236 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 237 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 238 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 239 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 240 =  */
	{ SYF_MPSAFE | AS(osf1_sysinfo_args), (sy_call_t *)osf1_sysinfo, AUE_NULL },	/* 241 = osf1_sysinfo */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 242 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 243 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 244 = osf_proplist_syscall */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 245 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 246 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 247 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 248 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 249 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 250 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 251 = osf_usleep_thread */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 252 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 253 =  */
	{ SYF_MPSAFE | AS(linux_sysfs_args), (sy_call_t *)linux_sysfs, AUE_NULL },	/* 254 = linux_sysfs */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 255 =  */
	{ SYF_MPSAFE | AS(osf1_getsysinfo_args), (sy_call_t *)osf1_getsysinfo, AUE_NULL },	/* 256 = osf1_getsysinfo */
	{ SYF_MPSAFE | AS(osf1_setsysinfo_args), (sy_call_t *)osf1_setsysinfo, AUE_NULL },	/* 257 = osf1_setsysinfo */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 258 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 259 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 260 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 261 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 262 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 263 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 264 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 265 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 266 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 267 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 268 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 269 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 270 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 271 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 272 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 273 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 274 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 275 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 276 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 277 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 278 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 279 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 280 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 281 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 282 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 283 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 284 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 285 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 286 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 287 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 288 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 289 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 290 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 291 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 292 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 293 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 294 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 295 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 296 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 297 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 298 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 299 =  */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_bdflush, AUE_BDFLUSH },	/* 300 = linux_bdflush */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_sethae, AUE_NULL },	/* 301 = linux_sethae */
	{ AS(linux_mount_args), (sy_call_t *)linux_mount, AUE_MOUNT },	/* 302 = linux_mount */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_old_adjtimex, AUE_ADJTIME },	/* 303 = linux_old_adjtimex */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_swapoff, AUE_SWAPOFF },	/* 304 = linux_swapoff */
	{ AS(linux_getdents_args), (sy_call_t *)linux_getdents, AUE_O_GETDENTS },	/* 305 = linux_getdents */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_create_module, AUE_NULL },	/* 306 = linux_create_module */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_init_module, AUE_NULL },	/* 307 = linux_init_module */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_delete_module, AUE_NULL },	/* 308 = linux_delete_module */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_get_kernel_syms, AUE_NULL },	/* 309 = linux_get_kernel_syms */
	{ SYF_MPSAFE | AS(linux_syslog_args), (sy_call_t *)linux_syslog, AUE_NULL },	/* 310 = linux_syslog */
	{ SYF_MPSAFE | AS(linux_reboot_args), (sy_call_t *)linux_reboot, AUE_REBOOT },	/* 311 = linux_reboot */
	{ SYF_MPSAFE | AS(linux_clone_args), (sy_call_t *)linux_clone, AUE_RFORK },	/* 312 = linux_clone */
	{ AS(linux_uselib_args), (sy_call_t *)linux_uselib, AUE_USELIB },	/* 313 = linux_uselib */
	{ SYF_MPSAFE | AS(mlock_args), (sy_call_t *)mlock, AUE_MLOCK },	/* 314 = mlock */
	{ SYF_MPSAFE | AS(munlock_args), (sy_call_t *)munlock, AUE_MUNLOCK },	/* 315 = munlock */
	{ SYF_MPSAFE | AS(mlockall_args), (sy_call_t *)mlockall, AUE_MLOCKALL },	/* 316 = mlockall */
	{ SYF_MPSAFE | 0, (sy_call_t *)munlockall, AUE_MUNLOCKALL },	/* 317 = munlockall */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_sysinfo, AUE_NULL },	/* 318 = linux_sysinfo */
	{ SYF_MPSAFE | AS(linux_sysctl_args), (sy_call_t *)linux_sysctl, AUE_SYSCTL },	/* 319 = linux_sysctl */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 320 = sys_idle */
	{ AS(linux_oldumount_args), (sy_call_t *)linux_oldumount, AUE_UMOUNT },	/* 321 = linux_oldumount */
	{ SYF_MPSAFE | AS(swapon_args), (sy_call_t *)swapon, AUE_SWAPON },	/* 322 = swapon */
	{ SYF_MPSAFE | AS(linux_times_args), (sy_call_t *)linux_times, AUE_NULL },	/* 323 = linux_times */
	{ SYF_MPSAFE | AS(linux_personality_args), (sy_call_t *)linux_personality, AUE_PERSONALITY },	/* 324 = linux_personality */
	{ SYF_MPSAFE | AS(linux_setfsuid_args), (sy_call_t *)linux_setfsuid, AUE_SETFSUID },	/* 325 = linux_setfsuid */
	{ SYF_MPSAFE | AS(linux_setfsgid_args), (sy_call_t *)linux_setfsgid, AUE_SETFSGID },	/* 326 = linux_setfsgid */
	{ SYF_MPSAFE | AS(linux_ustat_args), (sy_call_t *)linux_ustat, AUE_NULL },	/* 327 = linux_ustat */
	{ SYF_MPSAFE | AS(linux_statfs_args), (sy_call_t *)linux_statfs, AUE_STATFS },	/* 328 = linux_statfs */
	{ SYF_MPSAFE | AS(linux_fstatfs_args), (sy_call_t *)linux_fstatfs, AUE_FSTATFS },	/* 329 = linux_fstatfs */
	{ SYF_MPSAFE | AS(sched_setparam_args), (sy_call_t *)sched_setparam, AUE_SCHED_SETPARAM },	/* 330 = sched_setparam */
	{ SYF_MPSAFE | AS(sched_getparam_args), (sy_call_t *)sched_getparam, AUE_SCHED_GETPARAM },	/* 331 = sched_getparam */
	{ SYF_MPSAFE | AS(linux_sched_setscheduler_args), (sy_call_t *)linux_sched_setscheduler, AUE_SCHED_SETSCHEDULER },	/* 332 = linux_sched_setscheduler */
	{ SYF_MPSAFE | AS(linux_sched_getscheduler_args), (sy_call_t *)linux_sched_getscheduler, AUE_SCHED_GETSCHEDULER },	/* 333 = linux_sched_getscheduler */
	{ SYF_MPSAFE | 0, (sy_call_t *)sched_yield, AUE_NULL },	/* 334 = sched_yield */
	{ SYF_MPSAFE | AS(linux_sched_get_priority_max_args), (sy_call_t *)linux_sched_get_priority_max, AUE_SCHED_GET_PRIORITY_MAX },	/* 335 = linux_sched_get_priority_max */
	{ SYF_MPSAFE | AS(linux_sched_get_priority_min_args), (sy_call_t *)linux_sched_get_priority_min, AUE_SCHED_GET_PRIORITY_MIN },	/* 336 = linux_sched_get_priority_min */
	{ SYF_MPSAFE | AS(sched_rr_get_interval_args), (sy_call_t *)sched_rr_get_interval, AUE_SCHED_RR_GET_INTERVAL },	/* 337 = sched_rr_get_interval */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 338 = sys_afs_syscall */
	{ SYF_MPSAFE | AS(linux_newuname_args), (sy_call_t *)linux_newuname, AUE_NULL },	/* 339 = linux_newuname */
	{ SYF_MPSAFE | AS(nanosleep_args), (sy_call_t *)nanosleep, AUE_NULL },	/* 340 = nanosleep */
	{ SYF_MPSAFE | AS(linux_mremap_args), (sy_call_t *)linux_mremap, AUE_NULL },	/* 341 = linux_mremap */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_nfsservctl, AUE_NULL },	/* 342 = linux_nfsservctl */
	{ SYF_MPSAFE | AS(setresuid_args), (sy_call_t *)setresuid, AUE_SETRESUID },	/* 343 = setresuid */
	{ SYF_MPSAFE | AS(getresuid_args), (sy_call_t *)getresuid, AUE_GETRESUID },	/* 344 = getresuid */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_pciconfig_read, AUE_NULL },	/* 345 = linux_pciconfig_read */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_pciconfig_write, AUE_NULL },	/* 346 = linux_pciconfig_write */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_query_module, AUE_NULL },	/* 347 = linux_query_module */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_prctl, AUE_PRCTL },	/* 348 = linux_prctl */
	{ SYF_MPSAFE | AS(linux_pread_args), (sy_call_t *)linux_pread, AUE_PREAD },	/* 349 = linux_pread */
	{ SYF_MPSAFE | AS(linux_pwrite_args), (sy_call_t *)linux_pwrite, AUE_PWRITE },	/* 350 = linux_pwrite */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_rt_sigreturn, AUE_NULL },	/* 351 = linux_rt_sigreturn */
	{ SYF_MPSAFE | AS(linux_rt_sigaction_args), (sy_call_t *)linux_rt_sigaction, AUE_NULL },	/* 352 = linux_rt_sigaction */
	{ SYF_MPSAFE | AS(linux_rt_sigprocmask_args), (sy_call_t *)linux_rt_sigprocmask, AUE_NULL },	/* 353 = linux_rt_sigprocmask */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_rt_sigpending, AUE_NULL },	/* 354 = linux_rt_sigpending */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_rt_sigtimedwait, AUE_NULL },	/* 355 = linux_rt_sigtimedwait */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_rt_sigqueueinfo, AUE_NULL },	/* 356 = linux_rt_sigqueueinfo */
	{ SYF_MPSAFE | AS(linux_rt_sigsuspend_args), (sy_call_t *)linux_rt_sigsuspend, AUE_NULL },	/* 357 = linux_rt_sigsuspend */
	{ SYF_MPSAFE | AS(linux_select_args), (sy_call_t *)linux_select, AUE_SELECT },	/* 358 = linux_select */
	{ SYF_MPSAFE | AS(gettimeofday_args), (sy_call_t *)gettimeofday, AUE_NULL },	/* 359 = gettimeofday */
	{ SYF_MPSAFE | AS(settimeofday_args), (sy_call_t *)settimeofday, AUE_SETTIMEOFDAY },	/* 360 = settimeofday */
	{ SYF_MPSAFE | AS(linux_getitimer_args), (sy_call_t *)linux_getitimer, AUE_GETITIMER },	/* 361 = linux_getitimer */
	{ SYF_MPSAFE | AS(linux_setitimer_args), (sy_call_t *)linux_setitimer, AUE_SETITIMER },	/* 362 = linux_setitimer */
	{ SYF_MPSAFE | AS(linux_utimes_args), (sy_call_t *)linux_utimes, AUE_UTIMES },	/* 363 = linux_utimes */
	{ SYF_MPSAFE | AS(getrusage_args), (sy_call_t *)getrusage, AUE_GETRUSAGE },	/* 364 = getrusage */
	{ SYF_MPSAFE | AS(linux_wait4_args), (sy_call_t *)linux_wait4, AUE_WAIT4 },	/* 365 = linux_wait4 */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_adjtimex, AUE_ADJTIME },	/* 366 = linux_adjtimex */
	{ SYF_MPSAFE | AS(linux_getcwd_args), (sy_call_t *)linux_getcwd, AUE_GETCWD },	/* 367 = linux_getcwd */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_capget, AUE_CAPGET },	/* 368 = linux_capget */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_capset, AUE_CAPSET },	/* 369 = linux_capset */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_sendfile, AUE_SENDFILE },	/* 370 = linux_sendfile */
	{ SYF_MPSAFE | AS(setresgid_args), (sy_call_t *)setresgid, AUE_SETRESGID },	/* 371 = setresgid */
	{ SYF_MPSAFE | AS(getresgid_args), (sy_call_t *)getresgid, AUE_GETRESGID },	/* 372 = getresgid */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 373 = sys_dipc */
	{ SYF_MPSAFE | AS(linux_pivot_root_args), (sy_call_t *)linux_pivot_root, AUE_PIVOT_ROOT },	/* 374 = linux_pivot_root */
	{ SYF_MPSAFE | AS(linux_mincore_args), (sy_call_t *)linux_mincore, AUE_MINCORE },	/* 375 = linux_mincore */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_pciconfig_iobase, AUE_NULL },	/* 376 = linux_pciconfig_iobase */
	{ AS(linux_getdents64_args), (sy_call_t *)linux_getdents64, AUE_O_GETDENTS },	/* 377 = linux_getdents64 */
};
