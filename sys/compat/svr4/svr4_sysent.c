/*
 * System call switch table.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * $FreeBSD$
 * created from;	@(#)syscalls.master	8.1 (Berkeley) 7/19/93
 */

#include <sys/types.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <netinet/in.h>
#include <svr4/svr4_types.h>
#include <svr4/svr4_signal.h>
#include <svr4/svr4_proto.h>

/* The casts are bogus but will do for now. */
struct sysent svr4_sysent[] = {
	{ 0, (sy_call_t *)nosys },			/* 0 = unused */
	{ 1, (sy_call_t *)exit },			/* 1 = exit */
	{ 0, (sy_call_t *)fork },			/* 2 = fork */
	{ 3, (sy_call_t *)read },			/* 3 = read */
	{ 3, (sy_call_t *)write },			/* 4 = write */
	{ 3, (sy_call_t *)svr4_sys_open },		/* 5 = svr4_sys_open */
	{ 1, (sy_call_t *)close },			/* 6 = close */
	{ 1, (sy_call_t *)svr4_sys_wait },		/* 7 = svr4_sys_wait */
	{ 2, (sy_call_t *)svr4_sys_creat },		/* 8 = svr4_sys_creat */
	{ 2, (sy_call_t *)link },			/* 9 = link */
	{ 1, (sy_call_t *)unlink },			/* 10 = unlink */
	{ 2, (sy_call_t *)svr4_sys_execv },		/* 11 = svr4_sys_execv */
	{ 1, (sy_call_t *)chdir },			/* 12 = chdir */
	{ 1, (sy_call_t *)svr4_sys_time },		/* 13 = svr4_sys_time */
	{ 3, (sy_call_t *)svr4_sys_mknod },		/* 14 = svr4_sys_mknod */
	{ 2, (sy_call_t *)chmod },			/* 15 = chmod */
	{ 3, (sy_call_t *)chown },			/* 16 = chown */
	{ 1, (sy_call_t *)svr4_sys_break },		/* 17 = svr4_sys_break */
	{ 2, (sy_call_t *)svr4_sys_stat },		/* 18 = svr4_sys_stat */
	{ 3, (sy_call_t *)lseek },			/* 19 = lseek */
	{ 0, (sy_call_t *)getpid },			/* 20 = getpid */
	{ 0, (sy_call_t *)nosys },			/* 21 = old_mount */
	{ 0, (sy_call_t *)nosys },			/* 22 = sysv_umount */
	{ 1, (sy_call_t *)setuid },			/* 23 = setuid */
	{ 0, (sy_call_t *)getuid },			/* 24 = getuid */
	{ 0, (sy_call_t *)nosys },			/* 25 = stime */
	{ 0, (sy_call_t *)nosys },			/* 26 = ptrace */
	{ 1, (sy_call_t *)svr4_sys_alarm },		/* 27 = svr4_sys_alarm */
	{ 2, (sy_call_t *)svr4_sys_fstat },		/* 28 = svr4_sys_fstat */
	{ 0, (sy_call_t *)svr4_sys_pause },		/* 29 = svr4_sys_pause */
	{ 2, (sy_call_t *)svr4_sys_utime },		/* 30 = svr4_sys_utime */
	{ 0, (sy_call_t *)nosys },			/* 31 = stty */
	{ 0, (sy_call_t *)nosys },			/* 32 = gtty */
	{ 2, (sy_call_t *)svr4_sys_access },		/* 33 = svr4_sys_access */
	{ 1, (sy_call_t *)svr4_sys_nice },		/* 34 = svr4_sys_nice */
	{ 0, (sy_call_t *)nosys },			/* 35 = statfs */
	{ 0, (sy_call_t *)sync },			/* 36 = sync */
	{ 2, (sy_call_t *)svr4_sys_kill },		/* 37 = svr4_sys_kill */
	{ 0, (sy_call_t *)nosys },			/* 38 = fstatfs */
	{ 3, (sy_call_t *)svr4_sys_pgrpsys },		/* 39 = svr4_sys_pgrpsys */
	{ 0, (sy_call_t *)nosys },			/* 40 = xenix */
	{ 1, (sy_call_t *)dup },			/* 41 = dup */
	{ 0, (sy_call_t *)pipe },			/* 42 = pipe */
	{ 1, (sy_call_t *)svr4_sys_times },		/* 43 = svr4_sys_times */
	{ 0, (sy_call_t *)nosys },			/* 44 = profil */
	{ 0, (sy_call_t *)nosys },			/* 45 = plock */
	{ 1, (sy_call_t *)setgid },			/* 46 = setgid */
	{ 0, (sy_call_t *)getgid },			/* 47 = getgid */
	{ 2, (sy_call_t *)svr4_sys_signal },		/* 48 = svr4_sys_signal */
#if defined(NOTYET)
	{ 5, (sy_call_t *)svr4_sys_msgsys },		/* 49 = svr4_sys_msgsys */
#else
	{ 0, (sy_call_t *)nosys },			/* 49 = msgsys */
#endif
	{ 2, (sy_call_t *)svr4_sys_sysarch },		/* 50 = svr4_sys_sysarch */
	{ 0, (sy_call_t *)nosys },			/* 51 = acct */
	{ 0, (sy_call_t *)nosys },			/* 52 = shmsys */
	{ 0, (sy_call_t *)nosys },			/* 53 = semsys */
	{ 3, (sy_call_t *)svr4_sys_ioctl },		/* 54 = svr4_sys_ioctl */
	{ 0, (sy_call_t *)nosys },			/* 55 = uadmin */
	{ 0, (sy_call_t *)nosys },			/* 56 = exch */
	{ 4, (sy_call_t *)svr4_sys_utssys },		/* 57 = svr4_sys_utssys */
	{ 1, (sy_call_t *)fsync },			/* 58 = fsync */
	{ 3, (sy_call_t *)svr4_sys_execve },		/* 59 = svr4_sys_execve */
	{ 1, (sy_call_t *)umask },			/* 60 = umask */
	{ 1, (sy_call_t *)chroot },			/* 61 = chroot */
	{ 3, (sy_call_t *)svr4_sys_fcntl },		/* 62 = svr4_sys_fcntl */
	{ 2, (sy_call_t *)svr4_sys_ulimit },		/* 63 = svr4_sys_ulimit */
	{ 0, (sy_call_t *)nosys },			/* 64 = reserved */
	{ 0, (sy_call_t *)nosys },			/* 65 = reserved */
	{ 0, (sy_call_t *)nosys },			/* 66 = reserved */
	{ 0, (sy_call_t *)nosys },			/* 67 = reserved */
	{ 0, (sy_call_t *)nosys },			/* 68 = reserved */
	{ 0, (sy_call_t *)nosys },			/* 69 = reserved */
	{ 0, (sy_call_t *)nosys },			/* 70 = advfs */
	{ 0, (sy_call_t *)nosys },			/* 71 = unadvfs */
	{ 0, (sy_call_t *)nosys },			/* 72 = rmount */
	{ 0, (sy_call_t *)nosys },			/* 73 = rumount */
	{ 0, (sy_call_t *)nosys },			/* 74 = rfstart */
	{ 0, (sy_call_t *)nosys },			/* 75 = sigret */
	{ 0, (sy_call_t *)nosys },			/* 76 = rdebug */
	{ 0, (sy_call_t *)nosys },			/* 77 = rfstop */
	{ 0, (sy_call_t *)nosys },			/* 78 = rfsys */
	{ 1, (sy_call_t *)rmdir },			/* 79 = rmdir */
	{ 2, (sy_call_t *)mkdir },			/* 80 = mkdir */
	{ 3, (sy_call_t *)svr4_sys_getdents },		/* 81 = svr4_sys_getdents */
	{ 0, (sy_call_t *)nosys },			/* 82 = libattach */
	{ 0, (sy_call_t *)nosys },			/* 83 = libdetach */
	{ 0, (sy_call_t *)nosys },			/* 84 = sysfs */
	{ 4, (sy_call_t *)svr4_sys_getmsg },		/* 85 = svr4_sys_getmsg */
	{ 4, (sy_call_t *)svr4_sys_putmsg },		/* 86 = svr4_sys_putmsg */
	{ 3, (sy_call_t *)svr4_sys_poll },		/* 87 = svr4_sys_poll */
	{ 2, (sy_call_t *)svr4_sys_lstat },		/* 88 = svr4_sys_lstat */
	{ 2, (sy_call_t *)symlink },			/* 89 = symlink */
	{ 3, (sy_call_t *)readlink },			/* 90 = readlink */
	{ 2, (sy_call_t *)getgroups },			/* 91 = getgroups */
	{ 2, (sy_call_t *)setgroups },			/* 92 = setgroups */
	{ 2, (sy_call_t *)fchmod },			/* 93 = fchmod */
	{ 3, (sy_call_t *)fchown },			/* 94 = fchown */
	{ 3, (sy_call_t *)svr4_sys_sigprocmask },		/* 95 = svr4_sys_sigprocmask */
	{ 1, (sy_call_t *)svr4_sys_sigsuspend },		/* 96 = svr4_sys_sigsuspend */
	{ 2, (sy_call_t *)svr4_sys_sigaltstack },		/* 97 = svr4_sys_sigaltstack */
	{ 3, (sy_call_t *)svr4_sys_sigaction },		/* 98 = svr4_sys_sigaction */
	{ 2, (sy_call_t *)svr4_sys_sigpending },		/* 99 = svr4_sys_sigpending */
	{ 2, (sy_call_t *)svr4_sys_context },		/* 100 = svr4_sys_context */
	{ 0, (sy_call_t *)nosys },			/* 101 = evsys */
	{ 0, (sy_call_t *)nosys },			/* 102 = evtrapret */
	{ 2, (sy_call_t *)svr4_sys_statvfs },		/* 103 = svr4_sys_statvfs */
	{ 2, (sy_call_t *)svr4_sys_fstatvfs },		/* 104 = svr4_sys_fstatvfs */
	{ 0, (sy_call_t *)nosys },			/* 105 = whoknows */
	{ 0, (sy_call_t *)nosys },			/* 106 = nfssvc */
	{ 4, (sy_call_t *)svr4_sys_waitsys },		/* 107 = svr4_sys_waitsys */
	{ 0, (sy_call_t *)nosys },			/* 108 = sigsendsys */
	{ 5, (sy_call_t *)svr4_sys_hrtsys },		/* 109 = svr4_sys_hrtsys */
	{ 0, (sy_call_t *)nosys },			/* 110 = acancel */
	{ 0, (sy_call_t *)nosys },			/* 111 = async */
	{ 0, (sy_call_t *)nosys },			/* 112 = priocntlsys */
	{ 2, (sy_call_t *)svr4_sys_pathconf },		/* 113 = svr4_sys_pathconf */
	{ 0, (sy_call_t *)nosys },			/* 114 = mincore */
	{ 6, (sy_call_t *)svr4_sys_mmap },		/* 115 = svr4_sys_mmap */
	{ 3, (sy_call_t *)mprotect },			/* 116 = mprotect */
	{ 2, (sy_call_t *)munmap },			/* 117 = munmap */
	{ 2, (sy_call_t *)svr4_sys_fpathconf },		/* 118 = svr4_sys_fpathconf */
	{ 0, (sy_call_t *)vfork },			/* 119 = vfork */
	{ 1, (sy_call_t *)fchdir },			/* 120 = fchdir */
	{ 3, (sy_call_t *)readv },			/* 121 = readv */
	{ 3, (sy_call_t *)writev },			/* 122 = writev */
	{ 3, (sy_call_t *)svr4_sys_xstat },		/* 123 = svr4_sys_xstat */
	{ 3, (sy_call_t *)svr4_sys_lxstat },		/* 124 = svr4_sys_lxstat */
	{ 3, (sy_call_t *)svr4_sys_fxstat },		/* 125 = svr4_sys_fxstat */
	{ 4, (sy_call_t *)svr4_sys_xmknod },		/* 126 = svr4_sys_xmknod */
	{ 0, (sy_call_t *)nosys },			/* 127 = clocal */
	{ 2, (sy_call_t *)svr4_sys_setrlimit },		/* 128 = svr4_sys_setrlimit */
	{ 2, (sy_call_t *)svr4_sys_getrlimit },		/* 129 = svr4_sys_getrlimit */
	{ 3, (sy_call_t *)lchown },			/* 130 = lchown */
	{ 6, (sy_call_t *)svr4_sys_memcntl },		/* 131 = svr4_sys_memcntl */
	{ 0, (sy_call_t *)nosys },			/* 132 = getpmsg */
	{ 0, (sy_call_t *)nosys },			/* 133 = putpmsg */
	{ 2, (sy_call_t *)rename },			/* 134 = rename */
	{ 2, (sy_call_t *)svr4_sys_uname },		/* 135 = svr4_sys_uname */
	{ 1, (sy_call_t *)setegid },			/* 136 = setegid */
	{ 1, (sy_call_t *)svr4_sys_sysconfig },		/* 137 = svr4_sys_sysconfig */
	{ 2, (sy_call_t *)adjtime },			/* 138 = adjtime */
	{ 3, (sy_call_t *)svr4_sys_systeminfo },		/* 139 = svr4_sys_systeminfo */
	{ 0, (sy_call_t *)nosys },			/* 140 = notused */
	{ 1, (sy_call_t *)seteuid },			/* 141 = seteuid */
	{ 0, (sy_call_t *)nosys },			/* 142 = vtrace */
	{ 0, (sy_call_t *)nosys },			/* 143 = { */
	{ 0, (sy_call_t *)nosys },			/* 144 = sigtimedwait */
	{ 0, (sy_call_t *)nosys },			/* 145 = lwp_info */
	{ 0, (sy_call_t *)nosys },			/* 146 = yield */
	{ 0, (sy_call_t *)nosys },			/* 147 = lwp_sema_wait */
	{ 0, (sy_call_t *)nosys },			/* 148 = lwp_sema_post */
	{ 0, (sy_call_t *)nosys },			/* 149 = lwp_sema_trywait */
	{ 0, (sy_call_t *)nosys },			/* 150 = notused */
	{ 0, (sy_call_t *)nosys },			/* 151 = notused */
	{ 0, (sy_call_t *)nosys },			/* 152 = modctl */
	{ 1, (sy_call_t *)svr4_sys_fchroot },		/* 153 = svr4_sys_fchroot */
	{ 2, (sy_call_t *)svr4_sys_utimes },		/* 154 = svr4_sys_utimes */
	{ 0, (sy_call_t *)svr4_sys_vhangup },		/* 155 = svr4_sys_vhangup */
	{ 1, (sy_call_t *)svr4_sys_gettimeofday },		/* 156 = svr4_sys_gettimeofday */
	{ 2, (sy_call_t *)getitimer },			/* 157 = getitimer */
	{ 3, (sy_call_t *)setitimer },			/* 158 = setitimer */
	{ 0, (sy_call_t *)nosys },			/* 159 = lwp_create */
	{ 0, (sy_call_t *)nosys },			/* 160 = lwp_exit */
	{ 0, (sy_call_t *)nosys },			/* 161 = lwp_suspend */
	{ 0, (sy_call_t *)nosys },			/* 162 = lwp_continue */
	{ 0, (sy_call_t *)nosys },			/* 163 = lwp_kill */
	{ 0, (sy_call_t *)nosys },			/* 164 = lwp_self */
	{ 0, (sy_call_t *)nosys },			/* 165 = lwp_getprivate */
	{ 0, (sy_call_t *)nosys },			/* 166 = lwp_setprivate */
	{ 0, (sy_call_t *)nosys },			/* 167 = lwp_wait */
	{ 0, (sy_call_t *)nosys },			/* 168 = lwp_mutex_unlock */
	{ 0, (sy_call_t *)nosys },			/* 169 = lwp_mutex_lock */
	{ 0, (sy_call_t *)nosys },			/* 170 = lwp_cond_wait */
	{ 0, (sy_call_t *)nosys },			/* 171 = lwp_cond_signal */
	{ 0, (sy_call_t *)nosys },			/* 172 = lwp_cond_broadcast */
	{ 0, (sy_call_t *)nosys },			/* 173 = { */
	{ 0, (sy_call_t *)nosys },			/* 174 = { */
	{ 4, (sy_call_t *)svr4_sys_llseek },		/* 175 = svr4_sys_llseek */
	{ 0, (sy_call_t *)nosys },			/* 176 = inst_sync */
	{ 0, (sy_call_t *)nosys },			/* 177 = whoknows */
	{ 0, (sy_call_t *)nosys },			/* 178 = kaio */
	{ 0, (sy_call_t *)nosys },			/* 179 = whoknows */
	{ 0, (sy_call_t *)nosys },			/* 180 = whoknows */
	{ 0, (sy_call_t *)nosys },			/* 181 = whoknows */
	{ 0, (sy_call_t *)nosys },			/* 182 = whoknows */
	{ 0, (sy_call_t *)nosys },			/* 183 = whoknows */
	{ 0, (sy_call_t *)nosys },			/* 184 = tsolsys */
	{ 4, (sy_call_t *)svr4_sys_acl },		/* 185 = svr4_sys_acl */
	{ 6, (sy_call_t *)svr4_sys_auditsys },		/* 186 = svr4_sys_auditsys */
	{ 0, (sy_call_t *)nosys },			/* 187 = processor_bind */
	{ 0, (sy_call_t *)nosys },			/* 188 = processor_info */
	{ 0, (sy_call_t *)nosys },			/* 189 = p_online */
	{ 0, (sy_call_t *)nosys },			/* 190 = sigqueue */
	{ 0, (sy_call_t *)nosys },			/* 191 = clock_gettime */
	{ 0, (sy_call_t *)nosys },			/* 192 = clock_settime */
	{ 0, (sy_call_t *)nosys },			/* 193 = clock_getres */
	{ 0, (sy_call_t *)nosys },			/* 194 = timer_create */
	{ 0, (sy_call_t *)nosys },			/* 195 = timer_delete */
	{ 0, (sy_call_t *)nosys },			/* 196 = timer_settime */
	{ 0, (sy_call_t *)nosys },			/* 197 = timer_gettime */
	{ 0, (sy_call_t *)nosys },			/* 198 = timer_overrun */
	{ 2, (sy_call_t *)nanosleep },			/* 199 = nanosleep */
	{ 4, (sy_call_t *)svr4_sys_facl },		/* 200 = svr4_sys_facl */
	{ 0, (sy_call_t *)nosys },			/* 201 = door */
	{ 2, (sy_call_t *)setreuid },			/* 202 = setreuid */
	{ 2, (sy_call_t *)setregid },			/* 203 = setregid */
	{ 0, (sy_call_t *)nosys },			/* 204 = install_utrap */
	{ 0, (sy_call_t *)nosys },			/* 205 = signotify */
	{ 0, (sy_call_t *)nosys },			/* 206 = schedctl */
	{ 0, (sy_call_t *)nosys },			/* 207 = pset */
	{ 0, (sy_call_t *)nosys },			/* 208 = whoknows */
	{ 3, (sy_call_t *)svr4_sys_resolvepath },		/* 209 = svr4_sys_resolvepath */
	{ 0, (sy_call_t *)nosys },			/* 210 = signotifywait */
	{ 0, (sy_call_t *)nosys },			/* 211 = lwp_sigredirect */
	{ 0, (sy_call_t *)nosys },			/* 212 = lwp_alarm */
	{ 3, (sy_call_t *)svr4_sys_getdents64 },		/* 213 = svr4_sys_getdents64 */
	{ 6, (sy_call_t *)svr4_sys_mmap64 },		/* 214 = svr4_sys_mmap64 */
	{ 2, (sy_call_t *)svr4_sys_stat64 },		/* 215 = svr4_sys_stat64 */
	{ 2, (sy_call_t *)svr4_sys_lstat64 },		/* 216 = svr4_sys_lstat64 */
	{ 2, (sy_call_t *)svr4_sys_fstat64 },		/* 217 = svr4_sys_fstat64 */
	{ 2, (sy_call_t *)svr4_sys_statvfs64 },		/* 218 = svr4_sys_statvfs64 */
	{ 2, (sy_call_t *)svr4_sys_fstatvfs64 },		/* 219 = svr4_sys_fstatvfs64 */
	{ 2, (sy_call_t *)svr4_sys_setrlimit64 },		/* 220 = svr4_sys_setrlimit64 */
	{ 2, (sy_call_t *)svr4_sys_getrlimit64 },		/* 221 = svr4_sys_getrlimit64 */
	{ 0, (sy_call_t *)nosys },			/* 222 = pread64 */
	{ 0, (sy_call_t *)nosys },			/* 223 = pwrite64 */
	{ 2, (sy_call_t *)svr4_sys_creat64 },		/* 224 = svr4_sys_creat64 */
	{ 3, (sy_call_t *)svr4_sys_open64 },		/* 225 = svr4_sys_open64 */
	{ 0, (sy_call_t *)nosys },			/* 226 = rpcsys */
	{ 0, (sy_call_t *)nosys },			/* 227 = whoknows */
	{ 0, (sy_call_t *)nosys },			/* 228 = whoknows */
	{ 0, (sy_call_t *)nosys },			/* 229 = whoknows */
	{ 3, (sy_call_t *)svr4_sys_socket },		/* 230 = svr4_sys_socket */
	{ 4, (sy_call_t *)socketpair },			/* 231 = socketpair */
	{ 3, (sy_call_t *)bind },			/* 232 = bind */
	{ 2, (sy_call_t *)listen },			/* 233 = listen */
	{ 3, (sy_call_t *)accept },			/* 234 = accept */
	{ 3, (sy_call_t *)connect },			/* 235 = connect */
	{ 2, (sy_call_t *)shutdown },			/* 236 = shutdown */
	{ 4, (sy_call_t *)svr4_sys_recv },		/* 237 = svr4_sys_recv */
	{ 6, (sy_call_t *)recvfrom },			/* 238 = recvfrom */
	{ 3, (sy_call_t *)recvmsg },			/* 239 = recvmsg */
	{ 4, (sy_call_t *)svr4_sys_send },		/* 240 = svr4_sys_send */
	{ 3, (sy_call_t *)sendmsg },			/* 241 = sendmsg */
	{ 6, (sy_call_t *)svr4_sys_sendto },		/* 242 = svr4_sys_sendto */
	{ 3, (sy_call_t *)getpeername },		/* 243 = getpeername */
	{ 3, (sy_call_t *)getsockname },		/* 244 = getsockname */
	{ 5, (sy_call_t *)getsockopt },			/* 245 = getsockopt */
	{ 5, (sy_call_t *)setsockopt },			/* 246 = setsockopt */
	{ 0, (sy_call_t *)nosys },			/* 247 = sockconfig */
	{ 0, (sy_call_t *)nosys },			/* 248 = { */
	{ 0, (sy_call_t *)nosys },			/* 249 = { */
};
