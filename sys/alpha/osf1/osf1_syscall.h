/*
 * System call numbers.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * $FreeBSD$
 * created from;	FreeBSD: src/sys/alpha/osf1/syscalls.master,v 1.5 2001/09/01 19:36:47 dillon Exp 
 */

#define	OSF1_SYS_nosys	0
#define	OSF1_SYS_exit	1
#define	OSF1_SYS_fork	2
#define	OSF1_SYS_read	3
#define	OSF1_SYS_write	4
#define	OSF1_SYS_close	6
#define	OSF1_SYS_osf1_wait4	7
#define	OSF1_SYS_link	9
#define	OSF1_SYS_unlink	10
#define	OSF1_SYS_chdir	12
#define	OSF1_SYS_fchdir	13
#define	OSF1_SYS_osf1_mknod	14
#define	OSF1_SYS_chmod	15
#define	OSF1_SYS_chown	16
#define	OSF1_SYS_obreak	17
#define	OSF1_SYS_osf1_getfsstat	18
#define	OSF1_SYS_osf1_lseek	19
#define	OSF1_SYS_getpid	20
#define	OSF1_SYS_osf1_mount	21
#define	OSF1_SYS_osf1_unmount	22
#define	OSF1_SYS_osf1_setuid	23
#define	OSF1_SYS_getuid	24
#define	OSF1_SYS_recvfrom	29
#define	OSF1_SYS_accept	30
#define	OSF1_SYS_getpeername	31
#define	OSF1_SYS_getsockname	32
#define	OSF1_SYS_osf1_access	33
#define	OSF1_SYS_sync	36
#define	OSF1_SYS_osf1_kill	37
#define	OSF1_SYS_setpgid	39
#define	OSF1_SYS_dup	41
#define	OSF1_SYS_pipe	42
#define	OSF1_SYS_osf1_set_program_attributes	43
#define	OSF1_SYS_osf1_open	45
				/* 46 is obsolete sigaction */
#define	OSF1_SYS_getgid	47
#define	OSF1_SYS_osf1_sigprocmask	48
#define	OSF1_SYS_getlogin	49
#define	OSF1_SYS_setlogin	50
#define	OSF1_SYS_acct	51
#define	OSF1_SYS_osf1_sigpending	52
#define	OSF1_SYS_osf1_classcntl	53
#define	OSF1_SYS_osf1_ioctl	54
#define	OSF1_SYS_osf1_reboot	55
#define	OSF1_SYS_revoke	56
#define	OSF1_SYS_symlink	57
#define	OSF1_SYS_readlink	58
#define	OSF1_SYS_osf1_execve	59
#define	OSF1_SYS_umask	60
#define	OSF1_SYS_chroot	61
#define	OSF1_SYS_getpgrp	63
#define	OSF1_SYS_ogetpagesize	64
#define	OSF1_SYS_vfork	66
#define	OSF1_SYS_osf1_stat	67
#define	OSF1_SYS_osf1_lstat	68
#define	OSF1_SYS_osf1_mmap	71
#define	OSF1_SYS_munmap	73
#define	OSF1_SYS_mprotect	74
#define	OSF1_SYS_osf1_madvise	75
#define	OSF1_SYS_getgroups	79
#define	OSF1_SYS_setgroups	80
#define	OSF1_SYS_osf1_setpgrp	82
#define	OSF1_SYS_osf1_setitimer	83
#define	OSF1_SYS_osf1_table	85
#define	OSF1_SYS_osf1_getitimer	86
#define	OSF1_SYS_ogethostname	87
#define	OSF1_SYS_osethostname	88
#define	OSF1_SYS_getdtablesize	89
#define	OSF1_SYS_dup2	90
#define	OSF1_SYS_osf1_fstat	91
#define	OSF1_SYS_osf1_fcntl	92
#define	OSF1_SYS_osf1_select	93
#define	OSF1_SYS_poll	94
#define	OSF1_SYS_fsync	95
#define	OSF1_SYS_setpriority	96
#define	OSF1_SYS_osf1_socket	97
#define	OSF1_SYS_connect	98
#define	OSF1_SYS_oaccept	99
#define	OSF1_SYS_getpriority	100
#define	OSF1_SYS_osend	101
#define	OSF1_SYS_orecv	102
#define	OSF1_SYS_osf1_sigreturn	103
#define	OSF1_SYS_bind	104
#define	OSF1_SYS_setsockopt	105
#define	OSF1_SYS_listen	106
#define	OSF1_SYS_osf1_sigsuspend	111
#define	OSF1_SYS_osf1_osigstack	112
#define	OSF1_SYS_osf1_gettimeofday	116
#define	OSF1_SYS_osf1_getrusage	117
#define	OSF1_SYS_getsockopt	118
#define	OSF1_SYS_osf1_readv	120
#define	OSF1_SYS_osf1_writev	121
#define	OSF1_SYS_settimeofday	122
#define	OSF1_SYS_fchown	123
#define	OSF1_SYS_fchmod	124
#define	OSF1_SYS_orecvfrom	125
#define	OSF1_SYS_setreuid	126
#define	OSF1_SYS_setregid	127
#define	OSF1_SYS_rename	128
#define	OSF1_SYS_osf1_truncate	129
#define	OSF1_SYS_osf1_ftruncate	130
#define	OSF1_SYS_flock	131
#define	OSF1_SYS_osf1_setgid	132
#define	OSF1_SYS_osf1_sendto	133
#define	OSF1_SYS_shutdown	134
#define	OSF1_SYS_mkdir	136
#define	OSF1_SYS_rmdir	137
#define	OSF1_SYS_utimes	138
				/* 139 is obsolete 4.2 sigreturn */
#define	OSF1_SYS_ogetpeername	141
#define	OSF1_SYS_ogethostid	142
#define	OSF1_SYS_osethostid	143
#define	OSF1_SYS_osf1_getrlimit	144
#define	OSF1_SYS_osf1_setrlimit	145
#define	OSF1_SYS_setsid	147
#define	OSF1_SYS_oquota	149
#define	OSF1_SYS_ogetsockname	150
#define	OSF1_SYS_osf1_sigaction	156
#define	OSF1_SYS_ogetdirentries	159
#define	OSF1_SYS_osf1_statfs	160
#define	OSF1_SYS_osf1_fstatfs	161
#define	OSF1_SYS_getdomainname	165
#define	OSF1_SYS_setdomainname	166
#define	OSF1_SYS_msgctl	200
#define	OSF1_SYS_msgget	201
#define	OSF1_SYS_msgrcv	202
#define	OSF1_SYS_msgsnd	203
#define	OSF1_SYS___semctl	204
#define	OSF1_SYS_semget	205
#define	OSF1_SYS_semop	206
#define	OSF1_SYS_uname	207
#define	OSF1_SYS_lchown	208
#define	OSF1_SYS_shmat	209
#define	OSF1_SYS_shmctl	210
#define	OSF1_SYS_shmdt	211
#define	OSF1_SYS_shmget	212
#define	OSF1_SYS_osf1_msync	217
#define	OSF1_SYS_osf1_signal	218
#define	OSF1_SYS_getpgid	233
#define	OSF1_SYS_getsid	234
#define	OSF1_SYS_osf1_sigaltstack	235
#define	OSF1_SYS_osf1_sysinfo	241
#define	OSF1_SYS_osf1_proplist_syscall	244
#define	OSF1_SYS_osf1_ntpadjtime	245
#define	OSF1_SYS_osf1_ntpgettime	246
#define	OSF1_SYS_osf1_pathconf	247
#define	OSF1_SYS_osf1_fpathconf	248
#define	OSF1_SYS_osf1_uswitch	250
#define	OSF1_SYS_osf1_usleep_thread	251
#define	OSF1_SYS_osf1_getsysinfo	256
#define	OSF1_SYS_osf1_setsysinfo	257
#define	OSF1_SYS_MAXSYSCALL	301
