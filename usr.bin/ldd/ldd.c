/*
 * Copyright (c) 1993 Paul Kranenburg
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Paul Kranenburg.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *	$Id: ldd.c,v 1.15 1998/05/01 08:40:11 dfr Exp $
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <a.out.h>
#include <elf.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern void	dump_file __P((const char *));
extern int	error_count;

void
usage()
{
	fprintf(stderr, "usage: ldd [-v] [-f format] program ...\n");
	exit(1);
}

int
main(argc, argv)
int	argc;
char	*argv[];
{
	char		*fmt1 = NULL, *fmt2 = NULL;
	int		rval;
	int		c;
	int		vflag = 0;

	while ((c = getopt(argc, argv, "vf:")) != EOF) {
		switch (c) {
		case 'v':
			vflag++;
			break;
		case 'f':
			if (fmt1) {
				if (fmt2)
					errx(1, "Too many formats");
				fmt2 = optarg;
			} else
				fmt1 = optarg;
			break;
		default:
			usage();
			/*NOTREACHED*/
		}
	}
	argc -= optind;
	argv += optind;

	if (vflag && fmt1)
		errx(1, "-v may not be used with -f");

	if (argc <= 0) {
		usage();
		/*NOTREACHED*/
	}

	if (vflag) {
		for (c = 0; c < argc; c++)
			dump_file(argv[c]);
		exit(error_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	/* ld.so magic */
	setenv("LD_TRACE_LOADED_OBJECTS", "1", 1);
	if (fmt1)
		setenv("LD_TRACE_LOADED_OBJECTS_FMT1", fmt1, 1);
	if (fmt2)
		setenv("LD_TRACE_LOADED_OBJECTS_FMT2", fmt2, 1);

	rval = 0;
	for ( ;  argc > 0;  argc--, argv++) {
		int	fd;
		union {
			struct exec aout;
			Elf32_Ehdr elf;
		} hdr;
		int	n;
		int	status;
		int	file_ok;

		if ((fd = open(*argv, O_RDONLY, 0)) < 0) {
			warn("%s", *argv);
			rval |= 1;
			continue;
		}
		if ((n = read(fd, &hdr, sizeof hdr)) == -1) {
			warn("%s: can't read program header", *argv);
			(void)close(fd);
			rval |= 1;
			continue;
		}

		file_ok = 1;
		if (n >= sizeof hdr.aout && !N_BADMAG(hdr.aout)) {
			/* a.out file */
			if ((N_GETFLAG(hdr.aout) & EX_DPMASK) != EX_DYNAMIC
#if 1 /* Compatibility */
			    || hdr.aout.a_entry < __LDPGSZ
#endif
				) {
				warnx("%s: not a dynamic executable", *argv);
				file_ok = 0;
			}
		} else if (n >= sizeof hdr.elf && IS_ELF(hdr.elf)) {
			Elf32_Ehdr ehdr;
			Elf32_Phdr phdr;
			int dynamic = 0, i;

			lseek(fd, 0, SEEK_SET);
			if (read(fd, &ehdr, sizeof ehdr) != sizeof ehdr) {
				warnx("%s: can't read program header", *argv);
				file_ok = 0;
			}
			lseek(fd, 0, ehdr.e_phoff);
			for (i = 0; i < ehdr.e_phnum; i++) {
				if (read(fd, &phdr, ehdr.e_phentsize)
				   != sizeof phdr) {
					warnx("%s: can't read program header",
					    *argv);
					file_ok = 0;
				}
				if (phdr.p_type == PT_DYNAMIC)
					dynamic = 1;
			}
			if (!dynamic) {
				warnx("%s: not a dynamic executable", *argv);
				file_ok = 0;
			}
		} else {
			warnx("%s: not a dynamic executable", *argv);
			file_ok = 0;
		}
		(void)close(fd);
		if (!file_ok) {
			rval |= 1;
			continue;
		}

		setenv("LD_TRACE_LOADED_OBJECTS_PROGNAME", *argv, 1);
		if (fmt1 == NULL && fmt2 == NULL)
			/* Default formats */
			printf("%s:\n", *argv);

		fflush(stdout);

		switch (fork()) {
		case -1:
			err(1, "fork");
			break;
		default:
			if (wait(&status) <= 0) {
				warn("wait");
				rval |= 1;
			} else if (WIFSIGNALED(status)) {
				fprintf(stderr, "%s: signal %d\n",
						*argv, WTERMSIG(status));
				rval |= 1;
			} else if (WIFEXITED(status) && WEXITSTATUS(status)) {
				fprintf(stderr, "%s: exit status %d\n",
						*argv, WEXITSTATUS(status));
				rval |= 1;
			}
			break;
		case 0:
			rval |= execl(*argv, *argv, NULL) != 0;
			perror(*argv);
			_exit(1);
		}
	}

	return rval;
}
