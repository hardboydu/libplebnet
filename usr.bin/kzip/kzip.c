/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * Copyright (C) 1993  Hannu Savolainen
 * Ported to 386bsd by Serge Vakulenko
 * based on tools/build.c by Linus Torvalds
 * $Id: kzip.c,v 1.7 1997/02/22 19:55:31 peter Exp $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <a.out.h>
#include <string.h>

#define MAXIMAGE	(2*1024*1024)
	/* This is the limit because a kzip'ed kernel loads at 3Mb and
	 * ends up at 1Mb
	 */
void
Usage(char *prog)
{
	fprintf(stderr,"usage:\n\t%s [-v] [ -l loadaddr] kernel\n", prog);
	exit(1);
}

int
main(int argc, char **argv)
{
	pid_t Pext, Pgzip, Ppiggy, Pld;
	int pipe1[2], pipe2[2];
	int status, fdi, fdo, fdn, c, verbose;
	int size;
	struct exec hdr;
	int zip_size, offset;
	struct stat st;
	u_long forceaddr = 0, addr, entry;
	char *kernname;
	char obj[BUFSIZ];
	char out[BUFSIZ];
	char base[32];
	
	while ((c = getopt(argc, argv, "l:v")) != -1) {
		switch (c) {
		case 'l':
			forceaddr = strtoul(optarg, NULL, 0);
			if (forceaddr == 0) {
				fprintf(stderr, "Invalid load address!\n");
				exit(1);
			}
			break;
		case 'v':
			verbose++;
			break;
		default:
			Usage(argv[0]);
			break;
		}
	}

	if ((argc - optind) != 1)
		Usage(argv[0]);

	argc -= optind;
	argv += optind;

	kernname = argv[0];
			
	strcpy(obj, kernname); strcat(obj,".o");
	strcpy(out, kernname); strcat(out,".kz");

	fdi = open(kernname ,O_RDONLY);
	if(fdi<0) {
		perror(kernname);
		return 2;
	}

	/* figure out how big the uncompressed image will be */
	if (read (fdi, (char *)&hdr, sizeof(hdr)) != sizeof(hdr)) {
		perror(argv[1]);
		exit(2);
	}

	size = hdr.a_text + hdr.a_data + hdr.a_bss;
	entry = hdr.a_entry - 0xf0000000;	/* replace KZBASE */

	lseek (fdi, 0, SEEK_SET);

	if (verbose) {
		printf("real kernel start address will be: 0x%x\n", entry);
		printf("real kernel end   address will be: 0x%x\n", entry+size);
	}


	fdo = open(obj,O_WRONLY|O_TRUNC|O_CREAT,0666);
	if(fdo<0) {
		perror(obj);
		return 2;
	}

	if (pipe(pipe1) < 0) { perror("pipe()"); return 1; }

	if (pipe(pipe2) < 0) { perror("pipe()"); return 1; }

	Pext = fork();
	if (Pext < 0) { perror("fork()"); return 1; }
	if (!Pext) {
		dup2(fdi,0);
		dup2(pipe1[1],1);
		close(pipe1[0]); close(pipe1[1]);
		close(pipe2[0]); close(pipe2[1]);
		close(fdi); close(fdo);
		extract(kernname);
		exit(0);
	}

	Pgzip = fork();
	if (Pgzip < 0) { perror("fork()"); return 1; }
	if (!Pgzip) {
		dup2(pipe1[0],0);
		dup2(pipe2[1],1);
		close(pipe1[0]); close(pipe1[1]);
		close(pipe2[0]); close(pipe2[1]);
		close(fdi); close(fdo);
		execlp("gzip", "gzip", "-9", "-n", 0);
		exit (0);
	}

	Ppiggy = fork();
	if (Ppiggy < 0) { perror("fork()"); return 1; }
	if (!Ppiggy) {
		dup2(pipe2[0],0);
		dup2(fdo,1);
		close(pipe1[0]); close(pipe1[1]);
		close(pipe2[0]); close(pipe2[1]);
		close(fdi); close(fdo);
		piggyback(obj);
		exit(0);
	}

	close(pipe1[0]); close(pipe1[1]);
	close(pipe2[0]); close(pipe2[1]);
	close(fdi); close(fdo);

	if (waitpid(Pext, &status,0) < 0)
		{ perror("waitpid(Pextract)"); return 1; }

	if(status) {
		fprintf(stderr,"extract returned %x\n",status);
		return 3;
	}

	if (waitpid(Pgzip, &status,0) < 0)
		{ perror("waitpid(Pgzip)"); return 1; }

	if(status) {
		fprintf(stderr,"gzip returned %x\n",status);
		return 3;
	}

	if (waitpid(Ppiggy, &status,0) < 0)
		{ perror("waitpid(Ppiggy)"); return 1; }

	if(status) {
		fprintf(stderr,"piggyback returned %x\n",status);
		return 3;
	}

	if (forceaddr)
		offset = forceaddr;
	else {
		/* a kludge to dynamically figure out where to start it */
		if (stat (obj, &st) < 0) {
			perror("cannot get size of compressed data");
			return 3;
		}
		zip_size = (int)st.st_size;
		offset = entry + size - zip_size + 0x8000; /* fudge factor */
	}
	sprintf(base, "0x%x", roundup(offset, 4096));

	Pld = fork();
	if (Pld < 0) { perror("fork()"); return 1; }
	if (!Pld) {
		execlp("ld",
			"ld",
			"-Bstatic",
			"-Z",
			"-T",
			base,
			"-o",
			out,
			"/usr/lib/kzhead.o",
			obj,
			"/usr/lib/kztail.o",
			0);
		exit(2);
	}

	if (waitpid(Pld, &status,0) < 0)
		{ perror("waitpid(Pld)"); return 1; }

	if(status) {
		fprintf(stderr,"ld returned %x\n",status);
		return 3;
	}

	if (verbose) {

		fdn = open(obj ,O_RDONLY);
		if(fdn<0) {
			perror(obj);
			return 3;
		}

		/* figure out how big the compressed image is */
		if (read (fdn, (char *)&hdr, sizeof(hdr)) != sizeof(hdr)) {
			perror(obj);
			return 3;
		}
		close(fdn);

		size = hdr.a_text + hdr.a_data + hdr.a_bss;

		printf("kzip data   start address will be: 0x%x\n",offset);
		printf("kzip data   end   address will be: 0x%x\n",offset+size);
	}

	unlink(obj);
	exit(0);
}

int
extract (char *file)
{
	int sz;
	char buf[BUFSIZ];
	struct exec hdr;

	if (read (0, (char *)&hdr, sizeof(hdr)) != sizeof(hdr)) {
		perror(file);
		exit(2);
	}
	if (hdr.a_magic != ZMAGIC) {
		fprintf(stderr,"Bad magic in file %s, probably not a kernel\n",
			file);
		exit(2);
	}
	if (lseek (0, N_TXTOFF(hdr), 0) < 0) {
		perror(file);
		exit(2);
	}

	sz = N_SYMOFF (hdr) - N_TXTOFF (hdr);

	while (sz) {
		int l, n;

		l = sz;
		if (l > sizeof(buf))
			l = sizeof(buf);

		n = read (0, buf, l);
		if (n != l) {
			if (n == -1)
				perror (file);
			else
				fprintf (stderr, "Unexpected EOF\n");

			exit(1);
		}

		write (1, buf, l);
		sz -= l;
	}
	exit(0);
}


char string_names[] = {"_input_data\0_input_len\0"};

struct nlist var_names[2] = {                           /* Symbol table */
	{ { (char*)  4 }, N_EXT|N_TEXT, 0, 0, 0 },      /* _input_data  */
	{ { (char*) 16 }, N_EXT|N_TEXT, 0, 0, 0 },      /* _input_len */
};

int
piggyback(char *file)
{
	int n, len;
	struct exec hdr;                        /* object header */
	char image[MAXIMAGE];                   /* kernel image buffer */

	len = 0;
	while ((n = read (0, &image[len], sizeof(image)-len+1)) > 0)
	      len += n;

	if (n < 0) {
		perror ("stdin");
		exit (1);
	}

	if (len >= sizeof(image)) {
		fprintf (stderr,"Input too large\n");
		exit (1);
	}

	/*
	 *      Output object header
	 */
	memset(&hdr,0,sizeof hdr);
	hdr.a_magic = OMAGIC;
	hdr.a_text = len + sizeof(long);
	hdr.a_syms = sizeof(var_names);
	write (1, (char *)&hdr, sizeof(hdr));

	/*
	 *      Output text segment (compressed system & len)
	 */
	write (1, image, len);
	write (1, (char *)&len, sizeof(len));

	/*
	 *      Output symbol table
	 */
	var_names[1].n_value = len;
	write (1, (char *)&var_names, sizeof(var_names));

	/*
	 *      Output string table
	 */
	len = sizeof(string_names) + sizeof(len);
	write (1, (char *)&len, sizeof(len));
	write (1, string_names, sizeof(string_names));

	return (0);
}
