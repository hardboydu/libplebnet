/*-
 * Copyright (c) 2000 S�ren Schmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification, immediately at the beginning of the file.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
 * $FreeBSD$
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <sysexits.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/cdio.h>
#include <sys/cdrio.h>

#define BLOCKS	32

static int fd, saved_block_size;
void cleanup(int);

int
main(int argc, char **argv)
{
	int ch, speed = 1, preemp = 0, test_write = 0, eject = 0, quiet = 0;
	char *devname = "/dev/acd0c";
	char buf[2352*BLOCKS];
	int arg, file, addr, count;
	int block_size, cdopen = 0, size, tot_size = 0;
	struct cdr_track track;

	while ((ch = getopt(argc, argv, "ef:pqs:")) != -1) {
		switch (ch) {
		case 'e':
			eject = 1;
			break;

		case 'f':
			devname = optarg;
			break;

		case 'p':
			preemp = 1;
			break;

		case 'q':
			quiet = 1;
			break;

		case 's':
			speed = atoi(optarg);
			break;

		case 't':
			test_write = 1;
			break;

		default: 
		}
	}
	argc -= optind;
	argv += optind;

	if ((fd = open(devname, O_RDWR, 0)) < 0)
		err(EX_NOINPUT, "open(%s)", devname);

	if (ioctl(fd, CDRIOCWRITESPEED, &speed) < 0) 
       		err(EX_IOERR, "ioctl(CDRIOCWRITESPEED)");

	if (ioctl(fd, CDRIOCGETBLOCKSIZE, &saved_block_size) < 0) 
       		err(EX_IOERR, "ioctl(CDRIOCGETBLOCKSIZE)");

	err_set_exit(cleanup);

	for (arg = 0; arg < argc; arg++) {
		if (!strcmp(argv[arg], "blank")) {
			if (!quiet)
				fprintf(stderr, "blanking CD, please wait..\n");
			if (ioctl(fd, CDRIOCBLANK) < 0)
        			err(EX_IOERR, "ioctl(CDRIOCBLANK)");
			continue;
		}
		if (!strcmp(argv[arg], "fixate")) {
			if (!quiet)
				fprintf(stderr, "fixating CD, please wait..\n");
			if (ioctl(fd, CDRIOCCLOSEDISK) < 0)
        			err(EX_IOERR, "ioctl(CDRIOCCLOSEDISK)");
			break;
		}
		if (!strcmp(argv[arg], "audio") || !strcmp(argv[arg], "raw")) {
			track.test_write = test_write;
			track.track_type = CDR_DB_RAW;
			track.preemp = preemp;
			block_size = 2352;
			continue;
		}
		if (!strcmp(argv[arg], "data") || !strcmp(argv[arg], "mode1")) {
			track.test_write = test_write;
			track.track_type = CDR_DB_ROM_MODE1;
			track.preemp = 0;
			block_size = 2048;
			continue;
		}
		if ((file = open(argv[arg], O_RDONLY, 0)) < 0) {
			err(EX_NOINPUT, "open(%s)", argv[arg]);
		}
		if (!cdopen) {
			if (ioctl(fd, CDRIOCOPENDISK) < 0)
        			err(EX_IOERR, "ioctl(CDRIOCOPENDISK)");
			cdopen = 1;
		}
		if (ioctl(fd, CDRIOCOPENTRACK, &track) < 0)
        		err(EX_IOERR, "ioctl(CDRIOCOPENTRACK)");

		if (ioctl(fd, CDRIOCNEXTWRITEABLEADDR, &addr) < 0) 
        		err(EX_IOERR, "ioctl(CDRIOCNEXTWRITEABLEADDR)");

		if (!quiet) {
			fprintf(stderr, "next writeable LBA %d\n", addr);
			fprintf(stderr, "writing from file %s\n", argv[arg]);
		}
		lseek(fd, 0, SEEK_SET);
		size = 0;

		while ((count = read(file, buf, block_size * BLOCKS)) > 0) {	
			if (count % block_size) {
				/* pad file to % block_size */
				bzero(&buf[count], block_size * BLOCKS - count);
				count = ((count / block_size) + 1) * block_size;
			}
			if (write(fd, buf, count) != count) {
				int res;

				fprintf(stderr, "\nonly wrote %d of %d bytes\n",
					res, count);
				break;
			}
			size += count;
			tot_size += count;
			if (!quiet)
				fprintf(stderr, "written this track %d KB"
						" total %d KB\r",
						size/1024, tot_size/1024);
		}
		if (!quiet)
			fprintf(stderr, "\n");
		close(file);
		if (ioctl(fd, CDRIOCCLOSETRACK) < 0)
        		err(EX_IOERR, "ioctl(CDRIOCCLOSETRACK)");
	}

	if (ioctl(fd, CDRIOCSETBLOCKSIZE, &saved_block_size) < 0) 
       		err(EX_IOERR, "ioctl(CDRIOCGETBLOCKSIZE)");

	if (eject)
		if (ioctl(fd, CDIOCEJECT) < 0)
			err(EX_IOERR, "ioctl(CDIOCEJECT)");
	close(fd);
}

void cleanup(int dummy)
{
	if (ioctl(fd, CDRIOCGETBLOCKSIZE, &saved_block_size) < 0) 
       		err(EX_IOERR, "ioctl(CDRIOCGETBLOCKSIZE)");
}
