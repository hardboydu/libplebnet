/*
 *  Copyright (c) 2004 Lukas Ertl
 *  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/utsname.h>

#include <geom/vinum/geom_vinum_var.h>
#include <geom/vinum/geom_vinum_share.h>

#include <ctype.h>
#include <err.h>
#include <libgeom.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <paths.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <unistd.h>

#include "gvinum.h"

void	gvinum_cancelinit(int, char **);
void	gvinum_create(int, char **);
void	gvinum_help(void);
void	gvinum_init(int, char **);
void	gvinum_list(int, char **);
void	gvinum_printconfig(int, char **);
void	gvinum_rm(int, char **);
void	gvinum_saveconfig(void);
void	gvinum_start(int, char **);
void	gvinum_stop(int, char **);
void	parseline(int, char **);
void	printconfig(FILE *, char *);

int
main(int argc, char **argv)
{
	int line, tokens;
	char buffer[BUFSIZ], *inputline, *token[GV_MAXARGS];

	/* Load the module if necessary. */
	if (kldfind(GVINUMMOD) < 0 && kldload(GVINUMMOD) < 0)
		err(1, GVINUMMOD ": Kernel module not available");

	/* Arguments given on the command line. */
	if (argc > 1) {
		argc--;
		argv++;
		parseline(argc, argv);

	/* Interactive mode. */
	} else {
		for (;;) {
			inputline = readline("gvinum -> ");
			if (inputline == NULL) {
				if (ferror(stdin)) {
					err(1, "can't read input");
				} else {
					printf("\n");
					exit(0);
				}
			} else if (*inputline) {
				add_history(inputline);
				strcpy(buffer, inputline);
				free(inputline);
				line++;		    /* count the lines */
				tokens = gv_tokenize(buffer, token, GV_MAXARGS);
				if (tokens)
					parseline(tokens, token);
			}
		}
	}
	exit(0);
}

void
gvinum_cancelinit(int argc, char **argv)
{
	struct gctl_req *req;
	int i;
	const char *errstr;
	char buf[20];

	if (argc == 1)
		return;

	argc--;
	argv++;

	req = gctl_get_handle();
	gctl_ro_param(req, "class", -1, "VINUM");
	gctl_ro_param(req, "verb", -1, "cancelinit");
	gctl_ro_param(req, "argc", sizeof(int), &argc);
	if (argc) {
		for (i = 0; i < argc; i++) {
			snprintf(buf, sizeof(buf), "argv%d", i);
			gctl_ro_param(req, buf, -1, argv[i]);
		}
	}
	errstr = gctl_issue(req);
	if (errstr != NULL) {
		warnx("can't init: %s", errstr);
		gctl_free(req);
		return;
	}

	gctl_free(req);
	gvinum_list(0, NULL);
}

void
gvinum_create(int argc, char **argv)
{
	struct gctl_req *req;
	struct gv_drive *d;
	struct gv_plex *p;
	struct gv_sd *s;
	struct gv_volume *v;
	FILE *tmp;
	int drives, errors, fd, line, plexes, plex_in_volume;
	int sd_in_plex, status, subdisks, tokens, volumes;
	const char *errstr;
	char buf[BUFSIZ], buf1[BUFSIZ], commandline[BUFSIZ], *ed;
	char original[BUFSIZ], tmpfile[20], *token[GV_MAXARGS];
	char plex[GV_MAXPLEXNAME], volume[GV_MAXVOLNAME];

	if (argc == 2) {
		if ((tmp = fopen(argv[1], "r")) == NULL) {
			warn("can't open '%s' for reading", argv[1]);
			return;
		}
	} else {
		snprintf(tmpfile, sizeof(tmpfile), "/tmp/gvinum.XXXXXX");
		
		if ((fd = mkstemp(tmpfile)) == -1) {
			warn("temporary file not accessible");
			return;
		}
		if ((tmp = fdopen(fd, "w")) == NULL) {
			warn("can't open '%s' for writing", tmpfile);
			return;
		}
		printconfig(tmp, "# ");
		fclose(tmp);
		
		ed = getenv("EDITOR");
		if (ed == NULL)
			ed = _PATH_VI;
		
		snprintf(commandline, sizeof(commandline), "%s %s", ed,
		    tmpfile);
		status = system(commandline);
		if (status != 0) {
			warn("couldn't exec %s; status: %d", ed, status);
			return;
		}
		
		if ((tmp = fopen(tmpfile, "r")) == NULL) {
			warn("can't open '%s' for reading", tmpfile);
			return;
		}
	}

	req = gctl_get_handle();
	gctl_ro_param(req, "class", -1, "VINUM");
	gctl_ro_param(req, "verb", -1, "create");

	drives = volumes = plexes = subdisks = 0;
	plex_in_volume = sd_in_plex = 0;
	errors = 0;
	line = 1;
	while ((fgets(buf, BUFSIZ, tmp)) != NULL) {

		/* Skip empty lines and comments. */
		if (*buf == '\0' || *buf == '#') {
			line++;
			continue;
		}

		/* Kill off the newline. */
		buf[strlen(buf) - 1] = '\0';

		/*
		 * Copy the original input line in case we need it for error
		 * output.
		 */
		strncpy(original, buf, sizeof(buf));

		tokens = gv_tokenize(buf, token, GV_MAXARGS);

		if (tokens > 0) {
			/* Volume definition. */
			if (!strcmp(token[0], "volume")) {
				v = gv_new_volume(tokens, token);
				if (v == NULL) {
					warnx("line %d: invalid volume "
					    "definition", line);
					warnx("line %d: '%s'", line, original);
					errors++;
				} else {
					/* Reset plex count for this volume. */
					plex_in_volume = 0;

					/*
					 * Set default volume name for
					 * following plex definitions.
					 */
					strncpy(volume, v->name,
					    sizeof(volume));

					snprintf(buf1, sizeof(buf1), "volume%d",
					    volumes);
					gctl_ro_param(req, buf1, sizeof(*v), v);
					volumes++;
				}

			/* Plex definition. */
			} else if (!strcmp(token[0], "plex")) {
				p = gv_new_plex(tokens, token);
				if (p == NULL) {
					warnx("line %d: invalid plex "
					    "definition", line);
					warnx("line %d: '%s'", line, original);
					errors++;
				} else {
					/* Reset subdisk count for this plex. */
					sd_in_plex = 0;

					/* Default name. */
					if (strlen(p->name) == 0) {
						snprintf(p->name,
						    GV_MAXPLEXNAME,
						    "%s.p%d", volume,
						    plex_in_volume++);
					}

					/* Default volume. */
					if (strlen(p->volume) == 0) {
						snprintf(p->volume,
						    GV_MAXVOLNAME, "%s",
						    volume);
					}

					/*
					 * Set default plex name for following
					 * subdisk definitions.
					 */
					strncpy(plex, p->name, GV_MAXPLEXNAME);

					snprintf(buf1, sizeof(buf1), "plex%d",
					    plexes);
					gctl_ro_param(req, buf1, sizeof(*p), p);
					plexes++;
				}

			/* Subdisk definition. */
			} else if (!strcmp(token[0], "sd")) {
				s = gv_new_sd(tokens, token);
				if (s == NULL) {
					warnx("line %d: invalid subdisk "
					    "definition:", line);
					warnx("line %d: '%s'", line, original);
					errors++;
				} else {
					/* Default name. */
					if (strlen(s->name) == 0) {
						snprintf(s->name, GV_MAXSDNAME,
						    "%s.s%d", plex,
						    sd_in_plex++);
					}

					/* Default plex. */
					if (strlen(s->plex) == 0) {
						snprintf(s->plex,
						    GV_MAXPLEXNAME, "%s", plex);
					}
			
					snprintf(buf1, sizeof(buf1), "sd%d",
					    subdisks);
					gctl_ro_param(req, buf1, sizeof(*s), s);
					subdisks++;
				}

			/* Subdisk definition. */
			} else if (!strcmp(token[0], "drive")) {
				d = gv_new_drive(tokens, token);
				if (d == NULL) {
					warnx("line %d: invalid drive "
					    "definition:", line);
					warnx("line %d: '%s'", line, original);
					errors++;
				} else {
					snprintf(buf1, sizeof(buf1), "drive%d",
					    drives);
					gctl_ro_param(req, buf1, sizeof(*d), d);
					drives++;
				}

			/* Everything else is bogus. */
			} else {
				warnx("line %d: invalid definition:", line);
				warnx("line %d: '%s'", line, original);
				errors++;
			}
		}
		line++;
	}

	fclose(tmp);
	unlink(tmpfile);

	if (!errors && (volumes || plexes || subdisks || drives)) {
		gctl_ro_param(req, "volumes", sizeof(int), &volumes);
		gctl_ro_param(req, "plexes", sizeof(int), &plexes);
		gctl_ro_param(req, "subdisks", sizeof(int), &subdisks);
		gctl_ro_param(req, "drives", sizeof(int), &drives);
		errstr = gctl_issue(req);
		if (errstr != NULL)
			warnx("create failed: %s", errstr);
	}
	gctl_free(req);
	gvinum_list(0, NULL);
}

void
gvinum_help(void)
{
	printf("COMMANDS\n"
	    "attach plex volume [rename]\n"
	    "attach subdisk plex [offset] [rename]\n"
	    "        Attach a plex to a volume, or a subdisk to a plex.\n"
	    "checkparity plex [-f] [-v]\n"
	    "        Check the parity blocks of a RAID-4 or RAID-5 plex.\n"
	    "concat [-f] [-n name] [-v] drives\n"
	    "        Create a concatenated volume from the specified drives.\n"
	    "create [-f] description-file\n"
	    "        Create a volume as described in description-file.\n"
	    "detach [-f] [plex | subdisk]\n"
	    "        Detach a plex or subdisk from the volume or plex to"
	    "which it is\n"
	    "        attached.\n"
	    "dumpconfig [drive ...]\n"
	    "        List the configuration information stored on the"
	    " specified\n"
	    "        drives, or all drives in the system if no drive names"
	    " are speci-\n"
	    "        fied.\n"
	    "info [-v] [-V]\n"
	    "        List information about volume manager state.\n"
	    "init [-S size] [-w] plex | subdisk\n"
	    "        Initialize the contents of a subdisk or all the subdisks"
	    " of a\n"
	    "        plex to all zeros.\n"
	    "label volume\n"
	    "        Create a volume label.\n"
	    "l | list [-r] [-s] [-v] [-V] [volume | plex | subdisk]\n"
	    "        List information about specified objects.\n"
	    "ld [-r] [-s] [-v] [-V] [volume]\n"
	    "        List information about drives.\n"
	    "ls [-r] [-s] [-v] [-V] [subdisk]\n"
	    "        List information about subdisks.\n"
	    "lp [-r] [-s] [-v] [-V] [plex]\n"
	    "        List information about plexes.\n"
	    "lv [-r] [-s] [-v] [-V] [volume]\n"
	    "        List information about volumes.\n"
	    "mirror [-f] [-n name] [-s] [-v] drives\n"
	    "        Create a mirrored volume from the specified drives.\n"
	    "move | mv -f drive object ...\n"
	    "        Move the object(s) to the specified drive.\n"
	    "printconfig [file]\n"
	    "        Write a copy of the current configuration to file.\n"
	    "quit    Exit the vinum program when running in interactive mode."
	    "  Nor-\n"
	    "        mally this would be done by entering the EOF character.\n"
	    "rename [-r] [drive | subdisk | plex | volume] newname\n"
	    "        Change the name of the specified object.\n"
	    "rebuildparity plex [-f] [-v] [-V]\n"
	    "        Rebuild the parity blocks of a RAID-4 or RAID-5 plex.\n"
	    "resetconfig\n"
	    "        Reset the complete vinum configuration.\n"
	    "rm [-f] [-r] volume | plex | subdisk\n"
	    "        Remove an object.\n"
	    "saveconfig\n"
	    "        Save vinum configuration to disk after configuration"
	    " failures.\n"
	    "setstate state [volume | plex | subdisk | drive]\n"
	    "        Set state without influencing other objects, for"
	    " diagnostic pur-\n"
	    "        poses only.\n"
	    "start [-i interval] [-S size] [-w] volume | plex | subdisk\n"
	    "        Allow the system to access the objects.\n"
	    "stop [-f] [volume | plex | subdisk]\n"
	    "        Terminate access to the objects, or stop vinum if no"
	    " parameters\n"
	    "        are specified.\n"
	    "stripe [-f] [-n name] [-v] drives\n"
	    "        Create a striped volume from the specified drives.\n"
	);

	return;
}

void
gvinum_init(int argc, char **argv)
{
	struct gctl_req *req;
	int i, initsize, j;
	const char *errstr;
	char buf[20];

	initsize = 0;
	optreset = 1;
	optind = 1;
	while ((j = getopt(argc, argv, "S")) != -1) {
		switch (j) {
		case 'S':
			initsize = atoi(optarg);
			break;
		case '?':
		default:
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (!initsize)
		initsize = 512;

	req = gctl_get_handle();
	gctl_ro_param(req, "class", -1, "VINUM");
	gctl_ro_param(req, "verb", -1, "init");
	gctl_ro_param(req, "argc", sizeof(int), &argc);
	gctl_ro_param(req, "initsize", sizeof(int), &initsize);
	if (argc) {
		for (i = 0; i < argc; i++) {
			snprintf(buf, sizeof(buf), "argv%d", i);
			gctl_ro_param(req, buf, -1, argv[i]);
		}
	}
	errstr = gctl_issue(req);
	if (errstr != NULL) {
		warnx("can't init: %s", errstr);
		gctl_free(req);
		return;
	}

	gctl_free(req);
	gvinum_list(0, NULL);
}

void
gvinum_list(int argc, char **argv)
{
	struct gctl_req *req;
	int flags, i, j;
	const char *errstr;
	char buf[20], *cmd, config[GV_CFG_LEN + 1];

	flags = 0;
	cmd = "list";

	if (argc) {
		optreset = 1;
		optind = 1;
		cmd = argv[0];
		while ((j = getopt(argc, argv, "rsvV")) != -1) {
			switch (j) {
			case 'r':
				flags |= GV_FLAG_R;
				break;
			case 's':
				flags |= GV_FLAG_S;
				break;
			case 'v':
				flags |= GV_FLAG_V;
				break;
			case 'V':
				flags |= GV_FLAG_V;
				flags |= GV_FLAG_VV;
				break;
			case '?':
			default:
				return;
			}
		}
		argc -= optind;
		argv += optind;

	}

	req = gctl_get_handle();
	gctl_ro_param(req, "class", -1, "VINUM");
	gctl_ro_param(req, "verb", -1, "list");
	gctl_ro_param(req, "cmd", -1, cmd);
	gctl_ro_param(req, "argc", sizeof(int), &argc);
	gctl_ro_param(req, "flags", sizeof(int), &flags);
	gctl_rw_param(req, "config", sizeof(config), config);
	if (argc) {
		for (i = 0; i < argc; i++) {
			snprintf(buf, sizeof(buf), "argv%d", i);
			gctl_ro_param(req, buf, -1, argv[i]);
		}
	}
	errstr = gctl_issue(req);
	if (errstr != NULL) {
		warnx("can't get configuration: %s", errstr);
		gctl_free(req);
		return;
	}

	printf("%s", config);
	gctl_free(req);
	return;
}

void
gvinum_printconfig(int argc, char **argv)
{
	printconfig(stdout, "");
}

void
gvinum_rm(int argc, char **argv)
{
	struct gctl_req *req;
	int flags, i, j;
	const char *errstr;
	char buf[20], *cmd;

	cmd = argv[0];
	flags = 0;
	optreset = 1;
	optind = 1;
	while ((j = getopt(argc, argv, "r")) != -1) {
		switch (j) {
		case 'r':
			flags |= GV_FLAG_R;
			break;
		case '?':
		default:
			return;
		}
	}
	argc -= optind;
	argv += optind;

	req = gctl_get_handle();
	gctl_ro_param(req, "class", -1, "VINUM");
	gctl_ro_param(req, "verb", -1, "remove");
	gctl_ro_param(req, "argc", sizeof(int), &argc);
	gctl_ro_param(req, "flags", sizeof(int), &flags);
	if (argc) {
		for (i = 0; i < argc; i++) {
			snprintf(buf, sizeof(buf), "argv%d", i);
			gctl_ro_param(req, buf, -1, argv[i]);
		}
	}
	errstr = gctl_issue(req);
	if (errstr != NULL) {
		warnx("can't remove: %s", errstr);
		gctl_free(req);
		return;
	}
	gctl_free(req);
	gvinum_list(0, NULL);
}

void
gvinum_saveconfig(void)
{
	struct gctl_req *req;
	const char *errstr;

	req = gctl_get_handle();
	gctl_ro_param(req, "class", -1, "VINUM");
	gctl_ro_param(req, "verb", -1, "saveconfig");
	errstr = gctl_issue(req);
	if (errstr != NULL)
		warnx("can't save configuration: %s", errstr);
	gctl_free(req);
}

void
gvinum_start(int argc, char **argv)
{
	struct gctl_req *req;
	int i, initsize, j;
	const char *errstr;
	char buf[20];

	/* 'start' with no arguments is a no-op. */
	if (argc == 1)
		return;

	initsize = 0;

	optreset = 1;
	optind = 1;
	while ((j = getopt(argc, argv, "S")) != -1) {
		switch (j) {
		case 'S':
			initsize = atoi(optarg);
			break;
		case '?':
		default:
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (!initsize)
		initsize = 512;

	req = gctl_get_handle();
	gctl_ro_param(req, "class", -1, "VINUM");
	gctl_ro_param(req, "verb", -1, "start");
	gctl_ro_param(req, "argc", sizeof(int), &argc);
	gctl_ro_param(req, "initsize", sizeof(int), &initsize);
	if (argc) {
		for (i = 0; i < argc; i++) {
			snprintf(buf, sizeof(buf), "argv%d", i);
			gctl_ro_param(req, buf, -1, argv[i]);
		}
	}
	errstr = gctl_issue(req);
	if (errstr != NULL) {
		warnx("can't start: %s", errstr);
		gctl_free(req);
		return;
	}

	gctl_free(req);
	gvinum_list(0, NULL);
}

void
gvinum_stop(int argc, char **argv)
{
	int fileid;

	fileid = kldfind(GVINUMMOD);
	if (fileid == -1) {
		warn("cannot find " GVINUMMOD);
		return;
	}
	if (kldunload(fileid) != 0) {
		warn("cannot unload " GVINUMMOD);
		return;
	}

	warnx(GVINUMMOD " unloaded");
	exit(0);
}

void
parseline(int argc, char **argv)
{
	if (argc <= 0)
		return;

	if (!strcmp(argv[0], "cancelinit"))
		gvinum_cancelinit(argc, argv);
	else if (!strcmp(argv[0], "create"))
		gvinum_create(argc, argv);
	else if (!strcmp(argv[0], "exit") || !strcmp(argv[0], "quit"))
		exit(0);
	else if (!strcmp(argv[0], "help"))
		gvinum_help();
	else if (!strcmp(argv[0], "init"))
		gvinum_init(argc, argv);
	else if (!strcmp(argv[0], "list") || !strcmp(argv[0], "l"))
		gvinum_list(argc, argv);
	else if (!strcmp(argv[0], "ld"))
		gvinum_list(argc, argv);
	else if (!strcmp(argv[0], "lp"))
		gvinum_list(argc, argv);
	else if (!strcmp(argv[0], "ls"))
		gvinum_list(argc, argv);
	else if (!strcmp(argv[0], "lv"))
		gvinum_list(argc, argv);
	else if (!strcmp(argv[0], "printconfig"))
		gvinum_printconfig(argc, argv);
	else if (!strcmp(argv[0], "rm"))
		gvinum_rm(argc, argv);
	else if (!strcmp(argv[0], "saveconfig"))
		gvinum_saveconfig();
	else if (!strcmp(argv[0], "start"))
		gvinum_start(argc, argv);
	else if (!strcmp(argv[0], "stop"))
		gvinum_stop(argc, argv);
	else
		printf("unknown command '%s'\n", argv[0]);

	return;
}

/*
 * The guts of printconfig.  This is called from gvinum_printconfig and from
 * gvinum_create when called without an argument, in order to give the user
 * something to edit.
 */
void
printconfig(FILE *of, char *comment)
{
	struct gctl_req *req;
	struct utsname uname_s;
	const char *errstr;
	time_t now;
	char buf[GV_CFG_LEN + 1];
	
	uname(&uname_s);
	time(&now);

	req = gctl_get_handle();
	gctl_ro_param(req, "class", -1, "VINUM");
	gctl_ro_param(req, "verb", -1, "getconfig");
	gctl_ro_param(req, "comment", -1, comment);
	gctl_rw_param(req, "config", sizeof(buf), buf);
	errstr = gctl_issue(req);
	if (errstr != NULL) {
		warnx("can't get configuration: %s", errstr);
		return;
	}
	gctl_free(req);

	fprintf(of, "# Vinum configuration of %s, saved at %s",
	    uname_s.nodename,
	    ctime(&now));
	
	if (*comment != '\0')
	    fprintf(of, "# Current configuration:\n");

	fprintf(of, buf);
}
