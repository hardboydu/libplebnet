/*
 * FreeBSD install - a package for the installation and maintainance
 * of non-core utilities.
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
 * Jordan K. Hubbard
 * 23 Aug 1993
 *
 * This is the main body of the info module.
 *
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "lib.h"
#include "info.h"
#include <err.h>
#include <signal.h>

static int pkg_do(char *);
static int find_pkg(const char *, struct which_head *);
static int cmp_path(const char *, const char *, const char *);
static char *abspath(const char *);
static int find_pkgs_by_origin(const char *, const char *);

int
pkg_perform(char **pkgs)
{
    char **matched;
    const char *tmp;
    int err_cnt = 0;
    int i, errcode;

    signal(SIGINT, cleanup);

    tmp = LOG_DIR;

    /* Overriding action? */
    if (CheckPkg) {
	char buf[FILENAME_MAX];

	snprintf(buf, FILENAME_MAX, "%s/%s", tmp, CheckPkg);
	return abs(access(buf, R_OK));
	/* Not reached */
    } else if (!TAILQ_EMPTY(whead)) {
	return find_pkg(tmp, whead);
    } else if (LookUpOrigin != NULL) {
	return find_pkgs_by_origin(tmp, LookUpOrigin);
    }

    if (MatchType != MATCH_EXACT) {
	matched = matchinstalled(MatchType, pkgs, &errcode);
	if (errcode != 0)
	    return 1;
	    /* Not reached */

	if (matched != NULL)
	    pkgs = matched;
	else switch (MatchType) {
	    case MATCH_GLOB:
		break;
	    case MATCH_ALL:
		warnx("no packages installed");
		return 0;
		/* Not reached */
	    case MATCH_REGEX:
		warnx("no packages match pattern(s)");
		return 1;
		/* Not reached */
	    default:
		break;
	}
    }

    for (i = 0; pkgs[i]; i++)
	err_cnt += pkg_do(pkgs[i]);

    return err_cnt;
}

static char *Home;

static int
pkg_do(char *pkg)
{
    Boolean installed = FALSE, isTMP = FALSE;
    char log_dir[FILENAME_MAX];
    char fname[FILENAME_MAX];
    Package plist;
    FILE *fp;
    struct stat sb;
    char *cp = NULL;
    int code = 0;

    if (isURL(pkg)) {
	if ((cp = fileGetURL(NULL, pkg)) != NULL) {
	    strcpy(fname, cp);
	    isTMP = TRUE;
	}
    }
    else if (fexists(pkg) && isfile(pkg)) {
	int len;

	if (*pkg != '/') {
	    if (!getcwd(fname, FILENAME_MAX))
		upchuck("getcwd");
	    len = strlen(fname);
	    snprintf(&fname[len], FILENAME_MAX - len, "/%s", pkg);
	}
	else
	    strcpy(fname, pkg);
	cp = fname;
    }
    else {
	if ((cp = fileFindByPath(NULL, pkg)) != NULL)
	    strncpy(fname, cp, FILENAME_MAX);
    }
    if (cp) {
	/*
	 * Apply a crude heuristic to see how much space the package will
	 * take up once it's unpacked.  I've noticed that most packages
	 * compress an average of 75%, but we're only unpacking the + files so
	 * be very optimistic.
	 */
	if (stat(fname, &sb) == FAIL) {
	    warnx("can't stat package file '%s'", fname);
	    code = 1;
	    goto bail;
	}
	Home = make_playpen(PlayPen, sb.st_size / 2);
	if (unpack(fname, "+*")) {
	    warnx("error during unpacking, no info for '%s' available", pkg);
	    code = 1;
	    goto bail;
	}
    }
    /* It's not an ininstalled package, try and find it among the installed */
    else {
	sprintf(log_dir, "%s/%s", LOG_DIR, pkg);
	if (!fexists(log_dir)) {
	    warnx("can't find package '%s' installed or in a file!", pkg);
	    return 1;
	}
	if (chdir(log_dir) == FAIL) {
	    warnx("can't change directory to '%s'!", log_dir);
	    return 1;
	}
	installed = TRUE;
    }

    /* Suck in the contents list */
    plist.head = plist.tail = NULL;
    fp = fopen(CONTENTS_FNAME, "r");
    if (!fp) {
	warnx("unable to open %s file", CONTENTS_FNAME);
	code = 1;
	goto bail;
    }
    /* If we have a prefix, add it now */
    read_plist(&plist, fp);
    fclose(fp);

    /*
     * Index is special info type that has to override all others to make
     * any sense.
     */
    if (Flags & SHOW_INDEX) {
	char tmp[FILENAME_MAX];

	snprintf(tmp, FILENAME_MAX, "%-19s ", pkg);
	show_index(tmp, COMMENT_FNAME);
    }
    else {
	/* Start showing the package contents */
	if (!Quiet)
	    printf("%sInformation for %s:\n\n", InfoPrefix, pkg);
	if (Flags & SHOW_COMMENT)
	    show_file("Comment:\n", COMMENT_FNAME);
	if (Flags & SHOW_REQUIRE)
	    show_plist("Depends on:\n", &plist, PLIST_PKGDEP, FALSE);
	if ((Flags & SHOW_REQBY) && !isemptyfile(REQUIRED_BY_FNAME))
	    show_file("Required by:\n", REQUIRED_BY_FNAME);
	if (Flags & SHOW_DESC)
	    show_file("Description:\n", DESC_FNAME);
	if ((Flags & SHOW_DISPLAY) && fexists(DISPLAY_FNAME))
	    show_file("Install notice:\n", DISPLAY_FNAME);
	if (Flags & SHOW_PLIST)
	    show_plist("Packing list:\n", &plist, (plist_t)0, TRUE);
	if ((Flags & SHOW_INSTALL) && fexists(INSTALL_FNAME))
	    show_file("Install script:\n", INSTALL_FNAME);
	if ((Flags & SHOW_INSTALL) && fexists(POST_INSTALL_FNAME))
	    show_file("Post-Install script:\n", POST_INSTALL_FNAME);
	if ((Flags & SHOW_DEINSTALL) && fexists(DEINSTALL_FNAME))
	    show_file("De-Install script:\n", DEINSTALL_FNAME);
	if ((Flags & SHOW_DEINSTALL) && fexists(POST_DEINSTALL_FNAME))
	    show_file("Post-DeInstall script:\n", POST_DEINSTALL_FNAME);
	if ((Flags & SHOW_MTREE) && fexists(MTREE_FNAME))
	    show_file("mtree file:\n", MTREE_FNAME);
	if (Flags & SHOW_PREFIX)
	    show_plist("Prefix(s):\n", &plist, PLIST_CWD, FALSE);
	if (Flags & SHOW_FILES)
	    show_files("Files:\n", &plist);
	if ((Flags & SHOW_SIZE) && installed)
	    show_size("Package Size:\n", &plist);
	if ((Flags & SHOW_CKSUM) && installed)
	    show_cksum("Mismatched Checksums:\n", &plist);
	if (Flags & SHOW_ORIGIN)
	    show_origin("Origin:\n", &plist);
	if (Flags & SHOW_FMTREV)
	    show_fmtrev("Packing list format revision:\n", &plist);
	if (!Quiet)
	    puts(InfoPrefix);
    }
    free_plist(&plist);
 bail:
    leave_playpen();
    if (isTMP)
	unlink(fname);
    return code;
}

void
cleanup(int sig)
{
    static int in_cleanup = 0;

    if (!in_cleanup) {
	in_cleanup = 1;
	leave_playpen();
    }
    if (sig)
	exit(1);
}

/*
 * Return an absolute path, additionally removing all .'s, ..'s, and extraneous
 * /'s, as realpath() would, but without resolving symlinks, because that can
 * potentially screw up our comparisons later.
 */
static char *
abspath(const char *pathname)
{
    char *tmp, *tmp1, *resolved_path;
    char *cwd = NULL;
    int len;

    if (pathname[0] != '/') {
	cwd = getcwd(NULL, MAXPATHLEN);
	asprintf(&resolved_path, "%s/%s/", cwd, pathname);
    } else
	asprintf(&resolved_path, "%s/", pathname);

    if (resolved_path == NULL)
	errx(2, NULL);

    if (cwd != NULL)
	free(cwd);    

    while ((tmp = strstr(resolved_path, "//")) != NULL)
	strcpy(tmp, tmp + 1);
 
    while ((tmp = strstr(resolved_path, "/./")) != NULL)
	strcpy(tmp, tmp + 2);
 
    while ((tmp = strstr(resolved_path, "/../")) != NULL) {
	*tmp = '\0';
	if ((tmp1 = strrchr(resolved_path, '/')) == NULL)
	   tmp1 = resolved_path;
	strcpy(tmp1, tmp + 3);
    }

    len = strlen(resolved_path);
    if (len > 1 && resolved_path[len - 1] == '/')
	resolved_path[len - 1] = '\0';

    return resolved_path;
}

/*
 * Comparison to see if the path we're on matches the
 * one we are looking for.
 */
static int
cmp_path(const char *target, const char *current, const char *cwd) 
{
    char *resolved, *temp;
    int rval;

    asprintf(&temp, "%s/%s", cwd, current);
    if (temp == NULL)
        errx(2, NULL);

    /*
     * Make sure there's no multiple /'s or other weird things in the PLIST,
     * since some plists seem to have them and it could screw up our strncmp.
     */
    resolved = abspath(temp);

    if (strcmp(target, resolved) == 0)
	rval = 1;
    else
	rval = 0;

    free(temp);
    free(resolved);
    return rval;
}

/* 
 * Look through package dbs in db_dir and find which
 * packages installed the files in which_list.
 */
static int 
find_pkg(const char *db_dir, struct which_head *which_list)
{
    char **installed;
    int errcode, i;
    struct which_entry *wp;

    TAILQ_FOREACH(wp, which_list, next) {
	const char *msg = "file cannot be found";
	char *tmp;

	wp->skip = TRUE;
	/* If it's not a file, we'll see if it's an executable. */
	if (isfile(wp->file) == FALSE) {
	    if (strchr(wp->file, '/') == NULL) {
		tmp = vpipe("/usr/bin/which %s", wp->file);
		if (tmp != NULL) {
		    strlcpy(wp->file, tmp, PATH_MAX);
		    wp->skip = FALSE;
		    free(tmp);
		} else
		    msg = "file is not in PATH";
	    }
	} else {
	    tmp = abspath(wp->file);
	    if (isfile(tmp)) {
	    	strlcpy(wp->file, tmp, PATH_MAX);
	    	wp->skip = FALSE;
	    }
	    free(tmp);
	}
	if (wp->skip == TRUE)
	    warnx("%s: %s", wp->file, msg);
    }

    installed = matchinstalled(MATCH_ALL, NULL, &errcode);
    if (installed == NULL)
        return errcode;
 
    for (i = 0; installed[i] != NULL; i++) {
     	FILE *fp;
     	Package pkg;
     	PackingList itr;
     	char *cwd = NULL;
     	char tmp[PATH_MAX];

	snprintf(tmp, PATH_MAX, "%s/%s/%s", db_dir, installed[i],
		 CONTENTS_FNAME);
	fp = fopen(tmp, "r");
	if (fp == NULL) {
	    warn("%s", tmp);
	    return 1;
	}

	pkg.head = pkg.tail = NULL;
	read_plist(&pkg, fp);
	fclose(fp);
	for (itr = pkg.head; itr != pkg.tail; itr = itr->next) {
	    if (itr->type == PLIST_CWD) {
		cwd = itr->name;
	    } else if (itr->type == PLIST_FILE) {
		TAILQ_FOREACH(wp, which_list, next) {
		    if (wp->skip == TRUE)
			continue;
		    if (!cmp_path(wp->file, itr->name, cwd))
			continue;
		    if (wp->package[0] != '\0') {
			warnx("both %s and %s claim to have installed %s\n",
			      wp->package, installed[i], wp->file);
		    } else {
			strlcpy(wp->package, installed[i], PATH_MAX);
		    }
		}
	    }
	}
	free_plist(&pkg);
    }

    TAILQ_FOREACH(wp, which_list, next) {
	if (wp->package[0] != '\0') {
	    if (Quiet)
		puts(wp->package);
	    else
		printf("%s was installed by package %s\n", \
		       wp->file, wp->package);
	}
    }
    while (!TAILQ_EMPTY(which_list)) {
	wp = TAILQ_FIRST(which_list);
	TAILQ_REMOVE(which_list, wp, next);
	free(wp);
    }

    free(which_list);
    return 0;
}

/* 
 * Look through package dbs in db_dir and find which
 * packages have the given origin. Don't use read_plist()
 * because this increases time necessary for lookup by 40
 * times, as we don't really have to parse all plist to
 * get origin.
 */
static int 
find_pkgs_by_origin(const char *db_dir, const char *origin)
{
    char **installed;
    int errcode, i;

    installed = matchinstalled(MATCH_ALL, NULL, &errcode);
    if (installed == NULL)
        return errcode;
 
    if (!Quiet)
	printf("The following installed package(s) has %s origin:\n", origin);
    for (i = 0; installed[i] != NULL; i++) {
     	FILE *fp;
     	char *cp, tmp[PATH_MAX];
     	int cmd;

	snprintf(tmp, PATH_MAX, "%s/%s", db_dir, installed[i]);
	/*
	 * SPECIAL CASE: ignore empty dirs, since we can can see them
	 * during port installation.
	 */
	if (isemptydir(tmp))
	    continue;
	snprintf(tmp, PATH_MAX, "%s/%s", tmp, CONTENTS_FNAME);
	fp = fopen(tmp, "r");
	if (fp == NULL) {
	    warn("%s", tmp);
	    return 1;
	}

	cmd = -1;
	while (fgets(tmp, sizeof(tmp), fp)) {
	    int len = strlen(tmp);

	    while (len && isspace(tmp[len - 1]))
		tmp[--len] = '\0';
	    if (!len)
		continue;
	    cp = tmp;
	    if (tmp[0] != CMD_CHAR)
		continue;
	    cmd = plist_cmd(tmp + 1, &cp);
	    if (cmd == PLIST_ORIGIN) {
		if (strcmp(origin, cp) == 0)
		    puts(installed[i]);
		break;
	    }
	}
	if (cmd != PLIST_ORIGIN)
	    warnx("package %s has no origin recorded", installed[i]);
	fclose(fp);
    }

    return 0;
}
