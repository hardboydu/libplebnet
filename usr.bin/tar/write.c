/*-
 * Copyright (c) 2003-2004 Tim Kientzle
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "bsdtar_platform.h"
__FBSDID("$FreeBSD$");

#include <sys/stat.h>
#include <sys/types.h>
#ifdef HAVE_POSIX_ACL
#include <sys/acl.h>
#endif
#include <archive.h>
#include <archive_entry.h>
#ifdef DMALLOC
#include <dmalloc.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <fts.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bsdtar.h"

struct links_entry {
	struct links_entry	*next;
	struct links_entry	*previous;
	int			 links;
	dev_t			 dev;
	ino_t			 ino;
	char			*name;
};

struct archive_dir_entry {
	struct archive_dir_entry	*next;
	time_t			 mtime_sec;
	int			 mtime_nsec;
	char			*name;
};


static void		 add_dir_list(struct bsdtar *bsdtar, const char *path,
			     time_t mtime_sec, int mtime_nsec);
static void		 create_cleanup(struct bsdtar *);
static int		 append_archive(struct bsdtar *, struct archive *,
			     const char *fname);
static const char *	 lookup_gname(struct bsdtar *bsdtar, gid_t gid);
static const char *	 lookup_uname(struct bsdtar *bsdtar, uid_t uid);
static int		 new_enough(struct bsdtar *, const char *path,
			     time_t mtime_sec, int mtime_nsec);
static void		 record_hardlink(struct bsdtar *,
			     struct archive_entry *entry, const struct stat *);
void			 setup_acls(struct bsdtar *, struct archive_entry *,
			     const char *path);
void			 test_for_append(struct bsdtar *);
static void		 write_archive(struct archive *, struct bsdtar *);
static void		 write_entry(struct bsdtar *, struct archive *,
			     struct stat *, const char *pathname,
			     unsigned pathlen, const char *accpath);
static int		 write_file_data(struct archive *, int fd);
static void		 write_heirarchy(struct bsdtar *, struct archive *,
			     const char *);

void
tar_mode_c(struct bsdtar *bsdtar)
{
	struct archive *a;
	int r;

	if (*bsdtar->argv == NULL)
		bsdtar_errc(1, 0, "no files or directories specified");

	a = archive_write_new();

	/* Support any format that the library supports. */
	if (bsdtar->create_format == NULL)
		archive_write_set_format_pax_restricted(a);
	else {
		r = archive_write_set_format_by_name(a, bsdtar->create_format);
		if (r != ARCHIVE_OK) {
			fprintf(stderr, "Can't use format %s: %s\n",
			    bsdtar->create_format,
			    archive_error_string(a));
			usage();
		}
	}

	archive_write_set_bytes_per_block(a, bsdtar->bytes_per_block);

	switch (bsdtar->create_compression) {
	case 'j': case 'y':
		archive_write_set_compression_bzip2(a);
		break;
	case 'z':
		archive_write_set_compression_gzip(a);
		break;
	}

	r = archive_write_open_file(a, bsdtar->filename);
	if (r != ARCHIVE_OK)
		bsdtar_errc(1, archive_errno(a),
		    archive_error_string(a));

	write_archive(a, bsdtar);

	archive_write_finish(a);
}

/*
 * Same as 'c', except we only support tar formats in uncompressed
 * files on disk.
 */
void
tar_mode_r(struct bsdtar *bsdtar)
{
	off_t	end_offset;
	int	format;
	struct archive *a;
	struct archive_entry *entry;

	/* Sanity-test some arguments and the file. */
	test_for_append(bsdtar);

	format = ARCHIVE_FORMAT_TAR_PAX_RESTRICTED;

	bsdtar->fd = open(bsdtar->filename, O_RDWR);
	if (bsdtar->fd < 0)
		bsdtar_errc(1, errno, "Cannot open %s", bsdtar->filename);

	a = archive_read_new();
	archive_read_support_compression_all(a);
	archive_read_support_format_tar(a);
	archive_read_support_format_gnutar(a);
	archive_read_open_fd(a, bsdtar->fd, 10240);
	while (0 == archive_read_next_header(a, &entry)) {
		if (archive_compression(a) != ARCHIVE_COMPRESSION_NONE) {
			archive_read_finish(a);
			close(bsdtar->fd);
			bsdtar_errc(1, 0,
			    "Cannot append to compressed archive.");
		}
		/* Keep going until we hit end-of-archive */
		format = archive_format(a);
	}

	end_offset = archive_read_header_position(a);
	archive_read_finish(a);

	/* Re-open archive for writing */
	a = archive_write_new();
	archive_write_set_compression_none(a);
	/*
	 * Set format to same one auto-detected above, except use
	 * ustar for appending to GNU tar, since the library doesn't
	 * write GNU tar format.
	 */
	if (format == ARCHIVE_FORMAT_TAR_GNUTAR)
		format = ARCHIVE_FORMAT_TAR_USTAR;
	archive_write_set_format(a, format);
	lseek(bsdtar->fd, end_offset, SEEK_SET);
	archive_write_open_fd(a, bsdtar->fd);

	write_archive(a, bsdtar);

	archive_write_finish(a);
	close(bsdtar->fd);
	bsdtar->fd = -1;
}

void
tar_mode_u(struct bsdtar *bsdtar)
{
	off_t			 end_offset;
	struct archive		*a;
	struct archive_entry	*entry;
	const char		*filename;
	int			 format;
	struct archive_dir_entry	*p;

	filename = NULL;
	format = ARCHIVE_FORMAT_TAR_PAX_RESTRICTED;

	/* Sanity-test some arguments and the file. */
	test_for_append(bsdtar);

	bsdtar->fd = open(bsdtar->filename, O_RDWR);
	if (bsdtar->fd < 0)
		bsdtar_errc(1, errno, "Cannot open %s", bsdtar->filename);

	a = archive_read_new();
	archive_read_support_compression_all(a);
	archive_read_support_format_tar(a);
	archive_read_support_format_gnutar(a);
	archive_read_open_fd(a, bsdtar->fd, bsdtar->bytes_per_block);

	/* Build a list of all entries and their recorded mod times. */
	while (0 == archive_read_next_header(a, &entry)) {
		if (archive_compression(a) != ARCHIVE_COMPRESSION_NONE) {
			archive_read_finish(a);
			close(bsdtar->fd);
			bsdtar_errc(1, 0,
			    "Cannot append to compressed archive.");
		}
		add_dir_list(bsdtar, archive_entry_pathname(entry),
		    archive_entry_mtime(entry),
		    archive_entry_mtime_nsec(entry));
		/* Record the last format determination we see */
		format = archive_format(a);
		/* Keep going until we hit end-of-archive */
	}

	end_offset = archive_read_header_position(a);
	archive_read_finish(a);

	/* Re-open archive for writing. */
	a = archive_write_new();
	archive_write_set_compression_none(a);
	/*
	 * Set format to same one auto-detected above, except that
	 * we don't write GNU tar format, so use ustar instead.
	 */
	if (format == ARCHIVE_FORMAT_TAR_GNUTAR)
		format = ARCHIVE_FORMAT_TAR_USTAR;
	archive_write_set_format(a, format);
	archive_write_set_bytes_per_block(a, bsdtar->bytes_per_block);
	lseek(bsdtar->fd, end_offset, SEEK_SET);
	ftruncate(bsdtar->fd, end_offset);
	archive_write_open_fd(a, bsdtar->fd);

	write_archive(a, bsdtar);

	archive_write_finish(a);
	close(bsdtar->fd);
	bsdtar->fd = -1;

	while (bsdtar->archive_dir_head != NULL) {
		p = bsdtar->archive_dir_head->next;
		free(bsdtar->archive_dir_head->name);
		free(bsdtar->archive_dir_head);
		bsdtar->archive_dir_head = p;
	}
	bsdtar->archive_dir_tail = NULL;
}


/*
 * Write files/dirs given on command line to opened archive.
 */
static void
write_archive(struct archive *a, struct bsdtar *bsdtar)
{
	const char *arg;
	char *pending_dir;

	pending_dir = NULL;

	if (bsdtar->start_dir != NULL && chdir(bsdtar->start_dir))
		bsdtar_errc(1, errno, "chdir(%s) failed", bsdtar->start_dir);

	while (*bsdtar->argv) {
		arg = *bsdtar->argv;
		if (arg[0] == 'C' && arg[1] == '=') {
			arg += 2;

			/*-
			 * The logic here for C=<dir> attempts to avoid
			 * chdir() as long as possible.  For example:
			 * "C=/foo C=/bar file"
			 *    needs chdir("/bar") but not chdir("/foo")
			 * "C=/foo C=bar file"
			 *    needs chdir("/foo/bar")
			 * "C=/foo C=bar /file1"
			 *    does not need chdir()
			 * "C=/foo C=bar /file1 file2"
			 *    needs chdir("/foo/bar") before file2
			 *
			 * The only correct way to handle this is to
			 * record a "pending" chdir request and only
			 * execute the real chdir when a non-absolute
			 * filename is seen on the command line.
			 *
			 * I went to all this work so that programs
			 * that build tar command lines don't have to
			 * worry about C= with non-existent
			 * directories; such requests will only fail
			 * if the directory must be accessed.
			 */
			if (pending_dir && *arg == '/') {
				/* The C=/foo C=/bar case; dump first one. */
				free(pending_dir);
				pending_dir = NULL;
			}
			if (pending_dir) {
				/* The C=/foo C=bar case; concatenate */
				char *old_pending = pending_dir;
				int old_len = strlen(old_pending);

				pending_dir =
				    malloc(old_len + 1 + strlen(arg));
				strcpy(pending_dir, old_pending);
				if (pending_dir[old_len - 1] != '/') {
					pending_dir[old_len] = '/';
					old_len ++;
				}
				strcpy(pending_dir + old_len, arg);
			} else {
				/* Easy case: no previously-saved dir. */
				pending_dir = strdup(arg);
			}
		} else {
			if (pending_dir &&
			    (*arg != '/' || (*arg == '@' && arg[1] != '/'))) {
				/* Handle a deferred -C request, see
				 * comments above. */
				if (chdir(pending_dir))
					bsdtar_errc(1, 0,
					    "could not chdir to '%s'\n",
					    pending_dir);
				free(pending_dir);
				pending_dir = NULL;
			}

			if (*arg == '@')
				append_archive(bsdtar, a, arg+1);
			else
				write_heirarchy(bsdtar, a, arg);
		}
		bsdtar->argv++;
	}

	create_cleanup(bsdtar);
}


/* Copy from specified archive to current archive. */
static int
append_archive(struct bsdtar *bsdtar, struct archive *a, const char *filename)
{
	struct archive *ina;
	struct archive_entry *in_entry;
	int bytes_read, bytes_written;
	char buff[8192];

	ina = archive_read_new();
	archive_read_support_format_all(ina);
	archive_read_support_compression_all(ina);
	archive_read_open_file(ina, filename, 10240);
	while (0 == archive_read_next_header(ina, &in_entry)) {
		if (!new_enough(bsdtar, archive_entry_pathname(in_entry),
			archive_entry_mtime(in_entry),
			archive_entry_mtime_nsec(in_entry)))
			continue;
		if (excluded(bsdtar, archive_entry_pathname(in_entry)))
			continue;
		if (bsdtar->option_interactive &&
		    !yes("copy '%s'", archive_entry_pathname(in_entry)))
			continue;
		if (bsdtar->verbose)
			safe_fprintf(stderr, "a %s",
			    archive_entry_pathname(in_entry));
		/* XXX handle/report errors XXX */
		archive_write_header(a, in_entry);
		bytes_read = archive_read_data(ina, buff, sizeof(buff));
		while (bytes_read > 0) {
			bytes_written =
			    archive_write_data(a, buff, bytes_read);
			if (bytes_written < bytes_read) {
				bsdtar_warnc( archive_errno(a), "%s",
				    archive_error_string(a));
				exit(1);
			}
			bytes_read =
			    archive_read_data(ina, buff, sizeof(buff));
		}
		if (bsdtar->verbose)
			fprintf(stderr, "\n");

	}
	if (archive_errno(ina))
		bsdtar_warnc(0, "Error reading archive %s: %s", filename,
		    archive_error_string(ina));

	return (0); /* TODO: Return non-zero on error */
}

/*
 * Add the file or dir heirarchy named by 'path' to the archive
 */
static void
write_heirarchy(struct bsdtar *bsdtar, struct archive *a, const char *path)
{
	FTS	*fts;
	FTSENT	*ftsent;
	int	 ftsoptions;
	char	*fts_argv[2];

	/*
	 * Sigh: fts_open modifies it's first parameter, so we have to
	 * copy 'path' to mutable storage.
	 */
	fts_argv[0] = strdup(path);
	fts_argv[1] = NULL;
	ftsoptions = FTS_PHYSICAL;
	switch (bsdtar->symlink_mode) {
	case 'H':
		ftsoptions |= FTS_COMFOLLOW;
		break;
	case 'L':
		ftsoptions = FTS_COMFOLLOW | FTS_LOGICAL;
		break;
	}
	if (bsdtar->option_dont_traverse_mounts)
		ftsoptions |= FTS_XDEV;

	fts = fts_open(fts_argv, ftsoptions, NULL);


	if (!fts) {
		bsdtar_warnc(errno, "%s: Cannot open", path);
		return;
	}

	while ((ftsent = fts_read(fts))) {
		switch (ftsent->fts_info) {
		case FTS_NS:
			bsdtar_warnc(ftsent->fts_errno, "%s: Could not stat",
			    ftsent->fts_path);
			break;
		case FTS_ERR:
			bsdtar_warnc(ftsent->fts_errno, "%s", ftsent->fts_path);
			break;
		case FTS_DNR:
			bsdtar_warnc(ftsent->fts_errno,
			    "%s: Cannot read directory contents",
			    ftsent->fts_path);
			break;
		case FTS_W:  /* Skip Whiteout entries */
			break;
		case FTS_DC: /* Directory that causes cycle */
			/* XXX Does this need special handling ? */
			break;
		case FTS_D:
			/*
			 * If this dir is flagged "nodump" and we're
			 * honoring such flags, tell FTS to skip the
			 * entire tree and don't write the entry for the
			 * directory itself.
			 */
#ifdef HAVE_CHFLAGS
			if (bsdtar->option_honor_nodump &&
			    (ftsent->fts_statp->st_flags & UF_NODUMP)) {
				fts_set(fts, ftsent, FTS_SKIP);
				break;
			}
#endif

			/*
			 * In -u mode, we need to check whether this
			 * is newer than what's already in the archive.
			 */
			if (!new_enough(bsdtar, ftsent->fts_path,
				ftsent->fts_statp->st_mtime,
				ftsent->fts_statp->st_mtimespec.tv_nsec))
				break;
			/*
			 * If this dir is excluded by a filename
			 * pattern, tell FTS to skip the entire tree
			 * and don't write the entry for the directory
			 * itself.
			 */
			if (excluded(bsdtar, ftsent->fts_path)) {
				fts_set(fts, ftsent, FTS_SKIP);
				break;
			}

			/*
			 * If the user vetoes the directory, skip
			 * the whole thing.
			 */
			if (bsdtar->option_interactive &&
			    !yes("add '%s'", ftsent->fts_path)) {
				fts_set(fts, ftsent, FTS_SKIP);
				break;
			}

			/*
			 * If we're not recursing, tell FTS to skip the
			 * tree but do fall through and write the entry
			 * for the dir itself.
			 */
			if (bsdtar->option_no_subdirs)
				fts_set(fts, ftsent, FTS_SKIP);
			write_entry(bsdtar, a, ftsent->fts_statp,
			    ftsent->fts_path, ftsent->fts_pathlen,
			    ftsent->fts_accpath);
			break;
		case FTS_F:
		case FTS_SL:
		case FTS_SLNONE:
		case FTS_DEFAULT:
			/*
			 * Skip this file if it's flagged "nodump" and we're
			 * honoring that flag.
			 */
#ifdef HAVE_CHFLAGS
			if (bsdtar->option_honor_nodump &&
			    (ftsent->fts_statp->st_flags & UF_NODUMP))
				break;
#endif
			/*
			 * Skip this file if it's excluded by a
			 * filename pattern.
			 */
			if (excluded(bsdtar, ftsent->fts_path))
				break;

			/*
			 * In -u mode, we need to check whether this
			 * is newer than what's already in the archive.
			 */
			if (!new_enough(bsdtar, ftsent->fts_path,
				ftsent->fts_statp->st_mtime,
				ftsent->fts_statp->st_mtimespec.tv_nsec))
				break;

			if (bsdtar->option_interactive &&
			    !yes("add '%s'", ftsent->fts_path)) {
				break;
			}

			write_entry(bsdtar, a, ftsent->fts_statp,
			    ftsent->fts_path, ftsent->fts_pathlen,
			    ftsent->fts_accpath);
			break;
		case FTS_DP:
			break;
		default:
			bsdtar_warnc(0, "%s: Heirarchy traversal error %d\n",
			    ftsent->fts_path,
			    ftsent->fts_info);
			break;
		}

	}
	if (errno)
		bsdtar_warnc(errno, "%s", path);
	if (fts_close(fts))
		bsdtar_warnc(errno, "fts_close failed");
	free(fts_argv[0]);
}

/*
 * Add a single filesystem object to the archive.
 */
static void
write_entry(struct bsdtar *bsdtar, struct archive *a, struct stat *st,
    const char *pathname, unsigned pathlen, const char *accpath)
{
	struct archive_entry	*entry;
	int			 e;
	int			 fd;
	char			*fflags = NULL;
	static char		 linkbuffer[PATH_MAX+1];

	(void)pathlen; /* UNUSED */

	fd = -1;
	entry = archive_entry_new();
	archive_entry_set_pathname(entry, pathname);

	/* If there are hard links, record it for later use */
	if (!S_ISDIR(st->st_mode) && (st->st_nlink > 1))
		record_hardlink(bsdtar, entry, st);

	/* Non-regular files get archived with zero size. */
	if (!S_ISREG(st->st_mode))
		st->st_size = 0;

	/* Strip redundant "./" from start of filename. */
	if (pathname && pathname[0] == '.' && pathname[1] == '/') {
		pathname += 2;
		if (*pathname == 0)	/* This is the "./" directory. */
			goto cleanup;	/* Don't archive it ever. */
	}

	/* Strip leading '/' unless user has asked us not to. */
	if (pathname && pathname[0] == '/' && !bsdtar->option_absolute_paths)
		pathname++;

	/* Display entry as we process it. This format is required by SUSv2. */
	if (bsdtar->verbose)
		safe_fprintf(stderr, "a %s", pathname);

	/* Read symbolic link information. */
	if ((st->st_mode & S_IFMT) == S_IFLNK) {
		int lnklen;

		lnklen = readlink(accpath, linkbuffer, PATH_MAX);
		if (lnklen < 0) {
			if (!bsdtar->verbose)
				bsdtar_warnc(errno,
				    "%s: Couldn't read symbolic link",
				    pathname);
			else
				safe_fprintf(stderr,
				    ": Couldn't read symbolic link: %s",
				    strerror(errno));
			goto cleanup;
		}
		linkbuffer[lnklen] = 0;
		archive_entry_set_symlink(entry, linkbuffer);
	}

	/* Look up username and group name. */
	archive_entry_set_uname(entry, lookup_uname(bsdtar, st->st_uid));
	archive_entry_set_gname(entry, lookup_gname(bsdtar, st->st_gid));

#ifdef HAVE_CHFLAGS
	if (st->st_flags != 0) {
		fflags = fflagstostr(st->st_flags);
		archive_entry_set_fflags(entry, fflags);
	}
#endif

	setup_acls(bsdtar, entry, accpath);

	/*
	 * If it's a regular file (and non-zero in size) make sure we
	 * can open it before we start to write.  In particular, note
	 * that we can always archive a zero-length file, even if we
	 * can't read it.
	 */
	if (S_ISREG(st->st_mode) && st->st_size > 0) {
		fd = open(accpath, O_RDONLY);
		if (fd < 0) {
			if (!bsdtar->verbose)
				bsdtar_warnc(errno, "%s", pathname);
			else
				fprintf(stderr, ": %s", strerror(errno));
			goto cleanup;
		}
	}

	archive_entry_copy_stat(entry, st);
	archive_entry_set_pathname(entry, pathname);

	e = archive_write_header(a, entry);
	if (e != ARCHIVE_OK) {
		if (!bsdtar->verbose)
			bsdtar_warnc(0, "%s: %s", pathname,
			    archive_error_string(a));
		else
			fprintf(stderr, ": %s", archive_error_string(a));
	}

	if (e == ARCHIVE_FATAL)
		exit(1);

	/*
	 * If we opened a file earlier, write it out now.  Note that
	 * the format handler might have reset the size field to zero
	 * to inform us that the archive body won't get stored.  In
	 * that case, just skip the write.
	 */
	if (fd >= 0 && archive_entry_size(entry) > 0)
		write_file_data(a, fd);

cleanup:
	if (fd >= 0)
		close(fd);

	if (entry != NULL)
		archive_entry_free(entry);

	if (bsdtar->verbose)
		fprintf(stderr, "\n");

	if (fflags != NULL) free(fflags);
}


/* Helper function to copy file to archive, with stack-allocated buffer. */
static int
write_file_data(struct archive *a, int fd)
{
	char	buff[8192];
	ssize_t	bytes_read;
	ssize_t	bytes_written;

	bytes_read = read(fd, buff, sizeof(buff));
	while (bytes_read > 0) {
		bytes_written = archive_write_data(a, buff, bytes_read);

		if (bytes_written == 0 && errno) {
			return -1; /* Write failed; this is bad */
		}
		bytes_read = read(fd, buff, sizeof(buff));
	}
	return 0;
}


static void
create_cleanup(struct bsdtar * bsdtar)
{
	/* Free inode->name map */
	while (bsdtar->links_head != NULL) {
		struct links_entry *lp = bsdtar->links_head->next;

		if (bsdtar->option_warn_links)
			bsdtar_warnc(0, "Missing links to %s",
			    bsdtar->links_head->name);

		if (bsdtar->links_head->name != NULL)
			free(bsdtar->links_head->name);
		free(bsdtar->links_head);
		bsdtar->links_head = lp;
	}
	cleanup_exclusions(bsdtar);
}


static void
record_hardlink(struct bsdtar *bsdtar, struct archive_entry *entry,
    const struct stat *st)
{
	struct links_entry	*le;

	/*
	 * First look in the list of multiply-linked files.  If we've
	 * already dumped it, convert this entry to a hard link entry.
	 */
	for (le = bsdtar->links_head; le != NULL; le = le->next) {
		if (le->dev == st->st_dev && le->ino == st->st_ino) {
			archive_entry_set_hardlink(entry, le->name);

			/*
			 * Decrement link count each time and release
			 * the entry if it hits zero.  This saves
			 * memory and is necessary for proper -l
			 * implementation.
			 */
			if (--le->links <= 0) {
				if (le->previous != NULL)
					le->previous->next = le->next;
				if (le->next != NULL)
					le->next->previous = le->previous;
				if (bsdtar->links_head == le)
					bsdtar->links_head = le->next;
				free(le);
			}

			return;
		}
	}

	le = malloc(sizeof(struct links_entry));
	if (bsdtar->links_head != NULL)
		bsdtar->links_head->previous = le;
	le->next = bsdtar->links_head;
	le->previous = NULL;
	bsdtar->links_head = le;
	le->dev = st->st_dev;
	le->ino = st->st_ino;
	le->links = st->st_nlink - 1;
	le->name = strdup(archive_entry_pathname(entry));
}

#ifdef HAVE_POSIX_ACL
void
setup_acls(struct bsdtar *bsdtar, struct archive_entry *entry,
    const char *accpath)
{
	acl_t		 acl;
	acl_tag_t	 acl_tag;
	acl_entry_t	 acl_entry;
	acl_permset_t	 acl_permset;
	int		 s, ae_id, ae_tag, ae_perm;
	const char	*ae_name;

	archive_entry_acl_clear(entry);

	/* Retrieve access ACL from file. */
	acl = acl_get_file(accpath, ACL_TYPE_ACCESS);
	if (acl != NULL) {
		s = acl_get_entry(acl, ACL_FIRST_ENTRY, &acl_entry);
		while (s == 1) {
			ae_id = -1;
			ae_name = NULL;

			acl_get_tag_type(acl_entry, &acl_tag);
			if (acl_tag == ACL_USER) {
				ae_id = (int)*(uid_t *)acl_get_qualifier(acl_entry);
				ae_name = lookup_uname(bsdtar, ae_id);
				ae_tag = ARCHIVE_ENTRY_ACL_USER;
			} else if (acl_tag == ACL_GROUP) {
				ae_id = (int)*(gid_t *)acl_get_qualifier(acl_entry);
				ae_name = lookup_gname(bsdtar, ae_id);
				ae_tag = ARCHIVE_ENTRY_ACL_GROUP;
			} else if (acl_tag == ACL_MASK) {
				ae_tag = ARCHIVE_ENTRY_ACL_MASK;
			} else if (acl_tag == ACL_USER_OBJ) {
				ae_tag = ARCHIVE_ENTRY_ACL_USER_OBJ;
			} else if (acl_tag == ACL_GROUP_OBJ) {
				ae_tag = ARCHIVE_ENTRY_ACL_GROUP_OBJ;
			} else if (acl_tag == ACL_OTHER) {
				ae_tag = ARCHIVE_ENTRY_ACL_OTHER;
			} else {
				/* Skip types that libarchive can't support. */
				continue;
			}

			acl_get_permset(acl_entry, &acl_permset);
			ae_perm = 0;
			if (acl_get_perm_np(acl_permset, ACL_EXECUTE))
				ae_perm |= ARCHIVE_ENTRY_ACL_EXECUTE;
			if (acl_get_perm_np(acl_permset, ACL_READ))
				ae_perm |= ARCHIVE_ENTRY_ACL_READ;
			if (acl_get_perm_np(acl_permset, ACL_WRITE))
				ae_perm |= ARCHIVE_ENTRY_ACL_WRITE;

			archive_entry_acl_add_entry(entry,
			    ARCHIVE_ENTRY_ACL_TYPE_ACCESS, ae_perm, ae_tag,
			    ae_id, ae_name);

			s = acl_get_entry(acl, ACL_NEXT_ENTRY, &acl_entry);
		}
		acl_free(acl);
	}

	/* XXX TODO: Default acl ?? XXX */
}
#else
void
setup_acls(struct archive_entry *entry, const char *accpath)
{
	(void)entry;
	(void)accpath;
}
#endif

/*
 * Lookup gid from gname and uid from uname.
 *
 * TODO: Cache gname/uname lookups to improve performance on
 * large extracts.
 */
const char *
lookup_uname(struct bsdtar *bsdtar, uid_t uid)
{
	struct passwd		*pwent;

	(void)bsdtar; /* UNUSED */

	pwent = getpwuid(uid);
	if (pwent)
		return (pwent->pw_name);
	if (errno)
		bsdtar_warnc(errno, "getpwuid(%d) failed", uid);
	return (NULL);
}

const char *
lookup_gname(struct bsdtar *bsdtar, gid_t gid)
{
	struct group		*grent;

	(void)bsdtar; /* UNUSED */
	grent = getgrgid(gid);
	if (grent)
		return (grent->gr_name);
	if (errno)
		bsdtar_warnc(errno, "getgrgid(%d) failed", gid);
	return (NULL);
}

/*
 * Test if the specified file is newer than what's already
 * in the archive.
 */
int
new_enough(struct bsdtar *bsdtar, const char *path,
    time_t mtime_sec, int mtime_nsec)
{
	struct archive_dir_entry *p;

	if (path[0] == '.' && path[1] == '/' && path[2] != '\0')
		path += 2;

	if (bsdtar->archive_dir_head == NULL)
		return (1);

	for (p = bsdtar->archive_dir_head; p != NULL; p = p->next) {
		if (strcmp(path, p->name)==0)
			return (p->mtime_sec < mtime_sec ||
				(p->mtime_sec == mtime_sec &&
				 p->mtime_nsec < mtime_nsec));
	}
	return (1);
}

/*
 * Add an entry to the dir list for 'u' mode.
 *
 * XXX TODO: Make this fast.
 */
static void
add_dir_list(struct bsdtar *bsdtar, const char *path,
    time_t mtime_sec, int mtime_nsec)
{
	struct archive_dir_entry	*p;

	if (path[0] == '.' && path[1] == '/' && path[2] != '\0')
		path += 2;

	p = bsdtar->archive_dir_head;
	while (p != NULL) {
		if (strcmp(path, p->name)==0) {
			p->mtime_sec = mtime_sec;
			p->mtime_nsec = mtime_nsec;
			return;
		}
		p = p->next;
	}

	p = malloc(sizeof(*p));
	p->name = strdup(path);
	p->mtime_sec = mtime_sec;
	p->mtime_nsec = mtime_nsec;
	p->next = NULL;
	if (bsdtar->archive_dir_tail == NULL) {
		bsdtar->archive_dir_head = bsdtar->archive_dir_tail = p;
	} else {
		bsdtar->archive_dir_tail->next = p;
		bsdtar->archive_dir_tail = p;
	}
}

void
test_for_append(struct bsdtar *bsdtar)
{
	struct stat s;

	if (*bsdtar->argv == NULL)
		bsdtar_errc(1, 0, "no files or directories specified");
	if (bsdtar->filename == NULL)
		bsdtar_errc(1, 0, "Cannot append to stdout.");

	if (bsdtar->create_compression != 0)
		bsdtar_errc(1, 0, "Cannot append to %s with compression",
		    bsdtar->filename);

	if (stat(bsdtar->filename, &s) != 0)
		bsdtar_errc(1, errno, "Cannot stat %s", bsdtar->filename);

	if (!S_ISREG(s.st_mode))
		bsdtar_errc(1, 0, "Cannot append to %s: not a regular file.",
		    bsdtar->filename);
}
