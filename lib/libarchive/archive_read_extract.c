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

#include "archive_platform.h"
__FBSDID("$FreeBSD$");

#include <sys/stat.h>
#include <sys/types.h>
#ifdef HAVE_POSIX_ACL
#include <sys/acl.h>
#endif
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tar.h>
#include <unistd.h>
#ifdef LINUX
#include <ext2fs/ext2_fs.h>
#include <sys/ioctl.h>
#endif

#include "archive.h"
#include "archive_string.h"
#include "archive_entry.h"
#include "archive_private.h"

static void	archive_extract_cleanup(struct archive *);
static int	archive_read_extract_block_device(struct archive *,
		    struct archive_entry *, int);
static int	archive_read_extract_char_device(struct archive *,
		    struct archive_entry *, int);
static int	archive_read_extract_device(struct archive *,
		    struct archive_entry *, int flags, mode_t mode);
static int	archive_read_extract_dir(struct archive *,
		    struct archive_entry *, int);
static int	archive_read_extract_dir_create(struct archive *,
		    const char *name, int mode, int flags);
static int	archive_read_extract_fifo(struct archive *,
		    struct archive_entry *, int);
static int	archive_read_extract_hard_link(struct archive *,
		    struct archive_entry *, int);
static int	archive_read_extract_regular(struct archive *,
		    struct archive_entry *, int);
static int	archive_read_extract_regular_open(struct archive *,
		    const char *name, int mode, int flags);
static int	archive_read_extract_symbolic_link(struct archive *,
		    struct archive_entry *, int);
static gid_t	lookup_gid(struct archive *, const char *uname, gid_t);
static uid_t	lookup_uid(struct archive *, const char *uname, uid_t);
static int	mkdirpath(struct archive *, const char *);
static int	mkdirpath_recursive(char *path);
static int	mksubdir(char *path);
#ifdef HAVE_POSIX_ACL
static int	set_acl(struct archive *, struct archive_entry *,
		    acl_type_t, int archive_entry_acl_type, const char *tn);
#endif
static int	set_acls(struct archive *, struct archive_entry *);
static int	set_extended_perm(struct archive *, struct archive_entry *,
		    int flags);
static int	set_fflags(struct archive *, struct archive_entry *);
static int	set_ownership(struct archive *, struct archive_entry *, int);
static int	set_perm(struct archive *, struct archive_entry *, int mode,
		    int flags);
static int	set_time(struct archive *, struct archive_entry *, int);
static struct archive_extract_dir_entry *
		sort_dir_list(struct archive_extract_dir_entry *p);


struct archive_extract_dir_entry {
	struct archive_extract_dir_entry	*next;
	mode_t		 mode;
	int64_t		 mtime;
	int64_t		 atime;
	unsigned long	 mtime_nanos;
	unsigned long	 atime_nanos;
	/* Note: ctime cannot be restored, so don't bother */
	char		*name;
};


/*
 * Extract this entry to disk.
 *
 * TODO: Validate hardlinks.  Is there any way to validate hardlinks
 * without keeping a complete list of filenames from the entire archive?? Ugh.
 *
 */
int
archive_read_extract(struct archive *a, struct archive_entry *entry, int flags)
{
	mode_t writable_mode;
	struct archive_extract_dir_entry *le;
	const struct stat *st;
	int ret;
	int restore_pwd;

	restore_pwd = -1;
	st = archive_entry_stat(entry);
	if (S_ISDIR(st->st_mode)) {
		/*
		 * TODO: Does this really work under all conditions?
		 *
		 * E.g., root restores a dir owned by someone else?
		 */
		writable_mode = st->st_mode | 0700;

		/*
		 * In order to correctly restore non-writable dirs or
		 * dir timestamps, we need to maintain a fix-up list.
		 */
		if (st->st_mode != writable_mode ||
		    flags & ARCHIVE_EXTRACT_TIME) {
			le = malloc(sizeof(struct archive_extract_dir_entry));
			le->next = a->archive_extract_dir_list;
			a->archive_extract_dir_list = le;
			le->mode = st->st_mode;
			le->mtime = st->st_mtime;
			le->mtime_nanos = ARCHIVE_STAT_MTIME_NANOS(st);
			le->atime = st->st_atime;
			le->atime_nanos = ARCHIVE_STAT_ATIME_NANOS(st);
			le->name = strdup(archive_entry_pathname(entry));
			a->cleanup_archive_extract = archive_extract_cleanup;
			/* Make sure I can write to this directory. */
			archive_entry_set_mode(entry, writable_mode);
		}
	}

	if (archive_entry_hardlink(entry) != NULL)
		return (archive_read_extract_hard_link(a, entry, flags));

	/*
	 * TODO: If pathname is longer than PATH_MAX, record starting
	 * directory and move to a suitable intermediate dir, which
	 * might require creating them!
	 */
	if (strlen(archive_entry_pathname(entry)) > PATH_MAX) {
		restore_pwd = open(".", O_RDONLY);
		/* XXX chdir() to a suitable intermediate dir XXX */
		/* XXX Update pathname in 'entry' XXX */
	}

	switch (st->st_mode & S_IFMT) {
	default:
		/* Fall through, as required by POSIX. */
	case S_IFREG:
		ret =  archive_read_extract_regular(a, entry, flags);
		break;
	case S_IFLNK:	/* Symlink */
		ret =  archive_read_extract_symbolic_link(a, entry, flags);
		break;
	case S_IFCHR:
		ret =  archive_read_extract_char_device(a, entry, flags);
		break;
	case S_IFBLK:
		ret =  archive_read_extract_block_device(a, entry, flags);
		break;
	case S_IFDIR:
		ret =  archive_read_extract_dir(a, entry, flags);
		break;
	case S_IFIFO:
		ret =  archive_read_extract_fifo(a, entry, flags);
		break;
	}

	/* If we changed directory above, restore it here. */
	if (restore_pwd >= 0)
		fchdir(restore_pwd);

	return (ret);
}

/*
 * Cleanup function for archive_extract.  Free name/mode list and
 * restore permissions and dir timestamps.  This must be done last;
 * otherwise, the dir permission might prevent us from restoring a
 * file.  Similarly, the act of restoring a file touches the directory
 * and changes the timestamp on the dir, so we have to touch-up the
 * timestamps at the end as well.  Note that tar/cpio do not require
 * that archives be in a particular order; there is no way to know
 * when the last file has been restored within a directory, so there's
 * no way to optimize the memory usage here by fixing up the directory
 * any earlier than the end-of-archive.
 *
 * XXX TODO: Directory ACLs should be restored here, for the same
 * reason we set directory perms here. XXX
 *
 * Registering this function (rather than calling it explicitly by
 * name from archive_read_finish) reduces static link pollution, since
 * applications that don't use this API won't get this file linked in.
 */
static
void archive_extract_cleanup(struct archive *a)
{
	struct archive_extract_dir_entry *next, *p;

	/* Sort dir list so directories are fixed up in depth-first order. */
	p = sort_dir_list(a->archive_extract_dir_list);

	while (p != NULL) {
		struct timeval times[2];

		times[1].tv_sec = p->mtime;
		times[1].tv_usec = p->mtime_nanos / 1000;
		times[0].tv_sec = p->atime;
		times[0].tv_usec = p->atime_nanos / 1000;

		chmod(p->name, p->mode);
		utimes(p->name, times);

		next = p->next;
		free(p->name);
		free(p);
		p = next;
	}
	a->archive_extract_dir_list = NULL;
}

/*
 * Simple O(n log n) merge sort to order the directories prior to fix-up.
 */
static struct archive_extract_dir_entry *
sort_dir_list(struct archive_extract_dir_entry *p)
{
	struct archive_extract_dir_entry *a, *b, *t;

	if (p == NULL)
		return NULL;
	/* A one-item list is already sorted. */
	if (p->next == NULL)
		return (p);

	/* Step 1: split the list. */
	t = p;
	a = p->next->next;
	while (a != NULL) {
		/* Step a twice, t once. */
		a = a->next;
		if (a != NULL)
			a = a->next;
		t = t->next;
	}
	/* Now, t is at the mid-point, so break the list here. */
	b = t->next;
	t->next = NULL;
	a = p;

	/* Step 2: Recursively sort the two sub-lists. */
	a = sort_dir_list(a);
	b = sort_dir_list(b);

	/* Step 3: Merge the returned lists. */
	/* Pick the first element for the merged list. */
	if (strcmp(a->name, b->name) > 0) {
		t = p = a;
		a = a->next;
	} else {
		t = p = b;
		b = b->next;
	}

	/* Always put the later element on the list first. */
	while (a != NULL && b != NULL) {
		if (strcmp(a->name, b->name) > 0) {
			t->next = a;
			a = a->next;
		} else {
			t->next = b;
			b = b->next;
		}
		t = t->next;
	}

	/* Only one list is non-empty, so just splice it on. */
	if (a != NULL)
		t->next = a;
	if (b != NULL)
		t->next = b;

	return (p);
}

static int
archive_read_extract_regular(struct archive *a, struct archive_entry *entry,
    int flags)
{
	int fd, r;
	ssize_t s;

	r = ARCHIVE_OK;
	fd = archive_read_extract_regular_open(a,
	    archive_entry_pathname(entry), archive_entry_stat(entry)->st_mode,
	    flags);
	if (fd < 0) {
		archive_set_error(a, errno, "Can't open");
		return (ARCHIVE_WARN);
	}
	s = archive_read_data_into_fd(a, fd);
	if (s < archive_entry_size(entry)) {
		/* Didn't read enough data?  Complain but keep going. */
		archive_set_error(a, EIO, "Archive data truncated");
		r = ARCHIVE_WARN;
	}
	set_ownership(a, entry, flags);
	set_time(a, entry, flags);
	/* set_perm(a, entry, mode, flags); */ /* Handled implicitly by open.*/
	set_extended_perm(a, entry, flags);
	close(fd);
	return (r);
}

/*
 * Keep trying until we either open the file or run out of tricks.
 *
 * Note: the GNU tar 'unlink first' option seems redundant
 * with this strategy, since we never actually write over an
 * existing file.  (If it already exists, we remove it.)
 */
static int
archive_read_extract_regular_open(struct archive *a,
    const char *name, int mode, int flags)
{
	int fd;

	fd = open(name, O_WRONLY | O_CREAT | O_EXCL, mode);
	if (fd >= 0)
		return (fd);

	/* Try removing a pre-existing file. */
	if (!(flags & ARCHIVE_EXTRACT_NO_OVERWRITE)) {
		unlink(name);
		fd = open(name, O_WRONLY | O_CREAT | O_EXCL, mode);
		if (fd >= 0)
			return (fd);
	}

	/* Might be a non-existent parent dir; try fixing that. */
	mkdirpath(a, name);
	fd = open(name, O_WRONLY | O_CREAT | O_EXCL, mode);
	if (fd >= 0)
		return (fd);

	return (-1);
}

static int
archive_read_extract_dir(struct archive *a, struct archive_entry *entry,
    int flags)
{
	int mode, ret, ret2;

	mode = archive_entry_stat(entry)->st_mode;

	if (archive_read_extract_dir_create(a, archive_entry_pathname(entry),
		mode, flags)) {
		/* Unable to create directory; just use the existing dir. */
		return (ARCHIVE_WARN);
	}

	set_ownership(a, entry, flags);
	/*
	 * There is no point in setting the time here.
	 *
	 * Note that future extracts into this directory will reset
	 * the times, so to get correct results, the client has to
	 * track timestamps for directories and update them at the end
	 * of the run anyway.
	 */
	/* set_time(t, flags); */

	/*
	 * This next line may appear redundant, but it's not.  If the
	 * directory already exists, it won't get re-created by
	 * mkdir(), so we have to manually set permissions to get
	 * everything right.
	 */
	ret = set_perm(a, entry, mode, flags);
	ret2 = set_extended_perm(a, entry, flags);

	/* XXXX TODO: Fix this to work the right way. XXXX */
	if (ret == ARCHIVE_OK)
		return (ret2);
	else
		return (ret);
}

/*
 * Create the directory: try until something works or we run out of magic.
 */
static int
archive_read_extract_dir_create(struct archive *a, const char *name, int mode,
    int flags)
{
	/* Don't try to create '.' */
	if (name[0] == '.' && name[1] == 0)
		return (ARCHIVE_OK);
	if (mkdir(name, mode) == 0)
		return (ARCHIVE_OK);
	if (errno == ENOENT) {	/* Missing parent directory. */
		mkdirpath(a, name);
		if (mkdir(name, mode) == 0)
			return (ARCHIVE_OK);
	}

	if (errno != EEXIST)
		return (ARCHIVE_WARN);
	if ((flags & ARCHIVE_EXTRACT_NO_OVERWRITE)) {
		archive_set_error(a, EEXIST, "Directory already exists");
		return (ARCHIVE_WARN);
	}

	/* Could be a file; try unlinking. */
	if (unlink(name) == 0 &&
	    mkdir(name, mode) == 0)
		return (ARCHIVE_OK);

	/* Unlink failed. It's okay if it failed because it's already a dir. */
	/*
	 * BSD returns EPERM for unlink on an dir,
	 * Linux returns EISDIR
	 */
	if (errno != EPERM && errno != EISDIR) {
		archive_set_error(a, errno, "Couldn't create dir");
		return (ARCHIVE_WARN);
	}

	/* Try removing the directory and recreating it from scratch. */
	if (rmdir(name)) {
		/* Failure to remove a non-empty directory is not a problem. */
		if (errno == ENOTEMPTY)
			return (ARCHIVE_OK);
		/* Any other failure is a problem. */
		archive_set_error(a, errno,
		    "Error attempting to remove existing directory");
		return (ARCHIVE_WARN);
	}

	/* We successfully removed the directory; now recreate it. */
	if (mkdir(name, mode) == 0)
		return (ARCHIVE_OK);

	archive_set_error(a, errno, "Failed to create dir");
	return (ARCHIVE_WARN);
}

static int
archive_read_extract_hard_link(struct archive *a, struct archive_entry *entry,
    int flags)
{
	/* Just remove any pre-existing file with this name. */
	if (!(flags & ARCHIVE_EXTRACT_NO_OVERWRITE))
		unlink(archive_entry_pathname(entry));

	if (link(archive_entry_hardlink(entry),
	    archive_entry_pathname(entry))) {
		archive_set_error(a, errno, "Can't restore hardlink");
		return (ARCHIVE_WARN);
	}

	/* Set ownership, time, permission information. */
	set_ownership(a, entry, flags);
	set_time(a, entry, flags);
	set_perm(a, entry, archive_entry_stat(entry)->st_mode, flags);
	set_extended_perm(a, entry, flags);

	return (ARCHIVE_OK);
}

static int
archive_read_extract_symbolic_link(struct archive *a,
    struct archive_entry *entry, int flags)
{
	/* Just remove any pre-existing file with this name. */
	if (!(flags & ARCHIVE_EXTRACT_NO_OVERWRITE))
		unlink(archive_entry_pathname(entry));

	if (symlink(archive_entry_symlink(entry),
		archive_entry_pathname(entry))) {
		/* XXX Better error message here XXX */
		archive_set_error(a, errno, "Can't restore symlink to '%s'",
		    archive_entry_symlink(entry));
		return (ARCHIVE_WARN);
	}

	/* Set ownership, time, permission information. */
	set_ownership(a, entry, flags);
	set_time(a, entry, flags);
	set_perm(a, entry, archive_entry_stat(entry)->st_mode, flags);
	set_extended_perm(a, entry, flags);

	return (ARCHIVE_OK);
}

static int
archive_read_extract_device(struct archive *a, struct archive_entry *entry,
    int flags, mode_t mode)
{
	int r;

	/* Just remove any pre-existing file with this name. */
	if (!(flags & ARCHIVE_EXTRACT_NO_OVERWRITE))
		unlink(archive_entry_pathname(entry));

	r = mknod(archive_entry_pathname(entry), mode,
	    archive_entry_stat(entry)->st_rdev);

	/* Might be a non-existent parent dir; try fixing that. */
	if (r != 0 && errno == ENOENT) {
		mkdirpath(a, archive_entry_pathname(entry));
		r = mknod(archive_entry_pathname(entry), mode,
		    archive_entry_stat(entry)->st_rdev);
	}

	if (r != 0) {
		archive_set_error(a, errno, "Can't recreate device node");
		return (ARCHIVE_WARN);
	}

	/* Set ownership, time, permission information. */
	set_ownership(a, entry, flags);
	set_time(a, entry, flags);
	set_perm(a, entry, archive_entry_stat(entry)->st_mode, flags);
	set_extended_perm(a, entry, flags);

	return (ARCHIVE_OK);
}

static int
archive_read_extract_char_device(struct archive *a,
    struct archive_entry *entry, int flags)
{
	mode_t mode;

	mode = (archive_entry_stat(entry)->st_mode & ~S_IFMT) | S_IFCHR;
	return (archive_read_extract_device(a, entry, flags, mode));
}

static int
archive_read_extract_block_device(struct archive *a,
    struct archive_entry *entry, int flags)
{
	mode_t mode;

	mode = (archive_entry_stat(entry)->st_mode & ~S_IFMT) | S_IFBLK;
	return (archive_read_extract_device(a, entry, flags, mode));
}

static int
archive_read_extract_fifo(struct archive *a,
    struct archive_entry *entry, int flags)
{
	int r;

	/* Just remove any pre-existing file with this name. */
	if (!(flags & ARCHIVE_EXTRACT_NO_OVERWRITE))
		unlink(archive_entry_pathname(entry));

	r = mkfifo(archive_entry_pathname(entry),
	    archive_entry_stat(entry)->st_mode);

	/* Might be a non-existent parent dir; try fixing that. */
	if (r != 0 && errno == ENOENT) {
		mkdirpath(a, archive_entry_pathname(entry));
		r = mkfifo(archive_entry_pathname(entry),
		    archive_entry_stat(entry)->st_mode);
	}

	if (r != 0) {
		archive_set_error(a, errno, "Can't restore fifo");
		return (ARCHIVE_WARN);
	}

	/* Set ownership, time, permission information. */
	set_ownership(a, entry, flags);
	set_time(a, entry, flags);
	/* Done by mkfifo. */
	/* set_perm(a, entry, archive_entry_stat(entry)->st_mode, flags); */
	set_extended_perm(a, entry, flags);

	return (ARCHIVE_OK);
}

/*
 * Returns 0 if it successfully created necessary directories.
 * Otherwise, returns ARCHIVE_WARN.
 */

static int
mkdirpath(struct archive *a, const char *path)
{
	char *p;

	/* Copy path to mutable storage, then call mkdirpath_recursive. */
	archive_strcpy(&(a->extract_mkdirpath), path);
	/* Prune a trailing '/' character. */
	p = a->extract_mkdirpath.s;
	if (p[strlen(p)-1] == '/')
		p[strlen(p)-1] = 0;
	/* Recursively try to build the path. */
	return (mkdirpath_recursive(p));
}

/*
 * For efficiency, just try creating longest path first (usually,
 * archives walk through directories in a reasonable order).  If that
 * fails, prune the last element and recursively try again.
 */
static int
mkdirpath_recursive(char *path)
{
	char * p;
	int r;

	p = strrchr(path, '/');
	if (!p) return (0);

	*p = 0;			/* Terminate path name. */
	r = mksubdir(path);	/* Try building path. */
	*p = '/';		/* Restore the '/' we just overwrote. */
	return (r);
}

static int
mksubdir(char *path)
{
	int mode = 0755;

	if (mkdir(path, mode) == 0) return (0);

	if (errno == EEXIST) /* TODO: stat() here to verify it is dir */
		return (0);
	if (mkdirpath_recursive(path))
		return (ARCHIVE_WARN);
	if (mkdir(path, mode) == 0)
		return (0);
	return (ARCHIVE_WARN); /* Still failed.  Harumph. */
}

/*
 * Note that I only inspect entry->ae_uid and entry->ae_gid here; if
 * the client wants POSIX compat, they'll need to do uname/gname
 * lookups themselves.  I don't do it here because of the potential
 * performance issues: if uname/gname lookup is expensive, then the
 * results should be aggressively cached; if they're cheap, then we
 * shouldn't waste memory on cache tables.
 *
 * Returns 0 if UID/GID successfully restored; ARCHIVE_WARN otherwise.
 */
static int
set_ownership(struct archive *a, struct archive_entry *entry, int flags)
{
	uid_t uid;
	gid_t gid;

	/* If UID/GID are already correct, return 0. */
	/* TODO: Fix this; need to stat() to find on-disk GID <sigh> */
	if (a->user_uid == archive_entry_stat(entry)->st_uid)
		return (0);

	/* Not changed. */
	if ((flags & ARCHIVE_EXTRACT_OWNER) == 0)
		return (ARCHIVE_WARN);

	uid = lookup_uid(a, archive_entry_uname(entry),
	    archive_entry_stat(entry)->st_uid);
	gid = lookup_gid(a, archive_entry_gname(entry),
	    archive_entry_stat(entry)->st_gid);

	/*
	 * Root can change owner/group; owner can change group;
	 * otherwise, bail out now.
	 */
	if (a->user_uid != 0  &&  a->user_uid != uid) {
		/* XXXX archive_set_error( XXXX ) ; XXX */
		return (ARCHIVE_WARN);
	}

	if (lchown(archive_entry_pathname(entry), uid, gid)) {
		archive_set_error(a, errno,
		    "Can't set user=%d/group=%d for %s", uid, gid,
		    archive_entry_pathname(entry));
		return (ARCHIVE_WARN);
	}
	return (ARCHIVE_OK);
}

static int
set_time(struct archive *a, struct archive_entry *entry, int flags)
{
	const struct stat *st;
	struct timeval times[2];

	(void)a; /* UNUSED */
	st = archive_entry_stat(entry);

	if ((flags & ARCHIVE_EXTRACT_TIME) == 0)
		return (ARCHIVE_OK);

	times[1].tv_sec = st->st_mtime;
	times[1].tv_usec = ARCHIVE_STAT_MTIME_NANOS(st) / 1000;

	times[0].tv_sec = st->st_atime;
	times[0].tv_usec = ARCHIVE_STAT_ATIME_NANOS(st) / 1000;

#ifdef HAVE_LUTIMES
	if (lutimes(archive_entry_pathname(entry), times) != 0) {
#else
	if ((archive_entry_mode(entry) & S_IFMT) != S_IFLNK &&
	    utimes(archive_entry_pathname(entry), times) != 0) {
#endif
		archive_set_error(a, errno, "Can't update time for %s",
		    archive_entry_pathname(entry));
		return (ARCHIVE_WARN);
	}

	/*
	 * Note: POSIX does not provide a portable way to restore ctime.
	 * So, any restoration of ctime will necessarily be OS-specific.
	 */

	/* TODO: Can FreeBSD restore ctime? */

	return (ARCHIVE_OK);
}

static int
set_perm(struct archive *a, struct archive_entry *entry, int mode, int flags)
{
	const char *name;

	if ((flags & ARCHIVE_EXTRACT_PERM) == 0)
		return (ARCHIVE_OK);

	name = archive_entry_pathname(entry);
#ifdef HAVE_LCHMOD
	if (lchmod(name, mode) != 0) {
#else
	if ((archive_entry_mode(entry) & S_IFMT) != S_IFLNK &&
	    chmod(name, mode) != 0) {
#endif
		archive_set_error(a, errno, "Can't set permissions");
		return (ARCHIVE_WARN);
	}
	return (0);
}

static int
set_extended_perm(struct archive *a, struct archive_entry *entry, int flags)
{
	int		 ret, ret2;

	if ((flags & ARCHIVE_EXTRACT_PERM) == 0)
		return (ARCHIVE_OK);

	ret = set_fflags(a, entry);
	ret2 = set_acls(a, entry);

	return (err_combine(ret,ret2));
}

static int
set_fflags(struct archive *a, struct archive_entry *entry)
{
	const char	*name;
	int		 ret;
	unsigned long	 set, clear;
	struct stat	 st;
#ifdef LINUX
	struct stat	 *stp;
	int		 fd;
	int		 err;
	unsigned long newflags, oldflags;
#endif

	name = archive_entry_pathname(entry);
	ret = ARCHIVE_OK;
	archive_entry_fflags(entry, &set, &clear);
	if (set == 0  && clear == 0)
		return (ret);

#ifdef HAVE_CHFLAGS
	/*
	 * XXX Is the stat here really necessary?  Or can I just use
	 * the 'set' flags directly?  In particular, I'm not sure
	 * about the correct approach if we're overwriting an existing
	 * file that already has flags on it. XXX
	 */
	if (stat(name, &st) == 0) {
		st.st_flags &= ~clear;
		st.st_flags |= set;
		if (chflags(name, st.st_flags) != 0) {
			archive_set_error(a, errno,
			    "Failed to set file flags");
			ret = ARCHIVE_WARN;
		}
	}
#endif
	/* Linux has flags too, but no chflags syscall */
#ifdef LINUX
	/*
	 * Linux has no define for the flags that are only settable
	 * by the root user...
	 */
#define	SF_MASK                 (EXT2_IMMUTABLE_FL|EXT2_APPEND_FL)

	/*
	 * XXX As above, this would be way simpler if we didn't have
	 * to read the current flags from disk. XXX
	 */
	stp = archive_entry_stat(entry);
	if ((S_ISREG(stp->st_mode) || S_ISDIR(stp->st_mode)) &&
	    ((fd = open(name, O_RDONLY|O_NONBLOCK)) >= 0)) {
		err = 1;
		if (fd >= 0 && (ioctl(fd, EXT2_IOC_GETFLAGS, &oldflags) >= 0)) {
			newflags = (oldflags & ~clear) | set;
			if (ioctl(fd, EXT2_IOC_SETFLAGS, &newflags) >= 0) {
				err = 0;
			} else if (errno == EPERM) {
				if (ioctl(fd, EXT2_IOC_GETFLAGS, &oldflags) >= 0) {
					newflags &= ~SF_MASK;
					oldflags &= SF_MASK;
					newflags |= oldflags;
					if (ioctl(fd, EXT2_IOC_SETFLAGS, &newflags) >= 0)
						err = 0;
				}
			}
		}
		close(fd);
		if (err) {
			archive_set_error(a, errno,
			    "Failed to set file flags");
			ret = ARCHIVE_WARN;
		}
	}
#endif

	return (ret);
}

#ifndef HAVE_POSIX_ACL
/* Default empty function body to satisfy mainline code. */
static int
set_acls(struct archive *a, struct archive_entry *entry)
{
	(void)a;
	(void)entry;

	return (ARCHIVE_OK);
}

#else

/*
 * XXX TODO: What about ACL types other than ACCESS and DEFAULT?
 */
static int
set_acls(struct archive *a, struct archive_entry *entry)
{
	int		 ret;

	ret = set_acl(a, entry, ACL_TYPE_ACCESS,
	    ARCHIVE_ENTRY_ACL_TYPE_ACCESS, "access");
	if (ret != ARCHIVE_OK)
		return (ret);
	ret = set_acl(a, entry, ACL_TYPE_DEFAULT,
	    ARCHIVE_ENTRY_ACL_TYPE_DEFAULT, "default");
	return (ret);
}


static int
set_acl(struct archive *a, struct archive_entry *entry, acl_type_t acl_type,
    int ae_requested_type, const char *typename)
{
	acl_t		 acl;
	acl_entry_t	 acl_entry;
	acl_permset_t	 acl_permset;
	int		 ret;
	int		 ae_type, ae_permset, ae_tag, ae_id;
	uid_t		 ae_uid;
	gid_t		 ae_gid;
	const char	*ae_name;
	int		 entries;
	const char	*name;

	ret = ARCHIVE_OK;
	entries = archive_entry_acl_reset(entry, ae_requested_type);
	if (entries == 0)
		return (ARCHIVE_OK);
	acl = acl_init(entries);
	while (archive_entry_acl_next(entry, ae_requested_type, &ae_type,
		   &ae_permset, &ae_tag, &ae_id, &ae_name) == ARCHIVE_OK) {
		acl_create_entry(&acl, &acl_entry);

		switch (ae_tag) {
		case ARCHIVE_ENTRY_ACL_USER:
			acl_set_tag_type(acl_entry, ACL_USER);
			ae_uid = lookup_uid(a, ae_name, ae_id);
			acl_set_qualifier(acl_entry, &ae_uid);
			break;
		case ARCHIVE_ENTRY_ACL_GROUP:
			acl_set_tag_type(acl_entry, ACL_GROUP);
			ae_gid = lookup_gid(a, ae_name, ae_id);
			acl_set_qualifier(acl_entry, &ae_gid);
			break;
		case ARCHIVE_ENTRY_ACL_USER_OBJ:
			acl_set_tag_type(acl_entry, ACL_USER_OBJ);
			break;
		case ARCHIVE_ENTRY_ACL_GROUP_OBJ:
			acl_set_tag_type(acl_entry, ACL_GROUP_OBJ);
			break;
		case ARCHIVE_ENTRY_ACL_MASK:
			acl_set_tag_type(acl_entry, ACL_MASK);
			break;
		case ARCHIVE_ENTRY_ACL_OTHER:
			acl_set_tag_type(acl_entry, ACL_OTHER);
			break;
		default:
			/* XXX */
			break;
		}

		acl_get_permset(acl_entry, &acl_permset);
		acl_clear_perms(acl_permset);
		if (ae_permset & ARCHIVE_ENTRY_ACL_EXECUTE)
			acl_add_perm(acl_permset, ACL_EXECUTE);
		if (ae_permset & ARCHIVE_ENTRY_ACL_WRITE)
			acl_add_perm(acl_permset, ACL_WRITE);
		if (ae_permset & ARCHIVE_ENTRY_ACL_READ)
			acl_add_perm(acl_permset, ACL_READ);
	}

	name = archive_entry_pathname(entry);

	if (acl_set_file(name, acl_type, acl) != 0) {
		archive_set_error(a, errno, "Failed to set %s acl", typename);
		ret = ARCHIVE_WARN;
	}
	acl_free(acl);
	return (ret);
}
#endif

/*
 * XXX The following gid/uid lookups can be a performance bottleneck.
 * Some form of caching would probably be very effective, though
 * I have concerns about staleness.
 */
static gid_t
lookup_gid(struct archive *a, const char *gname, gid_t gid)
{
	struct group	*grent;

	(void)a; /* UNUSED */

	/* Look up gid from gname. */
	if (gname != NULL  &&  *gname != '\0') {
		grent = getgrnam(gname);
		if (grent != NULL)
			gid = grent->gr_gid;
	}
	return (gid);
}

static uid_t
lookup_uid(struct archive *a, const char *uname, uid_t uid)
{
	struct passwd	*pwent;

	(void)a; /* UNUSED */

	/* Look up uid from uname. */
	if (uname != NULL  &&  *uname != '\0') {
		pwent = getpwnam(uname);
		if (pwent != NULL)
			uid = pwent->pw_uid;
	}
	return (uid);
}
