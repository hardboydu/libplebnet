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
#include <unistd.h>
#ifdef LINUX
#include <ext2fs/ext2_fs.h>
#include <sys/ioctl.h>
#endif

#include "archive.h"
#include "archive_string.h"
#include "archive_entry.h"
#include "archive_private.h"

struct fixup_entry {
	struct fixup_entry	*next;
	mode_t			 mode;
	int64_t			 mtime;
	int64_t			 atime;
	unsigned long		 mtime_nanos;
	unsigned long		 atime_nanos;
	unsigned long		 fflags_set;
	int			 fixup; /* bitmask of what needs fixing */
	char			*name;
};

#define	FIXUP_MODE	1
#define	FIXUP_TIMES	2
#define	FIXUP_FFLAGS	4

struct extract {
	mode_t			 umask;
	mode_t			 default_dir_mode;
	struct archive_string	 mkdirpath;
	struct fixup_entry	*fixup_list;

	/*
	 * Cached stat data from disk for the current entry.
	 * If this is valid, pst points to st.  Otherwise,
	 * pst is null.
	 *
	 * TODO: Have all of the stat calls use this cached data
	 * if possible.
	 */
	struct stat		 st;
	struct stat		*pst;
};

/* Default mode for dirs created automatically (will be modified by umask). */
#define DEFAULT_DIR_MODE 0777
/*
 * Mode to use for newly-created dirs during extraction; the correct
 * mode will be set at the end of the extraction.
 */
#define SECURE_DIR_MODE 0700

static void	archive_extract_cleanup(struct archive *);
static int	extract_block_device(struct archive *,
		    struct archive_entry *, int);
static int	extract_char_device(struct archive *,
		    struct archive_entry *, int);
static int	extract_device(struct archive *,
		    struct archive_entry *, int flags, mode_t mode);
static int	extract_dir(struct archive *, struct archive_entry *, int);
static int	extract_fifo(struct archive *, struct archive_entry *, int);
static int	extract_file(struct archive *, struct archive_entry *, int);
static int	extract_hard_link(struct archive *, struct archive_entry *, int);
static int	extract_symlink(struct archive *, struct archive_entry *, int);
static gid_t	lookup_gid(struct archive *, const char *uname, gid_t);
static uid_t	lookup_uid(struct archive *, const char *uname, uid_t);
static int	mkdirpath(struct archive *, const char *);
static int	mkdirpath_recursive(struct archive *, char *,
		    const struct stat *, mode_t, int);
static int	restore_metadata(struct archive *, struct archive_entry *,
		    int flags);
#ifdef HAVE_POSIX_ACL
static int	set_acl(struct archive *, struct archive_entry *,
		    acl_type_t, int archive_entry_acl_type, const char *tn);
#endif
static int	set_acls(struct archive *, struct archive_entry *);
static int	set_fflags(struct archive *, const char *name, mode_t mode,
		    unsigned long fflags_set, unsigned long fflags_clear);
static int	set_ownership(struct archive *, struct archive_entry *, int);
static int	set_perm(struct archive *, struct archive_entry *, int mode,
		    int flags);
static int	set_time(struct archive *, struct archive_entry *, int);
static struct fixup_entry *sort_dir_list(struct fixup_entry *p);


/*
 * Extract this entry to disk.
 *
 * TODO: Validate hardlinks.  According to the standards, we're
 * supposed to check each extracted hardlink and squawk if it refers
 * to a file that we didn't restore.  I'm not entirely convinced this
 * is a good idea, but more importantly: Is there any way to validate
 * hardlinks without keeping a complete list of filenames from the
 * entire archive?? Ugh.
 *
 */
int
archive_read_extract(struct archive *a, struct archive_entry *entry, int flags)
{
	mode_t mode;
	struct extract *extract;
	int ret;
	int restore_pwd;

	if (a->extract == NULL) {
		a->extract = malloc(sizeof(*a->extract));
		if (a->extract == NULL) {
			archive_set_error(a, ENOMEM, "Can't extract");
			return (ARCHIVE_FATAL);
		}
		a->cleanup_archive_extract = archive_extract_cleanup;
		memset(a->extract, 0, sizeof(*a->extract));
	}
	extract = a->extract;
	umask(extract->umask = umask(0)); /* Read the current umask. */
	extract->default_dir_mode = DEFAULT_DIR_MODE & ~extract->umask;
	extract->pst = NULL;
	restore_pwd = -1;

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

	if (stat(archive_entry_pathname(entry), &extract->st) == 0)
		extract->pst = &extract->st;

	if (extract->pst != NULL &&
	    extract->pst->st_dev == a->skip_file_dev &&
	    extract->pst->st_ino == a->skip_file_ino) {
		archive_set_error(a, 0, "Refusing to overwrite archive");
		ret = ARCHIVE_WARN;
	} else if (archive_entry_hardlink(entry) != NULL)
		ret = extract_hard_link(a, entry, flags);
	else {
		mode = archive_entry_mode(entry);
		switch (mode & S_IFMT) {
		default:
			/* Fall through, as required by POSIX. */
		case S_IFREG:
			ret = extract_file(a, entry, flags);
			break;
		case S_IFLNK:	/* Symlink */
			ret = extract_symlink(a, entry, flags);
			break;
		case S_IFCHR:
			ret = extract_char_device(a, entry, flags);
			break;
		case S_IFBLK:
			ret = extract_block_device(a, entry, flags);
			break;
		case S_IFDIR:
			ret = extract_dir(a, entry, flags);
			break;
		case S_IFIFO:
			ret = extract_fifo(a, entry, flags);
			break;
		}
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
static void
archive_extract_cleanup(struct archive *a)
{
	struct fixup_entry *next, *p;
	struct extract *extract;

	/* Sort dir list so directories are fixed up in depth-first order. */
	extract = a->extract;
	p = sort_dir_list(extract->fixup_list);

	while (p != NULL) {
		if (p->fixup & FIXUP_TIMES) {
			struct timeval times[2];
			times[1].tv_sec = p->mtime;
			times[1].tv_usec = p->mtime_nanos / 1000;
			times[0].tv_sec = p->atime;
			times[0].tv_usec = p->atime_nanos / 1000;
			utimes(p->name, times);
		}
		if (p->fixup & FIXUP_MODE)
			chmod(p->name, p->mode);

		if (p->fixup & FIXUP_FFLAGS)
			set_fflags(a, p->name, p->mode, p->fflags_set, 0);

		next = p->next;
		free(p->name);
		free(p);
		p = next;
	}
	extract->fixup_list = NULL;
	archive_string_free(&extract->mkdirpath);
	free(a->extract);
	a->extract = NULL;
}

/*
 * Simple O(n log n) merge sort to order the fixup list.  In
 * particular, we want to restore dir timestamps depth-first.
 */
static struct fixup_entry *
sort_dir_list(struct fixup_entry *p)
{
	struct fixup_entry *a, *b, *t;

	if (p == NULL)
		return (NULL);
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
extract_file(struct archive *a, struct archive_entry *entry, int flags)
{
	struct extract *extract;
	const char *name;
	mode_t mode;
	int fd, r, r2;

	extract = a->extract;
	name = archive_entry_pathname(entry);
	mode = archive_entry_mode(entry) & 0777;
	r = ARCHIVE_OK;

	/*
	 * If we're not supposed to overwrite pre-existing files,
	 * use O_EXCL.  Otherwise, use O_TRUNC.
	 */
	if (flags & (ARCHIVE_EXTRACT_UNLINK | ARCHIVE_EXTRACT_NO_OVERWRITE))
		fd = open(name, O_WRONLY | O_CREAT | O_EXCL, mode);
	else
		fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, mode);

	/* Try removing a pre-existing file. */
	if (fd < 0 && !(flags & ARCHIVE_EXTRACT_NO_OVERWRITE)) {
		unlink(name);
		fd = open(name, O_WRONLY | O_CREAT | O_EXCL, mode);
	}

	/* Might be a non-existent parent dir; try fixing that. */
	if (fd < 0) {
		mkdirpath(a, name);
		fd = open(name, O_WRONLY | O_CREAT | O_EXCL, mode);
	}
	if (fd < 0) {
		archive_set_error(a, errno, "Can't open '%s'", name);
		return (ARCHIVE_WARN);
	}
	r = archive_read_data_into_fd(a, fd);
	extract->pst = NULL; /* Cached stat data no longer valid. */
	r2 = restore_metadata(a, entry, flags);
	close(fd);
	return (err_combine(r, r2));
}

static int
extract_dir(struct archive *a, struct archive_entry *entry, int flags)
{
	struct extract *extract;
	const struct stat *st;
	char *p;
	size_t len;
	mode_t mode;

	extract = a->extract;

	/* Copy path to mutable storage. */
	archive_strcpy(&(extract->mkdirpath),
	    archive_entry_pathname(entry));
	p = extract->mkdirpath.s;
	len = strlen(p);
	if (len > 2 && p[len - 1] == '.' && p[len - 2] == '/')
		p[--len] = '\0'; /* Remove trailing "/." */
	if (len > 2 && p[len - 1] == '/')
		p[--len] = '\0'; /* Remove trailing "/" */
	/* Recursively try to build the path. */
	st = archive_entry_stat(entry);
	mode = st->st_mode;
	/* Obey umask unless ARCHIVE_EXTRACT_PERM for explicit dirs. */
	if ((flags & ARCHIVE_EXTRACT_PERM) == 0)
		mode &= ~extract->umask;
	extract->pst = NULL; /* Invalidate cached stat data. */
	if (mkdirpath_recursive(a, p, st, mode, flags))
		return (ARCHIVE_WARN);
	archive_entry_set_mode(entry, 0700);
	return (restore_metadata(a, entry, flags));
}


/*
 * Convenience form.
 */
static int
mkdirpath(struct archive *a, const char *path)
{
	struct extract *extract;
	char *p;

	extract = a->extract;

	/* Copy path to mutable storage. */
	archive_strcpy(&(extract->mkdirpath), path);
	p = extract->mkdirpath.s;
	p = strrchr(extract->mkdirpath.s, '/');
	if (p == NULL)
		return (ARCHIVE_OK);
	*p = '\0';

	/* Recursively try to build the path. */
	if (mkdirpath_recursive(a, extract->mkdirpath.s,
	    NULL, extract->default_dir_mode, 0))
		return (ARCHIVE_WARN);
	return (ARCHIVE_OK);
}

/*
 * Returns 0 if it successfully created necessary directories.
 * Otherwise, returns ARCHIVE_WARN.
 */
static int
mkdirpath_recursive(struct archive *a, char *path,
    const struct stat *desired_stat, mode_t mode, int flags)
{
	struct stat st;
	struct extract *extract;
	struct fixup_entry *le;
	char *p;
	mode_t writable_mode = SECURE_DIR_MODE;
	int r;

	extract = a->extract;

	if (path[0] == '.' && path[1] == 0)
		return (ARCHIVE_OK);

	if (mode != writable_mode ||
	    (desired_stat != NULL && (flags & ARCHIVE_EXTRACT_TIME))) {
		/* Add this dir to the fixup list. */
		le = malloc(sizeof(struct fixup_entry));
		le->fixup = 0;
		le->next = extract->fixup_list;
		extract->fixup_list = le;
		le->name = strdup(path);

		if (mode != writable_mode) {
			le->mode = mode;
			le->fixup |= FIXUP_MODE;
			mode = writable_mode;
		}
		if (flags & ARCHIVE_EXTRACT_TIME) {
			le->mtime = desired_stat->st_mtime;
			le->mtime_nanos = ARCHIVE_STAT_MTIME_NANOS(desired_stat);
			le->atime = desired_stat->st_atime;
			le->atime_nanos = ARCHIVE_STAT_ATIME_NANOS(desired_stat);
			le->fixup |= FIXUP_TIMES;
		}
	}

	/*
	 * Try to make the longest dir first.  Most archives are
	 * written in a reasonable order, so this will almost always
	 * save us from having to inspect the parent dirs.
	 */
	if (mkdir(path, mode) == 0)
		return (ARCHIVE_OK);
	/*
	 * Do "unlink first" after.  The preceding syscall will always
	 * fail if something already exists, so we save a little time
	 * in the common case by not trying to unlink until we know
	 * something is there.
	 */
	if ((flags & ARCHIVE_EXTRACT_UNLINK))
		unlink(path);
	/*
	 * Yes, this should be stat() and not lstat().  Using lstat()
	 * here loses the ability to extract through symlinks.  If
	 * clients don't want to extract through symlinks, they should
	 * specify ARCHIVE_EXTRACT_UNLINK.
	 *
	 * Note that this cannot use the extract->st cache.
	 */
	if (stat(path, &st) == 0) {
		/* Already exists! */
		if (S_ISDIR(st.st_mode))
			return (ARCHIVE_OK);
		if ((flags & ARCHIVE_EXTRACT_NO_OVERWRITE)) {
			archive_set_error(a, EEXIST,
			    "Can't create directory '%s'", path);
			return (ARCHIVE_WARN);
		}
		/* Not a dir: remove it and create a directory. */
		if (unlink(path) == 0 &&
		    mkdir(path, mode) == 0)
			return (ARCHIVE_OK);
	} else if (errno != ENOENT) {
		/* Stat failed? */
		archive_set_error(a, errno, "Can't test directory '%s'", path);
		return (ARCHIVE_WARN);
	}

	/* Doesn't exist: try creating parent dir. */
	p = strrchr(path, '/');
	if (p != NULL) {
		*p = '\0';	/* Terminate path name. */
		/* Note that implicit dirs always obey the umask. */
		r = mkdirpath_recursive(a, path, NULL,
		    extract->default_dir_mode, 0);
		*p = '/';	/* Restore the '/' we just overwrote. */
		if (r != ARCHIVE_OK)
			return (r);
		/* Parent exists now; let's create the last component. */
		p++;
		/* Of course, "", ".", and ".." are easy. */
		if (p[0] == '\0')
			return (ARCHIVE_OK);
		if (p[0] == '.' && p[1] == '\0')
			return (ARCHIVE_OK);
		if (p[0] == '.' && p[1] == '.' && p[2] == '\0')
			return (ARCHIVE_OK);
		if (mkdir(path, mode) == 0)
			return (ARCHIVE_OK);
		/*
		 * Without the following check, a/b/../b/c/d fails at
		 * the second visit to 'b', so 'd' can't be created.
		 */
		if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
			return (ARCHIVE_OK);
	}
	archive_set_error(a, errno, "Failed to create dir '%s'", path);
	return (ARCHIVE_WARN);
}

static int
extract_hard_link(struct archive *a, struct archive_entry *entry, int flags)
{
	struct extract *extract;
	int r;
	const char *pathname;
	const char *linkname;

	extract = a->extract;
	pathname = archive_entry_pathname(entry);
	linkname = archive_entry_hardlink(entry);

	/* Just remove any pre-existing file with this name. */
	if (!(flags & ARCHIVE_EXTRACT_NO_OVERWRITE))
		unlink(pathname);

	r = link(linkname, pathname);
	extract->pst = NULL; /* Invalidate cached stat data. */

	if (r != 0) {
		/* Might be a non-existent parent dir; try fixing that. */
		mkdirpath(a, pathname);
		r = link(linkname, pathname);
	}

	if (r != 0) {
		/* XXX Better error message here XXX */
		archive_set_error(a, errno,
		    "Can't restore hardlink to '%s'", linkname);
		return (ARCHIVE_WARN);
	}

	/* Set ownership, time, permission information. */
	r = restore_metadata(a, entry, flags);
	return (r);
}

static int
extract_symlink(struct archive *a, struct archive_entry *entry, int flags)
{
	struct extract *extract;
	int r;
	const char *pathname;
	const char *linkname;

	extract = a->extract;
	pathname = archive_entry_pathname(entry);
	linkname = archive_entry_symlink(entry);

	/* Just remove any pre-existing file with this name. */
	if (!(flags & ARCHIVE_EXTRACT_NO_OVERWRITE))
		unlink(pathname);

	r = symlink(linkname, pathname);
	extract->pst = NULL; /* Invalidate cached stat data. */

	if (r != 0) {
		/* Might be a non-existent parent dir; try fixing that. */
		mkdirpath(a, pathname);
		r = symlink(linkname, pathname);
	}

	if (r != 0) {
		/* XXX Better error message here XXX */
		archive_set_error(a, errno,
		    "Can't restore symlink to '%s'", linkname);
		return (ARCHIVE_WARN);
	}

	r = restore_metadata(a, entry, flags);
	return (r);
}

static int
extract_device(struct archive *a, struct archive_entry *entry,
    int flags, mode_t mode)
{
	struct extract *extract;
	int r;

	extract = a->extract;
	/* Just remove any pre-existing file with this name. */
	if (!(flags & ARCHIVE_EXTRACT_NO_OVERWRITE))
		unlink(archive_entry_pathname(entry));

	r = mknod(archive_entry_pathname(entry), mode,
	    archive_entry_rdev(entry));
	extract->pst = NULL; /* Invalidate cached stat data. */

	/* Might be a non-existent parent dir; try fixing that. */
	if (r != 0 && errno == ENOENT) {
		mkdirpath(a, archive_entry_pathname(entry));
		r = mknod(archive_entry_pathname(entry), mode,
		    archive_entry_rdev(entry));
	}

	if (r != 0) {
		archive_set_error(a, errno, "Can't restore device node");
		return (ARCHIVE_WARN);
	}

	r = restore_metadata(a, entry, flags);
	return (r);
}

static int
extract_char_device(struct archive *a, struct archive_entry *entry, int flags)
{
	mode_t mode;

	mode = (archive_entry_mode(entry) & ~S_IFMT) | S_IFCHR;
	return (extract_device(a, entry, flags, mode));
}

static int
extract_block_device(struct archive *a, struct archive_entry *entry, int flags)
{
	mode_t mode;

	mode = (archive_entry_mode(entry) & ~S_IFMT) | S_IFBLK;
	return (extract_device(a, entry, flags, mode));
}

static int
extract_fifo(struct archive *a, struct archive_entry *entry, int flags)
{
	struct extract *extract;
	int r;

	extract = a->extract;
	/* Just remove any pre-existing file with this name. */
	if (!(flags & ARCHIVE_EXTRACT_NO_OVERWRITE))
		unlink(archive_entry_pathname(entry));

	r = mkfifo(archive_entry_pathname(entry),
	    archive_entry_mode(entry));
	extract->pst = NULL; /* Invalidate cached stat data. */

	/* Might be a non-existent parent dir; try fixing that. */
	if (r != 0 && errno == ENOENT) {
		mkdirpath(a, archive_entry_pathname(entry));
		r = mkfifo(archive_entry_pathname(entry),
		    archive_entry_mode(entry));
	}

	if (r != 0) {
		archive_set_error(a, errno, "Can't restore fifo");
		return (ARCHIVE_WARN);
	}

	r = restore_metadata(a, entry, flags);
	return (r);
}

static int
restore_metadata(struct archive *a, struct archive_entry *entry, int flags)
{
	int r, r2;

	r = set_ownership(a, entry, flags);
	r2 = set_time(a, entry, flags);
	r = err_combine(r, r2);
	r2 = set_perm(a, entry, archive_entry_mode(entry), flags);
	return (err_combine(r, r2));
}

static int
set_ownership(struct archive *a, struct archive_entry *entry, int flags)
{
	uid_t uid;
	gid_t gid;

	/* Not changed. */
	if ((flags & ARCHIVE_EXTRACT_OWNER) == 0)
		return (ARCHIVE_OK);

	uid = lookup_uid(a, archive_entry_uname(entry),
	    archive_entry_uid(entry));
	gid = lookup_gid(a, archive_entry_gname(entry),
	    archive_entry_gid(entry));

	/* If we know we can't change it, don't bother trying. */
	if (a->user_uid != 0  &&  a->user_uid != uid)
		return (ARCHIVE_OK);

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
	/* It's a waste of time to mess with dir timestamps here. */
	if (S_ISDIR(archive_entry_mode(entry)))
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
	 * (Apart from resetting the system clock, which is distasteful.)
	 * So, any restoration of ctime will necessarily be OS-specific.
	 */

	/* XXX TODO: Can FreeBSD restore ctime? XXX */

	return (ARCHIVE_OK);
}

static int
set_perm(struct archive *a, struct archive_entry *entry, int mode, int flags)
{
	struct extract *extract;
	struct fixup_entry *le;
	const char *name;
	unsigned long	 set, clear;
	int		 r;
	int		 critical_flags;

	extract = a->extract;

	/* Obey umask unless ARCHIVE_EXTRACT_PERM. */
	if ((flags & ARCHIVE_EXTRACT_PERM) == 0)
		mode &= ~extract->umask; /* Enforce umask. */
	name = archive_entry_pathname(entry);

	if (mode & (S_ISUID | S_ISGID)) {
		if (extract->pst == NULL && stat(name, &extract->st) != 0) {
			archive_set_error(a, errno, "Can't check ownership");
			return (ARCHIVE_WARN);
		}
		extract->pst = &extract->st;
		/*
		 * TODO: Use the uid/gid looked up in set_ownership
		 * above rather than the uid/gid stored in the entry.
		 */
		if (extract->pst->st_uid != archive_entry_uid(entry))
			mode &= ~ S_ISUID;
		if (extract->pst->st_gid != archive_entry_gid(entry))
			mode &= ~ S_ISGID;
	}

	/*
	 * Ensure we change permissions on the object we extracted,
	 * and not any incidental symlink that might have gotten in
	 * the way.
	 */
	if (!S_ISLNK(archive_entry_mode(entry))) {
		if (chmod(name, mode) != 0) {
			archive_set_error(a, errno, "Can't set permissions");
			return (ARCHIVE_WARN);
		}
	} else {
#ifdef HAVE_LCHMOD
		/*
		 * If lchmod() isn't supported, it's no big deal.
		 * Permissions on symlinks are actually ignored on
		 * most platforms.
		 */
		if (lchmod(name, mode) != 0) {
			archive_set_error(a, errno, "Can't set permissions");
			return (ARCHIVE_WARN);
		}
#endif
	}

	if (flags & ARCHIVE_EXTRACT_ACL) {
		r = set_acls(a, entry);
		if (r != ARCHIVE_OK)
			return (r);
	}

	/*
	 * Make 'critical_flags' hold all file flags that can't be
	 * immediately restored.  For example, on BSD systems,
	 * SF_IMMUTABLE prevents hardlinks from being created, so
	 * should not be set until after any hardlinks are created.  To
	 * preserve some semblance of portability, this uses #ifdef
	 * extensively.  Ugly, but it works.
	 *
	 * Yes, Virginia, this does create a security race.  It's mitigated
	 * somewhat by the practice of creating dirs 0700 until the extract
	 * is done, but it would be nice if we could do more than that.
	 * People restoring critical file systems should be wary of
	 * other programs that might try to muck with files as they're
	 * being restored.
	 */
	/* Hopefully, the compiler will optimize this mess into a constant. */
	critical_flags = 0;
#ifdef SF_IMMUTABLE
	critical_flags |= SF_IMMUTABLE;
#endif
#ifdef UF_IMMUTABLE
	critical_flags |= UF_IMMUTABLE;
#endif
#ifdef SF_APPEND
	critical_flags |= SF_APPEND;
#endif
#ifdef UF_APPEND
	critical_flags |= UF_APPEND;
#endif
#ifdef EXT2_APPEND_FL
	critical_flags |= EXT2_APPEND_FL;
#endif
#ifdef EXT2_IMMUTABLE_FL
	critical_flags |= EXT2_IMMUTABLE_FL;
#endif

	if (flags & ARCHIVE_EXTRACT_FFLAGS) {
		archive_entry_fflags(entry, &set, &clear);

		/*
		 * The first test encourages the compiler to eliminate
		 * all of this if it's not necessary.
		 */
		if ((critical_flags != 0)  &&  (set & critical_flags)) {
			le = malloc(sizeof(struct fixup_entry));
			le->fixup = FIXUP_FFLAGS;
			le->next = extract->fixup_list;
			extract->fixup_list = le;
			le->name = strdup(archive_entry_pathname(entry));
			le->mode = archive_entry_mode(entry);
			le->fflags_set = set;
		} else {
			r = set_fflags(a, archive_entry_pathname(entry),
			    archive_entry_mode(entry), set, clear);
			if (r != ARCHIVE_OK)
				return (r);
		}
	}
	return (ARCHIVE_OK);
}

static int
set_fflags(struct archive *a, const char *name, mode_t mode,
    unsigned long set, unsigned long clear)
{
	struct extract *extract;
	int		 ret;
#ifdef LINUX
	int		 fd;
	int		 err;
	unsigned long newflags, oldflags;
#endif

	extract = a->extract;
	ret = ARCHIVE_OK;
	if (set == 0  && clear == 0)
		return (ret);

#ifdef HAVE_CHFLAGS
	(void)mode; /* UNUSED */
	/*
	 * XXX Is the stat here really necessary?  Or can I just use
	 * the 'set' flags directly?  In particular, I'm not sure
	 * about the correct approach if we're overwriting an existing
	 * file that already has flags on it. XXX
	 */
	if (stat(name, &extract->st) == 0) {
		extract->st.st_flags &= ~clear;
		extract->st.st_flags |= set;
		if (chflags(name, extract->pst->st_flags) != 0) {
			archive_set_error(a, errno,
			    "Failed to set file flags");
			ret = ARCHIVE_WARN;
		}
		extract->pst = &extract->st;
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
	if ((S_ISREG(mode) || S_ISDIR(mode)) &&
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

void
archive_read_extract_set_progress_callback(struct archive *a,
    void (*progress_func)(void *), void *user_data)
{
	a->extract_progress = progress_func;
	a->extract_progress_user_data = user_data;
}
