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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

#include "archive.h"
#include "archive_entry.h"
#include "archive_private.h"

struct pax {
	uint64_t	entry_bytes_remaining;
	uint64_t	entry_padding;
	struct archive_string	pax_header;
	char		written;
};

static void		 add_pax_attr(struct archive_string *, const char *key,
			     const char *value);
static void		 add_pax_attr_int(struct archive_string *,
			     const char *key, int64_t value);
static void		 add_pax_attr_time(struct archive_string *,
			     const char *key, int64_t sec,
			     unsigned long nanos);
static void		 add_pax_attr_w(struct archive_string *,
			     const char *key, const wchar_t *wvalue);
static int		 archive_write_pax_data(struct archive *,
			     const void *, size_t);
static int		 archive_write_pax_finish(struct archive *);
static int		 archive_write_pax_finish_entry(struct archive *);
static int		 archive_write_pax_header(struct archive *,
			     struct archive_entry *);
static char		*build_pax_attribute_name(const char *abbreviated,
			     struct archive_string *work);
static char		*build_ustar_entry_name(char *dest, const char *src);
static char		*format_int(char *dest, int64_t);
static int		 write_nulls(struct archive *, size_t);

/*
 * Set output format to 'restricted pax' format.
 *
 * This is the same as normal 'pax', but tries to suppress
 * the pax header whenever possible.  This is the default for
 * bsdtar, for instance.
 */
int
archive_write_set_format_pax_restricted(struct archive *a)
{
	int r;
	r = archive_write_set_format_pax(a);
	a->archive_format = ARCHIVE_FORMAT_TAR_PAX_RESTRICTED;
	a->archive_format_name = "restricted POSIX pax interchange";
	return (r);
}

/*
 * Set output format to 'pax' format.
 */
int
archive_write_set_format_pax(struct archive *a)
{
	struct pax *pax;

	if (a->format_finish != NULL)
		(a->format_finish)(a);

	pax = malloc(sizeof(*pax));
	if (pax == NULL) {
		archive_set_error(a, ENOMEM, "Can't allocate pax data");
		return (ARCHIVE_FATAL);
	}
	memset(pax, 0, sizeof(*pax));
	a->format_data = pax;

	a->pad_uncompressed = 1;
	a->format_write_header = archive_write_pax_header;
	a->format_write_data = archive_write_pax_data;
	a->format_finish = archive_write_pax_finish;
	a->format_finish_entry = archive_write_pax_finish_entry;
	a->archive_format = ARCHIVE_FORMAT_TAR_PAX_INTERCHANGE;
	a->archive_format_name = "POSIX pax interchange";
	return (ARCHIVE_OK);
}

/*
 * Note: This code assumes that 'nanos' has the same sign as 'sec',
 * which implies that sec=-1, nanos=200000000 represents -1.2 seconds
 * and not -0.8 seconds.  This is a pretty pedantic point, as we're
 * unlikely to encounter many real files created before Jan 1, 1970,
 * much less ones with timestamps recorded to sub-second resolution.
 */
static void
add_pax_attr_time(struct archive_string *as, const char *key,
    int64_t sec, unsigned long nanos)
{
	int digit, i;
	char *t;
	/*
	 * Note that each byte contributes fewer than 3 base-10
	 * digits, so this will always be big enough.
	 */
	char tmp[1 + 3*sizeof(sec) + 1 + 3*sizeof(nanos)];

	tmp[sizeof(tmp) - 1] = 0;
	t = tmp + sizeof(tmp) - 1;

	/* Skip trailing zeros in the fractional part. */
	for(digit = 0, i = 10; i > 0 && digit == 0; i--) {
		digit = nanos % 10;
		nanos /= 10;
	}

	/* Only format the fraction if it's non-zero. */
	if (i > 0) {
		while (i > 0) {
			*--t = "0123456789"[digit];
			digit = nanos % 10;
			nanos /= 10;
			i--;
		}
		*--t = '.';
	}
	t = format_int(t, sec);

	add_pax_attr(as, key, t);
}

static char *
format_int(char *t, int64_t i)
{
	int sign;

	if (i < 0) {
		sign = -1;
		i = -i;
	} else
		sign = 1;

	do {
		*--t = "0123456789"[i % 10];
	} while (i /= 10);
	if (sign < 0)
		*--t = '-';
	return (t);
}

static void
add_pax_attr_int(struct archive_string *as, const char *key, int64_t value)
{
	char tmp[1 + 3 * sizeof(value)];

	tmp[sizeof(tmp) - 1] = 0;
	add_pax_attr(as, key, format_int(tmp + sizeof(tmp) - 1, value));
}

static void
add_pax_attr_w(struct archive_string *as, const char *key, const wchar_t *wval)
{
	int	utf8len;
	const wchar_t *wp;
	wchar_t wc;
	char *utf8_value, *p;

	utf8len = 0;
	for (wp = wval; *wp != L'\0'; ) {
		wc = *wp++;
		if (wc <= 0) {
			/* Ignore negative values. */
		} else if (wc <= 0x7f)
			utf8len++;
		else if (wc <= 0x7ff)
			utf8len += 2;
		else if (wc <= 0xffff)
			utf8len += 3;
		else if (wc <= 0x1fffff)
			utf8len += 4;
		else if (wc <= 0x3ffffff)
			utf8len += 5;
		else
			utf8len += 6;
	}

	utf8_value = malloc(utf8len + 1);
	for (wp = wval, p = utf8_value; *wp != L'\0'; ) {
		wc = *wp++;
		if (wc <= 0) {
			/* Ignore negative values. */
		} else if (wc <= 0x7f) {
			*p++ = (char)wc;
		} else if (wc <= 0x7ff) {
			p[0] = 0xc0 | ((wc >> 6) & 0x1f);
			p[1] = 0x80 | (wc & 0x3f);
			p += 2;
		} else if (wc <= 0xffff) {
			p[0] = 0xe0 | ((wc >> 12) & 0x0f);
			p[1] = 0x80 | ((wc >> 6) & 0x3f);
			p[2] = 0x80 | (wc & 0x3f);
			p += 3;
		} else if (wc <= 0x1fffff) {
			p[0] = 0xf0 | ((wc >> 18) & 0x07);
			p[1] = 0x80 | ((wc >> 12) & 0x3f);
			p[2] = 0x80 | ((wc >> 6) & 0x3f);
			p[3] = 0x80 | (wc & 0x3f);
			p += 4;
		} else if (wc <= 0x3ffffff) {
			p[0] = 0xf8 | ((wc >> 24) & 0x03);
			p[1] = 0x80 | ((wc >> 18) & 0x3f);
			p[2] = 0x80 | ((wc >> 12) & 0x3f);
			p[3] = 0x80 | ((wc >> 6) & 0x3f);
			p[4] = 0x80 | (wc & 0x3f);
			p += 5;
		} else if (wc <= 0x7fffffff) {
			p[0] = 0xfc | ((wc >> 30) & 0x01);
			p[1] = 0x80 | ((wc >> 24) & 0x3f);
			p[1] = 0x80 | ((wc >> 18) & 0x3f);
			p[2] = 0x80 | ((wc >> 12) & 0x3f);
			p[3] = 0x80 | ((wc >> 6) & 0x3f);
			p[4] = 0x80 | (wc & 0x3f);
			p += 6;
		}
	}
	*p = '\0';
	add_pax_attr(as, key, utf8_value);
	free(utf8_value);
}

/*
 * Add a key/value attribute to the pax header.  This function handles
 * the length field and various other syntactic requirements.
 */
static void
add_pax_attr(struct archive_string *as, const char *key, const char *value)
{
	int digits, i, len, next_ten;
	char tmp[1 + 3 * sizeof(int)];	/* < 3 base-10 digits per byte */

	/*-
	 * PAX attributes have the following layout:
	 *     <len> <space> <key> <=> <value> <nl>
	 */
	len = 1 + strlen(key) + 1 + strlen(value) + 1;

	/*
	 * The <len> field includes the length of the <len> field, so
	 * computing the correct length is tricky.  I start by
	 * counting the number of base-10 digits in 'len' and
	 * computing the next higher power of 10.
	 */
	next_ten = 1;
	digits = 0;
	i = len;
	while (i > 0) {
		i = i / 10;
		digits++;
		next_ten = next_ten * 10;
	}
	/*
	 * For example, if string without the length field is 99
	 * chars, then adding the 2 digit length "99" will force the
	 * total length past 100, requiring an extra digit.  The next
	 * statement adjusts for this effect.
	 */
	if (len + digits >= next_ten)
		digits++;

	/* Now, we have the right length so we can build the line. */
	tmp[sizeof(tmp) - 1] = 0;	/* Null-terminate the work area. */
	archive_strcat(as, format_int(tmp + sizeof(tmp) - 1, len + digits));
	archive_strappend_char(as, ' ');
	archive_strcat(as, key);
	archive_strappend_char(as, '=');
	archive_strcat(as, value);
	archive_strappend_char(as, '\n');
}

/*
 * TODO: Consider adding 'comment' and 'charset' fields to
 * archive_entry so that clients can specify them.  Also, consider
 * adding generic key/value tags so clients can add arbitrary
 * key/value data.
 */
static int
archive_write_pax_header(struct archive *a,
    struct archive_entry *entry_original)
{
	struct archive_entry *entry_main;
	const char *linkname, *p;
	const wchar_t *wp, *wp2, *wname_start;
	int need_extension, oldstate, r, ret;
	struct pax *pax;
	const struct stat *st_main, *st_original;

	struct archive_string pax_entry_name;
	char paxbuff[512];
	char ustarbuff[512];
	char ustar_entry_name[256];

	archive_string_init(&pax_entry_name);
	need_extension = 0;
	pax = a->format_data;
	pax->written = 1;

	st_original = archive_entry_stat(entry_original);

	/* Make sure this is a type of entry that we can handle here */
	if (!archive_entry_hardlink(entry_original)) {
		switch (st_original->st_mode & S_IFMT) {
		case S_IFREG:
		case S_IFLNK:
		case S_IFCHR:
		case S_IFBLK:
		case S_IFDIR:
		case S_IFIFO:
			break;
		case S_IFSOCK:
			archive_set_error(a, ARCHIVE_ERRNO_FILE_FORMAT,
			    "tar format cannot archive socket");
			return (ARCHIVE_WARN);
		default:
			archive_set_error(a, ARCHIVE_ERRNO_FILE_FORMAT,
			    "tar format cannot archive this");
			return (ARCHIVE_WARN);
		}
	}

	/* Copy entry so we can modify it as needed. */
	entry_main = archive_entry_clone(entry_original);
	archive_string_empty(&(pax->pax_header)); /* Blank our work area. */
	st_main = archive_entry_stat(entry_main);

	/*
	 * Determining whether or not the name is too big is ugly
	 * because of the rules for dividing names between 'name' and
	 * 'prefix' fields.  Here, I pick out the longest possible
	 * suffix, then test whether the remaining prefix is too long.
	 */
	wp = archive_entry_pathname_w(entry_main);
	p = archive_entry_pathname(entry_main);
	if (wcslen(wp) <= 100)	/* Short enough for just 'name' field */
		wname_start = wp;	/* Record a zero-length prefix */
	else
		/* Find the largest suffix that fits in 'name' field. */
		wname_start = wcschr(wp + wcslen(wp) - 100 - 1, '/');

	/* Find non-ASCII character, if any. */
	wp2 = wp;
	while (*wp2 != L'\0' && *wp2 < 128)
		wp2++;

	/*
	 * If name is too long, or has non-ASCII characters, add
	 * 'path' to pax extended attrs.
	 */
	if (wname_start == NULL || wname_start - wp > 155 ||
	    *wp2 != L'\0') {
		add_pax_attr_w(&(pax->pax_header), "path", wp);
		archive_entry_set_pathname(entry_main,
		    build_ustar_entry_name(ustar_entry_name, p));
		need_extension = 1;
	}

	/* If link name is too long, add 'linkpath' to pax extended attrs. */
	linkname = archive_entry_hardlink(entry_main);
	if (linkname == NULL)
		linkname = archive_entry_symlink(entry_main);

	if (linkname != NULL && strlen(linkname) > 100) {
		add_pax_attr(&(pax->pax_header), "linkpath", linkname);
		if (archive_entry_hardlink(entry_main))
			archive_entry_set_hardlink(entry_main,
			    "././@LongHardLink");
		else
			archive_entry_set_symlink(entry_main,
			    "././@LongSymLink");
		need_extension = 1;
	}

	/* If file size is too large, add 'size' to pax extended attrs. */
	if (st_main->st_size >= (1 << 30)) {
		add_pax_attr_int(&(pax->pax_header), "size", st_main->st_size);
		need_extension = 1;
	}

	/* If numeric GID is too large, add 'gid' to pax extended attrs. */
	if (st_main->st_gid >= (1 << 20)) {
		add_pax_attr_int(&(pax->pax_header), "gid", st_main->st_gid);
		need_extension = 1;
	}

	/* If group name is too large, add 'gname' to pax extended attrs. */
	/* TODO: If gname has non-ASCII characters, use pax attribute. */
	p = archive_entry_gname(entry_main);
	if (p != NULL && strlen(p) > 31) {
		add_pax_attr(&(pax->pax_header), "gname", p);
		archive_entry_set_gname(entry_main, NULL);
		need_extension = 1;
	}

	/* If numeric UID is too large, add 'uid' to pax extended attrs. */
	if (st_main->st_uid >= (1 << 20)) {
		add_pax_attr_int(&(pax->pax_header), "uid", st_main->st_uid);
		need_extension = 1;
	}

	/* If user name is too large, add 'uname' to pax extended attrs. */
	/* TODO: If uname has non-ASCII characters, use pax attribute. */
	p = archive_entry_uname(entry_main);
	if (p != NULL && strlen(p) > 31) {
		add_pax_attr(&(pax->pax_header), "uname", p);
		archive_entry_set_uname(entry_main, NULL);
		need_extension = 1;
	}

	/*
	 * POSIX/SUSv3 doesn't provide a standard key for large device
	 * numbers.  I use the same keys here that Joerg Schilling used for
	 * 'star.'  No doubt, other implementations use other keys.  Note that
	 * there's no reason we can't write the same information into a number
	 * of different keys.
	 *
	 * Of course, this is only needed for block or char device entries.
	 */
	if (S_ISBLK(st_main->st_mode) ||
	    S_ISCHR(st_main->st_mode)) {
		/*
		 * If devmajor is too large, add 'SCHILY.devmajor' to
		 * extended attributes.
		 */
		dev_t devmajor, devminor;
		devmajor = major(st_main->st_rdev);
		devminor = minor(st_main->st_rdev);
		if (devmajor >= (1 << 18)) {
			add_pax_attr_int(&(pax->pax_header), "SCHILY.devmajor",
			    devmajor);
			archive_entry_set_devmajor(entry_main, (1 << 18) - 1);
			need_extension = 1;
		}

		/*
		 * If devminor is too large, add 'SCHILY.devminor' to
		 * extended attributes.
		 */
		if (devminor >= (1 << 18)) {
			add_pax_attr_int(&(pax->pax_header), "SCHILY.devminor",
			    devminor);
			archive_entry_set_devminor(entry_main, (1 << 18) - 1);
			need_extension = 1;
		}
	}

	/*
	 * Technically, the mtime field in the ustar header can
	 * support 33 bits, but many platforms use signed 32-bit time
	 * values.  The cutoff of 0x7fffffff here is a compromise.
	 * Yes, this check is duplicated just below; this helps to
	 * avoid writing an mtime attribute just to handle a
	 * high-resolution timestamp in "restricted pax" mode.
	 */
	if (!need_extension &&
	    ((st_main->st_mtime < 0) || (st_main->st_mtime >= 0x7fffffff)))
		need_extension = 1;

	/* If there are non-trivial ACL entries, we need an extension. */
	if (!need_extension && archive_entry_acl_count(entry_original,
		ARCHIVE_ENTRY_ACL_TYPE_ACCESS) > 0)
		need_extension = 1;

	/* If there are non-trivial ACL entries, we need an extension. */
	if (!need_extension && archive_entry_acl_count(entry_original,
		ARCHIVE_ENTRY_ACL_TYPE_DEFAULT) > 0)
		need_extension = 1;

	/*
	 * The following items are handled differently in "pax
	 * restricted" format.  In particular, in "pax restricted"
	 * format they won't be added unless need_extension is
	 * already set (we're already generated an extended header, so
	 * may as well include these).
	 */
	if (a->archive_format != ARCHIVE_FORMAT_TAR_PAX_RESTRICTED ||
	    need_extension) {

		if (st_main->st_mtime < 0  ||
		    st_main->st_mtime >= 0x7fffffff  ||
		    st_main->st_mtimespec.tv_nsec != 0)
			add_pax_attr_time(&(pax->pax_header), "mtime",
			    st_main->st_mtime, st_main->st_mtimespec.tv_nsec);

		if (st_main->st_ctimespec.tv_nsec != 0 ||
		    st_main->st_ctime != 0)
			add_pax_attr_time(&(pax->pax_header), "ctime",
			    st_main->st_ctime, st_main->st_ctimespec.tv_nsec);

		if (st_main->st_atimespec.tv_nsec != 0 ||
		    st_main->st_atime != 0)
			add_pax_attr_time(&(pax->pax_header), "atime",
			    st_main->st_atime, st_main->st_atimespec.tv_nsec);

		/* I use a star-compatible file flag attribute. */
		p = archive_entry_fflags(entry_main);
		if (p != NULL  &&  *p != '\0')
			add_pax_attr(&(pax->pax_header), "SCHILY.fflags", p);

		/* I use star-compatible ACL attributes. */
		wp = archive_entry_acl_text_w(entry_original,
		    ARCHIVE_ENTRY_ACL_TYPE_ACCESS |
		    ARCHIVE_ENTRY_ACL_STYLE_EXTRA_ID);
		if (wp != NULL && *wp != L'\0')
			add_pax_attr_w(&(pax->pax_header),
			    "SCHILY.acl.access", wp);
		wp = archive_entry_acl_text_w(entry_original,
		    ARCHIVE_ENTRY_ACL_TYPE_DEFAULT |
		    ARCHIVE_ENTRY_ACL_STYLE_EXTRA_ID);
		if (wp != NULL && *wp != L'\0')
			add_pax_attr_w(&(pax->pax_header),
			    "SCHILY.acl.default", wp);

		/* Include star-compatible metadata info. */
		add_pax_attr_int(&(pax->pax_header), "SCHILY.dev",
		    st_main->st_dev);
		add_pax_attr_int(&(pax->pax_header), "SCHILY.ino",
		    st_main->st_ino);
		add_pax_attr_int(&(pax->pax_header), "SCHILY.nlink",
		    st_main->st_nlink);
	}

	/* Only regular files have data. */
	if (!S_ISREG(archive_entry_mode(entry_main)))
		archive_entry_set_size(entry_main, 0);

	/*
	 * Pax-restricted does not store data for hardlinks, in order
	 * to improve compatibility with ustar.
	 */
	if (a->archive_format != ARCHIVE_FORMAT_TAR_PAX_INTERCHANGE &&
	    archive_entry_hardlink(entry_main) != NULL)
		archive_entry_set_size(entry_main, 0);

	/*
	 * XXX Full pax interchange format does permit a hardlink
	 * entry to have data associated with it.  I'm not supporting
	 * that here because the client expects me to tell them whether
	 * or not this format expects data for hardlinks.  If I
	 * don't check here, then every pax archive will end up with
	 * duplicated data for hardlinks.  Someday, there may be
	 * need to select this behavior, in which case the following
	 * will need to be revisited. XXX
	 */
	if (archive_entry_hardlink(entry_main) != NULL)
		archive_entry_set_size(entry_main, 0);

	/* Format 'ustar' header for main entry. */
	/* We don't care if this returns an error. */
	__archive_write_format_header_ustar(a, ustarbuff, entry_main, -1);

	/* If we built any extended attributes, write that entry first. */
	ret = 0;
	if (archive_strlen(&(pax->pax_header)) > 0) {
		struct stat st;
		struct archive_entry *pax_attr_entry;
		const char *pax_attr_name;

		memset(&st, 0, sizeof(st));
		pax_attr_entry = archive_entry_new();
		p = archive_entry_pathname(entry_main);
		pax_attr_name = build_pax_attribute_name(p, &pax_entry_name);

		archive_entry_set_pathname(pax_attr_entry, pax_attr_name);
		st.st_size = archive_strlen(&(pax->pax_header));
		st.st_uid = st_main->st_uid;
		st.st_gid = st_main->st_gid;
		st.st_mode = st_main->st_mode;
		archive_entry_copy_stat(pax_attr_entry, &st);

		archive_entry_set_uname(pax_attr_entry,
		    archive_entry_uname(entry_main));
		archive_entry_set_gname(pax_attr_entry,
		    archive_entry_gname(entry_main));

		ret = __archive_write_format_header_ustar(a, paxbuff,
		    pax_attr_entry, 'x');

		archive_entry_free(pax_attr_entry);
		free(pax_entry_name.s);

		/* Note that the 'x' header shouldn't ever fail to format */
		if (ret != 0) {
			const char *msg = "archive_write_header_pax: "
			    "'x' header failed?!  This can't happen.\n";
			write(2, msg, strlen(msg));
			exit(1);
		}
		r = (a->compression_write)(a, paxbuff, 512);
		if (r < 512) {
			pax->entry_bytes_remaining = 0;
			pax->entry_padding = 0;
			return (ARCHIVE_FATAL);
		}

		pax->entry_bytes_remaining = archive_strlen(&(pax->pax_header));
		pax->entry_padding = 0x1ff & (- pax->entry_bytes_remaining);

		oldstate = a->state;
		a->state = ARCHIVE_STATE_DATA;
		r = archive_write_data(a, pax->pax_header.s,
		    archive_strlen(&(pax->pax_header)));
		a->state = oldstate;
		if (r < (int)archive_strlen(&(pax->pax_header))) {
			/* If a write fails, we're pretty much toast. */
			return (ARCHIVE_FATAL);
		}

		archive_write_pax_finish_entry(a);
	}

	/* Write the header for main entry. */
	r = (a->compression_write)(a, ustarbuff, 512);
	if (ret != ARCHIVE_OK)
		ret = (r < 512) ? ARCHIVE_FATAL : ARCHIVE_OK;

	/*
	 * Inform the client of the on-disk size we're using, so
	 * they can avoid unnecessarily writing a body for something
	 * that we're just going to ignore.
	 */
	archive_entry_set_size(entry_original, archive_entry_size(entry_main));
	pax->entry_bytes_remaining = archive_entry_size(entry_main);
	pax->entry_padding = 0x1ff & (- pax->entry_bytes_remaining);
	archive_entry_free(entry_main);

	return (ret);
}

/*
 * We need a valid name for the regular 'ustar' entry.  This routine
 * tries to hack something more-or-less reasonable.
 */
static char *
build_ustar_entry_name(char *dest, const char *src)
{
	const char *basename, *break_point, *prefix;
	int basename_length, dirname_length, prefix_length;

	prefix = src;
	basename = strrchr(src, '/');
	if (basename == NULL) {
		basename = src;
		prefix_length = 0;
		basename_length = strlen(basename);
		if (basename_length > 100)
			basename_length = 100;
	} else {
		basename_length = strlen(basename);
		if (basename_length > 100)
			basename_length = 100;
		dirname_length = basename - src;

		break_point =
		    strchr(src + dirname_length + basename_length - 101, '/');
		prefix_length = break_point - prefix - 1;
		while (prefix_length > 155) {
			prefix = strchr(prefix, '/') + 1; /* Drop 1st dir. */
			prefix_length = break_point - prefix - 1;
		}
	}

	/* The OpenBSD strlcpy function is safer, but less portable. */
	/* Rather than maintain two versions, just use the strncpy version. */
	strncpy(dest, prefix, basename - prefix + basename_length);
	dest[basename - prefix + basename_length] = '\0';

	return (dest);
}

/*
 * The ustar header for the pax extended attributes must have a
 * reasonable name:  SUSv3 suggests 'dirname'/PaxHeaders/'basename'
 *
 * Joerg Schiling has argued that this is unnecessary because, in practice,
 * if the pax extended attributes get extracted as regular files, noone is
 * going to bother reading those attributes to manually restore them.
 * This is a tempting argument, but I'm not entirely convinced.
 *
 * Of course, adding "PaxHeaders/" might force the name to be too big.
 * Here, I start from the (possibly already-trimmed) name used in the
 * main ustar header and delete some additional early path elements to
 * fit in the extra "PaxHeader/" part.
 */
static char *
build_pax_attribute_name(const char *abbreviated, /* ustar-compat name */
    struct archive_string *work)
{
	const char *basename, *break_point, *prefix;
	int prefix_length, suffix_length;

	/*
	 * This is much simpler because I know that "abbreviated" is
	 * already small enough; I just need to determine if it needs
	 * any further trimming to fit the "PaxHeader/" portion.
	 */

	/* Identify the final prefix and suffix portions. */
	prefix = abbreviated;	/* First guess: prefix starts at beginning */
	if (strlen(abbreviated) > 100) {
		break_point = strchr(prefix + strlen(prefix) - 101, '/');
		prefix_length = break_point - prefix - 1;
		suffix_length = strlen(break_point + 1);
		/*
		 * The next loop keeps trimming until "/PaxHeader/" can
		 * be added to either the prefix or the suffix.
		 */
		while (prefix_length > 144 && suffix_length > 89) {
			prefix = strchr(prefix, '/') + 1; /* Drop 1st dir. */
			prefix_length = break_point - prefix - 1;
		}
	}

	archive_string_empty(work);
	basename = strrchr(prefix, '/');
	if (basename == NULL) {
		archive_strcpy(work, "PaxHeader/");
		archive_strcat(work, prefix);
	} else {
		basename++;
		archive_strncpy(work, prefix, basename - prefix);
		archive_strcat(work, "PaxHeader/");
		archive_strcat(work, basename);
	}

	return (work->s);
}

/* Write two null blocks for the end of archive */
static int
archive_write_pax_finish(struct archive *a)
{
	struct pax *pax;
	pax = a->format_data;
	if (pax->written && a->compression_write != NULL)
		return (write_nulls(a, 512 * 2));
	free(pax);
	a->format_data = NULL;
	return (ARCHIVE_OK);
}

static int
archive_write_pax_finish_entry(struct archive *a)
{
	struct pax *pax;
	int ret;

	pax = a->format_data;
	ret = write_nulls(a, pax->entry_bytes_remaining + pax->entry_padding);
	pax->entry_bytes_remaining = pax->entry_padding = 0;
	return (ret);
}

static int
write_nulls(struct archive *a, size_t padding)
{
	int ret, to_write;

	while (padding > 0) {
		to_write = padding < a->null_length ? padding : a->null_length;
		ret = (a->compression_write)(a, a->nulls, to_write);
		if (ret <= 0)
			return (ARCHIVE_FATAL);
		padding -= ret;
	}
	return (ARCHIVE_OK);
}

static int
archive_write_pax_data(struct archive *a, const void *buff, size_t s)
{
	struct pax *pax;
	int ret;

	pax = a->format_data;
	pax->written = 1;
	if (s > pax->entry_bytes_remaining)
		s = pax->entry_bytes_remaining;

	ret = (a->compression_write)(a, buff, s);
	pax->entry_bytes_remaining -= s;
	return (ret);
}
