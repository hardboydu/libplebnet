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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "archive.h"
#include "archive_entry.h"
#include "archive_private.h"

struct shar {
	int			 dump;
	int			 end_of_line;
	struct archive_entry	*entry;
	int			 has_data;
	char			*last_dir;
	char			 outbuff[1024];
	size_t			 outbytes;
	size_t			 outpos;
	int			 uuavail;
	char			 uubuffer[3];
	int			 wrote_header;
	char			*work;
	size_t			 work_len;
};

static int	archive_write_shar_finish(struct archive *);
static int	archive_write_shar_header(struct archive *,
		    struct archive_entry *);
static int	archive_write_shar_data_sed(struct archive *,
		    const void * buff, size_t);
static int	archive_write_shar_data_uuencode(struct archive *,
		    const void * buff, size_t);
static int	archive_write_shar_finish_entry(struct archive *);
static int	shar_printf(struct archive *, const char *fmt, ...);
static void	uuencode_group(struct shar *);

static int
shar_printf(struct archive *a, const char *fmt, ...)
{
	struct shar *shar;
	va_list ap;
	int required;
	int ret;

	shar = a->format_data;
	if (shar->work_len <= 0) {
		shar->work_len = 1024;
		shar->work = malloc(shar->work_len);
	}

	va_start(ap, fmt);
	required = vsnprintf(shar->work, shar->work_len, fmt, ap);
	if ((size_t)required >= shar->work_len) {
		shar->work_len = required + 256;
		realloc(shar->work, shar->work_len);
		required = vsnprintf(shar->work, shar->work_len, fmt, ap);
	}
	ret = ((a->compression_write)(a, shar->work, strlen(shar->work)));
	va_end(ap);
	return (ret);
}

/*
 * Set output format to 'shar' format.
 */
int
archive_write_set_format_shar(struct archive *a)
{
	struct shar *shar;

	/* If someone else was already registered, unregister them. */
	if (a->format_finish != NULL)
		(a->format_finish)(a);

	shar = malloc(sizeof(*shar));
	if (shar == NULL) {
		archive_set_error(a, ENOMEM, "Can't allocate shar data");
		return (ARCHIVE_FATAL);
	}
	memset(shar, 0, sizeof(*shar));
	a->format_data = shar;

	a->pad_uncompressed = 0;
	a->format_write_header = archive_write_shar_header;
	a->format_finish = archive_write_shar_finish;
	a->format_write_data = archive_write_shar_data_sed;
	a->format_finish_entry = archive_write_shar_finish_entry;
	a->archive_format = ARCHIVE_FORMAT_SHAR_BASE;
	a->archive_format_name = "shar";
	return (ARCHIVE_OK);
}

/*
 * An alternate 'shar' that uses uudecode instead of 'sed' to encode
 * file contents and can therefore be used to archive binary files.
 * In addition, this variant also attempts to restore ownership, file modes,
 * and other extended file information.
 */
int
archive_write_set_format_shar_dump(struct archive *a)
{
	archive_write_set_format_shar(a);
	a->format_write_data = archive_write_shar_data_uuencode;
	a->archive_format = ARCHIVE_FORMAT_SHAR_DUMP;
	a->archive_format_name = "shar dump";
	return (ARCHIVE_OK);
}

static int
archive_write_shar_header(struct archive *a, struct archive_entry *entry)
{
	const char *linkname;
	const char *name;
	char *p, *pp;
	struct shar *shar;
	const struct stat *st;

	shar = a->format_data;
	if (!shar->wrote_header) {
		shar_printf(a, "#!/bin/sh\n");
		shar_printf(a, "# This is a shar archive\n");
		shar->wrote_header = 1;
	}

	/* Save the entry for the closing. */
	if (shar->entry)
		archive_entry_free(shar->entry);
	shar->entry = archive_entry_clone(entry);
	name = archive_entry_pathname(entry);
	st = archive_entry_stat(entry);

	/* Handle some preparatory issues. */
	switch(st->st_mode & S_IFMT) {
	case S_IFREG:
		/* Only regular files have non-zero size. */
		break;
	case S_IFDIR:
	case S_IFIFO:
	case S_IFCHR:
	case S_IFBLK:
		/* All other file types have zero size in the archive. */
		archive_entry_set_size(entry, 0);
		break;
	default:
		archive_entry_set_size(entry, 0);
		if (archive_entry_hardlink(entry) == NULL &&
		    archive_entry_symlink(entry) == NULL) {
			archive_set_error(a, ARCHIVE_ERRNO_MISC,
			    "shar format cannot archive this");
			return (ARCHIVE_WARN);
		}
	}

	/* Stock preparation for all file types. */
	shar_printf(a, "echo x %s\n", name);

	if (!S_ISDIR(st->st_mode)) {
		/* Try to create the dir. */
		p = strdup(name);
		pp = strrchr(p, '/');
		if (pp != NULL)
			*pp = '\0';

		if (shar->last_dir == NULL) {
			shar_printf(a, "mkdir -p %s > /dev/null 2>&1\n", p);
			shar->last_dir = p;
		} else if (strcmp(p, shar->last_dir) == 0) {
			/* We've already created this exact dir. */
			free(p);
		} else if (strlen(p) < strlen(shar->last_dir) &&
		    strncmp(p, shar->last_dir, strlen(p)) == 0) {
			/* We've already created a subdir. */
			free(p);
		} else {
			shar_printf(a, "mkdir -p %s > /dev/null 2>&1\n", p);
			free(shar->last_dir);
			shar->last_dir = p;
		}
	}

	/* Handle file-type specific issues. */
	shar->has_data = 0;
	if ((linkname = archive_entry_hardlink(entry)) != NULL)
		shar_printf(a, "ln -f %s %s\n", linkname, name);
	else if ((linkname = archive_entry_symlink(entry)) != NULL)
		shar_printf(a, "ln -fs %s %s\n", linkname, name);
	else {
		switch(st->st_mode & S_IFMT) {
		case S_IFREG:
			if (archive_entry_size(entry) == 0)
				shar_printf(a, "touch %s\n", name);
			else {
				if (shar->dump) {
					shar_printf(a,
					    "uudecode -o %s << 'SHAR_END'\n",
					    name);
					shar_printf(a, "begin %o %s\n",
					    archive_entry_mode(entry) & 0777,
					    name);
				} else
					shar_printf(a,
					    "sed 's/^X//' > %s << 'SHAR_END'\n",
					    name);
				shar->has_data = 1;
				shar->end_of_line = 1;
				shar->outpos = 0;
				shar->outbytes = 0;
			}
			break;
		case S_IFDIR:
			shar_printf(a, "mkdir -p %s > /dev/null 2>&1\n", name);
			/* Record that we just created this directory. */
			if (shar->last_dir != NULL)
				free(shar->last_dir);

			shar->last_dir = strdup(name);
			/* Trim a trailing '/'. */
			pp = strrchr(shar->last_dir, '/');
			if (pp != NULL && pp[1] == '\0')
				*pp = '\0';
			/*
			 * TODO: Put dir name/mode on a list to be fixed
			 * up at end of archive.
			 */
			break;
		case S_IFIFO:
			shar_printf(a, "mkfifo %s\n", name);
			break;
		case S_IFCHR:
			shar_printf(a, "mknod %s c %d %d\n", name,
			    archive_entry_devmajor(entry),
			    archive_entry_devminor(entry));
			break;
		case S_IFBLK:
			shar_printf(a, "mknod %s b %d %d\n", name,
			    archive_entry_devmajor(entry),
			    archive_entry_devminor(entry));
			break;
		default:
			return (ARCHIVE_WARN);
		}
	}

	return (ARCHIVE_OK);
}

/* XXX TODO: This could be more efficient XXX */
static int
archive_write_shar_data_sed(struct archive *a, const void *buff, size_t length)
{
	struct shar *shar;
	const char *src;
	size_t n;

	shar = a->format_data;
	if (!shar->has_data)
		return (0);

	src = buff;
	n = length;
	shar->outpos = 0;
	while (n-- > 0) {
		if (shar->end_of_line) {
			shar->outbuff[shar->outpos++] = 'X';
			shar->end_of_line = 0;
		}
		if (*src == '\n')
			shar->end_of_line = 1;
		shar->outbuff[shar->outpos++] = *src++;

		if (shar->outpos > sizeof(shar->outbuff) - 2) {
			(a->compression_write)(a, shar->outbuff, shar->outpos);
			shar->outpos = 0;
		}
	}

	if (shar->outpos > 0)
		(a->compression_write)(a, shar->outbuff, shar->outpos);
	return (length);
}

#define	UUENC(c)	(((c)!=0) ? ((c) & 077) + ' ': '`')

/* XXX This could be a lot more efficient. XXX */
static void
uuencode_group(struct shar *shar)
{
	int	t;

	t = 0;
	if (shar->uuavail > 0)
		t = 0xff0000 & (shar->uubuffer[0] << 16);
	if (shar->uuavail > 1)
		t |= 0x00ff00 & (shar->uubuffer[1] << 8);
	if (shar->uuavail > 2)
		t |= 0x0000ff & (shar->uubuffer[2]);
	shar->outbuff[shar->outpos++] = UUENC( 0x3f & (t>>18) );
	shar->outbuff[shar->outpos++] = UUENC( 0x3f & (t>>12) );
	shar->outbuff[shar->outpos++] = UUENC( 0x3f & (t>>6) );
	shar->outbuff[shar->outpos++] = UUENC( 0x3f & (t) );
	shar->uuavail = 0;
	shar->outbytes += shar->uuavail;
	shar->outbuff[shar->outpos] = 0;
}

static int
archive_write_shar_data_uuencode(struct archive *a, const void *buff,
    size_t length)
{
	struct shar *shar;
	const char *src;
	size_t n;

	shar = a->format_data;
	if (!shar->has_data)
		return (ARCHIVE_OK);
	src = buff;
	n = length;
	while (n-- > 0) {
		if (shar->uuavail == 3)
			uuencode_group(shar);
		if (shar->outpos >= 60) {
			shar_printf(a, "%c%s\n", UUENC(shar->outbytes),
			    shar->outbuff);
			shar->outpos = 0;
			shar->outbytes = 0;
		}

		shar->uubuffer[shar->uuavail++] = *src++;
		shar->outbytes++;
	}
	return (length);
}

static int
archive_write_shar_finish_entry(struct archive *a)
{
	const char *g, *p, *u;
	struct shar *shar;

	shar = a->format_data;
	if (shar->entry == NULL)
		return (0);

	if (shar->dump) {
		/* Finish uuencoded data. */
		if (shar->has_data) {
			if (shar->uuavail > 0)
				uuencode_group(shar);
			if (shar->outpos > 0) {
				shar_printf(a, "%c%s\n", UUENC(shar->outbytes),
				    shar->outbuff);
				shar->outpos = 0;
				shar->uuavail = 0;
				shar->outbytes = 0;
			}
			shar_printf(a, "%c\n", UUENC(0));
			shar_printf(a, "end\n", UUENC(0));
			shar_printf(a, "SHAR_END\n");
		}
		/* Restore file mode, owner, flags. */
		/*
		 * TODO: Don't immediately restore mode for
		 * directories; defer that to end of script.
		 */
		shar_printf(a, "chmod %o %s\n",
		    archive_entry_mode(shar->entry) & 07777,
		    archive_entry_pathname(shar->entry));

		u = archive_entry_uname(shar->entry);
		g = archive_entry_gname(shar->entry);
		if (u != NULL || g != NULL) {
			shar_printf(a, "chown %s%s%s %s\n",
			    (u != NULL) ? u : "",
			    (g != NULL) ? ":" : "", (g != NULL) ? g : "",
			    archive_entry_pathname(shar->entry));
		}

		if ((p = archive_entry_fflags(shar->entry)) != NULL) {
			shar_printf(a, "chflags %s %s\n", p,
			    archive_entry_pathname(shar->entry));
		}

		/* TODO: restore ACLs */

	} else {
		if (shar->has_data) {
			/* Finish sed-encoded data:  ensure last line ends. */
			if (!shar->end_of_line)
				shar_printf(a, "\n");
			shar_printf(a, "SHAR_END\n");
		}
	}

	archive_entry_free(shar->entry);
	shar->entry = NULL;
	return (0);
}

static int
archive_write_shar_finish(struct archive *a)
{
	struct shar *shar;

	/*
	 * TODO: Accumulate list of directory names/modes and
	 * fix them all up at end-of-archive.
	 */

	shar = a->format_data;

	/*
	 * Only write the end-of-archive markers if the archive was
	 * actually started.  This avoids problems if someone sets
	 * shar format, then sets another format (which would invoke
	 * shar_finish to free the format-specific data).
	 */
	if (shar->wrote_header) {
		shar_printf(a, "exit\n");
		/* Shar output is never padded. */
		archive_write_set_bytes_in_last_block(a, 1);
		/*
		 * TODO: shar should also suppress padding of
		 * uncompressed data within gzip/bzip2 streams.
		 */
	}
	if (shar->entry != NULL)
		archive_entry_free(shar->entry);
	if (shar->last_dir != NULL)
		free(shar->last_dir);
	if (shar->work != NULL)
		free(shar->work);
	free(shar);
	a->format_data = NULL;
	return (ARCHIVE_OK);
}
