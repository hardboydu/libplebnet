/*-
 * Copyright (c) 2000 Poul-Henning Kamp and Dag-Erling Co�dan Sm�rgrav
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
 *      $FreeBSD$
 */

#include <sys/param.h>
#include <sys/sbuf.h>

#ifdef _KERNEL
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <machine/stdarg.h>
#else /* _KERNEL */
#include <stdarg.h>
#endif /* _KERNEL */

#ifdef _KERNEL
MALLOC_DEFINE(M_SBUF, "sbuf", "string buffers");
#define SBMALLOC(size)		malloc(size, M_SBUF, M_WAITOK)
#define SBFREE(buf)		free(buf, M_SBUF)
#else /* _KERNEL */
#define KASSERT(e, m)
#define SBMALLOC(size)		malloc(size)
#define SBFREE(buf)		free(buf)
#define min(x,y)		MIN(x,y)
#endif /* _KERNEL */

/*
 * Predicates
 */
#define SBUF_ISDYNAMIC(s)	((s)->s_flags & SBUF_DYNAMIC)
#define SBUF_ISDYNSTRUCT(s)	((s)->s_flags & SBUF_DYNSTRUCT)
#define SBUF_ISFINISHED(s)	((s)->s_flags & SBUF_FINISHED)
#define SBUF_HASOVERFLOWED(s)	((s)->s_flags & SBUF_OVERFLOWED)
#define SBUF_HASROOM(s)		((s)->s_len < (s)->s_size - 1)

/*
 * Set / clear flags
 */
#define SBUF_SETFLAG(s, f)	do { (s)->s_flags |= (f); } while (0)
#define SBUF_CLEARFLAG(s, f)	do { (s)->s_flags &= ~(f); } while (0)

/*
 * Debugging support
 */
#if defined(_KERNEL) && defined(INVARIANTS)
static void
_assert_sbuf_integrity(char *fun, struct sbuf *s)
{
	KASSERT(s != NULL,
	    ("%s called with a NULL sbuf pointer", fun));
	KASSERT(s->s_buf != NULL,
	    ("%s called with unitialized or corrupt sbuf", fun));
	KASSERT(s->s_len < s->s_size,
	    ("wrote past end of sbuf (%d >= %d)", s->s_len, s->s_size));
}

static void
_assert_sbuf_state(char *fun, struct sbuf *s, int state)
{
	KASSERT((s->s_flags & SBUF_FINISHED) == state,
	    ("%s called with %sfinished or corrupt sbuf", fun,
	    (state ? "un" : "")));
}
#define assert_sbuf_integrity(s) _assert_sbuf_integrity(__FUNCTION__, (s))
#define assert_sbuf_state(s, i)	 _assert_sbuf_state(__FUNCTION__, (s), (i))
#else /* _KERNEL && INVARIANTS */
#define assert_sbuf_integrity(s) do { } while (0)
#define assert_sbuf_state(s, i)	 do { } while (0)
#endif /* _KERNEL && INVARIANTS */

/*
 * Initialize an sbuf.
 * If buf is non-NULL, it points to a static or already-allocated string
 * big enough to hold at least length characters.
 */
struct sbuf *
sbuf_new(struct sbuf *s, char *buf, int length, int flags)
{
	KASSERT(length >= 0,
	    ("attempt to create an sbuf of negative length (%d)", length));
	KASSERT(flags == 0,
	    (__FUNCTION__ " called with non-zero flags"));

	if (s == NULL) {
		s = (struct sbuf *)SBMALLOC(sizeof *s);
		if (s == NULL)
			return (NULL);
		bzero(s, sizeof *s);
		SBUF_SETFLAG(s, SBUF_DYNSTRUCT);
	} else {
		bzero(s, sizeof *s);
	}
	s->s_size = length;
	if (buf) {
		s->s_buf = buf;
		return (s);
	}
	s->s_buf = (char *)SBMALLOC(s->s_size);
	if (s->s_buf == NULL) {
		if (SBUF_ISDYNSTRUCT(s))
			SBFREE(s);
		return (NULL);
	}
	SBUF_SETFLAG(s, SBUF_DYNAMIC);
	return (s);
}

/*
 * Clear an sbuf and reset its position
 */
void
sbuf_clear(struct sbuf *s)
{
	assert_sbuf_integrity(s);
	/* don't care if it's finished or not */

	SBUF_CLEARFLAG(s, SBUF_FINISHED);
	SBUF_CLEARFLAG(s, SBUF_OVERFLOWED);
	s->s_len = 0;
}

/*
 * Set the sbuf's position to an arbitrary value
 */
int
sbuf_setpos(struct sbuf *s, int pos)
{
	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);
	
	KASSERT(pos >= 0,
	    ("attempt to seek to a negative position (%d)", pos));
	KASSERT(pos < s->s_size,
	    ("attempt to seek past end of sbuf (%d >= %d)", pos, s->s_size));
	       
	if (pos < 0 || pos > s->s_len)
		return (-1);
	s->s_len = pos;
	return (0);
}

/*
 * Append a byte string to an sbuf.
 */
int
sbuf_bcat(struct sbuf *s, const char *str, size_t len)
{
	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);
	
	if (SBUF_HASOVERFLOWED(s))
		return (-1);
	
	while (len-- && SBUF_HASROOM(s))
		s->s_buf[s->s_len++] = *str++;
	if (len) {
		SBUF_SETFLAG(s, SBUF_OVERFLOWED);
		return (-1);
	}
	return (0);
}

#ifdef _KERNEL
/*
 * Copy a byte string from userland into an sbuf.
 */
int
sbuf_bcopyin(struct sbuf *s, const void *uaddr, size_t len)
{
	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);

	if (SBUF_HASOVERFLOWED(s))
		return (-1);

	if (len == 0)
		return (0);
	if (len > (s->s_size - s->s_len - 1))
		len = s->s_size - s->s_len - 1;
	switch (copyin(uaddr, s->s_buf + s->s_len, len)) {
	case ENAMETOOLONG:
		SBUF_SETFLAG(s, SBUF_OVERFLOWED);
		/* fall through */
	case 0:
		s->s_len += len;
		break;
	default:
		return (-1);	/* XXX */
	}
	
	return (0);
}
#endif

/*
 * Copy a byte string into an sbuf.
 */
int
sbuf_bcpy(struct sbuf *s, const char *str, size_t len)
{
	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);
	
	sbuf_clear(s);
	return (sbuf_bcat(s, str, len));
}

/*
 * Append a string to an sbuf.
 */
int
sbuf_cat(struct sbuf *s, const char *str)
{
	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);
	
	if (SBUF_HASOVERFLOWED(s))
		return (-1);
	
	while (*str && SBUF_HASROOM(s))
		s->s_buf[s->s_len++] = *str++;
	if (*str) {
		SBUF_SETFLAG(s, SBUF_OVERFLOWED);
		return (-1);
	}
	return (0);
}

#ifdef _KERNEL
/*
 * Copy a string from userland into an sbuf.
 */
int
sbuf_copyin(struct sbuf *s, const void *uaddr, size_t len)
{
	size_t done;
	
	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);

	if (SBUF_HASOVERFLOWED(s))
		return (-1);

	if (len == 0 || len > (s->s_size - s->s_len - 1))
		len = s->s_size - s->s_len - 1;
	switch (copyinstr(uaddr, s->s_buf + s->s_len, len + 1, &done)) {
	case ENAMETOOLONG:
		SBUF_SETFLAG(s, SBUF_OVERFLOWED);
		/* fall through */
	case 0:
		s->s_len += done - 1;
		break;
	default:
		return (-1);	/* XXX */
	}
	
	return (0);
}
#endif

/*
 * Copy a string into an sbuf.
 */
int
sbuf_cpy(struct sbuf *s, const char *str)
{
	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);
	
	sbuf_clear(s);
	return (sbuf_cat(s, str));
}

/*
 * Format the given arguments and append the resulting string to an sbuf.
 */
int
sbuf_printf(struct sbuf *s, char *fmt, ...)
{
	va_list ap;
	int len;

	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);
	
	KASSERT(fmt != NULL,
	    (__FUNCTION__ " called with a NULL format string"));
	
	if (SBUF_HASOVERFLOWED(s))
		return (-1);

	va_start(ap, fmt);
	len = vsnprintf(&s->s_buf[s->s_len], s->s_size - s->s_len, fmt, ap);
	va_end(ap);

	/*
	 * s->s_len is the length of the string, without the terminating nul.
	 * When updating s->s_len, we must subtract 1 from the length that
	 * we passed into vsnprintf() because that length includes the
	 * terminating nul.
	 *
	 * vsnprintf() returns the amount that would have been copied,
	 * given sufficient space, hence the min() calculation below.
	 */
	s->s_len += min(len, s->s_size - s->s_len - 1);
	if (!SBUF_HASROOM(s))
		SBUF_SETFLAG(s, SBUF_OVERFLOWED);

	KASSERT(s->s_len < s->s_size,
	    ("wrote past end of sbuf (%d >= %d)", s->s_len, s->s_size));

	if (SBUF_HASOVERFLOWED(s))
		return (-1);
	return (0);
}

/*
 * Append a character to an sbuf.
 */
int
sbuf_putc(struct sbuf *s, int c)
{
	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);
	
	if (SBUF_HASOVERFLOWED(s))
		return (-1);
	
	if (!SBUF_HASROOM(s)) {
		SBUF_SETFLAG(s, SBUF_OVERFLOWED);
		return (-1);
	}
	if (c != '\0')
	    s->s_buf[s->s_len++] = c;
	return (0);
}

/*
 * Check if an sbuf overflowed
 */
int
sbuf_overflowed(struct sbuf *s)
{
    return SBUF_HASOVERFLOWED(s);
}

/*
 * Finish off an sbuf.
 */
void
sbuf_finish(struct sbuf *s)
{
	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);
	
	s->s_buf[s->s_len] = '\0';
	SBUF_CLEARFLAG(s, SBUF_OVERFLOWED);
	SBUF_SETFLAG(s, SBUF_FINISHED);
}

/*
 * Return a pointer to the sbuf data.
 */
char *
sbuf_data(struct sbuf *s)
{
	assert_sbuf_integrity(s);
	assert_sbuf_state(s, SBUF_FINISHED);
	
	return s->s_buf;
}

/*
 * Return the length of the sbuf data.
 */
int
sbuf_len(struct sbuf *s)
{
	assert_sbuf_integrity(s);
	/* don't care if it's finished or not */
	
	if (SBUF_HASOVERFLOWED(s))
		return (-1);
	return s->s_len;
}

/*
 * Clear an sbuf, free its buffer if necessary.
 */
void
sbuf_delete(struct sbuf *s)
{
	assert_sbuf_integrity(s);
	/* don't care if it's finished or not */
	
	if (SBUF_ISDYNAMIC(s))
		SBFREE(s->s_buf);
	bzero(s, sizeof *s);
	if (SBUF_ISDYNSTRUCT(s))
		SBFREE(s);
}
