/*
 * Copyright (c) 1999 Cameron Grant <gandalf@vilnya.demon.co.uk>
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
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

#include <dev/sound/pcm/sound.h>

#include "feeder_if.h"

MALLOC_DEFINE(M_FEEDER, "feeder", "pcm feeder");

#define MAXFEEDERS 	256
#undef FEEDER_DEBUG

struct feedertab_entry {
	SLIST_ENTRY(feedertab_entry) link;
	struct feeder_class *feederclass;
	struct pcm_feederdesc *desc;

	int idx;
};
static SLIST_HEAD(, feedertab_entry) feedertab;

/*****************************************************************************/

void
feeder_register(void *p)
{
	struct feeder_class *fc = p;
	struct feedertab_entry *fte;
	static int feedercnt = 0;
	int i;

	if (feedercnt == 0) {
		if (fc->desc)
			panic("FIRST FEEDER NOT ROOT: %s\n", fc->name);
		SLIST_INIT(&feedertab);
		fte = malloc(sizeof(*fte), M_FEEDER, M_WAITOK | M_ZERO);
		fte->feederclass = fc;
		fte->desc = NULL;
		fte->idx = feedercnt;
		SLIST_INSERT_HEAD(&feedertab, fte, link);
		feedercnt++;
		return;
	}

	i = 0;
	while ((feedercnt < MAXFEEDERS) && (fc->desc[i].type > 0)) {
		fte = malloc(sizeof(*fte), M_FEEDER, M_WAITOK | M_ZERO);
		fte->feederclass = fc;
		fte->desc = &fc->desc[i];
		fte->idx = feedercnt;
		fte->desc->idx = feedercnt;
		SLIST_INSERT_HEAD(&feedertab, fte, link);
		i++;
	}
	feedercnt++;
	if (feedercnt >= MAXFEEDERS)
		printf("MAXFEEDERS exceeded\n");
}

static void
feeder_unregisterall(void *p)
{
	struct feedertab_entry *fte, *next;

	next = SLIST_FIRST(&feedertab);
	while (next != NULL) {
		fte = next;
		next = SLIST_NEXT(fte, link);
		free(fte, M_FEEDER);
	}
}

static int
cmpdesc(struct pcm_feederdesc *n, struct pcm_feederdesc *m)
{
	return ((n->type == m->type) &&
		((n->in == 0) || (n->in == m->in)) &&
		((n->out == 0) || (n->out == m->out)) &&
		(n->flags == m->flags));
}

static void
feeder_destroy(pcm_feeder *f)
{
	FEEDER_FREE(f);
	free(f->desc, M_FEEDER);
	kobj_delete((kobj_t)f, M_FEEDER);
}

static pcm_feeder *
feeder_create(struct feeder_class *fc, struct pcm_feederdesc *desc)
{
	pcm_feeder *f;
	int err;

	f = (pcm_feeder *)kobj_create((kobj_class_t)fc, M_FEEDER, M_WAITOK | M_ZERO);
	f->align = fc->align;
	f->desc = malloc(sizeof(*(f->desc)), M_FEEDER, M_WAITOK | M_ZERO);
	if (desc)
		*(f->desc) = *desc;
	else {
		f->desc->type = FEEDER_ROOT;
		f->desc->in = 0;
		f->desc->out = 0;
		f->desc->flags = 0;
		f->desc->idx = 0;
	}
	f->data = fc->data;
	f->source = NULL;
	err = FEEDER_INIT(f);
	if (err) {
		feeder_destroy(f);
		return NULL;
	} else
		return f;
}

struct feeder_class *
feeder_getclass(struct pcm_feederdesc *desc)
{
	struct feedertab_entry *fte;

	SLIST_FOREACH(fte, &feedertab, link) {
		if ((desc == NULL) && (fte->desc == NULL))
			return fte->feederclass;
		if ((fte->desc != NULL) && (desc != NULL) && cmpdesc(desc, fte->desc))
			return fte->feederclass;
	}
	return NULL;
}

int
chn_addfeeder(pcm_channel *c, struct feeder_class *fc, struct pcm_feederdesc *desc)
{
	pcm_feeder *nf;

	nf = feeder_create(fc, desc);
	if (nf == NULL)
		return -1;

	nf->source = c->feeder;

	if (nf->align > 0)
		c->align += nf->align;
	else if (nf->align < 0 && c->align < -nf->align)
		c->align = -nf->align;

	c->feeder = nf;

	return 0;
}

int
chn_removefeeder(pcm_channel *c)
{
	pcm_feeder *f;

	if (c->feeder == NULL)
		return -1;
	f = c->feeder;
	c->feeder = c->feeder->source;
	feeder_destroy(f);
	return 0;
}

pcm_feeder *
chn_findfeeder(pcm_channel *c, u_int32_t type)
{
	pcm_feeder *f;

	f = c->feeder;
	while (f != NULL) {
		if (f->desc->type == type)
			return f;
		f = f->source;
	}
	return NULL;
}

static int
chainok(pcm_feeder *test, pcm_feeder *stop)
{
	u_int32_t visited[MAXFEEDERS / 32];
	u_int32_t idx, mask;

	bzero(visited, sizeof(visited));
	while (test && (test != stop)) {
		idx = test->desc->idx;
		if (idx < 0)
			panic("bad idx %d", idx);
		if (idx >= MAXFEEDERS)
			panic("bad idx %d", idx);
		mask = 1 << (idx & 31);
		idx >>= 5;
		if (visited[idx] & mask)
			return 0;
		visited[idx] |= mask;
		test = test->source;
	}
	return 1;
}

static pcm_feeder *
feeder_fmtchain(u_int32_t *to, pcm_feeder *source, pcm_feeder *stop, int maxdepth)
{
	struct feedertab_entry *fte;
	pcm_feeder *try, *ret;
	struct pcm_feederdesc trydesc;

	/* printf("trying %s...\n", source->name); */
	if (fmtvalid(source->desc->out, to)) {
		/* printf("got it\n"); */
		return source;
	}

	if (maxdepth < 0)
		return NULL;

	trydesc.type = FEEDER_FMT;
	trydesc.in = source->desc->out;
	trydesc.out = 0;
	trydesc.flags = 0;
	trydesc.idx = -1;

	SLIST_FOREACH(fte, &feedertab, link) {
		if ((fte->desc) && (fte->desc->in == source->desc->out)) {
			trydesc.out = fte->desc->out;
			trydesc.idx = fte->idx;
			try = feeder_create(fte->feederclass, &trydesc);
			if (try == NULL)
				return NULL;
			try->source = source;
			ret = chainok(try, stop)? feeder_fmtchain(to, try, stop, maxdepth - 1) : NULL;
			if (ret != NULL)
				return ret;
			feeder_destroy(try);
		}
	}
	/* printf("giving up %s...\n", source->name); */
	return NULL;
}

u_int32_t
chn_fmtchain(pcm_channel *c, u_int32_t *to)
{
	pcm_feeder *try, *stop;
	int max;

	stop = c->feeder;
	try = NULL;
	max = 0;
	while (try == NULL && max < 8) {
		try = feeder_fmtchain(to, c->feeder, stop, max);
		max++;
	}
	if (try == NULL)
		return 0;
	c->feeder = try;
	c->align = 0;
#ifdef FEEDER_DEBUG
	printf("chain: ");
#endif
	while (try && (try != stop)) {
#ifdef FEEDER_DEBUG
		printf("%s [%d]", try->name, try->desc->idx);
		if (try->source)
			printf(" -> ");
#endif
		if (try->align > 0)
			c->align += try->align;
		else if (try->align < 0 && c->align < -try->align)
			c->align = -try->align;
		try = try->source;
	}
#ifdef FEEDER_DEBUG
	printf("%s [%d]\n", try->name, try->desc->idx);
#endif
	return c->feeder->desc->out;
}

/*****************************************************************************/

static int
feed_root(pcm_feeder *feeder, pcm_channel *ch, u_int8_t *buffer, u_int32_t count, struct uio *stream)
{
	int ret, s;

	KASSERT(count, ("feed_root: count == 0"));
	count &= ~((1 << ch->align) - 1);
	KASSERT(count, ("feed_root: aligned count == 0 (align = %d)", ch->align));

	s = spltty();
	count = min(count, stream->uio_resid);
	if (count) {
		ret = uiomove(buffer, count, stream);
		KASSERT(ret == 0, ("feed_root: uiomove failed (%d)", ret));
	}
	splx(s);

	return count;
}

static kobj_method_t feeder_root_methods[] = {
    	KOBJMETHOD(feeder_feed,		feed_root),
	{ 0, 0 }
};
static struct feeder_class feeder_root_class = {
	name:		"feeder_root",
	methods:	feeder_root_methods,
	size:		sizeof(pcm_feeder),
	align:		0,
	desc:		NULL,
	data:		NULL,
};
SYSINIT(feeder_root, SI_SUB_DRIVERS, SI_ORDER_FIRST, feeder_register, &feeder_root_class);
SYSUNINIT(feeder_root, SI_SUB_DRIVERS, SI_ORDER_FIRST, feeder_unregisterall, NULL);





