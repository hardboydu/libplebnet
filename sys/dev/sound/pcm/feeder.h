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

void feeder_register(void *p);
pcm_feeder *feeder_get(struct pcm_feederdesc *desc);
pcm_feeder *feeder_getroot(void);
int feeder_set(pcm_feeder *feeder, int what, int value);

u_int32_t chn_fmtchain(pcm_channel *c, u_int32_t *to);
int chn_addfeeder(pcm_channel *c, pcm_feeder *f);
int chn_removefeeder(pcm_channel *c);
pcm_feeder *chn_findfeeder(pcm_channel *c, u_int32_t type);

#define FEEDER_DECLARE(feeder) SYSINIT(feeder, SI_SUB_DRIVERS, SI_ORDER_MIDDLE, feeder_register, &feeder)

#define FEEDER_ROOT	1
#define FEEDER_FMT 	2
#define FEEDER_RATE 	3
#define FEEDER_FILTER 	4
#define FEEDER_VOLUME 	5
#define FEEDER_LAST	FEEDER_VOLUME

#define FEEDRATE_SRC	1
#define FEEDRATE_DST	2


