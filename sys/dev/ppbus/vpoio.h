/*-
 * Copyright (c) 1998 Nicolas Souchu
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
 *
 */
#ifndef __VP0IO_H
#define __VP0IO_H

/*
 * The ZIP drive cannot act as an initiator.
 */
#define VP0_INITIATOR	0x7

#define VP0_ESELECT_TIMEOUT	1
#define VP0_ECMD_TIMEOUT	2
#define VP0_ECONNECT		3
#define VP0_ESTATUS_TIMEOUT	4
#define VP0_EDATA_OVERFLOW	5	
#define VP0_EDISCONNECT		6
#define VP0_EPPDATA_TIMEOUT	7
#define VP0_ENEGOCIATE		8
#define VP0_ENOPORT		9
#define VP0_EINITFAILED		10
#define VP0_EINTR		12

#define VP0_EOTHER		13

#define VP0_OPENNINGS	1

/*
 * Data structure used during microsequence execution
 * when characters are received in nibble mode
 */
struct vpo_nibble {
	char h;			/* most significant nibble */
	char l;			/* less significant nibble */
};

struct vpoio_data {
	unsigned short int vpo_unit;

	struct vpo_nibble vpo_nibble;

	/* each device must have its own nibble inbyte microsequence */
	struct ppb_microseq *vpo_nibble_inbyte_msq;

	struct ppb_device vpo_dev;
};

#define vpoio_set_unit(vpo,unit) ((vpo)->vpo_unit = unit)

struct ppb_device *vpoio_probe(struct ppb_data *ppb, struct vpoio_data *vpo);

int vpoio_attach(struct vpoio_data *vpo);
int vpoio_reset_bus(struct vpoio_data *vpo);

int vpoio_do_scsi(struct vpoio_data *vpo, int host, int target, char *command,
		int clen, char *buffer, int blen, int *result, int *count,
		int *ret);

struct ppb_device *imm_probe(struct ppb_data *ppb, struct vpoio_data *vpo);

int imm_attach(struct vpoio_data *vpo);
int imm_reset_bus(struct vpoio_data *vpo);

int imm_do_scsi(struct vpoio_data *vpo, int host, int target, char *command,
		int clen, char *buffer, int blen, int *result, int *count,
		int *ret);

#endif
