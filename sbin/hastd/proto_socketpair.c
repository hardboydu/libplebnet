/*-
 * Copyright (c) 2009-2010 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Pawel Jakub Dawidek under sponsorship from
 * the FreeBSD Foundation.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "hast.h"
#include "proto_impl.h"

#define	SP_CTX_MAGIC	0x50c3741
struct sp_ctx {
	int			sp_magic;
	int			sp_fd[2];
	int			sp_side;
#define	SP_SIDE_UNDEF		0
#define	SP_SIDE_CLIENT		1
#define	SP_SIDE_SERVER		2
};

static void sp_close(void *ctx);

static int
sp_client(const char *addr, void **ctxp)
{
	struct sp_ctx *spctx;
	int ret;

	if (strcmp(addr, "socketpair://") != 0)
		return (-1);

	spctx = malloc(sizeof(*spctx));
	if (spctx == NULL)
		return (errno);

	if (socketpair(PF_UNIX, SOCK_STREAM, 0, spctx->sp_fd) < 0) {
		ret = errno;
		free(spctx);
		return (ret);
	}

	spctx->sp_side = SP_SIDE_UNDEF;
	spctx->sp_magic = SP_CTX_MAGIC;
	*ctxp = spctx;

	return (0);
}

static int
sp_connect(void *ctx __unused)
{

	assert(!"proto_connect() not supported on socketpairs");
	abort();
}

static int
sp_server(const char *addr __unused, void **ctxp __unused)
{

	assert(!"proto_server() not supported on socketpairs");
	abort();
}

static int
sp_accept(void *ctx __unused, void **newctxp __unused)
{

	assert(!"proto_server() not supported on socketpairs");
	abort();
}

static int
sp_send(void *ctx, const unsigned char *data, size_t size)
{
	struct sp_ctx *spctx = ctx;
	int fd;

	assert(spctx != NULL);
	assert(spctx->sp_magic == SP_CTX_MAGIC);

	switch (spctx->sp_side) {
	case SP_SIDE_UNDEF:
		/*
		 * If the first operation done by the caller is proto_send(),
		 * we assume this the client.
		 */
		/* FALLTHROUGH */
		spctx->sp_side = SP_SIDE_CLIENT;
		/* Close other end. */
		close(spctx->sp_fd[1]);
	case SP_SIDE_CLIENT:
		assert(spctx->sp_fd[0] >= 0);
		fd = spctx->sp_fd[0];
		break;
	case SP_SIDE_SERVER:
		assert(spctx->sp_fd[1] >= 0);
		fd = spctx->sp_fd[1];
		break;
	default:
		abort();
	}

	return (proto_common_send(fd, data, size));
}

static int
sp_recv(void *ctx, unsigned char *data, size_t size)
{
	struct sp_ctx *spctx = ctx;
	int fd;

	assert(spctx != NULL);
	assert(spctx->sp_magic == SP_CTX_MAGIC);

	switch (spctx->sp_side) {
	case SP_SIDE_UNDEF:
		/*
		 * If the first operation done by the caller is proto_recv(),
		 * we assume this the server.
		 */
		/* FALLTHROUGH */
		spctx->sp_side = SP_SIDE_SERVER;
		/* Close other end. */
		close(spctx->sp_fd[0]);
	case SP_SIDE_SERVER:
		assert(spctx->sp_fd[1] >= 0);
		fd = spctx->sp_fd[1];
		break;
	case SP_SIDE_CLIENT:
		assert(spctx->sp_fd[0] >= 0);
		fd = spctx->sp_fd[0];
		break;
	default:
		abort();
	}

	return (proto_common_recv(fd, data, size));
}

static int
sp_descriptor(const void *ctx)
{
	const struct sp_ctx *spctx = ctx;

	assert(spctx != NULL);
	assert(spctx->sp_magic == SP_CTX_MAGIC);
	assert(spctx->sp_side == SP_SIDE_CLIENT ||
	    spctx->sp_side == SP_SIDE_SERVER);

	switch (spctx->sp_side) {
	case SP_SIDE_CLIENT:
		assert(spctx->sp_fd[0] >= 0);
		return (spctx->sp_fd[0]);
	case SP_SIDE_SERVER:
		assert(spctx->sp_fd[1] >= 0);
		return (spctx->sp_fd[1]);
	}

	abort();
}

static bool
sp_address_match(const void *ctx __unused, const char *addr __unused)
{

	assert(!"proto_address_match() not supported on socketpairs");
	abort();
}

static void
sp_local_address(const void *ctx __unused, char *addr __unused,
    size_t size __unused)
{

	assert(!"proto_local_address() not supported on socketpairs");
	abort();
}

static void
sp_remote_address(const void *ctx __unused, char *addr __unused,
    size_t size __unused)
{

	assert(!"proto_remote_address() not supported on socketpairs");
	abort();
}

static void
sp_close(void *ctx)
{
	struct sp_ctx *spctx = ctx;

	assert(spctx != NULL);
	assert(spctx->sp_magic == SP_CTX_MAGIC);

	switch (spctx->sp_side) {
	case SP_SIDE_UNDEF:
		close(spctx->sp_fd[0]);
		close(spctx->sp_fd[1]);
		break;
	case SP_SIDE_CLIENT:
		close(spctx->sp_fd[0]);
		break;
	case SP_SIDE_SERVER:
		close(spctx->sp_fd[1]);
		break;
	default:
		abort();
	}

	spctx->sp_magic = 0;
	free(spctx);
}

static struct hast_proto sp_proto = {
	.hp_name = "socketpair",
	.hp_client = sp_client,
	.hp_connect = sp_connect,
	.hp_server = sp_server,
	.hp_accept = sp_accept,
	.hp_send = sp_send,
	.hp_recv = sp_recv,
	.hp_descriptor = sp_descriptor,
	.hp_address_match = sp_address_match,
	.hp_local_address = sp_local_address,
	.hp_remote_address = sp_remote_address,
	.hp_close = sp_close
};

static __constructor void
sp_ctor(void)
{

	proto_register(&sp_proto);
}
