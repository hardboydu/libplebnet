/*-
 * Copyright (c) 2002, Jeffrey Roberson <jeff@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 * $FreeBSD$
 *
 */
#ifndef _SYS_ALQ_H_
#define	_SYS_ALQ_H_

/*
 * Opaque type for the Async. Logging Queue
 */
struct alq;

/* The thread for the logging daemon */
extern struct thread *ald_thread;

/*
 * Async. Logging Entry
 */
struct ale {
	struct ale	*ae_next;	/* Next Entry */
	char		*ae_data;	/* Entry buffer */
	int		ae_flags;	/* Entry flags */
};

#define	AE_VALID	0x0001		/* Entry has valid data */
 

/* waitok options */
#define	ALQ_NOWAIT	0x0001
#define	ALQ_WAITOK	0x0002

/*
 * alq_open:  Creates a new queue
 *
 * Arguments:
 *	alq	Storage for a pointer to the newly created queue.
 *	file	The filename to open for logging.
 *	size	The size of each entry in the queue.
 *	count	The number of items in the buffer, this should be large enough
 *		to store items over the period of a disk write.
 * Returns:
 *	error from open or 0 on success
 */
struct ucred;
int alq_open(struct alq **, const char *file, struct ucred *cred, int size,
	    int count);

/*
 * alq_write:  Write data into the queue
 *
 * Arguments:
 *	alq	The queue we're writing to
 *	data	The entry to be recorded
 *	waitok	Are we permitted to wait?
 *
 * Returns:
 *	EWOULDBLOCK if:
 *		Waitok is ALQ_NOWAIT and the queue is full.
 *		The system is shutting down.
 *	0 on success.
 */
int alq_write(struct alq *alq, void *data, int waitok);

/*
 * alq_flush:  Flush the queue out to disk
 */
void alq_flush(struct alq *alq);

/*
 * alq_close:  Flush the queue and free all resources.
 */
void alq_close(struct alq *alq);

/*
 * alq_get:  Return an entry for direct access
 *
 * Arguments:
 *	alq	The queue to retrieve an entry from
 *	waitok	Are we permitted to wait?
 *
 * Returns:
 *	The next available ale on success.
 *	NULL if:
 *		Waitok is ALQ_NOWAIT and the queue is full.
 *		The system is shutting down.
 *
 * This leaves the queue locked until a subsequent alq_post.
 */
struct ale *alq_get(struct alq *alq, int waitok);

/*
 * alq_post:  Schedule the ale retrieved by alq_get for writing.
 *	alq	The queue to post the entry to.
 *	ale	An asynch logging entry returned by alq_get.
 */
void alq_post(struct alq *, struct ale *);

#endif	/* _SYS_ALQ_H_ */
