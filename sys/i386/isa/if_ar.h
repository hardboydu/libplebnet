/*
 * if_ar.h
 *
 * Copyright (C) 1997-1999 Whistle Communications Inc.
 * All rights reserved.
 *
 * $FreeBSD$
 */

#ifndef _I386_ISA_IF_AR_H_
#define _I386_ISA_IF_AR_H_

/* Node type name and type cookie */
#define NG_AR_NODE_TYPE		"sync_ar"
#define NG_AR_COOKIE		860552149

/* Netgraph hooks */
#define NG_AR_HOOK_DEBUG	"debug"
#define NG_AR_HOOK_CONTROL	"control"
#define NG_AR_HOOK_RAW		"rawdata"

#endif /* _I386_ISA_IF_AR_H_ */

