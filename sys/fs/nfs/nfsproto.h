/*-
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Rick Macklem at The University of Guelph.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
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

#ifndef _NFS_NFSPROTO_H_
#define	_NFS_NFSPROTO_H_

/*
 * nfs definitions as per the Version 2, 3 and 4 specs
 */

/*
 * Constants as defined in the NFS Version 2, 3 and 4 specs.
 * "NFS: Network File System Protocol Specification" RFC1094
 * and in the "NFS: Network File System Version 3 Protocol
 * Specification"
 */

#define	NFS_PORT	2049
#define	NFS_PROG	100003
#define	NFS_CALLBCKPROG	0x40000000	/* V4 only */
#define	NFS_VER2	2
#define	NFS_VER3	3
#define	NFS_VER4	4
#define	NFS_V2MAXDATA	8192
#define	NFS_MAXDGRAMDATA 16384
#define	NFS_MAXDATA	NFS_MAXBSIZE
#define	NFS_MAXPATHLEN	1024
#define	NFS_MAXNAMLEN	255
#define	NFS_MAXPKTHDR	404
#define	NFS_MAXPACKET	(NFS_MAXDATA + 2048)
#define	NFS_MINPACKET	20
#define	NFS_FABLKSIZE	512	/* Size in bytes of a block wrt fa_blocks */
#define	NFSV4_MINORVERSION	0	/* V4 Minor version */
#define	NFSV4_CBVERS		1	/* V4 CB Version */
#define	NFSV4_SMALLSTR	50		/* Strings small enough for stack */

/* Stat numbers for rpc returns (version 2, 3 and 4) */
#define	NFSERR_OK		0
#define	NFSERR_PERM		1
#define	NFSERR_NOENT		2
#define	NFSERR_IO		5
#define	NFSERR_NXIO		6
#define	NFSERR_ACCES		13
#define	NFSERR_EXIST		17
#define	NFSERR_XDEV		18	/* Version 3, 4 only */
#define	NFSERR_NODEV		19
#define	NFSERR_NOTDIR		20
#define	NFSERR_ISDIR		21
#define	NFSERR_INVAL		22	/* Version 3, 4 only */
#define	NFSERR_FBIG		27
#define	NFSERR_NOSPC		28
#define	NFSERR_ROFS		30
#define	NFSERR_MLINK		31	/* Version 3, 4 only */
#define	NFSERR_NAMETOL		63
#define	NFSERR_NOTEMPTY		66
#define	NFSERR_DQUOT		69
#define	NFSERR_STALE		70
#define	NFSERR_REMOTE		71	/* Version 3 only */
#define	NFSERR_WFLUSH		99	/* Version 2 only */
#define	NFSERR_BADHANDLE	10001	/* These are Version 3, 4 only */
#define	NFSERR_NOT_SYNC		10002	/* Version 3 Only */
#define	NFSERR_BAD_COOKIE	10003
#define	NFSERR_NOTSUPP		10004
#define	NFSERR_TOOSMALL		10005
#define	NFSERR_SERVERFAULT	10006
#define	NFSERR_BADTYPE		10007
#define	NFSERR_DELAY		10008	/* Called NFSERR_JUKEBOX for V3 */
#define	NFSERR_SAME		10009	/* These are Version 4 only */
#define	NFSERR_DENIED		10010
#define	NFSERR_EXPIRED		10011
#define	NFSERR_LOCKED		10012
#define	NFSERR_GRACE		10013
#define	NFSERR_FHEXPIRED	10014
#define	NFSERR_SHAREDENIED	10015
#define	NFSERR_WRONGSEC		10016
#define	NFSERR_CLIDINUSE	10017
#define	NFSERR_RESOURCE		10018
#define	NFSERR_MOVED		10019
#define	NFSERR_NOFILEHANDLE	10020
#define	NFSERR_MINORVERMISMATCH	10021
#define	NFSERR_STALECLIENTID	10022
#define	NFSERR_STALESTATEID	10023
#define	NFSERR_OLDSTATEID	10024
#define	NFSERR_BADSTATEID	10025
#define	NFSERR_BADSEQID		10026
#define	NFSERR_NOTSAME		10027
#define	NFSERR_LOCKRANGE	10028
#define	NFSERR_SYMLINK		10029
#define	NFSERR_RESTOREFH	10030
#define	NFSERR_LEASEMOVED	10031
#define	NFSERR_ATTRNOTSUPP	10032
#define	NFSERR_NOGRACE		10033
#define	NFSERR_RECLAIMBAD	10034
#define	NFSERR_RECLAIMCONFLICT	10035
#define	NFSERR_BADXDR		10036
#define	NFSERR_LOCKSHELD	10037
#define	NFSERR_OPENMODE		10038
#define	NFSERR_BADOWNER		10039
#define	NFSERR_BADCHAR		10040
#define	NFSERR_BADNAME		10041
#define	NFSERR_BADRANGE		10042
#define	NFSERR_LOCKNOTSUPP	10043
#define	NFSERR_OPILLEGAL	10044
#define	NFSERR_DEADLOCK		10045
#define	NFSERR_FILEOPEN		10046
#define	NFSERR_ADMINREVOKED	10047
#define	NFSERR_CBPATHDOWN	10048

#define	NFSERR_STALEWRITEVERF	30001	/* Fake return for nfs_commit() */
#define	NFSERR_DONTREPLY	30003	/* Don't process request */
#define	NFSERR_RETVOID		30004	/* Return void, not error */
#define	NFSERR_REPLYFROMCACHE	30005	/* Reply from recent request cache */
#define	NFSERR_STALEDONTRECOVER	30006	/* Don't initiate recovery */

#define	NFSERR_RPCERR		0x40000000 /* Mark an RPC layer error */
#define	NFSERR_AUTHERR		0x80000000 /* Mark an authentication error */

#define	NFSERR_RPCMISMATCH	(NFSERR_RPCERR | RPC_MISMATCH)
#define	NFSERR_PROGUNAVAIL	(NFSERR_RPCERR | RPC_PROGUNAVAIL)
#define	NFSERR_PROGMISMATCH	(NFSERR_RPCERR | RPC_PROGMISMATCH)
#define	NFSERR_PROGNOTV4	(NFSERR_RPCERR | 0xffff)
#define	NFSERR_PROCUNAVAIL	(NFSERR_RPCERR | RPC_PROCUNAVAIL)
#define	NFSERR_GARBAGE		(NFSERR_RPCERR | RPC_GARBAGE)

/* Sizes in bytes of various nfs rpc components */
#define	NFSX_UNSIGNED	4
#define	NFSX_HYPER	(2 * NFSX_UNSIGNED)

/* specific to NFS Version 2 */
#define	NFSX_V2FH	32
#define	NFSX_V2FATTR	68
#define	NFSX_V2SATTR	32
#define	NFSX_V2COOKIE	4
#define	NFSX_V2STATFS	20

/* specific to NFS Version 3 */
#define	NFSX_V3FHMAX		64	/* max. allowed by protocol */
#define	NFSX_V3FATTR		84
#define	NFSX_V3SATTR		60	/* max. all fields filled in */
#define	NFSX_V3SRVSATTR		(sizeof (struct nfsv3_sattr))
#define	NFSX_V3POSTOPATTR	(NFSX_V3FATTR + NFSX_UNSIGNED)
#define	NFSX_V3WCCDATA		(NFSX_V3POSTOPATTR + 8 * NFSX_UNSIGNED)
#define	NFSX_V3STATFS		52
#define	NFSX_V3FSINFO		48
#define	NFSX_V3PATHCONF		24

/* specific to NFS Version 4 */
#define	NFSX_V4FHMAX		128
#define	NFSX_V4FSID		(2 * NFSX_HYPER)
#define	NFSX_V4SPECDATA		(2 * NFSX_UNSIGNED)
#define	NFSX_V4TIME		(NFSX_HYPER + NFSX_UNSIGNED)
#define	NFSX_V4SETTIME		(NFSX_UNSIGNED + NFSX_V4TIME)

/* sizes common to multiple NFS versions */
#define	NFSX_FHMAX		(NFSX_V4FHMAX)
#define	NFSX_MYFH		(sizeof (fhandle_t)) /* size this server uses */
#define	NFSX_VERF 		8
#define	NFSX_STATEIDOTHER	12
#define	NFSX_STATEID		(NFSX_UNSIGNED + NFSX_STATEIDOTHER)
#define	NFSX_GSSH		12

/* variants for multiple versions */
#define	NFSX_STATFS(v3)		((v3) ? NFSX_V3STATFS : NFSX_V2STATFS)

/* nfs rpc procedure numbers (before version mapping) */
#define	NFSPROC_NULL		0
#define	NFSPROC_GETATTR		1
#define	NFSPROC_SETATTR		2
#define	NFSPROC_LOOKUP		3
#define	NFSPROC_ACCESS		4
#define	NFSPROC_READLINK	5
#define	NFSPROC_READ		6
#define	NFSPROC_WRITE		7
#define	NFSPROC_CREATE		8
#define	NFSPROC_MKDIR		9
#define	NFSPROC_SYMLINK		10
#define	NFSPROC_MKNOD		11
#define	NFSPROC_REMOVE		12
#define	NFSPROC_RMDIR		13
#define	NFSPROC_RENAME		14
#define	NFSPROC_LINK		15
#define	NFSPROC_READDIR		16
#define	NFSPROC_READDIRPLUS	17
#define	NFSPROC_FSSTAT		18
#define	NFSPROC_FSINFO		19
#define	NFSPROC_PATHCONF	20
#define	NFSPROC_COMMIT		21

/*
 * NFSPROC_NOOP is a fake op# that can't be the same as any V2/3/4 Procedure
 * or Operation#. Since the NFS V4 Op #s go higher, use NFSV4OP_NOPS, which
 * is one greater than the highest Op#.
 */
#define	NFSPROC_NOOP		NFSV4OP_NOPS

/* Actual Version 2 procedure numbers */
#define	NFSV2PROC_NULL		0
#define	NFSV2PROC_GETATTR	1
#define	NFSV2PROC_SETATTR	2
#define	NFSV2PROC_NOOP		3
#define	NFSV2PROC_ROOT		NFSV2PROC_NOOP	/* Obsolete */
#define	NFSV2PROC_LOOKUP	4
#define	NFSV2PROC_READLINK	5
#define	NFSV2PROC_READ		6
#define	NFSV2PROC_WRITECACHE	NFSV2PROC_NOOP	/* Obsolete */
#define	NFSV2PROC_WRITE		8
#define	NFSV2PROC_CREATE	9
#define	NFSV2PROC_REMOVE	10
#define	NFSV2PROC_RENAME	11
#define	NFSV2PROC_LINK		12
#define	NFSV2PROC_SYMLINK	13
#define	NFSV2PROC_MKDIR		14
#define	NFSV2PROC_RMDIR		15
#define	NFSV2PROC_READDIR	16
#define	NFSV2PROC_STATFS	17

/*
 * V4 Procedure numbers
 */
#define	NFSV4PROC_COMPOUND	1
#define	NFSV4PROC_CBNULL	0
#define	NFSV4PROC_CBCOMPOUND	1

/*
 * Constants used by the Version 3 and 4 protocols for various RPCs
 */
#define	NFSV3SATTRTIME_DONTCHANGE	0
#define	NFSV3SATTRTIME_TOSERVER		1
#define	NFSV3SATTRTIME_TOCLIENT		2

#define	NFSV4SATTRTIME_TOSERVER		0
#define	NFSV4SATTRTIME_TOCLIENT		1

#define	NFSV4LOCKT_READ			1
#define	NFSV4LOCKT_WRITE		2
#define	NFSV4LOCKT_READW		3
#define	NFSV4LOCKT_WRITEW		4
#define	NFSV4LOCKT_RELEASE		5

#define	NFSV4OPEN_NOCREATE		0
#define	NFSV4OPEN_CREATE		1
#define	NFSV4OPEN_CLAIMNULL		0
#define	NFSV4OPEN_CLAIMPREVIOUS		1
#define	NFSV4OPEN_CLAIMDELEGATECUR	2
#define	NFSV4OPEN_CLAIMDELEGATEPREV	3
#define	NFSV4OPEN_DELEGATENONE		0
#define	NFSV4OPEN_DELEGATEREAD		1
#define	NFSV4OPEN_DELEGATEWRITE		2
#define	NFSV4OPEN_LIMITSIZE		1
#define	NFSV4OPEN_LIMITBLOCKS		2

/*
 * Nfs V4 ACE stuff
 */
#define	NFSV4ACE_ALLOWEDTYPE		0x00000000
#define	NFSV4ACE_DENIEDTYPE		0x00000001
#define	NFSV4ACE_AUDITTYPE		0x00000002
#define	NFSV4ACE_ALARMTYPE		0x00000003

#define	NFSV4ACE_SUPALLOWED		0x00000001
#define	NFSV4ACE_SUPDENIED		0x00000002
#define	NFSV4ACE_SUPAUDIT		0x00000004
#define	NFSV4ACE_SUPALARM		0x00000008

#define	NFSV4ACE_SUPTYPES	(NFSV4ACE_SUPALLOWED | NFSV4ACE_SUPDENIED)

#define	NFSV4ACE_FILEINHERIT		0x00000001
#define	NFSV4ACE_DIRECTORYINHERIT	0x00000002
#define	NFSV4ACE_NOPROPAGATEINHERIT	0x00000004
#define	NFSV4ACE_INHERITONLY		0x00000008
#define	NFSV4ACE_SUCCESSFULACCESS	0x00000010
#define	NFSV4ACE_FAILEDACCESS		0x00000020
#define	NFSV4ACE_IDENTIFIERGROUP	0x00000040

#define	NFSV4ACE_READDATA		0x00000001
#define	NFSV4ACE_LISTDIRECTORY		0x00000001
#define	NFSV4ACE_WRITEDATA		0x00000002
#define	NFSV4ACE_ADDFILE		0x00000002
#define	NFSV4ACE_APPENDDATA		0x00000004
#define	NFSV4ACE_ADDSUBDIRECTORY	0x00000004
#define	NFSV4ACE_READNAMEDATTR		0x00000008
#define	NFSV4ACE_WRITENAMEDATTR		0x00000010
#define	NFSV4ACE_EXECUTE		0x00000020
#define	NFSV4ACE_SEARCH			0x00000020
#define	NFSV4ACE_DELETECHILD		0x00000040
#define	NFSV4ACE_READATTRIBUTES		0x00000080
#define	NFSV4ACE_WRITEATTRIBUTES	0x00000100
#define	NFSV4ACE_DELETE			0x00010000
#define	NFSV4ACE_READACL		0x00020000
#define	NFSV4ACE_WRITEACL		0x00040000
#define	NFSV4ACE_WRITEOWNER		0x00080000
#define	NFSV4ACE_SYNCHRONIZE		0x00100000

/*
 * Here are the mappings between mode bits and acl mask bits for
 * directories and other files.
 * (Named attributes have not been included, since named attributes are
 *  not yet supported.)
 * The mailing list seems to indicate that NFSV4ACE_EXECUTE refers to
 * searching a directory, although I can't find a statement of that in
 * the RFC.
 */
#define	NFSV4ACE_ALLFILESMASK	(NFSV4ACE_READATTRIBUTES | NFSV4ACE_READACL)
#define	NFSV4ACE_OWNERMASK	(NFSV4ACE_WRITEATTRIBUTES | NFSV4ACE_WRITEACL)
#define	NFSV4ACE_DIRREADMASK	NFSV4ACE_LISTDIRECTORY
#define	NFSV4ACE_DIREXECUTEMASK	NFSV4ACE_EXECUTE
#define	NFSV4ACE_DIRWRITEMASK	(NFSV4ACE_ADDFILE | 			\
		NFSV4ACE_ADDSUBDIRECTORY | NFSV4ACE_DELETECHILD)
#define	NFSV4ACE_READMASK	NFSV4ACE_READDATA
#define	NFSV4ACE_WRITEMASK	(NFSV4ACE_WRITEDATA | NFSV4ACE_APPENDDATA)
#define	NFSV4ACE_EXECUTEMASK	NFSV4ACE_EXECUTE
#define	NFSV4ACE_ALLFILEBITS	(NFSV4ACE_READMASK | NFSV4ACE_WRITEMASK | \
	NFSV4ACE_EXECUTEMASK | NFSV4ACE_SYNCHRONIZE)
#define	NFSV4ACE_ALLDIRBITS	(NFSV4ACE_DIRREADMASK | 		\
	NFSV4ACE_DIRWRITEMASK | NFSV4ACE_DIREXECUTEMASK)
#define	NFSV4ACE_AUDITMASK	0x0

/*
 * These GENERIC masks are not used and are no longer believed to be useful.
 */
#define	NFSV4ACE_GENERICREAD		0x00120081
#define	NFSV4ACE_GENERICWRITE		0x00160106
#define	NFSV4ACE_GENERICEXECUTE		0x001200a0

#define	NFSSTATEID_PUTALLZERO		0
#define	NFSSTATEID_PUTALLONE		1
#define	NFSSTATEID_PUTSTATEID		2

/*
 * Bits for share access and deny.
 */
#define	NFSV4OPEN_ACCESSREAD		0x00000001
#define	NFSV4OPEN_ACCESSWRITE		0x00000002
#define	NFSV4OPEN_ACCESSBOTH		0x00000003

#define	NFSV4OPEN_DENYNONE		0x00000000
#define	NFSV4OPEN_DENYREAD		0x00000001
#define	NFSV4OPEN_DENYWRITE		0x00000002
#define	NFSV4OPEN_DENYBOTH		0x00000003

/*
 * Open result flags
 * (The first two are in the spec. The rest are used internally.)
 */
#define	NFSV4OPEN_RESULTCONFIRM		0x00000002
#define	NFSV4OPEN_LOCKTYPEPOSIX		0x00000004
#define	NFSV4OPEN_RFLAGS 						\
		(NFSV4OPEN_RESULTCONFIRM | NFSV4OPEN_LOCKTYPEPOSIX)
#define	NFSV4OPEN_RECALL		0x00010000
#define	NFSV4OPEN_READDELEGATE		0x00020000
#define	NFSV4OPEN_WRITEDELEGATE		0x00040000

/*
 * NFS V4 File Handle types
 */
#define	NFSV4FHTYPE_PERSISTENT		0x0
#define	NFSV4FHTYPE_NOEXPIREWITHOPEN	0x1
#define	NFSV4FHTYPE_VOLATILEANY		0x2
#define	NFSV4FHTYPE_VOLATILEMIGRATE	0x4
#define	NFSV4FHTYPE_VOLATILERENAME	0x8

/*
 * Maximum size of V4 opaque strings.
 */
#define	NFSV4_OPAQUELIMIT	1024

/*
 * These are the same for V3 and V4.
 */
#define	NFSACCESS_READ			0x01
#define	NFSACCESS_LOOKUP		0x02
#define	NFSACCESS_MODIFY		0x04
#define	NFSACCESS_EXTEND		0x08
#define	NFSACCESS_DELETE		0x10
#define	NFSACCESS_EXECUTE		0x20

#define	NFSWRITE_UNSTABLE		0
#define	NFSWRITE_DATASYNC		1
#define	NFSWRITE_FILESYNC		2

#define	NFSCREATE_UNCHECKED		0
#define	NFSCREATE_GUARDED		1
#define	NFSCREATE_EXCLUSIVE		2

#define	NFSV3FSINFO_LINK		0x01
#define	NFSV3FSINFO_SYMLINK		0x02
#define	NFSV3FSINFO_HOMOGENEOUS		0x08
#define	NFSV3FSINFO_CANSETTIME		0x10

/* Conversion macros */
#define	vtonfsv2_mode(t,m) 						\
		txdr_unsigned(((t) == VFIFO) ? MAKEIMODE(VCHR, (m)) : 	\
				MAKEIMODE((t), (m)))
#define	vtonfsv34_mode(m)	txdr_unsigned((m) & 07777)
#define	nfstov_mode(a)		(fxdr_unsigned(u_int16_t, (a))&07777)
#define	vtonfsv2_type(a)  (((u_int32_t)(a)) >= 9 ? txdr_unsigned(NFNON) : \
		txdr_unsigned(newnfsv2_type[((u_int32_t)(a))]))
#define	vtonfsv34_type(a)  (((u_int32_t)(a)) >= 9 ? txdr_unsigned(NFNON) : \
		txdr_unsigned(nfsv34_type[((u_int32_t)(a))]))
#define	nfsv2tov_type(a)	newnv2tov_type[fxdr_unsigned(u_int32_t,(a))&0x7]
#define	nfsv34tov_type(a)	nv34tov_type[fxdr_unsigned(u_int32_t,(a))&0x7]
#define	vtonfs_dtype(a)	(((u_int32_t)(a)) >= 9 ? IFTODT(VTTOIF(VNON)) : \
			 IFTODT(VTTOIF(a)))

/* File types */
typedef enum { NFNON=0, NFREG=1, NFDIR=2, NFBLK=3, NFCHR=4, NFLNK=5,
	NFSOCK=6, NFFIFO=7, NFATTRDIR=8, NFNAMEDATTR=9 } nfstype;

/* Structs for common parts of the rpc's */

struct nfsv2_time {
	u_int32_t nfsv2_sec;
	u_int32_t nfsv2_usec;
};
typedef struct nfsv2_time	nfstime2;

struct nfsv3_time {
	u_int32_t nfsv3_sec;
	u_int32_t nfsv3_nsec;
};
typedef struct nfsv3_time	nfstime3;

struct nfsv4_time {
	u_int32_t nfsv4_highsec;
	u_int32_t nfsv4_sec;
	u_int32_t nfsv4_nsec;
};
typedef struct nfsv4_time	nfstime4;

/*
 * Quads are defined as arrays of 2 longs to ensure dense packing for the
 * protocol and to facilitate xdr conversion.
 */
struct nfs_uquad {
	u_int32_t nfsuquad[2];
};
typedef	struct nfs_uquad	nfsuint64;

/*
 * Used to convert between two u_longs and a u_quad_t.
 */
union nfs_quadconvert {
	u_int32_t lval[2];
	u_quad_t  qval;
};
typedef union nfs_quadconvert	nfsquad_t;

/*
 * NFS Version 3 special file number.
 */
struct nfsv3_spec {
	u_int32_t specdata1;
	u_int32_t specdata2;
};
typedef	struct nfsv3_spec	nfsv3spec;

/*
 * File attributes and setable attributes. These structures cover both
 * NFS version 2 and the version 3 protocol. Note that the union is only
 * used so that one pointer can refer to both variants. These structures
 * go out on the wire and must be densely packed, so no quad data types
 * are used. (all fields are longs or u_longs or structures of same)
 * NB: You can't do sizeof(struct nfs_fattr), you must use the
 *     NFSX_FATTR(v3) macro.
 */
struct nfs_fattr {
	u_int32_t fa_type;
	u_int32_t fa_mode;
	u_int32_t fa_nlink;
	u_int32_t fa_uid;
	u_int32_t fa_gid;
	union {
		struct {
			u_int32_t nfsv2fa_size;
			u_int32_t nfsv2fa_blocksize;
			u_int32_t nfsv2fa_rdev;
			u_int32_t nfsv2fa_blocks;
			u_int32_t nfsv2fa_fsid;
			u_int32_t nfsv2fa_fileid;
			nfstime2  nfsv2fa_atime;
			nfstime2  nfsv2fa_mtime;
			nfstime2  nfsv2fa_ctime;
		} fa_nfsv2;
		struct {
			nfsuint64 nfsv3fa_size;
			nfsuint64 nfsv3fa_used;
			nfsv3spec nfsv3fa_rdev;
			nfsuint64 nfsv3fa_fsid;
			nfsuint64 nfsv3fa_fileid;
			nfstime3  nfsv3fa_atime;
			nfstime3  nfsv3fa_mtime;
			nfstime3  nfsv3fa_ctime;
		} fa_nfsv3;
	} fa_un;
};

/* and some ugly defines for accessing union components */
#define	fa2_size		fa_un.fa_nfsv2.nfsv2fa_size
#define	fa2_blocksize		fa_un.fa_nfsv2.nfsv2fa_blocksize
#define	fa2_rdev		fa_un.fa_nfsv2.nfsv2fa_rdev
#define	fa2_blocks		fa_un.fa_nfsv2.nfsv2fa_blocks
#define	fa2_fsid		fa_un.fa_nfsv2.nfsv2fa_fsid
#define	fa2_fileid		fa_un.fa_nfsv2.nfsv2fa_fileid
#define	fa2_atime		fa_un.fa_nfsv2.nfsv2fa_atime
#define	fa2_mtime		fa_un.fa_nfsv2.nfsv2fa_mtime
#define	fa2_ctime		fa_un.fa_nfsv2.nfsv2fa_ctime
#define	fa3_size		fa_un.fa_nfsv3.nfsv3fa_size
#define	fa3_used		fa_un.fa_nfsv3.nfsv3fa_used
#define	fa3_rdev		fa_un.fa_nfsv3.nfsv3fa_rdev
#define	fa3_fsid		fa_un.fa_nfsv3.nfsv3fa_fsid
#define	fa3_fileid		fa_un.fa_nfsv3.nfsv3fa_fileid
#define	fa3_atime		fa_un.fa_nfsv3.nfsv3fa_atime
#define	fa3_mtime		fa_un.fa_nfsv3.nfsv3fa_mtime
#define	fa3_ctime		fa_un.fa_nfsv3.nfsv3fa_ctime

struct nfsv2_sattr {
	u_int32_t sa_mode;
	u_int32_t sa_uid;
	u_int32_t sa_gid;
	u_int32_t sa_size;
	nfstime2  sa_atime;
	nfstime2  sa_mtime;
};

/*
 * NFS Version 3 sattr structure for the new node creation case.
 */
struct nfsv3_sattr {
	u_int32_t sa_modetrue;
	u_int32_t sa_mode;
	u_int32_t sa_uidfalse;
	u_int32_t sa_gidfalse;
	u_int32_t sa_sizefalse;
	u_int32_t sa_atimetype;
	nfstime3  sa_atime;
	u_int32_t sa_mtimetype;
	nfstime3  sa_mtime;
};

/*
 * The attribute bits used for V4.
 * NFSATTRBIT_xxx defines the attribute# (and its bit position)
 * NFSATTRBM_xxx is a 32bit mask with the correct bit set within the
 *	appropriate 32bit word.
 * NFSATTRBIT_MAX is one greater than the largest NFSATTRBIT_xxx
 */
#define	NFSATTRBIT_SUPPORTEDATTRS	0
#define	NFSATTRBIT_TYPE			1
#define	NFSATTRBIT_FHEXPIRETYPE		2
#define	NFSATTRBIT_CHANGE		3
#define	NFSATTRBIT_SIZE			4
#define	NFSATTRBIT_LINKSUPPORT		5
#define	NFSATTRBIT_SYMLINKSUPPORT	6
#define	NFSATTRBIT_NAMEDATTR		7
#define	NFSATTRBIT_FSID			8
#define	NFSATTRBIT_UNIQUEHANDLES	9
#define	NFSATTRBIT_LEASETIME		10
#define	NFSATTRBIT_RDATTRERROR		11
#define	NFSATTRBIT_ACL			12
#define	NFSATTRBIT_ACLSUPPORT		13
#define	NFSATTRBIT_ARCHIVE		14
#define	NFSATTRBIT_CANSETTIME		15
#define	NFSATTRBIT_CASEINSENSITIVE	16
#define	NFSATTRBIT_CASEPRESERVING	17
#define	NFSATTRBIT_CHOWNRESTRICTED	18
#define	NFSATTRBIT_FILEHANDLE		19
#define	NFSATTRBIT_FILEID		20
#define	NFSATTRBIT_FILESAVAIL		21
#define	NFSATTRBIT_FILESFREE		22
#define	NFSATTRBIT_FILESTOTAL		23
#define	NFSATTRBIT_FSLOCATIONS		24
#define	NFSATTRBIT_HIDDEN		25
#define	NFSATTRBIT_HOMOGENEOUS		26
#define	NFSATTRBIT_MAXFILESIZE		27
#define	NFSATTRBIT_MAXLINK		28
#define	NFSATTRBIT_MAXNAME		29
#define	NFSATTRBIT_MAXREAD		30
#define	NFSATTRBIT_MAXWRITE		31
#define	NFSATTRBIT_MIMETYPE		32
#define	NFSATTRBIT_MODE			33
#define	NFSATTRBIT_NOTRUNC		34
#define	NFSATTRBIT_NUMLINKS		35
#define	NFSATTRBIT_OWNER		36
#define	NFSATTRBIT_OWNERGROUP		37
#define	NFSATTRBIT_QUOTAHARD		38
#define	NFSATTRBIT_QUOTASOFT		39
#define	NFSATTRBIT_QUOTAUSED		40
#define	NFSATTRBIT_RAWDEV		41
#define	NFSATTRBIT_SPACEAVAIL		42
#define	NFSATTRBIT_SPACEFREE		43
#define	NFSATTRBIT_SPACETOTAL		44
#define	NFSATTRBIT_SPACEUSED		45
#define	NFSATTRBIT_SYSTEM		46
#define	NFSATTRBIT_TIMEACCESS		47
#define	NFSATTRBIT_TIMEACCESSSET	48
#define	NFSATTRBIT_TIMEBACKUP		49
#define	NFSATTRBIT_TIMECREATE		50
#define	NFSATTRBIT_TIMEDELTA		51
#define	NFSATTRBIT_TIMEMETADATA		52
#define	NFSATTRBIT_TIMEMODIFY		53
#define	NFSATTRBIT_TIMEMODIFYSET	54
#define	NFSATTRBIT_MOUNTEDONFILEID	55

#define	NFSATTRBM_SUPPORTEDATTRS	0x00000001
#define	NFSATTRBM_TYPE			0x00000002
#define	NFSATTRBM_FHEXPIRETYPE		0x00000004
#define	NFSATTRBM_CHANGE		0x00000008
#define	NFSATTRBM_SIZE			0x00000010
#define	NFSATTRBM_LINKSUPPORT		0x00000020
#define	NFSATTRBM_SYMLINKSUPPORT	0x00000040
#define	NFSATTRBM_NAMEDATTR		0x00000080
#define	NFSATTRBM_FSID			0x00000100
#define	NFSATTRBM_UNIQUEHANDLES		0x00000200
#define	NFSATTRBM_LEASETIME		0x00000400
#define	NFSATTRBM_RDATTRERROR		0x00000800
#define	NFSATTRBM_ACL			0x00001000
#define	NFSATTRBM_ACLSUPPORT		0x00002000
#define	NFSATTRBM_ARCHIVE		0x00004000
#define	NFSATTRBM_CANSETTIME		0x00008000
#define	NFSATTRBM_CASEINSENSITIVE	0x00010000
#define	NFSATTRBM_CASEPRESERVING	0x00020000
#define	NFSATTRBM_CHOWNRESTRICTED	0x00040000
#define	NFSATTRBM_FILEHANDLE		0x00080000
#define	NFSATTRBM_FILEID		0x00100000
#define	NFSATTRBM_FILESAVAIL		0x00200000
#define	NFSATTRBM_FILESFREE		0x00400000
#define	NFSATTRBM_FILESTOTAL		0x00800000
#define	NFSATTRBM_FSLOCATIONS		0x01000000
#define	NFSATTRBM_HIDDEN		0x02000000
#define	NFSATTRBM_HOMOGENEOUS		0x04000000
#define	NFSATTRBM_MAXFILESIZE		0x08000000
#define	NFSATTRBM_MAXLINK		0x10000000
#define	NFSATTRBM_MAXNAME		0x20000000
#define	NFSATTRBM_MAXREAD		0x40000000
#define	NFSATTRBM_MAXWRITE		0x80000000
#define	NFSATTRBM_MIMETYPE		0x00000001
#define	NFSATTRBM_MODE			0x00000002
#define	NFSATTRBM_NOTRUNC		0x00000004
#define	NFSATTRBM_NUMLINKS		0x00000008
#define	NFSATTRBM_OWNER			0x00000010
#define	NFSATTRBM_OWNERGROUP		0x00000020
#define	NFSATTRBM_QUOTAHARD		0x00000040
#define	NFSATTRBM_QUOTASOFT		0x00000080
#define	NFSATTRBM_QUOTAUSED		0x00000100
#define	NFSATTRBM_RAWDEV		0x00000200
#define	NFSATTRBM_SPACEAVAIL		0x00000400
#define	NFSATTRBM_SPACEFREE		0x00000800
#define	NFSATTRBM_SPACETOTAL		0x00001000
#define	NFSATTRBM_SPACEUSED		0x00002000
#define	NFSATTRBM_SYSTEM		0x00004000
#define	NFSATTRBM_TIMEACCESS		0x00008000
#define	NFSATTRBM_TIMEACCESSSET		0x00010000
#define	NFSATTRBM_TIMEBACKUP		0x00020000
#define	NFSATTRBM_TIMECREATE		0x00040000
#define	NFSATTRBM_TIMEDELTA		0x00080000
#define	NFSATTRBM_TIMEMETADATA		0x00100000
#define	NFSATTRBM_TIMEMODIFY		0x00200000
#define	NFSATTRBM_TIMEMODIFYSET		0x00400000
#define	NFSATTRBM_MOUNTEDONFILEID	0x00800000

#define	NFSATTRBIT_MAX			56

/*
 * Sets of attributes that are supported, by words in the bitmap.
 */
/*
 * NFSATTRBIT_SUPPORTED - SUPP0 - bits 0<->31
 *			  SUPP1 - bits 32<->63
 */
#define	NFSATTRBIT_SUPP0						\
 	(NFSATTRBM_SUPPORTEDATTRS |					\
 	NFSATTRBM_TYPE |						\
 	NFSATTRBM_FHEXPIRETYPE |					\
 	NFSATTRBM_CHANGE |						\
 	NFSATTRBM_SIZE |						\
 	NFSATTRBM_LINKSUPPORT |						\
 	NFSATTRBM_SYMLINKSUPPORT |					\
 	NFSATTRBM_NAMEDATTR |						\
 	NFSATTRBM_FSID |						\
 	NFSATTRBM_UNIQUEHANDLES |					\
 	NFSATTRBM_LEASETIME |						\
 	NFSATTRBM_RDATTRERROR |						\
 	NFSATTRBM_ACL |							\
 	NFSATTRBM_ACLSUPPORT |						\
 	NFSATTRBM_CANSETTIME |						\
 	NFSATTRBM_CASEINSENSITIVE |					\
 	NFSATTRBM_CASEPRESERVING |					\
 	NFSATTRBM_CHOWNRESTRICTED |					\
 	NFSATTRBM_FILEHANDLE |						\
 	NFSATTRBM_FILEID |						\
 	NFSATTRBM_FILESAVAIL |						\
 	NFSATTRBM_FILESFREE |						\
 	NFSATTRBM_FILESTOTAL |						\
	NFSATTRBM_FSLOCATIONS |						\
 	NFSATTRBM_HOMOGENEOUS |						\
 	NFSATTRBM_MAXFILESIZE |						\
 	NFSATTRBM_MAXLINK |						\
 	NFSATTRBM_MAXNAME |						\
 	NFSATTRBM_MAXREAD |						\
 	NFSATTRBM_MAXWRITE)

/*
 * NFSATTRBIT_S1 - subset of SUPP1 - OR of the following bits:
 */
#define	NFSATTRBIT_S1							\
 	(NFSATTRBM_MODE |						\
 	NFSATTRBM_NOTRUNC |						\
 	NFSATTRBM_NUMLINKS |						\
 	NFSATTRBM_OWNER |						\
 	NFSATTRBM_OWNERGROUP |						\
 	NFSATTRBM_RAWDEV |						\
 	NFSATTRBM_SPACEAVAIL |						\
 	NFSATTRBM_SPACEFREE |						\
 	NFSATTRBM_SPACETOTAL |						\
 	NFSATTRBM_SPACEUSED |						\
 	NFSATTRBM_TIMEACCESS |						\
 	NFSATTRBM_TIMEDELTA |						\
 	NFSATTRBM_TIMEMETADATA |					\
 	NFSATTRBM_TIMEMODIFY |						\
 	NFSATTRBM_MOUNTEDONFILEID)

#ifdef QUOTA
/*
 * If QUOTA OR in NFSATTRBIT_QUOTAHARD, NFSATTRBIT_QUOTASOFT and
 * NFSATTRBIT_QUOTAUSED.
 */
#define	NFSATTRBIT_SUPP1	(NFSATTRBIT_S1 |			\
				NFSATTRBM_QUOTAHARD |			\
				NFSATTRBM_QUOTASOFT |			\
				NFSATTRBM_QUOTAUSED)
#else
#define	NFSATTRBIT_SUPP1	NFSATTRBIT_S1
#endif

/*
 * NFSATTRBIT_SUPPSETONLY is the OR of NFSATTRBIT_TIMEACCESSSET and
 * NFSATTRBIT_TIMEMODIFYSET.
 */
#define	NFSATTRBIT_SUPPSETONLY	 (NFSATTRBM_TIMEACCESSSET |		\
				 NFSATTRBM_TIMEMODIFYSET)

/*
 * NFSATTRBIT_SETABLE - SETABLE0 - bits 0<->31
 *			SETABLE1 - bits 32<->63
 */
#define	NFSATTRBIT_SETABLE0						\
	(NFSATTRBM_SIZE |						\
	NFSATTRBM_ACL)
#define	NFSATTRBIT_SETABLE1						\
 	(NFSATTRBM_MODE |						\
 	NFSATTRBM_OWNER |						\
 	NFSATTRBM_OWNERGROUP |						\
 	NFSATTRBM_TIMEACCESSSET |					\
 	NFSATTRBM_TIMEMODIFYSET)

/*
 * Set of attributes that the getattr vnode op needs.
 * OR of the following bits.
 * NFSATTRBIT_GETATTR0 - bits 0<->31
 */
#define	NFSATTRBIT_GETATTR0						\
 	(NFSATTRBM_SUPPORTEDATTRS |					\
 	NFSATTRBM_TYPE |						\
 	NFSATTRBM_CHANGE |						\
 	NFSATTRBM_SIZE |						\
 	NFSATTRBM_FSID |						\
 	NFSATTRBM_FILEID |						\
 	NFSATTRBM_MAXREAD)

/*
 * NFSATTRBIT_GETATTR1 - bits 32<->63
 */
#define	NFSATTRBIT_GETATTR1						\
 	(NFSATTRBM_MODE |						\
 	NFSATTRBM_NUMLINKS |						\
 	NFSATTRBM_OWNER |						\
 	NFSATTRBM_OWNERGROUP |						\
 	NFSATTRBM_RAWDEV |						\
 	NFSATTRBM_SPACEUSED |						\
 	NFSATTRBM_TIMEACCESS |						\
 	NFSATTRBM_TIMEMETADATA |					\
 	NFSATTRBM_TIMEMODIFY)

/*
 * Subset of the above that the Write RPC gets.
 * OR of the following bits.
 * NFSATTRBIT_WRITEGETATTR0 - bits 0<->31
 */
#define	NFSATTRBIT_WRITEGETATTR0					\
 	(NFSATTRBM_CHANGE |						\
 	NFSATTRBM_SIZE |						\
 	NFSATTRBM_FSID)

/*
 * NFSATTRBIT_WRITEGETATTR1 - bits 32<->63
 */
#define	NFSATTRBIT_WRITEGETATTR1					\
 	(NFSATTRBM_TIMEMETADATA |					\
 	NFSATTRBM_TIMEMODIFY)

/*
 * Set of attributes that the wccattr operation op needs.
 * OR of the following bits.
 * NFSATTRBIT_WCCATTR0 - bits 0<->31
 */
#define	NFSATTRBIT_WCCATTR0	0

/*
 * NFSATTRBIT_WCCATTR1 - bits 32<->63
 */
#define	NFSATTRBIT_WCCATTR1						\
 	(NFSATTRBM_TIMEMODIFY)

/*
 * NFSATTRBIT_CBGETATTR0 - bits 0<->31
 */
#define	NFSATTRBIT_CBGETATTR0	(NFSATTRBM_CHANGE | NFSATTRBM_SIZE)

/*
 * NFSATTRBIT_CBGETATTR1 - bits 32<->63
 */
#define	NFSATTRBIT_CBGETATTR1		0x0

/*
 * Sets of attributes that require a VFS_STATFS() call to get the
 * values of.
 * NFSATTRBIT_STATFS0 - bits 0<->31
 */
#define	NFSATTRBIT_STATFS0						\
	(NFSATTRBM_LINKSUPPORT |					\
	NFSATTRBM_SYMLINKSUPPORT |					\
	NFSATTRBM_CANSETTIME |						\
 	NFSATTRBM_FILESAVAIL |						\
 	NFSATTRBM_FILESFREE |						\
 	NFSATTRBM_FILESTOTAL |						\
 	NFSATTRBM_HOMOGENEOUS |						\
 	NFSATTRBM_MAXFILESIZE |						\
	NFSATTRBM_MAXNAME |						\
	NFSATTRBM_MAXREAD |						\
	NFSATTRBM_MAXWRITE)

/*
 * NFSATTRBIT_STATFS1 - bits 32<->63
 */
#define	NFSATTRBIT_STATFS1						\
 	(NFSATTRBM_QUOTAHARD |						\
 	NFSATTRBM_QUOTASOFT |						\
 	NFSATTRBM_QUOTAUSED |						\
 	NFSATTRBM_SPACEAVAIL |						\
 	NFSATTRBM_SPACEFREE |						\
 	NFSATTRBM_SPACETOTAL |						\
 	NFSATTRBM_SPACEUSED |						\
	NFSATTRBM_TIMEDELTA)

/*
 * These are the bits that are needed by the nfs_statfs() call.
 * (The regular getattr bits are or'd in so the vnode gets the correct
 *  type, etc.)
 * NFSGETATTRBIT_STATFS0 - bits 0<->31
 */
#define	NFSGETATTRBIT_STATFS0	(NFSATTRBIT_GETATTR0 |			\
				NFSATTRBM_LINKSUPPORT |			\
				NFSATTRBM_SYMLINKSUPPORT |		\
				NFSATTRBM_CANSETTIME |			\
				NFSATTRBM_FILESFREE |			\
				NFSATTRBM_FILESTOTAL |			\
				NFSATTRBM_HOMOGENEOUS |			\
				NFSATTRBM_MAXFILESIZE |			\
				NFSATTRBM_MAXNAME |			\
				NFSATTRBM_MAXREAD |			\
				NFSATTRBM_MAXWRITE)

/*
 * NFSGETATTRBIT_STATFS1 - bits 32<->63
 */
#define	NFSGETATTRBIT_STATFS1	(NFSATTRBIT_GETATTR1 |			\
				NFSATTRBM_SPACEAVAIL |			\
				NFSATTRBM_SPACEFREE |			\
				NFSATTRBM_SPACETOTAL |			\
				NFSATTRBM_TIMEDELTA)

/*
 * Set of attributes for the equivalent of an nfsv3 pathconf rpc.
 * NFSGETATTRBIT_PATHCONF0 - bits 0<->31
 */
#define	NFSGETATTRBIT_PATHCONF0	(NFSATTRBIT_GETATTR0 |			\
			 	NFSATTRBM_CASEINSENSITIVE |		\
			 	NFSATTRBM_CASEPRESERVING |		\
			 	NFSATTRBM_CHOWNRESTRICTED |		\
			 	NFSATTRBM_MAXLINK |			\
			 	NFSATTRBM_MAXNAME)

/*
 * NFSGETATTRBIT_PATHCONF1 - bits 32<->63
 */
#define	NFSGETATTRBIT_PATHCONF1	(NFSATTRBIT_GETATTR1 |			\
				NFSATTRBM_NOTRUNC)

/*
 * Sets of attributes required by readdir and readdirplus.
 * NFSATTRBIT_READDIRPLUS0	(NFSATTRBIT_GETATTR0 | NFSATTRBIT_FILEHANDLE |
 *				 NFSATTRBIT_RDATTRERROR)
 */
#define	NFSATTRBIT_READDIRPLUS0	(NFSATTRBIT_GETATTR0 | NFSATTRBM_FILEHANDLE | \
				NFSATTRBM_RDATTRERROR)
#define	NFSATTRBIT_READDIRPLUS1	NFSATTRBIT_GETATTR1

/*
 * Set of attributes supported by Referral vnodes.
 */
#define	NFSATTRBIT_REFERRAL0	(NFSATTRBM_TYPE | NFSATTRBM_FSID |	\
	NFSATTRBM_RDATTRERROR | NFSATTRBM_FSLOCATIONS)
#define	NFSATTRBIT_REFERRAL1	NFSATTRBM_MOUNTEDONFILEID

/*
 * Structure for data handled by the statfs rpc. Since some fields are
 * u_int64_t, this cannot be used for copying data on/off the wire, due
 * to alignment concerns.
 */
struct nfsstatfs {
	union {
		struct {
			u_int32_t nfsv2sf_tsize;
			u_int32_t nfsv2sf_bsize;
			u_int32_t nfsv2sf_blocks;
			u_int32_t nfsv2sf_bfree;
			u_int32_t nfsv2sf_bavail;
		} sf_nfsv2;
		struct {
			u_int64_t nfsv3sf_tbytes;
			u_int64_t nfsv3sf_fbytes;
			u_int64_t nfsv3sf_abytes;
			u_int64_t nfsv3sf_tfiles;
			u_int64_t nfsv3sf_ffiles;
			u_int64_t nfsv3sf_afiles;
			u_int32_t nfsv3sf_invarsec;
		} sf_nfsv3;
	} sf_un;
};

#define	sf_tsize	sf_un.sf_nfsv2.nfsv2sf_tsize
#define	sf_bsize	sf_un.sf_nfsv2.nfsv2sf_bsize
#define	sf_blocks	sf_un.sf_nfsv2.nfsv2sf_blocks
#define	sf_bfree	sf_un.sf_nfsv2.nfsv2sf_bfree
#define	sf_bavail	sf_un.sf_nfsv2.nfsv2sf_bavail
#define	sf_tbytes	sf_un.sf_nfsv3.nfsv3sf_tbytes
#define	sf_fbytes	sf_un.sf_nfsv3.nfsv3sf_fbytes
#define	sf_abytes	sf_un.sf_nfsv3.nfsv3sf_abytes
#define	sf_tfiles	sf_un.sf_nfsv3.nfsv3sf_tfiles
#define	sf_ffiles	sf_un.sf_nfsv3.nfsv3sf_ffiles
#define	sf_afiles	sf_un.sf_nfsv3.nfsv3sf_afiles
#define	sf_invarsec	sf_un.sf_nfsv3.nfsv3sf_invarsec

/*
 * Now defined using u_int64_t for the 64 bit field(s).
 * (Cannot be used to move data on/off the wire, due to alignment concerns.)
 */
struct nfsfsinfo {
	u_int32_t fs_rtmax;
	u_int32_t fs_rtpref;
	u_int32_t fs_rtmult;
	u_int32_t fs_wtmax;
	u_int32_t fs_wtpref;
	u_int32_t fs_wtmult;
	u_int32_t fs_dtpref;
	u_int64_t fs_maxfilesize;
	struct timespec fs_timedelta;
	u_int32_t fs_properties;
};

/*
 * Bits for fs_properties
 */
#define	NFSV3_FSFLINK		0x1
#define	NFSV3_FSFSYMLINK	0x2
#define	NFSV3_FSFHOMOGENEOUS	0x4
#define	NFSV3_FSFCANSETTIME	0x8

/*
 * Yikes, overload fs_rtmult as fs_maxname for V4.
 */
#define	fs_maxname	fs_rtmult

struct nfsv3_pathconf {
	u_int32_t pc_linkmax;
	u_int32_t pc_namemax;
	u_int32_t pc_notrunc;
	u_int32_t pc_chownrestricted;
	u_int32_t pc_caseinsensitive;
	u_int32_t pc_casepreserving;
};

/*
 * NFS V4 data structures.
 */
struct nfsv4stateid {
	u_int32_t	seqid;
	u_int32_t	other[NFSX_STATEIDOTHER / NFSX_UNSIGNED];
};
typedef struct nfsv4stateid nfsv4stateid_t;

#endif	/* _NFS_NFSPROTO_H_ */
