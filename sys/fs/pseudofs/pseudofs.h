/*-
 * Copyright (c) 2001 Dag-Erling Co�dan Sm�rgrav
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

#ifndef _PSEUDOFS_H_INCLUDED
#define _PSEUDOFS_H_INCLUDED

/*
 * Limits and constants
 */
#define PFS_NAMELEN		24
#define PFS_DELEN		(8 + PFS_NAMELEN)

typedef enum {
	pfstype_none = 0,
	pfstype_root,
	pfstype_dir,
	pfstype_this,
	pfstype_parent,
	pfstype_file,
	pfstype_symlink,
	pfstype_procdir
} pfs_type_t;

/*
 * Flags
 */
#define PFS_RDONLY	0x0000	/* read-only (default) */
#define PFS_WRONLY	0x0001	/* write-only */
#define PFS_RDWR	0x0002	/* read-write */
#define PFS_RAWRD	0x0004	/* raw reader */
#define	PFS_RAWWR	0x0008	/* raw writer */

/*
 * Data structures
 */
struct pfs_info;
struct pfs_node;
struct pfs_bitmap;

/*
 * Filler callback
 */
#define PFS_FILL_ARGS \
	struct thread *td, struct proc *p, struct pfs_node *pn, \
	struct sbuf *sb, struct uio *uio
#define PFS_FILL_PROTO(name) \
	int name(PFS_FILL_ARGS);
typedef int (*pfs_fill_t)(PFS_FILL_ARGS);

/*
 * Attribute callback
 */
struct vattr;
#define PFS_ATTR_ARGS \
	struct thread *td, struct proc *p, struct pfs_node *pn, \
	struct vattr *vap
#define PFS_ATTR_PROTO(name) \
	int name(PFS_ATTR_ARGS);
typedef int (*pfs_attr_t)(PFS_ATTR_ARGS);

struct pfs_bitmap;		/* opaque */

/*
 * pfs_info: describes a pseudofs instance
 */
struct pfs_info {
	char			 pi_name[MFSNAMELEN];
	struct pfs_node		*pi_root;
	/* members below this line aren't initialized */
	/* currently, the mutex is only used to protect the bitmap */
	struct mtx		 pi_mutex;
	struct pfs_bitmap	*pi_bitmap;
};

/*
 * pfs_node: describes a node (file or directory) within a pseudofs
 */
struct pfs_node {
	char			 pn_name[PFS_NAMELEN];
	pfs_type_t		 pn_type;
	union {
		void		*_pn_dummy;
		pfs_fill_t	 _pn_func;
		struct pfs_node	*_pn_nodes;
	} u1;
#define pn_func		u1._pn_func
#define pn_nodes	u1._pn_nodes
	pfs_attr_t		 pn_attr;
	void			*pn_data;
	int			 pn_flags;
	/* members below this line aren't initialized */
	struct pfs_node		*pn_parent;
	u_int32_t		 pn_fileno;
};

#define PFS_NODE(name, type, fill, attr, data, flags) \
        { (name), (type), { (fill) }, (attr), (data), (flags) }
#define PFS_DIR(name, nodes, attr, data, flags) \
        PFS_NODE(name, pfstype_dir, nodes, attr, data, flags)
#define PFS_ROOT(nodes) \
        PFS_NODE("/", pfstype_root, nodes, NULL, NULL, 0)
#define PFS_THIS \
	PFS_NODE(".", pfstype_this, NULL, NULL, NULL, 0)
#define PFS_PARENT \
	PFS_NODE("..", pfstype_parent, NULL, NULL, NULL, 0)
#define PFS_FILE(name, func, attr, data, flags) \
	PFS_NODE(name, pfstype_file, func, attr, data, flags)
#define PFS_SYMLINK(name, func, attr, data, flags) \
	PFS_NODE(name, pfstype_symlink, func, attr, data, flags)
#define PFS_PROCDIR(nodes, attr, data, flags) \
        PFS_NODE("", pfstype_procdir, nodes, attr, data, flags)
#define PFS_LASTNODE \
	PFS_NODE("", pfstype_none, NULL, NULL, NULL, 0)

/*
 * VFS interface
 */
int	 pfs_mount		(struct pfs_info *pi,
				 struct mount *mp, char *path, caddr_t data,
				 struct nameidata *ndp, struct thread *td);
int	 pfs_unmount		(struct mount *mp, int mntflags,
				 struct thread *td);
int	 pfs_root		(struct mount *mp, struct vnode **vpp);
int	 pfs_statfs		(struct mount *mp, struct statfs *sbp,
				 struct thread *td);
int	 pfs_init		(struct pfs_info *pi, struct vfsconf *vfc);
int	 pfs_uninit		(struct pfs_info *pi, struct vfsconf *vfc);

/*
 * Now for some initialization magic...
 */
#define PSEUDOFS(name, root, version)					\
									\
static struct pfs_info name##_info = {					\
	#name,								\
	&(root)								\
};									\
									\
static int								\
_##name##_mount(struct mount *mp, char *path, caddr_t data,		\
	     struct nameidata *ndp, struct thread *td) {		\
        return pfs_mount(&name##_info, mp, path, data, ndp, td);	\
}									\
									\
static int								\
_##name##_init(struct vfsconf *vfc) {					\
        return pfs_init(&name##_info, vfc);				\
}									\
									\
static int								\
_##name##_uninit(struct vfsconf *vfc) {					\
        return pfs_uninit(&name##_info, vfc);				\
}									\
									\
static struct vfsops name##_vfsops = {					\
	_##name##_mount,						\
	vfs_stdstart,							\
	pfs_unmount,							\
	pfs_root,							\
	vfs_stdquotactl,						\
	pfs_statfs,							\
	vfs_stdsync,							\
	vfs_stdvget,							\
	vfs_stdfhtovp,							\
	vfs_stdcheckexp,						\
	vfs_stdvptofh,							\
	_##name##_init,							\
	_##name##_uninit,						\
	vfs_stdextattrctl,						\
};									\
VFS_SET(name##_vfsops, name, VFCF_SYNTHETIC);				\
MODULE_VERSION(name, version);						\
MODULE_DEPEND(name, pseudofs, 2, 2, 2);

#endif
