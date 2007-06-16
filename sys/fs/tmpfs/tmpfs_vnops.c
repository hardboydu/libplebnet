/*	$NetBSD: tmpfs_vnops.c,v 1.20 2006/01/26 20:07:34 jmmv Exp $	*/

/*
 * Copyright (c) 2005 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Julio M. Merino Vidal, developed as part of Google's Summer of Code
 * 2005 program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * tmpfs vnode interface.
 */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/lockf.h>
#include <sys/namei.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/unistd.h>
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <sys/sched.h>
#include <sys/sf_buf.h>
#include <machine/_inttypes.h>

#include <fs/fifofs/fifo.h>
#include <fs/tmpfs/tmpfs_vnops.h>
#include <fs/tmpfs/tmpfs.h>

/* --------------------------------------------------------------------- */

/*
 * vnode operations vector used for files stored in a tmpfs file system.
 */
struct vop_vector tmpfs_vnodeop_entries = {
	.vop_default =			&default_vnodeops,
	.vop_lookup =			vfs_cache_lookup,
	.vop_cachedlookup =		tmpfs_lookup,
	.vop_create =			tmpfs_create,
	.vop_mknod =			tmpfs_mknod,
	.vop_open =			tmpfs_open,
	.vop_close =			tmpfs_close,
	.vop_access =			tmpfs_access,
	.vop_getattr =			tmpfs_getattr,
	.vop_setattr =			tmpfs_setattr,
	.vop_read =			tmpfs_read,
	.vop_write =			tmpfs_write,
	.vop_fsync =			tmpfs_fsync,
	.vop_remove =			tmpfs_remove,
	.vop_link =			tmpfs_link,
	.vop_rename =			tmpfs_rename,
	.vop_mkdir =			tmpfs_mkdir,
	.vop_rmdir =			tmpfs_rmdir,
	.vop_symlink = 			tmpfs_symlink,
	.vop_readdir =			tmpfs_readdir,
	.vop_readlink =			tmpfs_readlink,
	.vop_inactive =			tmpfs_inactive,
	.vop_reclaim =			tmpfs_reclaim,
	.vop_print =			tmpfs_print,
	.vop_pathconf =			tmpfs_pathconf,
	.vop_advlock =			tmpfs_advlock,
	.vop_bmap =			VOP_EOPNOTSUPP,
};

/* --------------------------------------------------------------------- */

int
tmpfs_lookup(struct vop_cachedlookup_args *v)
{
	struct vnode *dvp = v->a_dvp;
	struct vnode **vpp = v->a_vpp;
	struct componentname *cnp = v->a_cnp;
	struct thread *td = cnp->cn_thread;

	int error;
	struct tmpfs_dirent *de;
	struct tmpfs_node *dnode;

	dnode = VP_TO_TMPFS_DIR(dvp);
	*vpp = NULLVP;

	/* Check accessibility of requested node as a first step. */
	error = VOP_ACCESS(dvp, VEXEC, cnp->cn_cred, td);
	if (error != 0)
		goto out;

	/* We cannot be requesting the parent directory of the root node. */
	MPASS(IMPLIES(dnode->tn_type == VDIR &&
	    dnode->tn_dir.tn_parent == dnode,
	    !(cnp->cn_flags & ISDOTDOT)));

	if (cnp->cn_flags & ISDOTDOT) {
		VOP_UNLOCK(dvp, 0, td);

		/* Allocate a new vnode on the matching entry. */
		error = tmpfs_alloc_vp(dvp->v_mount, dnode->tn_dir.tn_parent, vpp, td);

		vn_lock(dvp, LK_EXCLUSIVE | LK_RETRY, td);

		dnode->tn_dir.tn_parent->tn_lookup_dirent = NULL;
	} else if (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.') {
		VREF(dvp);
		*vpp = dvp;
		dnode->tn_lookup_dirent = NULL;
		error = 0;
	} else {
		de = tmpfs_dir_lookup(dnode, cnp);
		if (de == NULL) {
			/* The entry was not found in the directory.
			 * This is OK if we are creating or renaming an
			 * entry and are working on the last component of
			 * the path name. */
			if ((cnp->cn_flags & ISLASTCN) &&
			    (cnp->cn_nameiop == CREATE || \
			    cnp->cn_nameiop == RENAME)) {
				error = VOP_ACCESS(dvp, VWRITE, cnp->cn_cred,
				    cnp->cn_thread);
				if (error != 0)
					goto out;

				/* Keep the component name in the buffer for
				 * future uses. */
				cnp->cn_flags |= SAVENAME;

				error = EJUSTRETURN;
			} else
				error = ENOENT;
		} else {
			struct tmpfs_node *tnode;

			/* The entry was found, so get its associated
			 * tmpfs_node. */
			tnode = de->td_node;

			/* If we are not at the last path component and
			 * found a non-directory or non-link entry (which
			 * may itself be pointing to a directory), raise
			 * an error. */
			if ((tnode->tn_type != VDIR &&
			    tnode->tn_type != VLNK) &&
			    !(cnp->cn_flags & ISLASTCN)) {
				error = ENOTDIR;
				goto out;
			}

			/* If we are deleting or renaming the entry, keep
			 * track of its tmpfs_dirent so that it can be
			 * easily deleted later. */
			if ((cnp->cn_flags & ISLASTCN) &&
			    (cnp->cn_nameiop == DELETE ||
			    cnp->cn_nameiop == RENAME)) {
				error = VOP_ACCESS(dvp, VWRITE, cnp->cn_cred,
				    cnp->cn_thread);
				if (error != 0)
					goto out;
			 
				/* Allocate a new vnode on the matching entry. */
				error = tmpfs_alloc_vp(dvp->v_mount, tnode, vpp, td);
				if (error != 0)
					goto out;

				if ((dnode->tn_mode & S_ISTXT) &&
				  VOP_ACCESS(dvp, VADMIN, cnp->cn_cred, cnp->cn_thread) &&
				  VOP_ACCESS(*vpp, VADMIN, cnp->cn_cred, cnp->cn_thread)) {
					error = EPERM;
					vput(*vpp);
					*vpp = NULL;
					goto out;
				} 
				tnode->tn_lookup_dirent = de;
				cnp->cn_flags |= SAVENAME;
			}
			else
				error = tmpfs_alloc_vp(dvp->v_mount, tnode, vpp, td);

		}
	}

	/* Store the result of this lookup in the cache.  Avoid this if the
	 * request was for creation, as it does not improve timings on
	 * emprical tests. */
	if ((cnp->cn_flags & MAKEENTRY) && cnp->cn_nameiop != CREATE)
		cache_enter(dvp, *vpp, cnp);

out:
	/* If there were no errors, *vpp cannot be null and it must be
	 * locked. */
	MPASS(IFF(error == 0, *vpp != NULLVP && VOP_ISLOCKED(*vpp, td)));

	return error;
}

/* --------------------------------------------------------------------- */

int
tmpfs_create(struct vop_create_args *v)
{
	struct vnode *dvp = v->a_dvp;
	struct vnode **vpp = v->a_vpp;
	struct componentname *cnp = v->a_cnp;
	struct vattr *vap = v->a_vap;

	MPASS(vap->va_type == VREG || vap->va_type == VSOCK);

	return tmpfs_alloc_file(dvp, vpp, vap, cnp, NULL);
}
/* --------------------------------------------------------------------- */

int
tmpfs_mknod(struct vop_mknod_args *v)
{
	struct vnode *dvp = v->a_dvp;
	struct vnode **vpp = v->a_vpp;
	struct componentname *cnp = v->a_cnp;
	struct vattr *vap = v->a_vap;

	if (vap->va_type != VBLK && vap->va_type != VCHR &&
	    vap->va_type != VFIFO)
		return EINVAL;

	return tmpfs_alloc_file(dvp, vpp, vap, cnp, NULL);
}

/* --------------------------------------------------------------------- */

int
tmpfs_open(struct vop_open_args *v)
{
	struct vnode *vp = v->a_vp;
	int mode = v->a_mode;

	int error;
	struct tmpfs_node *node;

	MPASS(VOP_ISLOCKED(vp, v->a_td));

	node = VP_TO_TMPFS_NODE(vp);
	
	/* The file is still active but all its names have been removed
	 * (e.g. by a "rmdir $(pwd)").  It cannot be opened any more as
	 * it is about to die. */
	if (node->tn_links < 1)
		return (ENOENT);

	/* If the file is marked append-only, deny write requests. */
	if (node->tn_flags & APPEND && (mode & (FWRITE | O_APPEND)) == FWRITE)
		error = EPERM;
	else {
		error = 0;
		vnode_create_vobject(vp, node->tn_size, v->a_td);	
	}

	MPASS(VOP_ISLOCKED(vp, v->a_td));
	return error;
}

/* --------------------------------------------------------------------- */

int
tmpfs_close(struct vop_close_args *v)
{
	struct vnode *vp = v->a_vp;

	struct tmpfs_node *node;

	MPASS(VOP_ISLOCKED(vp, v->a_td));

	node = VP_TO_TMPFS_NODE(vp);

	if (node->tn_links > 0) {
		/* Update node times.  No need to do it if the node has
		 * been deleted, because it will vanish after we return. */
		tmpfs_update(vp);
	}

	return 0;
}

/* --------------------------------------------------------------------- */

int
tmpfs_access(struct vop_access_args *v)
{
	struct vnode *vp = v->a_vp;
	int mode = v->a_mode;
	struct ucred *cred = v->a_cred;

	int error;
	struct tmpfs_node *node;

	MPASS(VOP_ISLOCKED(vp, v->a_td));

	node = VP_TO_TMPFS_NODE(vp);

	switch (vp->v_type) {
	case VDIR:
		/* FALLTHROUGH */
	case VLNK:
		/* FALLTHROUGH */
	case VREG:
		if (mode & VWRITE && vp->v_mount->mnt_flag & MNT_RDONLY) {
			error = EROFS;
			goto out;
		}
		break;

	case VBLK:
		/* FALLTHROUGH */
	case VCHR:
		/* FALLTHROUGH */
	case VSOCK:
		/* FALLTHROUGH */
	case VFIFO:
		break;

	default:
		error = EINVAL;
		goto out;
	}

	if (mode & VWRITE && node->tn_flags & IMMUTABLE) {
		error = EPERM;
		goto out;
	}

	error = vaccess(vp->v_type, node->tn_mode, node->tn_uid,
	    node->tn_gid, mode, cred, NULL);

out:
	MPASS(VOP_ISLOCKED(vp, v->a_td));

	return error;
}

/* --------------------------------------------------------------------- */

int
tmpfs_getattr(struct vop_getattr_args *v)
{
	struct vnode *vp = v->a_vp;
	struct vattr *vap = v->a_vap;

	struct tmpfs_node *node;

	node = VP_TO_TMPFS_NODE(vp);

	VATTR_NULL(vap);

	tmpfs_update(vp);

	vap->va_type = vp->v_type;
	vap->va_mode = node->tn_mode;
	vap->va_nlink = node->tn_links;
	vap->va_uid = node->tn_uid;
	vap->va_gid = node->tn_gid;
	vap->va_fsid = vp->v_mount->mnt_stat.f_fsid.val[0];
	vap->va_fileid = node->tn_id;
	vap->va_size = node->tn_size;
	vap->va_blocksize = PAGE_SIZE;
	vap->va_atime = node->tn_atime;
	vap->va_mtime = node->tn_mtime;
	vap->va_ctime = node->tn_ctime;
	vap->va_birthtime = node->tn_birthtime;
	vap->va_gen = node->tn_gen;
	vap->va_flags = node->tn_flags;
	vap->va_rdev = (vp->v_type == VBLK || vp->v_type == VCHR) ?
		node->tn_rdev : VNOVAL;
	vap->va_bytes = round_page(node->tn_size);
	vap->va_filerev = VNOVAL;
	vap->va_vaflags = 0;
	vap->va_spare = VNOVAL; /* XXX */

	return 0;
}

/* --------------------------------------------------------------------- */

/* XXX Should this operation be atomic?  I think it should, but code in
 * XXX other places (e.g., ufs) doesn't seem to be... */
int
tmpfs_setattr(struct vop_setattr_args *v)
{
	struct vnode *vp = v->a_vp;
	struct vattr *vap = v->a_vap;
	struct ucred *cred = v->a_cred;
	struct thread *l = v->a_td;

	int error;

	MPASS(VOP_ISLOCKED(vp, l));

	error = 0;

	/* Abort if any unsettable attribute is given. */
	if (vap->va_type != VNON ||
	    vap->va_nlink != VNOVAL ||
	    vap->va_fsid != VNOVAL ||
	    vap->va_fileid != VNOVAL ||
	    vap->va_blocksize != VNOVAL ||
	    vap->va_gen != VNOVAL ||
	    vap->va_rdev != VNOVAL ||
	    vap->va_bytes != VNOVAL)
		error = EINVAL;

	if (error == 0 && (vap->va_flags != VNOVAL))
		error = tmpfs_chflags(vp, vap->va_flags, cred, l);

	if (error == 0 && (vap->va_size != VNOVAL))
		error = tmpfs_chsize(vp, vap->va_size, cred, l);

	if (error == 0 && (vap->va_uid != VNOVAL || vap->va_gid != VNOVAL))
		error = tmpfs_chown(vp, vap->va_uid, vap->va_gid, cred,
		    l);

	if (error == 0 && (vap->va_mode != (mode_t)VNOVAL))
		error = tmpfs_chmod(vp, vap->va_mode, cred, l);

	if (error == 0 && ((vap->va_atime.tv_sec != VNOVAL &&
	    vap->va_atime.tv_nsec != VNOVAL) ||
	    (vap->va_mtime.tv_sec != VNOVAL &&
	    vap->va_mtime.tv_nsec != VNOVAL) ||
	    (vap->va_birthtime.tv_sec != VNOVAL &&
	    vap->va_birthtime.tv_nsec != VNOVAL)))
		error = tmpfs_chtimes(vp, &vap->va_atime, &vap->va_mtime, 
			&vap->va_birthtime, vap->va_vaflags, cred, l);

	/* Update the node times.  We give preference to the error codes
	 * generated by this function rather than the ones that may arise
	 * from tmpfs_update. */
	tmpfs_update(vp);

	MPASS(VOP_ISLOCKED(vp, l));

	return error;
}

/* --------------------------------------------------------------------- */
static int
tmpfs_uio_xfer(struct tmpfs_mount *tmp, struct tmpfs_node *node, 
    struct uio *uio, vm_object_t uobj)
{
	struct sf_buf *sf;
	vm_pindex_t idx;
	vm_offset_t d;
	vm_page_t m;
	size_t len;
	int error = 0;

	/* uobj - locked by caller */

	VM_OBJECT_LOCK(uobj);
	vm_object_pip_add(uobj, 1);
	while (error == 0 && uio->uio_resid > 0) {
		if (node->tn_size <= uio->uio_offset)
			break;

		len = MIN(node->tn_size - uio->uio_offset, uio->uio_resid);
		if (len == 0)
			break;

		idx = OFF_TO_IDX(uio->uio_offset);
		d = uio->uio_offset - IDX_TO_OFF(idx);
		len = MIN(len, (PAGE_SIZE - d));
		m = vm_page_grab(uobj, idx, VM_ALLOC_NORMAL | VM_ALLOC_RETRY);
		if (uio->uio_rw == UIO_READ && m->valid != VM_PAGE_BITS_ALL)
			if (vm_pager_get_pages(uobj, &m, 1, 0) != VM_PAGER_OK)
				vm_page_zero_invalid(m, TRUE);
		VM_OBJECT_UNLOCK(uobj);
		sched_pin();
		sf = sf_buf_alloc(m, SFB_CPUPRIVATE);
		error = uiomove((void *)(sf_buf_kva(sf) + d), len, uio);
		sf_buf_free(sf);
		sched_unpin();
		VM_OBJECT_LOCK(uobj);
		vm_page_lock_queues();
		if (error == 0 && uio->uio_rw == UIO_WRITE) {
			vm_page_set_validclean(m, d, len);
			vm_page_zero_invalid(m, TRUE);
			vm_page_dirty(m);
		}
		vm_page_activate(m);
		vm_page_wakeup(m);
		vm_page_unlock_queues();
	}
	vm_object_pip_subtract(uobj, 1);
	VM_OBJECT_UNLOCK(uobj);
	return error;
}

int
tmpfs_read(struct vop_read_args *v)
{
	struct vnode *vp = v->a_vp;
	struct uio *uio = v->a_uio;

	struct tmpfs_node *node;
	vm_object_t uobj;

	int error;

	node = VP_TO_TMPFS_NODE(vp);

	if (vp->v_type != VREG) {
		error = EISDIR;
		goto out;
	}

	if (uio->uio_offset < 0) {
		error = EINVAL;
		goto out;
	}

	node->tn_status |= TMPFS_NODE_ACCESSED;

	uobj = node->tn_reg.tn_aobj;
	error = tmpfs_uio_xfer(VFS_TO_TMPFS(vp->v_mount), node, uio, uobj);

out:

	return error;
}

/* --------------------------------------------------------------------- */

int
tmpfs_write(struct vop_write_args *v)
{
	struct vnode *vp = v->a_vp;
	struct uio *uio = v->a_uio;
	int ioflag = v->a_ioflag;
	struct thread *td = uio->uio_td;

	boolean_t extended;
	int error;
	off_t oldsize;
	struct tmpfs_node *node;
	vm_object_t uobj;

	node = VP_TO_TMPFS_NODE(vp);
	oldsize = node->tn_size;

	if (uio->uio_offset < 0 || vp->v_type != VREG) {
		error = EINVAL;
		goto out;
	}

	if (uio->uio_resid == 0) {
		error = 0;
		goto out;
	}

	if (ioflag & IO_APPEND)
		uio->uio_offset = node->tn_size;
	
	if (uio->uio_offset + uio->uio_resid > 
	  VFS_TO_TMPFS(vp->v_mount)->tm_maxfilesize)
		return (EFBIG);

	if (vp->v_type == VREG && td != NULL) {
		PROC_LOCK(td->td_proc);
		if (uio->uio_offset + uio->uio_resid >
		  lim_cur(td->td_proc, RLIMIT_FSIZE)) {
			psignal(td->td_proc, SIGXFSZ);
			PROC_UNLOCK(td->td_proc);
			return (EFBIG);
		}
		PROC_UNLOCK(td->td_proc);
	}

	extended = uio->uio_offset + uio->uio_resid > node->tn_size;
	if (extended) {
		error = tmpfs_reg_resize(vp, uio->uio_offset + uio->uio_resid);
		if (error != 0)
			goto out;
	}

	uobj = node->tn_reg.tn_aobj;
	error = tmpfs_uio_xfer(VFS_TO_TMPFS(vp->v_mount), node, uio, uobj);

	node->tn_status |= TMPFS_NODE_ACCESSED | TMPFS_NODE_MODIFIED |
	    (extended ? TMPFS_NODE_CHANGED : 0);

	if (node->tn_mode & (S_ISUID | S_ISGID)) {
		if (priv_check_cred(v->a_cred, PRIV_VFS_RETAINSUGID, 0))
			node->tn_mode &= ~(S_ISUID | S_ISGID);
	}

	if (error != 0)
		(void)tmpfs_reg_resize(vp, oldsize);

out:
	MPASS(IMPLIES(error == 0, uio->uio_resid == 0));
	MPASS(IMPLIES(error != 0, oldsize == node->tn_size));

	return error;
}

/* --------------------------------------------------------------------- */

int
tmpfs_fsync(struct vop_fsync_args *v)
{
	struct vnode *vp = v->a_vp;

	MPASS(VOP_ISLOCKED(vp, v->a_td));

	tmpfs_update(vp);

	return 0;
}

/* --------------------------------------------------------------------- */

int
tmpfs_remove(struct vop_remove_args *v)
{
	struct vnode *dvp = v->a_dvp;
	struct vnode *vp = v->a_vp;

	int error;
	struct tmpfs_dirent *de;
	struct tmpfs_mount *tmp;
	struct tmpfs_node *dnode;
	struct tmpfs_node *node;

	MPASS(VOP_ISLOCKED(dvp, v->a_cnp->cn_thread));
	MPASS(VOP_ISLOCKED(vp, v->a_cnp->cn_thread));

	if (vp->v_type == VDIR) {
		error = EISDIR;
		goto out;
	}

	dnode = VP_TO_TMPFS_DIR(dvp);
	node = VP_TO_TMPFS_NODE(vp);
	tmp = VFS_TO_TMPFS(vp->v_mount);
	de = node->tn_lookup_dirent;
	MPASS(de != NULL);

	/* Files marked as immutable or append-only cannot be deleted. */
	if ((node->tn_flags & (IMMUTABLE | APPEND | NOUNLINK)) ||
	    (dnode->tn_flags & APPEND)) {
		error = EPERM;
		goto out;
	}

	/* Remove the entry from the directory; as it is a file, we do not
	 * have to change the number of hard links of the directory. */
	tmpfs_dir_detach(dvp, de);

	/* Free the directory entry we just deleted.  Note that the node
	 * referred by it will not be removed until the vnode is really
	 * reclaimed. */
	tmpfs_free_dirent(tmp, de, TRUE);

	if (node->tn_links > 0)
		node->tn_status |= TMPFS_NODE_ACCESSED | TMPFS_NODE_CHANGED | \
	    TMPFS_NODE_MODIFIED;
	error = 0;

out:

	return error;
}

/* --------------------------------------------------------------------- */

int
tmpfs_link(struct vop_link_args *v)
{
	struct vnode *dvp = v->a_tdvp;
	struct vnode *vp = v->a_vp;
	struct componentname *cnp = v->a_cnp;

	int error;
	struct tmpfs_dirent *de;
	struct tmpfs_node *dnode;
	struct tmpfs_node *node;

	MPASS(VOP_ISLOCKED(dvp, cnp->cn_thread));
	MPASS(cnp->cn_flags & HASBUF);
	MPASS(dvp != vp); /* XXX When can this be false? */

	dnode = VP_TO_TMPFS_DIR(dvp);
	node = VP_TO_TMPFS_NODE(vp);

	/* XXX: Why aren't the following two tests done by the caller? */

	/* Hard links of directories are forbidden. */
	if (vp->v_type == VDIR) {
		error = EPERM;
		goto out;
	}

	/* Cannot create cross-device links. */
	if (dvp->v_mount != vp->v_mount) {
		error = EXDEV;
		goto out;
	}

	/* Ensure that we do not overflow the maximum number of links imposed
	 * by the system. */
	MPASS(node->tn_links <= LINK_MAX);
	if (node->tn_links == LINK_MAX) {
		error = EMLINK;
		goto out;
	}

	/* We cannot create links of files marked immutable or append-only. */
	if (node->tn_flags & (IMMUTABLE | APPEND)) {
		error = EPERM;
		goto out;
	}

	/* Allocate a new directory entry to represent the node. */
	error = tmpfs_alloc_dirent(VFS_TO_TMPFS(vp->v_mount), node,
	    cnp->cn_nameptr, cnp->cn_namelen, &de);
	if (error != 0)
		goto out;

	/* Insert the new directory entry into the appropriate directory. */
	tmpfs_dir_attach(dvp, de);

	/* vp link count has changed, so update node times. */
	node->tn_status |= TMPFS_NODE_CHANGED;
	tmpfs_update(vp);

	error = 0;
out:
	
	return error;
}

/* --------------------------------------------------------------------- */

int
tmpfs_rename(struct vop_rename_args *v)
{
	struct vnode *fdvp = v->a_fdvp;
	struct vnode *fvp = v->a_fvp;
	struct componentname *fcnp = v->a_fcnp;
	struct vnode *tdvp = v->a_tdvp;
	struct vnode *tvp = v->a_tvp;
	struct componentname *tcnp = v->a_tcnp;
	struct tmpfs_node *tnode = 0; /* pacify gcc */

	char *newname;
	int error;
	struct tmpfs_dirent *de;
	struct tmpfs_mount *tmp;
	struct tmpfs_node *fdnode;
	struct tmpfs_node *fnode;
	struct tmpfs_node *tdnode;

	MPASS(VOP_ISLOCKED(tdvp, tcnp->cn_thread));
	MPASS(IMPLIES(tvp != NULL, VOP_ISLOCKED(tvp, tcnp->cn_thread)));
	MPASS(fcnp->cn_flags & HASBUF);
	MPASS(tcnp->cn_flags & HASBUF);

	fdnode = VP_TO_TMPFS_DIR(fdvp);
	fnode = VP_TO_TMPFS_NODE(fvp);
	de = fnode->tn_lookup_dirent;

	/* Disallow cross-device renames.
	 * XXX Why isn't this done by the caller? */
	if (fvp->v_mount != tdvp->v_mount ||
	    (tvp != NULL && fvp->v_mount != tvp->v_mount)) {
		error = EXDEV;
		goto out;
	}

	tmp = VFS_TO_TMPFS(tdvp->v_mount);
	tdnode = VP_TO_TMPFS_DIR(tdvp);

	/* If source and target are the same file, there is nothing to do. */
	if (fvp == tvp) {
		error = 0;
		goto out;
	}

	/* Avoid manipulating '.' and '..' entries. */
	if (de == NULL) {
		MPASS(fvp->v_type == VDIR);
		error = EINVAL;
		goto out;
	}
	MPASS(de->td_node == fnode);

	/* If re-naming a directory to another preexisting directory 
	 * ensure that the target directory is empty so that its
	 * removal causes no side effects. 
	 * Kern_rename gurantees the destination to be a directory
	 * if the source is one. */
	if (tvp != NULL) {
		tnode = VP_TO_TMPFS_NODE(tvp);
		
		if ((tnode->tn_flags & (NOUNLINK | IMMUTABLE | APPEND)) ||
		    (tdnode->tn_flags & (APPEND | IMMUTABLE))) {
			error = EPERM;
			goto out;
		}

	    	if ((de->td_node->tn_type == VDIR) && (tnode->tn_size > 0)) {
			error = ENOTEMPTY;
			goto out;
		}
	}

	/* If we need to move the directory between entries, lock the
	 * source so that we can safely operate on it. */
	if (fdnode != tdnode) {
		error = vn_lock(fdvp, LK_EXCLUSIVE | LK_RETRY, tcnp->cn_thread);
		if (error != 0)
			goto out;
	}

	if ((fnode->tn_flags & (NOUNLINK | IMMUTABLE | APPEND))
	    || (fdnode->tn_flags & (APPEND | IMMUTABLE))) {
		error = EPERM;
		goto out_locked;
	}

	/* Ensure that we have enough memory to hold the new name, if it
	 * has to be changed. */
	if (fcnp->cn_namelen != tcnp->cn_namelen ||
	    memcmp(fcnp->cn_nameptr, tcnp->cn_nameptr, fcnp->cn_namelen) != 0) {
		newname = tmpfs_str_zone_alloc(&tmp->tm_str_pool, M_WAITOK,
		    tcnp->cn_namelen);
		if (newname == NULL) {
			error = ENOSPC;
			goto out_locked;
		}
	} else
		newname = NULL;

	/* If the node is being moved to another directory, we have to do
	 * the move. */
	if (fdnode != tdnode) {
		/* In case we are moving a directory, we have to adjust its
		 * parent to point to the new parent. */
		if (de->td_node->tn_type == VDIR) {
			struct tmpfs_node *n;

			/* Ensure the target directory is not a child of the
			 * directory being moved.  Otherwise, we'd end up
			 * with stale nodes. */
			n = tdnode;
			while (n != n->tn_dir.tn_parent) {
				if (n == fnode) {
					error = EINVAL;
					if (newname != NULL)
						tmpfs_str_zone_free(&tmp->tm_str_pool,
						    newname, tcnp->cn_namelen);
					goto out_locked;
				}
				n = n->tn_dir.tn_parent;
			}

			/* Adjust the parent pointer. */
			TMPFS_VALIDATE_DIR(fnode);
			de->td_node->tn_dir.tn_parent = tdnode;

			/* As a result of changing the target of the '..'
			 * entry, the link count of the source and target
			 * directories has to be adjusted. */
			fdnode->tn_links--;
			tdnode->tn_links++;
		}

		/* Do the move: just remove the entry from the source directory
		 * and insert it into the target one. */
		tmpfs_dir_detach(fdvp, de);
		tmpfs_dir_attach(tdvp, de);
	}

	/* If the name has changed, we need to make it effective by changing
	 * it in the directory entry. */
	if (newname != NULL) {
		MPASS(tcnp->cn_namelen <= MAXNAMLEN);

		tmpfs_str_zone_free(&tmp->tm_str_pool, de->td_name,
		    de->td_namelen);
		de->td_namelen = (uint16_t)tcnp->cn_namelen;
		memcpy(newname, tcnp->cn_nameptr, tcnp->cn_namelen);
		de->td_name = newname;

		fnode->tn_status |= TMPFS_NODE_CHANGED;
		tdnode->tn_status |= TMPFS_NODE_MODIFIED;
	}

	/* If we are overwriting an entry, we have to remove the old one
	 * from the target directory. */
	if (tvp != NULL) {
		/* Remove the old entry from the target directory. */
		de = tnode->tn_lookup_dirent;
		tmpfs_dir_detach(tdvp, de);

		/* Free the directory entry we just deleted.  Note that the
		 * node referred by it will not be removed until the vnode is
		 * really reclaimed. */
		tmpfs_free_dirent(VFS_TO_TMPFS(tvp->v_mount), de, TRUE);
	}

	error = 0;

out_locked:
	if (fdnode != tdnode)
		VOP_UNLOCK(fdvp, 0, tcnp->cn_thread);

out:
	/* Release target nodes. */
	/* XXX: I don't understand when tdvp can be the same as tvp, but
	 * other code takes care of this... */
	if (tdvp == tvp)
		vrele(tdvp);
	else
		vput(tdvp);
	if (tvp != NULL)
		vput(tvp);

	/* Release source nodes. */
	vrele(fdvp);
	vrele(fvp);

	return error;
}

/* --------------------------------------------------------------------- */

int
tmpfs_mkdir(struct vop_mkdir_args *v)
{
	struct vnode *dvp = v->a_dvp;
	struct vnode **vpp = v->a_vpp;
	struct componentname *cnp = v->a_cnp;
	struct vattr *vap = v->a_vap;

	MPASS(vap->va_type == VDIR);

	return tmpfs_alloc_file(dvp, vpp, vap, cnp, NULL);
}

/* --------------------------------------------------------------------- */

int
tmpfs_rmdir(struct vop_rmdir_args *v)
{
	struct vnode *dvp = v->a_dvp;
	struct vnode *vp = v->a_vp;

	int error;
	struct tmpfs_dirent *de;
	struct tmpfs_mount *tmp;
	struct tmpfs_node *dnode;
	struct tmpfs_node *node;

	MPASS(VOP_ISLOCKED(dvp, v->a_cnp->cn_thread));
	MPASS(VOP_ISLOCKED(vp, v->a_cnp->cn_thread));

	tmp = VFS_TO_TMPFS(dvp->v_mount);
	dnode = VP_TO_TMPFS_DIR(dvp);
	node = VP_TO_TMPFS_DIR(vp);

	
	/* Directories with more than two entries ('.' and '..') cannot be 
	  * removed. */ 
	 if (node->tn_size > 0) { 
		 error = ENOTEMPTY; 
		 goto out; 
	 } 

	if ((dnode->tn_flags & APPEND)
	    || (node->tn_flags & (NOUNLINK | IMMUTABLE | APPEND))) {
		error = EPERM;
		goto out;
	}

	/* This invariant holds only if we are not trying to remove "..". 
	  * We checked for that above so this is safe now. */ 
	MPASS(node->tn_dir.tn_parent == dnode);

	/* Get the directory entry associated with node (vp).  This was
	 * filled by tmpfs_lookup while looking up the entry. */
	de = node->tn_lookup_dirent;
	MPASS(TMPFS_DIRENT_MATCHES(de,
	    v->a_cnp->cn_nameptr,
	    v->a_cnp->cn_namelen));

	/* Check flags to see if we are allowed to remove the directory. */
	if (dnode->tn_flags & APPEND
		|| node->tn_flags & (NOUNLINK | IMMUTABLE | APPEND)) {
		error = EPERM;
		goto out;
	}

	/* Detach the directory entry from the directory (dnode). */
	tmpfs_dir_detach(dvp, de);

	node->tn_links--;
	node->tn_status |= TMPFS_NODE_ACCESSED | TMPFS_NODE_CHANGED | \
	    TMPFS_NODE_MODIFIED;
	node->tn_dir.tn_parent->tn_links--;
	node->tn_dir.tn_parent->tn_status |= TMPFS_NODE_ACCESSED | \
	    TMPFS_NODE_CHANGED | TMPFS_NODE_MODIFIED;

	cache_purge(dvp); 
	cache_purge(vp);

	/* Free the directory entry we just deleted.  Note that the node
	 * referred by it will not be removed until the vnode is really
	 * reclaimed. */
	tmpfs_free_dirent(tmp, de, TRUE);

	/* Release the deleted vnode (will destroy the node, notify
	 * interested parties and clean it from the cache). */

	dnode->tn_status |= TMPFS_NODE_CHANGED;
	tmpfs_update(dvp);

	error = 0;

out:
	return error;
}

/* --------------------------------------------------------------------- */

int
tmpfs_symlink(struct vop_symlink_args *v)
{
	struct vnode *dvp = v->a_dvp;
	struct vnode **vpp = v->a_vpp;
	struct componentname *cnp = v->a_cnp;
	struct vattr *vap = v->a_vap;
	char *target = v->a_target;

#ifdef notyet /* XXX FreeBSD BUG: kern_symlink is not setting VLNK */
	MPASS(vap->va_type == VLNK);
#else
	vap->va_type = VLNK;
#endif

	return tmpfs_alloc_file(dvp, vpp, vap, cnp, target);
}

/* --------------------------------------------------------------------- */

int
tmpfs_readdir(struct vop_readdir_args *v)
{
	struct vnode *vp = v->a_vp;
	struct uio *uio = v->a_uio;
	int *eofflag = v->a_eofflag;
	u_long **cookies = v->a_cookies;
	int *ncookies = v->a_ncookies;

	int error;
	off_t startoff;
	off_t cnt;
	struct tmpfs_node *node;

	/* This operation only makes sense on directory nodes. */
	if (vp->v_type != VDIR) {
		error = ENOTDIR;
		goto out;
	}

	node = VP_TO_TMPFS_DIR(vp);

	startoff = uio->uio_offset;

	cnt = 0;
	if (uio->uio_offset == TMPFS_DIRCOOKIE_DOT) {
		error = tmpfs_dir_getdotdent(node, uio);
		if (error == -1) {
			error = 0;
			goto outok;
		} else if (error != 0)
			goto outok;
		cnt++;
	}

	if (uio->uio_offset == TMPFS_DIRCOOKIE_DOTDOT) {
		error = tmpfs_dir_getdotdotdent(node, uio);
		if (error == -1) {
			error = 0;
			goto outok;
		} else if (error != 0)
			goto outok;
		cnt++;
	}

	error = tmpfs_dir_getdents(node, uio, &cnt);
	if (error == -1)
		error = 0;
	MPASS(error >= 0);

outok:
	/* This label assumes that startoff has been
	 * initialized.  If the compiler didn't spit out warnings, we'd
	 * simply make this one be 'out' and drop 'outok'. */

	if (eofflag != NULL)
		*eofflag =
		    (error == 0 && uio->uio_offset == TMPFS_DIRCOOKIE_EOF);

	/* Update NFS-related variables. */
	if (error == 0 && cookies != NULL && ncookies != NULL) {
		off_t i;
		off_t off = startoff;
		struct tmpfs_dirent *de = NULL;

		*ncookies = cnt;
		*cookies = malloc(cnt * sizeof(off_t), M_TEMP, M_WAITOK);

		for (i = 0; i < cnt; i++) {
			MPASS(off != TMPFS_DIRCOOKIE_EOF);
			if (off == TMPFS_DIRCOOKIE_DOT) {
				off = TMPFS_DIRCOOKIE_DOTDOT;
			} else {
				if (off == TMPFS_DIRCOOKIE_DOTDOT) {
					de = TAILQ_FIRST(&node->tn_dir.tn_dirhead);
				} else if (de != NULL) {
					de = TAILQ_NEXT(de, td_entries);
				} else {
					de = tmpfs_dir_lookupbycookie(node,
					    off);
					MPASS(de != NULL);
					de = TAILQ_NEXT(de, td_entries);
				}
				if (de == NULL) {
					off = TMPFS_DIRCOOKIE_EOF;
				} else {
					off = TMPFS_DIRCOOKIE(de);
				}
			}

			(*cookies)[i] = off;
		}
		MPASS(uio->uio_offset == off);
	}

out:
	return error;
}

/* --------------------------------------------------------------------- */

int
tmpfs_readlink(struct vop_readlink_args *v)
{
	struct vnode *vp = v->a_vp;
	struct uio *uio = v->a_uio;

	int error;
	struct tmpfs_node *node;

	MPASS(uio->uio_offset == 0);
	MPASS(vp->v_type == VLNK);

	node = VP_TO_TMPFS_NODE(vp);

	error = uiomove(node->tn_link, MIN(node->tn_size, uio->uio_resid),
	    uio);
	node->tn_status |= TMPFS_NODE_ACCESSED;

	return error;
}

/* --------------------------------------------------------------------- */

int
tmpfs_inactive(struct vop_inactive_args *v)
{
	struct vnode *vp = v->a_vp;
	struct thread *l = v->a_td;

	struct tmpfs_node *node;

	MPASS(VOP_ISLOCKED(vp, l));

	node = VP_TO_TMPFS_NODE(vp);

	if (node->tn_links == 0)
		vrecycle(vp, l);

	return 0;
}

/* --------------------------------------------------------------------- */

int
tmpfs_reclaim(struct vop_reclaim_args *v)
{
	struct vnode *vp = v->a_vp;

	struct tmpfs_mount *tmp;
	struct tmpfs_node *node;

	node = VP_TO_TMPFS_NODE(vp);
	tmp = VFS_TO_TMPFS(vp->v_mount);
		
	vnode_destroy_vobject(vp);
	cache_purge(vp);
	tmpfs_free_vp(vp);

	/* If the node referenced by this vnode was deleted by the user,
	 * we must free its associated data structures (now that the vnode
	 * is being reclaimed). */
	if (node->tn_links == 0)
		tmpfs_free_node(tmp, node);

	MPASS(vp->v_data == NULL);
	return 0;
}

/* --------------------------------------------------------------------- */

int
tmpfs_print(struct vop_print_args *v)
{
	struct vnode *vp = v->a_vp;

	struct tmpfs_node *node;

	node = VP_TO_TMPFS_NODE(vp);

	printf("tag VT_TMPFS, tmpfs_node %p, flags 0x%x, links %d\n",
	    node, node->tn_flags, node->tn_links);
	printf("\tmode 0%o, owner %d, group %d, size %" PRIdMAX
	    ", status 0x%x\n",
	    node->tn_mode, node->tn_uid, node->tn_gid,
	    (uintmax_t)node->tn_size, node->tn_status);

	if (vp->v_type == VFIFO)
		fifo_printinfo(vp);

	printf("\n");

	return 0;
}

/* --------------------------------------------------------------------- */

int
tmpfs_pathconf(struct vop_pathconf_args *v)
{
	int name = v->a_name;
	register_t *retval = v->a_retval;

	int error;

	error = 0;

	switch (name) {
	case _PC_LINK_MAX:
		*retval = LINK_MAX;
		break;

	case _PC_NAME_MAX:
		*retval = NAME_MAX;
		break;

	case _PC_PATH_MAX:
		*retval = PATH_MAX;
		break;

	case _PC_PIPE_BUF:
		*retval = PIPE_BUF;
		break;

	case _PC_CHOWN_RESTRICTED:
		*retval = 1;
		break;

	case _PC_NO_TRUNC:
		*retval = 1;
		break;

	case _PC_SYNC_IO:
		*retval = 1;
		break;

	case _PC_FILESIZEBITS:
		*retval = 0; /* XXX Don't know which value should I return. */
		break;

	default:
		error = EINVAL;
	}

	return error;
}

/* --------------------------------------------------------------------- */

int
tmpfs_advlock(struct vop_advlock_args *v)
{
	struct vnode *vp = v->a_vp;

	struct tmpfs_node *node;

	node = VP_TO_TMPFS_NODE(vp);

	return lf_advlock(v, &node->tn_lockf, node->tn_size);
}

/* --------------------------------------------------------------------- */

int
tmpfs_vptofh(struct vop_vptofh_args *ap)
{
	struct tmpfs_fid *tfhp;
	struct tmpfs_node *node;

	tfhp = (struct tmpfs_fid *)ap->a_fhp;
	node = VP_TO_TMPFS_NODE(ap->a_vp);

	tfhp->tf_len = sizeof(struct tmpfs_fid);
	tfhp->tf_id = node->tn_id;
	tfhp->tf_gen = node->tn_gen;
	
	return (0);
}
