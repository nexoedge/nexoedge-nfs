// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) Panasas Inc., 2011
 * Author: Jim Lieb jlieb@panasas.com
 *
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *                Helen H. W. Chan  <hwchan@cuhk.edu.hk>
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

/* handle.c
 */

#include "config.h"

#include "fsal.h"
#include <libgen.h>		/* used for 'dirname' */
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "gsh_list.h"
#include "fsal_convert.h"
#include "FSAL/fsal_commonlib.h"
#include "ncloud_methods.h"
#include "nfs4_acls.h"
#include <os/subr.h>

/**
 * helpers (ncloud requests)
 */

/**
 * Rename the file in nCloud
 * @param[in] export	fsal export
 * @param[in] spath	source path
 * @param[in] dpath	destination path
 * @return status of the rename operation
 */
static fsal_status_t ncloud_rename_backend_file(struct ncloud_fsal_export *export, char *spath, char *dpath);

/**
 * Delete a file in nCloud
 * @param[in] export	fsal export
 * @param[in] path	file path
 * @return status of the rename operation
 */
static fsal_status_t ncloud_delete_backend_file(struct ncloud_fsal_export *export, char *path);

static fsal_status_t ncloud_operate_on_directory(struct ncloud_fsal_export *export, char *ndir, int op, char *odir) {
	char filepath[PATH_MAX], dest_filepath[PATH_MAX];
	fsal_status_t ret = fsalstat(ERR_FSAL_NO_ERROR, 0);

	bool is_rename = op == 1;
	size_t mount_dir_len = strlen(get_mount_path());

	snprintf(filepath, PATH_MAX, "%s", is_rename? odir : ndir);
	DIR *dir = opendir(filepath);

	struct dirent *item = 0;
	if (dir != NULL) {
		int dir_id = ncloud_path_map_load_dir_id(filepath);
		while((item = readdir(dir)) != NULL) {
			/** 
			 * skip if the entry is
			 * (1) is neither a regular file nor directory
			 * (2) is "."
			 * (3) is ".."
			 **/
			if (
				(!(item->d_type & DT_REG) && !(item->d_type & DT_DIR)) ||
				is_dot_or_dotdot(item->d_name)
			) {
				continue;
			}
			snprintf(filepath, PATH_MAX, "%s/%s", ndir, item->d_name);
			if (item->d_type & DT_DIR) {
				switch (op) {
				case 0: /* delete */
					LogFullDebug(COMPONENT_FSAL,
						"Clean up directory %s",
						filepath
					);
					/* handle directory (recursively) */
					ncloud_operate_on_directory(export, filepath, op, odir);
					/* remove the empty directory */
					if (rmdir(filepath) != 0)
						LogMajor(COMPONENT_FSAL,
							"Failed to rmdir %s, %s, %d",
							filepath,
							strerror(errno),
							errno
						);
					break;

				case 1: /* rename */
					LogInfo(COMPONENT_FSAL,
						"rename directory from %s %s to %s %s",
						odir, item->d_name,
						ndir, item->d_name
					);
					snprintf(dest_filepath, PATH_MAX, "%s/%s", ndir, item->d_name);
					snprintf(filepath, PATH_MAX, "%s/%s", odir, item->d_name);
					ncloud_operate_on_directory(export, dest_filepath, op, filepath);
					break;

				default:
					break;
				}
			} else {
				switch (op) {
				case 0: /* delete */
					/* remove the file */
					if (unlink(filepath) != 0)
						LogMajor(COMPONENT_FSAL, 
							"Failed to unlink %s, %s, %d",
							filepath,
							strerror(errno),
							errno
						);
					break;

				case 1: /* rename */
					if (!ncloud_is_system_file(item->d_name)) {
						LogInfo(COMPONENT_FSAL,
							"rename file from %s %s to %s %s",
							odir, item->d_name,
							ndir, item->d_name
						);
						snprintf(filepath, PATH_MAX, "%s/%s", odir, item->d_name);
						snprintf(dest_filepath, PATH_MAX, "%s/%s", ndir, item->d_name);
						int id = ncloud_path_map_load_file_id(filepath);
						ret = ncloud_rename_backend_file(export, filepath + mount_dir_len + 1, dest_filepath + mount_dir_len + 1);
						if (ncloud_path_map_is_id_valid(id))
							ncloud_path_map_update(export, id, dest_filepath); 
					}
					break;

				default:
					break;
				}
			}
		}
		closedir(dir);
		/* also update the directory path in mapping */
		if (ncloud_path_map_is_id_valid(dir_id)) {
			if (is_rename) {
				snprintf(dest_filepath, PATH_MAX, "%s", ndir);
				ncloud_path_map_update(export, dir_id, dest_filepath); 
			} else {
				ncloud_path_map_remove(export, dir_id); 
			}
		}
	} else {
		LogMajor(COMPONENT_FSAL,
			"Failed to operate on directory %s",
			filepath
		);
	}

	return ret;
}

static fsal_status_t ncloud_rename_backend_file(struct ncloud_fsal_export *export, char *spath, char *dpath) {
	if (export == NULL || spath == NULL || dpath == NULL)
		return fsalstat(ERR_FSAL_INVAL, 0);

	fsal_errors_t error = ERR_FSAL_NO_ERROR;

	/* use disposable connection */
	ncloud_conn_t conn;

	if (ncloud_conn_t_init(export->ncloud.proxy_ip, export->ncloud.proxy_port, &conn, 1) < 0) {
		LogMajor(
			COMPONENT_FSAL,
			"Failed to init connection to get the append size"
		);
		return fsalstat(ERR_FSAL_FAULT, ENETDOWN);
	}

	/* send the file rename request */
	request_t req;
	if (set_file_rename_request(&req, spath, dpath, export->ncloud.namespace_id) == -1) {
		LogMajor(COMPONENT_FSAL,
			"Failed to set file rename request from %s to %s",
			spath,
			dpath
		);
		error = ERR_FSAL_INVAL;
	} else {
		if (send_request(&conn, &req) == -1) {
			LogMajor(COMPONENT_FSAL,
				"Failed to complete file rename request from %s to %s",
				spath,
				dpath
			);
			error = ERR_FSAL_ACCESS;
		}
	}

	/* release request and connection */
	request_t_release(&req);
	ncloud_conn_t_release(&conn);

	return fsalstat(error, 0);
}

static fsal_status_t ncloud_delete_backend_file(
		struct ncloud_fsal_export *export,
		char *path) 
{
	if (export == NULL || path == NULL)
		return fsalstat(ERR_FSAL_INVAL, 0);

	/* use disposable connection */
	ncloud_conn_t conn;

	if (ncloud_conn_t_init(export->ncloud.proxy_ip, export->ncloud.proxy_port, &conn, 1) < 0) {
		LogMajor(
			COMPONENT_FSAL,
			"Failed to init connection to get the append size"
		);
		return fsalstat(ERR_FSAL_FAULT, ENETDOWN);
	}

	/* send the file delete request */
	fsal_errors_t error = ERR_FSAL_NO_ERROR;
	request_t req;
	if (set_delete_file_request(&req,
				    path,
				    export->ncloud.namespace_id) == -1) 
	{
		LogMajor(COMPONENT_FSAL,
			"Failed to set file delete request for %s",
			path
		);
		error = ERR_FSAL_INVAL;
	} else {
		send_request(&conn, &req);
	}

	/* release request and connection */
	request_t_release(&req);
	ncloud_conn_t_release(&conn);

	return fsalstat(error, 0);
}

/**
 * Allocate and initialize a new ncloud handle.
 *
 * This function doesn't free the sub_handle if the allocation fails. It must
 * be done in the calling function.
 *
 * @param[in] export The ncloud export used by the handle.
 * @param[in] sub_handle The handle used by the subfsal.
 * @param[in] fs The filesystem of the new handle.
 *
 * @return The new handle, or NULL if the allocation failed.
 */
static struct ncloud_fsal_obj_handle *ncloud_alloc_handle(
		struct ncloud_fsal_export *export,
		struct fsal_obj_handle *sub_handle,
		struct fsal_filesystem *fs)
{
	struct ncloud_fsal_obj_handle *result;

	result = gsh_calloc(1, sizeof(struct ncloud_fsal_obj_handle));

	/* default handles */
	fsal_obj_handle_init(&result->obj_handle, &export->export,
			     sub_handle? sub_handle->type : REGULAR_FILE);
	/* ncloud handles */
	result->obj_handle.obj_ops = &NCLOUD.handle_ops;
	result->sub_handle = sub_handle;
	if (sub_handle) {
		result->obj_handle.type = sub_handle->type;
		result->obj_handle.fsid = sub_handle->fsid;
		result->obj_handle.fileid = sub_handle->fileid;
		result->obj_handle.state_hdl = sub_handle->state_hdl;
	} else {
		result->obj_handle.state_hdl = NULL;
	}
	result->obj_handle.fs = fs;
	result->refcnt = 1;

	return result;
}

/**
 * Attempts to create a new ncloud handle, or cleanup memory if it fails.
 *
 * This function is a wrapper of ncloud_alloc_handle. It adds error checking
 * and logging. It also cleans objects allocated in the subfsal if it fails.
 *
 * @param[in] export The ncloud export used by the handle.
 * @param[in,out] sub_handle The handle used by the subfsal.
 * @param[in] fs The filesystem of the new handle.
 * @param[in] new_handle Address where the new allocated pointer should be
 * written.
 * @param[in] subfsal_status Result of the allocation of the subfsal handle.
 * @param[in] path obj path if available
 *
 * @return An error code for the function.
 */
fsal_status_t ncloud_alloc_and_check_handle(
		struct ncloud_fsal_export *export,
		struct fsal_obj_handle *sub_handle,
		struct fsal_filesystem *fs,
		struct fsal_obj_handle **new_handle,
		fsal_status_t subfsal_status,
		const char *path)
{
	/** Result status of the operation. */
	fsal_status_t status = subfsal_status;

	if (sub_handle) {
		struct ncloud_fsal_obj_handle *ncloud_handle;

		ncloud_handle = ncloud_alloc_handle(export, sub_handle, fs);

		*new_handle = &ncloud_handle->obj_handle;

		ncloud_init_obj_handle(
			export,
			ncloud_handle,
			path,
			/* write buffer */ NULL,
			/* write buffer size */ 0,
			/* read buffer */ NULL,
			/* read buffer size */ 0
		);

		LogDebug(
			COMPONENT_FSAL,
			"Create handle for object at path %s,%d with last write offset %lu and last read offset %lu",
			ncloud_handle->ncloud.path,
			ncloud_handle->ncloud.path_id,
			ncloud_handle->ncloud.last_written_offset,
			ncloud_handle->ncloud.last_read_offset
		);
	}
	LogDebug(COMPONENT_FSAL,
		"End of creating handle for object at path %s subfsal_err = %d,%d",
		path,
		subfsal_status.major,
		subfsal_status.minor
	);
	return status;
}

/* lookup
 * deprecated NULL parent && NULL path implies root handle
 */

static fsal_status_t lookup(struct fsal_obj_handle *parent,
			    const char *path, struct fsal_obj_handle **handle,
			    struct attrlist *attrs_out)
{

	LogDebug(COMPONENT_FSAL, "trace: called lookup on path %s", path);

	/** Parent as ncloud handle.*/
	struct ncloud_fsal_obj_handle *ncloud_parent =
		container_of(parent, struct ncloud_fsal_obj_handle, obj_handle);

	/** Current ncloud export. */
	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	/** Handle given by the subfsal. */
	struct fsal_obj_handle *sub_handle = NULL;

	*handle = NULL;

	LogFullDebug(COMPONENT_FSAL, "trace: called lookup on path %s updated meta", path);

	/* call to subfsal lookup with the good context. */
	fsal_status_t status;
	op_ctx->fsal_export = export->export.sub_export;
	status = ncloud_parent->sub_handle->obj_ops->lookup(
			ncloud_parent->sub_handle, path, &sub_handle, attrs_out);
	op_ctx->fsal_export = &export->export;

	LogMajor(COMPONENT_FSAL, "trace: called lookup on path %s end subhandle %p", path, sub_handle);

	char full_path[PATH_MAX + 2];
	snprintf(full_path, PATH_MAX + 2, "%s/%s", ncloud_parent->ncloud.path, path);

	int id = NCLOUD_INVALID_PATH_ID;
	if (!FSAL_IS_ERROR(status)) {
		/* update the directory first */
		char obj_path[PATH_MAX];
		snprintf(obj_path, PATH_MAX, "%s%s", strlen(path) > 0 && path[0] == '/'? path + 1 : path, sub_handle && sub_handle->type == DIRECTORY? "/" : "");
		//LogInfo(COMPONENT_FSAL, "lookup metadata %s", obj_path);
		ncloud_update_meta(export, obj_path);
		if (!FSAL_IS_ERROR(status) && sub_handle) {
			/* 
			 * for regular files, check and update the file size and timestamps from nCloud file meta 
			 * for directories, load the directory id
			 */
			if (sub_handle->type == REGULAR_FILE) {
				ncloud_stat_file(path, attrs_out);
				id = ncloud_path_map_load_file_id(full_path);
			}
			else if (sub_handle->type == DIRECTORY)
				id = ncloud_path_map_load_dir_id(full_path);
		}
	}

	/* wraping the subfsal handle in a ncloud handle. */
	status = ncloud_alloc_and_check_handle(export, sub_handle, parent->fs,
					     handle, status, full_path);

	if (!FSAL_IS_ERROR(status) && handle) {
		struct ncloud_fsal_obj_handle *hdl =
			container_of(*handle, struct ncloud_fsal_obj_handle, obj_handle);
		hdl->ncloud.path_id = id;
	}

	return status;
}

static fsal_status_t makedir(struct fsal_obj_handle *dir_hdl,
			     const char *name, struct attrlist *attrs_in,
			     struct fsal_obj_handle **new_obj,
			     struct attrlist *attrs_out)
{
	LogInfo(COMPONENT_FSAL, "trace: call mkdir on name %s", name);
	*new_obj = NULL;
	/** Parent directory ncloud handle. */
	struct ncloud_fsal_obj_handle *parent_hdl =
		container_of(dir_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);
	/** Current ncloud export. */
	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	/** Subfsal handle of the new directory.*/
	struct fsal_obj_handle *sub_handle;

	/* Creating the directory with a subfsal handle. */
	op_ctx->fsal_export = export->export.sub_export;
	fsal_status_t status = parent_hdl->sub_handle->obj_ops->mkdir(
		parent_hdl->sub_handle, name, attrs_in, &sub_handle, attrs_out);
	op_ctx->fsal_export = &export->export;

	char full_path[PATH_MAX + 2];
	snprintf(full_path, PATH_MAX + 2, "%s/%s", parent_hdl->ncloud.path, name);

	if (!FSAL_IS_ERROR(status)) {
		/* wraping the subfsal handle in a ncloud handle. */
		status = ncloud_alloc_and_check_handle(export, sub_handle, dir_hdl->fs,
						     new_obj, status, full_path);

		/* create a new directory id for the new directory */
		if (!FSAL_IS_ERROR(status)) {
			int id = ncloud_path_map_add(export, full_path);
			if (ncloud_path_map_is_id_valid(id)) {
				struct ncloud_fsal_obj_handle *hdl =
					container_of(*new_obj,
							struct ncloud_fsal_obj_handle,
							obj_handle);
				hdl->ncloud.path_id = id;
			}
		}
	}

	return status;
}

//static fsal_status_t makenode(struct fsal_obj_handle *dir_hdl,
//			      const char *name,
//			      object_file_type_t nodetype,
//			      struct attrlist *attrs_in,
//			      struct fsal_obj_handle **new_obj,
//			      struct attrlist *attrs_out)
//{
//	LogMajor(COMPONENT_FSAL, "trace: call makenode");
//	/** Parent directory ncloud handle. */
//	struct ncloud_fsal_obj_handle *ncloud_dir =
//		container_of(dir_hdl, struct ncloud_fsal_obj_handle,
//			     obj_handle);
//	/** Current ncloud export. */
//	struct ncloud_fsal_export *export =
//		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
//			     export);
//
//	/** Subfsal handle of the new node.*/
//	struct fsal_obj_handle *sub_handle;
//
//	*new_obj = NULL;
//
//	/* Creating the node with a subfsal handle. */
//	op_ctx->fsal_export = export->export.sub_export;
//	fsal_status_t status = ncloud_dir->sub_handle->obj_ops->mknode(
//		ncloud_dir->sub_handle, name, nodetype, attrs_in,
//		&sub_handle, attrs_out);
//	op_ctx->fsal_export = &export->export;
//
//	/* wraping the subfsal handle in a ncloud handle. */
//	return ncloud_alloc_and_check_handle(export, sub_handle, dir_hdl->fs,
//					     new_obj, status, name);
//}

/** makesymlink
 *  Note that we do not set mode bits on symlinks for Linux/POSIX
 *  They are not really settable in the kernel and are not checked
 *  anyway (default is 0777) because open uses that target's mode
 */

//static fsal_status_t makesymlink(struct fsal_obj_handle *dir_hdl,
//				 const char *name,
//				 const char *link_path,
//				 struct attrlist *attrs_in,
//				 struct fsal_obj_handle **new_obj,
//				 struct attrlist *attrs_out)
//{
//	LogMajor(COMPONENT_FSAL, "trace: call makesymlink");
//	/** Parent directory ncloud handle. */
//	struct ncloud_fsal_obj_handle *ncloud_dir =
//		container_of(dir_hdl, struct ncloud_fsal_obj_handle,
//			     obj_handle);
//	/** Current ncloud export. */
//	struct ncloud_fsal_export *export =
//		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
//			     export);
//
//	/** Subfsal handle of the new link.*/
//	struct fsal_obj_handle *sub_handle;
//
//	*new_obj = NULL;
//
//	/* creating the file with a subfsal handle. */
//	op_ctx->fsal_export = export->export.sub_export;
//	fsal_status_t status = ncloud_dir->sub_handle->obj_ops->symlink(
//		ncloud_dir->sub_handle, name, link_path, attrs_in, &sub_handle,
//		attrs_out);
//	op_ctx->fsal_export = &export->export;
//
//	/* wraping the subfsal handle in a ncloud handle. */
//	return ncloud_alloc_and_check_handle(export, sub_handle, dir_hdl->fs,
//					     new_obj, status);
//}
//
//static fsal_status_t readsymlink(struct fsal_obj_handle *obj_hdl,
//				 struct gsh_buffdesc *link_content,
//				 bool refresh)
//{
//	LogMajor(COMPONENT_FSAL, "trace: call readsymlink");
//	struct ncloud_fsal_obj_handle *handle =
//		(struct ncloud_fsal_obj_handle *) obj_hdl;
//	struct ncloud_fsal_export *export =
//		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
//			     export);
//
//	/* calling subfsal method */
//	op_ctx->fsal_export = export->export.sub_export;
//	fsal_status_t status =
//		handle->sub_handle->obj_ops->readlink(handle->sub_handle,
//						     link_content, refresh);
//	op_ctx->fsal_export = &export->export;
//
//	return status;
//}
//
//static fsal_status_t linkfile(struct fsal_obj_handle *obj_hdl,
//			      struct fsal_obj_handle *destdir_hdl,
//			      const char *name)
//{
//	LogMajor(COMPONENT_FSAL, "trace: call linkfile");
//	struct ncloud_fsal_obj_handle *handle =
//		(struct ncloud_fsal_obj_handle *) obj_hdl;
//	struct ncloud_fsal_obj_handle *ncloud_dir =
//		(struct ncloud_fsal_obj_handle *) destdir_hdl;
//	struct ncloud_fsal_export *export =
//		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
//			     export);
//
//	/* calling subfsal method */
//	op_ctx->fsal_export = export->export.sub_export;
//	fsal_status_t status = handle->sub_handle->obj_ops->link(
//		handle->sub_handle, ncloud_dir->sub_handle, name);
//	op_ctx->fsal_export = &export->export;
//
//	return status;
//}

/**
 * Callback function for read_dirents.
 *
 * See fsal_readdir_cb type for more details.
 *
 * This function restores the context for the upper stacked fsal or inode.
 *
 * @param name Directly passed to upper layer.
 * @param dir_state A ncloud_readdir_state struct.
 * @param cookie Directly passed to upper layer.
 *
 * @return Result coming from the upper layer.
 */
static enum fsal_dir_result ncloud_readdir_cb(
					const char *name,
					struct fsal_obj_handle *sub_handle,
					struct attrlist *attrs,
					void *dir_state, fsal_cookie_t cookie)
{
	struct ncloud_readdir_state *state =
		(struct ncloud_readdir_state *) dir_state;
	struct fsal_obj_handle *new_obj;

	LogDebug(COMPONENT_FSAL, "trace: call ncloud_readdir_cb on name %s/%s", state->path, name);
	/* figure out the full path (folder + file name) */
	char full_path[PATH_MAX];
	const char *folder_path = state->path;
	if (snprintf(full_path, PATH_MAX, "%s/%s", folder_path, name) <= 0) {
		/* ignore error by skip listing */
		return DIR_CONTINUE;
	}

	/* create a new obj handle */
	if (FSAL_IS_ERROR(ncloud_alloc_and_check_handle(state->exp, sub_handle,
		sub_handle->fs, &new_obj, fsalstat(ERR_FSAL_NO_ERROR, 0), full_path))) {
		/* ignore error by skip listing */
		return DIR_CONTINUE;
	}

	if (new_obj && !is_dot_or_dotdot(name) && !ncloud_is_system_file(name)) {
		struct ncloud_fsal_obj_handle *hdl =
			container_of(new_obj, struct ncloud_fsal_obj_handle, obj_handle);
		/* figure out the actual file size for regular files (which are supposed to be ncloud files) */
		if (new_obj->type == REGULAR_FILE) {
			/* check and update the file size and timestamps from nCloud file meta */
			ncloud_stat_file(full_path, attrs);
			hdl->ncloud.path_id = ncloud_path_map_load_file_id(full_path);
		} else if (new_obj->type == DIRECTORY) {
			/* get the directory id for directories */
			hdl->ncloud.path_id = ncloud_path_map_load_dir_id(full_path);
		}
	}

	/* only list non-system files */
	if (!ncloud_is_system_file(name)) {
		op_ctx->fsal_export = &state->exp->export;
		enum fsal_dir_result result = state->cb(name, new_obj, attrs,
							state->dir_state, cookie);

		op_ctx->fsal_export = state->exp->export.sub_export;
		return result;
	}

	return DIR_CONTINUE;
}

/**
 * read_dirents
 * read the directory and call through the callback function for
 * each entry.
 * @param dir_hdl [IN] the directory to read
 * @param whence [IN] where to start (next)
 * @param dir_state [IN] pass thru of state to callback
 * @param cb [IN] callback function
 * @param eof [OUT] eof marker true == end of dir
 */

static fsal_status_t read_dirents(struct fsal_obj_handle *dir_hdl,
				  fsal_cookie_t *whence, void *dir_state,
				  fsal_readdir_cb cb, attrmask_t attrmask,
				  bool *eof)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(dir_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	LogDebug(COMPONENT_FSAL, "trace: call read_dirents is_eof=%d on path %s", eof? *eof : -1, handle->ncloud.path);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	struct ncloud_readdir_state cb_state = {
		.cb = cb,
		.dir_state = dir_state,
		.exp = export
	};
	snprintf(cb_state.path, PATH_MAX, "%s", handle->ncloud.path);
	LogInfo(COMPONENT_FSAL, "trace: call read_dirents on state path %s %s", handle->ncloud.path, cb_state.path);

	char dir_path[PATH_MAX];
	size_t mount_path_len = strlen(get_mount_path());
	snprintf(dir_path, PATH_MAX, "%s%s", handle->ncloud.path + mount_path_len + 1, strlen(handle->ncloud.path) == mount_path_len? "" : "/");
	ncloud_update_meta(export, dir_path);

	/* calling subfsal method */
	op_ctx->fsal_export = export->export.sub_export;
	fsal_status_t status =
		handle->sub_handle->obj_ops->readdir(handle->sub_handle,
		whence, &cb_state, ncloud_readdir_cb, attrmask, eof);
	op_ctx->fsal_export = &export->export;

	return status;
}

/**
 * @brief Compute the readdir cookie for a given filename.
 *
 * Some FSALs are able to compute the cookie for a filename deterministically
 * from the filename. They also have a defined order of entries in a directory
 * based on the name (could be strcmp sort, could be strict alpha sort, could
 * be deterministic order based on cookie - in any case, the dirent_cmp method
 * will also be provided.
 *
 * The returned cookie is the cookie that can be passed as whence to FIND that
 * directory entry. This is different than the cookie passed in the readdir
 * callback (which is the cookie of the NEXT entry).
 *
 * @param[in]  parent  Directory file name belongs to.
 * @param[in]  name    File name to produce the cookie for.
 *
 * @retval 0 if not supported.
 * @returns The cookie value.
 */

fsal_cookie_t compute_readdir_cookie(struct fsal_obj_handle *parent,
				     const char *name)
{
	LogDebug(COMPONENT_FSAL, "trace: call compute_readdir_cookie on name %s", name);
	fsal_cookie_t cookie;
	struct ncloud_fsal_obj_handle *handle =
		container_of(parent, struct ncloud_fsal_obj_handle,
			     obj_handle);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	/* calling subfsal method */
	op_ctx->fsal_export = export->export.sub_export;
	cookie = handle->sub_handle->obj_ops->compute_readdir_cookie(
						handle->sub_handle, name);
	op_ctx->fsal_export = &export->export;
	return cookie;
}

/**
 * @brief Help sort dirents.
 *
 * For FSALs that are able to compute the cookie for a filename
 * deterministically from the filename, there must also be a defined order of
 * entries in a directory based on the name (could be strcmp sort, could be
 * strict alpha sort, could be deterministic order based on cookie).
 *
 * Although the cookies could be computed, the caller will already have them
 * and thus will provide them to save compute time.
 *
 * @param[in]  parent   Directory entries belong to.
 * @param[in]  name1    File name of first dirent
 * @param[in]  cookie1  Cookie of first dirent
 * @param[in]  name2    File name of second dirent
 * @param[in]  cookie2  Cookie of second dirent
 *
 * @retval < 0 if name1 sorts before name2
 * @retval == 0 if name1 sorts the same as name2
 * @retval >0 if name1 sorts after name2
 */

int dirent_cmp(struct fsal_obj_handle *parent,
	       const char *name1, fsal_cookie_t cookie1,
	       const char *name2, fsal_cookie_t cookie2)
{
	LogDebug(COMPONENT_FSAL, "trace: call dirent_cmp %s vs %s", name1, name2);
	int rc;
	struct ncloud_fsal_obj_handle *handle =
		container_of(parent, struct ncloud_fsal_obj_handle,
			     obj_handle);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	/* calling subfsal method */
	op_ctx->fsal_export = export->export.sub_export;
	rc = handle->sub_handle->obj_ops->dirent_cmp(handle->sub_handle,
						    name1, cookie1,
						    name2, cookie2);
	op_ctx->fsal_export = &export->export;
	return rc;
}

static fsal_status_t renamefile(struct fsal_obj_handle *obj_hdl,
				struct fsal_obj_handle *olddir_hdl,
				const char *old_name,
				struct fsal_obj_handle *newdir_hdl,
				const char *new_name)
{
	struct ncloud_fsal_obj_handle *ncloud_olddir =
		container_of(olddir_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);
	struct ncloud_fsal_obj_handle *ncloud_newdir =
		container_of(newdir_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);
	struct ncloud_fsal_obj_handle *ncloud_obj =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);

	char old_path[PATH_MAX + 2], new_path[PATH_MAX + 2];
	snprintf(old_path, PATH_MAX + 2, "%s/%s", ncloud_olddir->ncloud.path, old_name); 
	snprintf(new_path, PATH_MAX + 2, "%s/%s", ncloud_newdir->ncloud.path, new_name); 
	LogInfo(COMPONENT_FSAL, "trace: call renamefile from %s (%s) to %s (%s)", old_name, old_path, new_name, new_path);
	size_t mount_dir_len = strlen(get_mount_path());
	/* do single file rename / or directory-based rename */
	if (obj_hdl->type == REGULAR_FILE) {
		status = ncloud_rename_backend_file(export, old_path + mount_dir_len + 1, new_path + mount_dir_len + 1);
		if (!FSAL_IS_ERROR(status)) {
			int fid = ncloud_path_map_load_file_id(old_path);
			if (ncloud_path_map_is_id_valid(fid))
				ncloud_path_map_update(export, fid, new_path);
		}
	} else if (obj_hdl->type == DIRECTORY) {
		status = ncloud_operate_on_directory(export, new_path, 1, old_path);
	}

	if (!FSAL_IS_ERROR(status)) {
		/* calling subfsal method */
		op_ctx->fsal_export = export->export.sub_export;
		status = ncloud_olddir->sub_handle->obj_ops->rename(
			ncloud_obj->sub_handle, ncloud_olddir->sub_handle,
			old_name, ncloud_newdir->sub_handle, new_name);
		op_ctx->fsal_export = &export->export;
		/* update obj path */
		snprintf(ncloud_obj->ncloud.path, PATH_MAX, "%s", new_path);
	}

	return status;
}

static fsal_status_t getattrs(struct fsal_obj_handle *obj_hdl,
			      struct attrlist *attrib_get)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	LogDebug(COMPONENT_FSAL,
		"trace: call getattrs on obj path %s is_regular = %d %p",
		handle->ncloud.path,
		handle->obj_handle.type == REGULAR_FILE,
		handle
	);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);
	/* calling subfsal method */
	if (handle->sub_handle) {
		op_ctx->fsal_export = export->export.sub_export;
		status = handle->sub_handle->obj_ops->getattrs(handle->sub_handle,
							     attrib_get);
		op_ctx->fsal_export = &export->export;
	}
	/* check nCloud attributes? */
	if (handle->obj_handle.type == REGULAR_FILE) {
		if (!ncloud_stat_file(handle->ncloud.path, attrib_get))
			handle->ncloud.path_id = ncloud_path_map_load_file_id(handle->ncloud.path);
		LogDebug(COMPONENT_FSAL,
			"trace: call getattrs on obj path %s,%d is_regular = %d %p",
			handle->ncloud.path,
			handle->ncloud.path_id,
			handle->obj_handle.type == REGULAR_FILE,
			handle
		);
	}

	return status;
}

static fsal_status_t ncloud_setattr2(struct fsal_obj_handle *obj_hdl,
				     bool bypass,
				     struct state_t *state,
				     struct attrlist *attrs)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	LogDebug(COMPONENT_FSAL,
		 "trace: call ncloud_setattr2 on obj path %s, "
		 "attr_size = %llx (%lu vs %lu), "
		 "owner = %llx (%lu), "
		 "group = %llx (%lu), "
		 "mask = %lx "
		 ,
		 handle->ncloud.path,
		 FSAL_TEST_MASK(attrs->valid_mask, ATTR_SIZE),
		 attrs->filesize, handle->ncloud.last_written_offset,
		 FSAL_TEST_MASK(attrs->valid_mask, ATTR_OWNER),
		 attrs->owner,
		 FSAL_TEST_MASK(attrs->valid_mask, ATTR_GROUP),
		 attrs->group,
		 attrs->valid_mask
	);

	if (FSAL_TEST_MASK(attrs->valid_mask, ATTR_SIZE)) {
		if (attrs->filesize != 0) {
			/* TODO: truncate file to a smaller but non-zero size */
		} else {
			handle->ncloud.last_written_offset = 0;
		}
	}

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);

	if (handle->sub_handle) {
		/* calling subfsal method */
		op_ctx->fsal_export = export->export.sub_export;
		status = handle->sub_handle->obj_ops->setattr2(
			handle->sub_handle, bypass, state, attrs);
		op_ctx->fsal_export = &export->export;
	}

	return status;
}

/* file_unlink
 * unlink the named file in the directory
 */

static fsal_status_t file_unlink(struct fsal_obj_handle *dir_hdl,
				 struct fsal_obj_handle *obj_hdl,
				 const char *name)
{
	struct ncloud_fsal_obj_handle *ncloud_dir =
		container_of(dir_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);
	struct ncloud_fsal_obj_handle *ncloud_obj =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);
	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	size_t mount_path_len = strlen(get_mount_path());
	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);

	if (obj_hdl->type == REGULAR_FILE) {
		LogInfo(COMPONENT_FSAL, "trace: call file_unlink on file path %s", ncloud_obj->ncloud.path + mount_path_len + 1);
		int fid = ncloud_path_map_load_file_id(ncloud_obj->ncloud.path);
		status = ncloud_delete_backend_file(export, ncloud_obj->ncloud.path + mount_path_len + 1);
		if (ncloud_path_map_is_id_valid(fid))
			ncloud_path_map_remove(export, fid); 
	} else if (obj_hdl->type == DIRECTORY) {
		LogInfo(COMPONENT_FSAL, "trace: call file_unlink on directory path %s", ncloud_obj->ncloud.path);
		status = ncloud_operate_on_directory(export, ncloud_obj->ncloud.path, /* delete: 0 */ 0, NULL);
	}

	/* calling subfsal method */
	if (!FSAL_IS_ERROR(status)) {
		op_ctx->fsal_export = export->export.sub_export;
		status = ncloud_dir->sub_handle->obj_ops->unlink(
			ncloud_dir->sub_handle, ncloud_obj->sub_handle, name);
		op_ctx->fsal_export = &export->export;
	}

	return status;
}

/* handle_to_wire
 * fill in the opaque f/s file handle part.
 * we zero the buffer to length first.  This MAY already be done above
 * at which point, remove memset here because the caller is zeroing
 * the whole struct.
 */

static fsal_status_t handle_to_wire(const struct fsal_obj_handle *obj_hdl,
				    fsal_digesttype_t output_type,
				    struct gsh_buffdesc *fh_desc)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	LogDebug(COMPONENT_FSAL,
		"trace: call handle_to_wire on obj path %s %p len = %lu",
		handle->ncloud.path, handle, fh_desc->len
	);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);
	/* serialize the handle (path) for ncloud */
	size_t ncloud_len = sizeof(int);
	memcpy(fh_desc->addr, &handle->ncloud.path_id, sizeof(int));

	struct gsh_buffdesc sub_fh_desc = {fh_desc->addr + ncloud_len, fh_desc->len + ncloud_len}; 

	/* serialize subfsal handle */
	if (handle->sub_handle) {
		op_ctx->fsal_export = export->export.sub_export;
		status = handle->sub_handle->obj_ops->handle_to_wire(
			handle->sub_handle, output_type, &sub_fh_desc);
		op_ctx->fsal_export = &export->export;
	}

	if (!FSAL_IS_ERROR(status)) {
		fh_desc->len = ncloud_len + sub_fh_desc.len;
		LogDebug(COMPONENT_FSAL,
			"handle_to_wire len = %lu [%d] for path %s",
			fh_desc->len, *((int*) fh_desc->addr),
			handle->ncloud.path
		);
	}

	return status;
}

/**
 * handle_to_key
 * return a handle descriptor into the handle in this object handle
 * @TODO reminder.  make sure things like hash keys don't point here
 * after the handle is released.
 */

static void handle_to_key(struct fsal_obj_handle *obj_hdl,
			  struct gsh_buffdesc *fh_desc)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	LogDebug(COMPONENT_FSAL, "trace: call handle_to_key on obj path %s", handle->ncloud.path);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	if (handle->sub_handle) {
		/* calling subfsal method */
		op_ctx->fsal_export = export->export.sub_export;
		handle->sub_handle->obj_ops->handle_to_key(handle->sub_handle, fh_desc);
		op_ctx->fsal_export = &export->export;
	}
}

/*
 * release
 * release our handle first so they know we are gone
 */

static void release(struct fsal_obj_handle *obj_hdl)
{
	struct ncloud_fsal_obj_handle *hdl =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	LogInfo(COMPONENT_FSAL, "trace: call release (handle) on obj path %s", hdl->ncloud.path);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	if (hdl->sub_handle) {
		/* calling subfsal method */
		op_ctx->fsal_export = export->export.sub_export;
		hdl->sub_handle->obj_ops->release(hdl->sub_handle);
		op_ctx->fsal_export = &export->export;
	}

	/* cleaning data allocated by ncloud */
	fsal_obj_handle_fini(&hdl->obj_handle);
	ncloud_release_handle_resources(export, hdl);
	gsh_free(hdl);
}

static bool ncloud_is_referral(struct fsal_obj_handle *obj_hdl,
			       struct attrlist *attrs,
			       bool cache_attrs)
{
	struct ncloud_fsal_obj_handle *hdl =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	LogDebug(COMPONENT_FSAL,
		"trace: call ncloud_is_referral on obj path %s is_regular %d (%lu;%lu;%lu;%lu)",
		hdl->ncloud.path,
		(obj_hdl->type & REGULAR_FILE) == REGULAR_FILE,
		attrs->filesize,
		attrs->creation.tv_sec,
		attrs->atime.tv_sec,
		attrs->mtime.tv_sec
		
	);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	bool result = true;
	if (hdl->sub_handle) {
		/* calling subfsal method */
		op_ctx->fsal_export = export->export.sub_export;
		result = hdl->sub_handle->obj_ops->is_referral(hdl->sub_handle, attrs,
							      cache_attrs);
		op_ctx->fsal_export = &export->export;
	}

	bool stat_success = false;
	if (obj_hdl->type == REGULAR_FILE) {
		stat_success = ncloud_stat_file(hdl->ncloud.path, attrs); 
		if (!stat_success)
			hdl->ncloud.path_id = ncloud_path_map_load_file_id(hdl->ncloud.path);
	}

	LogDebug(COMPONENT_FSAL,
		"trace: call ncloud_is_referral on obj path %s,%d end is_referral = %d stat okay = %d",
		hdl->ncloud.path,
		hdl->ncloud.path_id,
		result,
		stat_success
	);
	return result;
}

void ncloud_handle_ops_init(struct fsal_obj_ops *ops)
{
	fsal_default_obj_ops_init(ops);

	ops->release = release;
	ops->lookup = lookup;
	ops->readdir = read_dirents;
	ops->dirent_cmp = dirent_cmp,
	ops->mkdir = makedir;
	ops->getattrs = getattrs;
	/*
	ops->compute_readdir_cookie = compute_readdir_cookie,
	ops->mknode = makenode;
	ops->symlink = makesymlink;
	ops->readlink = readsymlink;
	ops->link = linkfile;
	*/
	ops->rename = renamefile;
	ops->unlink = file_unlink;
	ops->close = ncloud_close;
	ops->handle_to_wire = handle_to_wire;
	ops->handle_to_key = handle_to_key;

	/* Multi-FD */
	ops->open2 = ncloud_open2;
	ops->check_verifier = ncloud_check_verifier;
	ops->status2 = ncloud_status2;
	ops->reopen2 = ncloud_reopen2;
	ops->read2 = ncloud_read2;
	ops->write2 = ncloud_write2;
	ops->seek2 = ncloud_seek2;
	ops->io_advise2 = ncloud_io_advise2;
	ops->commit2 = ncloud_commit2;
	ops->lock_op2 = ncloud_lock_op2;
	ops->setattr2 = ncloud_setattr2;
	ops->close2 = ncloud_close2;
	ops->fallocate = ncloud_fallocate;

	/* xattr related functions */
	/*
	ops->list_ext_attrs = ncloud_list_ext_attrs;
	ops->getextattr_id_by_name = ncloud_getextattr_id_by_name;
	ops->getextattr_value_by_name = ncloud_getextattr_value_by_name;
	ops->getextattr_value_by_id = ncloud_getextattr_value_by_id;
	ops->setextattr_value = ncloud_setextattr_value;
	ops->setextattr_value_by_id = ncloud_setextattr_value_by_id;
	ops->remove_extattr_by_id = ncloud_remove_extattr_by_id;
	ops->remove_extattr_by_name = ncloud_remove_extattr_by_name;
	*/

	ops->is_referral = ncloud_is_referral;
}

/* export methods that create object handles
 */

/* lookup_path
 * modeled on old api except we don't stuff attributes.
 * KISS
 */

fsal_status_t ncloud_lookup_path(struct fsal_export *exp_hdl,
				 const char *path,
				 struct fsal_obj_handle **handle,
				 struct attrlist *attrs_out)
{
	LogDebug(COMPONENT_FSAL, "trace: call ncloud_lookup_path on path %s", path);
	/** Handle given by the subfsal. */
	struct fsal_obj_handle *sub_handle = NULL;
	*handle = NULL;

	/* call underlying FSAL ops with underlying FSAL handle */
	struct ncloud_fsal_export *exp =
		container_of(exp_hdl, struct ncloud_fsal_export, export);

	/* call to subfsal lookup with the good context. */
	fsal_status_t status;

	op_ctx->fsal_export = exp->export.sub_export;

	status = exp->export.sub_export->exp_ops.lookup_path(
				exp->export.sub_export, path, &sub_handle,
				attrs_out);

	op_ctx->fsal_export = &exp->export;

	int id = NCLOUD_INVALID_PATH_ID;
	/* get the directory id for directories */
	if (sub_handle->type == DIRECTORY) 
		id = ncloud_path_map_load_dir_id(path);
	else if (sub_handle->type == REGULAR_FILE)
		id = ncloud_path_map_load_file_id(path);

	/* check and update the file size and timestamps from nCloud file meta */
	//ncloud_stat_file(path, attrs_out);

	/* wraping the subfsal handle in a ncloud handle. */
	/* Note : ncloud filesystem = subfsal filesystem or NULL ? */
	status = ncloud_alloc_and_check_handle(exp, sub_handle, NULL, handle,
					     status, path);
	if (!FSAL_IS_ERROR(status) && handle && *handle) {
		struct ncloud_fsal_obj_handle *hdl =
			container_of(*handle, struct ncloud_fsal_obj_handle, obj_handle);
		hdl->ncloud.path_id = id;
	}
	return status;
}

/* create_handle
 * Does what original FSAL_ExpandHandle did (sort of)
 * returns a ref counted handle to be later used in cache_inode etc.
 * NOTE! you must release this thing when done with it!
 * BEWARE! Thanks to some holes in the *AT syscalls implementation,
 * we cannot get an fd on an AF_UNIX socket, nor reliably on block or
 * character special devices.  Sorry, it just doesn't...
 * we could if we had the handle of the dir it is in, but this method
 * is for getting handles off the wire for cache entries that have LRU'd.
 * Ideas and/or clever hacks are welcome...
 */

fsal_status_t ncloud_create_handle(struct fsal_export *exp_hdl,
				   struct gsh_buffdesc *hdl_desc,
				   struct fsal_obj_handle **handle,
				   struct attrlist *attrs_out)
{
	LogInfo(COMPONENT_FSAL, "trace: call ncloud_create_handle (%lu) (%d)", hdl_desc->len, *((int*) hdl_desc->addr));
	/* current ncloud export. */
	struct ncloud_fsal_export *export =
		container_of(exp_hdl, struct ncloud_fsal_export, export);

	struct fsal_obj_handle *sub_handle; /*< New subfsal handle.*/
	*handle = NULL;

	size_t ncloud_len = sizeof(int);
	struct gsh_buffdesc sub_hdl_desc = {hdl_desc->addr + ncloud_len, hdl_desc->len - ncloud_len};

	/* use the id from client to obtain the path if available */
	int id;
	memcpy(&id, hdl_desc->addr, sizeof(int));
	char path[PATH_MAX];
	path[0] = 0;
	if (ncloud_path_id_to_path(export, id, path) <= 0) {
		LogMajor(COMPONENT_FSAL,
			"Failed to get path from cache, id = %d", id
		);
		return fsalstat(ERR_FSAL_STALE, 0);
	} else {
		LogDebug(COMPONENT_FSAL, "Path %s found for id = %d", path, id);
	}

	/* call to subfsal lookup with the good context. */
	fsal_status_t status;

	op_ctx->fsal_export = export->export.sub_export;

	status = export->export.sub_export->exp_ops.create_handle(
			export->export.sub_export, &sub_hdl_desc, &sub_handle,
			attrs_out);

	op_ctx->fsal_export = &export->export;

	/* wraping the subfsal handle in a ncloud handle. */
	/* Note : ncloud filesystem = subfsal filesystem or NULL ? */
	return ncloud_alloc_and_check_handle(export, sub_handle, NULL, handle,
					     status, path);
}
