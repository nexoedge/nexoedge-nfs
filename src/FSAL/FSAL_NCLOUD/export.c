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

/* export.c
 * nCloud FSAL export object
 */

#include "config.h"

#include "fsal.h"
#include <libgen.h>		/* used for 'dirname' */
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <os/mntent.h>
#include <os/quota.h>
#include <dlfcn.h>
#include "gsh_list.h"
#include "config_parsing.h"
#include "fsal_convert.h"
#include "FSAL/fsal_commonlib.h"
#include "FSAL/fsal_config.h"
#include "ncloud_methods.h"
#include "nfs_exports.h"
#include "export_mgr.h"

/* helpers init export
 */
static fsal_status_t ncloud_export_init(struct ncloud_fsal_export *export) {
	if (export == NULL)
		return fsalstat(ERR_FSAL_INVAL, EINVAL);

	/* create file cache directory */
	char cache_dir_path[PATH_MAX];
	snprintf(cache_dir_path, PATH_MAX, "%s/%s", get_mount_path(), NCLOUD_CACHE_DIR);
	if (mkdir(cache_dir_path, 0777) != 0 && errno != EEXIST) {
		LogMajor(
			COMPONENT_FSAL,
			"Failed to create cache directory (%s) for write",
			cache_dir_path
		);
	}

	/* create/open directory cache file */
	if (!ncloud_path_map_bootstrap(export)) {
		LogMajor(
			COMPONENT_FSAL,
			"Failed to init the directory cache"
		);
		return fsalstat(ERR_FSAL_FAULT, 0);
	}

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/* export object methods
 */

static void release(struct fsal_export *exp_hdl)
{
	struct ncloud_fsal_export *myself;
	struct fsal_module *sub_fsal;

	LogMajor(COMPONENT_FSAL, "trace: call export release");
	myself = container_of(exp_hdl, struct ncloud_fsal_export, export);

	/* close the directory cache file */
	ncloud_path_map_shutdown(myself);

	/* Release the sub_export */
	sub_fsal = myself->export.sub_export->fsal;
	myself->export.sub_export->exp_ops.release(myself->export.sub_export);
	fsal_put(sub_fsal);

	fsal_detach_export(exp_hdl->fsal, &exp_hdl->exports);
	free_export_ops(exp_hdl);

	gsh_free(myself);	/* elvis has left the building */
}

static fsal_status_t get_dynamic_info(struct fsal_export *exp_hdl,
				      struct fsal_obj_handle *obj_hdl,
				      fsal_dynamicfsinfo_t *infop)
{
	struct ncloud_fsal_export *export =
		container_of(exp_hdl, struct ncloud_fsal_export,
			     export);

	LogDebug(COMPONENT_FSAL, "trace: call get_dynamic_info");
	/* setup and send request to nCloud */
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int ret = 0;

	request_t req;
	ncloud_conn_t conn;
	if (ncloud_conn_t_init(export->ncloud.proxy_ip, export->ncloud.proxy_port, &conn, 1) < 0) {
		LogMajor(
			COMPONENT_FSAL,
			"Failed to init connection to get dynamic info"
		);
		fsal_error = ERR_FSAL_XDEV;
		ret = -1;
	} else {
		set_get_storage_capacity_request(&req);
		if (send_request(&conn, &req)) {
			fsal_error = ERR_FSAL_XDEV;
			ret = -1;
		} else {
			//memset(infop, 0, sizeof(fsal_dynamicfsinfo_t));

			infop->total_bytes = req.stats.capacity;
			infop->free_bytes = (req.stats.capacity >= req.stats.usage? req.stats.capacity - req.stats.usage : 0);
			infop->avail_bytes = req.stats.capacity - req.stats.usage;
			infop->total_files = req.stats.file_limit;
			infop->free_files = req.stats.file_limit - req.stats.file_count;
			infop->avail_files = req.stats.file_limit - req.stats.file_count;
			infop->time_delta.tv_sec = 1;
			infop->time_delta.tv_sec = 0;

			LogDebug(
				COMPONENT_FSAL,
				"Get dynamic info total = %lu, free = %lu, avail = %lu, total files = %lu, avail files = %lu, free files= %lu",
				infop->total_bytes,
				infop->free_bytes,
				infop->avail_bytes,
				infop->total_files,
				infop->avail_files,
				infop->free_files
			);
		}
		request_t_release(&req);
		ncloud_conn_t_release(&conn);
	}

	return fsalstat(fsal_error, ret);
}

static uint32_t fs_maxnamelen(struct fsal_export *exp_hdl)
{
	LogFullDebug(COMPONENT_FSAL, "trace: called fs_maxnamelen");
	return container_of(exp_hdl, struct ncloud_fsal_export, export)
		->export.fsal->fs_info.maxnamelen;
}

static uint32_t fs_maxpathlen(struct fsal_export *exp_hdl)
{
	LogFullDebug(COMPONENT_FSAL, "trace: called fs_maxpathlen");
	return container_of(exp_hdl, struct ncloud_fsal_export, export)
		->export.fsal->fs_info.maxpathlen;
}

/* get_quota
 * return quotas for this export.
 * path could cross a lower mount boundary which could
 * mask lower mount values with those of the export root
 * if this is a real issue, we can scan each time with setmntent()
 * better yet, compare st_dev of the file with st_dev of root_fd.
 * on linux, can map st_dev -> /proc/partitions name -> /dev/<name>
 */

static fsal_status_t get_quota(struct fsal_export *exp_hdl,
			       const char *filepath, int quota_type,
			       int quota_id,
			       fsal_quota_t *pquota)
{
	LogInfo(COMPONENT_FSAL, "trace: called get_quota");
	return fsalstat(ERR_FSAL_NOTSUPP, -1);
}

/* set_quota
 * same lower mount restriction applies
 */

static fsal_status_t set_quota(struct fsal_export *exp_hdl,
			       const char *filepath, int quota_type,
			       int quota_id,
			       fsal_quota_t *pquota, fsal_quota_t *presquota)
{
	LogInfo(COMPONENT_FSAL, "trace: called set_quota");
	return fsalstat(ERR_FSAL_NOTSUPP, -1);
}

static struct state_t *ncloud_alloc_state(struct fsal_export *exp_hdl,
					  enum state_type state_type,
					  struct state_t *related_state)
{
	struct ncloud_fsal_export *export =
		container_of(exp_hdl, struct ncloud_fsal_export, export);

	state_t *state;

	LogDebug(COMPONENT_FSAL, "trace: called alloc_state");

	op_ctx->fsal_export = export->export.sub_export;
	state = export->export.sub_export->exp_ops.alloc_state(exp_hdl, state_type, related_state);
	op_ctx->fsal_export = &export->export;

	return state;
}

static void ncloud_free_state(struct fsal_export *exp_hdl,
			      struct state_t *state)
{
	struct ncloud_fsal_export *export =
		container_of(exp_hdl, struct ncloud_fsal_export, export);

	LogInfo(COMPONENT_FSAL, "trace: called free_state");
	
	op_ctx->fsal_export = export->export.sub_export;
	export->export.sub_export->exp_ops.free_state(exp_hdl, state);
	op_ctx->fsal_export = &export->export;
}

static fsal_status_t wire_to_host(struct fsal_export *exp_hdl,
				    fsal_digesttype_t in_type,
				    struct gsh_buffdesc *fh_desc,
				    int flags)
{
	struct ncloud_fsal_export *exp =
		container_of(exp_hdl, struct ncloud_fsal_export, export);

	/* exclude the part for ncloud handle */
	size_t ncloud_len = sizeof(int);

	/* past the part for vfs for processing */
	struct gsh_buffdesc sub_fh_desc = {fh_desc->addr + ncloud_len, fh_desc->len - ncloud_len};
	
	op_ctx->fsal_export = exp->export.sub_export;
	fsal_status_t result =
		exp->export.sub_export->exp_ops.wire_to_host(
			exp->export.sub_export, in_type, &sub_fh_desc, flags);
	op_ctx->fsal_export = &exp->export;

	/* update length if there is any change */
	if (sub_fh_desc.len != fh_desc->len - ncloud_len) {
		fh_desc->len = ncloud_len + sub_fh_desc.len;
	}

	LogInfo(COMPONENT_FSAL,
		"trace: wire_to_host len = %lu id = %d",
		fh_desc->len, *((int*) fh_desc->addr)
	);

	return result;
}

void ncloud_export_ops_init(struct export_ops *ops)
{
	ops->release = release;
	ops->lookup_path = ncloud_lookup_path;
	ops->wire_to_host = wire_to_host;
	ops->create_handle = ncloud_create_handle;
	ops->get_fs_dynamic_info = get_dynamic_info;
	ops->get_quota = get_quota;
	ops->set_quota = set_quota;
	ops->free_state = ncloud_free_state;
	ops->alloc_state = ncloud_alloc_state;

	ops->fs_maxnamelen = fs_maxnamelen;
	ops->fs_maxpathlen = fs_maxpathlen;
}

static struct config_item ncloud_params[] = {
	CONF_ITEM_NOOP("name"),
	CONF_ITEM_STR("proxy_ip", 0, 16, "127.0.0.1", ncloud_fsal_export, ncloud.proxy_ip),
	CONF_ITEM_UI16("proxy_port", 0, 65535, 59001, ncloud_fsal_export, ncloud.proxy_port),
	CONF_ITEM_STR("storage_class", 0, 1024, "STANDARD", ncloud_fsal_export, ncloud.storage_class),
	CONF_ITEM_I32("namespace_id", -1, INT_MAX, -1, ncloud_fsal_export, ncloud.namespace_id),
  CONF_ITEM_BOOL("use_read_disk_cache", true, ncloud_fsal_export, ncloud.cache_to_disk_after_read),
	CONFIG_EOL
};

static struct config_block ncloud_block = {
	.dbus_interface_name = "org.ganesha.nfsd.config.fsal.ncloud%d",
	.blk_desc.name = "FSAL",
	.blk_desc.type = CONFIG_BLOCK,
	.blk_desc.u.blk.init = noop_conf_init,
	.blk_desc.u.blk.params = ncloud_params,
	.blk_desc.u.blk.commit = noop_conf_commit
};

/* create_export
 * Create an export point and return a handle to it to be kept
 * in the export list.
 * First lookup the fsal, then create the export and then put the fsal back.
 * returns the export with one reference taken.
 */

fsal_status_t ncloud_create_export(struct fsal_module *fsal_hdl,
				   void *parse_node,
				   struct config_error_type *err_type,
				   const struct fsal_up_vector *up_ops)
{
	struct ncloud_fsal_export *myself = gsh_calloc(1, sizeof(struct ncloud_fsal_export));
	int retval;

	LogInfo(COMPONENT_FSAL, "trace: call create_export");
	
	fsal_export_init(&myself->export);
	ncloud_export_ops_init(&myself->export.exp_ops);


	/* process our FSAL block to get the name of the fsal
	 * underneath us.
	 */
	if (parse_node) {
		retval = load_config_from_node(parse_node,
					       &ncloud_block,
					       myself,
					       true,
					       err_type);
		LogInfo(COMPONENT_FSAL,
			 "parse_node: %s:%u storage class = %s namespace id = %d",
			 myself->ncloud.proxy_ip,
			 myself->ncloud.proxy_port,
			 myself->ncloud.storage_class,
			 myself->ncloud.namespace_id
		);
		if (retval != 0) {
			gsh_free(myself);
			return fsalstat(ERR_FSAL_INVAL, 0);
		}
	}

	/* ncloud export init; TODO init using parameters if provided */
	fsal_status_t ncloud_init_status = ncloud_export_init(myself);
	if (FSAL_IS_ERROR(ncloud_init_status)) {
		gsh_free(myself);
		return ncloud_init_status;
	}

	struct fsal_module *fsal_stack;
	//ncloudal.subfsal.name = "VFS";
	fsal_stack = lookup_fsal("VFS");
	if (fsal_stack == NULL) {
		LogInfo(COMPONENT_FSAL,
			 "ncloud create export failed to lookup for FSAL VFS");
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	}

	fsal_status_t expres;
	expres = fsal_stack->m_ops.create_export(fsal_stack,
						 parse_node,
						 err_type,
						 up_ops);
	fsal_put(fsal_stack);

	LogFullDebug(COMPONENT_FSAL,
		     "FSAL %s refcount %"PRIu32,
		     fsal_stack->name,
		     atomic_fetch_int32_t(&fsal_stack->refcount));

	if (FSAL_IS_ERROR(expres)) {
		LogMajor(COMPONENT_FSAL,
			 "Failed to call create_export on underlying FSAL VFS");
		gsh_free(myself);
		return expres;
	}

	fsal_export_stack(op_ctx->fsal_export, &myself->export);

#ifdef EXPORT_OPS_INIT
	/*** FIX ME!!!
	 * Need to iterate through the lists to save and restore.
	 */
	ncloud_handle_ops_init(myself->export.obj_ops);
#endif				/* EXPORT_OPS_INIT */
	myself->export.up_ops = up_ops;
	myself->export.fsal = fsal_hdl;

	/* lock myself before attaching to the fsal.
	 * keep myself locked until done with creating myself.
	 */
	op_ctx->fsal_export = &myself->export;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}
