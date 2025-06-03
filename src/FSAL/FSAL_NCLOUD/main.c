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
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

/* main.c
 * Module core functions
 */

#include "config.h"

#include "fsal.h"
#include <libgen.h>		/* used for 'dirname' */
#include <pthread.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include "gsh_list.h"
#include "FSAL/fsal_init.h"
#include "ncloud_methods.h"


/* FSAL name determines name of shared library: libfsal<name>.so */
const char myname[] = "ncloud";

/* my module private storage
 */


struct ncloud_fsal_module NCLOUD = {
	.module = {
		.fs_info = {
			.maxfilesize = UINT64_MAX,
			.maxlink = 0,
			.maxnamelen = 1024,
			.maxpathlen = PATH_MAX,
			.no_trunc = true,
			.chown_restricted = true,
			.case_insensitive = false,
			.case_preserving = true,
			.link_support = false,
			.symlink_support = false,
			.lock_support = true,
			.lock_support_async_block = false,
			.named_attr = true,
			.unique_handles = true,
			.acl_support = FSAL_ACLSUPPORT_ALLOW,
			.cansettime = true,
			.homogenous = true,
			.supported_attrs = ALL_ATTRIBUTES,
			.maxread = FSAL_MAXIOSIZE,
			.maxwrite = FSAL_MAXIOSIZE,
			.umask = 0,
			.auth_exportpath_xdev = false,
			.link_supports_permission_checks = true,
			.expire_time_parent = -1,
		}
	}
};

/* Module methods
 */

/* init_config
 * must be called with a reference taken (via lookup_fsal)
 */

static fsal_status_t init_config(struct fsal_module *fsal_module,
				 config_file_t config_struct,
				 struct config_error_type *err_type)
{
	/* Configuration setting options:
	 * 1. there are none that are changeable. (this case)
	 *
	 * 2. we set some here.  These must be independent of whatever
	 *    may be set by lower level fsals.
	 *
	 * If there is any filtering or change of parameters in the stack,
	 * this must be done in export data structures, not fsal params because
	 * a stackable could be configured above multiple fsals for multiple
	 * diverse exports.
	 */

	display_fsinfo(fsal_module);
	LogDebug(COMPONENT_FSAL,
		 "FSAL INIT: Supported attributes mask = 0x%" PRIx64,
		 fsal_module->fs_info.supported_attrs);

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/* Internal nCloud method linkage to export object
 */

fsal_status_t ncloud_create_export(struct fsal_module *fsal_hdl,
				   void *parse_node,
				   struct config_error_type *err_type,
				   const struct fsal_up_vector *up_ops);

/* Module initialization.
 * Called by dlopen() to register the module
 * keep a private pointer to me in myself
 */

/* linkage to the exports and handle ops initializers
 */
MODULE_INIT void ncloud_init(void)
{
	int retval;
	struct fsal_module *myself = &NCLOUD.module;

	retval = register_fsal(myself, myname, FSAL_MAJOR_VERSION,
			       FSAL_MINOR_VERSION, FSAL_ID_NO_PNFS);
	if (retval != 0) {
		fprintf(stderr, "nCloud module failed to register");
		return;
	}
	myself->m_ops.create_export = ncloud_create_export;
	myself->m_ops.init_config = init_config;

	/* Initialize the fsal_obj_handle ops for FSAL nCloud */
	ncloud_handle_ops_init(&NCLOUD.handle_ops);
}

MODULE_FINI void ncloud_unload(void)
{
	int retval;

	retval = unregister_fsal(&NCLOUD.module);
	if (retval != 0) {
		fprintf(stderr, "nCloud module failed to unregister");
		return;
	}
}
