// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * Copyright © 2019-2025, CUHK.
 * Author: Helen H. W. Chan <hwchan@cuhk.edu.hk>
 *
 * contributor : Helen H. W. Chan <hwchan@cuhk.edu.hk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * -------------
 */

/**
 * @brief NCLOUD methods for handles
 */

/* NCLOUD methods for handles
 */

#ifndef NCLOUD_METHODS_H
#define NCLOUD_METHODS_H

#include "FSAL/fsal_commonlib.h"
#include "ds/rbtree_augmented.h"
#include <ncloud/client.h>
#include <linux/limits.h>
#include <pthread.h>

#define NCLOUD_BUF_MAX_NUM_SPLITS 	(16)
#define NCLOUD_CACHE_MAX_NUM_SPLITS	(8192)
#define NCLOUD_CACHE_MAX_PER_FILE   (512 << 20)
#define NCLOUD_CACHE_DIR		".cache"
#define NCLOUD_PATH_MAP_FILE		".path_map"
#define NCLOUD_DIR_PATH_ID		".dir_id"
#define NCLOUD_PATH_MAP_MAX_NUM		(1 << 27)
#define NCLOUD_INVALID_PATH_ID		((int) -1)
#define NCLOUD_MAX_TRANS_SIZE		(128 << 20)

#define max_of(x,y)  ((x) > (y)? (x) : (y))
#define min_of(x,y)  ((x) < (y)? (x) : (y))

struct ncloud_fsal_obj_handle;

/**
 * Buffer structure for nCloud
 */
struct ncloud_buffer {
	char *buf; /* buffer data */
	uint64_t offset;
	uint64_t bytes_written[NCLOUD_BUF_MAX_NUM_SPLITS]; /* write buffer offset */
	uint64_t size; /* buffer size */
	uint8_t num_splits;
};

bool ncloud_init_buffer(struct ncloud_buffer *buf);
void ncloud_release_buffer(struct ncloud_buffer *buf);
/** 
 * Caller should initialize buf using ncloud_init_buffer() before calling this
 * function
 */
bool ncloud_allocate_buffer(struct ncloud_buffer *buf,
			    uint64_t split_size,
			    uint8_t num_splits);

uint64_t ncloud_get_buffer_split_size(struct ncloud_buffer *buf);

struct ncloud_disk_cache_range {
	uint64_t offset;
	uint32_t length;
};

struct ncloud_disk_cache_item {
	struct rb_node node;
	uint64_t offset;
	uint32_t length;
	bool in_use;
};

struct ncloud_disk_cache_head {
	int start_idx;
	int num_splits_in_use;
	pthread_mutex_t lock;
	struct rb_root root;
	struct ncloud_disk_cache_item splits[NCLOUD_CACHE_MAX_NUM_SPLITS];
};

void ncloud_disk_cache_item_init(struct ncloud_disk_cache_item *t);
void ncloud_disk_cache_item_release(struct ncloud_disk_cache_item *t);

void ncloud_disk_cache_head_init(struct ncloud_disk_cache_head *h);
void ncloud_disk_cache_head_release(struct ncloud_disk_cache_head *h);

bool ncloud_disk_cache_item_add(struct ncloud_fsal_obj_handle *handle, uint64_t offset, uint32_t length, bool is_write);

/*
 * Get ranges of disk cache which (partially) cover a specific range
 * @param[in] handle		ncloud object handle
 * @param[in] offset		start of the specific range
 * @param[in] length		length of the specific range
 * @param[out] ranges		ranges of disk cache (partially) cover in the specific range
 * @param[in] is_write          whether to check against write or read records
 * @param[in] is_remove         remove ranges from the cache record
 *
 * @return number of ranges in of disk cache found
 */
int ncloud_disk_cache_get_ranges(struct ncloud_fsal_obj_handle *handle, uint64_t offset, uint32_t length, struct ncloud_disk_cache_range *ranges, bool is_write, bool is_remove);

/**
 * Write data to disk cache
 *
 * @param[in] handle		ncloud object handle
 * @param[in] offset		data offset in file 
 * @param[in] buf		data buffer
 * @param[in] length		data length
 */
ssize_t ncloud_write_disk_cache(struct ncloud_fsal_obj_handle *handle, uint64_t offset, char *buf, uint64_t length);

/**
 * Write data to disk cache
 *
 * @param[in] handle		ncloud object handle
 * @param[in] offset		data offset in file
 * @param[in, out] buf		data buffer, preallocated with size length
 * @param[in] length		data length
 */
ssize_t ncloud_read_disk_cache(struct ncloud_fsal_obj_handle *handle, uint64_t offset, char *buf, uint64_t length);

/**
 * Purge data in disk cache
 *
 * @param[in] handle		ncloud object handle
 * @param[in] offset		data offset in file
 * @param[in] length		data length
 */
bool ncloud_purge_disk_cache(struct ncloud_fsal_obj_handle *handle, uint64_t offset, uint64_t length);

struct ncloud_fsal_module {
	struct fsal_module module;
	struct fsal_obj_ops handle_ops;
};

extern struct ncloud_fsal_module NCLOUD;

/**
 * Structure used to store data for read_dirents callback.
 *
 * Before executing the upper level callback (it might be another
 * stackable fsal or the inode cache), the context has to be restored.
 */
struct ncloud_readdir_state {
	fsal_readdir_cb cb; /*< Callback to the upper layer. */
	struct ncloud_fsal_export *exp; /*< Export of the current ncloudal. */
	void *dir_state; /*< State to be sent to the next callback. */
	char path[PATH_MAX];
};

extern struct fsal_up_vector fsal_up_top;
void ncloud_handle_ops_init(struct fsal_obj_ops *ops);

/*
 * NCLOUD internal export
 */
struct ncloud_fsal_export {
	struct fsal_export export;
	/* Other private export data goes here */
	struct {
		int namespace_id; /*< ncloud namespace id */
		char *storage_class;  /*< ncloud storage class name */
		char *proxy_ip; /*< ncloud proxy ip */
		uint16_t proxy_port; /*< ncloud proxy port */
		struct {
			int fd; /*< file descriptor */
			char *map_addr; /*< mmapped address */
			int map_size; /*< mmapped size */

			unsigned int *record_offsets; /*< offsets of the records from the mmapped address */
			int next_idx; /*< next empty slot to search for inserting new records */

			pthread_rwlock_t lock; /*< lock for concurrent operations */
		} path_map; /*< ncloud directory path mapping */
    bool cache_to_disk_after_read;
	} ncloud;
};

fsal_status_t ncloud_lookup_path(struct fsal_export *exp_hdl,
				 const char *path,
				 struct fsal_obj_handle **handle,
				 struct attrlist *attrs_out);

fsal_status_t ncloud_create_handle(struct fsal_export *exp_hdl,
				   struct gsh_buffdesc *hdl_desc,
				   struct fsal_obj_handle **handle,
				   struct attrlist *attrs_out);

fsal_status_t ncloud_alloc_and_check_handle(
		struct ncloud_fsal_export *export,
		struct fsal_obj_handle *sub_handle,
		struct fsal_filesystem *fs,
		struct fsal_obj_handle **new_handle,
		fsal_status_t subfsal_status,
		const char *path);

/*
 * NCLOUD internal object handle
 *
 * It contains a pointer to the fsal_obj_handle used by the subfsal.
 *
 * AF_UNIX sockets are strange ducks.  I personally cannot see why they
 * are here except for the ability of a client to see such an animal with
 * an 'ls' or get rid of one with an 'rm'.  You can't open them in the
 * usual file way so open_by_handle_at leads to a deadend.  To work around
 * this, we save the args that were used to mknod or lookup the socket.
 */

struct ncloud_fsal_obj_handle {
	struct fsal_obj_handle obj_handle; /*< Handle containing ncloud data.*/
	struct fsal_obj_handle *sub_handle; /*< Handle containing VFS data.*/
	int32_t refcnt;		/*< Reference count.  This is signed to make
				   mistakes easy to see. */

	/* properties for ncloud */
	struct {
		ncloud_conn_t conn;  /*< nCloud connection */

		char path[PATH_MAX]; /* name of object */
		int path_id; /* id of the name in cache */

		uint64_t last_written_offset; /* last written offset */
		uint64_t append_size; /* size of appends */
		struct ncloud_buffer write_buf; /* write buffer */

		uint64_t last_read_offset; /* last read offset */
		uint64_t read_size; /* size of reads */
		struct ncloud_buffer read_buf; /* read buffer */

		bool is_write; /* whether the file is open for write */

		struct {
			struct ncloud_disk_cache_head read_list;
			struct ncloud_disk_cache_head write_list;
			FILE *fd;
		} disk_cache;

		pthread_rwlock_t buf_cache_lock;

	} ncloud;
};

/**
 * Init nCloud object handle
 * @param[in] export	fsal export
 * @param[out] handle	ncloud object handle which contains the connection to ncloud
 * @param[in] path	path to the object
 * @param[in] write_buf		pointer to write buffer
 * @param[in] write_buf_size	size of the write buffer
 * @param[in] read_buf		pointer to read buffer
 * @param[in] read_buf_size	size of the read buffer
 */
void ncloud_init_obj_handle(struct ncloud_fsal_export *export,
			    struct ncloud_fsal_obj_handle *handle,
			    const char *path,
			    char *write_buf,
			    uint64_t write_buf_size,
			    char *read_buf,
			    uint64_t read_buf_size
);

void ncloud_release_handle_resources(struct ncloud_fsal_export *export,
			    struct ncloud_fsal_obj_handle *handle
);

void ncloud_set_write_buf(struct ncloud_fsal_obj_handle *handle,
			  char *write_buf,
			  uint64_t write_buf_size,
			  uint64_t write_buf_offset);
void ncloud_set_read_buf(struct ncloud_fsal_obj_handle *handle,
			 char *read_buf,
			 uint64_t read_buf_size,
			 uint64_t read_buf_offset);

/**
 * Get expected append size for file write
 * @param[in] export	fsal export
 * @param[in] handle	ncloud object handle which contains the connection to ncloud
 * @return expected append size for file write
 */
unsigned long int ncloud_get_append_size(struct ncloud_fsal_export *export, struct ncloud_fsal_obj_handle *handle);

/**
 * Get expected read size for file read 
 * @param[in] export	fsal export
 * @param[in] handle	ncloud object handle which contains the connection to ncloud
 * @param[in] name	name of the file
 * @return expected append size for file write
 */
unsigned long int ncloud_get_read_size(struct ncloud_fsal_export *export, struct ncloud_fsal_obj_handle *handle, char *name);

/**
 * Get the attributes (size and timestamps) of a file
 * @param[in] name	name of the file
 * @param[out] attrs_out	structure for holding the file attributes
 * @return whether the file attributes are obtained and updated to attrs_out
 */
bool ncloud_stat_file(const char *name, struct attrlist *attrs_out);

/**
 * Update the metadata (attributes) of a file or files under a path
 * @param[in] export	fsal export
 * @param[in] name	path (file or directory name) to update
 * @return whether the update (request) is successful
 */
bool ncloud_update_meta(struct ncloud_fsal_export *export, char *name);

/**
 * Create directory recursively for a file path, under a parent directory
 * @param[in] parent	path of the parent directory
 * @param[in] path	path of the file
 * @return whether the directories contained in path is created successful
 */
bool ncloud_create_directory(const char *parent, const char *path);

/**
 * Get the NFS server-side mounting point
 * @return a path to the NFS server-side mounting point
 */
const char* get_mount_path();

static inline bool is_dot_or_dotdot(const char *name) {
	return name && (strcmp(name, ".") == 0 || strcmp(name, "..") == 0);
}

/**
 * Tell whether the file/directory is a system file/directory by its name
 * @param[in] name	file name (not path)
 * @return whether this file/directory is a system file/directory
 */
bool ncloud_is_system_file(const char *name);

/**
 * Get path by path id
 * @param[in] export	ncloud fsal export
 * @param[in] id	path id
 * @param[out] path	placeholder for path
 * @return length of the path; 0 means 'path not found'
 */
size_t ncloud_path_id_to_path(struct ncloud_fsal_export *export, int id, char *path);

/**
 * Map a new path
 * @param[in] export	ncloud fsal export
 * @param[in] path	new path
 * @return id of the cached path; -1 means 'path not cached'
 */
int ncloud_path_map_add(struct ncloud_fsal_export *export, const char *path);

/**
 * Remove a mapped path
 * @param[in] export	ncloud fsal export
 * @param[in] id	path id
 * @return whether the id is mapped to a valid path
 */
bool ncloud_path_map_remove(struct ncloud_fsal_export *export, int id);

/**
 * Update a mapped path
 * @param[in] export	ncloud fsal export
 * @param[in] id	path id
 * @param[in] path	the new path
 * @return whether the entry is updated
 */
bool ncloud_path_map_update(struct ncloud_fsal_export *export, int id, const char *path);

/**
 * Check if the directory id is valid (in a valid range)
 * @param[in] id	path id to check
 * @return whether the given id is valid
 */
bool ncloud_path_map_is_id_valid(int id);

/**
 * Save the id (to a hidden file) under the directory
 * @param[in] path	directory path
 * @param[in] id	id of the directory
 * @return whether the id is successfully saved
 */
bool ncloud_path_map_save_dir_id(const char *path, int id);
/**
 * Remove the id under the directory
 * @param[in] path	directory path
 * @return the id of the directory (NCLOUD_INVALID_PATH_ID if the id or directory does not exist)
 */
int ncloud_path_map_erase_dir_id(const char *path);
/**
 * Load the id under the directory
 * @param[in] path	directory path
 * @return the id of the directory (NCLOUD_INVALID_PATH_ID if the id or directory does not exist)
 */
int ncloud_path_map_load_dir_id(const char *path);

/**
 * Save the id for a file 
 * @param[in] path	file path
 * @param[in] id	path id
 * @return whether the id is successfully saved
 */
bool ncloud_path_map_save_file_id(const char *path, int id);
/**
 * Load the id of a file
 * @param[in] path	file path
 * @return the id of the directory (-1 if the id or directory does not exist)
 */
int ncloud_path_map_load_file_id(const char *path);

/**
 * Scan the on-disk mapping back into memory
 * (1) figure out the latest mapping on disk
 * (2) read <id,on-disk offset> into memory, check if needed
 * (3) build a new mapping file on disk, and migrate the <id,offset> mapping to this new file
 *
 * return whether the operation completes sucessfully
 */
bool ncloud_path_map_scan_ondisk_mapping_to_mem(struct ncloud_fsal_export *export, bool validate);

/**
 * Init the path mapping for upon the initialization of export
 * @param[in,out] export	export under init
 * @return whether the init is successful
 */
bool ncloud_path_map_bootstrap(struct ncloud_fsal_export *export);
/**
 * Cleaup the path mapping for upon the release of export
 * @param[in,out] export	export under release 
 * @return always true
 */
bool ncloud_path_map_shutdown(struct ncloud_fsal_export *export);

double get_duration(const struct timespec start, const struct timespec end);

int ncloud_fsal_open(struct ncloud_fsal_obj_handle *, int, fsal_errors_t *);
int ncloud_fsal_readlink(struct ncloud_fsal_obj_handle *, fsal_errors_t *);

static inline bool ncloud_unopenable_type(object_file_type_t type)
{
	if ((type == SOCKET_FILE) || (type == CHARACTER_FILE)
	    || (type == BLOCK_FILE)) {
		return true;
	} else {
		return false;
	}
}

/* I/O management */
fsal_status_t ncloud_close(struct fsal_obj_handle *obj_hdl);

/* Multi-FD */
fsal_status_t ncloud_open2(struct fsal_obj_handle *obj_hdl,
			   struct state_t *state,
			   fsal_openflags_t openflags,
			   enum fsal_create_mode createmode,
			   const char *name,
			   struct attrlist *attrs_in,
			   fsal_verifier_t verifier,
			   struct fsal_obj_handle **new_obj,
			   struct attrlist *attrs_out,
			   bool *caller_perm_check);
bool ncloud_check_verifier(struct fsal_obj_handle *obj_hdl,
			   fsal_verifier_t verifier);
fsal_openflags_t ncloud_status2(struct fsal_obj_handle *obj_hdl,
				struct state_t *state);
fsal_status_t ncloud_reopen2(struct fsal_obj_handle *obj_hdl,
			     struct state_t *state,
			     fsal_openflags_t openflags);
void ncloud_read2(struct fsal_obj_handle *obj_hdl,
		  bool bypass,
		  fsal_async_cb done_cb,
		  struct fsal_io_arg *read_arg,
		  void *caller_arg);
void ncloud_write2(struct fsal_obj_handle *obj_hdl,
		   bool bypass,
		   fsal_async_cb done_cb,
		   struct fsal_io_arg *write_arg,
		   void *caller_arg);
fsal_status_t ncloud_seek2(struct fsal_obj_handle *obj_hdl,
			   struct state_t *state,
			   struct io_info *info);
fsal_status_t ncloud_io_advise2(struct fsal_obj_handle *obj_hdl,
				struct state_t *state,
				struct io_hints *hints);
fsal_status_t ncloud_commit2(struct fsal_obj_handle *obj_hdl, off_t offset,
			     size_t len);
fsal_status_t ncloud_lock_op2(struct fsal_obj_handle *obj_hdl,
			      struct state_t *state,
			      void *p_owner,
			      fsal_lock_op_t lock_op,
			      fsal_lock_param_t *req_lock,
			      fsal_lock_param_t *conflicting_lock);
fsal_status_t ncloud_close2(struct fsal_obj_handle *obj_hdl,
			    struct state_t *state);
fsal_status_t ncloud_fallocate(struct fsal_obj_handle *obj_hdl,
			       struct state_t *state, uint64_t offset,
			       uint64_t length, bool allocate);

/* extended attributes management */
fsal_status_t ncloud_list_ext_attrs(struct fsal_obj_handle *obj_hdl,
				    unsigned int cookie,
				    fsal_xattrent_t *xattrs_tab,
				    unsigned int xattrs_tabsize,
				    unsigned int *p_nb_returned,
				    int *end_of_list);
fsal_status_t ncloud_getextattr_id_by_name(struct fsal_obj_handle *obj_hdl,
					   const char *xattr_name,
					   unsigned int *pxattr_id);
fsal_status_t ncloud_getextattr_value_by_name(struct fsal_obj_handle *obj_hdl,
					      const char *xattr_name,
					      void *buffer_addr,
					      size_t buffer_size,
					      size_t *p_output_size);
fsal_status_t ncloud_getextattr_value_by_id(struct fsal_obj_handle *obj_hdl,
					    unsigned int xattr_id,
					    void *buffer_addr,
					    size_t buffer_size,
					    size_t *p_output_size);
fsal_status_t ncloud_setextattr_value(struct fsal_obj_handle *obj_hdl,
				      const char *xattr_name,
				      void *buffer_addr,
				      size_t buffer_size,
				      int create);
fsal_status_t ncloud_setextattr_value_by_id(struct fsal_obj_handle *obj_hdl,
					    unsigned int xattr_id,
					    void *buffer_addr,
					    size_t buffer_size);
fsal_status_t ncloud_remove_extattr_by_id(struct fsal_obj_handle *obj_hdl,
					  unsigned int xattr_id);
fsal_status_t ncloud_remove_extattr_by_name(struct fsal_obj_handle *obj_hdl,
					    const char *xattr_name);

#endif			/* NCLOUD_METHODS_H */
