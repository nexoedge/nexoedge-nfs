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
 
#include "fsal.h"

#include "ncloud_methods.h"
#include <sys/file.h>			/* flock() */
#include <sys/mman.h>			/* mmap() */
#include <sys/types.h>			/* stat() */
#include <sys/stat.h>			/* stat() */
#include <unistd.h>			/* stat() */
#include <time.h>			/* clock_gettime() */

/**
 * Get the cache file path for a file
 *
 * @param[in] handle	ncloud object handle
 * @param[out] path	path to the disk cache file, should be of size PATH_MAX
 */
static bool ncloud_get_disk_cache_path(struct ncloud_fsal_obj_handle *handle, char *path);

double get_duration(const struct timespec start, const struct timespec end) {
	double duration = end.tv_sec - start.tv_sec;
	if (duration < 0)
		return 0;
	if (end.tv_nsec < start.tv_nsec) {
		duration += (end.tv_nsec + 1e9 - start.tv_nsec) * 1.0 / 1e9 - 1;
	} else {
		duration += (end.tv_nsec - start.tv_nsec) * 1.0 / 1e9;
	}
	return duration;
}
/**
 * helpers (nCloud)
 */
unsigned long int ncloud_get_append_size(struct ncloud_fsal_export *export, struct ncloud_fsal_obj_handle *handle) {
	if (export == NULL)
		return 0;


	/* use disposable connection */
	ncloud_conn_t conn;
	if (ncloud_conn_t_init(export->ncloud.proxy_ip, export->ncloud.proxy_port, &conn, 1) < 0) {
		LogMajor(
			COMPONENT_FSAL,
			"Failed to init connection to get the append size"
		);
		return 0;
	}

	unsigned long int size = 0;
	request_t req;
	if (set_get_append_size_request(&req, export->ncloud.storage_class) == -1 || send_request(&conn, &req) == -1) {
		LogMajor(
			COMPONENT_FSAL,
			"Failed to get append size for [%s]",
			export->ncloud.storage_class
		);
	} else {
		size = req.file.length;
	}

	/* release the request and connection */
	request_t_release(&req);
	ncloud_conn_t_release(&conn);
	
	return size;
}

unsigned long int ncloud_get_read_size(struct ncloud_fsal_export *export, struct ncloud_fsal_obj_handle *handle, char *name) {
	if (export == NULL)
		return 0;

	/* use disposable connection */
	ncloud_conn_t conn;
	if (ncloud_conn_t_init(export->ncloud.proxy_ip, export->ncloud.proxy_port, &conn, 1) < 0) {
		LogMajor(
			COMPONENT_FSAL,
			"Failed to init connection to get the append size"
		);
		return 0;
	}

	unsigned long int size = 0;
	request_t req;
	if (set_get_read_size_request(&req, name, export->ncloud.namespace_id) == -1 || send_request(&conn, &req) == -1) {
		LogMajor(
			COMPONENT_FSAL,
			"Failed to get read size for file %s",
			name
		);
	} else {
		size = req.file.length;
	}

	/* release the request and connection */
	request_t_release(&req);
	ncloud_conn_t_release(&conn);

	return size;
}

void ncloud_init_obj_handle(struct ncloud_fsal_export *export, struct ncloud_fsal_obj_handle *handle, const char *path, char *write_buf, uint64_t write_buf_size, char *read_buf, uint64_t read_buf_size) {
	/* store the path name of the object */
	snprintf(handle->ncloud.path, PATH_MAX, "%s", path? path : "");
	handle->ncloud.path_id = NCLOUD_INVALID_PATH_ID;

	/* Init without setting up connection (to nCloud) */
	ncloud_conn_t_init(export->ncloud.proxy_ip, export->ncloud.proxy_port, &handle->ncloud.conn, 0);

	/* information and buffer for write/append/overwrite */
	handle->ncloud.last_written_offset = 0;
	if (handle->sub_handle && handle->sub_handle->type == REGULAR_FILE) {
		/* update the file metadata, and get the file size if already exists */
		char obj_path[PATH_MAX];
		snprintf(obj_path, PATH_MAX, "%s", handle->ncloud.path + strlen(get_mount_path()) + 1);
		//LogInfo(COMPONENT_FSAL, "init_obj %s", obj_path);
		ncloud_update_meta(export, obj_path);
		struct attrlist attrs;
		attrs.type = REGULAR_FILE;
		if (ncloud_stat_file(handle->ncloud.path, &attrs)) {
			handle->ncloud.last_written_offset = attrs.filesize;
			handle->ncloud.path_id = attrs.fileid;
			LogDebug(COMPONENT_FSAL, "Init object stat okay path %s id = %d", handle->ncloud.path, handle->ncloud.path_id);
		} else {
			/* sometimes the file is still writing and the stats are incomplete, try to get the file id alone */
			handle->ncloud.path_id = ncloud_path_map_load_file_id(handle->ncloud.path);
			LogDebug(COMPONENT_FSAL, "Init object stat failed path %s id = %d", handle->ncloud.path, handle->ncloud.path_id);
		}
	}
	ncloud_init_buffer(&handle->ncloud.write_buf);
	handle->ncloud.append_size = ncloud_get_append_size(export, handle);

	/* information and buffer for read */
	handle->ncloud.last_read_offset = 0;
	ncloud_init_buffer(&handle->ncloud.read_buf);
	handle->ncloud.read_size = 0;

	/* disk cache for write and read */
	ncloud_disk_cache_head_init(&handle->ncloud.disk_cache.write_list);
	ncloud_disk_cache_head_init(&handle->ncloud.disk_cache.read_list);
	handle->ncloud.disk_cache.fd = NULL;

	pthread_rwlock_init(&handle->ncloud.buf_cache_lock, NULL);

	/* assume the file is not open for write */
	handle->ncloud.is_write = false;
}

static void ncloud_release_cache(struct ncloud_fsal_obj_handle *handle) {
	if (handle == NULL)
		return;
	char cache_path[PATH_MAX];
	ncloud_get_disk_cache_path(handle, cache_path);
	/* close and remove the disk cache file */
	if (handle->ncloud.disk_cache.fd != NULL) {
		fclose(handle->ncloud.disk_cache.fd);
		handle->ncloud.disk_cache.fd = NULL;
		unlink(cache_path);
	}
	/* release disk cache records */
	ncloud_disk_cache_head_init(&handle->ncloud.disk_cache.write_list);
	ncloud_disk_cache_head_init(&handle->ncloud.disk_cache.read_list);
	
}


void ncloud_release_handle_resources(struct ncloud_fsal_export *export, struct ncloud_fsal_obj_handle *handle) {
	if (handle == NULL)
		return;

	/* release nCloud connection */
	ncloud_conn_t_release(&handle->ncloud.conn);
	/* release all disk caches */
	ncloud_release_cache(handle);
	/* release all buffers */
	ncloud_release_buffer(&handle->ncloud.write_buf);
	ncloud_release_buffer(&handle->ncloud.read_buf);
}

/**
 * Read the file meta from files under the mount directory
 * Caller MUST check and only pass in files with type 'REGULAR_FILE'
 **/
bool ncloud_stat_file(const char *name, struct attrlist *attrs_out) {
	if (name == NULL || attrs_out == NULL)
		return false;
	/* skip objects that are not regular files (is this necessary??) */
	if ((attrs_out->type | REGULAR_FILE) != REGULAR_FILE)
		return true;
	/* try reading the file meta from the mount directory */
	char file_path[PATH_MAX];
	if (snprintf(file_path, PATH_MAX, "%s", name) < 0) {
		LogMajor(
			COMPONENT_FSAL,
			"Failed to obtain stats for file %s, path too long",
			name
		);
		return false;
	}
	FILE *fd = fopen(file_path, "r");
	if (fd == NULL)
		return false;
	int fid = 0; 
	/* format: file_id; file_size; create_time; last_access_time; last_modified_time */
	int num_fields = fscanf(fd,
		"%d;%lu;%lu;%lu;%lu",
		&fid,
		&attrs_out->filesize,
		&attrs_out->creation.tv_sec,
		&attrs_out->atime.tv_sec,
		&attrs_out->mtime.tv_sec
	);
	attrs_out->fileid = fid;
	fclose(fd);
	LogDebug(COMPONENT_FSAL,
		"get stats of file %s (at path %s) from ncloud metadata %lu;%lu;%lu;%lu;%lu, num_fields = %d",
		name,
		file_path,
		attrs_out->fileid,
		attrs_out->filesize,
		attrs_out->creation.tv_sec,
		attrs_out->atime.tv_sec,
		attrs_out->mtime.tv_sec,
		num_fields
	);
	return num_fields == 5;
}

/**
 * Update the metadata of a file / directory
 */
bool ncloud_update_meta(struct ncloud_fsal_export *export, char *name) {

	const char *mount_path = get_mount_path();

	if (export == 0 || name == 0) {
		return false;
	}

	/* use disposable connection */
	ncloud_conn_t conn;

	if (ncloud_conn_t_init(export->ncloud.proxy_ip, export->ncloud.proxy_port, &conn, 1) < 0) {
		LogMajor(
			COMPONENT_FSAL,
			"Failed to init connection to update metadata"
		);
		return 0;
	}

	char path[PATH_MAX];
	snprintf(path, PATH_MAX, "%s", is_dot_or_dotdot(name)? "/" : name);
	request_t req;
	/* request the list of file meta from nCloud */
	set_get_file_list_request(&req, export->ncloud.namespace_id, path);
	bool ret = send_request(&conn, &req) == 0;

	if (!ret)
		LogMajor(COMPONENT_FSAL, "Failed to update directory [%s] (%s) on nCloud", name, path);
	else
		LogInfo(COMPONENT_FSAL, "Update directory [%s] (%s) on nCloud with %d files", name, path, req.file_list.total);

	int i = 0; 
	char file_name[PATH_MAX];
	FILE *fd;
	/* update the ncloud mount directory according to the list of file meta retreived */
	for (i = 0; ret && i < req.file_list.total; i++) {
		LogDebug(
			COMPONENT_FSAL,
			"item = %d name = %s size = %lu (c,a,m)-time = (%lu,%lu,%lu)",
			i,
			req.file_list.list[i].fname,
			req.file_list.list[i].fsize,
			req.file_list.list[i].ctime,
			req.file_list.list[i].atime,
			req.file_list.list[i].mtime
		);
		/* create parent directories if needed */
		if (!ncloud_create_directory("", req.file_list.list[i].fname))
			continue;
		/* create the file record in the mount directory */
		if (snprintf(file_name, PATH_MAX, "%s/%s", mount_path, req.file_list.list[i].fname) < 0) {
			LogMajor(
				COMPONENT_FSAL,
				"Path name (%s/%s) is too long for file record",
				mount_path, req.file_list.list[i].fname
			); 
			continue;
		}
		int fid = NCLOUD_INVALID_PATH_ID;
		/* read the id from file */
		fid = ncloud_path_map_load_file_id(file_name);
		/* assigned new id to the file if the entry does not exist */
		if (fid == NCLOUD_INVALID_PATH_ID) {
			fid = ncloud_path_map_add(export, file_name);
		}
		LogDebug(COMPONENT_FSAL, "Update metadata of path %s with id %d", file_name, fid);
		/* open the recrod for write */
		fd = fopen(file_name, "r+");
		if (fd == NULL) {
			fd = fopen(file_name, "w");
		}
		if (fd == NULL) {
			LogMajor(
				COMPONENT_FSAL,
				"Failed to create file record (%s) for file %s",
				file_name,
				req.file_list.list[i].fname
			);
			continue;
		}
		/* format: file_id; file_size; create_time; last_access_time; last_modified_time */
		int fsize = fprintf(
			fd,
			"%d;%lu;%lu;%lu;%lu", 
			fid,
			req.file_list.list[i].fsize,
			req.file_list.list[i].ctime,
			req.file_list.list[i].atime,
			req.file_list.list[i].mtime
		);
		fclose(fd);
    truncate(file_name, fsize);
	}
	request_t_release(&req);

	ncloud_conn_t_release(&conn);

	return ret;
}

/**
 * Create directories for a given file path
 */
bool ncloud_create_directory(const char *parent, const char *path) {
	char dir_path[PATH_MAX];

	/* check if the path contains at least one directory */
	char *end_idx = strchr(path, '/'), *next_idx = NULL;
	const char *mount = get_mount_path();
	if (end_idx == NULL)
		return true;

	/* create the levels of directories */
	do {
		/* probe if there is a next level of directory to create */
		next_idx = strchr(end_idx + 1, '/');
		if (snprintf(dir_path, PATH_MAX, "%s/%s/%.*s", mount, parent, (int)(end_idx - path), path) < 0) {
			LogMajor(
				COMPONENT_FSAL,
				"Failed to create directory %s for file records, path too long",
				dir_path
			);
			return false;
		}
		struct stat sbuf;
		if (stat(dir_path, &sbuf) == 0) {
			if (!S_ISDIR(sbuf.st_mode)) {
				/* cannot create directory if the path is already taken */
				LogMajor(
					COMPONENT_FSAL,
					"Failed to create directory %s for file records, path exists but is not a directory",
					dir_path
				);
				return false;
			} else {
				/* update the permission if already exists */
				chmod(dir_path, 0700);
			}
		} else {
			LogInfo(
				COMPONENT_FSAL,
				"Create directory %s for file record %s in parent dir %s",
				dir_path,
				path,
				parent
			);
			/* create the current level directory */
			if (mkdir(dir_path, 0700) != 0) {
				if (errno != EEXIST)
					return false;
				/* update the permission if already exists */
				chmod(dir_path, 0700);
			}
		}
		end_idx = next_idx;
	} while (end_idx != NULL);

	return true;
}


/**
 * helpers (NFS internal)
 */
const char* get_mount_path() {
	bool mount_path_avail = op_ctx && op_ctx->ctx_export && op_ctx->ctx_export->fullpath;
	return mount_path_avail? op_ctx->ctx_export->fullpath : "/";
}

bool ncloud_init_buffer(struct ncloud_buffer *buf) {
	if (buf == NULL)
		return false;
	buf->buf = NULL;
	int i = 0;
	for (i = 0; i < NCLOUD_BUF_MAX_NUM_SPLITS; i++)
		buf->bytes_written[i] = 0;
	buf->size = 0;
	buf->offset = 0;
	return true;
}

void ncloud_release_buffer(struct ncloud_buffer *buf) {
	if (buf == NULL)
		return;
	LogDebug(COMPONENT_FSAL,
		 "Free buffer = %p ofs = %lu size = %lu num = %d",
		 buf->buf, buf->offset, buf->size, buf->num_splits);
	gsh_free(buf->buf);
	ncloud_init_buffer(buf);
}

bool ncloud_allocate_buffer(struct ncloud_buffer *buf,
			    uint64_t split_size,
			    uint8_t num_splits) {
	if (buf == NULL)
		return false;
	if (num_splits <= 0 || split_size == 0)
		return false;
	buf->buf = gsh_malloc(split_size * num_splits);
	if (buf->buf) {
		buf->size = split_size * num_splits;
		buf->num_splits = num_splits;
	}
	buf->offset = 0;
	LogDebug(COMPONENT_FSAL,
		 "Buffer = %p ofs = %lu size = %lu num = %d",
		 buf->buf, buf->offset, buf->size, buf->num_splits);
	return buf->buf != NULL;
}

uint64_t ncloud_get_buffer_split_size(struct ncloud_buffer *buf) {
	return buf && buf->num_splits > 0? buf->size / buf->num_splits : 0;
}

void ncloud_disk_cache_item_init(struct ncloud_disk_cache_item *t) {
	if (t == NULL)
		return;
	t->offset = 0;
	t->length = 0;
	t->in_use = false;
}

void ncloud_disk_cache_item_release(struct ncloud_disk_cache_item *t) {
	return ncloud_disk_cache_item_init(t);
}

void ncloud_disk_cache_head_init(struct ncloud_disk_cache_head *h) {
	if (h == NULL)
		return;
	h->start_idx = 0;
	h->num_splits_in_use = 0;
	h->root = RB_ROOT;
	pthread_mutex_init(&h->lock, NULL);
	int i = 0;
	for (i = 0; i < NCLOUD_CACHE_MAX_NUM_SPLITS; i++)
		ncloud_disk_cache_item_init(h->splits);
}

void ncloud_disk_cache_head_release(struct ncloud_disk_cache_head *h) {
	return ncloud_disk_cache_head_init(h);
}

bool ncloud_disk_cache_item_add(struct ncloud_fsal_obj_handle *handle, uint64_t offset, uint32_t length, bool is_write) {
	struct timespec start, end;
	double duration = 0.0;
	clock_gettime(CLOCK_REALTIME, &start);

	struct ncloud_disk_cache_head *head = is_write? &handle->ncloud.disk_cache.write_list : &handle->ncloud.disk_cache.read_list;
	int i = 0;

	pthread_mutex_lock(&head->lock);

  	struct rb_node **new = &(head->root.rb_node), *parent = NULL;

  	/* figure out where to put new record */
  	while (*new) {
  		struct ncloud_disk_cache_item *this = container_of(*new, struct ncloud_disk_cache_item, node);
		
		bool merge_at_the_back = this->offset + this->length == offset;
		bool merge_at_the_front = this->offset == offset + length;

		if (merge_at_the_back) {
			/* merge to existing record */
			this->length += length;
			clock_gettime(CLOCK_REALTIME, &end);
			duration = get_duration(start, end);
			LogDebug(COMPONENT_FSAL,
				 "New record: Merge at the back %s (%lu,%u) + (%lu,%u) in %.3lfs",
				 handle->ncloud.path,
				 this->offset, this->length,
				 offset, length,
				 duration
			);
			pthread_mutex_unlock(&head->lock);
			return true;
		}

		if (merge_at_the_front) {
			/* remove the current record */
			rb_erase(*new, &head->root);
			clock_gettime(CLOCK_REALTIME, &end);
			duration = get_duration(start, end);
			LogDebug(COMPONENT_FSAL,
				 "New record: Merge at the front %s (%lu,%u) + (%lu,%u) in %.3lfs",
				 handle->ncloud.path,
				 offset, length,
				 this->offset, this->length,
				 duration
			);
			pthread_mutex_unlock(&head->lock);
			/* insert a merged record */
			return ncloud_disk_cache_item_add(handle, offset, length + this->length, is_write);
		}

		parent = *new;
  		if (offset < this->offset)
  			new = &((*new)->rb_left);
  		else if (offset > this->offset + this->length)
  			new = &((*new)->rb_right);
		else if (!is_write) { /* try merging the read records */
  			struct rb_node *right = ((*new)->rb_right);
			struct ncloud_disk_cache_item *next = container_of(right, struct ncloud_disk_cache_item, node);
			if (right == NULL || next->offset > offset + length) { /* if no next record, or next record's offset is beyond the current range */
				this->length = length;
			} else { /* at most up to next record (TODO better merge next overlapping record(s) for covering a larger file range with limited records) */
				this->length = next->offset - offset;
			}
			pthread_mutex_unlock(&head->lock);
			return true;
  		} else {
			clock_gettime(CLOCK_REALTIME, &end);
			duration = get_duration(start, end);
			/* report overlapping range, which is not supported yet */
			LogMajor(COMPONENT_FSAL,
				 "New record: Failed to handle overlapping records existing=(%lu,%u) new=(%lu,%u) in %.3lfs",
				 this->offset, this->length,
				 offset, length,
				 duration
			);
			pthread_mutex_unlock(&head->lock);
  			return false;
		}
  	}

	/* check if a free record is available before search */
	if (head->num_splits_in_use == NCLOUD_CACHE_MAX_NUM_SPLITS) {
		clock_gettime(CLOCK_REALTIME, &end);
		duration = get_duration(start, end);
		LogMajor(COMPONENT_FSAL,
			 "New record: Failed, no free record left for new splits in %.3lfs",
			 duration);
		pthread_mutex_unlock(&head->lock);
		return false;
	}

	/* find next free record */
	for (i = head->start_idx; head->splits[i].in_use; i = (i + 1) % NCLOUD_CACHE_MAX_NUM_SPLITS);

	/* set new record */
	struct ncloud_disk_cache_item *data = head->splits + i;
	data->offset = offset;
	data->length = length;
	data->in_use = true;

	/* set next index to search */
	head->start_idx = (i + 1) % NCLOUD_CACHE_MAX_NUM_SPLITS;

  	/* add new record and rebalance tree */
  	rb_link_node(&data->node, parent, new);
  	rb_insert_color(&data->node, &head->root);

	/* increment the number of splits in use */
	head->num_splits_in_use++;

	clock_gettime(CLOCK_REALTIME, &end);
	duration = get_duration(start, end);
	LogDebug(COMPONENT_FSAL,
		 "New record: add new record (%lu,%u) in %.3lfs",
		 offset, length,
		 duration);

	pthread_mutex_unlock(&head->lock);

	/* share data cached due to writes with reads */
	if (is_write) {
		ncloud_disk_cache_item_add(handle, offset, length, /* is_write */ false);
	}

	return true;
}

int ncloud_disk_cache_get_ranges(struct ncloud_fsal_obj_handle *handle, uint64_t offset, uint32_t length, struct ncloud_disk_cache_range *ranges, bool is_write, bool is_remove) {
	int num_ranges = 0;

	struct ncloud_disk_cache_head *head = is_write? &handle->ncloud.disk_cache.write_list : &handle->ncloud.disk_cache.read_list;
	struct rb_node *prev = NULL, *next = head->root.rb_node;

	pthread_mutex_lock(&head->lock);

	/* find the starting cache record with offset <= range starting offset */
	while (next) {
		struct ncloud_disk_cache_item *this = container_of(next, struct ncloud_disk_cache_item, node);
		if (offset < this->offset) { /* offset is before this record, go left */
			next = next->rb_left;
		} else if (offset >= this->offset + this->length) { /* offset is beyond this record, go right */
			next = next->rb_right;
		} else { /* starting point found */
			prev = rb_prev(next);
			break;
		}
	}

	/* assume the given offset is always less than the right-most record */
	if (next == NULL && prev == NULL) {
		next = rb_first(&head->root);
	}

	/* add the ranges and remove the records */
	/* if record is removed, find the next node using the previous node or head */
	for (; next; next = prev? rb_next(prev) : rb_first(&head->root), num_ranges++) {
		struct ncloud_disk_cache_item *this = container_of(next, struct ncloud_disk_cache_item, node);

		/* exit if this record starts after the search range */
		if (this->offset >= offset + length)
			break;

		/* exit if this record ends before the search range */
		if (this->offset + this->length <= offset)
			break;

		/* mark the range */
		ranges[num_ranges].offset = this->offset;
		ranges[num_ranges].length = this->length;

		LogDebug(COMPONENT_FSAL,
			 "Get range (%lu,%u)",
			 this->offset, this->length
		);

		if (is_remove) {
			/* clean the cache item for reuse */
			ncloud_disk_cache_item_init(this);

			/* remove record */
			rb_erase(next, &head->root);
			
			/* decrement the number of splits in use */
			head->num_splits_in_use--;
		} else {
			prev = next;
		}
	}

	LogInfo(COMPONENT_FSAL,
		 "Return %d ranges for (%lu,%u,%lu)",
		 num_ranges, offset, length, offset + length);

	pthread_mutex_unlock(&head->lock);
	return num_ranges;
}

static bool ncloud_get_disk_cache_path(struct ncloud_fsal_obj_handle *handle, char *path) {
	if (handle == NULL || path == NULL)
		return false;
	bool okay = snprintf(path,
			PATH_MAX,
			"%s/%s/%s",
			get_mount_path(),
			NCLOUD_CACHE_DIR,
			handle->ncloud.path + strlen(get_mount_path()) + 1
		) >= 0;
	/* replace '/' with '\n' so the cache file hierarchy is flat */
	char *idx = path + strlen(get_mount_path()) + strlen(NCLOUD_CACHE_DIR) + 2;
	while (1) {
		idx = strstr(idx, "/");
		if (idx == NULL)
			break;
		*idx = '\n';
	}
	return okay;
}

ssize_t ncloud_access_disk_cache(struct ncloud_fsal_obj_handle *handle, uint64_t offset, char *buf, uint64_t length, bool is_write) {
	struct timespec start, end;
	clock_gettime(CLOCK_REALTIME, &start);

	if (handle == NULL || buf == NULL) {
		LogMajor(COMPONENT_FSAL,
			 "Failed to %s buffer %p to disk cache at (%lu,%lu) for file %s",
			 is_write? "write" : "read", buf, offset,
			 length, handle? handle->ncloud.path : "(nil)");
		return -1;
	}
	char cache_path[PATH_MAX];
	if (ncloud_get_disk_cache_path(handle, cache_path) == false) {
		LogMajor(COMPONENT_FSAL,
			 "Failed to get disk cache path for file %s for %s",
			 handle->ncloud.path, is_write? "write" : "read");
		return -1;
	}
	FILE *fd = 0;
	/* open for read and write, create one if this is write and the cache
	 * file does not exist */
	if (handle->ncloud.disk_cache.fd == NULL) {
		fd = fopen(cache_path, "r+");
		if (fd == NULL && is_write)
			fd = fopen(cache_path, "w+");
		if (fd == NULL) {
			LogMajor(COMPONENT_FSAL,
				 "Failed to open disk cache (%s) for file %s",
				 cache_path, handle->ncloud.path);
			return -1;
		}
		/* keep the fd in the object handler */
		handle->ncloud.disk_cache.fd = fd;
	} 
	/* get the fd for write/read cache */
	fd = handle->ncloud.disk_cache.fd;
	if (fseek(fd, offset, SEEK_SET)  != 0) {
		LogMajor(COMPONENT_FSAL,
			 "Failed to seek to offset %lu for write disk cache %s of file %s",
			 offset, cache_path, handle->ncloud.path);
		return -1;
	}
	/* write / read data from disk cache */
	ssize_t accessed_bytes = 0, ret = 0;
	while (accessed_bytes < length) {
		if (is_write)
			ret = fwrite(buf + accessed_bytes, 1, length - accessed_bytes, fd);
		else
			ret = fread(buf + accessed_bytes, 1, length - accessed_bytes, fd);
		if (ret <= 0) /* no need to read further if eof or error occurs */
			break;
		accessed_bytes += ret;
	}
		
	/* flush after write */
	if (accessed_bytes != -1 && is_write) 
		fflush(fd);

	/* report error */
	if (accessed_bytes == -1) {
		LogMajor(COMPONENT_FSAL,
			 "Failed to %s to cache file %s at (%ld,%ld) for file %s",
			 is_write? "write" : "read",
			 cache_path, offset, length,
			 handle->ncloud.path);
	} else {
		clock_gettime(CLOCK_REALTIME, &end);
		double duration = get_duration(start, end);
		LogDebug(COMPONENT_FSAL,
			 "%s cache file %s at (%ld,%ld) for file %s in %.3lfs",
			 is_write? "Write" : "Read",
			 cache_path, offset, length,
			 handle->ncloud.path,
			 duration);
	}

	return accessed_bytes;
}

ssize_t ncloud_write_disk_cache(struct ncloud_fsal_obj_handle *handle, uint64_t offset, char *buf, uint64_t length) {
	return ncloud_access_disk_cache(handle, offset, buf, length, /* is_write */ true);
} 

ssize_t ncloud_read_disk_cache(struct ncloud_fsal_obj_handle *handle, uint64_t offset, char *buf, uint64_t length) {
	return ncloud_access_disk_cache(handle, offset, buf, length, /* is_write */ false);
}

bool ncloud_purge_disk_cache(struct ncloud_fsal_obj_handle *handle, uint64_t offset, uint64_t length) {
  char disk_cache_path[PATH_MAX];
  if (!ncloud_get_disk_cache_path(handle, disk_cache_path)) {
    LogDebug(COMPONENT_FSAL, "Failed to get file cache on-disk path for purging disk cache!");
    return false;
  }
	int fd = 0;
  fd = open(disk_cache_path, O_WRONLY);
  if (fd <= 0) {
    LogDebug(COMPONENT_FSAL, "Failed to open the on-disk file cache for purging disk cache!");
    return false;
  }
  int ret = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, length);
  if (ret != 0) {
    LogWarn(COMPONENT_FSAL, "Failed to purge (%lu, %lu) of the on-disk file cache!", offset, length);
    return false;
  }
  return true;
}

static bool ncloud_path_map_is_mapping_online(struct ncloud_fsal_export *export) {
	bool ret = export->ncloud.path_map.map_addr != 0 && export->ncloud.path_map.record_offsets != 0;
	if (!ret)
		LogMajor(COMPONENT_FSAL, "Directory cache is not init for operations");
	return ret;
}

size_t ncloud_path_id_to_path(struct ncloud_fsal_export *export, int id, char *path) {
	size_t len = 0;

	/* skip invalid id */
	if (!ncloud_path_map_is_id_valid(id))
		return len;

	/* check if the map is usable */
	if (!ncloud_path_map_is_mapping_online(export))
		return len;

	/* ensure process (file-level) and thread (process-level) consistency */
	pthread_rwlock_rdlock(&export->ncloud.path_map.lock);
	flock(export->ncloud.path_map.fd, LOCK_SH);
	/* check if the entry exists */
	unsigned int ofs = export->ncloud.path_map.record_offsets[id];
	if (ofs == 0) {
		LogMajor(COMPONENT_FSAL,
			"Path for id %d does not exists", id
		);
		flock(export->ncloud.path_map.fd, LOCK_UN);
		pthread_rwlock_unlock(&export->ncloud.path_map.lock);
		return len;
	}
	LogDebug(COMPONENT_FSAL, "path for id %d has ofs %u/%d", id, ofs, export->ncloud.path_map.map_size);
	/* check length first, and copy if the length is valid */
	len = strlen(export->ncloud.path_map.map_addr + ofs) + 1;
	if (len >= PATH_MAX) {
		LogMajor(COMPONENT_FSAL,
			"Path for id %d is too long (%lu, cache file is corrupted?)",
			id, len
		);
		len = 0;
	} else if (len > 0) {
		size_t max_len = PATH_MAX;
		if (max_len > export->ncloud.path_map.map_size - ofs)
			max_len = export->ncloud.path_map.map_size - ofs;
		strncpy(path, export->ncloud.path_map.map_addr + ofs, max_len);
		LogInfo(COMPONENT_FSAL, "Get path %s by id %d", path, id);
	}
	flock(export->ncloud.path_map.fd, LOCK_UN);
	pthread_rwlock_unlock(&export->ncloud.path_map.lock);
	return len;
}

/**
 * Caller must lock the path map and path map fd before calling
 */
static unsigned int ncloud_path_map_append_entry(struct ncloud_fsal_export *export, const char *path, int id) {
	/* starting offset */
	unsigned int ofs = export->ncloud.path_map.map_size;
	unsigned int new_size = ofs + sizeof(int) + strlen(path) + 1;
	/* remap to allocate space for new path */
	fallocate(export->ncloud.path_map.fd, 0, 0, ofs + sizeof(int) + strlen(path) + 1);
	export->ncloud.path_map.map_addr = 
		mremap(export->ncloud.path_map.map_addr,
			ofs, new_size,
			MREMAP_MAYMOVE
		);
	/* copy the id and new path */
	memcpy(export->ncloud.path_map.map_addr + ofs, &id, sizeof(int));
	strncpy(export->ncloud.path_map.map_addr + ofs + sizeof(int), path, new_size - ofs - sizeof(int));
	/* record the mapping */
	export->ncloud.path_map.record_offsets[id] = ofs + sizeof(int);
	/* record the new map size */
	export->ncloud.path_map.map_size = new_size;
	/* flush changes to disk */
	msync(export->ncloud.path_map.map_addr + ofs, new_size - ofs, MS_SYNC);
	return id;
}

int ncloud_path_map_add(struct ncloud_fsal_export *export, const char *path) {
	/* check if the map is usable */
	if (!ncloud_path_map_is_mapping_online(export))
		return NCLOUD_INVALID_PATH_ID;

	/* ensure process (file-level) and thread (process-level) consistency */
	pthread_rwlock_wrlock(&export->ncloud.path_map.lock);
	flock(export->ncloud.path_map.fd, LOCK_EX);

	int id = NCLOUD_INVALID_PATH_ID, i = export->ncloud.path_map.next_idx;
	
	/* search for empty map slot for placing the new record */
	do {
		/* check if slot is empty, if yes, append path to the mapping file and add the record to mapping */
		if (export->ncloud.path_map.record_offsets[i] == 0) {
			/* expand the map and append entry */
			id = ncloud_path_map_append_entry(export, path, i);
			/* increment index for next search */
			export->ncloud.path_map.next_idx = (i + 1) % NCLOUD_PATH_MAP_MAX_NUM;
			break;
		}
		i = (i + 1) % NCLOUD_PATH_MAP_MAX_NUM;
	} while (i != export->ncloud.path_map.next_idx);

	if (id != NCLOUD_INVALID_PATH_ID) {
		LogInfo(COMPONENT_FSAL, "Map path %s to id %d", path, id);
		/* save the id by type */
		struct stat sbuf;
		int ret = stat(path, &sbuf);
		if (ret == 0 && S_ISDIR(sbuf.st_mode))
			ncloud_path_map_save_dir_id(path, id);
		else if (ret == 0 && S_ISREG(sbuf.st_mode))
			ncloud_path_map_save_file_id(path, id);
	} else {
		LogMajor(COMPONENT_FSAL, "Failed to map %s to any id", path);
	}

	flock(export->ncloud.path_map.fd, LOCK_UN);
	pthread_rwlock_unlock(&export->ncloud.path_map.lock);
	return id;
}

bool ncloud_path_map_remove(struct ncloud_fsal_export *export, int id) {
	/* skip invalid id */
	if (!ncloud_path_map_is_id_valid(id))
		return false;

	/* skip if mapping is offline */
	if (!ncloud_path_map_is_mapping_online(export))
		return false;

	/* lazy delete, let the system do the clean up upon reboot */
	pthread_rwlock_wrlock(&export->ncloud.path_map.lock);
	flock(export->ncloud.path_map.fd, LOCK_EX);

	unsigned int ofs = export->ncloud.path_map.record_offsets[id];
	LogInfo(COMPONENT_FSAL, "Remove path %s by id %d", ofs == 0? "(NIL)" : export->ncloud.path_map.map_addr + ofs, id);

	/* update the next empty slot for quick insert */
	if (export->ncloud.path_map.record_offsets[export->ncloud.path_map.next_idx] != 0) {
		export->ncloud.path_map.next_idx = id;
	}

	flock(export->ncloud.path_map.fd, LOCK_UN);
	pthread_rwlock_unlock(&export->ncloud.path_map.lock);
	return ofs > 0;
}

bool ncloud_path_map_update(struct ncloud_fsal_export *export, int id, const char *path) {
	/* skip invalid id */
	if (!ncloud_path_map_is_id_valid(id))
		return false;

	/* skip if mapping is offline */
	if (!ncloud_path_map_is_mapping_online(export))
		return false;

	pthread_rwlock_wrlock(&export->ncloud.path_map.lock);
	flock(export->ncloud.path_map.fd, LOCK_EX);

	bool okay = ncloud_path_map_append_entry(export, path, id) == id;
	LogInfo(COMPONENT_FSAL, "Update id %d to path %s", id, path);

	flock(export->ncloud.path_map.fd, LOCK_UN);
	pthread_rwlock_unlock(&export->ncloud.path_map.lock);
	
	return okay;
}

bool ncloud_path_map_is_id_valid(int id) {
	return id >= 0 && id < NCLOUD_PATH_MAP_MAX_NUM && id != NCLOUD_INVALID_PATH_ID;
}

static int ncloud_path_map_gen_mapping_path(int ver, char *path) {
	return snprintf(path, PATH_MAX, "%s/%s_%d", get_mount_path(), NCLOUD_PATH_MAP_FILE, ver);
}

static bool ncloud_path_map_find_latest_ondisk_mapping(struct ncloud_fsal_export *export, char *path) {
	ncloud_path_map_gen_mapping_path(0, path);
	struct stat sbuf;
	int ret = stat(path, &sbuf);
	LogDebug(COMPONENT_FSAL,
		"Check ondisk mapping %s %d %lu %d %d",
		path, ret, sbuf.st_size, S_ISREG(sbuf.st_mode), !S_ISDIR(sbuf.st_mode)
	);
	return ret == 0 && sbuf.st_size > 0 && S_ISREG(sbuf.st_mode) && !S_ISDIR(sbuf.st_mode);
}

bool ncloud_path_map_scan_ondisk_mapping_to_mem(struct ncloud_fsal_export *export, bool validate) {
	unsigned int map_size = 0, old_map_size = 0;
	bool okay = true;
	int id = 0, largest_id = NCLOUD_INVALID_PATH_ID, i = 0;
	unsigned int ofs = 0;
	char *path = 0, prev_map_path[PATH_MAX], new_map_path[PATH_MAX];
	struct stat sbuf;
	int fd = 0;
	void *omap = 0; 

	pthread_rwlock_wrlock(&export->ncloud.path_map.lock);
	flock(export->ncloud.path_map.fd, LOCK_EX);

	memset(export->ncloud.path_map.record_offsets, 0, NCLOUD_PATH_MAP_MAX_NUM * sizeof(int));
	/* skip if no ondisk mapping found */
	if (ncloud_path_map_find_latest_ondisk_mapping(export, prev_map_path)) {
		/* read the latest mapping to memory and validate if needed */
		fd = open(prev_map_path, O_RDONLY);
		if (fd <= 0) {
			okay = false;
			LogMajor(COMPONENT_FSAL,
				"Failed to open the latest mapping from disk");
			goto path_map_scan_ondisk_mapping_to_mem_exit;
		}
		fstat(fd, &sbuf);
		old_map_size = sbuf.st_size;
		omap = mmap(NULL, old_map_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (omap == MAP_FAILED) {
			okay = false;
			LogMajor(COMPONENT_FSAL,
				"Failed to map the latest mapping on disk");
			close(fd);
			goto path_map_scan_ondisk_mapping_to_mem_exit;
		}
		/* scan the records, <4-B id,null-terminated string> */
		for (ofs = 0; ofs + sizeof(int) < old_map_size;) {
			LogFullDebug(COMPONENT_FSAL, "ofs = %u", ofs);
			/* directory id and path */
			memcpy(&id, omap + ofs, sizeof(int));
			path = omap + ofs + sizeof(int);
			/* increment offset to the start of next record */
			ofs += sizeof(int) + strlen(path) + 1;
			/* do not add if path does not exists or is not (or no longer) a directory */
			int ret = stat(path, &sbuf);
			if (validate) {
				if (ret < 0) {
					LogMajor(COMPONENT_FSAL,
						 "Failed to validate path %s with id %d",
						 path, id
					);
					continue;
				}
			}
			LogInfo(COMPONENT_FSAL,
				 "Add mapping %d to %s from previous cache file pos = %u",
				 id, path, ofs);
			/* we don't care about overwriting the previous records,
			 * since the ondisk mapping is append only,
			 * and the latest one must be the valid ones */
			map_size += sizeof(int) + strlen(path) + 1;
			export->ncloud.path_map.record_offsets[id] = ofs - (strlen(path) + 1); 
			if (S_ISDIR(sbuf.st_mode))
				ncloud_path_map_save_dir_id(path, id);
			largest_id = max_of(id, largest_id);
		}
	}

	/* create a new version and switch the mapping to reference the new version */
	/* new the file */
	ncloud_path_map_gen_mapping_path(1, new_map_path);
	int new_fd = open(new_map_path, O_CREAT | O_RDWR, 0644);
	if (new_fd <= 0) {
		largest_id = NCLOUD_INVALID_PATH_ID;
		okay = false;
		LogMajor(COMPONENT_FSAL,
			"Failed to open file %s for directory cache",
			new_map_path
		);
	}
	bool sys_empty = largest_id == NCLOUD_INVALID_PATH_ID && map_size == 0;
	/* handle empty start (always add a root record) */
	if (sys_empty) {
		map_size = sizeof(int) + strlen(get_mount_path()) + 1;
	}
	/* mmap the new file */
	fallocate(new_fd, 0, 0, map_size);
	void *new_map = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, new_fd, 0);
	if (new_map == MAP_FAILED) {
		largest_id = NCLOUD_INVALID_PATH_ID;
		okay = false;
		LogMajor(COMPONENT_FSAL,
			"Failed to mmap file %s for directory cache",
			new_map_path
		);
	}
	i = 0;
	ofs = 0;
	if (okay && sys_empty) {
		/* if system is empty, create a root record */
		memcpy(new_map + ofs, &i, sizeof(int));
		strncpy(new_map + ofs + sizeof(int), get_mount_path(), map_size - sizeof(int));
		export->ncloud.path_map.record_offsets[i] = ofs + sizeof(int);
		ncloud_path_map_save_dir_id(get_mount_path(), i);
		ofs += sizeof(int) + strlen(get_mount_path()) + 1;
		LogWarn(COMPONENT_FSAL, "Empty start: copy root record done map_size = %u", map_size);
	}
	/* write and point the referenced record to the new record file */
	for (i = 0; okay && i <= largest_id; i++) {
		/* skip empty record */
		if (export->ncloud.path_map.record_offsets[i] == 0)
			continue;
		
		path = omap + export->ncloud.path_map.record_offsets[i];
		LogDebug(COMPONENT_FSAL,
			"process record at ofs = %u (%s)",
			export->ncloud.path_map.record_offsets[i],
			path
		);
		/* check if it may overflows */
		if (ofs + sizeof(int) + strlen(path) + 1 > map_size) {
			LogMajor(COMPONENT_FSAL,
				"Failed to append new record, size too small (%u new but need %lu), remap now",
				map_size, ofs + sizeof(int) + strlen(path) + 1);
			fallocate(new_fd, 0, 0, ofs + sizeof(int) + strlen(path) + 1);
			new_map = mremap(new_map, map_size,
					ofs + sizeof(int) + strlen(path) + 1,
					MREMAP_MAYMOVE);
			map_size = ofs + sizeof(int) + strlen(path) + 1;
		}
		/* copy the record */
		memcpy(new_map + ofs, &i, sizeof(int));
		strncpy(new_map + ofs + sizeof(int), path, map_size - (ofs + sizeof(int)));
		/* mark the new address (offset) */
		export->ncloud.path_map.record_offsets[i] = ofs + sizeof(int);
		/* increment the mapping offset */
		ofs += sizeof(int) + strlen(path) + 1;
	}

	if (map_size > 0) {
		/* save it to export if everything is okay */
		export->ncloud.path_map.fd = new_fd;
		export->ncloud.path_map.map_addr = new_map;
		export->ncloud.path_map.map_size = map_size;
		export->ncloud.path_map.next_idx = ncloud_path_map_is_id_valid(largest_id)? largest_id : 1;
	} else if (largest_id >= 0) {
		/* release resources if failed when parsing */
		munmap(new_map, map_size);
		close(new_fd);
		okay = false;
	}

	/* clean up, close the stable version of mapping */
	if (fd) {
		munmap(omap, old_map_size);
		close(fd);
	}

path_map_scan_ondisk_mapping_to_mem_exit:
	flock(export->ncloud.path_map.fd, LOCK_UN);
	pthread_rwlock_unlock(&export->ncloud.path_map.lock);

	return okay;
}

static void ncloud_path_map_reset_export_var(struct ncloud_fsal_export *export) {
	export->ncloud.path_map.fd = 0;
	export->ncloud.path_map.map_addr = 0;
	export->ncloud.path_map.map_size = 0;
	export->ncloud.path_map.record_offsets = 0;
	export->ncloud.path_map.next_idx = 0;
	pthread_rwlock_init(&export->ncloud.path_map.lock, NULL);
}

bool ncloud_path_map_bootstrap(struct ncloud_fsal_export *export) {
	ncloud_path_map_reset_export_var(export);
	/* allocate the in-memory mapping */
	export->ncloud.path_map.record_offsets = gsh_malloc(NCLOUD_PATH_MAP_MAX_NUM * sizeof(int));
	if (export->ncloud.path_map.record_offsets == NULL) {
		LogMajor(
			COMPONENT_FSAL,
			"Failed to allocate record_offsets for directory cache"
		);
		return false;
	}
	/* scan the validate mapping to disk */
	return ncloud_path_map_scan_ondisk_mapping_to_mem(export, true);
}

bool ncloud_path_map_shutdown(struct ncloud_fsal_export *export) {

	pthread_rwlock_wrlock(&export->ncloud.path_map.lock);

	flock(export->ncloud.path_map.fd, LOCK_EX);
	/* sync whole map */
	msync(export->ncloud.path_map.map_addr, export->ncloud.path_map.map_size, MS_SYNC);
	/* cleanup (close and unmap) */
	munmap(export->ncloud.path_map.map_addr, export->ncloud.path_map.map_size);
	flock(export->ncloud.path_map.fd, LOCK_UN);
	close(export->ncloud.path_map.fd);

	gsh_free(export->ncloud.path_map.record_offsets);
	ncloud_path_map_reset_export_var(export);

	/* move the directory cache file, in-use = version 1, stable = version 0 */
	char cur_cache_path[PATH_MAX], stable_cache_path[PATH_MAX];
	ncloud_path_map_gen_mapping_path(0, stable_cache_path);
	ncloud_path_map_gen_mapping_path(1, cur_cache_path);
	rename(cur_cache_path, stable_cache_path);
	
	pthread_rwlock_unlock(&export->ncloud.path_map.lock);
	return true;
}

static int ncloud_path_map_get_dir_id_path(const char *path, char *id_path) {
	return snprintf(id_path, PATH_MAX, "%s/%s", path, NCLOUD_DIR_PATH_ID);
}

static bool ncloud_path_map_operate_on_dir_id(const char *path, int *id, bool is_save) {
	char id_file_path[PATH_MAX];
	ncloud_path_map_get_dir_id_path(path, id_file_path);
	FILE *fd = fopen(id_file_path, is_save? "w" : "r");
	bool okay = false;
	if (fd != NULL) {
		if (is_save)
			okay = fwrite(id, sizeof(int), 1, fd) > 0;
		else
			okay = fread(id, sizeof(int), 1, fd) > 0;
		fclose(fd);
	}
	if (!okay)
		LogMajor(COMPONENT_FSAL,
			"Failed to %s id %d for path %s",
			is_save? "save" : "read", *id, path
		);
	return okay;
}

bool ncloud_path_map_save_dir_id(const char *path, int id) {
	return ncloud_path_map_operate_on_dir_id(path, &id, true);
}

int ncloud_path_map_erase_dir_id(const char *path) {
	char id_file_path[PATH_MAX];
	ncloud_path_map_get_dir_id_path(path, id_file_path);
	/* get the id first for returning, and remove the file */
	int id = ncloud_path_map_load_dir_id(path);
	unlink(id_file_path);
	return id;
}

int ncloud_path_map_load_dir_id(const char *path) {
	int id = NCLOUD_INVALID_PATH_ID;
	ncloud_path_map_operate_on_dir_id(path, &id, false);
	return id;
}

bool ncloud_path_map_save_file_id(const char *path, int id) {
	FILE *fd = fopen(path, "w");
	if (fd == NULL)
		return false;
	bool okay = fprintf(fd, "%d;", id) > 0;
	fclose(fd);
	return okay;
}

int ncloud_path_map_load_file_id(const char *path) {
	int id = NCLOUD_INVALID_PATH_ID;
	FILE *fd = fopen(path, "r");
	/* record not found */
	if (fd == NULL) {
		LogMajor(COMPONENT_FSAL, "Failed to load id for path %s", path);
		return id;
	}
	/* check if id is not found */
	if (fscanf(fd, "%d;", &id) <= 0)
		id = NCLOUD_INVALID_PATH_ID;
	fclose(fd);
	LogInfo(COMPONENT_FSAL, "Load id %d for path %s", id, path);
	return id;
}

bool ncloud_is_system_file(const char *name) {
	return strcmp(name, NCLOUD_CACHE_DIR) == 0 || 
		strcmp(name, NCLOUD_PATH_MAP_FILE) == 0 || 
		strcmp(name, NCLOUD_DIR_PATH_ID) == 0; 
}
