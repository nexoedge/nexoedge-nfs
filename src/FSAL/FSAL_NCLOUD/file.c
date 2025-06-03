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
 */

/* file.c
 * File I/O methods for nCloud module
 */

#include "config.h"

#include <assert.h>
#include "fsal.h"
#include "FSAL/access_check.h"
#include "fsal_convert.h"
#include <unistd.h>
#include <fcntl.h>
#include "FSAL/fsal_commonlib.h"
#include "ncloud_methods.h"
#include "ncloud/client.h"

/**
 * @brief Callback arg for NULL async callbacks
 *
 * NULL needs to know what its object is related to the sub-FSAL's object.
 * This wraps the given callback arg with NULL specific info
 */
struct null_async_arg {
	struct fsal_obj_handle *obj_hdl;	/**< NULL's handle */
	fsal_async_cb cb;			/**< Wrapped callback */
	void *cb_arg;				/**< Wrapped callback data */
};

/**
 * helper functions
 */

static ssize_t ncloud_flush_buffer_data(struct ncloud_fsal_export *export,
				      struct ncloud_fsal_obj_handle *handle,
				      uint64_t offset, uint64_t length,
				      char *buf, bool is_overwrite)
{
	request_t req;
	bool okay = false;
	char *path = handle->ncloud.path + strlen(get_mount_path()) + 1;

	LogMidDebug(COMPONENT_FSAL,
		"Going to flush data (%s) to ncloud for file %s at (%lu,%lu)",
		is_overwrite? "overwrite" : (offset == 0? "write" : "append"),
		path,
		offset,
		length	
	);

	/* connect the socket to nCloud if it is not yet set up */
	if (handle->ncloud.conn.socket == 0 && ncloud_conn_t_init(export->ncloud.proxy_ip, export->ncloud.proxy_port, &handle->ncloud.conn, 1) < 0) {
		LogCrit(
			COMPONENT_FSAL,
			"Failed to init connection to flush buffer data for file %s",
			handle->ncloud.path
		);
		return -1;
	}

	if (is_overwrite) {
		/* overwrite a stripe */
		okay = set_buffered_file_overwrite_request(&req, path, buf, offset, length, export->ncloud.namespace_id) != -1;
	} else if (offset == 0) {
		/* write the first stripe of a new file */
		okay = set_buffered_file_write_request(&req, path, length, buf, export->ncloud.storage_class, export->ncloud.namespace_id) != -1;
	} else {
		/* append stripes to the file */
		okay = set_buffered_file_append_request(&req, path, buf, offset, length, export->ncloud.namespace_id) != -1;
	}
	/* send the write/append request */
	if (!okay || send_request(&handle->ncloud.conn, &req) != offset + length) {
		LogMajor(COMPONENT_FSAL,
			"Failed to flush data (%s) to ncloud for file %s at (%lu,%lu)",
			is_overwrite? "overwrite" : (offset == 0? "write" : "append"),
			path,
			offset,
			length	
		);
		request_t_release(&req);
		/* report error */
		return -1;
	}
	request_t_release(&req);
	return length;
}

/**
 * Flush write buffer of the object handle
 * @param[in] export export of the FSAL module (ncloud parameters)
 * @param[in] handle object handle whose write buffer needs flushing
 * @return offset of the write buffer if succeed, -1 if failed
 */
static ssize_t ncloud_flush_write_buf(struct ncloud_fsal_export *export,
				      struct ncloud_fsal_obj_handle *handle,
				      int num_splits_to_flush)
{
	uint64_t offset = 0, length = 0;
	ssize_t bytes_flushed = 0;
	struct ncloud_buffer *write_buf = &handle->ncloud.write_buf;
	int num_splits_flushed = 0, i = 0;
	uint64_t split_size = ncloud_get_buffer_split_size(write_buf);

	static double memmove_duration = 0.0, cache_scan_duration = 0.0, find_splits_duration = 0.0;
	struct timespec start, end;

	/* 
	 * no need to flush if (1) no splits needs flushing, (2) buf is not
	 * allocated (no buffer or size is 0)
	 */
	if (num_splits_to_flush == 0 || write_buf->buf == NULL || write_buf->size == 0) {
		return 0;
	} else if (num_splits_to_flush > NCLOUD_BUF_MAX_NUM_SPLITS) {
		num_splits_to_flush = NCLOUD_BUF_MAX_NUM_SPLITS;
	}

	clock_gettime(CLOCK_REALTIME, &start);
	bool is_full = true, is_flushed = true;
	for (i = 0, length = 0; i < num_splits_to_flush && is_full; i++) {
		is_full = write_buf->bytes_written[i] == split_size;
		length += write_buf->bytes_written[i];

		/* set the next flush offset */
		if (is_flushed) {
			offset = handle->ncloud.last_written_offset + i * split_size;
			is_flushed = false;
		}

		LogMidDebug(COMPONENT_FSAL,
			 "Go over split %d/%d for flush "
			 "(%lu,%lu) is_flushed = %d, is_full = %d",
			 i, num_splits_to_flush,
			 offset, length, is_flushed, is_full);

		/* flush if
		 * (1) some pending data to flush and
		 *   (a) current split is not full and continuity breaks, or 
		 *   (b) it is the last split to flush, or 
		 *   (c) no data in the current split but some pending in previous splits for flush
		 * or
		 * (2) larger than the max transfer limit
		 */
		if ((length > 0 && 
		     (!is_full || i + 1 == num_splits_to_flush ||
		     write_buf->bytes_written[i] == 0)) ||
		    length >= NCLOUD_MAX_TRANS_SIZE)
		{
			clock_gettime(CLOCK_REALTIME, &end);
			find_splits_duration += get_duration(start, end);
			struct timespec flush_start, flush_end;
			clock_gettime(CLOCK_REALTIME, &flush_start);
			ssize_t ret = ncloud_flush_buffer_data(export, handle, 
							       offset, length,
							       write_buf->buf + offset - handle->ncloud.last_written_offset,
							       /* is_overwrite */ false);
			clock_gettime(CLOCK_REALTIME, &flush_end);
			double duration = get_duration(flush_start, flush_end);
			LogDebug(COMPONENT_FSAL,
				 "Internal of the write buffer flush (%lu,%lu) for file %s in %.3lfs",
				 offset, length, handle->ncloud.path, duration);
			if (ret < 0) {
				LogMajor(COMPONENT_FSAL,
					 "Failed to flush the write buffer (%lu,%lu) for file %s",
					 offset, length, handle->ncloud.path);
				bytes_flushed = -1;
				break;
			}
			bytes_flushed += ret;
      /* purge the cached area after flushing to cloud */
      ncloud_purge_disk_cache(handle, offset, length);
			/* reset the length and flush condition */
			length = 0;
			is_flushed = true;
			num_splits_flushed = i + 1;
			clock_gettime(CLOCK_REALTIME, &start);
		}
		
		/* end the flush operation once we hit an empty split */
		if (write_buf->bytes_written[i] == 0) {
			LogMidDebug(COMPONENT_FSAL,
				 "skip flush buf as split %d of length 0",
				 num_splits_flushed);
			break;
		}
	}
	clock_gettime(CLOCK_REALTIME, &end);
	find_splits_duration += get_duration(start, end);
	LogMidDebug(COMPONENT_FSAL, "find splits for file %s total %.3lfs", handle->ncloud.path, find_splits_duration);

	LogDebug(COMPONENT_FSAL, "flush buf splits = %d/%d", num_splits_flushed, num_splits_to_flush);
	/* skip chaning the write buffer if no flush at all */
	if (num_splits_flushed == 0)
		return bytes_flushed;

	int ending_split = num_splits_flushed;
	/* move the byte tracker of splits forward */
	for (i = 0; i < write_buf->num_splits; i++) {
		if (i + num_splits_flushed < write_buf->num_splits) {
			if (write_buf->bytes_written[i + num_splits_flushed] > 0) {
				ending_split = i + num_splits_flushed + 1;
			}
			write_buf->bytes_written[i] = write_buf->bytes_written[i + num_splits_flushed];
		} else {
			write_buf->bytes_written[i] = 0;
		}
	}

	clock_gettime(CLOCK_REALTIME, &start);
	/* move the data of splits forward */
	if (ending_split > num_splits_flushed) {
		if (ending_split - num_splits_flushed <= num_splits_flushed) {
			memcpy(write_buf->buf, write_buf->buf + num_splits_flushed * split_size, (ending_split - num_splits_flushed) * split_size);
		} else {
			memmove(write_buf->buf, write_buf->buf + num_splits_flushed * split_size, (ending_split - num_splits_flushed) * split_size);
		}
	}
	clock_gettime(CLOCK_REALTIME, &end);
	memmove_duration += get_duration(start, end);
	LogDebug(COMPONENT_FSAL, "memmove buffer for file %s total %.3lfs %d,%d", handle->ncloud.path, memmove_duration, num_splits_flushed, ending_split);

	handle->ncloud.last_written_offset += num_splits_flushed * split_size;

	/* get splits pending in disk cache into memory, if any */
	uint64_t cur_buffer_start = handle->ncloud.last_written_offset;
	uint64_t cur_buffer_end = cur_buffer_start + write_buf->size;

	clock_gettime(CLOCK_REALTIME, &start);
	struct ncloud_disk_cache_range ranges[NCLOUD_CACHE_MAX_NUM_SPLITS];
	int num_ranges = ncloud_disk_cache_get_ranges(handle, cur_buffer_start, write_buf->size, ranges, /* is_write */ true, /* is_remove */ true); 

	int cache_range_idx = 0, buf_idx = 0;
	for (cache_range_idx = 0; cache_range_idx < num_ranges; cache_range_idx++) {
		uint64_t split_offset = ranges[cache_range_idx].offset;
		uint64_t split_length = ranges[cache_range_idx].length;

		/* skip splits that have no (unwritten) data left */
		if (split_length == 0)
			continue;

		/* skips splits that are outside the buffer */
		if (split_offset + split_length <= cur_buffer_start || split_offset >= cur_buffer_end)
			continue;

		uint64_t adjusted_split_offset = max_of(split_offset, cur_buffer_start);
		uint64_t adjusted_split_length = min_of(split_offset + split_length, cur_buffer_end) - adjusted_split_offset;

		/*
		 *                            adjusted_split_length
		 *                        <-------------------------------------->
		 * 0 .. |            XXXXXXXXZZZZZZZZ                             |
		 *      ^                ^
		 * st   cur_buffer_start
		 *                       adjusted_split_offset
		 */

		LogDebug(COMPONENT_FSAL,
			 "Get split %d from disk at file (%lu,%lu) adjusted (%lu,%lu)",
			 cache_range_idx, split_offset, split_length, adjusted_split_offset, adjusted_split_length);

		/* read data from cache to memory, update memory buffer meta */
		ssize_t read_len = ncloud_read_disk_cache(handle, adjusted_split_offset, write_buf->buf + (adjusted_split_offset - cur_buffer_start), adjusted_split_length);
		if (read_len == -1) {
			LogMajor(COMPONENT_FSAL,
				 "Failed to read split from disk (%lu,%lu)",
				 adjusted_split_offset, adjusted_split_length);
			continue;
		}
		int buf_st_split_idx = (adjusted_split_offset - cur_buffer_start) / split_size;
		int buf_ed_split_idx = (adjusted_split_offset - cur_buffer_start + adjusted_split_length - 1) / split_size;
		for (buf_idx = buf_st_split_idx; adjusted_split_length > 0 && buf_idx <= buf_ed_split_idx; buf_idx++)
		{
			write_buf->bytes_written[buf_idx] += 
				min_of(adjusted_split_offset - cur_buffer_start + adjusted_split_length, (buf_idx + 1) * split_size) -
				max_of(adjusted_split_offset - cur_buffer_start, buf_idx * split_size);

			LogDebug(COMPONENT_FSAL,
				 "In-memory splits %d with bytes %lu",
				 buf_idx, write_buf->bytes_written[buf_idx]);

		}

		/* add the unused part back */
		if (adjusted_split_length < split_length) {
			if (!ncloud_disk_cache_item_add(handle, split_offset + adjusted_split_length, split_length - adjusted_split_length, /* is_write */ true))
				LogMajor(COMPONENT_FSAL,
					 "Failed to insert unused part back (%lu,%lu)",
					 offset + adjusted_split_length, split_length - adjusted_split_length);
		}
	}
	clock_gettime(CLOCK_REALTIME, &end);
	cache_scan_duration += get_duration(start, end);
	LogMidDebug(COMPONENT_FSAL, "cache_scan for file %s total %.3lfs", handle->ncloud.path, cache_scan_duration);

	/* count the splits to flush */
	int extra_splits_to_flush = 0;
	for (extra_splits_to_flush = 0;
	     extra_splits_to_flush < write_buf->num_splits && write_buf->bytes_written[extra_splits_to_flush] == split_size;
	     extra_splits_to_flush++);
	if (extra_splits_to_flush > 0)
		bytes_flushed += ncloud_flush_write_buf(export, handle, extra_splits_to_flush);

	return bytes_flushed;
}

ssize_t ncloud_read_and_try_fill_buf_with_cache(struct ncloud_fsal_obj_handle *handle, uint64_t offset, uint64_t length, char *buf) {
	struct ncloud_disk_cache_range ranges[NCLOUD_CACHE_MAX_NUM_SPLITS];

	/* TODO check if cached data is out-dated */

	/* check disk cache first */
	int num_ranges = ncloud_disk_cache_get_ranges(handle, offset, length, ranges, /* is_write */ false, /* is_remove */ false);
	int range_idx = 0;
	uint64_t bytes_read = 0;

	/* copy data from the ranges */
	for (range_idx = 0; range_idx < num_ranges; range_idx++) {
		if (ranges[range_idx].offset <= offset + bytes_read && ranges[range_idx].offset + ranges[range_idx].length >= offset + bytes_read) {
			uint64_t read_ofs = max_of(ranges[range_idx].offset, offset + bytes_read); /* start of buffer or range to read */
			uint64_t copy_len = min_of(ranges[range_idx].offset + ranges[range_idx].length, offset + length)  /* end of cache range or read range */ - read_ofs;
			ssize_t read_len = 0;
			LogDebug(COMPONENT_FSAL,
				"Get range (%lu,%d) for (%lu,%lu) read = %lu Copying (%lu,%lu)",
				ranges[range_idx].offset, ranges[range_idx].length,
				offset, length, bytes_read,
				read_ofs, copy_len
			);
			if (copy_len > 0) {
				read_len = ncloud_read_disk_cache(handle, read_ofs, buf + bytes_read, copy_len);
			}
			if (read_len > 0) {
				bytes_read += read_len;
			}
		} else {
			break;
		}
	}

	return bytes_read;
}

static ssize_t ncloud_read_and_fill_buf(struct ncloud_fsal_export *export, struct ncloud_fsal_obj_handle *handle, uint64_t offset, uint64_t length, char *buf) {
	request_t req;
	char *path = handle->ncloud.path + strlen(get_mount_path()) + 1;
	LogMidDebug(COMPONENT_FSAL, "Read data into buf (%lu,%lu)", offset, length);

	/* return data if cache is in-use and all found in cache */
  if (export->ncloud.cache_to_disk_after_read) {
    if (ncloud_read_and_try_fill_buf_with_cache(handle, offset, length, buf) == length)
      return length;
  }

	struct timespec start, end;
	clock_gettime(CLOCK_REALTIME, &start);
	/* connect the socket to nCloud if it is not yet set up */
	if (handle->ncloud.conn.socket == 0 && ncloud_conn_t_init(export->ncloud.proxy_ip, export->ncloud.proxy_port, &handle->ncloud.conn, 1) < 0) {
		LogCrit(COMPONENT_FSAL,
			"Failed to init connection to read data for file %s",
			handle->ncloud.path
		);
		return -1;
	}

	if (!set_buffered_file_partial_read_request(&req, path, buf, offset, length, export->ncloud.namespace_id) || send_request(&handle->ncloud.conn, &req) <= 0) {
		LogMajor(COMPONENT_FSAL,
			 "Failed to read file %s at (%lu,%lu)",
			 path, offset, length);
		return -1;
	}

	/* mark the size read as return value */
	length = req.file.size;
	clock_gettime(CLOCK_REALTIME, &end);
	double duration = get_duration(start, end);

	LogInfo(COMPONENT_FSAL,
		"Read from remote (%lu,%lu) for file %s in %.3lfs",
		offset, length, handle->ncloud.path, duration
	);

  if (export->ncloud.cache_to_disk_after_read) {
    /* cache the data read */
    if (length == ncloud_write_disk_cache(handle, offset, buf, length)) {
      ncloud_disk_cache_item_add(handle, offset, length, /* is_write */ false);
    }
  }

	request_t_release(&req);

	return length;
}

static ssize_t ncloud_fill_read_buf(struct ncloud_fsal_export *export, struct ncloud_fsal_obj_handle *handle, unsigned long int new_read_offset) {
	uint64_t offset = new_read_offset;
	ssize_t length = handle->ncloud.read_buf.size;
	char *buf = handle->ncloud.read_buf.buf;

	LogMidDebug(COMPONENT_FSAL, "Read data into buf (%lu,%lu)", offset, length);

	if ((length = ncloud_read_and_fill_buf(export, handle, offset, length, buf)) >= 0) {
		/* update the buffer metadata */
		handle->ncloud.last_read_offset = offset;
		handle->ncloud.read_buf.offset = length;
	}

	return length;
}

/**
 * copy data into the write buffer and check if flush is required
 * @param[in] export export of the FSAL module (ncloud parameters)
 * @param[in, out] handle object handle which the write operation operates on
 * @param[in] bypass  
 * @param[in] write_arg args of the write operation (data, offsets and lengths) 
 * @param[in, out] status status of the write operation
 * @param[in] is_flush_all whether to flush all data out of buffer
 *
 * @return number bytes written (>=0) upon success; otherwise, -1 for errors
 */
static ssize_t ncloud_check_and_write_if_needed(struct ncloud_fsal_export *export,
						struct ncloud_fsal_obj_handle *handle,
						bool bypass,
						struct fsal_io_arg *write_arg,
						fsal_status_t *status,
						bool is_flush_all)
{
	if (export == NULL || handle == NULL || (write_arg == NULL && is_flush_all == false) || status == NULL) {
		if (status)
			*status = fsalstat(ERR_FSAL_INVAL, EINVAL);
		return -1;
	}

	struct ncloud_buffer *write_buf = &handle->ncloud.write_buf; /* write buffer of the object (file) */

	/* nothing in buffer to flush, TODO check and exec for file write only */
	if (is_flush_all && write_buf->buf == NULL && write_arg == NULL && handle->ncloud.is_write) {
		/* flush empty file */
		if (handle->ncloud.last_written_offset == 0) {
			char empty_buf[1];
			return ncloud_flush_buffer_data(export, handle, 0, 0, empty_buf, /* is_overwrite */ false) == 0;
		}
		*status = fsalstat(ERR_FSAL_NO_ERROR, 0);
		return 0;
	}

	pthread_rwlock_wrlock(&handle->ncloud.buf_cache_lock);
	struct timespec start_all, end_all;
	clock_gettime(CLOCK_REALTIME, &start_all);
	/* allocate write buffer before first use */
  int num_splits_in_write_buf = 1; 
  if (handle->ncloud.append_size <= NCLOUD_CACHE_MAX_PER_FILE) {
    num_splits_in_write_buf = NCLOUD_CACHE_MAX_PER_FILE / handle->ncloud.append_size + 1;
    if (num_splits_in_write_buf > NCLOUD_BUF_MAX_NUM_SPLITS) {
      num_splits_in_write_buf = NCLOUD_BUF_MAX_NUM_SPLITS;
    }
  }
	if (write_buf->buf == NULL &&
	    !ncloud_allocate_buffer(write_buf, handle->ncloud.append_size, num_splits_in_write_buf))
	{
		/* TODO switch to disk cache mode if out-of-memory */
		LogCrit(COMPONENT_FSAL,
			 "Failed to allocate write buffer of size %lu for file %s",
			 handle->ncloud.append_size * num_splits_in_write_buf, handle->ncloud.path);
		pthread_rwlock_unlock(&handle->ncloud.buf_cache_lock);
		*status = fsalstat(ERR_FSAL_NOMEM, ENOMEM);
		return -1;
	}

	int iov_index = 0; /* index of the current iov */
	ssize_t bytes_written = 0; /* offset within the current iov (io vector) */
	ssize_t total_bytes_written = 0; /* total number of bytes written */
	ssize_t copy_len = 0; /* length of data to copy from the iov */

	int i = 0;

	/* detect overwrites and handle separately
	 * (1) normal write (not sync/flush), and
	 *   (a) overwrite and possibly append
	 *   (b) append to a file whose end is not aligned to the multiples of stripe size
	 */
	if (write_arg &&
	    (write_arg->offset < handle->ncloud.last_written_offset ||
	    (write_arg->offset >= handle->ncloud.last_written_offset && handle->ncloud.last_written_offset % handle->ncloud.append_size != 0)))
	{

		LogInfo(COMPONENT_FSAL,
			 "Overwrite detected at %lu with current file size %lu",
			 write_arg->offset, handle->ncloud.last_written_offset
		);
		/* check and make sure the file exists and is not empty */
		if (handle->ncloud.read_size == 0) {
			handle->ncloud.read_size =
				ncloud_get_read_size(export, handle, handle->ncloud.path + strlen(get_mount_path()) + 1);
		}
		if (handle->ncloud.read_size <= 0) {
			LogCrit(COMPONENT_FSAL,
				 "Failed to obtain the read size of file %s",
				 handle->ncloud.path);
			pthread_rwlock_unlock(&handle->ncloud.buf_cache_lock);
			*status = fsalstat(ERR_FSAL_NOMEM, ENOMEM);
			return -1;
		}

		/* assume there is no append beyond the (aligned) file size first, so we can skip writing to the write buffer */
		bool skip_write_buf = true;
		uint64_t append_size = handle->ncloud.append_size;

#define UPDATE_OVERWRITE_BUFFER_INFO(__OFFSET__) do { \
	aligned_offset = (__OFFSET__) / append_size * append_size; \
	prev_aligned_length = aligned_length; \
	aligned_length = (__OFFSET__ - aligned_offset + append_size) / append_size * append_size; \
} while (0)

		/*
		 * aligned offset, lengths for reading data into buffer for overwrite 
		 * mark down the previous length of data read (i.e., the buffer size) for buffer reallocation if needed
		 */
		uint64_t aligned_offset = 0, aligned_length = 0, prev_aligned_length = 0;
		ssize_t read_length = 0, max_touched_offset = 0;
		/* the next smallest file size that is a multiple of stripe size */
		uint64_t aligned_file_size = (handle->ncloud.last_written_offset + append_size - 1) / append_size * append_size;

		/* find the offset and length of old data to read for overwrite */
		UPDATE_OVERWRITE_BUFFER_INFO(write_arg->offset);
		LogDebug(COMPONENT_FSAL,
			 "Going to read old data (%lu,%lu) for overwriting (%lu) of file %s",
			 aligned_offset, aligned_length, write_arg->offset,
			 handle->ncloud.path);

		/* allocate and fill the buffer with old data for overwriting */
		char *odata = gsh_malloc(aligned_length);
		if (odata == NULL) {
			LogCrit(COMPONENT_FSAL,
				 "Failed to allocate buffer for overwrite data (%lu) for file %s",
				 aligned_length, handle->ncloud.path);
			gsh_free(odata);
			pthread_rwlock_unlock(&handle->ncloud.buf_cache_lock);
			*status = fsalstat(ERR_FSAL_NOMEM, ENOMEM);
			return -1;
		}
		if ((read_length = ncloud_read_and_fill_buf(export, handle, aligned_offset, aligned_length, odata)) < 0) {
			LogCrit(COMPONENT_FSAL,
				 "Failed to read old data (%lu,%lu) for overwriting (%lu) of file %s",
				 aligned_offset, aligned_length, write_arg->offset,
				 handle->ncloud.path);
			gsh_free(odata);
			pthread_rwlock_unlock(&handle->ncloud.buf_cache_lock);
			*status = fsalstat(ERR_FSAL_NO_DATA, ENODATA);
			return -1;
		}

		/* 
		 * start processing the overwrite, keep processing until
		 * (1) all iov are processed, or
		 * (2) the file size becomes aligned to the stripe size again, so we can do stripe append instead
		 */
		for (; iov_index < write_arg->iov_count && total_bytes_written + write_arg->offset < aligned_file_size;
		       total_bytes_written += bytes_written)
		{
			for (bytes_written = 0, copy_len = 0;
			     bytes_written < write_arg->iov[iov_index].iov_len;
			     bytes_written += copy_len)
			{
				/* offset and length of data to overwrite in the current buffer */
				uint64_t cur_write_offset = write_arg->offset + total_bytes_written + bytes_written;
				copy_len = write_arg->iov[iov_index].iov_len - bytes_written;
				if (cur_write_offset >= aligned_offset + aligned_length) { /* all data in the iov is beyond buffer */
					copy_len = 0;
				} else if (cur_write_offset + copy_len > aligned_offset + aligned_length) { /* some data in the iov is beyond buffer, only write those covered in the buffer */
					copy_len = aligned_offset + aligned_length - cur_write_offset;
				}
				/* copy (i.e., overwrite) data covered in the buffer */
				if (copy_len > 0) {
					memcpy(odata + cur_write_offset - aligned_offset,
					       write_arg->iov[iov_index].iov_base + bytes_written,
					       copy_len);
					max_touched_offset = cur_write_offset - aligned_offset + copy_len;
				}
				/* 
				 * flush if 
				 * (1) some data is the current iov is beyond the buffer (so the next overwrite would be completely beyond the buffer), or
				 * (2) copy op touches the end of the buffer (so the next overwrite would be beyond the buffer), or
				 * (3) the last iov is fully written
				 */
				bool beyond_buffer = copy_len < write_arg->iov[iov_index].iov_len - bytes_written;
				bool touch_buffer_end = cur_write_offset + copy_len == aligned_offset + aligned_length;
				bool last_iov_written =
					bytes_written + copy_len == write_arg->iov[iov_index].iov_len &&
					iov_index + 1 == write_arg->iov_count;

				if (beyond_buffer || touch_buffer_end || last_iov_written) {
					/* 
					 * actual length to write can be smaller than a full stripe for last stripe, only write up to the max of 
					 * (1) the length of old data (overwrite only)
					 * (2) max offset touched in the buffer (data append to the last non-full stripe)
					 */
					uint64_t write_length = max_of(read_length, max_touched_offset);
					if (ncloud_flush_buffer_data(export, handle, aligned_offset, write_length, odata, /* is_overwrite */ true) < 0) {
						LogMajor(COMPONENT_FSAL,
							 "Failed to flush overwrite data read = %lu, max_touched = %lu, aligned = %lu, write = %lu for file %s",
							 read_length, max_touched_offset, aligned_length, write_length, handle->ncloud.path);
						gsh_free(odata);
						pthread_rwlock_unlock(&handle->ncloud.buf_cache_lock);
						*status = fsalstat(ERR_FSAL_FAULT, ENETUNREACH);
						return -1;
					}
					/* update the file size if needed */
					handle->ncloud.last_written_offset = max_of(handle->ncloud.last_written_offset, aligned_offset + write_length);
					/* return to the append flow if overwrite extends the file size to the aligned one, i.e., future writes are appends */
					if (aligned_offset + aligned_length == aligned_file_size) {
						LogDebug(COMPONENT_FSAL,
							 "File size is aligned to stripe size (%lu) again",
							 aligned_file_size);
						/* mark the size of data processed in the current iov for the append flow */
						bytes_written += copy_len;
						skip_write_buf = false;
						break;
					}
				}

				/* read new data if some pending data to write is beyond the current buffer */
				if (beyond_buffer) {
					/* update the offset and length of data to read */
					uint64_t new_offset = write_arg->offset + total_bytes_written + bytes_written + copy_len;
					UPDATE_OVERWRITE_BUFFER_INFO(new_offset);
					/* reallocate buffer for read (and overwrite) if it is not large enough */
					if (prev_aligned_length < aligned_length) {
						gsh_free(odata);
						odata = gsh_malloc(aligned_length);
						if (odata == NULL) {
							LogCrit(COMPONENT_FSAL,
								 "Failed to allocate buffer for overwrite data (%lu) for file %s",
								 aligned_length, handle->ncloud.path);
							pthread_rwlock_unlock(&handle->ncloud.buf_cache_lock);
							*status = fsalstat(ERR_FSAL_NOMEM, ENOMEM);
							return -1;
						}
					}
					/* read and fill the buffer with old data */
					if ((read_length = ncloud_read_and_fill_buf(export, handle, aligned_offset, aligned_length, odata)) < 0) {
						LogCrit(COMPONENT_FSAL,
							 "Failed to read old data (%lu,%lu) for overwriting file %s",
							 aligned_offset, aligned_length, handle->ncloud.path);
						gsh_free(odata);
						pthread_rwlock_unlock(&handle->ncloud.buf_cache_lock);
						*status = fsalstat(ERR_FSAL_NO_DATA, ENODATA);
						return -1;
					}
				}
			}
			/* increment the iov index at the end of processing the current iov */
			if (bytes_written == write_arg->iov[iov_index].iov_len)
				iov_index++;
		}

		/* free buffer */
		gsh_free(odata);

#undef UPDATE_OVERWRITE_BUFFER_INFO

		/* skip append flow if nothing left for append */
		if (skip_write_buf) {
			pthread_rwlock_unlock(&handle->ncloud.buf_cache_lock);
			LogDebug(COMPONENT_FSAL,
				 "End of overwrite with %lu bytes written",
				 total_bytes_written);
			*status = fsalstat(ERR_FSAL_NO_ERROR, 0);
			return total_bytes_written;
		}
	}

	/* collect the new data into a single buffer, or disk cache */
	size_t total_bytes_added_to_buffer = 0; /* total number of bytes added to buffer */
	copy_len = 0; /* length of data to copy from the iov */

	for (i = iov_index; write_arg && i < write_arg->iov_count; i++) {
		LogMidDebug(COMPONENT_FSAL,
			 "%s write_arg offset %lu io vector %d size = %lu",
			 handle->ncloud.path,
			 write_arg->offset, i, write_arg->iov[i].iov_len);
		/* init condition: only reset if starting on a new iov, such that append-after-overwrite works correctly for a partially consumed iov TODO: whether this is correct? */
		for (bytes_written = (i != iov_index? 0 : bytes_written); bytes_written < write_arg->iov[i].iov_len; bytes_written += copy_len) {
			/* 
			 * figure out the amount of data to copy to buffer
			 * (1) all data remains in the current iov, if buffer won't overflow; otherwise,
			 * (2) the remaining available space in the buffer
			 * 
			 *                          cur_buffer_offset        copy_len
			 *                        |<----------------->|<-------------------->|
			 *                       
			 *                        |         write_buf->buf                           |
			 *                       
			 *   |<...................^...................^
			 *   start of file (0)    cur_buffer_start    cur_write_offset
			 */
			uint64_t cur_write_offset = write_arg->offset + total_bytes_written + bytes_written;
			uint64_t cur_buffer_start = handle->ncloud.last_written_offset;
			uint64_t cur_buffer_end = cur_buffer_start + write_buf->size;

			uint64_t split_size = ncloud_get_buffer_split_size(write_buf);

			copy_len = write_arg->iov[i].iov_len - bytes_written;

			/* if write is beyond the buffer, save to disk cache first */
			if (cur_write_offset >= cur_buffer_end) {
				struct ncloud_disk_cache_head *list = &handle->ncloud.disk_cache.write_list;
				if (list->num_splits_in_use >= NCLOUD_CACHE_MAX_NUM_SPLITS) {
					pthread_rwlock_unlock(&handle->ncloud.buf_cache_lock);
					LogCrit(COMPONENT_FSAL,
						 "Not enough cache record for more splits");
					return -1;
				}
				/* copy up to split size */
				if (copy_len > split_size)
					copy_len = split_size;
				if (copy_len == ncloud_write_disk_cache(handle,
							cur_write_offset,
							write_arg->iov[i].iov_base + bytes_written,
							copy_len))
				{
					ncloud_disk_cache_item_add(handle, cur_write_offset, copy_len, /* is_write */ true);
				} 
				continue;
			}

			uint64_t cur_buffer_offset = cur_write_offset - cur_buffer_start;

			if (cur_write_offset >= cur_buffer_end) {
				continue;
			}

			if (copy_len + cur_buffer_offset >= write_buf->size)
				copy_len = write_buf->size - cur_buffer_offset; 

			/* copy the data to write buffer */
			if (copy_len > 0) {
				memcpy(write_buf->buf + cur_buffer_offset,
				       write_arg->iov[i].iov_base + bytes_written,
				       copy_len);
				total_bytes_added_to_buffer += copy_len;
			}

			/* update the filling status of splits */
			int i = 0;
			int split_start_idx = cur_buffer_offset / split_size;
			int split_end_idx = (cur_buffer_offset + copy_len - 1) / split_size;
			int num_cont_full_splits = 0; /* count the number of continuous splits that are full */
			for (i = split_start_idx; copy_len > 0 && i <= split_end_idx; i++) {
				write_buf->bytes_written[i] +=
					min_of((i + 1) * split_size + cur_buffer_start, cur_write_offset + copy_len) -
					max_of(cur_write_offset, i * split_size + cur_buffer_start);
				num_cont_full_splits += (num_cont_full_splits == i && write_buf->bytes_written[i] >= split_size); // should not be larger anyway...
				LogDebug(COMPONENT_FSAL, 
					 "Update splits %d of (%d to %d, inclusive) bytes = %lu (%lu - %lu = %lu)",
					 i, split_start_idx, split_end_idx, write_buf->bytes_written[i], 
					 min_of((i + 1) * split_size + cur_buffer_start, cur_write_offset + copy_len),
					 max_of(cur_write_offset, i * split_size + cur_buffer_start),
					 min_of((i + 1) * split_size + cur_buffer_start, cur_write_offset + copy_len) -
					 max_of(cur_write_offset, i * split_size + cur_buffer_start));
			}

			/* also flush the subsequent (untouched) full splits */
			for (; i < write_buf->num_splits &&
			       num_cont_full_splits == i &&
			       write_buf->bytes_written[i] == split_size;
			       num_cont_full_splits++, i++);

			/* write the data to backend if some buffer split become full */
			if (num_cont_full_splits > 0) {
				struct timespec start, end;
				clock_gettime(CLOCK_REALTIME, &start);
				ssize_t bytes_flushed = ncloud_flush_write_buf(export, handle, num_cont_full_splits);
				clock_gettime(CLOCK_REALTIME, &end);
				double duration = get_duration(start, end);
				if (bytes_flushed == -1 || bytes_flushed < num_cont_full_splits * split_size) {
					LogMajor(COMPONENT_FSAL,
						"Failed to write data to nCloud (%lu instead of %lu) for file %s",
						bytes_flushed, num_cont_full_splits * split_size, handle->ncloud.path
					);
					total_bytes_written = -1;
					pthread_rwlock_unlock(&handle->ncloud.buf_cache_lock);
					break;
				}
				LogInfo(COMPONENT_FSAL,
					"Flush data to nCloud (%lu) for file %s in %.3lfs",
					bytes_flushed, handle->ncloud.path, duration
				);
			}
		}
		/* sum up the total bytes written (to buffer) */
		total_bytes_written += bytes_written;
	}

	/* force flush all remaining data if needed */
	if (is_flush_all) {
		/* TODO check the length of data flushed ?? */
		struct timespec start, end;
		clock_gettime(CLOCK_REALTIME, &start);
		bytes_written = ncloud_flush_write_buf(export, handle, write_buf->num_splits);
		clock_gettime(CLOCK_REALTIME, &end);
		double duration = get_duration(start, end);
		LogMajor(COMPONENT_FSAL,
			"Flush data to nCloud (%lu) for file %s in %.3lfs",
			bytes_written, handle->ncloud.path, duration
		);
		if (bytes_written < 0) {
			LogMajor(COMPONENT_FSAL,
				 "Failed to flush all data of file %s to nCloud",
				 handle->ncloud.path
			);
			total_bytes_written = -1;
		} else if (write_arg == NULL) {
			total_bytes_written += bytes_written;
		}
	}
	clock_gettime(CLOCK_REALTIME, &end_all);
	double duration = get_duration(start_all, end_all);

	pthread_rwlock_unlock(&handle->ncloud.buf_cache_lock);

	LogDebug(COMPONENT_FSAL,
		 "%s offset = %lu total_bytes written = %ld in %.3lfs",
		 handle->ncloud.path, write_arg? write_arg->offset : 0, total_bytes_written, duration);

	*status = fsalstat(ERR_FSAL_NO_ERROR, 0);
	return total_bytes_written;
}

static ssize_t ncloud_check_and_read_if_needed(struct ncloud_fsal_export *export,
						struct ncloud_fsal_obj_handle *handle,
						bool bypass,
						fsal_status_t *status,
						struct fsal_io_arg *read_arg)
{
	if (export == NULL || handle == NULL || read_arg == NULL) {
		*status = fsalstat(ERR_FSAL_INVAL, EINVAL);
		return -1;
	}

	struct timespec start, end;
	double duration = 0.0;
	clock_gettime(CLOCK_REALTIME, &start);

	if (handle->ncloud.read_size == 0 || handle->ncloud.read_size < handle->ncloud.append_size) {
		handle->ncloud.read_size =
			ncloud_get_read_size(export, handle, handle->ncloud.path + strlen(get_mount_path()) + 1);
	}

	/* see if the file exists */
	/* TODO handle empty file (read_size also equals to 0?) */
	if (handle->ncloud.read_size == 0) {
		LogMajor(COMPONENT_FSAL,
			 "Failed to get the read size for file %s",
			 handle->ncloud.path
		);
		*status = fsalstat(ERR_FSAL_NOENT, 0);
		return 0;
	}

	clock_gettime(CLOCK_REALTIME, &end);
	duration = get_duration(start, end);
	LogDebug(COMPONENT_FSAL, "read arg buffer prep (read size) for read on file %s takes %.3lfs", handle->ncloud.path, duration);

	/* allocate buffer on first read */
	if (handle->ncloud.read_buf.size == 0 ||
	    handle->ncloud.read_buf.buf == NULL)
	{
		if (!ncloud_allocate_buffer(&handle->ncloud.read_buf,
					    handle->ncloud.read_size, 1))
		{
			/* TODO switch to disk cache mode if out-of-memory */
			LogCrit(COMPONENT_FSAL,
				 "Failed to allocate buffer of size %lu for read of file %s",
				 handle->ncloud.read_size * 1,
				 handle->ncloud.path
			);
			*status = fsalstat(ERR_FSAL_NOMEM, ENOMEM);
			return -1;
		}
	}

	clock_gettime(CLOCK_REALTIME, &start);
	duration = get_duration(end, start);
	LogDebug(COMPONENT_FSAL, "read arg buffer prep (read buffer) for read on file %s takes %.3lfs", handle->ncloud.path, duration);

	/* start reading data from back-end and copying it to the io vectors */
	unsigned long int read_size = handle->ncloud.read_size;
	ssize_t total_bytes_read = 0, bytes_read = 0;
	size_t copy_len = 0; /* length of data copied to the current iov */
	int i = 0;
	unsigned long int aligned_offset = 0;
	for (i = 0; read_arg && i < read_arg->iov_count; i++) {
		LogDebug(COMPONENT_FSAL,
			 "read_arg offset %lu "
			 "io vector %d size = %lu; buf_offset = %lu",
			 read_arg->offset, i, read_arg->iov[i].iov_len,
			 handle->ncloud.read_buf.offset);

		for (bytes_read = 0;
		     bytes_read < read_arg->iov[i].iov_len;
		     bytes_read += copy_len)
		{
			unsigned long int cur_read_offset = read_arg->offset + total_bytes_read + bytes_read;
			unsigned long int cur_buffer_start = handle->ncloud.last_read_offset;
			unsigned long int cur_buffer_end = handle->ncloud.last_read_offset + handle->ncloud.read_buf.offset;
			copy_len = 0;
			/* 
			 * current read points to an offset beyond the buffer,
			 * read data from disk cache or ncloud
			 */
			LogMidDebug(COMPONENT_FSAL,
				"check and read for cond (%lu <= %lu) or (%lu < %lu)",
				cur_buffer_end, cur_read_offset, cur_buffer_start, cur_read_offset
			);

			if (cur_read_offset < cur_buffer_start || cur_buffer_end <= cur_read_offset) {
				/* try to read directly from disk cache */
				copy_len = read_arg->iov[i].iov_len - bytes_read;
				if (ncloud_read_and_try_fill_buf_with_cache(handle, cur_read_offset, copy_len, read_arg->iov[i].iov_base + bytes_read) == copy_len)
					continue;

				copy_len = 0;

				aligned_offset = cur_read_offset / read_size * read_size;
				if (ncloud_fill_read_buf(export, handle, aligned_offset) <= 0) {
					LogMajor(COMPONENT_FSAL,
						 "Failed to read data beyond offset %lu (aligned = %lu)",
						 cur_read_offset,
						 aligned_offset);
					*status = fsalstat(ERR_FSAL_FAULT, 0);
					break;
				}
				/* last_read_offset maybe modified by ncloud_fill_read_buf() */
				cur_buffer_start = handle->ncloud.last_read_offset;
				cur_buffer_end = handle->ncloud.last_read_offset + handle->ncloud.read_buf.offset;
			}
			/* data inside the buffer is in the range to read */
			if (cur_buffer_start <= cur_read_offset &&
				cur_read_offset < cur_buffer_end) {
				/* assume copy to the end of vector */
				copy_len = read_arg->iov[i].iov_len - bytes_read;
				/* 
				 * check and shorten the length if it goes
				 * beyond the buffer
				 */
				if (cur_read_offset + copy_len > cur_buffer_end)
					copy_len = cur_buffer_end - cur_read_offset;
				/* copy data from buffer to vector */
				memcpy(read_arg->iov[i].iov_base + bytes_read,
				       handle->ncloud.read_buf.buf + (cur_read_offset - cur_buffer_start),
				       copy_len);
				LogMidDebug(COMPONENT_FSAL,
					 "copy %lu bytes from buffer (%lu) into vector %d (%lu)",
					 copy_len, cur_read_offset - cur_buffer_start,
					 i, bytes_read);
			}
			if (copy_len == 0) {
				LogMajor(COMPONENT_FSAL,
					 "Failed to read file %s (%lu,%lu) with buffer (%lu,%lu)",
					 handle->ncloud.path,
					 read_arg->offset, read_arg->iov[i].iov_len,
					 handle->ncloud.last_read_offset, handle->ncloud.read_buf.offset
				);
				break;
			}
		}
		total_bytes_read += bytes_read;
	}

	return total_bytes_read;
}

/**
 * @brief Callback for NULL async calls
 *
 * Unstack, and call up.
 *
 * @param[in] obj		Object being acted on
 * @param[in] ret		Return status of call
 * @param[in] obj_data		Data for call
 * @param[in] caller_data	Data for caller
 */
void null_async_cb(struct fsal_obj_handle *obj, fsal_status_t ret,
		   void *obj_data, void *caller_data)
{
	LogDebug(COMPONENT_FSAL, "trace: call null_async_cb");
	struct fsal_export *save_exp = op_ctx->fsal_export;
	struct null_async_arg *arg = caller_data;

	op_ctx->fsal_export = save_exp->super_export;
	arg->cb(arg->obj_hdl, ret, obj_data, arg->cb_arg);
	op_ctx->fsal_export = save_exp;

	gsh_free(arg);
}

/* ncloud_close
 * Close the file if it is still open.
 * Yes, we ignor lock status.  Closing a file in POSIX
 * releases all locks but that is state and cache inode's problem.
 */

fsal_status_t ncloud_close(struct fsal_obj_handle *obj_hdl)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);
	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);

	/* calling subfsal method */
	op_ctx->fsal_export = export->export.sub_export;
	status = handle->sub_handle->obj_ops->close(handle->sub_handle);
	op_ctx->fsal_export = &export->export;

	LogMidDebug(COMPONENT_FSAL,
		 "trace: call ncloud_close on object %s error= %d (%d,%d)",
		 handle->ncloud.path,
		 FSAL_IS_ERROR(status),
		 status.major,
		 status.minor);

	/* release resources on close() */
	ncloud_release_handle_resources(export, handle);
	return status;
}

fsal_status_t ncloud_open2(struct fsal_obj_handle *obj_hdl,
			   struct state_t *state,
			   fsal_openflags_t openflags,
			   enum fsal_create_mode createmode,
			   const char *name,
			   struct attrlist *attrs_in,
			   fsal_verifier_t verifier,
			   struct fsal_obj_handle **new_obj,
			   struct attrlist *attrs_out,
			   bool *caller_perm_check)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);
	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);
	struct fsal_obj_handle *sub_handle = NULL;
	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);

	LogDebug(COMPONENT_FSAL, "trace: call ncloud_open2 %s (%s) flags = %x type = %d", name, handle->ncloud.path, openflags, attrs_in->type);
	/* 
	 * TODO (?)
	 * (1) check if the file is already exists, get the read size
	 * (2) check if the file is designated to be written / read
	 */

	op_ctx->fsal_export = export->export.sub_export;
	status = handle->sub_handle->obj_ops->open2(handle->sub_handle, state,
						  openflags, createmode, name,
						  attrs_in, verifier,
						  &sub_handle, attrs_out,
						  caller_perm_check);
	op_ctx->fsal_export = &export->export;

	LogDebug(COMPONENT_FSAL, "trace: call ncloud_open2 %s (%s) allocate sub fsal obj handle %p", name, handle->ncloud.path, sub_handle);
	/* wrap the subfsal handle in a ncloud handle. */
	if (sub_handle) {
		char obj_path[PATH_MAX];
		snprintf(obj_path, PATH_MAX, "%s%s%s", handle->ncloud.path, name? "/" : "", name? name : "");

		status = ncloud_alloc_and_check_handle(export, sub_handle,
					     obj_hdl->fs, new_obj,
					     status, obj_path);
		/* mark if the file is opened for write */
		if (!FSAL_IS_ERROR(status)) {
			struct ncloud_fsal_obj_handle *new_handle =
				container_of(*new_obj, struct ncloud_fsal_obj_handle, obj_handle);
			new_handle->ncloud.is_write = (openflags & FSAL_O_WRITE) != 0;
			/* create a new id for the file path if not assigned */
			if (!ncloud_path_map_is_id_valid(new_handle->ncloud.path_id)) {
				new_handle->ncloud.path_id = ncloud_path_map_add(export, obj_path);
			}
			struct timespec ts;
			clock_gettime(CLOCK_REALTIME, &ts);
			LogMidDebug(COMPONENT_FSAL, "trace: call ncloud_open2 %s (%s) allocate ncloud obj handle is_write = %d path_id = %d at %.3lf", name, obj_path, new_handle->ncloud.is_write, new_handle->ncloud.path_id, ts.tv_sec + ts.tv_nsec * 1.0 / 1e9);
		} else {
			LogDebug(COMPONENT_FSAL, "trace: call ncloud_open2 %s (%s) allocate ncloud obj handle", name, obj_path);
		}
	}
	return status;
}

bool ncloud_check_verifier(struct fsal_obj_handle *obj_hdl,
			   fsal_verifier_t verifier)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	LogDebug(COMPONENT_FSAL, "trace: call ncloud_check_verifier on object %s", handle->ncloud.path);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	/* calling subfsal method */
	op_ctx->fsal_export = export->export.sub_export;
	bool result =
		handle->sub_handle->obj_ops->check_verifier(handle->sub_handle,
							   verifier);
	op_ctx->fsal_export = &export->export;

	return result;
}

fsal_openflags_t ncloud_status2(struct fsal_obj_handle *obj_hdl,
				struct state_t *state)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	LogDebug(COMPONENT_FSAL, "trace: call ncloud_status2 on object %s", handle->ncloud.path);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	/* calling subfsal method */
	op_ctx->fsal_export = export->export.sub_export;
	fsal_openflags_t result =
		handle->sub_handle->obj_ops->status2(handle->sub_handle, state);
	op_ctx->fsal_export = &export->export;

	return result;
}

fsal_status_t ncloud_reopen2(struct fsal_obj_handle *obj_hdl,
			     struct state_t *state,
			     fsal_openflags_t openflags)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	LogMidDebug(COMPONENT_FSAL, "trace: call ncloud_reopen2 on object %s is_write = %d", handle->ncloud.path, openflags & FSAL_O_WRITE);
	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	/* calling subfsal method */
	op_ctx->fsal_export = export->export.sub_export;
	status = handle->sub_handle->obj_ops->reopen2(handle->sub_handle,
						    state, openflags);
	op_ctx->fsal_export = &export->export;

	/* update the file write access flag */
	handle->ncloud.is_write = !FSAL_IS_ERROR(status) && (openflags & FSAL_O_WRITE) != 0;

	return status;
}

void ncloud_read2(struct fsal_obj_handle *obj_hdl,
		  bool bypass,
		  fsal_async_cb done_cb,
		  struct fsal_io_arg *read_arg,
		  void *caller_arg)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);
	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);
	struct null_async_arg *arg;

	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);

	struct timespec start, end;
	clock_gettime(CLOCK_REALTIME, &start);
	LogMidDebug(COMPONENT_FSAL, "trace: call ncloud_read2 on object %s offset = %lu starts at %.3lf", handle->ncloud.path, read_arg->offset, start.tv_sec + start.tv_nsec * 1.0 / 1e9);

	/* Set up async callback */
	arg = gsh_calloc(1, sizeof(*arg));
	arg->obj_hdl = obj_hdl;
	arg->cb = done_cb;
	arg->cb_arg = caller_arg;

	if (obj_hdl->type != REGULAR_FILE) {
		LogDebug(COMPONENT_FSAL, "trace: call ncloud_read2 on object %s not regular file %d", handle->ncloud.path, obj_hdl->type);
		/* calling subfsal method */
		op_ctx->fsal_export = export->export.sub_export;
		handle->sub_handle->obj_ops->read2(handle->sub_handle, bypass,
						  null_async_cb, read_arg, arg);
		op_ctx->fsal_export = &export->export;
	} else {
		/* 
		 * use exclusive lock, since the read buffer might be
		 * modified
		 */
		pthread_rwlock_wrlock(&handle->ncloud.buf_cache_lock);
		/* get data from ncloud */
		clock_gettime(CLOCK_REALTIME, &start);
		ssize_t bytes_read = ncloud_check_and_read_if_needed(export, handle, bypass, &status, read_arg);
		clock_gettime(CLOCK_REALTIME, &end);
		double duration = get_duration(start, end);
		LogMidDebug(COMPONENT_FSAL, "trace: call ncloud_read2 on nCloud object %s offset = %lu bytes_read = %lu in %.3lfs", handle->ncloud.path, read_arg->offset, bytes_read, duration);
		/* 
		 * mark the number of bytes read (0 for failed case), 
		 * and whether the end of file is reached 
		 */
		read_arg->io_amount = (bytes_read > 0)? bytes_read : 0;
		read_arg->end_of_file = (read_arg->io_amount == 0);
		pthread_rwlock_unlock(&handle->ncloud.buf_cache_lock);
		/* call the call-back function at the end of operation */
		done_cb(obj_hdl, status, read_arg, caller_arg);
	}
}

void ncloud_write2(struct fsal_obj_handle *obj_hdl,
		   bool bypass,
		   fsal_async_cb done_cb,
		   struct fsal_io_arg *write_arg,
		   void *caller_arg)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	struct null_async_arg *arg;

	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);

	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	LogMidDebug(COMPONENT_FSAL,
		 "trace: call ncloud_write2 on object %s vers = %d stable = %d (%lu,%d,%lu) starts at %.3lf",
		 handle->ncloud.path,
		 op_ctx->nfs_vers,
		 write_arg->fsal_stable,
		 write_arg->offset,
		 write_arg->iov_count,
		 (write_arg->iov_count > 0? write_arg->iov[0].iov_len : -1),
		 ts.tv_sec + ts.tv_nsec * 1.0 / 1e9
	);

	/* report error for NFSv3 (not supported) */
	if (op_ctx->nfs_vers < 4) {
		LogCrit(
			COMPONENT_FSAL,
			"Do not support writes for NFSv3 or below current = %d",
			op_ctx->nfs_vers
		);
		status = fsalstat(ERR_FSAL_NOTSUPP, EPFNOSUPPORT);
		done_cb(obj_hdl, status, write_arg, caller_arg);
		return;
	}

	/* Set up async callback */
	arg = gsh_calloc(1, sizeof(*arg));
	arg->obj_hdl = obj_hdl;
	arg->cb = done_cb;
	arg->cb_arg = caller_arg;


	/* calling subfsal method */
	if (obj_hdl->type != REGULAR_FILE && handle->sub_handle) {
		//LogDebug(COMPONENT_FSAL, "trace: call ncloud_write2 on object %s not regular file %d", handle->ncloud.path, obj_hdl->type);
		LogMajor(COMPONENT_FSAL, "trace: call ncloud_write2 on object %s not regular file %d", handle->ncloud.path, obj_hdl->type);
		op_ctx->fsal_export = export->export.sub_export;
		handle->sub_handle->obj_ops->write2(handle->sub_handle, bypass,
						   null_async_cb, write_arg, arg);
		op_ctx->fsal_export = &export->export;
	} else {
		/* check and write data to nCloud */
		ssize_t bytes_processed = ncloud_check_and_write_if_needed(export, handle, bypass, write_arg, &status, /* is_flush_all */ false);
		/* mark the amount of bytes processed */
		write_arg->io_amount = (bytes_processed > 0)? bytes_processed : 0;
		/* call the call-back function at the end of operation */
		done_cb(obj_hdl, status, write_arg, caller_arg);
	}
	clock_gettime(CLOCK_REALTIME, &ts);
	LogDebug(COMPONENT_FSAL,
		 "trace: call ncloud_write2 on object %s vers = %d stable = %d (%lu,%d,%lu) ends at %.3lf",
		 handle->ncloud.path,
		 op_ctx->nfs_vers,
		 write_arg->fsal_stable,
		 write_arg->offset,
		 write_arg->iov_count,
		 (write_arg->iov_count > 0? write_arg->iov[0].iov_len : -1),
		 ts.tv_sec + ts.tv_nsec * 1.0 / 1e9
	);
}

fsal_status_t ncloud_seek2(struct fsal_obj_handle *obj_hdl,
			   struct state_t *state,
			   struct io_info *info)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);
	LogDebug(COMPONENT_FSAL, "trace: call ncloud_seek2 on object %s", handle->ncloud.path);

	/* calling subfsal method */
	op_ctx->fsal_export = export->export.sub_export;
	status = handle->sub_handle->obj_ops->seek2(handle->sub_handle, state,
						  info);
	op_ctx->fsal_export = &export->export;

	return status;
}

fsal_status_t ncloud_io_advise2(struct fsal_obj_handle *obj_hdl,
				struct state_t *state,
				struct io_hints *hints)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	LogDebug(COMPONENT_FSAL, "trace: call ncloud_io_advise2 on object %s", handle->ncloud.path);
	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);

	/* calling subfsal method */
	op_ctx->fsal_export = export->export.sub_export;
	status = handle->sub_handle->obj_ops->io_advise2(handle->sub_handle,
						       state, hints);
	op_ctx->fsal_export = &export->export;

	return status;
}

fsal_status_t ncloud_commit2(struct fsal_obj_handle *obj_hdl, off_t offset,
			     size_t len)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	LogDebug(COMPONENT_FSAL, "trace: call ncloud_commit2 for object %s at (%lu,%lu)", handle->ncloud.path, offset, len);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);

	/* calling subfsal method */
	op_ctx->fsal_export = export->export.sub_export;
	status = handle->sub_handle->obj_ops->commit2(handle->sub_handle, offset,
						    len);
	op_ctx->fsal_export = &export->export;

	return status;
}

fsal_status_t ncloud_lock_op2(struct fsal_obj_handle *obj_hdl,
			      struct state_t *state,
			      void *p_owner,
			      fsal_lock_op_t lock_op,
			      fsal_lock_param_t *req_lock,
			      fsal_lock_param_t *conflicting_lock)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	LogInfo(COMPONENT_FSAL, "trace: call ncloud_lock_op2 on object %s", handle->ncloud.path);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);
	/* calling subfsal method */
	op_ctx->fsal_export = export->export.sub_export;
	status = handle->sub_handle->obj_ops->lock_op2(handle->sub_handle, state,
						     p_owner, lock_op, req_lock,
						     conflicting_lock);
	op_ctx->fsal_export = &export->export;

	return status;
}

fsal_status_t ncloud_close2(struct fsal_obj_handle *obj_hdl,
			    struct state_t *state)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	fsal_status_t status;
	fsal_status_t ncloud_status = fsalstat(ERR_FSAL_NO_ERROR, 0);

	LogInfo(COMPONENT_FSAL, "trace: call ncloud_close2 on object %s", handle->ncloud.path);

	if (obj_hdl->type == REGULAR_FILE) {
		ncloud_check_and_write_if_needed(export,
						 handle,
						 /* bypass */ false,
						 /* write_io_arg */ NULL, 
						 &ncloud_status,
						 /* is_flush_all */ true);
		ncloud_conn_t_release(&handle->ncloud.conn);
	}

	/* calling subfsal method */
	op_ctx->fsal_export = export->export.sub_export;
	status = handle->sub_handle->obj_ops->close2(handle->sub_handle, state);
	op_ctx->fsal_export = &export->export;

	/* remove entry if file is not created */
	ncloud_update_meta(export, handle->ncloud.path + strlen(get_mount_path()) + 1);
	struct attrlist attr_out;
	attr_out.type = REGULAR_FILE;
	if (!ncloud_stat_file(handle->ncloud.path, &attr_out) || FSAL_IS_ERROR(ncloud_status)) {
		if (!FSAL_IS_ERROR(ncloud_status))
			ncloud_status = fsalstat(ERR_FSAL_FAULT, ENETDOWN);
		unlink(handle->ncloud.path);
	}

	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	LogMidDebug(COMPONENT_FSAL,
		 "trace: call ncloud_close2 on object %s ends is_regular = %d, error = %d(%d,%d) error = %d(%d,%d) at %.3lf",
		 handle->ncloud.path,
		 obj_hdl->type == REGULAR_FILE,
		 FSAL_IS_ERROR(status),
		 status.major,
		 status.minor,
		 FSAL_IS_ERROR(ncloud_status),
		 ncloud_status.major,
		 ncloud_status.minor,
		 ts.tv_sec + ts.tv_nsec * 1.0 / 1e9
	);

	/* release resources on close() */
	ncloud_release_handle_resources(export, handle);

	return FSAL_IS_ERROR(ncloud_status)? ncloud_status : status;
}

fsal_status_t ncloud_fallocate(struct fsal_obj_handle *obj_hdl,
			       struct state_t *state, uint64_t offset,
			       uint64_t length, bool allocate)
{
	struct ncloud_fsal_obj_handle *handle =
		container_of(obj_hdl, struct ncloud_fsal_obj_handle,
			     obj_handle);

	struct ncloud_fsal_export *export =
		container_of(op_ctx->fsal_export, struct ncloud_fsal_export,
			     export);

	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);

	LogMajor(COMPONENT_FSAL, "trace: call ncloud_fallocate on object %s", handle->ncloud.path);

	/* calling subfsal method */
	//op_ctx->fsal_export = export->export.sub_export;
	//status = handle->sub_handle->obj_ops->fallocate(handle->sub_handle,
	//						state, offset, length,
	//						allocate);
	//op_ctx->fsal_export = &export->export;
	return status;
}
