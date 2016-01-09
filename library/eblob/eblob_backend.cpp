/*
 * Copyright 2008+ Evgeniy Polyakov <zbr@ioremap.net>
 * Copyright 2015+ Kirill Smorodinnikov <shaitkir@gmail.com>
 *
 * This file is part of Elliptics.
 *
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "eblob_backend.h"

#include "elliptics/backends.h"
#include "elliptics/utils.hpp"
#include "library/elliptics.h"

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include "monitor/measure_points.h"

#if EBLOB_ID_SIZE != DNET_ID_SIZE
#error "EBLOB_ID_SIZE must be equal to DNET_ID_SIZE"
#endif

static inline void convert_id(const uint8_t *id, eblob_key &key) {
	memcpy(key.id, id, EBLOB_ID_SIZE);
}

static inline void convert_id(const dnet_raw_id &id, eblob_key &key) {
	convert_id(id.id, key);
}

static inline eblob_key convert_id(const uint8_t *id) {
	eblob_key key;
	convert_id(id, key);
	return std::move(key);
}

static inline eblob_key convert_id(const dnet_raw_id &id) {
	return std::move(convert_id(id.id));
}

extern __thread trace_id_t backend_trace_id_hook;

trace_id_t get_trace_id()
{
	return backend_trace_id_hook;
}

int blob_lookup_struct(struct eblob_backend_config *c, struct dnet_net_state *state, struct dnet_cmd *cmd, void *data);
int blob_read_struct(struct eblob_backend_config *c, struct dnet_net_state *state, struct dnet_cmd *cmd, void *data);
int blob_write_struct(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd, void *data);
std::string blob_read_stored_index(eblob_backend_config *c, const eblob_key &key, const eblob_write_control &wc);

class struct_reader {
public:
	struct_reader(eblob_backend_config *c, dnet_net_state *state)
	: m_eblob(c->eblob)
	, m_log(c->blog)
	, m_state(state)

	, m_io(nullptr)
	, m_key()
	, m_wc()
	, m_request_index()
	, m_stored_index()

	, m_c(c)
	{}

	int read(dnet_cmd *cmd, void *data);
	int read_default(dnet_cmd *cmd, void *data);
private:
	void parse_request(void *data);
	int read_stored_index();

	/* useful out-come fields */
	eblob_backend *m_eblob;
	dnet_logger *m_log;
	dnet_net_state *m_state;

	/* generated fields */
	dnet_io_attr *m_io;
	eblob_key m_key;
	eblob_write_control m_wc;
	std::string m_request_index;
	std::string m_stored_index;

	/* which should be removed */
	eblob_backend_config *m_c;
};

/* Pre-callback that formats arguments and calls ictl->callback */
static int blob_iterate_callback_common(struct eblob_disk_control *dc, int fd, uint64_t data_offset, void *priv, int no_meta) {
	auto ictl = static_cast<dnet_iterator_ctl *>(priv);
	struct dnet_ext_list_hdr ehdr;
	struct dnet_ext_list elist;
	auto c = static_cast< eblob_backend_config *>(ictl->iterate_private);
	uint64_t size;
	int err;

	assert(dc != NULL);

	size = dc->data_size;
	dnet_ext_list_init(&elist);

	/* If it's an extended record - extract header, move data pointer */
	if (dc->flags & BLOB_DISK_CTL_EXTHDR) {
		/*
		 * Skip reading/extracting header of the committed records if iterator runs with no_meta.
		 * Header of uncommitted records should be read in any cases for correct recovery.
		 */
		if (!no_meta || (dc->flags & BLOB_DISK_CTL_UNCOMMITTED)) {
			err = dnet_ext_hdr_read(&ehdr, fd, data_offset);
			if (!err) {
				dnet_ext_hdr_to_list(&ehdr, &elist);
			} else {
				/* If extended header couldn't be extracted reset elist,
				 * call callback for key with empty elist
				 * and continue iteration because the rest records can be ok.
				 * We need to reset the error to make iteration continue.
				 */
				char buffer[2*DNET_ID_SIZE + 1] = {0};
				dnet_backend_log(c->blog, DNET_LOG_ERROR,
					"blob: iter: %s: dnet_ext_hdr_read failed: %d. Use empty extended header for this key\n",
					dnet_dump_id_len_raw((const unsigned char*)&dc->key, DNET_ID_SIZE, buffer), err);

				err = 0;
			}
		}

		data_offset += sizeof(struct dnet_ext_list_hdr);

		/*
		 * When record has not been committed (no matter whether data has been written or not)
		 * its @data_size is zero and removing ext header size ends up with
		 * negative size converted back to very large positive number (0xffffffffffffffd0).
		 *
		 * It is possible that iterator will catch this key before commit time,
		 * we have to be ready and do not provide invalid size.
		 *
		 * For more details, see blob_write() function below and prepare section comments.
		 *
		 * @data_header is safe, since we have preallocated all needed space for ext header
		 * it just hasn't yet been committed to disk and thus @data_size hasn't yet been updated.
		 */

		if (size >= sizeof(struct dnet_ext_list_hdr)) {
			size -= sizeof(struct dnet_ext_list_hdr);
		}
	}

	err = ictl->callback(ictl->callback_private,
	                     (struct dnet_raw_id *)&dc->key, dc->flags,
	                     fd, data_offset, size, &elist);

	dnet_ext_list_destroy(&elist);
	return err;
}

/* Pre-callback which calls blob_iterate_callback_common with no_meta=1.
 * With no_meta=1 blob_iterate_callback_common will not read ext header from blob and
 * will empty timestamp.
 */
static int blob_iterate_callback_without_meta(struct eblob_disk_control *dc,
		struct eblob_ram_control *,
		int fd, uint64_t data_offset, void *priv, void *) {
	return blob_iterate_callback_common(dc, fd, data_offset, priv, 1);
}

/* Pre-callback which calls blob_iterate_callback_common with no_meta=0
 * With no_meta=0 blob_iterate_callback_common will read ext header from blob.
 */
static int blob_iterate_callback_with_meta(struct eblob_disk_control *dc,
		struct eblob_ram_control *,
		int fd, uint64_t data_offset, void *priv, void *) {
	return blob_iterate_callback_common(dc, fd, data_offset, priv, 0);
}

static int blob_lookup(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc) {
	int err = eblob_read_return(b, key, EBLOB_READ_NOCSUM, wc);
	/* Uncommitted records can be read, so fail lookup with ENOENT */
	if (err == 0 && wc->flags & BLOB_DISK_CTL_UNCOMMITTED)
		err = -ENOENT;
	return err;
}

static int blob_write(struct eblob_backend_config *c, dnet_net_state *state,
		struct dnet_cmd *cmd, void *data)
{
	struct dnet_ext_list elist;
	auto io = static_cast<dnet_io_attr *>(data);
	auto b = static_cast<eblob_backend *>(c->eblob);
	eblob_write_control wc;
	memset(&wc, 0, sizeof(wc));
	wc.data_fd = -1;
	struct dnet_ext_list_hdr ehdr;
	uint64_t flags = BLOB_DISK_CTL_EXTHDR;
	uint64_t fd_offset;
	static const size_t ehdr_size = sizeof(struct dnet_ext_list_hdr);
	int err;

	dnet_backend_log(c->blog, DNET_LOG_NOTICE, "%s: EBLOB: blob-write: WRITE: start: offset: %llu, size: %llu, ioflags: %s",
		dnet_dump_id_str(io->id), (unsigned long long)io->offset, (unsigned long long)io->size,
		dnet_flags_dump_ioflags(io->flags));

	dnet_convert_io_attr(io);

	dnet_ext_list_init(&elist);
	dnet_ext_io_to_list(io, &elist);
	dnet_ext_list_to_hdr(&elist, &ehdr);

	data += sizeof(struct dnet_io_attr);

	if (io->flags & DNET_IO_FLAGS_APPEND)
		flags |= BLOB_DISK_CTL_APPEND;

	if (io->flags & DNET_IO_FLAGS_NOCSUM)
		flags |= BLOB_DISK_CTL_NOCSUM;

	auto key = convert_id(io->id);

	if (io->flags & DNET_IO_FLAGS_PREPARE) {
		/*
		 * We have to put ext header flag into prepare command, since otherwise
		 * we can not overwrite data later with this flag.
		 *
		 * Eblob correctly believes that existing on-disk record without ext header
		 * (this will be the case after prepare has been completed) can not be
		 * overwritten with chunk containing ext-header.
		 *
		 * Setting this flag opens a window for race with iterator.
		 * Iterator will see the record with ext header bit set,
		 * but without actual data.
		 *
		 * XXX Alternative way is to fix eblob not to check ext header flag if uncommitted bit is set.
		 * XXX See eblob_plain_writev_prepare() and ext header check.
		 */
		err = eblob_write_prepare(b, &key, io->num + ehdr_size, flags);
		if (err) {
			dnet_backend_log(c->blog, DNET_LOG_ERROR, "%s: EBLOB: blob-write: eblob_write_prepare: "
					"size: %" PRIu64 ": %s %d", dnet_dump_id_str(io->id),
					io->num + ehdr_size, strerror(-err), err);
			goto err_out_exit;
		}

		const struct eblob_iovec iov { &ehdr, sizeof(ehdr), 0};

		err = eblob_plain_writev(b, &key, &iov, 1, flags);
		if (err) {
			dnet_backend_log(c->blog, DNET_LOG_ERROR,
				"%s: EBLOB: blob-write: eblob_plain_writev: header WRITE: %d: %s",
				dnet_dump_id_str(io->id), err, strerror(-err));
			goto err_out_exit;
		}

		dnet_backend_log(c->blog, DNET_LOG_NOTICE, "%s: EBLOB: blob-write: eblob_write_prepare: "
				"size: %" PRIu64 ": Ok", dnet_dump_id_str(io->id), io->num + ehdr_size);
	}

	if (io->size) {
		/*
		 * Although we have already filled ext header above (at prepare time),
		 * we update it each time chunk has been written to change timestamp and user flags.
		 */
		const struct eblob_iovec iov[2] {
			{ &ehdr, sizeof(ehdr), 0 },
			{ data, io->size, sizeof(ehdr) + io->offset },
		};

		if (io->flags & DNET_IO_FLAGS_PLAIN_WRITE) {
			err = eblob_plain_writev(b, &key, iov, 2, flags);
		} else {
			err = eblob_writev_return(b, &key, iov, 2, flags, &wc);
		}

		if (err) {
			dnet_backend_log(c->blog, DNET_LOG_ERROR, "%s: EBLOB: blob-write: WRITE: %d: %s",
				dnet_dump_id_str(io->id), err, strerror(-err));
			goto err_out_exit;
		}

		dnet_backend_log(c->blog, DNET_LOG_NOTICE, "%s: EBLOB: blob-write: WRITE: Ok: "
				"offset: %" PRIu64 ", size: %" PRIu64 ".",
				dnet_dump_id_str(io->id), io->offset, io->size);
	}

	if (io->flags & DNET_IO_FLAGS_COMMIT) {
		/*
		 * If io->size is not zero, ext header has been written above.
		 */
		if (io->size == 0) {
			const struct eblob_iovec iov { &ehdr, sizeof(ehdr), 0 };

			err = eblob_plain_writev(b, &key, &iov, 1, flags);
			if (err) {
				dnet_backend_log(c->blog, DNET_LOG_ERROR,
					"%s: EBLOB: blob-write: eblob_plain_writev: commit WRITE: %d: %s",
					dnet_dump_id_str(io->id), err, strerror(-err));
				goto err_out_exit;
			}
		}

		if (io->flags & DNET_IO_FLAGS_PLAIN_WRITE) {
			uint64_t csize = io->num + ehdr_size;
			if (io->flags & DNET_IO_FLAGS_PREPARE) {
				// client has set PREPARE, PLAIN_WRITE and COMMIT flags,
				// there is no way he could write more data than io->size,
				// thus it is an error to commit more than io->size + io->offset,
				// otherwise it will commit empty (zeroed) space (io->num) as data
				//
				// this set of flags is used to reserve disk (not data) space for future updates
				csize = io->size + io->offset + ehdr_size;
			}
			err = eblob_write_commit(b, &key, csize, flags);
			if (err) {
				dnet_backend_log(c->blog, DNET_LOG_ERROR, "%s: EBLOB: blob-write: eblob_write_commit: "
						"size: %" PRIu64 ": %s %d", dnet_dump_id_str(io->id),
						csize, strerror(-err), err);
				goto err_out_exit;
			}

			dnet_backend_log(c->blog, DNET_LOG_NOTICE, "%s: EBLOB: blob-write: eblob_write_commit: "
					"size: %" PRIu64 ": Ok", dnet_dump_id_str(io->id), csize);
		}
	}

	if (!err && wc.data_fd == -1) {
		err = eblob_read_return(b, &key, EBLOB_READ_NOCSUM, &wc);
		if (err) {
			dnet_backend_log(c->blog, DNET_LOG_ERROR, "%s: EBLOB: blob-write: eblob_read: "
					"size: %" PRIu64 ": %s %d", dnet_dump_id_str(io->id),
					io->num, strerror(-err), err);
			goto err_out_exit;
		}
	}

	if (io->flags & DNET_IO_FLAGS_WRITE_NO_FILE_INFO) {
		cmd->flags |= DNET_FLAGS_NEED_ACK;
		err = 0;
		goto err_out_exit;
	}

	fd_offset = wc.ctl_data_offset + sizeof(struct eblob_disk_control);
	if (wc.flags & BLOB_DISK_CTL_EXTHDR)
		fd_offset += ehdr_size;

	err = dnet_send_file_info_ts(state, cmd, wc.data_fd, fd_offset, wc.size, &elist.timestamp, wc.flags);
	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "%s: EBLOB: blob-write: dnet_send_file_info: "
				"fd: %d, offset: %" PRIu64 ", offset-within-fd: %" PRIu64 ", size: %" PRIu64 ": %s %d",
				dnet_dump_id_str(io->id), wc.data_fd, wc.offset, fd_offset, wc.size,
				strerror(-err), err);
		goto err_out_exit;
	}

	dnet_backend_log(c->blog, DNET_LOG_INFO, "%s: EBLOB: blob-write: fd: %d, offset: %" PRIu64
			", offset-within-fd: %" PRIu64 ", size: %" PRIu64 "",
			dnet_dump_id_str(io->id), wc.data_fd, wc.offset, fd_offset, wc.size);

err_out_exit:
	dnet_ext_list_destroy(&elist);
	return err;
}

static int blob_read_struct_default(eblob_backend_config *c,
                                    const eblob_key &key,
                                    const eblob_write_control &wc,
                                    const dnet_ext_list_hdr &ehdr,
                                    uint64_t &size,
                                    uint64_t &offset,
                                    uint64_t &record_offset) {
	size -= ehdr.index_size;
	offset += ehdr.index_size;
	record_offset += ehdr.index_size;

	auto index = blob_read_stored_index(c, key, wc);
	rapidjson::Document stored_doc;
	stored_doc.Parse<0>(index.data());

	if (stored_doc.HasMember("default")) {
		const auto &value = stored_doc["default"];
		if (value.HasMember("__attributes__")) {
			const auto &attributes = value["__attributes__"];
			size = attributes["size"].GetUint64();
			offset += attributes["offset"].GetUint64();
			record_offset += attributes["offset"].GetUint64();
		}
	}
	return 0;
}


static int blob_read(struct eblob_backend_config *c, dnet_net_state *state, struct dnet_cmd *cmd, void *data, int last)
{
	struct dnet_ext_list elist;
	auto io = static_cast<dnet_io_attr *>(data);
	auto b = static_cast<eblob_backend *>(c->eblob);
	struct eblob_write_control wc;
	uint64_t offset = 0, size = 0, record_offset = io->offset;
	int err, fd = -1, on_close = 0;
	static const size_t ehdr_size = sizeof(struct dnet_ext_list_hdr);

	dnet_ext_list_init(&elist);
	dnet_convert_io_attr(io);

	auto key = convert_id(io->id);

	err = blob_lookup(b, &key, &wc);
	if (err < 0) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "%s: EBLOB: blob-read-fd: READ: %d: %s",
		                 dnet_dump_id_str(io->id), err, strerror(-err));
		goto err_out_exit;
	}

	/* Existing entry */
	offset = wc.data_offset;
	size = wc.total_data_size;
	fd = wc.data_fd;

	/* Existing new-format entry */
	if ((wc.flags & BLOB_DISK_CTL_EXTHDR) != 0) {
		struct dnet_ext_list_hdr ehdr;

		/* Sanity */
		if (size < ehdr_size) {
			err = -ERANGE;
			goto err_out_exit;
		}

		err = dnet_ext_hdr_read(&ehdr, fd, offset);
		if (err != 0)
			goto err_out_exit;
		dnet_ext_hdr_to_list(&ehdr, &elist);
		dnet_ext_list_to_io(&elist, io);

		/* Take into an account extended header's len */
		size -= sizeof(struct dnet_ext_list_hdr);
		offset += sizeof(struct dnet_ext_list_hdr);
		record_offset += sizeof(struct dnet_ext_list_hdr);

		if (ehdr.index_size != 0) {
			err = blob_read_struct_default(c, key, wc, ehdr, size, offset, record_offset);
			if (err) {
				goto err_out_exit;
			}
		}
	}

	err = dnet_backend_check_get_size(io, &offset, &size);
	if (err) {
		goto err_out_exit;
	}

	io->record_flags = wc.flags;

	if (!(io->flags & DNET_IO_FLAGS_NOCSUM)) {
		wc.offset = record_offset;
		wc.size = size;
		err = eblob_verify_checksum(b, &key, &wc);
		if (err)
			goto err_out_exit;
	}

	if (size && last)
		cmd->flags &= ~DNET_FLAGS_NEED_ACK;

	if (fd >= 0) {
		struct eblob_read_params *p, *prev;
		int i;

		pthread_mutex_lock(&c->last_read_lock);
		p = &c->last_reads[c->last_read_index];

		if (++c->last_read_index >= (int)ARRAY_SIZE(c->last_reads)) {
			int64_t tmp;
			int64_t mult = 1;
			int64_t mean = 0;
			int old_ra;

			std::sort(c->last_reads, c->last_reads + ARRAY_SIZE(c->last_reads),
				[] (const eblob_read_params &r1, const eblob_read_params &r2) {
					if (r1.fd != r2.fd) {
						return r1.fd > r2.fd;
					} else {
						return r1.offset > r2.offset;
					}
				}
			);

			prev = &c->last_reads[0];
			tmp = prev->offset;

			for (i = 1; i < (int)ARRAY_SIZE(c->last_reads); ++i) {
				p = &c->last_reads[i];

				if (p->fd != prev->fd)
					mult++;

				tmp += p->offset * mult;
				prev = p;
			}

			/* found mean offset */
			mean = tmp / ARRAY_SIZE(c->last_reads);

			/* calculating mean squared error */
			tmp = 0;
			for (i = 0; i < (int)ARRAY_SIZE(c->last_reads); ++i) {
				p = &c->last_reads[i];

				tmp += ((int64_t)p->offset - mean) * ((int64_t)p->offset - mean);
			}
			tmp /= ARRAY_SIZE(c->last_reads);

			/*
			 * tmp and vm_total are squared, so if this check is true,
			 * mean offset difference (error) is more than 25% of RAM
			 */
			old_ra = c->random_access;
			if (tmp > c->vm_total / 16)
				c->random_access = 1;
			else
				c->random_access = 0;

			if (old_ra != c->random_access) {
				dnet_backend_log(c->blog, DNET_LOG_ERROR,
					"EBLOB: switch RA %d -> %d, offset MSE: %llu, squared VM total: %llu",
					old_ra, c->random_access, (unsigned long long)tmp, (unsigned long long)c->vm_total);
			}

			c->last_read_index = 0;
		}

		p->fd = fd;
		p->offset = offset;
		pthread_mutex_unlock(&c->last_read_lock);
	}

	if (c->random_access)
		on_close = DNET_IO_REQ_FLAGS_CACHE_FORGET;

	err = dnet_send_read_data(state, cmd, io, NULL, fd, offset, on_close);

err_out_exit:
	dnet_ext_list_destroy(&elist);
	return err;
}

struct eblob_read_range_priv {
	dnet_net_state		*state;
	struct dnet_cmd		*cmd;
	dnet_logger		*blog;
	struct eblob_range_request	*keys;
	uint64_t		keys_size;
	uint64_t		keys_cnt;
	uint32_t		flags;
};

static int blob_cmp_range_request(const void *req1, const void *req2)
{
	return memcmp(((struct eblob_range_request *)(req1))->record_key,
	              ((struct eblob_range_request *)(req2))->record_key,
	              EBLOB_ID_SIZE);
}

static int blob_read_range_callback(struct eblob_range_request *req)
{
	auto p = static_cast<eblob_read_range_priv *>(req->priv);
	struct dnet_io_attr io;
	int err;

	if (req->requested_offset > req->record_size) {
		err = 0;
		goto err_out_exit;
	}

	if (!(p->flags & DNET_IO_FLAGS_NODATA)) {
		struct eblob_write_control wc;

		io.flags = 0;
		io.size = req->record_size - req->requested_offset;
		io.offset = req->requested_offset;

		/* FIXME: This is slow! */
		err = blob_lookup(req->back, (struct eblob_key *)req->record_key, &wc);
		if (err)
			goto err_out_exit;

		if (wc.flags & BLOB_DISK_CTL_EXTHDR) {
			struct dnet_ext_list_hdr ehdr;
			struct dnet_ext_list elist;

			err = dnet_ext_hdr_read(&ehdr, req->record_fd, req->record_offset);
			if (err != 0)
				goto err_out_exit;

			dnet_ext_hdr_to_list(&ehdr, &elist);
			dnet_ext_list_to_io(&elist, &io);

			io.offset += sizeof(struct dnet_ext_list_hdr);
			io.size -= sizeof(struct dnet_ext_list_hdr);
		}

		memcpy(io.id, req->record_key, DNET_ID_SIZE);
		memcpy(io.parent, req->end, DNET_ID_SIZE);

		err = dnet_send_read_data(p->state, p->cmd, &io, NULL, req->record_fd,
				req->record_offset + io.offset, 0);
		if (!err)
			req->current_pos++;
	} else {
		req->current_pos++;
		err = 0;
	}

err_out_exit:
	return err;
}

static int blob_del_range_callback(struct eblob_backend_config *c, struct eblob_range_request *req)
{
	int err;

	dnet_backend_log(c->blog, DNET_LOG_DEBUG, "%s: EBLOB: blob-read-range: DEL",
			dnet_dump_id_str(req->record_key));

	auto key = convert_id(req->record_key);
	err = eblob_remove(req->back, &key);
	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_DEBUG, "%s: EBLOB: blob-read-range: DEL: err: %d",
				dnet_dump_id_str(req->record_key), err);
	}

	return err;
}

static int blob_range_callback(struct eblob_range_request *req)
{
	auto p = static_cast<eblob_read_range_priv *>(req->priv);
	int len = 10;
	char start_id[len*2+1], end_id[len*2+1], cur_id[2*len+1];
	int err = 0;

	dnet_dump_id_len_raw(req->start, len, start_id);
	dnet_dump_id_len_raw(req->end, len, end_id);
	dnet_dump_id_len_raw(req->record_key, len, cur_id);

	dnet_backend_log(p->blog, DNET_LOG_NOTICE, "%s: EBLOB: blob-range: limit: %llu [%llu, %llu]: "
			"start: %s, end: %s: io record/requested: offset: %llu/%llu, size: %llu/%llu",
			cur_id,
			(unsigned long long)req->current_pos,
			(unsigned long long)req->requested_limit_start, (unsigned long long)req->requested_limit_num,
			start_id, end_id,
			(unsigned long long)req->record_offset, (unsigned long long)req->requested_offset,
			(unsigned long long)req->record_size, (unsigned long long)req->requested_size);

	if (req->requested_offset > req->record_size) {
		err = 0;
		goto err_out_exit;
	}

	if (p->keys_size == p->keys_cnt) {
		/* On first pass allocate 1000, otherwise double allocation size */
		p->keys_size = p->keys_size ? p->keys_size * 2 : 1000;
		p->keys = (eblob_range_request*)realloc(p->keys, sizeof(struct eblob_range_request) * p->keys_size);
		if (p->keys == NULL) {
			err = -ENOMEM;
			dnet_backend_log(p->blog, DNET_LOG_ERROR, "%s: EBLOB: blob-del-range: can't (re-)allocate memory, "
					"new size: %" PRIu64 "", cur_id, p->keys_size);
			goto err_out_exit;
		}
	}

	memcpy(&p->keys[p->keys_cnt], req, sizeof(struct eblob_range_request));
	dnet_dump_id_len_raw(p->keys[p->keys_cnt].record_key, len, cur_id);
	dnet_backend_log(p->blog, DNET_LOG_DEBUG, "%s: count: %llu", cur_id, (unsigned long long)(p->keys_cnt));
	p->keys_cnt++;

	if (!err)
		req->current_pos++;
err_out_exit:
	return err;
}

static int blob_read_range(struct eblob_backend_config *c, dnet_net_state *state, struct dnet_cmd *cmd, void *data)
{
	struct eblob_read_range_priv p;
	auto io = static_cast<dnet_io_attr *>(data);
	auto b = static_cast<eblob_backend *>(c->eblob);
	struct eblob_range_request req;
	uint64_t i, start_from = 0;
	int err;

	memset(&p, 0, sizeof(p));

	p.cmd = cmd;
	p.state = state;
	p.keys = NULL;
	p.keys_size= 0;
	p.keys_cnt = 0;
	p.flags = io->flags;
	p.blog = c->blog;

	dnet_convert_io_attr(io);

	memset(&req, 0, sizeof(req));

	memcpy(req.start, io->id, EBLOB_ID_SIZE);
	memcpy(req.end, io->parent, EBLOB_ID_SIZE);
	req.requested_offset = io->offset;
	req.requested_size = io->size;
	req.requested_limit_start = 0;
	req.requested_limit_num = ~0ULL;

	req.callback = blob_range_callback;
	req.back = b;
	req.priv = &p;

	err = eblob_read_range(&req);
	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "%s: EBLOB: blob-read-range: %d: %s",
			dnet_dump_id_str(io->id), err, strerror(-err));
		goto err_out_exit;
	}

	if ((cmd->cmd == DNET_CMD_READ_RANGE) && (cmd->flags & DNET_ATTR_SORT)) {
		dnet_backend_log(c->blog, DNET_LOG_DEBUG, "Sorting keys before sending");
		qsort(p.keys, p.keys_cnt, sizeof(struct eblob_range_request), &blob_cmp_range_request);
	}

	if (cmd->cmd == DNET_CMD_READ_RANGE) {
		start_from = io->start;
	}

	for (i = start_from; i < p.keys_cnt; ++i) {
		switch(cmd->cmd) {
			case DNET_CMD_READ_RANGE:
				if ((io->num > 0) && (i >= (io->num + start_from)))
					break;
				dnet_backend_log(c->blog, DNET_LOG_DEBUG, "%s: EBLOB: blob-read-range: READ",
						dnet_dump_id_str(p.keys[i].record_key));
				err = blob_read_range_callback(&p.keys[i]);
				break;
			case DNET_CMD_DEL_RANGE:
				dnet_backend_log(c->blog, DNET_LOG_DEBUG, "%s: EBLOB: blob-read-range: DEL",
						dnet_dump_id_str(p.keys[i].record_key));
				err = blob_del_range_callback(c, &p.keys[i]);
				break;
		}

		if (err) {
			dnet_backend_log(c->blog, DNET_LOG_DEBUG, "%s: EBLOB: blob-read-range: err: %d",
					dnet_dump_id_str(p.keys[i].record_key), err);
			goto err_out_exit;
		}
	}

	if (req.current_pos) {
		struct dnet_io_attr r;

		memcpy(&r, io, sizeof(struct dnet_io_attr));
		r.num = req.current_pos - start_from;
		r.offset = r.size = 0;

		err = dnet_send_read_data(state, cmd, &r, NULL, -1, 0, 0);
	}

err_out_exit:
	if (p.keys)
		free(p.keys);

	return err;
}

static int blob_del(struct eblob_backend_config *c, struct dnet_cmd *cmd)
{
	int err;

	auto key = convert_id(cmd->id.id);

	err = eblob_remove(c->eblob, &key);
	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "%s: EBLOB: blob-del: REMOVE: %d: %s",
			dnet_dump_id_str(cmd->id.id), err, strerror(-err));
	}

	return err;
}

static int blob_file_info(struct eblob_backend_config *c, dnet_net_state *state, struct dnet_cmd *cmd)
{
	struct eblob_backend *b = c->eblob;
	struct eblob_write_control wc;
	struct dnet_ext_list elist;
	static const size_t ehdr_size = sizeof(struct dnet_ext_list_hdr);
	uint64_t offset, size;
	int fd, err;

	dnet_ext_list_init(&elist);

	auto key = convert_id(cmd->id.id);
	err = blob_lookup(b, &key, &wc);
	if (err < 0) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "%s: EBLOB: blob-file-info: info-read: %d: %s.",
				dnet_dump_id(&cmd->id), err, strerror(-err));
		goto err_out_exit;
	}

	/* Existing entry */
	offset = wc.data_offset;
	size = wc.total_data_size;
	fd = wc.data_fd;

	/* Existing new-format entry */
	if ((wc.flags & BLOB_DISK_CTL_EXTHDR) != 0) {
		struct dnet_ext_list_hdr ehdr;

		/* Sanity */
		if (size < ehdr_size) {
			err = -ERANGE;
			goto err_out_exit;
		}

		err = dnet_ext_hdr_read(&ehdr, fd, offset);
		if (err != 0)
			goto err_out_exit;
		dnet_ext_hdr_to_list(&ehdr, &elist);

		/* Take into an account extended header's len */
		size -= ehdr_size;
		offset += ehdr_size;

		if (ehdr.index_size != 0) {
			uint64_t record_offset = 0;
			err = blob_read_struct_default(c, key, wc, ehdr, size, offset, record_offset);
			if (err) {
				goto err_out_exit;
			}
		}
	}

	if (size == 0) {
		err = -ENOENT;
		dnet_backend_log(c->blog, DNET_LOG_INFO, "%s: EBLOB: blob-file-info: info-read: ZERO-SIZE-FILE.",
				dnet_dump_id(&cmd->id));
		goto err_out_exit;
	}

	err = dnet_send_file_info_ts(state, cmd, fd, offset, size, &elist.timestamp, wc.flags);

err_out_exit:
	dnet_ext_list_destroy(&elist);
	return err;
}

static int eblob_backend_checksum(struct dnet_node *n, void *priv, struct dnet_id *id, void *csum, int *csize) {
	auto c = static_cast<eblob_backend_config *>(priv);
	auto b = static_cast<eblob_backend *>(c->eblob);
	struct eblob_write_control wc;
	static const size_t ehdr_size = sizeof(struct dnet_ext_list_hdr);
	int err;

	auto key = convert_id(id->id);
	err = blob_lookup(b, &key, &wc);
	if (err < 0) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "%s: EBLOB: blob-checksum: read: %d: %s.",
							dnet_dump_id_str(id->id), err, strerror(-err));
		goto err_out_exit;
	}
	err = 0;

	if (wc.flags & BLOB_DISK_CTL_EXTHDR) {
		/* Sanity */
		if (wc.total_data_size < ehdr_size) {
			err = -EINVAL;
			goto err_out_exit;
		}
		wc.data_offset += ehdr_size;
		wc.total_data_size -= ehdr_size;
	}

	if (wc.total_data_size == 0)
		memset(csum, 0, *csize);
	else
		err = dnet_checksum_fd(n, wc.data_fd, wc.data_offset,
				wc.total_data_size, csum, *csize);

err_out_exit:
	return err;
}

static int eblob_backend_lookup(struct dnet_node *n, void *priv, struct dnet_io_local *io)
{
	auto c = static_cast<eblob_backend_config *>(priv);
	auto b = static_cast<eblob_backend *>(c->eblob);
	struct dnet_ext_list_hdr ehdr;
	struct dnet_ext_list elist;
	struct eblob_write_control wc;
	memset(&wc, 0, sizeof(wc));
	wc.data_fd = -1;
	uint64_t size, offset;
	int err;

	(void) n;
	auto key = convert_id(io->key);

	dnet_ext_list_init(&elist);

	err = blob_lookup(b, &key, &wc);
	if (err < 0) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "%s: EBLOB: blob-backend-lookup: LOOKUP: %d: %s",
			 dnet_dump_id_str(io->key), err, strerror(-err));
		goto err_out_exit;
	}

	io->record_flags = wc.flags;
	io->fd = wc.data_fd;

	size = wc.total_data_size;
	offset = wc.data_offset;

	if (!(wc.flags & BLOB_DISK_CTL_EXTHDR)) {
		err = 0;
		goto err_out_set_sizes;
	}

	/* Sanity */
	if (wc.total_data_size < sizeof(struct dnet_ext_list_hdr)) {
		err = -ERANGE;
		goto err_out_set_sizes;
	}

	err = dnet_ext_hdr_read(&ehdr, wc.data_fd, wc.data_offset);
	if (err != 0)
		goto err_out_set_sizes;

	dnet_ext_hdr_to_list(&ehdr, &elist);

	io->timestamp = elist.timestamp;
	io->user_flags = elist.flags;

	size -= sizeof(struct dnet_ext_list_hdr);
	offset += sizeof(struct dnet_ext_list_hdr);

	err = 0;

err_out_set_sizes:
	io->total_size = size;
	io->fd_offset = offset;

err_out_exit:
	dnet_ext_list_destroy(&elist);
	return err;
}

static int blob_defrag_status(void *priv)
{
	auto c = static_cast<eblob_backend_config *>(priv);

	return eblob_defrag_status(c->eblob);
}

static int blob_defrag_start(void *priv, enum dnet_backend_defrag_level level)
{
	auto c = static_cast<eblob_backend_config *>(priv);
	enum eblob_defrag_state defrag_level;
	switch (level) {
		case DNET_BACKEND_DEFRAG_FULL:
			defrag_level = EBLOB_DEFRAG_STATE_DATA_SORT;
			break;
		case DNET_BACKEND_DEFRAG_COMPACT:
			defrag_level = EBLOB_DEFRAG_STATE_DATA_COMPACT;
			break;
		default:
			dnet_backend_log(c->blog, DNET_LOG_ERROR, "DEFRAG: unknown defragmentation level: %d", (int)level);
			return -ENOTSUP;
	}

	int err = eblob_start_defrag_level(c->eblob, defrag_level);

	dnet_backend_log(c->blog, DNET_LOG_INFO, "DEFRAG: defragmentation request: status: %d", err);

	return err;
}

static int blob_defrag_stop(void *priv)
{
	auto c = static_cast<eblob_backend_config *>(priv);

	return eblob_stop_defrag(c->eblob);
}

static int blob_send_reply(dnet_net_state *state, struct dnet_cmd *cmd, struct dnet_iterator_response *re, int more)
{
	int err;

	dnet_convert_iterator_response(re);
	err = dnet_send_reply_threshold(state, cmd, re, sizeof(struct dnet_iterator_response), more);

	/* we have to convert response back, since it can be reused, for example like error response */
	dnet_convert_iterator_response(re);
	return err;
}

static int blob_send(struct eblob_backend_config *cfg, dnet_net_state *state, struct dnet_cmd *cmd, void *data)
{
	auto b = static_cast<eblob_backend *>(cfg->eblob);
	auto req = static_cast<dnet_server_send_request *>(data);
	struct dnet_raw_id *ids;
	struct dnet_iterator_response re;
	struct dnet_server_send_ctl *ctl;
	int *groups;
	int i, err;

	struct dnet_ext_list elist;
	static const size_t ehdr_size = sizeof(struct dnet_ext_list_hdr);
	struct eblob_key key;
	struct eblob_write_control wc;
	uint64_t data_offset, record_offset;

	dnet_ext_list_init(&elist);


	/* structure has been already checked and has been proved to be correct no need to perform sanity checks */
	dnet_convert_server_send_request(req);

	ids = (struct dnet_raw_id *)(req + 1);
	groups = (int *)(ids + req->id_num);

	memset(&re, 0, sizeof(struct dnet_iterator_response));
	re.total_keys = req->id_num;

	/*
	 * Set NEED_ACK bit to signal server-send controller that we want
	 * to send final ACK when controller will be destroyed, which in turn
	 * will happen after all WRITE commands are completed.
	 *
	 * Command will be copied internally in @dnet_server_send_alloc(),
	 * thus it is safe to clear that bit afterward.
	 */
	cmd->flags |= DNET_FLAGS_NEED_ACK;

	ctl = dnet_server_send_alloc(state, cmd, req->iflags, groups, req->group_num);
	if (!ctl) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	/*
	 * Deliberately clear NEED_ACK bit
	 * This function will iterate over provided ids,
	 * read them from the blob and queue WRITE command to remote groups.
	 * When single WRITE command completes, it will send response back to client.
	 *
	 * If we send ACK in the middle, it will force client to stop accepting further responses.
	 *
	 * If there will be an error, it will be sent to client too.
	 * If there is an error with command processing (like fail to allocate memory),
	 * iteration will stop and error will be returned from this function to the higher layer,
	 * which in turn will force ACK message to client with error code.
	 */
	cmd->flags &= ~DNET_FLAGS_NEED_ACK;



	for (i = 0; i < req->id_num; ++i) {
		convert_id(ids[i], key);

		err = blob_lookup(b, &key, &wc);
		if (err < 0) {
			dnet_backend_log(cfg->blog, DNET_LOG_ERROR, "%s: EBLOB: blob_send: lookup: %d: %s",
					 dnet_dump_id_str(key.id), err, strerror(-err));
			goto err_out_send_fail_reply;
		}

		re.key = ids[i];
		re.flags = wc.flags; // these flags correspond to DNET_RECORD_FLAGS_*
		re.status = 0;
		re.iterated_keys = i;
		re.size = wc.total_data_size;
		// set iterator response id to differentiate various commands
		// client can use cmd->backend_id from reply though
		re.id = cmd->backend_id;

		data_offset = wc.data_offset;
		record_offset = 0;

		if ((wc.flags & BLOB_DISK_CTL_EXTHDR) != 0) {
			struct dnet_ext_list_hdr ehdr;

			/* Sanity */
			if (re.size < ehdr_size) {
				err = -ERANGE;
				goto err_out_send_fail_reply;
			}

			err = dnet_ext_hdr_read(&ehdr, wc.data_fd, wc.data_offset);
			if (err != 0)
				goto err_out_send_fail_reply;

			dnet_ext_hdr_to_list(&ehdr, &elist);

			re.timestamp = elist.timestamp;
			re.user_flags = elist.flags;

			/* Take into an account extended header's len */
			re.size -= sizeof(struct dnet_ext_list_hdr);
			data_offset += sizeof(struct dnet_ext_list_hdr);
			record_offset += sizeof(struct dnet_ext_list_hdr);
		}

		wc.offset = record_offset;
		wc.size = re.size;
		err = eblob_verify_checksum(b, &key, &wc);
		if (err)
			goto err_out_send_fail_reply;

		err = dnet_server_send_write(ctl, &re, sizeof(struct dnet_iterator_response), wc.data_fd, data_offset);
		if (err)
			goto err_out_send_fail_reply;

		continue;

err_out_send_fail_reply:
		re.status = err;
		err = blob_send_reply(state, cmd, &re, 1);

		// server has failed to send a reply to client, likely because of lack of memory
		// we can not proceed with this request anymore, so its better to exit earlier
		if (err)
			goto err_out_put;
	}

	err = 0;

err_out_put:
	dnet_server_send_put(ctl);
err_out_exit:
	return err;
}

static int eblob_backend_command_handler(void *state, void *priv, struct dnet_cmd *cmd, void *data)
{
	FORMATTED(HANDY_TIMER_SCOPE, ("eblob_backend.cmd.%s", dnet_cmd_string(cmd->cmd)));

	auto st = static_cast<dnet_net_state *>(state);

	int err;
	auto c = static_cast<eblob_backend_config *>(priv);

	switch (cmd->cmd) {
		case DNET_CMD_LOOKUP:
			err = blob_file_info(c, st, cmd);
			break;
		case DNET_CMD_WRITE:
			err = blob_write(c, st, cmd, data);
			break;
		case DNET_CMD_READ:
			err = blob_read(c, st, cmd, data, 1);
			break;
		case DNET_CMD_READ_RANGE:
		case DNET_CMD_DEL_RANGE:
			err = blob_read_range(c, st, cmd, data);
			break;
		case DNET_CMD_DEL:
			err = blob_del(c, cmd);
			break;
		case DNET_CMD_SEND:
			err = blob_send(c, st, cmd, data);
			break;
		case DNET_CMD_LOOKUP_STRUCT:
			err = blob_lookup_struct(c, st, cmd, data);
			break;
		case DNET_CMD_WRITE_STRUCT:
			err = blob_write_struct(c, st, cmd, data);
			break;
		case DNET_CMD_READ_STRUCT:
			err = blob_read_struct(c, st, cmd, data);
			break;
		default:
			err = -ENOTSUP;
			break;
	}

	return err;
}

static int dnet_blob_set_sync(struct dnet_config_backend *b,
                              const char *, const char *value)
{
	auto c = static_cast<eblob_backend_config *>(b->data);

	c->data.sync = atoi(value);
	return 0;
}

static int dnet_blob_set_data(struct dnet_config_backend *b,
                              const char *, const char *file)
{
	auto c = static_cast<eblob_backend_config *>(b->data);
	int err;

	err = backend_storage_size(b, file);
	if (err) {
		char root[strlen(file)+1], *ptr;

		snprintf(root, sizeof(root), "%s", file);
		ptr = strrchr(root, '/');
		if (ptr) {
			*ptr = '\0';
			err = backend_storage_size(b, root);
		}

		if (err)
			return err;
	}

	free(c->data.file);
	c->data.file = strdup(file);
	if (!c->data.file)
		return -ENOMEM;

	return 0;
}

static int dnet_blob_set_datasort_dir(struct dnet_config_backend *b,
				      const char *, const char *dir)
{
	auto c = static_cast<eblob_backend_config *>(b->data);
	struct stat st;
	int err;

	err = stat(dir, &st);
	if (err == -1)
		return -errno;

	if (!S_ISDIR(st.st_mode))
		return -ENOTDIR;

	free(c->data.chunks_dir);
	c->data.chunks_dir = strdup(dir);
	if (!c->data.chunks_dir)
		return -ENOMEM;

	return 0;
}

static int dnet_blob_set_blob_size(struct dnet_config_backend *b,
                                   const char *key, const char *value)
{
	auto c = static_cast<eblob_backend_config *>(b->data);
	uint64_t val = strtoul(value, NULL, 0);

	if (strchr(value, 'T') || strchr(value, 't'))
		val *= 1024*1024*1024*1024ULL;
	else if (strchr(value, 'G') || strchr(value, 'g'))
		val *= 1024*1024*1024ULL;
	else if (strchr(value, 'M') || strchr(value, 'm'))
		val *= 1024*1024;
	else if (strchr(value, 'K') || strchr(value, 'k'))
		val *= 1024;

	if (!strcmp(key, "blob_size"))
		c->data.blob_size = val;
	else if (!strcmp(key, "blob_size_limit"))
		c->data.blob_size_limit = val;

	return 0;
}

static int dnet_blob_set_index_block_size(struct dnet_config_backend *b,
                                          const char *, const char *value)
{
	auto c = static_cast<eblob_backend_config *>(b->data);

	c->data.index_block_size = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_set_index_block_bloom_length(struct dnet_config_backend *b,
                                                  const char *, const char *value)
{
	auto c = static_cast<eblob_backend_config *>(b->data);

	c->data.index_block_bloom_length = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_set_periodic_timeout(struct dnet_config_backend *b,
                                          const char *, const char *value) {
	auto c = static_cast<eblob_backend_config *>(b->data);

	c->data.periodic_timeout = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_set_records_in_blob(struct dnet_config_backend *b,
                                         const char *, const char *value)
{
	auto c = static_cast<eblob_backend_config *>(b->data);
	uint64_t val = strtoul(value, NULL, 0);

	c->data.records_in_blob = val;
	return 0;
}

static int dnet_blob_set_defrag_timeout(struct dnet_config_backend *b,
                                        const char *, const char *value)
{
	auto c = static_cast<eblob_backend_config *>(b->data);

	c->data.defrag_timeout = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_set_defrag_time(struct dnet_config_backend *b,
                                     const char *, const char *value)
{
	auto c = static_cast<eblob_backend_config *>(b->data);

	c->data.defrag_time = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_set_defrag_splay(struct dnet_config_backend *b,
                                      const char *, const char *value)
{
	auto c = static_cast<eblob_backend_config *>(b->data);

	c->data.defrag_splay = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_set_defrag_percentage(struct dnet_config_backend *b,
                                           const char *, const char *value)
{
	auto c = static_cast<eblob_backend_config *>(b->data);

	c->data.defrag_percentage = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_set_blob_flags(struct dnet_config_backend *b,
                                    const char *, const char *value)
{
	auto c = static_cast<eblob_backend_config *>(b->data);

	c->data.blob_flags = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_set_backend_id(struct dnet_config_backend *b,
                                    const char *, const char *value) {
	auto c = static_cast<eblob_backend_config *>(b->data);

	c->data.stat_id = strtoul(value, NULL, 0);
	return 0;
}


uint64_t eblob_backend_total_elements(void *priv) {
	auto r = static_cast<eblob_backend_config *>(priv);
	return eblob_total_elements(r->eblob);
}

int eblob_backend_storage_stat_json(void *priv, char **json_stat, size_t *size)
{
	int err;
	auto r = static_cast<eblob_backend_config *>(priv);

	err = eblob_stat_json_get(r->eblob, json_stat, size);
	if (err) {
		return err;
	}

	return 0;
}

static void eblob_backend_cleanup(void *priv)
{
	auto c = static_cast<eblob_backend_config *>(priv);

	eblob_cleanup(c->eblob);

	pthread_mutex_destroy(&c->last_read_lock);
}

static int dnet_eblob_iterator(struct dnet_iterator_ctl *ictl, struct dnet_iterator_request *ireq,
		struct dnet_iterator_range *irange)
{
	std::vector<eblob_index_block> range;
	auto c = static_cast<eblob_backend_config *>(ictl->iterate_private);
	auto b = static_cast<eblob_backend *>(c->eblob);
	int err;
	const int no_meta = ireq->flags & DNET_IFLAGS_NO_META && !(ireq->flags & (DNET_IFLAGS_TS_RANGE | DNET_IFLAGS_DATA));

	/* Init iterator config */
	struct eblob_iterate_control eictl;
	memset(&eictl, 0, sizeof(eictl));
	eictl.priv = ictl;
	eictl.b = b;
	eictl.log = c->data.log;
	eictl.flags = EBLOB_ITERATE_FLAGS_ALL | EBLOB_ITERATE_FLAGS_READONLY;
	eictl.iterator_cb.iterator = no_meta ? blob_iterate_callback_without_meta : blob_iterate_callback_with_meta;

	if (ireq->range_num) {
		try {
			range.resize(ireq->range_num);
		} catch (std::exception &e) {
			err = -ENOMEM;
			goto err_out_exit;
		}

		for (uint64_t i = 0; i < ireq->range_num; ++i) {
			memcpy(range[i].start_key.id, irange[i].key_begin.id, DNET_ID_SIZE);
			memcpy(range[i].end_key.id, irange[i].key_end.id, DNET_ID_SIZE);
		}

		eictl.range = range.data();
		eictl.range_num = range.size();
	}

	err = eblob_iterate(b, &eictl);

err_out_exit:
	return err;
}

static dnet_log_level convert_to_dnet_log(int level)
{
	switch (level) {
	default:
	case EBLOB_LOG_DATA:
	case EBLOB_LOG_ERROR:
		return DNET_LOG_ERROR;
	case EBLOB_LOG_INFO:
		return DNET_LOG_INFO;
	case EBLOB_LOG_NOTICE:
		return DNET_LOG_NOTICE;
	case EBLOB_LOG_DEBUG:
	case EBLOB_LOG_SPAM:
		return DNET_LOG_DEBUG;
	}
}

static eblob_log_levels convert_to_eblob_log(dnet_log_level level)
{
	switch (level) {
	case DNET_LOG_DEBUG:
		return EBLOB_LOG_DEBUG;
	case DNET_LOG_NOTICE:
		return EBLOB_LOG_NOTICE;
	case DNET_LOG_INFO:
		return EBLOB_LOG_INFO;
	case DNET_LOG_WARNING:
	case DNET_LOG_ERROR:
	default:
		return EBLOB_LOG_ERROR;
	}
}

static void dnet_eblob_log_implemenation(void *priv, int level, const char *msg)
{
	auto log = static_cast<dnet_logger *>(priv);

	dnet_log_level dnet_level = convert_to_dnet_log(level);

	dnet_backend_log(log, dnet_level, "%s", msg);
}

static int dnet_blob_config_init(struct dnet_config_backend *b)
{
	auto c = static_cast<eblob_backend_config *>(b->data);
	struct dnet_vm_stat st;
	int err = 0;

	c->blog = b->log;

	if (!c->data.file) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "blob: no data file present. Exiting.");
		err = -EINVAL;
		goto err_out_exit;
	}

	c->log.log_private = b->log;
	c->log.log_level = convert_to_eblob_log(dnet_log_get_verbosity(b->log));
	c->log.log = dnet_eblob_log_implemenation;

	c->data.log = &c->log;

	err = pthread_mutex_init(&c->last_read_lock, NULL);
	if (err) {
		err = -err;
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "blob: could not create last-read lock: %d.", err);
		goto err_out_exit;
	}

	c->eblob = eblob_init(&c->data);
	if (!c->eblob) {
		err = errno;
		if (err == 0)
			err = -EINVAL;
		goto err_out_last_read_lock_destroy;
	}

	memset(&st, 0, sizeof(struct dnet_vm_stat));
	err = dnet_get_vm_stat(c->blog, &st);
	if (err)
		goto err_out_last_read_lock_destroy;

	eblob_set_trace_id_function(&get_trace_id);

	c->vm_total = st.vm_total * st.vm_total * 1024 * 1024;

	b->cb.storage_stat_json = eblob_backend_storage_stat_json;
	b->cb.total_elements = eblob_backend_total_elements;

	b->cb.command_private = c;
	b->cb.command_handler = eblob_backend_command_handler;
	b->cb.backend_cleanup = eblob_backend_cleanup;
	b->cb.checksum = eblob_backend_checksum;
	b->cb.lookup = eblob_backend_lookup;

	b->cb.iterator = dnet_eblob_iterator;

	b->cb.defrag_start = blob_defrag_start;
	b->cb.defrag_stop = blob_defrag_stop;
	b->cb.defrag_status = blob_defrag_status;

	return 0;

err_out_last_read_lock_destroy:
	pthread_mutex_destroy(&c->last_read_lock);
err_out_exit:
	return err;
}


/*
 * dnet_blob_config_cleanup() stops and cleans up eblob if it is needed and
 * frees memory allocated by config.
 * There are 3 stages of backend:
 *   1. config parsing
 *   2. eblob initialization
 *   3. cleaning up eblob and config
 * In common case backend goes through all 3 steps.
 * But there is specific case (backends_stat_provider.cpp: @fill_disabled_backend_config()):
 *   monitor subsystem for disabled backends makes only 1 and 3 stages and skips stage 2.
 *   So when monitor makes stage 3, it has uninitialized eblob and
 *   should cleanups only config data.
 */
static void dnet_blob_config_cleanup(struct dnet_config_backend *b)
{
	auto c = static_cast<eblob_backend_config *>(b->data);

	/* do not cleans up eblob if it hasn't been initialized */
	if (c->eblob)
		eblob_backend_cleanup(c);

	free(c->data.file);
	free(c->data.chunks_dir);
}

static struct dnet_config_entry dnet_cfg_entries_blobsystem[] = {
	{"sync", dnet_blob_set_sync},
	{"data", dnet_blob_set_data},
	{"datasort_dir", dnet_blob_set_datasort_dir},
	{"blob_flags", dnet_blob_set_blob_flags},
	{"blob_size", dnet_blob_set_blob_size},
	{"records_in_blob", dnet_blob_set_records_in_blob},
	{"defrag_timeout", dnet_blob_set_defrag_timeout},
	{"defrag_time", dnet_blob_set_defrag_time},
	{"defrag_splay", dnet_blob_set_defrag_splay},
	{"defrag_percentage", dnet_blob_set_defrag_percentage},
	{"blob_size_limit", dnet_blob_set_blob_size},
	{"index_block_size", dnet_blob_set_index_block_size},
	{"index_block_bloom_length", dnet_blob_set_index_block_bloom_length},
	{"periodic_timeout", dnet_blob_set_periodic_timeout},
	{"backend_id", dnet_blob_set_backend_id}
};

static auto dnet_eblob_backend = [] () {
	dnet_config_backend ret;
	memset(&ret, 0, sizeof(ret));
	strcpy(ret.name, "blob");
	ret.ent = dnet_cfg_entries_blobsystem;
	ret.num = ARRAY_SIZE(dnet_cfg_entries_blobsystem);
	ret.size = sizeof(struct eblob_backend_config);
	ret.init = dnet_blob_config_init;
	ret.cleanup = dnet_blob_config_cleanup;
	ret.to_json = dnet_blob_config_to_json;
	return ret;
} ();

struct dnet_config_backend *dnet_eblob_backend_info() {
	return &dnet_eblob_backend;
}

int dnet_blob_config_to_json(struct dnet_config_backend *b, char **json_stat, size_t *size) {
	struct eblob_backend_config *c = static_cast<struct eblob_backend_config *>(b->data);
	int err = 0;

	rapidjson::Document doc;
	doc.SetObject();
	rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();

	doc.AddMember("blob_flags", c->data.blob_flags, allocator);
	doc.AddMember("sync", c->data.sync, allocator);
	if (c->data.file)
		doc.AddMember("data", c->data.file, allocator);
	else
		doc.AddMember("data", "", allocator);
	doc.AddMember("blob_size", c->data.blob_size, allocator);
	doc.AddMember("records_in_blob", c->data.records_in_blob, allocator);
	doc.AddMember("defrag_percentage", c->data.defrag_percentage, allocator);
	doc.AddMember("defrag_timeout", c->data.defrag_timeout, allocator);
	doc.AddMember("index_block_size", c->data.index_block_size, allocator);
	doc.AddMember("index_block_bloom_length", c->data.index_block_bloom_length, allocator);
	doc.AddMember("blob_size_limit", c->data.blob_size_limit, allocator);
	doc.AddMember("defrag_time", c->data.defrag_time, allocator);
	doc.AddMember("defrag_splay", c->data.defrag_splay, allocator);

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	doc.Accept(writer);

	std::string json = buffer.GetString();

	*json_stat = (char *)malloc(json.length() + 1);
	if (*json_stat) {
		*size = json.length();
		snprintf(*json_stat, *size + 1, "%s", json.c_str());
	} else {
		err = -ENOMEM;
		goto err_out_reset;
	}

	return 0;

err_out_reset:
	*size = 0;
	*json_stat = NULL;
	return err;
}

std::string blob_read_stored_index(eblob_backend_config *c,
                                   const eblob_key &key,
                                   const eblob_write_control &wc) {
	if ((wc.flags & BLOB_DISK_CTL_EXTHDR) == 0) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR,
		                 "EBLOB: blob_read_stored_index: FAILED: key doesn't have exthdr");
		return "";
	}

	static const size_t ehdr_size = sizeof(struct dnet_ext_list_hdr);

	if (wc.total_data_size < ehdr_size) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "EBLOB: blob_read_stored_index: FAILED: "
		                 "total_data_size is too small: %" PRIu64 " < %" PRIu64,
		                 wc.total_data_size, ehdr_size);
		return "";
	}

	struct dnet_ext_list_hdr ehdr;
	// TODO: we should verify checksums before reading
	int err = dnet_ext_hdr_read(&ehdr, wc.data_fd, wc.data_offset);
	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR,
		                 "EBLOB: blob_read_stored_index: dnet_ext_hdr_read: FAILED: %s: %d",
		                 strerror(-err), err);
		return "";
	}

	if (ehdr.index_size == 0)
		return "";

	if (ehdr.index_size + ehdr_size > wc.total_data_size) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "EBLOB: blob_read_stored_index: FAILED: "
		                 "index_size (%" PRIu64 ") + ehdr_size: (%" PRIu64 ") > total_data_size (%" PRIu64 ")",
		                 ehdr.index_size, ehdr_size, wc.total_data_size);
		return "";
	}

	const uint64_t index_offset = wc.data_offset + ehdr_size;

	std::string ret(ehdr.index_size, '\0');

	// TODO: we should verify checksums before reading
	err = dnet_read_ll(wc.data_fd, const_cast<char*>(ret.data()), ret.size(), index_offset);
	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "EBLOB: blob_read_stored_index: failed to read: %s: %d",
		                 strerror(-err), err);
		return "";
	}

	dnet_backend_log(c->blog, DNET_LOG_DEBUG, "EBLOB: blob_read_stored_index: succeeded: %s",
	                 ret.c_str());

	return ret;
}

static int blob_lookup(struct eblob_backend *b, struct eblob_key &key, struct eblob_write_control &wc) {
	int err = eblob_read_return(b, &key, EBLOB_READ_NOCSUM, &wc);
	/* Uncommitted records can be read, so fail lookup with ENOENT */
	if (err == 0 && wc.flags & BLOB_DISK_CTL_UNCOMMITTED)
		err = -ENOENT;
	return err;
}

int blob_lookup_struct(struct eblob_backend_config *c, struct dnet_net_state *state, struct dnet_cmd *cmd, void *data) {
	int err = 0;
	struct eblob_backend *b = c->eblob;

	auto key = convert_id(cmd->id.id);

	struct eblob_write_control wc;
	err = blob_lookup(b, key, wc);
	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "%s: EBLOB: blob_lookup_struct: FAILED: %s: %d",
		                 dnet_dump_id(&cmd->id), strerror(-err), err);
		return err;
	}

	std::string stored_index = blob_read_stored_index(c, key, wc);

	ioremap::elliptics::data_buffer buffer(sizeof(struct dnet_write_struct_response) + stored_index.size());
	struct dnet_write_struct_response r;
	memset(&r, 0, sizeof(r));
	r.size = stored_index.size();

	buffer.write(r);
	buffer.write(stored_index.data(), stored_index.size());

	ioremap::elliptics::data_pointer data_p(std::move(buffer));

	err = dnet_send_reply(state, cmd, data_p.data(), data_p.size(), 0);

	return err;
}

static uint64_t blob_write_stuct_process_subfields(
		struct eblob_backend_config *c,
		const rapidjson::Value &request_value,
		rapidjson::Value &stored_value,
		rapidjson::Document::AllocatorType &allocator,
		std::vector<std::string> &datas,
		std::vector<struct eblob_iovec> &iov) {
	dnet_backend_log(c->blog, EBLOB_LOG_ERROR, "blob: %s: start", __func__);
	uint64_t ret = 0;

	for (auto it = request_value.MemberBegin(); it != request_value.MemberEnd(); ++it) {
		const auto member_name = it->name.GetString();
		if (it->name.GetString() == std::string("__attributes__"))
			continue;
		dnet_backend_log(c->blog, EBLOB_LOG_ERROR, "blob: %s: found member: '%s'",
		                 __func__, member_name);

		if (stored_value.HasMember(member_name)) {
			dnet_backend_log(c->blog, EBLOB_LOG_ERROR, "blob: %s: stored_index already has member: '%s'",
			                 __func__, member_name);
		} else {
			dnet_backend_log(c->blog, EBLOB_LOG_ERROR, "blob: %s: stored_index doesn't have member: '%s'",
			                 __func__, member_name);

			uint64_t offset = 0, size = 0, capacity = 0;
			struct eblob_iovec data_iov;
			memset(&data_iov, 0, sizeof(data_iov));

			if (!stored_value.HasMember("__attributes__")) {
				stored_value.AddMember("__attributes__", allocator, rapidjson::Value().SetObject(), allocator);
			}
			auto &stored_attributes = stored_value["__attributes__"];
			if (stored_attributes.HasMember("capacity")) {
				offset = stored_attributes["offset"].GetUint64() + stored_attributes["size"].GetUint64();
			} else {
				if (stored_attributes.HasMember("offset")) {
					offset = stored_attributes["offset"].GetUint64();
				}
				if (stored_attributes.HasMember("size")) {
					offset += stored_attributes["size"].GetUint64();
				}
			}

			rapidjson::Value field_value(rapidjson::kObjectType);
			field_value.AddMember("__attributes__", allocator,
			                      rapidjson::Value().SetObject(), allocator);
			auto &field_attributes = field_value["__attributes__"];
			field_attributes.AddMember("offset", offset, allocator);

			if (it->value.IsString()) {
				dnet_backend_log(c->blog, EBLOB_LOG_ERROR, "blob: %s: request value '%s' is string",
				                 __func__, member_name);

				size = capacity = it->value.GetStringLength();
				datas.emplace_back(it->value.GetString(), size);
				data_iov.size = size;
				data_iov.offset = offset;
				// TODO: remove const_cast here
				data_iov.base = const_cast<char*>(datas.back().data());
			} else if (it->value.IsUint64()) {
				dnet_backend_log(c->blog, EBLOB_LOG_ERROR, "blob: %s: request value '%s' is uint64_t",
				                 __func__, member_name);

				size = capacity = datas[it->value.GetUint64()].size();
				data_iov.size = size;
				data_iov.offset = offset;
				// TODO: remove const_cast here
				data_iov.base = const_cast<char*>(datas[it->value.GetUint64()].data());
			} else if (it->value.IsObject()) {
				dnet_backend_log(c->blog, EBLOB_LOG_ERROR, "blob: %s: request value '%s' is object",
				                 __func__, member_name);

				uint64_t internal_offset = 0;
				auto subfields_count = it->value.MemberCount();
				if (it->value.HasMember("__attributes__")) {
					dnet_backend_log(c->blog, EBLOB_LOG_ERROR, "blob: %s: request value '%s' has '__attributes__'",
					                 __func__, member_name);
					--subfields_count;
					const auto &attributes = it->value["__attributes__"];
					if (attributes.HasMember("offset")) {
						internal_offset = attributes["offset"].GetUint64();
						size = internal_offset;
						data_iov.offset = internal_offset;
					}

					if (attributes.HasMember("capacity")) {
						capacity = attributes["capacity"].GetUint64();
					}

					if (subfields_count == 0 && attributes.HasMember("data")) {
						// if there is no subfields and
						// data is presented at __attributes__
						const auto &data = attributes["data"];
						if (data.IsString()) {
							size = data.GetStringLength();
							datas.emplace_back(data.GetString(), size);
							data_iov.size = size;
							data_iov.offset = offset;
							// TODO: remove const_cast here
							data_iov.base = const_cast<char*>(datas.back().data());
							size += internal_offset;
						} else if (data.IsUint64()) {
							size = datas[data.GetUint64()].size();
							data_iov.size = size;
							data_iov.offset = offset;
							// TODO: remove const_cast here
							data_iov.base = const_cast<char*>(datas[data.GetUint64()].data());
							size += internal_offset;
						}
					}
				}

				if (subfields_count > 0) {
					size = blob_write_stuct_process_subfields(c,
					                                          it->value,
					                                          field_value,
					                                          allocator,
					                                          datas,
					                                          iov);
				}

				capacity = std::max(size, capacity);
			}

			if (capacity > 0) {
				field_attributes.AddMember("capacity", capacity, allocator)
				                .AddMember("size", size, allocator);
			}

			stored_value.AddMember(member_name, allocator, field_value, allocator);

			if (!stored_attributes.HasMember("offset")) {
				stored_attributes.AddMember("offset", 0, allocator);
			}

			if (!stored_attributes.HasMember("size")) {
				stored_attributes.AddMember("size", capacity, allocator);
			} else {
				stored_attributes["size"] = stored_attributes["size"].GetUint64() + capacity;
			}

			if (data_iov.size > 0) {
				iov.push_back(data_iov);
			}

			ret += capacity;
		}
	}
	dnet_backend_log(c->blog, EBLOB_LOG_ERROR, "blob: %s: finish", __func__);

	return ret;
}

static int blob_write_struct_parse_request(struct eblob_backend_config *c,
                                           const struct dnet_io_attr *io,
                                           const std::string &request_index,
                                           std::string &stored_index,
                                           std::vector<std::string> &datas,
                                           std::vector<struct eblob_iovec> &iov) {
	int err = 0;

	dnet_backend_log(c->blog, DNET_LOG_ERROR, "blob: %s: blob_write_struct_parse_request: "
	                 "request_index: %s, stored_index: %s, datas.size(): %zu",
	                 dnet_dump_id_str(io->id), request_index.data(), stored_index.data(), datas.size());

	rapidjson::Document stored_doc;
	auto &allocator = stored_doc.GetAllocator();
	if (!stored_index.empty()) {
		stored_doc.Parse<0>(stored_index.data());
	} else {
		stored_doc.SetObject();
	}

	rapidjson::Document request_doc(&allocator);
	request_doc.Parse<0>(request_index.data());

	auto size = blob_write_stuct_process_subfields(c,
	                                               request_doc,
	                                               stored_doc,
	                                               allocator,
	                                               datas,
	                                               iov);

	stored_index = [&stored_doc] () {
		rapidjson::StringBuffer buffer;
		rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
		stored_doc.Accept(writer);

		return std::string(buffer.GetString(), buffer.Size());
	} ();

	dnet_backend_log(c->blog, DNET_LOG_ERROR, "blob: %s: process_data: size: %" PRIu64 " stored_json: %s, stored_json_size: %" PRIu64 ", iov.size(): %zu",
	                 dnet_dump_id_str(io->id), size, stored_index.c_str(), stored_index.size(), iov.size());
	return err;
}

int blob_write_struct(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd, void *data) {
	int err = 0;

	struct eblob_backend *b = c->eblob; // eblob instance

	struct eblob_write_control wc;
	memset(&wc, 0, sizeof(wc));
	wc.data_fd = -1;

	auto io = static_cast<struct dnet_io_attr *>(data); // io attributes
	data += sizeof(struct dnet_io_attr); // move pointer to the request

	uint64_t flags = BLOB_DISK_CTL_EXTHDR; // set that the record has ext header

	dnet_convert_io_attr(io);

	struct dnet_ext_list_hdr ehdr = [&io] {
		struct dnet_ext_list_hdr val;
		memset(&val, 0, sizeof(val));

		struct dnet_ext_list elist;
		dnet_ext_list_init(&elist);

		dnet_ext_io_to_list(io, &elist);

		dnet_ext_list_to_hdr(&elist, &val);

		dnet_ext_list_destroy(&elist);
		return val;
	}();

	if (io->flags & DNET_IO_FLAGS_NOCSUM)
		flags |= BLOB_DISK_CTL_NOCSUM;

	auto key = convert_id(io->id);

	/*
	 * get all entries from the request.
	 * The first one is index and others are data
	 */
	auto request = static_cast<dnet_write_struct_request *>(data);

	dnet_backend_log(c->blog, DNET_LOG_ERROR, "blob: %s: blob_write_struct: entries_count: %" PRIu64,
	                 dnet_dump_id_str(io->id), request->entries_count);

	/*
	 * Read index separately
	 */
	auto request_raw = reinterpret_cast<char*>(request->entries);
	auto index_entry = reinterpret_cast<const struct dnet_write_struct_request_entry *>(request_raw);

	const std::string request_index(index_entry->data, index_entry->size);
	request_raw += sizeof(*index_entry) + index_entry->size;

	dnet_backend_log(c->blog, DNET_LOG_ERROR, "blob: %s: blob_write_struct: index: %s",
	                 dnet_dump_id_str(io->id), request_index.data());

	/*
	 * Adds all entries to vector;
	 */
	std::vector<std::string> datas;
	datas.reserve(request->entries_count - 1);

	for (decltype(request->entries_count) i = 1; i < request->entries_count; ++i) {
		auto entry = reinterpret_cast<const struct dnet_write_struct_request_entry *>(request_raw);
		datas.emplace_back(entry->data, entry->size);
		request_raw += sizeof(*entry) + entry->size;
	}

	std::vector<struct eblob_iovec> iov(2);
	memset(&iov[0], 0, sizeof(iov[0])); // zero-fills iovec for ehdr
	memset(&iov[1], 0, sizeof(iov[1])); // zero-fills iovec for json index

	std::string stored_index("");

	err = blob_write_struct_parse_request(c, io, request_index, stored_index, datas, iov);

	ehdr.index_size = stored_index.size();
	iov[0].size = sizeof(struct dnet_ext_list_hdr);
	iov[0].base = &ehdr;

	iov[1].offset = iov[0].size;
	iov[1].size = stored_index.size();
	iov[1].base = const_cast<char*>(stored_index.data());

	const auto data_offset = iov[1].offset + iov[1].size;

	for (auto it = iov.begin() + 2; it != iov.end(); ++it) {
		it->offset += data_offset;
	}

	dnet_backend_log(c->blog, DNET_LOG_ERROR, "blob: %s: blob_write_struct: final index: %s, iov.size(): %zu",
	                 dnet_dump_id_str(io->id), stored_index.data(), iov.size());
	for (auto it = iov.begin() + 1; it != iov.end(); ++it) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "blob: %s: iov: size: %" PRIu64 ", offset: %" PRIu64 ". data: %s",
		                 dnet_dump_id_str(io->id), it->size, it->offset, (const char*)it->base);
	}

	err = eblob_writev_return(b, &key, iov.data(), iov.size(), flags, &wc);

	ioremap::elliptics::data_buffer buffer(sizeof(struct dnet_write_struct_response) + stored_index.size());
	struct dnet_write_struct_response r;
	memset(&r, 0, sizeof(r));
	r.size = stored_index.size();

	buffer.write(r);
	buffer.write(stored_index.data(), stored_index.size());

	ioremap::elliptics::data_pointer data_p(std::move(buffer));
	err = dnet_send_reply(state, cmd, data_p.data(), data_p.size(), 0);

	return err;
}

struct field_point{
	uint64_t offset;
	uint64_t size;
};

static int blob_read_struct_process_data(struct eblob_backend_config *c,
                                         const rapidjson::Value &value,
                                         rapidjson::Document::AllocatorType &allocator,
                                         rapidjson::Value &response_value,
                                         std::vector<struct field_point> &points);

static int blob_read_struct_process_field(struct eblob_backend_config *c,
                                          const rapidjson::Value &value,
                                          rapidjson::Document::AllocatorType &allocator,
                                          rapidjson::Value &response_value,
                                          std::vector<struct field_point> &points) {
	int err = 0;
	uint64_t offset = 0, size = 0, capacity = 0;

	std::tie(offset, size, capacity) = [&] {
		const auto &attributes = value["__attributes__"];
		return std::make_tuple(attributes["offset"].GetUint64(),
		                       attributes["size"].GetUint64(),
		                       attributes["capacity"].GetUint64());
	} ();

	response_value.AddMember("__attributes__", allocator, rapidjson::Value().SetObject(), allocator);

	auto &attributes = response_value["__attributes__"];
	attributes.AddMember("offset", offset, allocator)
	          .AddMember("size", size, allocator)
	          .AddMember("capacity", capacity, allocator);

	if (value.MemberCount() > 1) {
		// Value isn't leap, so it should be processed recursively
		err = blob_read_struct_process_data(c,
		                                    value,
		                                    allocator,
		                                    response_value,
		                                    points);
	} else {
		// Value is leap, provides its data in points
		attributes.AddMember("data", points.size(), allocator);
		points.push_back({offset, size});
	}

	return err;
}

static int blob_read_struct_process_data(struct eblob_backend_config *c,
                                         const rapidjson::Value &value,
                                         rapidjson::Document::AllocatorType &allocator,
                                         rapidjson::Value &response_value,
                                         std::vector<struct field_point> &points) {
	int err = 0;

	for (auto it = value.MemberBegin(), end = value.MemberEnd(); it != end; ++it) {
		if (it->name.GetString() == std::string("__attributes__"))
			continue;
		rapidjson::Value field_value(rapidjson::kObjectType);
		err = blob_read_struct_process_field(c,
		                                     it->value,
		                                     allocator,
		                                     field_value,
		                                     points);
		if (err) {
			dnet_backend_log(c->blog, DNET_LOG_ERROR,
			                 "EBLOB: blob_read_struct_process_data: FAILED: %d",
			                 err);
			break;
		}
		dnet_backend_log(c->blog, DNET_LOG_DEBUG,
		                 "EBLOB: blob_read_struct_process_data: adding '%s' element",
		                 it->name.GetString());
		response_value.AddMember(it->name.GetString(), allocator, field_value, allocator);
	}

	return err;
}

static int blob_read_struct_without_request_index(struct eblob_backend_config *c,
                                                  const rapidjson::Document &stored_doc,
                                                  rapidjson::Document::AllocatorType &allocator,
                                                  rapidjson::Document &response_doc,
                                                  std::vector<struct field_point> &points) {
	return blob_read_struct_process_data(c,
	                                     stored_doc,
	                                     allocator,
	                                     response_doc,
	                                     points);
}

static int blob_read_struct_process_data_with_request(struct eblob_backend_config *c,
                                                      const rapidjson::Value &stored_value,
                                                      const rapidjson::Value &request_value,
                                                      rapidjson::Document::AllocatorType &allocator,
                                                      rapidjson::Value &response_value,
                                                      std::vector<struct field_point> &points);

static int blob_read_struct_process_field_with_request(struct eblob_backend_config *c,
                                                       const rapidjson::Value &stored_value,
                                                       const rapidjson::Value &request_value,
                                                       rapidjson::Document::AllocatorType &allocator,
                                                       rapidjson::Value &response_value,
                                                       std::vector<struct field_point> &points) {
	int err = 0;
	auto request_member_count = request_value.MemberCount();
	if (request_value.HasMember("__attributes__"))
		--request_member_count;

	if (request_member_count) {
		if (stored_value.MemberCount() > 1) {
			err = blob_read_struct_process_data_with_request(c,
			                                                 stored_value,
			                                                 request_value,
			                                                 allocator,
			                                                 response_value,
			                                                 points);
		} else {
			for (auto it = request_value.MemberBegin(), end = request_value.MemberEnd(); it != end; ++it) {
				if (it->name.GetString() == std::string("__attributes__"))
					continue;

				rapidjson::Value field_attributes(rapidjson::kObjectType);
				field_attributes.AddMember("data", -ENOENT, allocator);

				rapidjson::Value field_value(rapidjson::kObjectType);
				field_value.AddMember("__attributes__", allocator, field_attributes, allocator);

				response_value.AddMember(it->name.GetString(), allocator, field_value, allocator);
			}
		}
	} else {
		if (stored_value.MemberCount() > 1) {
			err = blob_read_struct_process_data(c,
			                                    stored_value,
			                                    allocator,
			                                    response_value,
			                                    points);
		} else {
			auto get = [&request_value] (const char* field) -> uint64_t {
				if (request_value.HasMember("__attributes__")) {
					const auto &attributes = request_value["__attributes__"];
					if (attributes.HasMember(field)) {
						return attributes[field].GetUint64();
					}
				}
				return 0;
			};
			const auto &stored_attributes = stored_value["__attributes__"];
			auto request_offset = get("offset");
			auto stored_offset = stored_attributes["offset"].GetUint64();
			auto stored_size = stored_attributes["size"].GetUint64();
			auto request_size = get("size");
			request_size = request_size == 0 ? stored_size : request_size;

			rapidjson::Value field_attributes(rapidjson::kObjectType);
			field_attributes.AddMember("offset", stored_offset, allocator)
			                .AddMember("size", stored_size, allocator)
			                .AddMember("capacity", stored_attributes["capacity"].GetUint64(), allocator);

			if (request_offset >= stored_size) {
				field_attributes.AddMember("data", -E2BIG, allocator);
			} else {
				request_size = std::min(request_size, stored_size - request_offset);

				field_attributes.AddMember("data", points.size(), allocator);
				points.push_back({request_offset + stored_offset, request_size});
			}

			response_value.AddMember("__attributes__", allocator, field_attributes, allocator);
		}
	}

	return err;
}

static int blob_read_struct_process_data_with_request(struct eblob_backend_config *c,
                                                      const rapidjson::Value &stored_value,
                                                      const rapidjson::Value &request_value,
                                                      rapidjson::Document::AllocatorType &allocator,
                                                      rapidjson::Value &response_value,
                                                      std::vector<struct field_point> &points) {
	int err = 0;
	for (auto it = request_value.MemberBegin(), end = request_value.MemberEnd(); it != end; ++it) {
		rapidjson::Value field_value(rapidjson::kObjectType);

		if (stored_value.HasMember(it->name.GetString())) {
			err = blob_read_struct_process_field_with_request(c,
			                                                  stored_value[it->name.GetString()],
			                                                  it->value,
			                                                  allocator,
			                                                  field_value,
			                                                  points);
		} else {
			rapidjson::Value field_attributes(rapidjson::kObjectType);
			field_attributes.AddMember("data", -ENOENT, allocator);
			field_value.AddMember("__attributes__", allocator, field_attributes, allocator);
		}

		response_value.AddMember(it->name.GetString(), allocator, field_value, allocator);
	}

	return err;
}

static int blob_read_struct_with_request_index(struct eblob_backend_config *c,
                                               const rapidjson::Document &stored_doc,
                                               const rapidjson::Document &request_doc,
                                               rapidjson::Document::AllocatorType &allocator,
                                               rapidjson::Document &response_doc,
                                               std::vector<struct field_point> &points) {
	return blob_read_struct_process_data_with_request(c,
	                                                  stored_doc,
	                                                  request_doc,
	                                                  allocator,
	                                                  response_doc,
	                                                  points);
}

static int blob_read_struct_raw(struct eblob_backend_config *c,
                                const std::string &stored_index,
                                const std::string &request_index,
                                struct dnet_net_state *state,
                                struct dnet_cmd *cmd,
                                const struct eblob_write_control &wc,
                                struct dnet_io_attr *io) {
	int err = 0;
	dnet_backend_log(c->blog, DNET_LOG_DEBUG,
	                 "%s: EBLOB: blob_read_struct_raw: stored_index: '%s', request_index: '%s'",
	                 dnet_dump_id_str(io->id), stored_index.c_str(), request_index.c_str());

	if (stored_index.empty()) {
		return -EINVAL;
	}

	rapidjson::Document stored_doc;
	stored_doc.Parse<0>(stored_index.data());

	rapidjson::Document response_doc;
	response_doc.SetObject();
	auto &allocator = response_doc.GetAllocator();

	std::vector<struct field_point> points;

	if (!request_index.empty()) {
		rapidjson::Document request_doc;
		request_doc.Parse<0>(request_index.data());

		err = blob_read_struct_with_request_index(c,
		                                          stored_doc,
		                                          request_doc,
		                                          allocator,
		                                          response_doc,
		                                          points);
	} else {
		err = blob_read_struct_without_request_index(c,
		                                             stored_doc,
		                                             allocator,
		                                             response_doc,
		                                             points);
	}

	const std::string response_index = [&response_doc] () {
		rapidjson::StringBuffer buffer;
		rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
		response_doc.Accept(writer);

		return std::string(buffer.GetString(), buffer.Size());
	} ();

	dnet_backend_log(c->blog, DNET_LOG_DEBUG,
	                 "%s: EBLOB: blob_read_struct_raw: response_index: '%s', points: %zu",
	                 dnet_dump_id_str(io->id), response_index.c_str(), points.size());

	int i = 0;
	for (auto &p: points) {
		dnet_backend_log(c->blog, DNET_LOG_DEBUG,
		                 "%s: EBLOB: blob_read_struct_raw: point: %d: %" PRIu64 "/%" PRIu64,
		                 dnet_dump_id_str(io->id), i++, p.offset, p.size);
	}

	ioremap::elliptics::data_pointer data_p = [&response_index] () {
		ioremap::elliptics::data_buffer buffer(sizeof(struct dnet_read_struct_response) + response_index.size());
		struct dnet_read_struct_response r;
		memset(&r, 0, sizeof(r));
		r.size = response_index.size();

		buffer.write(r);
		buffer.write(response_index.data(), response_index.size());
		return std::move(buffer);
	} ();

	int more = points.empty() ? 0 : 1; // if points is empty we will send only index
	err = dnet_send_reply(state, cmd, data_p.data(), data_p.size(), more);
	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR,
		                 "%s: EBLOB: blob_read_struct_raw: failed to dnet_send_reply with index: %d",
		                 dnet_dump_id_str(io->id), err);
		return err;
	}

	cmd->flags |= DNET_FLAGS_MORE;
	auto offset = wc.data_offset + sizeof(struct dnet_ext_list_hdr) + stored_index.size();
	for (auto it = points.cbegin(), end = points.cend(); it != end; ++it) {
		io->size = it->size;
		static const auto hsize = sizeof(struct dnet_cmd) + sizeof(struct dnet_io_attr);
		cmd->flags |= DNET_FLAGS_REPLY;
		cmd->size = sizeof(struct dnet_io_attr) + it->size;
		if (std::next(it) == points.cend())
			cmd->flags &= ~DNET_FLAGS_MORE;
		err = dnet_send_fd(state, cmd, hsize, wc.data_fd, offset + it->offset, it->size, 0);
		if (err) {
			dnet_backend_log(c->blog, DNET_LOG_ERROR,
			                 "%s: EBLOB: blob_read_struct_raw: failed to dnet_send_fd: %d",
			                 dnet_dump_id_str(io->id), err);
			return err;
		}
	}

	return err;
}

void struct_reader::parse_request(void *data) {
	m_io = static_cast<struct dnet_io_attr *>(data);
	data += sizeof(*m_io);

	dnet_convert_io_attr(m_io);

	dnet_read_struct_request *request = static_cast<struct dnet_read_struct_request *>(data);

	m_key = convert_id(m_io->id);

	m_request_index = std::string(request->index, request->size);
}

int struct_reader::read_stored_index() {
	int err = eblob_read_return(m_eblob, &m_key, EBLOB_READ_NOCSUM, &m_wc);
	if (err) {
		dnet_backend_log(m_log, DNET_LOG_ERROR, "%s: EBLOB: blob-read-struct: failed: %d",
		                 dnet_dump_id_str(m_io->id), err);
		return err;
	}

	if (err == 0 && m_wc.flags & BLOB_DISK_CTL_UNCOMMITTED) {
		err = -ENOENT;
		dnet_backend_log(m_log, DNET_LOG_ERROR, "%s: EBLOB: blob-read-struct: record is uncommitted",
		                 dnet_dump_id_str(m_io->id));
		return err;
	}

	if (!(m_wc.flags & BLOB_DISK_CTL_EXTHDR)) {
		err = -EINVAL;
		dnet_backend_log(m_log, DNET_LOG_ERROR, "%s: EBLOB: blob-read-struct: record has no exthdr",
		                 dnet_dump_id_str(m_io->id));
		return err;
	}

	m_stored_index = blob_read_stored_index(m_c, m_key, m_wc);

	return err;
}

int struct_reader::read(dnet_cmd *cmd, void *data) {
	int err = 0;
	parse_request(data);
	err = read_stored_index();
	if (err) {
		return err;
	}

	return blob_read_struct_raw(m_c, m_stored_index, m_request_index, m_state, cmd, m_wc, m_io);
}

int blob_read_struct(struct eblob_backend_config *c, struct dnet_net_state *state, struct dnet_cmd *cmd, void *data) {
	struct_reader reader(c, state);
	return reader.read(cmd, data);
}
