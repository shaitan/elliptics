/*
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

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "example/eblob_backend.h"

#include "elliptics/packet.h"
#include "elliptics/backends.h"
#include "elliptics/newapi/session.hpp"

#include "library/protocol.hpp"
#include "library/elliptics.h"

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

static int dnet_get_filename(int fd, std::string &filename) {
	char *name = NULL;
	if (const int err = dnet_fd_readlink(fd, &name) < 0)
		return err;

	filename.assign(name);
	free(name);
	return 0;
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

int dnet_read_json_header(int fd, uint64_t offset, uint64_t size, dnet_json_header *jhdr) {
	memset(jhdr, 0, sizeof(*jhdr));

	if (!size)
		return 0;

	auto json_header = ioremap::elliptics::data_pointer::allocate(size);
	int err = dnet_read_ll(fd, (char *)json_header.data(), json_header.size(), offset);
	if (err)
		return err;

	try {
		deserialize(json_header, *jhdr);
	} catch( std::exception &) {
		return -EINVAL;
	}

	return 0;
}

int blob_file_info_new(eblob_backend_config *c, void *state, dnet_cmd *cmd) {
	using namespace ioremap::elliptics;
	eblob_backend *b = c->eblob;

	eblob_key key;
	memcpy(key.id, cmd->id.id, EBLOB_ID_SIZE);

	eblob_write_control wc;
	int err = eblob_read_return(b, &key, EBLOB_READ_NOCSUM, &wc);
	if (err == 0 && wc.flags & BLOB_DISK_CTL_UNCOMMITTED)
		err = -ENOENT;

	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "%s: EBLOB: blob-file-info-new: failed: %s [%d]",
		                 dnet_dump_id(&cmd->id), strerror(-err), err);
		return err;
	}

	std::string filename;
	err = dnet_get_filename(wc.data_fd, filename);

	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR,
		                 "%s: EBLOB: blob-file-info-new: dnet_get_filename: fd: %d:  failed: %s [%d]",
		                 dnet_dump_id(&cmd->id), wc.data_fd, strerror(-err), err);
		return err;
	}

	dnet_ext_list_hdr ehdr;
	memset(&ehdr, 0, sizeof(ehdr));

	dnet_json_header jhdr;
	memset(&jhdr, 0, sizeof(jhdr));

	if (wc.flags & BLOB_DISK_CTL_EXTHDR) {
		if (wc.total_data_size < sizeof(ehdr))
			return -ERANGE;

		err = dnet_ext_hdr_read(&ehdr, wc.data_fd, wc.data_offset);
		if (err)
			return err;

		if (wc.total_data_size < sizeof(ehdr) + ehdr.size)
			return -ERANGE;

		err = dnet_read_json_header(wc.data_fd, wc.data_offset + sizeof(ehdr), ehdr.size, &jhdr);
		if(err)
			return err;

		if (wc.total_data_size < sizeof(ehdr) + ehdr.size + jhdr.capacity)
			return -ERANGE;

		wc.size -= sizeof(ehdr) + ehdr.size + jhdr.capacity;
		// wc.total_data_size -= sizeof(ehdr);
		wc.data_offset += sizeof(ehdr) + ehdr.size + jhdr.capacity;
	}

	auto response = serialize(dnet_lookup_response{
		wc.flags,
		ehdr.flags,
		filename,

		jhdr.timestamp,
		wc.data_offset - jhdr.capacity,
		jhdr.size,
		jhdr.capacity,

		ehdr.timestamp,
		wc.data_offset,
		wc.size,
	});

	err = dnet_send_reply(state, cmd, response.data(), response.size(), 0);
	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR,
		                 "%s: EBLOB: blob-file-info-new: dnet_send_reply: data: %p, size: %zu: %s [%d]",
		                 dnet_dump_id(&cmd->id), response.data(), response.size(), strerror(-err), err);
		return err;
	}

	dnet_backend_log(c->blog, DNET_LOG_INFO,
	                 "%s: EBLOB: blob-file-info-new: fd: %d, json_size: %" PRIu64", data_size: %" PRIu64,
	                 dnet_dump_id(&cmd->id), wc.data_fd, jhdr.size, wc.size);

	return 0;
}

int blob_read_new(eblob_backend_config *c, void *state, dnet_cmd *cmd, void *data) {
	using namespace ioremap::elliptics;

	eblob_backend *b = c->eblob;

	auto request = [&data, &cmd] () {
		dnet_read_request request;
		deserialize(data_pointer::from_raw(data, cmd->size), request);
		return request;
	} ();

	dnet_backend_log(c->blog, DNET_LOG_NOTICE,
	                 "%s: EBLOB: blob-read-new: READ_NEW: start: ioflags: %s, read_flags: %llu, "
	                 "data_offset: %llu, data_size: %llu",
	                 dnet_dump_id(&cmd->id), dnet_flags_dump_ioflags(request.ioflags),
	                 (unsigned long long)request.read_flags,
	                 (unsigned long long)request.data_offset, (unsigned long long)request.data_size);

	eblob_key key;
	memcpy(key.id, cmd->id.id, EBLOB_ID_SIZE);

	eblob_write_control wc;
	int err = eblob_read_return(b, &key, EBLOB_READ_NOCSUM, &wc);
	if (err == 0 && wc.flags & BLOB_DISK_CTL_UNCOMMITTED)
		err = -ENOENT;

	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "%s: EBLOB: blob-read-new: failed: %s [%d]",
		                 dnet_dump_id(&cmd->id), strerror(-err), err);
		return err;
	}

	dnet_ext_list_hdr ehdr;
	memset(&ehdr, 0, sizeof(ehdr));

	dnet_json_header jhdr;
	memset(&jhdr, 0, sizeof(jhdr));

	uint64_t record_offset = 0;

	if (wc.flags & BLOB_DISK_CTL_EXTHDR) {
		if (wc.total_data_size < sizeof(ehdr))
			return -ERANGE;

		err = dnet_ext_hdr_read(&ehdr, wc.data_fd, wc.data_offset);
		if (err)
			return err;

		if (wc.total_data_size < sizeof(ehdr) + ehdr.size)
			return -ERANGE;

		err = dnet_read_json_header(wc.data_fd, wc.data_offset + sizeof(ehdr), ehdr.size, &jhdr);
		if (err)
			return err;

		if (wc.total_data_size < sizeof(ehdr) + ehdr.size + jhdr.capacity)
			return -ERANGE;

		wc.size -= sizeof(ehdr) + ehdr.size;
		wc.data_offset += sizeof(ehdr) + ehdr.size;
		record_offset += sizeof(ehdr) + ehdr.size;
	}

	data_pointer json;

	auto verify_checksum = [&, wc] (uint64_t offset, uint64_t size) mutable {
		if (request.ioflags & DNET_IO_FLAGS_NOCSUM)
			return 0;
		wc.offset = offset;
		wc.size = size;
		return eblob_verify_checksum(b, &key, &wc);
	};

	if (request.read_flags & DNET_READ_FLAGS_JSON && jhdr.size) {
		err = verify_checksum(record_offset, jhdr.size);
		if (err) {
			dnet_backend_log(c->blog, DNET_LOG_ERROR,
			                 "%s: EBLOB: blob-read-new: READ_NEW: failed to verify checksum for json: "
			                 "fd: %d, offset: %" PRIu64 ", size: %" PRIu64 "%s [%d]",
			                 dnet_dump_id(&cmd->id), wc.data_fd, wc.offset, wc.size,
			                 strerror(-err), err);
			return err;
		}

		json = data_pointer::allocate(jhdr.size);
		err = dnet_read_ll(wc.data_fd, (char*)json.data(), json.size(), wc.data_offset);
		if (err) {
			dnet_backend_log(c->blog, DNET_LOG_ERROR,
			                 "%s: EBLOB: blob-read-new: READ_NEW: failed to read json: "
			                 "fd: %d, offset: %" PRIu64 ", size: %" PRIu64 "%s [%d]",
			                 dnet_dump_id(&cmd->id),
			                 wc.data_fd, wc.data_offset, json.size(), strerror(-err), err);
			return err;
		}
	}

	uint64_t data_size = 0;
	uint64_t data_offset = 0;

	if (request.read_flags & DNET_READ_FLAGS_DATA) {
		data_size = wc.size - jhdr.capacity;
		data_offset = wc.data_offset + jhdr.capacity;

		if (request.data_offset >= data_size)
			return -E2BIG;

		data_size -= request.data_offset;
		data_offset += request.data_offset;
		record_offset += request.data_offset;

		if (request.data_size &&
		    request.data_size < data_size)
			data_size = request.data_size;

		err = verify_checksum(record_offset + jhdr.capacity, data_size);
		if (err) {
			dnet_backend_log(c->blog, DNET_LOG_ERROR,
			                 "%s: EBLOB: blob-read-new: READ_NEW: failed to verify checksum for data: "
			                 "offset: %" PRIu64 ", size: %" PRIu64 "%s [%d]",
			                 dnet_dump_id(&cmd->id), request.data_offset, request.data_offset,
			                 strerror(-err), err);
			return err;
		}
	}

	auto header = serialize(dnet_read_response{
		wc.flags,
		ehdr.flags,

		jhdr.timestamp,
		jhdr.size,
		jhdr.capacity,
		json.size(),

		ehdr.timestamp,
		wc.size - jhdr.capacity,
		request.data_offset,
		data_size,
	});

	cmd->flags &= ~DNET_FLAGS_NEED_ACK;
	auto response = data_pointer::allocate(sizeof(*cmd) + header.size() + json.size());
	memcpy(response.data(), cmd, sizeof(*cmd));
	memcpy(response.skip(sizeof(*cmd)).data(), header.data(), header.size());
	if (!json.empty())
		memcpy(response.skip(sizeof(*cmd) + header.size()).data(), json.data(), json.size());

	response.data<dnet_cmd>()->size = header.size() + json.size() + data_size;
	response.data<dnet_cmd>()->flags |= DNET_FLAGS_REPLY;
	response.data<dnet_cmd>()->flags &= ~DNET_FLAGS_NEED_ACK;

	err = dnet_send_fd((dnet_net_state *)state, response.data(), response.size(),
	                   wc.data_fd, data_offset, data_size, 0);

	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR,
		                 "%s: EBLOB: blob-read-new: dnet_send_reply: data %p, size: %zu, %s [%d]",
		                 dnet_dump_id(&cmd->id), response.data(), response.size(), strerror(-err), err);
		return err;
	}

	dnet_backend_log(c->blog, DNET_LOG_INFO,
	                 "%s: EBLOB: blob-read-new: fd: %d, json_size: %" PRIu64", data_size: %" PRIu64,
	                 dnet_dump_id(&cmd->id), wc.data_fd, json.size(), data_size);

	return 0;
}

int blob_write_new(eblob_backend_config *c, void *state, dnet_cmd *cmd, void *data) {
	using namespace ioremap::elliptics;

	struct eblob_backend *b = c->eblob;
	auto data_p = data_pointer::from_raw(data, cmd->size);

	auto request = [&data_p] () {
		size_t offset = 0;
		dnet_write_request request;
		deserialize(data_p, request, offset);
		data_p = data_p.skip(offset);
		return request;
	} ();

	dnet_backend_log(c->blog, DNET_LOG_NOTICE,
	                 "%s: EBLOB: blob-write-new: WRITE_NEW: start: offset: %llu, size: %llu, ioflags: %s",
		dnet_dump_id(&cmd->id), (unsigned long long)request.data_offset, (unsigned long long)request.data_size,
		dnet_flags_dump_ioflags(request.ioflags));

	if (request.ioflags & DNET_IO_FLAGS_APPEND) {
		dnet_backend_log(c->blog, DNET_LOG_NOTICE, "%s: EBLOB: blob-write-new: WRITE_NEW: append is not supported",
		                 dnet_dump_id(&cmd->id));
		return -ENOTSUP;
	}

	dnet_ext_list_hdr ehdr;
	memset(&ehdr, 0, sizeof(ehdr));
	ehdr.timestamp = request.timestamp;
	ehdr.flags = request.user_flags;

	dnet_json_header jhdr;
	memset(&jhdr, 0, sizeof(jhdr));
	if (request.json_capacity || request.json_size) {
		jhdr.size = request.json_size;
		jhdr.capacity = request.json_capacity;
		jhdr.timestamp = request.json_timestamp;
	}

	auto json_header = jhdr.capacity ? serialize(jhdr) : data_pointer();

	eblob_key key;
	memcpy(key.id, cmd->id.id, EBLOB_ID_SIZE);

	uint64_t flags = BLOB_DISK_CTL_EXTHDR;
	if (request.ioflags & DNET_IO_FLAGS_NOCSUM)
		flags |= BLOB_DISK_CTL_NOCSUM;

	int err = 0;
	eblob_write_control wc;
	memset(&wc, 0, sizeof(wc));
	bool record_exists = false;

	if (request.ioflags & DNET_IO_FLAGS_PREPARE) {
		const uint64_t prepare_size = sizeof(ehdr) + json_header.size() + request.json_capacity + request.data_capacity;
		err = eblob_write_prepare(b, &key, prepare_size, flags);
		if (err) {
			dnet_backend_log(c->blog, DNET_LOG_ERROR,
			                 "%s: EBLOB: blob-write-new: eblob_write_prepare: "
			                 "size: %" PRIu64 " (json_capacity: %" PRIu64 ", data_pointer: %" PRIu64 "): %s [%d]",
			                 dnet_dump_id(&cmd->id), prepare_size,
			                 request.json_capacity, request.data_capacity, strerror(-err), err);
			return err;
		}
	} else {
		[&] () {
			if (eblob_read_return(b, &key, EBLOB_READ_NOCSUM, &wc))
				return;

			record_exists = true;

			dnet_ext_list_hdr old_ehdr;
			if (dnet_ext_hdr_read(&old_ehdr, wc.data_fd, wc.data_offset))
				return;

			if (request.ioflags & DNET_IO_FLAGS_UPDATE_JSON)
				ehdr.timestamp = old_ehdr.timestamp;

			if (!old_ehdr.size)
				return;

			if (dnet_read_json_header(wc.data_fd, wc.data_offset + sizeof(old_ehdr), old_ehdr.size, &jhdr))
				return;

			if (request.json_size || (request.ioflags & DNET_IO_FLAGS_UPDATE_JSON)) {
				jhdr.size = request.json_size;
				jhdr.timestamp = request.json_timestamp;
			}
		} ();
	}

	if (request.ioflags & DNET_IO_FLAGS_UPDATE_JSON) {
		/* update_json can not be applied to nonexistent or uncommitted records.
		 * we return -ENOENT in such cases.
		 */
		if (!record_exists || wc.flags & BLOB_DISK_CTL_UNCOMMITTED) {
			return -ENOENT;
		}
	} else if (!(request.ioflags & DNET_IO_FLAGS_PREPARE)) {
		/* plain_write and commit without prepare can not be applied to
		 * nonexistent or committed records.
		 * Return -ENOENT for nonexistent records and -EPERM for committed records.
		 */
		if  (!record_exists) {
			return -ENOENT;
		} else if(!(wc.flags & BLOB_DISK_CTL_UNCOMMITTED)) {
			return -EPERM;
		}
	}

	json_header = jhdr.capacity ? serialize(jhdr) : data_pointer();

	ehdr.size = json_header.size();

	std::vector<eblob_iovec> iov;
	iov.reserve(3);
	iov.emplace_back(eblob_iovec{&ehdr, sizeof(ehdr), 0});

	if (!json_header.empty()) {
		iov.emplace_back(eblob_iovec{json_header.data(), json_header.size(), sizeof(ehdr)});
	}

	if (request.json_size) {
		if (request.json_size > jhdr.capacity) {
			err = -E2BIG;
			dnet_backend_log(c->blog, DNET_LOG_ERROR,
			                 "%s: EBLOB: blob-write-new: WRITE_NEW: "
			                 "json (%" PRIu64 ") exceed capacity (%" PRIu64"): %s [%d]",
			                 dnet_dump_id(&cmd->id), request.json_size, jhdr.capacity,
			                 strerror(-err), err);
			return err;
		}
		const auto offset = sizeof(ehdr) + ehdr.size;
		iov.emplace_back(eblob_iovec{data_p.data(), request.json_size, offset});
	}

	if (request.data_size) {
		const auto offset = sizeof(ehdr) + ehdr.size + jhdr.capacity + request.data_offset;
		iov.emplace_back(eblob_iovec{data_p.skip(request.json_size).data(), request.data_size, offset});
	}

	if (request.ioflags & DNET_IO_FLAGS_PLAIN_WRITE) {
		err = eblob_plain_writev(b, &key, iov.data(), iov.size(), flags);
	} else if (request.ioflags & DNET_IO_FLAGS_UPDATE_JSON) {
		iov.emplace_back(eblob_iovec{nullptr, 0, wc.size});
		err = eblob_writev(b, &key, iov.data(), iov.size(), flags);
	} else {
		err = eblob_writev(b, &key, iov.data(), iov.size(), flags);
	}

	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR,
		                 "%s: EBLOB: blob-write-new: WRITE_NEW: writev failed %s [%d]",
		                 dnet_dump_id(&cmd->id), strerror(-err), err);
		return err;
	}

	if (request.ioflags & DNET_IO_FLAGS_COMMIT) {
		const uint64_t commit_size = sizeof(ehdr) + ehdr.size + jhdr.capacity + request.data_commit_size;
		err = eblob_write_commit(b, &key, commit_size, flags);
		if (err) {
			dnet_backend_log(c->blog, DNET_LOG_ERROR, "%s: EBLOB: blob-write-new: eblob_write_commit: "
			                 "size: %" PRIu64 ": %s [%d]",
			                 dnet_dump_id(&cmd->id), commit_size, strerror(-err), err);
			return err;
		}
	}

	memset(&wc, 0, sizeof(wc));
	err = eblob_read_return(b, &key, EBLOB_READ_NOCSUM, &wc);
	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR,
		                 "%s: EBLOB: blob-write-new: eblob_read failed: %s [%d]",
		                 dnet_dump_id(&cmd->id), strerror(-err), err);
		return err;
	}

	if (request.ioflags & DNET_IO_FLAGS_WRITE_NO_FILE_INFO) {
		cmd->flags |= DNET_FLAGS_NEED_ACK;
		return 0;
	}

	std::string filename;
	err = dnet_get_filename(wc.data_fd, filename);
	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR,
		                 "%s: EBLOB: blob-write-new: dnet_get_filename: fd: %d:  failed: %s [%d]",
		                 dnet_dump_id(&cmd->id), wc.data_fd, strerror(-err), err);
		return err;
	}

	if (wc.size) {
		if (wc.size >= sizeof(ehdr) + ehdr.size) {
			wc.size -= sizeof(ehdr) + ehdr.size;
			// wc.total_data_size -= sizeof(ehdr);
			wc.data_offset += + sizeof(ehdr) + ehdr.size;
		} else
			return -EINVAL;
	}

	auto response = serialize(dnet_lookup_response{
		wc.flags,
		ehdr.flags,
		filename,

		jhdr.timestamp,
		wc.data_offset,
		jhdr.size,
		jhdr.capacity,

		ehdr.timestamp,
		wc.data_offset + jhdr.capacity,
		wc.size ? (wc.size - jhdr.capacity) : 0,
	});

	err = dnet_send_reply(state, cmd, response.data(), response.size(), 0);
	if (err) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR,
		                 "%s: EBLOB: blob-write-new: dnet_send_reply: data: %p, size: %zu: %s [%d]",
		                 dnet_dump_id(&cmd->id), response.data(), response.size(), strerror(-err), err);
		return err;
	}

	dnet_backend_log(c->blog, DNET_LOG_INFO,
	                 "%s: EBLOB: blob-write-new: fd: %d, json_size: %" PRIu64", data_size: %" PRIu64,
	                 dnet_dump_id(&cmd->id), wc.data_fd, jhdr.size, wc.size - jhdr.capacity);

	return 0;
}

static bool check_key_ranges(eblob_backend_config *c, ioremap::elliptics::dnet_iterator_request &request) {
	if (!(request.flags & DNET_IFLAGS_KEY_RANGE)) {
		return true;
	}

	request.flags &= ~DNET_IFLAGS_KEY_RANGE;

	if (request.key_ranges.empty()) {
		return true;
	}

	auto empty = [&] () {
		static const dnet_raw_id empty_key = {{0}};
		for (const auto &range : request.key_ranges) {
			if (memcmp(&empty_key, &range.key_begin, sizeof(empty_key)) ||
			    memcmp(&empty_key, &range.key_end, sizeof(empty_key))) {
				return false;
			}
		}
		return true;
	} ();

	if (empty) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "EBLOB: iterator: all keys in all ranges are 0");
		return true;
	}

	char k1[2 * DNET_ID_SIZE + 1];
	char k2[2 * DNET_ID_SIZE + 1];
	for (const auto &range : request.key_ranges) {
		if (dnet_id_cmp_str(range.key_begin.id, range.key_end.id) > 0) {
			dnet_backend_log(c->blog, DNET_LOG_ERROR, "EBLOB: iterator: key_begin (%s) > key_end (%s)",
			                 dnet_dump_id_len_raw(range.key_begin.id, DNET_ID_SIZE, k1),
			                 dnet_dump_id_len_raw(range.key_end.id, DNET_ID_SIZE, k2));
			return false;
		}
	}

	request.flags |= DNET_IFLAGS_KEY_RANGE;

	for (const auto &range : request.key_ranges) {
		dnet_backend_log(c->blog, DNET_LOG_NOTICE, "EBLOB: iterator: using key range: %s...%s",
		                 dnet_dump_id_len_raw(range.key_begin.id, DNET_ID_SIZE, k1),
		                 dnet_dump_id_len_raw(range.key_end.id, DNET_ID_SIZE, k2));
	}

	return true;
}

static bool check_ts_range(eblob_backend_config *c, ioremap::elliptics::dnet_iterator_request &request) {
	if (!(request.flags & DNET_IFLAGS_TS_RANGE)) {
		return true;
	}

	request.flags &= ~DNET_IFLAGS_TS_RANGE;

	static const dnet_time empty_time{0, 0};
	if ((memcmp(&empty_time, &std::get<0>(request.time_range), sizeof(empty_time)) == 0) &&
	    (memcmp(&empty_time, &std::get<1>(request.time_range), sizeof(empty_time)) == 0)) {
		dnet_backend_log(c->blog, DNET_LOG_NOTICE, "EBLOB: iterator: both times are zero");
		return true;
	}

	if (dnet_time_cmp(&std::get<0>(request.time_range), &std::get<1>(request.time_range)) > 0) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "EBLOB: iterator:  time_begin > time_end");
		return false;
	}

	request.flags |= DNET_IFLAGS_TS_RANGE;

	const std::string time_begin = dnet_print_time(&std::get<0>(request.time_range));
	const std::string time_end = dnet_print_time(&std::get<1>(request.time_range));

	dnet_backend_log(c->blog, DNET_LOG_NOTICE, "EBLOB: iterator: using ts range: %s...%s",
	                 time_begin.c_str(), time_end.c_str());
	return true;
}

struct iterated_key_info {
	iterated_key_info(const dnet_raw_id &key, const uint64_t record_flags, int fd)
	: key(key)
	, record_flags{record_flags}
	, fd{fd}
	, json_offset{0}
	, data_offset{0}
	, data_size{0} {
		memset(&jhdr, 0, sizeof(jhdr));
		memset(&ehdr, 0, sizeof(ehdr));
	}

	iterated_key_info(const eblob_disk_control *dc, int fd)
	: key{{0}}
	, record_flags{dc->flags}
	, fd{fd}
	, json_offset{0}
	, data_offset{0}
	, data_size{0} {
		memcpy(key.id, dc->key.id, DNET_ID_SIZE);

		memset(&jhdr, 0, sizeof(jhdr));
		memset(&ehdr, 0, sizeof(ehdr));
	}

	dnet_raw_id key;
	uint64_t record_flags;
	int fd;
	uint64_t json_offset;
	uint64_t data_offset;
	uint64_t data_size;
	dnet_json_header jhdr;
	dnet_ext_list_hdr ehdr;
};

typedef std::function<int (const iterated_key_info &info)> iterator_callback;

static iterator_callback make_iterator_server_send_callback(eblob_backend_config *c, dnet_net_state *st,
                                                            dnet_cmd *cmd,
                                                            ioremap::elliptics::dnet_server_send_request &request,
                                                            uint64_t iterator_id,
                                                            uint64_t &counter) {
	using namespace ioremap::elliptics;
	return [=, &request] (const iterated_key_info &info) -> int {
		if (st->__need_exit) {
			dnet_backend_log(c->blog, DNET_LOG_ERROR,
			                 "EBLOB: Interrupting server_send: peer has been disconnected");
			return -EINTR;
		}

		data_pointer json;
		if (info.jhdr.size) {
			json = data_pointer::allocate(info.jhdr.size);
			const int err = dnet_read_ll(info.fd, json.data<char>(), json.size(), info.json_offset);
			if (err) {
				dnet_backend_log(c->blog, DNET_LOG_ERROR,
				                 "EBLOB: server_send: %s: failed to read json: %s",
				                 dnet_dump_id_str(info.key.id), dnet_print_error(err));
				return 0;
			}
		}

		data_pointer data;
		if (info.data_size) {
			data = data_pointer::allocate(info.data_size);
			const int err = dnet_read_ll(info.fd, data.data<char>(), data.size(), info.data_offset);
			if (err) {
				dnet_backend_log(c->blog, DNET_LOG_ERROR,
				                 "EBLOB: server_send: %s: failed to read data: %s",
				                 dnet_dump_id_str(info.key.id), dnet_print_error(err));
				return 0;
			}
		}

		auto session = std::make_shared<newapi::session>(st->n);
		session->set_exceptions_policy(session::no_exceptions);
		session->set_trace_id(cmd->trace_id);
		session->set_trace_id(!!(cmd->flags & DNET_FLAGS_TRACE_BIT));
		session->set_groups(request.groups);
		session->set_user_flags(info.ehdr.flags);
		session->set_ioflags(DNET_IO_FLAGS_CAS_TIMESTAMP);
		// if (dnet_time_cmp(&info.ehdr.timestamp, &info.jhdr.timestamp) < 0) {
		// 	session->set_timestamp(info.jhdr.timestamp);
		// } else {
			session->set_timestamp(info.ehdr.timestamp);
		// }
		if (session->get_timeout() < 60) {
			session->set_timeout(60);
		}

		auto async = session->write(info.key,
		                            json, info.jhdr.capacity,
		                            data, info.data_size);

		async.connect([&] (const newapi::sync_write_result &/*results*/, const error_info &error) {
			if (st->__need_exit) {
				dnet_backend_log(c->blog, DNET_LOG_ERROR,
				                 "EBLOB: Interrupting server_send: peer has been disconnected");
			}

			auto response = serialize(ioremap::elliptics::dnet_iterator_response{
				iterator_id, // iterator_id
				info.key, // key
				error.code(), // status

				counter, // iterated_keys
				request.keys.size(), // total_keys

				info.record_flags, // record_flags
				info.ehdr.flags, // user_flags

				info.jhdr.timestamp, // json_timestamp
				info.jhdr.size, // json_size
				info.jhdr.capacity, // json_capacity
				0, // read_json_size

				info.ehdr.timestamp, // data timestamp
				info.data_size, // data_size
				0, // read_data_size
			});

			dnet_send_reply(st, cmd, response.data(), response.size(), 1);
		});

		async.wait();
		return 0;
	};
}

static iterator_callback make_iterator_network_callback(eblob_backend_config *c, dnet_net_state *st,
                                                        dnet_cmd *cmd,
                                                        ioremap::elliptics::dnet_iterator_request &request,
                                                        const dnet_iterator *it) {
	using namespace ioremap::elliptics;
	auto counter = std::make_shared<std::atomic<uint64_t>>(0);
	const uint64_t total_keys = eblob_total_elements(c->eblob);

	return [=, &request] (const iterated_key_info &info) -> int {
		if (st->__need_exit) {
			dnet_backend_log(c->blog, DNET_LOG_ERROR,
			                 "EBLOB: iterator: Interrupting iterator: peer has been disconnected");
			return -EINTR;
		}

		data_pointer json;
		if ((request.flags & DNET_IFLAGS_JSON) && info.jhdr.size) {
			json = data_pointer::allocate(info.jhdr.size);
			const int err = dnet_read_ll(info.fd, json.data<char>(), json.size(), info.json_offset);
			if (err) {
				dnet_backend_log(c->blog, DNET_LOG_ERROR,
				                 "EBLOB: iterator: %s: failed to read json: %s [%d]",
				                 dnet_dump_id_str(info.key.id), strerror(-err), err);
				return err;
			}
		}

		const uint64_t read_data_size = (request.flags & DNET_IFLAGS_DATA) ? info.data_size : 0;

		auto header = serialize(ioremap::elliptics::dnet_iterator_response{
			it->id, // iterator_id
			info.key, // key
			0, // status

			++(*counter), // iterated_keys
			total_keys, // total_keys

			info.record_flags, // record_flags
			info.ehdr.flags, // user_flags

			info.jhdr.timestamp, // json_timestamp
			info.jhdr.size, // json_size
			info.jhdr.capacity, // json_capacity
			json.size(), // read_json_size

			info.ehdr.timestamp, // data timestamp
			info.data_size, // data_size
			read_data_size // read_data_size
		});

		if (st->__need_exit) {
			dnet_backend_log(c->blog, DNET_LOG_ERROR,
			                 "EBLOB: iterator: Interrupting iterator because peer has been disconnected");
			return -EINTR;
		}

		auto response = data_pointer::allocate(sizeof(*cmd) + header.size() + json.size());

		memcpy(response.data(), cmd, sizeof(*cmd));
		memcpy(response.skip<dnet_cmd>().data(), header.data(), header.size());
		if (!json.empty()) {
			memcpy(response.skip(sizeof(*cmd) + header.size()).data(), json.data(), json.size());
		}

		response.data<dnet_cmd>()->size = header.size() + json.size() + read_data_size;
		response.data<dnet_cmd>()->flags |= DNET_FLAGS_REPLY | DNET_FLAGS_MORE;
		response.data<dnet_cmd>()->flags &= ~DNET_FLAGS_NEED_ACK;

		return dnet_send_fd_threshold(st, response.data(), response.size(), info.fd, info.data_offset, read_data_size);
	};
}


static int blob_iterate_callback_common(const eblob_backend_config *c,
                                        const ioremap::elliptics::dnet_iterator_request &request,
                                        dnet_iterator *it,
                                        const eblob_disk_control *dc, int fd, uint64_t offset,
                                        iterator_callback callback) {
	assert(dc != nullptr);

	iterated_key_info info{dc, fd};

	uint64_t size = dc->data_size;

	int err = 0;
	if (dc->flags & BLOB_DISK_CTL_EXTHDR) {
		if (!(request.flags & DNET_IFLAGS_NO_META)) {
			err = dnet_ext_hdr_read(&info.ehdr, fd, offset);
			if (err) {
				dnet_backend_log(c->blog, DNET_LOG_ERROR,
				                 "EBLOB: iterator: %s: dnet_ext_hdr_read failed: %s [%d]",
				                 dnet_dump_id_str(info.key.id), strerror(-err), err);
				return err;
			}

			if (info.ehdr.size) {
				err = dnet_read_json_header(fd, offset + sizeof(info.ehdr), info.ehdr.size, &info.jhdr);
				if (err) {
					dnet_backend_log(c->blog, DNET_LOG_ERROR,
					                 "EBLOB: iterator: %s: dnet_read_json_header failed: %s [%d]",
					                 dnet_dump_id_str(info.key.id), strerror(-err), err);
					return err;
				}
			}
		}

		offset += sizeof(info.ehdr) + info.ehdr.size;
		if (size >= sizeof(info.ehdr) + info.ehdr.size) {
			size -= sizeof(info.ehdr) + info.ehdr.size;
		} else if (size) {
			err = -EINVAL;
			dnet_backend_log(c->blog, DNET_LOG_ERROR,
			                 "EBLOB: iterator: %s: has invalid size: %" PRIu64 " < "
			                 "%zu (sizeof(info.ehdr)) + %" PRIu32 "(info.ehdr.size): %s [%d]",
			                 dnet_dump_id_str(info.key.id), size, sizeof(info.ehdr), info.ehdr.size,
			                 strerror(-err), err);
			return err;
		}
	}

	if (request.flags & DNET_IFLAGS_TS_RANGE) {
		if (dnet_time_cmp(&info.ehdr.timestamp, &std::get<0>(request.time_range)) < 0 ||
		    dnet_time_cmp(&info.ehdr.timestamp, &std::get<1>(request.time_range)) > 0) {
			/* skip key which timestamp is not in request.time_range */
			return 0;
		}
	}

	if (size >= info.jhdr.capacity) {
		info.data_size = size - info.jhdr.capacity;
	} else if (size) {
		err = -EINVAL;
		dnet_backend_log(c->blog, DNET_LOG_ERROR,
		                 "EBLOB: iterator %s: has invalid size(%" PRIu64 ") < "
		                 "info.jhdr.capacity(%" PRIu64 "): %s [%d]",
		                 dnet_dump_id_str(info.key.id), size, info.jhdr.capacity,
		                 strerror(-err), -err);
		return err;
	}

	info.json_offset = offset;
	info.data_offset = offset + info.jhdr.capacity;

	const std::string data_ts = dnet_print_time(&info.ehdr.timestamp);
	const std::string json_ts = dnet_print_time(&info.jhdr.timestamp);

	dnet_backend_log(c->blog, DNET_LOG_DEBUG,
	                 "EBLOB: iterated: key: %s, fd: %d, user_flags: 0x%" PRIx64 ", "
	                 "json: {offset: %" PRIu64 ", size: %" PRIu64 ", capacity: %" PRIu64 ", ts: %s}, "
	                 "data: {offset: %" PRIu64 ", size: %" PRIu64 ", ts: %s}",
	                 dnet_dump_id_str(info.key.id), fd, info.ehdr.flags,
	                 offset, info.jhdr.size, info.jhdr.capacity, json_ts.c_str(),
	                 info.data_offset, info.data_size, data_ts.c_str());

	err = callback(info);
	if (err) {
		return err;
	}

	return dnet_iterator_flow_control(it);
}

static int blob_iterator_start(struct eblob_backend_config *c, dnet_net_state *st, dnet_cmd *cmd,
                               ioremap::elliptics::dnet_iterator_request &request) {
	using namespace ioremap::elliptics;

	if (request.flags & ~DNET_IFLAGS_ALL) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "EBLOB: iteration failed: unknown iteration flags: %" PRIu64,
		                 request.flags);
		return -ENOTSUP;
	}

	if (request.type <= DNET_ITYPE_FIRST ||
	    request.type >= DNET_ITYPE_LAST) {
		dnet_backend_log(c->blog, DNET_LOG_ERROR, "EBLOB: iteration failed: unknown iteration type: %" PRIu32,
		                 request.type);
		return -ENOTSUP;
	}

	if (!check_key_ranges(c, request)) {
		return -ERANGE;
	}

	if (!check_ts_range(c, request)) {
		return -ERANGE;
	}

	eblob_iterate_control control;
	memset(&control, 0, sizeof(control));

	control.b = c->eblob;
	control.log = c->data.log;
	control.flags = EBLOB_ITERATE_FLAGS_ALL | EBLOB_ITERATE_FLAGS_READONLY;

	std::vector<eblob_index_block> ranges;
	ranges.reserve(request.key_ranges.size());

	for (const auto &range : request.key_ranges) {
		eblob_key begin, end;
		memcpy(begin.id, range.key_begin.id, EBLOB_ID_SIZE);
		memcpy(end.id, range.key_end.id, EBLOB_ID_SIZE);

		ranges.emplace_back(eblob_index_block{begin, end, 0, 0});
	}

	control.range = ranges.data();
	control.range_num = ranges.size();

	auto deleter = [&st] (dnet_iterator *p) {
		dnet_iterator_destroy(st->n, p);
	};

	std::unique_ptr<dnet_iterator, decltype(deleter)> it{dnet_iterator_create(st->n), deleter};
	if (!it) {
		return -ENOMEM;
	}

	iterator_callback callback;

	switch (request.type) {
		case DNET_ITYPE_DISK: {
			dnet_backend_log(c->blog, DNET_LOG_ERROR,
			                 "EBLOB: iteration failed: type: 'DNET_ITYPE_DISK' is not implemented");
			return -ENOTSUP;
		}
		case DNET_ITYPE_NETWORK: {
			callback = make_iterator_network_callback(c, st, cmd, request, it.get());
			break;
		}
		default: {
			dnet_backend_log(c->blog, DNET_LOG_ERROR, "EBLOB: iteration failed: unknown type: %" PRIu32,
			                 request.type);
			return -ENOTSUP;
		}
	}

	auto common_callback = [&] (const eblob_disk_control *dc, int fd, uint64_t data_offset) -> int {
		return blob_iterate_callback_common(c, request, it.get(), dc, fd, data_offset, callback);
	};

	control.priv = &common_callback;

	control.iterator_cb.iterator = [] (eblob_disk_control *dc, eblob_ram_control *,
	                                   int fd, uint64_t data_offset, void *priv, void *) ->int {
		auto callback = *static_cast<decltype(common_callback) *>(priv);
		return callback(dc, fd, data_offset);
	};

	return eblob_iterate(c->eblob, &control);
}

int blob_iterate(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd, void *data) {
	using namespace ioremap::elliptics;
	/*
	 * Sanity
	 */
	if (state == nullptr || cmd == nullptr || data == nullptr) {
		return -EINVAL;
	}

	ioremap::elliptics::dnet_iterator_request request;
	deserialize(data_pointer::from_raw(data, cmd->size), request);

	dnet_backend_log(c->blog, DNET_LOG_INFO,
	                 "EBLOB: %s started: id: %" PRIu64 ", flags: %" PRIu64 ", action: %d, "
	                 "type: %" PRIu32 ", key_ranges: %zu, groups: %zu",
	                 __func__, request.iterator_id, request.flags, request.action,
	                 request.type, request.key_ranges.size(), request.groups.size());

	/*
	 * Check iterator action start/pause/cont
	 * On pause, find in list and mark as stopped
	 * On continue, find in list and mark as running, broadcast condition variable.
	 * On start, create and start iterator.
	 */
	int err = 0;
	switch (request.action) {
		case DNET_ITERATOR_ACTION_START:
			err = blob_iterator_start(c, static_cast<dnet_net_state*>(state), cmd, request);
			break;
		case DNET_ITERATOR_ACTION_PAUSE:
		case DNET_ITERATOR_ACTION_CONTINUE:
		case DNET_ITERATOR_ACTION_CANCEL:
			err = -ENOTSUP;
			break;
		default:
			err = -ENOTSUP;
			break;
	}

	dnet_backend_log(c->blog, err ? DNET_LOG_ERROR : DNET_LOG_INFO,
	                 "EBLOB: %s finished: %s [%d]",
	                 __func__, strerror(-err), err);

	return err;
}

int blob_send_new(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd, void *data) {
	using namespace ioremap::elliptics;

	if (c == nullptr || state == nullptr || cmd == nullptr || data == nullptr)
		return -EINVAL;

	ioremap::elliptics::dnet_server_send_request request;
	deserialize(data_pointer::from_raw(data, cmd->size), request);

	dnet_backend_log(c->blog, DNET_LOG_INFO,
	                 "EBLOB: %s started: ids_num: %zd, groups_num: %zd",
	                 __func__, request.keys.size(), request.groups.size());

	int err = 0;

	size_t counter = 0;
	ioremap::elliptics::dnet_iterator_response response{
		uint64_t(cmd->backend_id), // iterator_id
		dnet_raw_id{{0}}, // key
		0, // status

		0, // iterated_keys
		request.keys.size(), // total_keys

		0, // record_flags
		0, // user_flags

		dnet_time{0, 0}, // json_timestamp
		0, // json_size
		0, // json_capacity
		0, // read_json_size

		dnet_time{0, 0}, // data_timestamp
		0, // data_size
		0, // read_data_size
	};

	auto send_fail_reply = [&] (int status) {
		response.status = status;

		auto response_data = serialize(response);
		return dnet_send_reply(state, cmd, response_data.data(), response_data.size(), 1);
	};

	auto callback = make_iterator_server_send_callback(c, static_cast<dnet_net_state*>(state),
	                                                   cmd, request, cmd->backend_id, counter);

	eblob_key ekey;
	eblob_write_control wc;
	uint64_t size = 0, offset = 0;

	for (const auto &key: request.keys) {
		response.key = key;
		response.iterated_keys = ++counter;

		memcpy(ekey.id, key.id, EBLOB_ID_SIZE);

		err = eblob_read_return(c->eblob, &ekey, EBLOB_READ_NOCSUM, &wc);
		if (err == 0 && wc.flags & BLOB_DISK_CTL_UNCOMMITTED) {
			err = -ENOENT;
		}

		if (err) {
			dnet_backend_log(c->blog, DNET_LOG_ERROR,
			                 "%s: EBLOB: blob_send_new: lookup failed: %s",
			                 dnet_dump_id_str(key.id), dnet_print_error(err));
			if ((err = send_fail_reply(err))) {
				break;
			}
			continue;
		}

		iterated_key_info info{key, wc.flags, wc.data_fd};

		size = wc.total_data_size;
		offset = wc.data_offset;

		if (wc.flags & BLOB_DISK_CTL_EXTHDR) {
			err = dnet_ext_hdr_read(&info.ehdr, info.fd, offset);
			if (err) {
				if ((err = send_fail_reply(err))) {
					break;
				}
				continue;
			}

			offset += sizeof(info.ehdr);

			if (size >= sizeof(info.ehdr)) {
				size -= sizeof(info.ehdr);
			} else if (size) {
				if ((err = send_fail_reply(-EINVAL))) {
					break;
				}
				continue;
			}

			if (info.ehdr.size) {
				err = dnet_read_json_header(info.fd, offset, info.ehdr.size, &info.jhdr);
				if (err) {
					if ((err = send_fail_reply(err))) {
						break;
					}
					continue;
				}
			}

			offset += info.ehdr.size;

			if (size >= info.ehdr.size) {
				size -= info.ehdr.size;
			} else if (size) {
				if ((err = send_fail_reply(-EINVAL))) {
					break;
				}
				continue;
			}
		}

		if (size >= info.jhdr.capacity) {
			info.data_size = size - info.jhdr.capacity;
		} else if (size) {
			if ((err = send_fail_reply(-EINVAL))) {
				break;
			}
			continue;
		}

		info.json_offset = offset;
		info.data_offset = offset + info.jhdr.capacity;

		wc.offset = 0;
		wc.size = sizeof(info.ehdr) + info.ehdr.size + info.jhdr.capacity + info.data_size;
		err = eblob_verify_checksum(c->eblob, &ekey, &wc);
		if (err) {
			if ((err = send_fail_reply(err))) {
				break;
			}
			continue;
		}

		if ((err = callback(info))) {
			break;
		}
	}

	dnet_backend_log(c->blog, err ? DNET_LOG_ERROR : DNET_LOG_INFO,
	                 "EBLOB: %s finished: %s",
	                 __func__, dnet_print_error(err));
	return err;
}
