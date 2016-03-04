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

		if (request.data_size != 0 &&
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
	jhdr.size = request.json_size;
	jhdr.capacity = request.json_capacity;
	jhdr.timestamp = request.timestamp;

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
				jhdr.timestamp = request.timestamp;
			}
			if (request.json_capacity) {
				jhdr.capacity = request.json_capacity;
			}
		} ();
	}

	if (request.ioflags & DNET_IO_FLAGS_UPDATE_JSON) {
		/* update_json can not be applied for nonexistent or uncommitted records.
		 * we return -ENOENT in such cases.
		 */
		if (!record_exists || wc.flags & BLOB_DISK_CTL_UNCOMMITTED) {
			return -ENOENT;
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
