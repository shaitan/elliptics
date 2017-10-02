/*
* 2012+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
* 2013+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
* 2013+ Copyright (c) Andrey Kashin <kashin.andrej@gmail.com>
* All rights reserved.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*/

#include "cache.hpp"
#include "slru_cache.hpp"

#include <blackhole/attribute.hpp>
#include <kora/config.hpp>

#include "library/backend.h"
#include "library/protocol.hpp"

#include "monitor/measure_points.h"
#include "rapidjson/document.h"

#include "example/config.hpp"

namespace ioremap { namespace cache {

write_request::write_request(unsigned char *id, struct dnet_io_attr *io, ioremap::elliptics::data_pointer &data)
: id(id)
, ioflags(io->flags)
, user_flags(io->user_flags)
, timestamp(io->timestamp)
, json_capacity(0)
, data_offset(io->offset)
, data_capacity(0)
, data_commit_size(0)
, cache_lifetime(io->start)
, data_checksum(&io->parent)
, request_data(io)
, data(data) {
	dnet_empty_time(&json_timestamp);
}

write_request::write_request(unsigned char *id,
                             struct ioremap::elliptics::dnet_write_request &req,
                             void *request_data,
                             ioremap::elliptics::data_pointer &data,
                             ioremap::elliptics::data_pointer &json)
: id(id)
, ioflags(req.ioflags)
, user_flags(req.user_flags)
, timestamp(req.timestamp)
, json_capacity(req.json_capacity)
, json_timestamp(req.json_timestamp)
, data_offset(req.data_offset)
, data_capacity(req.data_capacity)
, data_commit_size(req.data_commit_size)
, cache_lifetime(req.cache_lifetime)
, data_checksum(nullptr)
, request_data(request_data)
, data(data)
, json(json) {}

static size_t parse_size(const std::string &value) {
	size_t ret = strtoul(value.c_str(), NULL, 0);

	if (strchr(value.c_str(), 'P') || strchr(value.c_str(), 'p')) {
		ret *= 1ULL << 50;
	} else if (strchr(value.c_str(), 'T') || strchr(value.c_str(), 't')) {
		ret *= 1ULL << 40;
	} else if (strchr(value.c_str(), 'G') || strchr(value.c_str(), 'g')) {
		ret *= 1ULL << 30;
	} else if (strchr(value.c_str(), 'M') || strchr(value.c_str(), 'm')) {
		ret *= 1ULL << 20;
	} else if (strchr(value.c_str(), 'K') || strchr(value.c_str(), 'k')) {
		ret *= 1ULL << 10;
	}

	return ret;
}

static size_t parse_size(const kora::config_t &value) {
	size_t ret = 0;
	if (value.underlying_object().is_uint()) {
		ret = value.to<size_t>();
	} else if (value.underlying_object().is_string()) {
		ret = parse_size(value.to<std::string>());
	} else {
		throw elliptics::config::config_error(value.path() + " must be specified");
	}

	if (ret == 0) {
		throw elliptics::config::config_error(value.path() + " must be non-zero");
	}
	return ret;
}

cache_config cache_config::parse(const kora::config_t &cache) {
	return {/*size*/ parse_size(cache["size"]),
	        /*count*/ cache.at<size_t>("shards", DNET_DEFAULT_CACHES_NUMBER),
	        /*sync_timeout*/ cache.at<unsigned>("sync_timeout", DNET_DEFAULT_CACHE_SYNC_TIMEOUT_SEC),
	        /*pages_proportions*/ cache.at("pages_proportions",
	                                       std::vector<size_t>(DNET_DEFAULT_CACHE_PAGES_NUMBER, 1))};
}

cache_manager::cache_manager(dnet_node *n, dnet_backend &backend, const cache_config &config)
: m_node(n)
, m_need_exit(false) {
	size_t caches_number = config.count;
	m_cache_pages_number = config.pages_proportions.size();
	m_max_cache_size = config.size;
	size_t max_size = m_max_cache_size / caches_number;

	size_t proportionsSum = 0;
	for (size_t i = 0; i < m_cache_pages_number; ++i) {
		proportionsSum += config.pages_proportions[i];
	}

	std::vector<size_t> pages_max_sizes(m_cache_pages_number);
	for (size_t i = 0; i < m_cache_pages_number; ++i) {
		pages_max_sizes[i] = max_size * (config.pages_proportions[i] * 1.0 / proportionsSum);
	}

	for (size_t i = 0; i < caches_number; ++i) {
		m_caches.emplace_back(
		        std::make_shared<slru_cache_t>(n, backend, pages_max_sizes, config.sync_timeout, m_need_exit));
	}
}

cache_manager::~cache_manager() {
	m_need_exit = true;
}

write_response_t cache_manager::write(dnet_net_state *st,
                                      dnet_cmd *cmd,
                                      const write_request &request) {
	return m_caches[idx(request.id)]->write(st, cmd, request);
}

read_response_t cache_manager::read(const unsigned char *id, uint64_t ioflags) {
	return m_caches[idx(id)]->read(id, ioflags);
}

int cache_manager::remove(const dnet_cmd *cmd, ioremap::elliptics::dnet_remove_request &request) {
	return m_caches[idx(cmd->id.id)]->remove(cmd, request);
}

read_response_t cache_manager::lookup(const unsigned char *id) {
	return m_caches[idx(id)]->lookup(id);
}

void cache_manager::clear() {
	for (size_t i = 0; i < m_caches.size(); ++i) {
		m_caches[i]->clear();
	}
}

size_t cache_manager::cache_size() const {
	return m_max_cache_size;
}

size_t cache_manager::cache_pages_number() const {
	return m_cache_pages_number;
}

cache_stats cache_manager::get_total_cache_stats() const {
	cache_stats stats;
	stats.pages_sizes.resize(m_cache_pages_number);
	stats.pages_max_sizes.resize(m_cache_pages_number);
	for (size_t i = 0; i < m_caches.size(); ++i) {
		const cache_stats &page_stats = m_caches[i]->get_cache_stats();
		stats.number_of_objects += page_stats.number_of_objects;
		stats.number_of_objects_marked_for_deletion += page_stats.number_of_objects_marked_for_deletion;
		stats.size_of_objects_marked_for_deletion += page_stats.size_of_objects_marked_for_deletion;
		stats.size_of_objects += page_stats.size_of_objects;

		for (size_t j = 0; j < m_cache_pages_number; ++j) {
			stats.pages_sizes[j] += page_stats.pages_sizes[j];
			stats.pages_max_sizes[j] += page_stats.pages_max_sizes[j];
		}
	}
	return stats;
}

void cache_manager::statistics(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator) const {
	value.SetObject();

	rapidjson::Value total_cache(rapidjson::kObjectType);
	{
		rapidjson::Value size_stats(rapidjson::kObjectType);
		get_total_cache_stats().to_json(size_stats, allocator);
		total_cache.AddMember("size_stats", size_stats, allocator);
	}
	value.AddMember("total_cache", total_cache, allocator);

	rapidjson::Value caches(rapidjson::kObjectType);
	for (size_t i = 0; i < m_caches.size(); ++i) {
		const auto &index = std::to_string(i);
		rapidjson::Value cache_time_stats(rapidjson::kObjectType);
		m_caches[i]->get_cache_stats().to_json(cache_time_stats, allocator);
		caches.AddMember(index.c_str(), allocator, cache_time_stats, allocator);
	}
	value.AddMember("caches", caches, allocator);
}

size_t cache_manager::idx(const unsigned char *id) {
	size_t i = *(size_t *)id;
	size_t j = *(size_t *)(id + DNET_ID_SIZE - sizeof(size_t));
	return (i ^ j) % m_caches.size();
}

}} /* namespace ioremap::cache */

using namespace ioremap::cache;

static int dnet_cmd_cache_io_write(struct cache_manager *cache,
                                   struct dnet_net_state *st,
                                   struct dnet_cmd *cmd,
                                   struct dnet_io_attr *io,
                                   char *data,
                                   struct dnet_cmd_stats *cmd_stats) {
	write_status status;
	int err;

	auto data_p = ioremap::elliptics::data_pointer::from_raw(data, io->size);

	std::tie(status, err, std::ignore) = cache->write(st, cmd, write_request(io->id, io, data_p));

	switch (status) {
	case write_status::ERROR:
		break;
	case write_status::HANDLED_IN_BACKEND:
		cmd_stats->size = io->size;
		cmd_stats->handled_in_cache = 0;

		cmd->flags &= ~DNET_FLAGS_NEED_ACK;
		break;
	case write_status::HANDLED_IN_CACHE:
		cmd_stats->size = io->size;
		cmd_stats->handled_in_cache = 1;

		cmd->flags &= ~DNET_FLAGS_NEED_ACK;
		err = dnet_send_file_info_ts_without_fd(st, cmd, data, io->size, &io->timestamp);
		break;
	}

	return err;
}

static int dnet_cmd_cache_io_write_new(struct cache_manager *cache,
                                       struct dnet_net_state *st,
                                       struct dnet_cmd *cmd,
                                       void *data,
                                       struct dnet_cmd_stats *cmd_stats) {
	using namespace ioremap::elliptics;

	auto data_p = data_pointer::from_raw(data, cmd->size);

	auto request = [&data_p] () {
		size_t offset = 0;
		dnet_write_request request;
		deserialize(data_p, request, offset);
		data_p = data_p.skip(offset);
		return request;
	} ();

	if (request.ioflags & DNET_IO_FLAGS_NOCACHE) {
		return -ENOTSUP;
	}

	auto json = data_p.slice(0, request.json_size);
	data_p = data_p.slice(request.json_size, request.data_size);

	write_status status;
	int err;
	cache_item it;

	std::tie(status, err, it) = cache->write(st, cmd, write_request(cmd->id.id, request, data, data_p, json));

	if (status == write_status::HANDLED_IN_CACHE) {
		auto response = serialize(dnet_lookup_response{
			0, // record_flags
			it.user_flags, // user_flags
			"", // path

			it.json_timestamp, // json_timestamp
			0, // json_offset
			it.json->size(), // json_size
			it.json->size(), // json_capacity

			it.timestamp, // data_timestamp
			0, // data_offset
			it.data->size(), // data_size
		});

		cmd_stats->size = request.json_size + request.data_size;
		cmd_stats->handled_in_cache = 1;

		cmd->flags &= ~DNET_FLAGS_NEED_ACK;
		err = dnet_send_reply(st, cmd, response.data(), response.size(), 0);
	} else if (status == write_status::HANDLED_IN_BACKEND) {
		cmd_stats->size = request.json_size + request.data_size;
		cmd_stats->handled_in_cache = 0;

		cmd->flags &= ~DNET_FLAGS_NEED_ACK;
	}

	return err;
}

static int dnet_cmd_cache_io_read(struct cache_manager *cache,
                                  struct dnet_net_state *st,
                                  struct dnet_cmd *cmd,
                                  struct dnet_io_attr *io,
                                  struct dnet_cmd_stats *cmd_stats) {
	struct dnet_node *n = st->n;

	int err;
	cache_item it;

	std::tie(err, it) = cache->read(io->id, io->flags);
	if (err) {
		return err;
	}

	auto d = it.data;

	/*!
	 * When offset is larger then size of the file, operation is definitely incorrect
	 */
	if (io->offset >= d->size()) {
		DNET_LOG_ERROR(n, "{}: {} cache: invalid offset: offset: {}, size: {}, cached-size: {}",
		               dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), io->offset, io->size, d->size());
		return -EINVAL;
	}

	/*!
	 * If offset is correct, but offset + read_size is bigger then file_size
	 * then we should return data from offset position till the end of the file
	 * This situation happens when for example we want to read first 100 bytes of
	 * the file and it's size appears to be less then 100 bytes.
	 */
	io->size = std::min(io->size, d->size() - io->offset);

	/*!
	 * 0 is special value for io operation size and in this case we should read all file
	 */
	if (io->size == 0)
		io->size = d->size() - io->offset;

	io->total_size = d->size();

	io->timestamp = it.timestamp;
	io->user_flags = it.user_flags;

	cmd_stats->size = io->size;
	cmd_stats->handled_in_cache = 1;

	cmd->flags &= ~DNET_FLAGS_NEED_ACK;
	return dnet_send_read_data(st, cmd, io, &d->at(io->offset), -1, io->offset, 0);
}

static int dnet_cmd_cache_io_read_new(struct cache_manager *cache,
                                      struct dnet_net_state *st,
                                      struct dnet_cmd *cmd,
                                      void *data,
                                      struct dnet_cmd_stats *cmd_stats) {
	using namespace ioremap::elliptics;

	auto request = [&data, &cmd] () {
		dnet_read_request request;
		deserialize(data_pointer::from_raw(data, cmd->size), request);
		return request;
	} ();

	if (request.ioflags & DNET_IO_FLAGS_NOCACHE) {
		return -ENOTSUP;
	}

	int err;
	cache_item it;

	std::tie(err, it) = cache->read(cmd->id.id, request.ioflags);
	if (err) {
		return err;
	}

	auto raw_data = it.data;
	auto raw_json = it.json;

	data_pointer json, data_p;

	if (request.read_flags & DNET_READ_FLAGS_JSON) {
		json = data_pointer::from_raw(*raw_json);
	}

	if (request.read_flags & DNET_READ_FLAGS_DATA) {
		if (request.data_offset && request.data_offset >= raw_data->size())
			return -E2BIG;

		uint64_t data_size = raw_data->size() - request.data_offset;

		if (request.data_size) {
			data_size = std::min(data_size, request.data_size);
		}

		data_p = data_pointer::from_raw(*raw_data);
		data_p = data_p.slice(request.data_offset, data_size);
	}

	auto header = serialize(dnet_read_response{
		0, // record_flags
		it.user_flags, // user_flags

		it.json_timestamp, // json_timestamp
		raw_json->size(), // json_size
		raw_json->size(), // json_capacity
		json.size(), // read_json_size

		it.timestamp, // data_timestamp
		raw_data->size(), // data_size
		request.data_offset, // read_data_offset
		data_p.size(), // read_data_size
	});

	// NB! Following code is a copy-paste from blob_read_new()
	auto response = data_pointer::allocate(sizeof(*cmd) + header.size() + json.size());
	memcpy(response.data(), cmd, sizeof(*cmd));
	memcpy(response.skip(sizeof(*cmd)).data(), header.data(), header.size());
	if (!json.empty())
		memcpy(response.skip(sizeof(*cmd) + header.size()).data(), json.data(), json.size());

	response.data<dnet_cmd>()->size = header.size() + json.size() + data_p.size();
	response.data<dnet_cmd>()->flags |= DNET_FLAGS_REPLY;
	response.data<dnet_cmd>()->flags &= ~DNET_FLAGS_NEED_ACK;

	cmd_stats->size = json.size() + data_p.size();
	cmd_stats->handled_in_cache = 1;

	cmd->flags &= ~DNET_FLAGS_NEED_ACK;
	return dnet_send_data(st, response.data(), response.size(), data_p.data(), data_p.size());
}

static int dnet_cmd_cache_io_lookup(struct dnet_backend *backend,
                                    struct dnet_net_state *st,
                                    struct dnet_cmd *cmd,
                                    struct dnet_cmd_stats *cmd_stats) {
	cmd_stats->handled_in_cache = 1;

	int err;
	cache_item it;

	std::tie(err, it) = backend->cache()->lookup(cmd->id.id);
	if (err) {
		return err;
	}


	// go check object on disk
	local_session sess(*backend, st->n);
	cmd->flags |= DNET_FLAGS_NOCACHE;
	ioremap::elliptics::data_pointer data = sess.lookup(*cmd, &err);
	cmd->flags &= ~DNET_FLAGS_NOCACHE;

	cmd->flags &= ~(DNET_FLAGS_MORE | DNET_FLAGS_NEED_ACK);

	if (err) {
		// zero size means 'we didn't find key on disk', but yet it exists in cache
		// lookup by its nature is 'show me what is on disk' command
		return dnet_send_file_info_ts_without_fd(st, cmd, nullptr, 0, &it.timestamp);
	}

	auto info = data.skip<dnet_addr>().data<dnet_file_info>();
	info->mtime = it.timestamp;

	return dnet_send_reply(st, cmd, data.data(), data.size(), 0);
}

static int dnet_cmd_cache_io_lookup_new(struct cache_manager *cache,
                                        struct dnet_net_state *st,
                                        struct dnet_cmd *cmd,
                                        struct dnet_cmd_stats *cmd_stats) {
	using namespace ioremap::elliptics;
	cmd_stats->handled_in_cache = 1;

	int err;
	cache_item it;

	std::tie(err, it) = cache->lookup(cmd->id.id);
	if (err) {
		return err;
	}

	auto response = serialize(dnet_lookup_response{
		0, // record_flags
		it.user_flags, // user_flags
		"", // path

		it.json_timestamp, // json_timestamp
		0, // json_offset
		it.json->size(), // json_size
		it.json->size(), // json_capacity

		it.timestamp, // data_timestamp
		0, // data_offset
		it.data->size(), // data_size
	});

	cmd->flags &= ~DNET_FLAGS_NEED_ACK;
	return dnet_send_reply(st, cmd, response.data(), response.size(), 0);
}

static int dnet_cmd_cache_io_remove(struct cache_manager *cache,
				    struct dnet_cmd *cmd,
				    struct dnet_io_attr *io,
				    struct dnet_cmd_stats *cmd_stats) {
	ioremap::elliptics::dnet_remove_request request{io->flags, {0, 0}};
	const int err = cache->remove(cmd, request);
	if (!err) {
		cmd_stats->handled_in_cache = 1;
	}
	return err;
}

static int dnet_cmd_cache_io_remove_new(struct cache_manager *cache,
                                        struct dnet_cmd *cmd,
                                        void *data,
                                        struct dnet_cmd_stats *cmd_stats) {
	using namespace ioremap::elliptics;

	auto request = [&data, &cmd] () {
		dnet_remove_request request;
		deserialize(data_pointer::from_raw(data, cmd->size), request);
		return request;
	} ();

	if (request.ioflags & DNET_IO_FLAGS_NOCACHE) {
		return -ENOTSUP;
	}

	const int err = cache->remove(cmd, request);
	if (!err) {
		cmd_stats->handled_in_cache = 1;
	}
	return err;
}

int dnet_cmd_cache_io(struct dnet_backend *backend,
                      struct dnet_net_state *st,
                      struct dnet_cmd *cmd,
                      char *data,
                      struct dnet_cmd_stats *cmd_stats) {
	auto io = [ cmd, &data ]() -> struct dnet_io_attr * {
		switch (cmd->cmd) {
		case DNET_CMD_WRITE:
		case DNET_CMD_READ:
		case DNET_CMD_DEL:
			auto ret = reinterpret_cast<struct dnet_io_attr*>(data);
			data += sizeof(struct dnet_io_attr);
			return ret;
		}
		return nullptr;
	}();

	auto cache = backend->cache();
	if (!cache) {
		if (io && (io->flags & DNET_IO_FLAGS_CACHE))
			DNET_LOG_NOTICE(st->n, "{}: cache is not supported", dnet_dump_id(&cmd->id));
		return -ENOTSUP;
	}

	FORMATTED(HANDY_TIMER_SCOPE, ("cache.%s", dnet_cmd_string(cmd->cmd)));

	try {
		switch (cmd->cmd) {
		case DNET_CMD_WRITE:
			return dnet_cmd_cache_io_write(cache, st, cmd, io, data, cmd_stats);
		case DNET_CMD_READ:
			return dnet_cmd_cache_io_read(cache, st, cmd, io, cmd_stats);
		case DNET_CMD_LOOKUP:
			return dnet_cmd_cache_io_lookup(backend, st, cmd, cmd_stats);
		case DNET_CMD_DEL:
			return dnet_cmd_cache_io_remove(cache, cmd, io, cmd_stats);
		case DNET_CMD_WRITE_NEW:
			return dnet_cmd_cache_io_write_new(cache, st, cmd, data, cmd_stats);
		case DNET_CMD_READ_NEW:
			return dnet_cmd_cache_io_read_new(cache, st, cmd, data, cmd_stats);
		case DNET_CMD_LOOKUP_NEW:
			return dnet_cmd_cache_io_lookup_new(cache, st, cmd, cmd_stats);
		case DNET_CMD_DEL_NEW:
			return dnet_cmd_cache_io_remove_new(cache, cmd, data, cmd_stats);
		default:
			return -ENOTSUP;
		}
	} catch (const std::exception &e) {
		DNET_LOG_ERROR(st->n, "{}: {} cache operation failed: {}", dnet_dump_id(&cmd->id),
		               dnet_cmd_string(cmd->cmd), e.what());
		return -ENOENT;
	}

}
