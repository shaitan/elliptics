/*
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

#ifndef _GLIBCXX_USE_NANOSLEEP
#define _GLIBCXX_USE_NANOSLEEP
#endif

#include "slru_cache.hpp"

#include <deque>

#include "library/request_queue.h"
#include "library/protocol.hpp"

#include "monitor/measure_points.h"

// Cache implementation is moderately instrumented with statistics gathering
// to provide insight into details of different cache operations.
// But overly detailed stats can also be confusing, so while some measuring
// points are always on, others are turned off by default.
// Use symbol DETAILED_CACHE_STATS to turn them on at compile time.
//
#ifdef DETAILED_CACHE_STATS
	#define METRIC_PREFIX(name) "slru_cache." name
	#define TIMER_SCOPE(name) HANDY_TIMER_SCOPE(METRIC_PREFIX(name))
	#define TIMER_START(name) HANDY_TIMER_START(METRIC_PREFIX(name), dnet_get_id())
	#define TIMER_STOP(name) HANDY_TIMER_STOP(METRIC_PREFIX(name), dnet_get_id())
#else
	#define TIMER_SCOPE(...)
	#define TIMER_START(...)
	#define TIMER_STOP(...)
#endif

namespace ioremap { namespace cache {

// public:

slru_cache_t::slru_cache_t(struct dnet_backend_io *backend, struct dnet_node *n,
	const std::vector<size_t> &cache_pages_max_sizes, unsigned sync_timeout) :
	m_backend(backend),
	m_node(n),
	m_cache_pages_number(cache_pages_max_sizes.size()),
	m_cache_pages_max_sizes(cache_pages_max_sizes),
	m_cache_pages_sizes(m_cache_pages_number, 0),
	m_cache_pages_lru(new lru_list_t[m_cache_pages_number]),
	m_clear_occured(false),
	m_sync_timeout(sync_timeout) {
	m_lifecheck = std::thread(std::bind(&slru_cache_t::life_check, this));
}

slru_cache_t::~slru_cache_t() {
	TIMER_SCOPE("dtor");
	DNET_LOG_NOTICE(m_node, "cache: disable: backend: {}: destructing SLRU cache", m_backend->backend_id);
	m_lifecheck.join();
	DNET_LOG_NOTICE(m_node, "cache: disable: backend: {}: clearing", m_backend->backend_id);
	clear();
	DNET_LOG_NOTICE(m_node, "cache: disable: backend: {}: destructed", m_backend->backend_id);
}

write_response_t slru_cache_t::write(dnet_net_state *st, dnet_cmd *cmd, const write_request &request)
{
	TIMER_SCOPE("write");

	const auto id = request.id;
	const bool remove_from_disk = (request.ioflags & DNET_IO_FLAGS_CACHE_REMOVE_FROM_DISK);
	const bool cache = (request.ioflags & DNET_IO_FLAGS_CACHE);
	const bool cache_only = (request.ioflags & DNET_IO_FLAGS_CACHE_ONLY);
	const bool append = (request.ioflags & DNET_IO_FLAGS_APPEND);
	const bool update_data = (request.ioflags & DNET_IO_FLAGS_PREPARE) || request.data.size();
	const bool update_json = (request.ioflags & (DNET_IO_FLAGS_PREPARE | DNET_IO_FLAGS_UPDATE_JSON)) || request.json.size();

	TIMER_START("write.lock");
	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE WRITE: %p", dnet_dump_id_str(id), this);
	TIMER_STOP("write.lock");

	TIMER_START("write.find");
	data_t* it = m_treap.find(id);
	TIMER_STOP("write.find");

	if (!it && !cache) {
		DNET_LOG_DEBUG(m_node, "{}: CACHE: not a cache call", dnet_dump_id_str(id));
		return write_response_t{write_status::ERROR, -ENOTSUP, cache_item()};
	}

	if (!cache_only && !append && it && it->only_append()) {
		TIMER_SCOPE("write.after_append_only");

		sync_after_append(guard, false, &*it);

		dnet_cmd_stats stats;
		int err = m_backend->cb->command_handler(st, m_backend->cb->command_private, cmd, request.request_data, &stats);

		it = populate_from_disk(guard, id, false, &err);

		return write_response_t{write_status::HANDLED_IN_BACKEND, err, it->get_cache_item()};
	}

	bool new_page = false;

	if (!it) {
		// If file not found and CACHE_ONLY flag is not set - fallback to backend request
		if (!cache_only && request.data_offset != 0) {
			int err = 0;
			it = populate_from_disk(guard, id, remove_from_disk, &err);
			new_page = true;

			if (err != 0 && err != -ENOENT)
				return write_response_t{write_status::ERROR, err, cache_item()};
		}

		// Create empty data for code simplifying
		if (!it) {
			it = create_data(id, 0, 0, remove_from_disk && !append);
			new_page = true;
			if (append) {
				it->set_only_append(true);
			}
		}
	}

	int err = check_cas(it, cmd, request);
	if (err)
		return write_response_t{write_status::ERROR, err, cache_item()};

	DNET_LOG_DEBUG(m_node, "{}: CACHE: CAS checked", dnet_dump_id_str(id));

	auto raw = it->data();

	const size_t new_json_size = [&] () -> size_t {
		if (update_json) {
			return request.json.size();
		} else {
			return it->json()->size();
		}
	} ();

	const size_t new_data_size = [&] () -> size_t {
		if (!update_data) {
			return raw->size();
		} else if (append) {
			return raw->size() + request.data.size();
		} else {
			return request.data_offset + request.data.size();
		}
	} ();

	const size_t new_size = new_data_size + new_json_size + it->overhead_size();

	const size_t page_number = it->cache_page_number();
	size_t new_page_number = page_number;

	if (!new_page) {
		new_page_number = get_next_page_number(page_number);
	}

	remove_data_from_page(id, page_number, &*it);
	resize_page(id, new_page_number, 2 * new_size);

	if (it->remove_from_cache()) {
		m_cache_stats.size_of_objects_marked_for_deletion -= it->size();
	}
	m_cache_stats.size_of_objects -= it->size();

	TIMER_START("write.modify");
	if (update_json) {
		if (request.json.size()) {
			it->json()->assign(reinterpret_cast<char *>(request.json.data()), request.json.size());
		} else {
			it->json()->clear();
		}

		if (cmd->cmd == DNET_CMD_WRITE_NEW) {
			it->set_json_timestamp(request.json_timestamp);
		} else {
			it->clear_json_timestamp();
		}
	}

	if (update_data) {
		if (append) {
			raw->append(reinterpret_cast<char *>(request.data.data()), request.data.size());
		} else {
			raw->resize(new_data_size);
			raw->replace(request.data_offset, std::string::npos,
				     reinterpret_cast<char *>(request.data.data()), request.data.size());
		}
	}
	TIMER_STOP("write.modify");
	m_cache_stats.size_of_objects += it->size();

	it->set_remove_from_cache(false);
	insert_data_into_page(id, new_page_number, &*it);

	// Mark data as dirty one, so it will be synced to the disk

	const size_t previous_eventtime = it->eventtime();
	const size_t current_time = time(nullptr);

	if (!it->synctime() && !cache_only) {
		it->set_synctime(current_time + m_sync_timeout);
	}

	if (request.cache_lifetime) {
		it->set_lifetime(current_time + request.cache_lifetime);
	}

	if (previous_eventtime != it->eventtime()) {
		TIMER_SCOPE("write.decrease_key");
		m_treap.decrease_key(it);
	}

	if (update_data) {
		it->set_timestamp(request.timestamp);
		it->set_user_flags(request.user_flags);
	}

	return write_response_t{write_status::HANDLED_IN_CACHE, 0, it->get_cache_item()};
}

read_response_t slru_cache_t::read(const unsigned char *id, uint64_t ioflags) {
	TIMER_SCOPE("read");

	const bool cache = (ioflags & DNET_IO_FLAGS_CACHE);
	const bool cache_only = (ioflags & DNET_IO_FLAGS_CACHE_ONLY);

	int err = 0;
	bool new_page = false;

	TIMER_START("read.lock");
	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE READ: %p", dnet_dump_id_str(id), this);
	TIMER_STOP("read.lock");

	TIMER_START("read.find");
	data_t* it = m_treap.find(id);
	TIMER_STOP("read.find");

	if (it && it->only_append()) {
		sync_after_append(guard, true, &*it);
		it = nullptr;
	}

	if (!it && cache && !cache_only) {
		it = populate_from_disk(guard, id, false, &err);
		new_page = true;
	}

	if (it) {
		size_t page_number = it->cache_page_number();
		size_t new_page_number = page_number;

		if (it->remove_from_cache()) {
			m_cache_stats.size_of_objects_marked_for_deletion -= it->size();
		}
		it->set_remove_from_cache(false);

		if (!new_page) {
			new_page_number = get_next_page_number(page_number);
		}

		move_data_between_pages(id, page_number, new_page_number, &*it);
		return read_response_t{0, it->get_cache_item()};
	}

	if (!err) {
		err = cache ? -ENOENT : -ENOTSUP;
	}
	return read_response_t{err, cache_item()};
}

int slru_cache_t::remove(const dnet_cmd *cmd, ioremap::elliptics::dnet_remove_request &request) {
	TIMER_SCOPE("remove");

	auto id = reinterpret_cast<const unsigned char *>(cmd->id.id);

	const bool cache_only = (request.ioflags & DNET_IO_FLAGS_CACHE_ONLY);
	bool remove_from_disk = !cache_only;
	int err = -ENOENT;

	TIMER_START("remove.lock");
	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE REMOVE: %p", dnet_dump_id_str(id), this);
	TIMER_STOP("remove.lock");

	TIMER_START("remove.find");
	data_t* it = m_treap.find(id);
	TIMER_STOP("remove.find");

	if (it) {
		if ((cmd->cmd == DNET_CMD_DEL_NEW) && (request.ioflags & DNET_IO_FLAGS_CAS_TIMESTAMP)) {
			auto cache_ts = it->timestamp();

			// cache timestamp is greater than timestamp of the data to be removed
			// do not allow it
			if (dnet_time_cmp(&cache_ts, &request.timestamp) > 0) {
				const std::string cache_ts_string = dnet_print_time(&cache_ts);
				const std::string request_ts_string = dnet_print_time(&request.timestamp);
				DNET_LOG_ERROR(m_node, "{}: CACHE: REMOVE_NEW: failed cas: "
					       "cache data timestamp is greater than request timestamp: "
					       "data-ts: {}, request-ts: {}",
				               dnet_dump_id(&cmd->id), cache_ts_string, request_ts_string);
				return -EBADFD;
			}
		}

		// If cache_only is not set the data also should be remove from the disk
		// If data is marked and cache_only is not set - data must not be synced to the disk
		remove_from_disk |= it->remove_from_disk();
		if (it->synctime() && !cache_only) {
			size_t previous_eventtime = it->eventtime();
			it->clear_synctime();

			if (previous_eventtime != it->eventtime()) {
				TIMER_SCOPE("remove.decrease_key");
				m_treap.decrease_key(it);
			}
		}
		if (it->is_syncing()) {
			it->set_sync_state(data_t::sync_state_t::ERASE_PHASE);
		}
		erase_element(&(*it));
		err = 0;
	}

	guard.unlock();

	if (remove_from_disk) {
		int local_err;
		struct dnet_id raw;
		memset(&raw, 0, sizeof(struct dnet_id));

		dnet_setup_id(&raw, 0, (unsigned char *)id);

		if (cmd->cmd == DNET_CMD_DEL_NEW) {
			if (it) {
				request.ioflags &= ~DNET_IO_FLAGS_CAS_TIMESTAMP;
			}
			const auto packet = ioremap::elliptics::serialize(request);

			TIMER_SCOPE("remove.local");

			local_err = dnet_remove_local_new(m_backend, m_node, &raw,
							  packet.data(), packet.size());
		} else {
			TIMER_SCOPE("remove.local");

			local_err = dnet_remove_local(m_backend, m_node, &raw);
		}

		if (local_err != -ENOENT)
			err = local_err;
	}

	return err;
}

read_response_t slru_cache_t::lookup(const unsigned char *id) {
	TIMER_SCOPE("lookup");

	TIMER_START("lookup.lock");
	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE LOOKUP: %p", dnet_dump_id_str(id), this);
	TIMER_STOP("lookup.lock");

	TIMER_START("lookup.find");
	data_t* it = m_treap.find(id);
	TIMER_STOP("lookup.find");

	if (it) {
		return read_response_t{0, it->get_cache_item()};
	}

	return read_response_t{-ENOENT, cache_item()};
}

void slru_cache_t::clear() {
	TIMER_SCOPE("clear");

	std::vector<size_t> cache_pages_max_sizes = m_cache_pages_max_sizes;

	TIMER_START("clear.lock");
	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "CACHE CLEAR: %p", this);
	TIMER_STOP("clear.lock");
	m_clear_occured = true;

	for (size_t page_number = 0; page_number < m_cache_pages_number; ++page_number) {
		m_cache_pages_max_sizes[page_number] = 0;
		resize_page((unsigned char *) "", page_number, 0);
	}

	while (!m_treap.empty()) {
		data_t *obj = m_treap.top();

		sync_if_required(obj, guard);
		obj->set_sync_state(data_t::sync_state_t::NOT_SYNCING);

		erase_element(obj);
	}

	m_cache_pages_max_sizes = cache_pages_max_sizes;
}

cache_stats slru_cache_t::get_cache_stats() const {
	m_cache_stats.pages_sizes = m_cache_pages_sizes;
	m_cache_stats.pages_max_sizes = m_cache_pages_max_sizes;
	return m_cache_stats;
}

// private:


int slru_cache_t::check_cas(const data_t* it, const dnet_cmd *cmd, const write_request &request) const {
	auto raw = it->data();

	if (request.ioflags & DNET_IO_FLAGS_COMPARE_AND_SWAP) {
		if (!request.data_checksum) {
			DNET_LOG_ERROR(m_node, "{}: cas: data checksum is empty", dnet_dump_id(&cmd->id));
			return -ENOTSUP;
		}

		TIMER_SCOPE("write.cas");

		// Data is already in memory, so it's free to use it
		// raw.size() is zero only if there is no such file on the server
		if (raw->size() != 0) {
			struct dnet_raw_id csum;
			dnet_transform_node(m_node, raw->data(), raw->size(), csum.id, sizeof(csum.id));

			if (memcmp(csum.id, *request.data_checksum, DNET_ID_SIZE)) {
				DNET_LOG_ERROR(m_node, "{}: cas: cache checksum mismatch", dnet_dump_id(&cmd->id));
				return -EBADFD;
			}
		}
	}

	if (request.ioflags & DNET_IO_FLAGS_CAS_TIMESTAMP) {
		TIMER_SCOPE("write.cas_timestamp");

		if (!raw->empty()) {
			auto cache_ts = it->timestamp();

			// cache timestamp is greater than timestamp of the data to be written
			// do not allow it
			if (dnet_time_cmp(&cache_ts, &request.timestamp) > 0) {
				const std::string cache_ts_string = dnet_print_time(&cache_ts);
				const std::string request_ts_string = dnet_print_time(&request.timestamp);
				DNET_LOG_ERROR(m_node, "{}: cas: cache data timestamp is greater than data to be "
				                       "written timestamp: cache-ts: '{}', data-ts: '{}'",
				               dnet_dump_id(&cmd->id), cache_ts_string, request_ts_string);
				return -EBADFD;
			}
		}

		if (!it->json()->empty()) {
			auto cache_ts = it->json_timestamp();

			if (dnet_time_cmp(&cache_ts, &request.json_timestamp) > 0) {
				const std::string cache_ts_string = dnet_print_time(&cache_ts);
				const std::string request_ts_string = dnet_print_time(&request.json_timestamp);
				DNET_LOG_ERROR(m_node, "{}: cas: cache json timestamp is greater than data to be "
				                       "written timestamp: cache-ts: '{}', data-ts: '{}'",
				               dnet_dump_id(&cmd->id), cache_ts_string, request_ts_string);
				return -EBADFD;
			}
		}
	}

	return 0;
}

void slru_cache_t::sync_if_required(data_t* it, elliptics_unique_lock<std::mutex> &guard) {
	TIMER_SCOPE("sync_if_required");

	if (it && it->is_syncing()) {
		dnet_id id;
		memset(&id, 0, sizeof(id));
		memcpy(id.id, it->id().id, DNET_ID_SIZE);

		bool only_append = it->only_append();
		std::string data = *it->data();
		uint64_t user_flags = it->user_flags();
		dnet_time timestamp = it->timestamp();

		guard.unlock();

		// sync_element uses local_session which always uses DNET_FLAGS_NOLOCK
		if (it->is_syncing()) {
			sync_element(id, only_append, data, user_flags, timestamp);
			it->set_sync_state(data_t::sync_state_t::ERASE_PHASE);
		}

		guard.lock();
	}
}

void slru_cache_t::insert_data_into_page(const unsigned char *id, size_t page_number, data_t *data) {
	TIMER_SCOPE("add_to_page");

	elliptics_timer timer;
	size_t size = data->size();

	// Recalc used space, free enough space for new data, move object to the end of the queue
	if (m_cache_pages_sizes[page_number] + size > m_cache_pages_max_sizes[page_number]) {
		DNET_LOG_DEBUG(m_node, "{}: CACHE: resize called: {} ms", dnet_dump_id_str(id), timer.restart());
		resize_page(id, page_number, size);
		DNET_LOG_DEBUG(m_node, "{}: CACHE: resize finished: {} ms", dnet_dump_id_str(id), timer.restart());
	}

	data->set_cache_page_number(page_number);
	m_cache_pages_lru[page_number].push_back(*data);
	m_cache_pages_sizes[page_number] += size;
}

void slru_cache_t::remove_data_from_page(const unsigned char *id, size_t page_number, data_t *data) {
	(void) id;
	m_cache_pages_sizes[page_number] -= data->size();
	if (!data->is_removed_from_page()) {
		m_cache_pages_lru[page_number].erase(m_cache_pages_lru[page_number].iterator_to(*data));
		data->set_removed_from_page(true);
	}
}

void slru_cache_t::move_data_between_pages(const unsigned char *id,
                                           size_t source_page_number,
                                           size_t destination_page_number,
                                           data_t *data) {
	TIMER_SCOPE("move_record");

	if (source_page_number != destination_page_number) {
		remove_data_from_page(id, source_page_number, data);
		insert_data_into_page(id, destination_page_number, data);
	}
}

data_t* slru_cache_t::create_data(const unsigned char *id, const char *data, size_t size, bool remove_from_disk) {
	TIMER_SCOPE("create_data");

	size_t last_page_number = m_cache_pages_number - 1;

	data_t *raw = new data_t(id, 0, data, size, remove_from_disk);

	insert_data_into_page(id, last_page_number, raw);

	m_cache_stats.number_of_objects++;
	m_cache_stats.size_of_objects += raw->size();
	m_treap.insert(raw);
	return raw;
}

data_t *slru_cache_t::populate_from_disk(elliptics_unique_lock<std::mutex> &guard,
                                         const unsigned char *id,
                                         bool remove_from_disk,
                                         int *err) {
	TIMER_SCOPE("populate_from_disk");

	if (guard.owns_lock()) {
		guard.unlock();
	}

	local_session sess(m_backend, m_node);
	sess.set_ioflags(DNET_IO_FLAGS_NOCACHE);

	dnet_id raw_id;
	memset(&raw_id, 0, sizeof(raw_id));
	memcpy(raw_id.id, id, DNET_ID_SIZE);

	uint64_t user_flags = 0;
	dnet_time timestamp;
	dnet_empty_time(&timestamp);

	TIMER_START("populate_from_disk.local_read");
	ioremap::elliptics::data_pointer data = sess.read(raw_id, &user_flags, &timestamp, err);
	TIMER_STOP("populate_from_disk.local_read");

	TIMER_START("populate_from_disk.lock");
	guard.lock();
	TIMER_STOP("populate_from_disk.lock");

	if (*err == 0) {
		auto it = create_data(id, reinterpret_cast<char *>(data.data()), data.size(), remove_from_disk);
		it->set_user_flags(user_flags);
		it->set_timestamp(timestamp);

		return it;
	}

	return NULL;
}

bool slru_cache_t::have_enough_space(const unsigned char *id, size_t page_number, size_t reserve) {
	(void) id;
	return m_cache_pages_max_sizes[page_number] >= reserve;
}

void slru_cache_t::resize_page(const unsigned char *id, size_t page_number, size_t reserve) {
	TIMER_SCOPE("resize_page");

	size_t removed_size = 0;
	size_t &cache_size = m_cache_pages_sizes[page_number];
	size_t &max_cache_size = m_cache_pages_max_sizes[page_number];
	size_t previous_page_number = get_previous_page_number(page_number);

	for (auto it = m_cache_pages_lru[page_number].begin(), end = m_cache_pages_lru[page_number].end(); it != end;) {
		if (max_cache_size + removed_size >= cache_size + reserve)
			break;

		data_t *raw = &*it;
		++it;

		// If page is not last move object to previous page
		if (previous_page_number < m_cache_pages_number) {
			move_data_between_pages(id, page_number, previous_page_number, raw);
		} else {
			if (raw->synctime() || raw->remove_from_cache()) {
				if (!raw->remove_from_cache()) {
					m_cache_stats.number_of_objects_marked_for_deletion++;
					m_cache_stats.size_of_objects_marked_for_deletion += raw->size();
					raw->set_remove_from_cache(true);

					const size_t previous_eventtime = raw->eventtime();
					raw->set_synctime(1);
					if (previous_eventtime != raw->eventtime()) {
						TIMER_SCOPE("resize_page.decrease_key");
						m_treap.decrease_key(raw);
					}
				}
				removed_size += raw->size();
				m_cache_pages_lru[page_number].erase(m_cache_pages_lru[page_number].iterator_to(*raw));
				raw->set_removed_from_page(true);
			} else {
				erase_element(raw);
			}
		}
	}
}

void slru_cache_t::erase_element(data_t *obj) {
	TIMER_SCOPE("erase");

	if (obj->will_be_erased()) {
		if (!obj->remove_from_cache()) {
			m_cache_stats.size_of_objects_marked_for_deletion += obj->size();
			obj->set_remove_from_cache(true);
		}
		return;
	}

	m_cache_stats.number_of_objects--;
	m_cache_stats.size_of_objects -= obj->size();

	size_t page_number = obj->cache_page_number();
	remove_data_from_page(obj->id().id, page_number, obj);
	m_treap.erase(obj);

	if (obj->synctime()) {
		sync_element(obj);
		obj->clear_synctime();
	}

	if (obj->remove_from_cache()) {
		m_cache_stats.number_of_objects_marked_for_deletion--;
		m_cache_stats.size_of_objects_marked_for_deletion -= obj->size();
	}

	delete obj;
}

void slru_cache_t::sync_element(const dnet_id &raw,
                                bool after_append,
                                const std::string &data,
                                uint64_t user_flags,
                                const dnet_time &timestamp) {
	HANDY_TIMER_SCOPE("slru_cache.sync_element");

	local_session sess(m_backend, m_node);
	sess.set_ioflags(DNET_IO_FLAGS_NOCACHE | (after_append ? DNET_IO_FLAGS_APPEND : 0));

	int err = sess.write(raw, data.data(), data.size(), user_flags, timestamp);
	const auto level = err ? DNET_LOG_ERROR : DNET_LOG_DEBUG;
	DNET_LOG(m_node, level, "{}: CACHE: forced to sync to disk, err: {}", dnet_dump_id_str(raw.id), err);
}

void slru_cache_t::sync_element(data_t *obj) {
	struct dnet_id raw;
	memset(&raw, 0, sizeof(struct dnet_id));
	memcpy(raw.id, obj->id().id, DNET_ID_SIZE);

	sync_element(raw, obj->only_append(), *obj->data(), obj->user_flags(), obj->timestamp());
}

void slru_cache_t::sync_after_append(elliptics_unique_lock<std::mutex> &guard, bool lock_guard, data_t *obj) {
	TIMER_SCOPE("sync_after_append");

	auto raw = obj->data();

	obj->clear_synctime();

	dnet_id id;
	memset(&id, 0, sizeof(id));
	memcpy(id.id, obj->id().id, DNET_ID_SIZE);

	uint64_t user_flags = obj->user_flags();
	dnet_time timestamp = obj->timestamp();

	erase_element(&*obj);

	guard.unlock();

	local_session sess(m_backend, m_node);
	sess.set_ioflags(DNET_IO_FLAGS_NOCACHE | DNET_IO_FLAGS_APPEND);

	TIMER_START("sync_after_append.local_write");
	int err = sess.write(id, raw->data(), raw->size(), user_flags, timestamp);
	TIMER_STOP("sync_after_append.local_write");

	TIMER_START("sync_after_append.lock");
	if (lock_guard)
		guard.lock();
	TIMER_STOP("sync_after_append.lock");

	DNET_LOG_INFO(m_node, "{}: CACHE: sync after append, err: {}", dnet_dump_id_str(id.id), err);
}

void slru_cache_t::life_check(void) {

	dnet_set_name("dnet_cache_%zu", m_backend->backend_id);

	while (!need_exit()) {
		{
			TIMER_SCOPE("life_check");

			std::deque<struct dnet_id> remove;
			std::deque<data_t*> elements_for_sync;
			size_t last_time = 0;
			dnet_id id;
			memset(&id, 0, sizeof(id));

			{
				TIMER_START("life_check.lock");
				elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "CACHE LIFE: %p", this);
				TIMER_STOP("life_check.lock");

				TIMER_SCOPE("life_check.prepare_sync");
				while (!need_exit() && !m_treap.empty()) {
					size_t time = ::time(nullptr);
					last_time = time;

					data_t* it = m_treap.top();
					if (it->eventtime() > time)
						break;

					if (it->eventtime() == it->lifetime())
					{
						if (it->remove_from_disk()) {
							memset(&id, 0, sizeof(struct dnet_id));
							dnet_setup_id(&id, 0, (unsigned char *)it->id().id);
							remove.push_back(id);
						}

						erase_element(it);
					}
					else if (it->eventtime() == it->synctime())
					{
						elements_for_sync.push_back(it);

						it->clear_synctime();
						it->set_sync_state(data_t::sync_state_t::SYNC_PHASE);

					        {
							TIMER_SCOPE("life_check.decrease_key");
							m_treap.decrease_key(it);
						}
					}
				}
			}

			{
				TIMER_SCOPE("life_check.sync_iterate");
				HANDY_GAUGE_SET("slru_cache.life_check.sync_iterate.element_count",
				                elements_for_sync.size());
				for (data_t *elem : elements_for_sync) {
					if (m_clear_occured)
						break;

					memcpy(id.id, elem->id().id, DNET_ID_SIZE);

					TIMER_START("life_check.sync_iterate.dnet_oplock");
					dnet_oplock(m_backend, &id);
					TIMER_STOP("life_check.sync_iterate.dnet_oplock");

					// sync_element uses local_session which always uses DNET_FLAGS_NOLOCK
					if (elem->is_syncing()) {
						sync_element(id, elem->only_append(), *elem->data(),
						             elem->user_flags(), elem->timestamp());
						elem->set_sync_state(data_t::sync_state_t::ERASE_PHASE);
					}

					dnet_opunlock(m_backend, &id);
				}
			}

			{
				TIMER_SCOPE("life_check.remove_local");
				for (struct dnet_id &id : remove) {
				        dnet_remove_local(m_backend, m_node, &id);
				}
			}

			{
				TIMER_START("life_check.lock");
				elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "CACHE CLEAR PAGES: %p", this);
				TIMER_STOP("life_check.lock");

				if (!m_clear_occured) {
					TIMER_SCOPE("life_check.erase_iterate");
					for (data_t *elem : elements_for_sync) {
						elem->set_sync_state(data_t::sync_state_t::NOT_SYNCING);
						if (elem->synctime() <= last_time) {
							if (elem->only_append() || elem->remove_from_cache()) {
								erase_element(elem);
							}
						}
					}
				} else {
					m_clear_occured = false;
				}
			}
		}

		std::this_thread::sleep_for( std::chrono::milliseconds(1000) );
	}

}

}}
