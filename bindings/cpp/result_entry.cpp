/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * 2012+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#define _XOPEN_SOURCE 600

#include "callback_p.h"
#include "monitor/compress.hpp"
#include "library/elliptics.h"

#include <fcntl.h>
#include <errno.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <queue>

namespace ioremap { namespace elliptics {

/*
 * This macroses should be used surrounding all entry::methods which work directly
 * with m_data or data() to ensure that meaningful exceptions are thrown
 */
#define DNET_DATA_BEGIN() try { \
	do {} while (false)

#define DNET_DATA_END(SIZE) \
	} catch (not_found_error &) { \
		if (!is_valid()) { \
			throw_error(-ENOENT, "entry::%s(): entry is null", __FUNCTION__); \
		} else {\
			dnet_cmd *cmd = command(); \
			throw_error(-ENOENT, cmd->id, "entry::%s(): data.size is too small, expected: %zu, actual: %zu, status: %d", \
				__FUNCTION__, size_t(SIZE), data().size(), cmd->status); \
		} \
		throw; \
	} \
	do {} while (false)

callback_result_entry::callback_result_entry() : m_data(std::make_shared<callback_result_data>())
{
}

callback_result_entry::callback_result_entry(const callback_result_entry &other) : m_data(other.m_data)
{
}

callback_result_entry::callback_result_entry(const std::shared_ptr<callback_result_data> &data) : m_data(data)
{
}

callback_result_entry::~callback_result_entry()
{
}

callback_result_entry &callback_result_entry::operator =(const callback_result_entry &other)
{
	m_data = other.m_data;
	return *this;
}

bool callback_result_entry::is_valid() const
{
	return !m_data->data.empty();
}

bool callback_result_entry::is_ack() const
{
	return status() == 0 && data().empty();
}

bool callback_result_entry::is_final() const
{
	return !(command()->flags & DNET_FLAGS_MORE);
}

bool callback_result_entry::is_client() const
{
	return !(command()->flags & DNET_FLAGS_REPLY);
}

int callback_result_entry::status() const
{
	return command()->status;
}

error_info callback_result_entry::error() const
{
	return m_data->error;
}

data_pointer callback_result_entry::raw_data() const
{
	return m_data->data;
}

struct dnet_addr *callback_result_entry::address() const
{
	DNET_DATA_BEGIN();
	return m_data->data
		.data<struct dnet_addr>();
	DNET_DATA_END(0);
}

struct dnet_cmd *callback_result_entry::command() const
{
	DNET_DATA_BEGIN();
	return m_data->data
		.skip<struct dnet_addr>()
		.data<struct dnet_cmd>();
	DNET_DATA_END(0);
}

data_pointer callback_result_entry::data() const
{
	DNET_DATA_BEGIN();
	return m_data->data
		.skip<struct dnet_addr>()
		.skip<struct dnet_cmd>();
	DNET_DATA_END(0);
}

uint64_t callback_result_entry::size() const
{
	return (m_data->data.size() <= (sizeof(struct dnet_addr) + sizeof(struct dnet_cmd)))
		? (0)
		: (m_data->data.size() - (sizeof(struct dnet_addr) + sizeof(struct dnet_cmd)));
}

read_result_entry::read_result_entry()
{
}

read_result_entry::read_result_entry(const read_result_entry &other) : callback_result_entry(other)
{
}

read_result_entry::~read_result_entry()
{
}

read_result_entry &read_result_entry::operator =(const read_result_entry &other)
{
	callback_result_entry::operator =(other);
	return *this;
}

struct dnet_io_attr *read_result_entry::io_attribute() const
{
	DNET_DATA_BEGIN();
	return data()
		.data<struct dnet_io_attr>();
	DNET_DATA_END(sizeof(dnet_io_attr));
}

data_pointer read_result_entry::file() const
{
	DNET_DATA_BEGIN();
	return data()
		.skip<struct dnet_io_attr>();
	DNET_DATA_END(sizeof(dnet_io_attr));
}

lookup_result_entry::lookup_result_entry()
{
}

lookup_result_entry::lookup_result_entry(const lookup_result_entry &other) : callback_result_entry(other)
{
}

lookup_result_entry::~lookup_result_entry()
{
}

lookup_result_entry &lookup_result_entry::operator =(const lookup_result_entry &other)
{
	callback_result_entry::operator =(other);
	return *this;
}

struct dnet_addr *lookup_result_entry::storage_address() const
{
	DNET_DATA_BEGIN();
	return data()
		.data<struct dnet_addr>();
	DNET_DATA_END(sizeof(dnet_addr));
}

struct dnet_file_info *lookup_result_entry::file_info() const
{
	DNET_DATA_BEGIN();
	return data()
		.skip<struct dnet_addr>()
		.data<struct dnet_file_info>();
	DNET_DATA_END(sizeof(dnet_addr) + sizeof(dnet_file_info));
}

const char *lookup_result_entry::file_path() const
{
	DNET_DATA_BEGIN();
	return data()
		.skip<struct dnet_addr>()
		.skip<struct dnet_file_info>()
		.data<char>();
	DNET_DATA_END(sizeof(dnet_addr) + sizeof(dnet_file_info) + sizeof(char));
}

monitor_stat_result_entry::monitor_stat_result_entry()
{}

monitor_stat_result_entry::monitor_stat_result_entry(const monitor_stat_result_entry &other)
: callback_result_entry(other)
{}

monitor_stat_result_entry::~monitor_stat_result_entry()
{}

monitor_stat_result_entry &monitor_stat_result_entry::operator =(const monitor_stat_result_entry &other)
{
	callback_result_entry::operator =(other);
	return *this;
}

std::string monitor_stat_result_entry::statistics() const
{
	DNET_DATA_BEGIN();
	return ioremap::monitor::decompress(data().to_string());
	DNET_DATA_END(0);
}

node_status_result_entry::node_status_result_entry()
{}

node_status_result_entry::node_status_result_entry(const node_status_result_entry &other)
: callback_result_entry(other)
{}

node_status_result_entry::~node_status_result_entry()
{}

node_status_result_entry &node_status_result_entry::operator =(const node_status_result_entry &other)
{
	callback_result_entry::operator =(other);
	return *this;
}

struct dnet_node_status *node_status_result_entry::node_status() const
{
	DNET_DATA_BEGIN();
	return data()
		.data<struct dnet_node_status>();
	DNET_DATA_END(sizeof(struct dnet_node_status));
}

exec_result_entry::exec_result_entry()
{
}

exec_result_entry::exec_result_entry(const std::shared_ptr<callback_result_data> &data)
	: callback_result_entry(data)
{
}

exec_result_entry::exec_result_entry(const exec_result_entry &other) : callback_result_entry(other)
{
}

exec_result_entry::~exec_result_entry()
{
}

exec_result_entry &exec_result_entry::operator =(const exec_result_entry &other)
{
	callback_result_entry::operator =(other);
	return *this;
}

exec_context exec_result_entry::context() const
{
	if (m_data->error)
		m_data->error.throw_error();
	return m_data->context;
}

iterator_result_entry::iterator_result_entry()
{
}

iterator_result_entry::iterator_result_entry(const iterator_result_entry &other) : callback_result_entry(other)
{
}

iterator_result_entry::~iterator_result_entry()
{
}

iterator_result_entry &iterator_result_entry::operator =(const iterator_result_entry &other)
{
	callback_result_entry::operator =(other);
	return *this;
}

dnet_iterator_response *iterator_result_entry::reply() const
{
	return data<dnet_iterator_response>();
}

uint64_t iterator_result_entry::id() const
{
	return reply()->id;
}

data_pointer iterator_result_entry::reply_data() const
{
	DNET_DATA_BEGIN();
	return data().skip<dnet_iterator_response>();
	DNET_DATA_END(sizeof(dnet_iterator_response));
}

//
// Iterator container
//

static const size_t MAX_ITERATOR_RESULT_CHUNK_SIZE = 500 * 1024 * 1024; // 500 Mb
static const size_t MAX_ITERATOR_RESULT_ITEMS_IN_CHUNK = MAX_ITERATOR_RESULT_CHUNK_SIZE / sizeof(struct dnet_iterator_response);

static inline bool compare_iterator_responses(const struct dnet_iterator_response &lhs, const struct dnet_iterator_response &rhs)
{
	int diff = dnet_id_cmp_str(lhs.key.id, rhs.key.id);

	if (diff == 0) {
		diff = dnet_time_cmp(&rhs.timestamp, &lhs.timestamp);
		if (diff == 0) {
			if (lhs.size > rhs.size)
				diff = -1;
			if(lhs.size < rhs.size)
				diff = 1;
		}
	}

	return diff == -1;
}

class iterator_result_chunk
{
public:
	iterator_result_chunk(int fd, uint64_t offset, size_t num_items)
	: m_fd{fd}
	, m_offset{offset}
	, m_num_items{num_items}
	, m_buffer_index{0}
	, m_num_processed_items{0}
	{}

	int sort() const
	{
		std::vector<struct dnet_iterator_response> items(m_num_items);
		const size_t items_size = m_num_items * sizeof(struct dnet_iterator_response);

		int err = dnet_read_ll(m_fd, reinterpret_cast<char *>(items.data()), items_size, m_offset);
		if (err)
			return err;

		std::sort(items.begin(), items.end(), compare_iterator_responses);

		return dnet_write_ll(m_fd, reinterpret_cast<char *>(items.data()), items_size, m_offset);
	}

	const struct dnet_iterator_response &get_item() const
	{
		return m_buffer[m_buffer_index];
	}

	bool next()
	{
		if (++m_num_processed_items >= m_num_items)
			return false;

		if (++m_buffer_index >= m_buffer.size()) {
			m_buffer_index = 0;
			if (read_buffer() != 0)
				return false;
		}
		return true;
	}

	int set_num_buffer_items(size_t num_buffer_items)
	{
		m_buffer.resize(num_buffer_items);
		return read_buffer();
	}

private:
	int read_buffer()
	{
		const auto remaining_items = std::min(m_buffer.size(), m_num_items - m_num_processed_items);
		const auto buffer_size = remaining_items * sizeof(struct dnet_iterator_response);
		const auto offset = m_offset + m_num_processed_items * sizeof(struct dnet_iterator_response);
		return dnet_read_ll(m_fd, reinterpret_cast<char *>(m_buffer.data()), buffer_size, offset);
	}

private:
	int m_fd;
	const uint64_t m_offset;
	const size_t m_num_items;

	std::vector<struct dnet_iterator_response> m_buffer;
	size_t m_buffer_index;
	size_t m_num_processed_items;
};

struct ChunksComparator
{
	bool operator () (const iterator_result_chunk *lhs, const iterator_result_chunk *rhs) const
	{
		return compare_iterator_responses(rhs->get_item(), lhs->get_item());
	}
};

//* Append one result to container
void iterator_result_container::append(const iterator_result_entry &result)
{
	append(result.reply());
}

void iterator_result_container::append(const dnet_iterator_response *response)
{
	static const ssize_t resp_size = sizeof(dnet_iterator_response);
	int err;

	if (m_sorted)
		throw_error(-EROFS, "can't append to already sorted container");

	err = dnet_iterator_response_container_append(response, m_fd, m_write_position);
	if (err != 0)
		throw_error(err, "dnet_iterator_response_container_append() failed");
	m_write_position += resp_size;
	m_count++;
}

//* Sort container by (key, timestamp) tuple
void iterator_result_container::sort()
{
	if (m_sorted == true)
		return;

	if (m_write_position % sizeof(struct dnet_iterator_response) != 0)
		throw_error(-EINVAL, "invalid container size");

	int err;
	std::vector<std::shared_ptr<iterator_result_chunk> > chunks;

	uint64_t offset = 0;
	while (offset < m_write_position) {
		const auto num_remaining_items = (m_write_position - offset) / sizeof(struct dnet_iterator_response);
		const size_t num_chunk_items = std::min(num_remaining_items, MAX_ITERATOR_RESULT_ITEMS_IN_CHUNK);

		auto chunk = std::make_shared<iterator_result_chunk>(m_fd, offset, num_chunk_items);
		err = chunk->sort();
		if (err != 0)
			throw_error(err, "chunk sort failed");

		chunks.push_back(chunk);
		offset += num_chunk_items * sizeof(struct dnet_iterator_response);
	}

	if (chunks.size() > 1) {
		const size_t num_buffer_items = std::max<size_t>(1, MAX_ITERATOR_RESULT_ITEMS_IN_CHUNK / chunks.size());

		std::priority_queue<iterator_result_chunk *, std::vector<iterator_result_chunk *>, ChunksComparator> pq;
		for (const auto &chunk : chunks) {
			err = chunk->set_num_buffer_items(num_buffer_items);
			if (err != 0)
				throw_error(err, "read chunk failed");
			pq.push(chunk.get());
		}

		char *file;
		err = dnet_fd_readlink(m_fd, &file);
		if (err < 0)
			throw_error(err, "read link failed");

		std::string old_path(file);
		free(file);
		std::string file_path(old_path + ".sort");

		int fd = open(file_path.c_str(), O_RDWR | O_CLOEXEC | O_TRUNC | O_CREAT, 0644);
		if (fd == -1)
			throw_error(-errno, "create result file failed");

		offset = 0;
		while (!pq.empty()) {
			auto chunk = pq.top();

			err = dnet_write_ll(fd, reinterpret_cast<const char *>(&chunk->get_item()),
					    sizeof(struct dnet_iterator_response), offset);
			if (err) {
				close(fd);
				throw_error(err, "write result failed");
			}
			offset += sizeof(struct dnet_iterator_response);

			pq.pop();
			if (chunk->next()) {
				pq.push(chunk);
			}
		}

		if (dup2(fd, m_fd) == -1) {
			close(fd);
			throw_error(-errno, "dup2 failed");
		}

		close(fd);
		if (rename(file_path.c_str(), old_path.c_str()) == -1)
			throw_error(-errno, "rename failed");
	}

	m_sorted = true;
}

//* Compute diff between `this' and \a other, put it to \a result
void iterator_result_container::diff(const iterator_result_container &other,
		iterator_result_container &result) const
{
	int64_t err;

	if (m_sorted == false || other.m_sorted == false)
		throw_error(-EINVAL, "both containers must be sorted");

	err = dnet_iterator_response_container_diff(result.m_fd, m_fd, m_write_position,
			other.m_fd, other.m_write_position);
	if (err < 0)
		throw_error(err, "diff failed");

	result.m_write_position = err;
	result.m_count = result.m_write_position / sizeof(dnet_iterator_response);
	result.m_sorted = true;
}

//* Extract n-th item from container
dnet_iterator_response iterator_result_container::operator [](size_t n) const
{
	dnet_iterator_response response;
	int err;

	err = dnet_iterator_response_container_read(m_fd, n * sizeof(response), &response);
	if (err != 0)
		throw_error(err, "dnet_iterator_response_container_read failed");
	return response;
}

backend_status_result_entry::backend_status_result_entry()
{
}

backend_status_result_entry::backend_status_result_entry(const backend_status_result_entry &other) : callback_result_entry(other)
{
}

backend_status_result_entry::~backend_status_result_entry()
{
}

backend_status_result_entry &backend_status_result_entry::operator =(const backend_status_result_entry &other)
{
	callback_result_entry::operator =(other);
	return *this;
}

dnet_backend_status_list *backend_status_result_entry::list() const
{
	DNET_DATA_BEGIN();
	return data()
		.data<dnet_backend_status_list>();
	DNET_DATA_END(sizeof(dnet_backend_status_list));
}

uint32_t backend_status_result_entry::count() const
{
	return list()->backends_count;
}

dnet_backend_status *backend_status_result_entry::backend(uint32_t index) const
{
	DNET_DATA_BEGIN();
	return data()
		.skip<dnet_backend_status_list>()
		.skip(index * sizeof(dnet_backend_status))
		.data<dnet_backend_status>();
	DNET_DATA_END(sizeof(dnet_backend_status_list) + (index + 1) * sizeof(dnet_backend_status));
}

} } // namespace ioremap::elliptics
