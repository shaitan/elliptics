#include "elliptics/newapi/result_entry.hpp"
#include "library/protocol.hpp"
#include "library/elliptics.h"

#include <algorithm>
#include <fcntl.h>
#include <queue>

namespace ioremap { namespace elliptics { namespace newapi {

data_pointer callback_result_entry::raw() const {
	return ioremap::elliptics::callback_result_entry::raw_data();
}

data_pointer callback_result_entry::raw_data() const {
	return ioremap::elliptics::callback_result_entry::data();
}

std::string lookup_result_entry::path() const {
	dnet_lookup_response response;

	deserialize(raw_data(), response);
	return response.path;
}

dnet_record_info lookup_result_entry::record_info() const {
	dnet_record_info info;
	memset(&info, 0, sizeof(info));

	dnet_lookup_response response;

	deserialize(raw_data(), response);

	info.record_flags = response.record_flags;
	info.user_flags = response.user_flags;

	info.json_timestamp = response.json_timestamp;
	info.json_offset = response.json_offset;
	info.json_size = response.json_size;
	info.json_capacity = response.json_capacity;

	info.data_timestamp = response.data_timestamp;
	info.data_offset = response.data_offset;
	info.data_size = response.data_size;
	// info.data_capacity = response.data_capacity;

	return info;
}

dnet_record_info read_result_entry::record_info() const {
	dnet_record_info info;
	memset(&info, 0, sizeof(info));

	dnet_read_response response;

	deserialize(raw_data(), response);

	info.record_flags = response.record_flags;
	info.user_flags = response.user_flags;

	info.json_timestamp = response.json_timestamp;
	info.json_size = response.json_size;
	info.json_capacity = response.json_capacity;

	info.data_timestamp = response.data_timestamp;
	info.data_size = response.data_size;

	return info;
}

dnet_io_info read_result_entry::io_info() const {
	dnet_io_info info;
	memset(&info, 0, sizeof(info));

	dnet_read_response response;
	deserialize(raw_data(), response);

	info.json_size = response.read_json_size;
	info.data_offset = response.read_data_offset;
	info.data_size = response.read_data_size;

	return info;
}

data_pointer read_result_entry::json() const {
	size_t offset = 0;
	dnet_read_response response;

	deserialize(raw_data(), response, offset);

	return raw_data().slice(offset, response.read_json_size);
}

data_pointer read_result_entry::data() const {
	size_t offset = 0;
	dnet_read_response response;

	deserialize(raw_data(), response, offset);

	return raw_data().slice(offset + response.read_json_size, response.read_data_size);
}

dnet_raw_id iterator_result_entry::key() const {
	dnet_iterator_response response;
	deserialize(raw_data(), response);

	return response.key;
}

uint64_t iterator_result_entry::iterator_id() const {
	dnet_iterator_response response;
	deserialize(raw_data(), response);

	return response.iterator_id;
}

uint64_t iterator_result_entry::iterated_keys() const {
	dnet_iterator_response response;
	deserialize(raw_data(), response);

	return response.iterated_keys;
}

uint64_t iterator_result_entry::total_keys() const {
	dnet_iterator_response response;
	deserialize(raw_data(), response);

	return response.total_keys;
}

int iterator_result_entry::status() const {
	dnet_iterator_response response;
	deserialize(raw_data(), response);

	return response.status;
}

dnet_record_info iterator_result_entry::record_info() const {
	dnet_iterator_response response;
	deserialize(raw_data(), response);

	dnet_record_info info;
	memset(&info, 0, sizeof(info));

	info.record_flags = response.record_flags;
	info.user_flags = response.user_flags;

	info.json_timestamp = response.json_timestamp;
	info.json_size = response.json_size;
	info.json_capacity = response.json_capacity;

	info.data_timestamp = response.data_timestamp;
	info.data_offset = response.data_offset;
	info.data_size = response.data_size;
	return info;
}

uint64_t iterator_result_entry::blob_id() const {
	dnet_iterator_response response;
	deserialize(raw_data(), response);

	return response.blob_id;
}

data_pointer iterator_result_entry::json() const {
	size_t offset = 0;
	dnet_iterator_response response;

	deserialize(raw_data(), response, offset);

	return raw_data().slice(offset, response.read_json_size);
}

data_pointer iterator_result_entry::data() const {
	size_t offset = 0;
	dnet_iterator_response response;

	deserialize(raw_data(), response, offset);

	return raw_data().slice(offset + response.read_json_size, response.read_data_size);
}

//
// Iterator container
//

static const size_t MAX_ITERATOR_RESULT_CHUNK_SIZE = 500 * 1024 * 1024; // 500 Mb
static const size_t MAX_ITERATOR_RESULT_ITEMS_IN_CHUNK = MAX_ITERATOR_RESULT_CHUNK_SIZE / sizeof(struct iterator_container_item);

static inline bool compare_iterator_container_items(const struct iterator_container_item &lhs, const struct iterator_container_item &rhs)
{
	int diff = dnet_id_cmp_str(lhs.key.id, rhs.key.id);

	if (diff == 0) {
		diff = dnet_time_cmp(&rhs.data_timestamp, &lhs.data_timestamp);
		if (diff == 0) {
			diff = dnet_time_cmp(&rhs.json_timestamp, &lhs.json_timestamp);
			if (diff == 0) {
				if (lhs.data_size > rhs.data_size)
					diff = -1;
				if (lhs.data_size < rhs.data_size)
					diff = 1;
			}
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
		std::vector<struct iterator_container_item> items(m_num_items);
		const size_t items_size = m_num_items * sizeof(iterator_container_item);

		int err = dnet_read_ll(m_fd, reinterpret_cast<char *>(items.data()), items_size, m_offset);
		if (err)
			return err;

		std::sort(items.begin(), items.end(), compare_iterator_container_items);

		return dnet_write_ll(m_fd, reinterpret_cast<char *>(items.data()), items_size, m_offset);
	}

	const struct iterator_container_item &get_item() const
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
		const auto buffer_size = remaining_items * sizeof(iterator_container_item);
		const auto offset = m_offset + m_num_processed_items * sizeof(iterator_container_item);
		return dnet_read_ll(m_fd, reinterpret_cast<char *>(m_buffer.data()), buffer_size, offset);
	}

private:
	int m_fd;
	const uint64_t m_offset;
	const size_t m_num_items;

	std::vector<iterator_container_item> m_buffer;
	size_t m_buffer_index;
	size_t m_num_processed_items;
};

struct ChunksComparator
{
	bool operator () (const iterator_result_chunk *lhs, const iterator_result_chunk *rhs) const
	{
		return compare_iterator_container_items(rhs->get_item(), lhs->get_item());
	}
};

//* Append one result to container
void iterator_result_container::append(const iterator_result_entry &result)
{
	if (m_sorted)
		throw_error(-EROFS, "can't append to already sorted container");

	dnet_iterator_response dnet_response;
	deserialize(result.raw_data(), dnet_response);

	iterator_container_item item;
	item.key = dnet_response.key;
	item.status = dnet_response.status;
	item.record_flags = dnet_response.record_flags;
	item.user_flags = dnet_response.user_flags;
	item.json_timestamp = dnet_response.json_timestamp;
	item.json_size = dnet_response.json_size;
	item.json_capacity = dnet_response.json_capacity;
	item.data_timestamp = dnet_response.data_timestamp;
	item.data_size = dnet_response.data_size;
	item.data_offset = dnet_response.data_offset;
	item.blob_id = dnet_response.blob_id;

	append_item(item);
}

void iterator_result_container::append_old(const ioremap::elliptics::iterator_result_entry &result)
{
	if (m_sorted)
		throw_error(-EROFS, "can't append to already sorted container");

	iterator_container_item item;
	auto reply = result.reply();
	item.key = reply->key;
	item.status = reply->status;
	item.record_flags = reply->flags;
	item.user_flags = reply->user_flags;
	item.data_timestamp = reply->timestamp;
	item.data_size = reply->size;

	append_item(item);
}

void iterator_result_container::append_item(const iterator_container_item &item)
{
	int err = dnet_write_ll(m_fd, reinterpret_cast<const char *>(&item), sizeof(item), m_write_position);
	if (err != 0)
		throw_error(err, "dnet_write_ll failed");
	m_write_position += sizeof(item);
	m_count++;
}

//* Sort container by (key, data_timestamp, json_timestamp, data_size) tuple
void iterator_result_container::sort()
{
	if (m_sorted)
		return;

	if (m_write_position % sizeof(iterator_container_item) != 0)
		throw_error(-EINVAL, "invalid container size");

	int err;
	std::vector<std::shared_ptr<iterator_result_chunk> > chunks;

	uint64_t offset = 0;
	while (offset < m_write_position) {
		const auto num_remaining_items = (m_write_position - offset) / sizeof(iterator_container_item);
		const size_t num_chunk_items = std::min(num_remaining_items, MAX_ITERATOR_RESULT_ITEMS_IN_CHUNK);

		auto chunk = std::make_shared<iterator_result_chunk>(m_fd, offset, num_chunk_items);
		err = chunk->sort();
		if (err != 0)
			throw_error(err, "chunk sort failed");

		chunks.push_back(chunk);
		offset += num_chunk_items * sizeof(iterator_container_item);
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
					    sizeof(iterator_container_item), offset);
			if (err) {
				close(fd);
				throw_error(err, "write result failed");
			}
			offset += sizeof(iterator_container_item);

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

//* Extract n-th item from container
iterator_container_item iterator_result_container::operator [](size_t n) const
{
	iterator_container_item item;
	int err;

	err = dnet_read_ll(m_fd, reinterpret_cast<char *>(&item), sizeof(item), n * sizeof(item));
	if (err != 0)
		throw_error(err, "dnet_read_ll failed");
	return item;
}

}}} // namespace ioremap::elliptics::newapi
