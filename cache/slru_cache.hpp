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

#ifndef SLRU_CACHE_HPP
#define SLRU_CACHE_HPP

#include <thread>

#include "cache.hpp"

class dnet_backend;

namespace ioremap { namespace cache {

class slru_cache_t {
public:
	slru_cache_t(struct dnet_node *n,
	             dnet_backend &backend,
	             const std::vector<size_t> &cache_pages_max_sizes,
	             unsigned sync_timeout,
	             bool &need_exit);

	~slru_cache_t();

	write_response_t write(dnet_net_state *st, dnet_cmd *cmd, const write_request &request);

	read_response_t read(const unsigned char *id, uint64_t ioflags);

	int remove(const dnet_cmd *cmd, ioremap::elliptics::dnet_remove_request &request);

	read_response_t lookup(const unsigned char *id);

	void clear();

	cache_stats get_cache_stats() const;

private:
	dnet_backend &m_backend;
	struct dnet_node *m_node;
	std::mutex m_lock;
	size_t m_cache_pages_number;
	std::vector<size_t> m_cache_pages_max_sizes;
	std::vector<size_t> m_cache_pages_sizes;
	std::unique_ptr<lru_list_t[]> m_cache_pages_lru;
	std::thread m_lifecheck;
	treap_t m_treap;
	mutable cache_stats m_cache_stats;
	bool m_clear_occured;
	unsigned m_sync_timeout;
	const bool &m_need_exit;

	slru_cache_t(const slru_cache_t &) = delete;

	bool need_exit() const;

	size_t get_next_page_number(size_t page_number) const {
		if (page_number == 0) {
			return 0;
		}
		return page_number - 1;
	}

	size_t get_previous_page_number(size_t page_number) const {
		return page_number + 1;
	}

	int check_cas(const data_t* it, const dnet_cmd *cmd, const write_request &request) const;

	void sync_if_required(data_t* it, elliptics_unique_lock<std::mutex> &guard);

	void insert_data_into_page(const unsigned char *id, size_t page_number, data_t *data);

	void remove_data_from_page(const unsigned char *id, size_t page_number, data_t *data);

	void move_data_between_pages(const unsigned char *id,
	                             size_t source_page_number,
	                             size_t destination_page_number,
	                             data_t *data);

	data_t *create_data(const unsigned char *id,
	                    const ioremap::elliptics::data_pointer &json,
	                    const ioremap::elliptics::data_pointer &data,
	                    bool remove_from_disk);

	data_t *populate_from_disk(elliptics_unique_lock<std::mutex> &guard,
	                           const unsigned char *id,
	                           bool remove_from_disk,
	                           int *err);

	bool have_enough_space(const unsigned char *id, size_t page_number, size_t reserve);

	void resize_page(const unsigned char *id, size_t page_number, size_t reserve);

	void erase_element(data_t *obj);

	void sync_element(const dnet_id &raw,
	                  bool after_append,
	                  uint64_t user_flags,
	                  const std::string &json,
	                  const dnet_time &json_ts,
	                  const std::string &data,
	                  const dnet_time &data_ts);

	void sync_element(data_t *obj);

	void sync_after_append(elliptics_unique_lock<std::mutex> &guard, bool lock_guard, data_t *obj);

	void life_check(void);
};

}} /* namespace ioremap::cache */


#endif // SLRU_CACHE_HPP
