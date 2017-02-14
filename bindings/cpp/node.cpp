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

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sstream>
#include <vector>

#include <blackhole/wrapper.hpp>

#include "node_p.hpp"
#include "library/elliptics.h"

namespace ioremap { namespace elliptics {

node::node(std::unique_ptr<dnet_logger> logger)
: m_data(std::make_shared<node_data>(std::move(logger))) {
	struct dnet_config cfg;

	memset(&cfg, 0, sizeof(cfg));

	cfg.wait_timeout = 5;
	cfg.check_timeout = 20;
	cfg.log = m_data->logger.get();

	m_data->node_ptr = dnet_node_create(&cfg);
	if (!m_data->node_ptr) {
		throw std::bad_alloc();
	}
}

node::node(std::unique_ptr<dnet_logger> logger, dnet_config &cfg)
: m_data(std::make_shared<node_data>(std::move(logger))) {
	cfg.log = m_data->logger.get();

	m_data->node_ptr = dnet_node_create(&cfg);
	if (!m_data->node_ptr) {
		throw std::bad_alloc();
	}
}

node::node(const node &other) : m_data(other.m_data)
{}

node::~node()
{}

node &node::operator =(const node &other)
{
	m_data = other.m_data;
	return *this;
}

bool node::is_valid() const
{
	return !!m_data;
}

void node::add_remote(const address &addr)
{
	if (!m_data)
		throw_error(-EINVAL, "Failed to add remote addr to null node");

	int err = dnet_add_state(m_data->node_ptr, &addr.to_raw(), 1, 0);
	if (err < 0) {
		throw_error(err, "Failed to add remote addr %s", addr.to_string().c_str());
	}
}

void node::add_remote(const std::vector<address> &addrs)
{
	if (!m_data)
		throw_error(-EINVAL, "Failed to add remote addr to null node");

	static_assert(sizeof(address) == sizeof(dnet_addr), "size of address is not equal to size of dnet_addr");

	// It's safe to cast address to dnet_addr as their size are equal
	int err = dnet_add_state(m_data->node_ptr, reinterpret_cast<const dnet_addr *>(addrs.data()), addrs.size(), 0);
	if (err < 0) {
		throw_error(err, "Failed to add remote %zd addrs", addrs.size());
	}
}

void node::set_timeouts(const int wait_timeout, const int check_timeout)
{
	if (m_data)
		dnet_set_timeouts(m_data->node_ptr, wait_timeout, check_timeout);
}

void node::set_keepalive(int idle, int cnt, int interval)
{
	if (m_data)
		dnet_set_keepalive(m_data->node_ptr, idle, cnt, interval);
}

std::unique_ptr<dnet_logger> node::get_logger() const {
	return std::unique_ptr<dnet_logger>(new blackhole::wrapper_t(*m_data->logger, {}));
}

dnet_node *node::get_native() const
{
	return m_data ? m_data->node_ptr : NULL;
}

} } // namespace ioremap::elliptics
