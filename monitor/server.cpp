/*
 * Copyright 2013+ Kirill Smorodinnikov <shaitkir@gmail.com>
 * Copyright 2018+ Artem Ikchurin <artem.ikchurin@gmail.com>
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
 * You should have received a copy of the GNU General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "server.hpp"
#include "monitor.hpp"
#include "http_request.hpp"

#include <chrono>

#include <blackhole/attribute.hpp>

#include "library/elliptics.h"
#include "library/logger.hpp"
#include "http_miscs.hpp"

namespace ioremap { namespace monitor {
std::string to_string(const boost::asio::ip::tcp::endpoint &endpoint, bool use_bracket=false) {
	std::ostringstream stream;
	const auto &address = endpoint.address();
	if (address.is_v6() && address.to_v6().is_v4_mapped()) {
		stream << address.to_v6().to_v4() << ":" << endpoint.port();
	} else if (use_bracket) {
		stream << endpoint;
	} else {
		stream << address << ":" << endpoint.port();
	}
	return stream.str();
}

class handler : public std::enable_shared_from_this<handler> {
public:
	handler(monitor &mon, boost::asio::ip::tcp::socket socket)
	: m_monitor(mon)
	, m_socket(std::move(socket))
	, m_remote(to_string(m_socket.remote_endpoint())) {}

	void start() {
		DNET_LOG_INFO(m_monitor.node(), "monitor: http-server: accepted client: {}", m_remote);
		async_read();
	}

private:
	void async_read();
	void async_write();
	void close();

	request parse_request();

	http_request m_http_request;

	monitor &m_monitor;
	boost::asio::ip::tcp::socket m_socket;

	const std::string m_remote;
	std::array<char, 1024> m_buffer;
	std::string m_response;

	std::chrono::time_point<std::chrono::system_clock> m_start_ts;
	std::chrono::time_point<std::chrono::system_clock> m_recv_ts;
	std::chrono::time_point<std::chrono::system_clock> m_collect_ts;
};

inline static boost::asio::ip::tcp convert_family(int family) {
	return family == AF_INET6 ? boost::asio::ip::tcp::v6() : boost::asio::ip::tcp::v4();
}

server::server(monitor &mon, unsigned short port, int family)
: m_monitor(mon)
, m_acceptor(m_io_service, {convert_family(family), port}) {
	m_listen = std::thread([this]() {
		try {
			async_accept();
			m_io_service.run();
		} catch (const std::exception &e) {
			DNET_LOG_ERROR(m_monitor.node(),
			               "monitor: http-server: got exception: {}, exiting", e.what());
		} catch (...) {
			DNET_LOG_ERROR(m_monitor.node(),
			               "monitor: http-server: got unknown exception, exiting");
		}

		dnet_set_need_exit(m_monitor.node());
	});
}

server::~server() {
	stop();
	m_listen.join();
}

void server::async_accept() {
	auto socket = std::make_shared<boost::asio::ip::tcp::socket>(m_io_service);
	m_acceptor.async_accept(*socket, [socket, this](const boost::system::error_code &err) {
		if (!err) {
			std::make_shared<handler>(m_monitor, std::move(*socket))->start();
		}

		async_accept();
	});
}

void server::stop() {
	m_acceptor.close();
	m_io_service.stop();
}

void handler::async_read() {
	auto self(shared_from_this());

	m_start_ts = std::chrono::system_clock::now();
	m_socket.async_read_some(boost::asio::buffer(m_buffer), [self, this](const boost::system::error_code &err,
	                                                                     size_t size) {
		if (err) {
			DNET_LOG_ERROR(m_monitor.node(), "monitor: http-server: failed to receive request: {}",
			               err.message());
			close();
			return;
		}
		if (!m_http_request.parse(m_buffer.data(), size)) {
			DNET_LOG_ERROR(m_monitor.node(), "monitor: http-server: failed to parse request url: {},"
			                                 " from {}: {} [{}]",
			               m_http_request.url(), m_remote,
			               m_http_request.error(), m_http_request.error_code());
			close();
			return;
		}
		if (m_http_request.ready()) {
			m_recv_ts = std::chrono::system_clock::now();
			const auto request = parse_request();
			m_response = make_reply(request.categories, [&]() {
				if (request.categories == 0)
					return std::string();

				DNET_LOG_DEBUG(m_monitor.node(), "monitor: http-server: "
				                                 "got statistics request for categories: {:x} from: {}",
				               request.categories, m_remote);
				return m_monitor.get_statistics().report(request);
			}());

			m_collect_ts = std::chrono::system_clock::now();

			async_write();
		} else {
			async_read();
		}
	});
}

void handler::async_write() {
	DNET_LOG_DEBUG(m_monitor.node(), "monitor: http-server: send requested statistics: started: {}, size: {}",
	               m_remote, m_response.size());

	auto self(shared_from_this());

	boost::asio::async_write(m_socket, boost::asio::buffer(m_response), [self,
	                                                                     this](const boost::system::error_code &err,
	                                                                           const long unsigned int &size) {
		const auto finish_ts = std::chrono::system_clock::now();

		if (err) {
			DNET_LOG_ERROR(m_monitor.node(), "monitor: http-server: failed to send response: {}",
			               err.message());
			return;
		}

		DNET_LOG_DEBUG(m_monitor.node(), "monitor: http-server: send requested statistics: finished: {}",
		               m_remote);

		const auto full_url = [this]() {
			std::ostringstream stream;
			stream << "http://" << to_string(m_socket.local_endpoint(), true) << m_http_request.url();
			return stream.str();
		}();

		DNET_LOG_INFO(m_monitor.node(), "monitor: http-server: client: {}, url: \"{}\", response-size: {}, "
		                                "recv-time: {} usecs, collect-time: {} usecs, send-time: {} usecs, "
		                                "total-time: {} usecs",
		              m_remote, full_url, size,
		              std::chrono::duration_cast<std::chrono::microseconds>(m_recv_ts - m_start_ts).count(),
		              std::chrono::duration_cast<std::chrono::microseconds>(m_collect_ts - m_recv_ts).count(),
		              std::chrono::duration_cast<std::chrono::microseconds>(finish_ts - m_collect_ts).count(),
		              std::chrono::duration_cast<std::chrono::microseconds>(finish_ts - m_start_ts).count());

		close();
	});
}

void handler::close() {
	boost::system::error_code ec;
	m_socket.shutdown(boost::asio::socket_base::shutdown_both, ec);
	m_socket.close(ec);
}

/*!
 * Parses HTTP request and determines statictics request
 кор*/
request handler::parse_request() {
	static const std::map<std::string, uint64_t> handlers = {
		{"/all", DNET_MONITOR_ALL},
		{"/cache", DNET_MONITOR_CACHE},
		{"/io", DNET_MONITOR_IO},
		{"/commands", DNET_MONITOR_COMMANDS},
		{"/backend", DNET_MONITOR_BACKEND},
		{"/stats", DNET_MONITOR_STATS},
		{"/procfs", DNET_MONITOR_PROCFS},
		{"/top", DNET_MONITOR_TOP}
	};

	request req;

	auto it = handlers.find(m_http_request.path());
	if (it != handlers.end()) {
		req.categories = it->second;
	} else if (m_http_request.path() == "/") {
		auto it = m_http_request.query().find("categories");
		if (it != m_http_request.query().end()) {
			try {
				req.categories = std::stoull(it->second);
			} catch (...) {
				DNET_LOG_ERROR(m_monitor.node(), "monitor: http-server: Can't parse categories: {}",
				               it->second);
				return request();
			}
		}
	} else {
		DNET_LOG_ERROR(m_monitor.node(), "monitor: http-server: request parser: Unknown path: {}",
		               m_http_request.path());
		return request();
	}

	const auto backends_item = m_http_request.query().find("backends");
	if (backends_item != m_http_request.query().end()) {
		std::string id_list = backends_item->second;
		char *id = std::strtok(const_cast<char*>(id_list.c_str()), ",");
		while (id != NULL) {
			try {
				req.backends_ids.insert(std::stoul(id, nullptr, 10));
			} catch (...) {
				DNET_LOG_ERROR(m_monitor.node(), "monitor: http-server: Can't parse backend ids: {}",
				               backends_item->second);
				return request();
			}
			id = std::strtok(NULL, ",");
		}
	}

	return req;
}

}} /* namespace ioremap::monitor */
