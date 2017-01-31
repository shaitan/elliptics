/*
 * Copyright 2013+ Kirill Smorodinnikov <shaitkir@gmail.com>
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

#include <chrono>

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

	uint64_t parse_request(size_t size);

	monitor &m_monitor;
	boost::asio::ip::tcp::socket m_socket;

	const std::string m_remote;
	std::array<char, 1024> m_buffer;
	std::string m_response;
	std::string m_url;

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

		m_recv_ts = std::chrono::system_clock::now();

		const auto req = parse_request(size);

		m_response = make_reply(req, [&]() {
			if (req == 0)
				return std::string();

			DNET_LOG_DEBUG(m_monitor.node(),
			               "monitor: http-server: got statistics request for categories: {:x} from: {}",
			               req, m_remote);
			return m_monitor.get_statistics().report(req);
		}());

		m_collect_ts = std::chrono::system_clock::now();

		async_write();

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
			const auto endpoint = m_socket.local_endpoint();
			const auto address = endpoint.address();

			std::ostringstream stream;
			stream << "http://" << to_string(m_socket.local_endpoint(), true) << m_url;
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
 * Parses simple HTTP request and determines requested category
 * @packet - HTTP request packet
 * @size - size of HTTP request packet
 */
uint64_t handler::parse_request(size_t size) {
	static const std::string categories_url = "/?categories=";
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

	const char *packet = m_buffer.data();
	const char* end = packet + size;
	const char *method_end = std::find(packet, end, ' ');
	if (method_end >= end || packet == method_end)
		return 0;

	const char *url_begin = method_end + 1;
	const char *url_end = std::find(url_begin, end, ' ');
	if (url_end >= end)
		return 0;

	m_url = std::string(url_begin, url_end);

	auto it = handlers.find(m_url);
	if (it != handlers.end()) {
		return it->second;
	} else if (ssize_t(categories_url.size()) < (url_end - url_begin) &&
	           strncmp(url_begin, categories_url.c_str(), categories_url.size()) == 0) {
		const char *categories = url_begin + categories_url.size();
		try {
			return std::stoull(std::string(categories, url_end));
		} catch(...) {
			DNET_LOG_ERROR(m_monitor.node(), "Can't parse categories: {}", categories);
		}
	}

	return 0;
}

}} /* namespace ioremap::monitor */
