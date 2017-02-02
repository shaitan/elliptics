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

#ifndef __DNET_MONITOR_SERVER_HPP
#define __DNET_MONITOR_SERVER_HPP

#include <thread>

#include <boost/asio.hpp>

namespace ioremap { namespace monitor {

class monitor;

/*!
 * Server class which is responsible for:
 *    listening incoming connection
 *    handling simple GET HTTP request
 *    sends simple HTTP response with json statistics of specified category
 */
class server {
public:
	server(const server &) = delete;
	/*!
	 * Constructor: initializes server for @mon to listen @port
	 */
	server(monitor &mon, unsigned short port, int family);

	/*!
	 * Destructor: stops server and freeing all data
	 */
	~server();

	/*!
	 * Stops listening incoming connection and sending responses
	 */
	void stop();

private:
	/*!
	 * Asynchronously accepts incoming connections
	 */
	void async_accept();

	/*!
	 * Monitor that creates server
	 */
	monitor &m_monitor;
	/*!
	 * boost::asio kitchen for asynchronous work with sockets
	 */
	boost::asio::io_service m_io_service;
	boost::asio::ip::tcp::acceptor m_acceptor;

	/*!
	 * Thread for executing boost::asio
	 */
	std::thread m_listen;
};
}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_SERVER_HPP */
