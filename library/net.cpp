/*
 * Copyright 2008+ Evgeniy Polyakov <zbr@ioremap.net>
 * Copyright 2014+ Ruslan Nigmatullin <euroelessar@yandex.ru>
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

#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/eventfd.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>

#include <netinet/tcp.h>

#include <set>
#include <boost/scope_exit.hpp>

#include <blackhole/attribute.hpp>

#include "bindings/cpp/timer.hpp"

#include "access_context.h"
#include "elliptics.h"
#include "elliptics/packet.h"
#include "elliptics/interface.h"
#include "common.hpp"
#include "protocol.hpp"
#include "logger.hpp"
#include "n2_protocol.hpp"
#include "old_protocol/serialize.hpp"
#include "tests.h"


enum dnet_socket_state {
	just_created = 0,
	trying_to_connect,
	started,
	send_reverse,
	recv_reverse,
	recv_reverse_data,
	recv_route_list,
	finished,
	failed
};

/*
 * This is internal structure used to help batch socket creation.
 * Socket @s will be set to negative value in case of error.
 * @ok will be set to 1 if given socket was successfully initialized (connected or made listened)
 */
struct dnet_addr_socket {
	dnet_addr_socket(dnet_node *node, const dnet_addr *address, bool ask_route_list_arg)
	: s(create_socket(node, address, 0)),
	 ok(0),
	 addr(*address),
	 state(just_created),
	 ask_route_list(ask_route_list_arg)
	{}

	~dnet_addr_socket() {
		close();
	}

	dnet_addr_socket(const dnet_addr_socket &) = delete;
	dnet_addr_socket & operator = (const dnet_addr_socket &) = delete;

	static int create_socket(dnet_node *node, const dnet_addr *address, int listening) {
		socklen_t salen;
		sockaddr *sa;
		dnet_net_state *st;
		int s;
		int err;

		st = dnet_state_search_by_addr(node, address);
		if (st) {
			err = -EEXIST;

			DNET_LOG_NOTICE(node, "Address {} already exists in route table", dnet_addr_string(address));
			dnet_state_put(st);
			return err;
		}

		salen = address->addr_len;
		sa = (sockaddr *)address;

		sa->sa_family = address->family;

		s = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
		if (s < 0) {
			err = -errno;

			DNET_LOG_ERROR(node, "Failed to create socket for {}: family: {}", dnet_addr_string(address),
			               sa->sa_family);
			return err;
		}

		fcntl(s, F_SETFL, O_NONBLOCK);
		fcntl(s, F_SETFD, FD_CLOEXEC);

		if (listening) {
			err = 1;
			setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &err, 4);

			err = bind(s, sa, salen);
			if (err) {
				err = -errno;
				DNET_LOG_ERROR(node, "Failed to bind to {}", dnet_addr_string(address));
				return err;
			}

			err = listen(s, 10240);
			if (err) {
				err = -errno;
				DNET_LOG_ERROR(node, "Failed to listen at {}", dnet_addr_string(address));
				return err;
			}

			DNET_LOG_INFO(node, "Server is now listening at {}", dnet_addr_string(address));
		} else {
			DNET_LOG_INFO(node, "Added {} to connect list", dnet_addr_string(address));
		}

		return s;
	}

	void close() {
		if (s >= 0) {
			::close(s);
			s = -1;
		}
	}

	int s;
	int ok;
	dnet_addr addr;
	dnet_socket_state state;
	dnet_cmd io_cmd;
	std::unique_ptr<char[]> buffer;
	char *io_data;
	size_t io_size;
	int version[4];
	bool ask_route_list;
};

typedef std::shared_ptr<dnet_addr_socket> dnet_addr_socket_ptr;

struct dnet_addr_socket_comparator
{
	bool operator () (const dnet_addr_socket_ptr &first, const dnet_addr_socket_ptr &second) {
		return first->addr < second->addr;
	}
};

typedef std::set<dnet_addr_socket_ptr, dnet_addr_socket_comparator> dnet_addr_socket_set;

struct dnet_connect_state
{
	dnet_connect_state()
	: lock_inited(false),
	 node(nullptr),
	 epollfd(-1),
	 interruptfd(-1),
	 failed_count(0),
	 succeed_count(0),
	 total_count(0),
	 finished(false)
	{
		atomic_set(&route_request_count, 0);
	}

	~dnet_connect_state() {
		if (lock_inited)
			pthread_mutex_destroy(&lock);
		if (epollfd >= 0)
			close(epollfd);
		if (interruptfd >= 0)
			close(interruptfd);
	}

	atomic_t route_request_count;
	pthread_mutex_t lock;
	bool lock_inited;
	dnet_node *node;
	int epollfd;
	int interruptfd;
	dnet_join_state join;
	size_t failed_count;
	size_t succeed_count;
	size_t total_count;
	dnet_addr_socket_set sockets_connected;
	dnet_addr_socket_set sockets_queue;
	bool finished;
};

typedef std::shared_ptr<dnet_connect_state> dnet_connect_state_ptr;

typedef std::vector<dnet_addr> net_addr_list;

/*!
 * Adds \a addr to reconnect list, so we will try to connect to it somewhere in the future.
 *
 * The \a addr will be really added to state only in case if it's error "is good enough",
 * we don't want to try to reconnect to nodes, to which we a hopeless to connect.
 */
static void dnet_add_to_reconnect_list(dnet_node *node, const dnet_addr &addr, int error, dnet_join_state join)
{
	if (error == -EEXIST) {
		return;
	}

	DNET_LOG_NOTICE(node, "{}: could not add state, its error: {}", dnet_addr_string(&addr), error);

	if ((error == -ENOMEM) ||
		(error == -EBADF)) {
		return;
	}

	dnet_add_reconnect_state(node, &addr, join);
}

/*!
 * Marks socket as failed one.
 *
 * This function removes it's socket from epoll, if needed;
 * closes socket, if possible; and adds to reconnect list, also, if possible
 */
static void dnet_fail_socket(const dnet_connect_state_ptr &state, dnet_addr_socket *socket,
		int error, bool remove_from_epoll = true)
{
	if (remove_from_epoll)
		epoll_ctl(state->epollfd, EPOLL_CTL_DEL, socket->s, NULL);

	state->failed_count++;
	if (socket->s >= 0)
		close(socket->s);
	socket->s = error;
	socket->state = failed;

	dnet_add_to_reconnect_list(state->node, socket->addr, error, state->join);
}

/*!
 * Adds new event for this socket to epoll, if failed - marks socket as failed one
 */
static bool dnet_epoll_ctl(const dnet_connect_state_ptr &state, dnet_addr_socket *socket, uint32_t operation,  uint32_t events)
{
	epoll_event ev;
	ev.events = events;
	ev.data.ptr = socket;

	int err = epoll_ctl(state->epollfd, operation, socket->s, &ev);
	if (err < 0) {
		int err = -errno;
		DNET_LOG_ERROR(state->node, "Could not add {} address to epoll set, operation: {}, events: {}",
		               dnet_addr_string(&socket->addr), operation, events);
		dnet_fail_socket(state, socket, err, operation == EPOLL_CTL_ADD);
		return false;
	}

	return true;
}

/*!
 * Tries to read as much as possible from socket's socket without blocking the thread, but not more than it's needed.
 *
 * On unrecoverable fail marks socket as failed.
 */
static bool dnet_recv_nolock(const dnet_connect_state_ptr &state, dnet_addr_socket *socket)
{
	ssize_t err = recv(socket->s, socket->io_data, socket->io_size, 0);
	if (err < 0) {
		if (errno != EAGAIN && errno != EINTR) {
			err = -errno;
			DNET_LOG_ERROR(state->node, "{}: failed to receive data, socket: {}",
			               dnet_addr_string(&socket->addr), socket->s);
			dnet_fail_socket(state, socket, err);
		}
		return false;
	}

	if (err == 0) {
		DNET_LOG_ERROR(state->node, "{}: peer has disconnected, socket: {}", dnet_addr_string(&socket->addr),
		               socket->s);
		dnet_fail_socket(state, socket, -ECONNRESET);
		return false;
	}

	socket->io_data = reinterpret_cast<char *>(socket->io_data) + err;
	socket->io_size -= err;

	if (socket->io_size == 0)
		return true;

	return false;
}

/*!
 * Tries to write as much as possible to socket's socket without blocking the thread, but not more than it's needed.
 *
 * On unrecoverable fail marks socket as failed.
 */
static bool dnet_send_nolock(const dnet_connect_state_ptr &state, dnet_addr_socket *socket)
{
	ssize_t err = send(socket->s, socket->io_data, socket->io_size, 0);
	if (err < 0) {
		err = -errno;
		if (err != -EAGAIN) {
			DNET_LOG_ERROR(state->node, "{}: failed to send packet: size: {}, socket: {}",
			               dnet_addr_string(&socket->addr), (unsigned long long)socket->io_size, socket->s);
			dnet_fail_socket(state, socket, err);
			return false;
		}

		return false;
	}

	if (err == 0) {
		DNET_LOG_ERROR(state->node, "Peer {} has dropped the connection: socket: {}",
		               dnet_addr_string(&socket->addr), socket->s);
		err = -ECONNRESET;
		dnet_fail_socket(state, socket, err);
		return false;
	}

	socket->io_data = socket->io_data + err;
	socket->io_size -= err;

	if (socket->io_size == 0)
		return true;

	return false;
}

/*
 * Returns true if address @addr equals to one of the listening node's addresses.
 * In this case we should not try to connect to it - connection will be dropped with -EEXIST status later.
 */
static bool dnet_addr_is_local(dnet_node *n, const dnet_addr *addr)
{
	for (int i = 0; i < n->addr_num; ++i) {
		if (dnet_addr_equal(addr, &n->addrs[i]))
			return true;
	}

	return false;
}

/*!
 * \brief dnet_socket_create_addresses creates a socket per each passed address,
 * returns array of allocated dnet_addr_sockets, their number is returned by addrs_count property.
 * If no sockets were created, NULL is returned, @at_least_one_exists is set if at least one address
 * already exists in local route table.
 *
 * This method actually doesn't connect to remote hosts or binds to local addresses.
 *
 * All sockets are sorted by their address, so we are able quickly to lookup if there are already such sockets.
 */
static dnet_addr_socket_set dnet_socket_create_addresses(dnet_node *node, const dnet_addr *addrs, size_t addrs_count,
					 bool ask_route_list, dnet_join_state join, bool *at_least_one_exist)
{
	dnet_addr_socket_set result;
	*at_least_one_exist = false;

	for (size_t i = 0; i < addrs_count; ++i) {
		if (dnet_addr_is_local(node, &addrs[i]))
			continue;

		auto socket = std::make_shared<dnet_addr_socket>(node, &addrs[i], ask_route_list);
		if (socket->s >= 0) {
			DNET_LOG_DEBUG(
			        node,
			        "dnet_socket_create_addresses: socket for state {} created successfully, socket: {}",
			        dnet_addr_string(&addrs[i]), socket->s);
			result.insert(socket);
		} else {
			const int err = socket->s;
			if (err == -EEXIST) {
				*at_least_one_exist = true;
			} else {
				dnet_add_to_reconnect_list(node, addrs[i], err, join);

				DNET_LOG_ERROR(
				        node,
				        "dnet_socket_create_addresses: failed to create a socket for state {}, err: {}",
				        dnet_addr_string(&addrs[i]), err);
			}
		}
	}

	return result;
}

/*!
 * Interrupts epoll, so it's possible to send data from 'some' thread to epoll's one
 */
static void dnet_interrupt_epoll(dnet_connect_state &state)
{
	uint64_t counter = 1;
	int err = ::write(state.interruptfd, &counter, sizeof(uint64_t));
	(void) err;
}

static int dnet_validate_route_list(const char *server_addr, dnet_node *node, struct dnet_cmd *cmd)
{
	dnet_addr_container *cnt;
	long size;
	int err, i;
	char rem_addr[128];

	err = cmd->status;
	if (err)
		goto err_out_exit;

	size = cmd->size + sizeof(dnet_cmd);
	if (size < (signed)sizeof(dnet_addr_cmd)) {
		err = -EINVAL;
		goto err_out_exit;
	}

	cnt = (struct dnet_addr_container *)(cmd + 1);
	dnet_convert_addr_container(cnt);

	if (cmd->size != sizeof(dnet_addr) * cnt->addr_num + sizeof(dnet_addr_container)) {
		err = -EINVAL;
		goto err_out_exit;
	}

	/* only compare addr-num if we are server, i.e. joined node, clients do not have local addresses at all */
	if (node->addr_num && (cnt->node_addr_num != node->addr_num)) {
		DNET_LOG_ERROR(node, "{}: invalid route list reply: recv-addr-num: {}, local-addr-num: {}", server_addr,
		               int(cnt->node_addr_num), node->addr_num);
		err = -EINVAL;
		goto err_out_exit;
	}

	if (cnt->node_addr_num == 0
		|| cnt->addr_num % cnt->node_addr_num != 0) {
		DNET_LOG_ERROR(node, "{}: invalid route list reply: recv-addr-num: {}, rec-node-addr-num: {}",
		               server_addr, int(cnt->addr_num), int(cnt->node_addr_num));
		err = -EINVAL;
		goto err_out_exit;
	}

	for (i = 0; i < cnt->addr_num; ++i) {
		if (dnet_empty_addr(&cnt->addrs[i])) {
			DNET_LOG_ERROR(node, "{}: received zero address route reply, aborting route update",
			               server_addr);
			err = -ENOTTY;
			goto err_out_exit;
		}

		DNET_LOG_DEBUG(node, "route-list: from: {}, node: {}, addr: {}", server_addr, i / cnt->node_addr_num,
		               dnet_addr_string_raw(&cnt->addrs[i], rem_addr, sizeof(rem_addr)));
	}

err_out_exit:
	return err;
}

class dnet_request_route_list_handler
{
public:
	dnet_request_route_list_handler(const dnet_connect_state_ptr &st)
	: m_state(st)
	{}

	static int complete_wrapper(dnet_addr *addr, dnet_cmd *cmd, void *priv)
	{
		auto handler = reinterpret_cast<dnet_request_route_list_handler *>(priv);
		int err = safe_call(handler, &dnet_request_route_list_handler::complete, addr, cmd);
		if (is_trans_destroyed(cmd))
			delete handler;
		return err;
	}

private:
	int complete(dnet_addr *addr, dnet_cmd *cmd)
	{
		dnet_node *node = m_state->node;

		char server_addr[128];
		dnet_addr_string_raw(addr, server_addr, sizeof(server_addr));

		int err;
		if (is_trans_destroyed(cmd)) {
			err = -EINVAL;
			if (cmd)
				err = cmd->status;

			atomic_dec(&m_state->route_request_count);
			dnet_interrupt_epoll(*m_state);

			DNET_LOG_NOTICE(node, "Received route-list reply from state: {}, route_request_count: {}",
			                server_addr, atomic_read(&m_state->route_request_count));

			return err;
		}

		err = dnet_validate_route_list(server_addr, node, cmd);
		if (err) {
			DNET_LOG_NOTICE(node, "Received invalid route-list reply from state: {}: {}", server_addr, err);
			return err;
		}


		dnet_net_state *st = dnet_state_search_by_addr(node, addr);
		if (!st) {
			DNET_LOG_NOTICE(node, "Received route-list reply from unknown (destroyed?) state: {}",
			                server_addr);
			err = -ENOENT;
			return err;
		}


		dnet_addr_container *cnt = reinterpret_cast<dnet_addr_container *>(cmd + 1);
		const size_t states_num = cnt->addr_num / cnt->node_addr_num;

		std::vector<dnet_addr> addrs(states_num);
		dnet_addr_socket_set sockets;
		size_t sockets_count;
		bool added_to_queue = false;
		bool at_least_one_exist = false;

		for (size_t i = 0; i < states_num; ++i) {
			const dnet_addr *addr = &cnt->addrs[i * cnt->node_addr_num + st->idx];
			addrs[i] = *addr;
		}

		sockets = dnet_socket_create_addresses(node, &addrs[0], addrs.size(), false, m_state->join, &at_least_one_exist);
		if (sockets.empty()) {
			err = at_least_one_exist ? 0 : -ENOMEM;
			dnet_state_put(st);
			return err;
		}

		sockets_count = sockets.size();

		pthread_mutex_lock(&m_state->lock);

		if (!m_state->finished) {
			m_state->sockets_queue.insert(sockets.begin(), sockets.end());
			added_to_queue = true;
		}

		pthread_mutex_unlock(&m_state->lock);

		if (added_to_queue) {
			dnet_interrupt_epoll(*m_state);

			DNET_LOG_INFO(node, "Trying to connect to additional {} states of {} original from "
			                    "route_list_recv, state: {}, route_request_count: {}",
			              sockets_count, states_num, server_addr,
			              atomic_read(&m_state->route_request_count));
		} else {
			DNET_LOG_ERROR(node, "Failed to connect to additional {} states of {} original from "
			                     "route_list_recv, state: {}, state is already destroyed, adding to "
			                     "reconnect list",
			               sockets_count, states_num, server_addr);

			for (auto it = sockets.cbegin(); it != sockets.cend(); ++it) {
				const dnet_addr_socket_ptr &socket = *it;

				socket->close();
				dnet_add_to_reconnect_list(node, socket->addr, -ETIMEDOUT, m_state->join);
			}
		}

		dnet_state_put(st);
		return 0;
	}

private:
	dnet_connect_state_ptr m_state;
};

/*!
 * Requests route list, every unknown node from reply will be added to state's connection queue.
 */
static void dnet_request_route_list(const dnet_connect_state_ptr &state, dnet_net_state *st)
{
	auto handler = new dnet_request_route_list_handler(state);
	int err = dnet_recv_route_list(st, dnet_request_route_list_handler::complete_wrapper, handler);
	if (!err) {
		atomic_inc(&state->route_request_count);
		DNET_LOG_NOTICE(state->node, "Sent route-list request to state: {}, route_request_count: {}",
		                dnet_state_dump_addr(st), atomic_read(&state->route_request_count));
	}
}

/*!
 * Adds new sockets from \a list to connection queue and add all of them to epoll.
 *
 * If some addresses are already in the queue - they are skipped
 */
static void dnet_socket_connect_new_sockets(const dnet_connect_state_ptr &state, dnet_addr_socket_set &list)
{
	state->total_count += list.size();

	for (auto it = list.begin(); it != list.end(); ++it) {
		const dnet_addr_socket_ptr &socket = *it;

		if (socket->s < 0) {
			state->failed_count++;
			continue;
		}

		const bool already_exist = state->sockets_connected.find(socket) != state->sockets_connected.end();
		if (already_exist) {
			DNET_LOG_NOTICE(state->node, "we are already connected to {}", dnet_addr_string(&socket->addr));

			dnet_fail_socket(state, socket.get(), -EEXIST, false);
			continue;
		}

		socket->state = trying_to_connect;

		socklen_t salen = socket->addr.addr_len;
		sockaddr *sa = (sockaddr *)&socket->addr;

		int err = connect(socket->s, sa, salen);
		if (err < 0) {
			err = -errno;
			if (err != -EINPROGRESS) {
				DNET_LOG_ERROR(state->node, "Failed to connect to {}", dnet_addr_string(&socket->addr));
				dnet_fail_socket(state, socket.get(), err, false);
				continue;
			}
		}

		if (dnet_epoll_ctl(state, socket.get(), EPOLL_CTL_ADD, EPOLLOUT)) {
			state->sockets_connected.insert(socket);
		}
	}
}

/*!
 * This method is state machine for socket's processing, it's invoked on every epoll's event.
 *
 * It's implemented in synchronous-like way for easier understanding and developing.
 * It's always known that it's called from only one possible thread, so there are no locks around the state.
 *
 * All logic can be split to different big blocks with some io-operations between them,
 * each block has it's own equivalent in socket's state enum, so we are able to jump to
 * current block's code by simple switch.
 */
static void dnet_process_socket(const dnet_connect_state_ptr &state, epoll_event &ev)
{
	if (ev.data.ptr == &state->interruptfd) {
		DNET_LOG_NOTICE(state->node, "Caught signal from interruptfd, list: {}",
		                static_cast<int>(state->sockets_queue.empty()));

		dnet_addr_socket_set local_queue;

		pthread_mutex_lock(&state->lock);
		local_queue = std::move(state->sockets_queue);
		pthread_mutex_unlock(&state->lock);

		dnet_socket_connect_new_sockets(state, local_queue);

		DNET_LOG_NOTICE(state->node, "Received route-list reply: count: {}, route_request_count: {}",
		                local_queue.size(), atomic_read(&state->route_request_count));

		return;
	}

	dnet_addr_socket *socket = reinterpret_cast<dnet_addr_socket *>(ev.data.ptr);
	dnet_cmd *cmd = &socket->io_cmd;

	DNET_LOG_DEBUG(state->node, "{}: socket: {}, state: {}", dnet_addr_string(&socket->addr), socket->s,
	               socket->state);

	switch (socket->state) {
	case trying_to_connect: {
		int status, err;
		socklen_t slen = 4;

		err = getsockopt(socket->s, SOL_SOCKET, SO_ERROR, &status, &slen);
		if (err || status) {
			if (status)
				err = -status;

			DNET_LOG_ERROR(state->node, "{}: failed to connect, status: {}: {} [{}]",
			               dnet_addr_string(&socket->addr), status, strerror(-err), err);

			dnet_fail_socket(state, socket, err);
			break;
		}

		DNET_LOG_NOTICE(state->node, "{}: successfully connected, sending reverse lookup command",
		                dnet_addr_string(&socket->addr));

		socket->state = started;
		// Fall through
	}
	case started:
		memset(cmd, 0, sizeof(dnet_cmd));

		cmd->flags = DNET_FLAGS_DIRECT | DNET_FLAGS_NOLOCK;
		cmd->cmd = DNET_CMD_REVERSE_LOOKUP;

		dnet_version_encode(&cmd->id);
		dnet_convert_cmd(cmd);

		socket->state = send_reverse;
		socket->io_data = reinterpret_cast<char*>(cmd);
		socket->io_size = sizeof(dnet_cmd);

		// Fall through
	case send_reverse:
		if (!dnet_send_nolock(state, socket))
			break;

		socket->io_data = reinterpret_cast<char*>(cmd);
		socket->io_size = sizeof(dnet_cmd);

		if (!dnet_epoll_ctl(state, socket, EPOLL_CTL_MOD, EPOLLIN))
			break;

		socket->state = recv_reverse;
		// Fall through
	case recv_reverse: {
		if (!dnet_recv_nolock(state, socket))
			break;

		int (&version)[4] = socket->version;
		int err;
		dnet_net_state dummy_state;

		memset(&dummy_state, 0, sizeof(dummy_state));
		dummy_state.addr = socket->addr;

		dummy_state.write_s = dummy_state.read_s = socket->state;
		dummy_state.n = state->node;

		dnet_convert_cmd(cmd);
		dnet_version_decode(&cmd->id, version);

		if (cmd->status != 0) {
			err = cmd->status;

			DNET_LOG_ERROR(state->node, "{}: reverse lookup command failed: local version: {}.{}.{}.{}, "
			                            "remote version: {}.{}.{}.{}, error: {} [{}]",
			               dnet_addr_string(&socket->addr), ELLIPTICS_PROTOCOL_VERSION_0,
			               ELLIPTICS_PROTOCOL_VERSION_1, ELLIPTICS_PROTOCOL_VERSION_2,
			               ELLIPTICS_PROTOCOL_VERSION_3, version[0], version[1], version[2], version[3],
			               strerror(-err), err);
			dnet_fail_socket(state, socket, err);
			break;
		}

		err = dnet_version_check(&dummy_state, version);
		if (err) {
			dnet_fail_socket(state, socket, err);
			break;
		}

		socket->buffer.reset(new(std::nothrow) char[cmd->size]);
		if (!socket->buffer) {
			err = -ENOMEM;
			DNET_LOG_ERROR(state->node, "{}: failed to allocate {} bytes for reverse lookup data",
			               dnet_addr_string(&socket->addr), cmd->size);
			dnet_fail_socket(state, socket, err);
			break;
		}

		socket->io_data = socket->buffer.get();
		socket->io_size = cmd->size;

		socket->state = recv_reverse_data;
		// Fall through
	}
	case recv_reverse_data: {
		if (!dnet_recv_nolock(state, socket))
			break;

		dnet_addr_container *cnt = reinterpret_cast<dnet_addr_container *>(socket->buffer.get());
		int err;

		/* If we are server check that connected node has the same number of addresses.
		 * At the moment server nodes with different number of addresses can't be connected to each other (for
		 * example, node with ipv4+ipv6 addresses cannot be connected with node with the only ipv4 address).
		 */
		if (state->node->addr_num && (cnt->addr_num != state->node->addr_num)) {
			err = -EINVAL;
			DNET_LOG_ERROR(state->node, "{}: received dnet_addr_container is invalid: recv-addr-num: {}, "
			                            "local-addr-num: {}, err: {}",
			               dnet_addr_string(&socket->addr), cnt->addr_num, state->node->addr_num, err);
			dnet_fail_socket(state, socket, err);
			break;
		}

		if (cmd->size < sizeof(dnet_addr_container) + cnt->addr_num * sizeof(dnet_addr) + sizeof(dnet_id_container)) {
			err = -EINVAL;
			DNET_LOG_ERROR(
			        state->node,
			        "{}: received dnet_addr_container is invalid: size: {}, expected at least: {}, err: {}",
			        dnet_addr_string(&socket->addr), cmd->size,
			        sizeof(dnet_addr_container) + cnt->addr_num * sizeof(dnet_addr) +
			                sizeof(dnet_id_container),
			        err);
			dnet_fail_socket(state, socket, err);
			break;
		}

		dnet_convert_addr_container(cnt);

		size_t size = cmd->size - sizeof(dnet_addr) * cnt->addr_num - sizeof(dnet_addr_container);
		dnet_id_container *id_container = reinterpret_cast<dnet_id_container *>(
			socket->buffer.get() + sizeof(dnet_addr) * cnt->addr_num + sizeof(dnet_addr_container)
		);

		err = dnet_validate_id_container(id_container, size);
		if (err) {
			DNET_LOG_ERROR(state->node, "connected-to-addr: {}: failed to validate id container: {}",
			               dnet_addr_string(&socket->addr), err);
			dnet_fail_socket(state, socket, err);
			break;
		}

		int idx = -1;
		for (int i = 0; i < cnt->addr_num; ++i) {
			if (dnet_empty_addr(&cnt->addrs[i])) {
				DNET_LOG_ERROR(state->node, "connected-to-addr: {}: received wildcard (like 0.0.0.0) "
				                            "addr: backends: {}, addr-num: {}, idx: {}",
				               dnet_addr_string(&socket->addr), id_container->backends_count,
				               cnt->addr_num, idx);
				err = -EPROTO;
				dnet_fail_socket(state, socket, err);
				break;
			}

			if (dnet_addr_equal(&socket->addr, &cnt->addrs[i])) {
				idx = i;
				break;
			}
		}
		if (idx == -1) {
			err = -EPROTO;
			DNET_LOG_ERROR(state->node, "{}: there is no connected addr in received reverse lookup data",
			               dnet_addr_string(&socket->addr));
			dnet_fail_socket(state, socket, err);
			break;
		}

		struct dnet_backend_ids **backends =
			(struct dnet_backend_ids **)malloc(id_container->backends_count * sizeof(struct dnet_backends_id *));
		if (!backends) {
			err = -ENOMEM;
			dnet_fail_socket(state, socket, err);
			break;
		}

		dnet_id_container_fill_backends(id_container, backends);

		for (int i = 0; i < id_container->backends_count; ++i) {
			struct dnet_backend_ids *backend = backends[i];

			for (uint32_t j = 0; j < backend->ids_count; ++j) {
				DNET_LOG_NOTICE(state->node, "connected-to-addr: {}: received backends: {}/{}, ids: "
				                             "{}/{}, addr-num: {}, idx: {}, backend_id: {}, group_id: "
				                             "{}, id: {}",
				                dnet_addr_string(&socket->addr), i, id_container->backends_count, j,
				                backend->ids_count, cnt->addr_num, idx, backend->backend_id,
				                backend->group_id, dnet_dump_id_str(backend->ids[j].id));
			}
		}

		epoll_ctl(state->epollfd, EPOLL_CTL_DEL, socket->s, NULL);

		dnet_net_state *st = dnet_state_create(state->node,
				backends, id_container->backends_count,
				&socket->addr, socket->s,
				&err, state->join, 1, idx, 0,
				cnt->addrs, cnt->addr_num);

		free(backends);

		// this socket lives in state now, socket will be closed if state creation has failed
		socket->s = -1;

		if (!st) {
			DNET_LOG_ERROR(state->node,
			               "Could not create state: {}, backends-num: {}, addr-num: {}, idx: {}, err: {}",
			               dnet_addr_string(&socket->addr), id_container->backends_count, cnt->addr_num,
			               idx, err);

			/* socket is closed already */
			dnet_fail_socket(state, socket, err, false);
			break;
		}

		memcpy(st->version, socket->version, sizeof(st->version));

		DNET_LOG_INFO(state->node, "Connected to {}, backends-num: {}, addr-num: {}, idx: {}, socket: {}/{}",
		              dnet_addr_string(&socket->addr), id_container->backends_count, cnt->addr_num, idx,
		              st->read_s, st->write_s);

		socket->buffer.reset();
		state->succeed_count++;
		socket->ok = 1;

		if (socket->ask_route_list) {
			dnet_request_route_list(state, st);
		}

		// @dnet_net_state() returns state with 2 reference counters
		dnet_state_put(st);
		socket->state = finished;
		break;
	}
	case just_created:
	case recv_route_list:
	case finished:
	case failed:
		DNET_LOG_ERROR(state->node,
		               "Socket was epolled in state: {}, which is impossible, state: {}, socket: {}",
		               socket->state, dnet_addr_string(&socket->addr), socket->s);
		break;
	}
}

struct net_state_list_destroyer
{
	net_state_list_destroyer() : count(0)
	{
	}

	net_state_list_destroyer(size_t count) : count(count)
	{
	}

	void operator ()(dnet_net_state **list)
	{
		if (!list) {
			return;
		}

		for (size_t i = 0; i < count; ++i) {
			if (list[i])
				dnet_state_put(list[i]);
		}

		free(list);
	}

	size_t count;
};

typedef std::unique_ptr<dnet_net_state *[], net_state_list_destroyer> net_state_list_ptr;

/*!
 * Asynchronously connects to nodes from original_list, asks them route_list, if needed,
 * and continues connecting to new nodes in addition to originally passed one.
 *
 * This function exits only if timeout is exceeded or if all connection operations have either failed or succeeded.
 * It returns either negative error value or positive number of successfully connected sockets.
 *
 * \a original_list will be freed by call of this function
 *
 * @states_count contains number of already connected valid sockets in @states array.
 * This function sends route request to those sockets and resets the array.
 */
static int dnet_socket_connect(dnet_node *node, dnet_addr_socket_set &original_list, dnet_join_state join,
	net_state_list_ptr states, size_t states_count)
{
	int err;
	long timeout;
	epoll_event ev;

	auto state = std::make_shared<dnet_connect_state>();

	state->node = node;
	state->join = join;

	err = pthread_mutex_init(&state->lock, NULL);
	if (err) {
		DNET_LOG_ERROR(state->node, "Failed to initialize mutex: {}", err);
		goto err_out_put;
	}

	state->lock_inited = true;
	state->epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (state->epollfd < 0) {
		err = -errno;
		DNET_LOG_ERROR(state->node, "Could not create epoll handler");
		goto err_out_put;
	}

	// this file descriptor is used to pass information from io thread to current one
	// for example it's used to pass here replies from route-list requests
	state->interruptfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (state->interruptfd < 0) {
		err = -errno;
		DNET_LOG_ERROR(state->node, "Could not create eventfd interrupter");
		close(state->epollfd);
		goto err_out_put;
	}

	ev.events = EPOLLIN | EPOLLET;
	ev.data.ptr = &state->interruptfd;
	err = epoll_ctl(state->epollfd, EPOLL_CTL_ADD, state->interruptfd, &ev);
	if (err) {
		err = -errno;
		DNET_LOG_ERROR(state->node, "Could not epoll eventfd interrupter, fd: {}", state->interruptfd);
		goto err_out_put;
	}

	// send route request to already connected states
	if (!(state->node->flags & DNET_CFG_NO_ROUTE_LIST)) {
		for (size_t i = 0; i < states_count; ++i) {
			dnet_request_route_list(state, states[i]);
		}
	}

	states.reset();

	dnet_socket_connect_new_sockets(state, original_list);
	original_list.clear();

	timeout = state->node->wait_ts.tv_sec * 1000 > 2000 ? state->node->wait_ts.tv_sec * 1000 : 2000;
	while (state->succeed_count + state->failed_count < state->total_count ||
	       atomic_read(&state->route_request_count) > 0 || !state->sockets_queue.empty()) {
		const size_t num = 128;
		size_t ready_num;
		epoll_event events[num];

		ioremap::elliptics::util::steady_timer timer;

		err = epoll_wait(state->epollfd, events, num, timeout);
		if (err < 0) {
			DNET_LOG_ERROR(state->node, "Epoll error");
			goto err_out_put;
		}

		if (err == 0) {
			err = -ETIMEDOUT;
			break;
		}

		ready_num = err;

		for (size_t i = 0; i < ready_num; ++i) {
			dnet_process_socket(state, events[i]);
		}

		timeout -= timer.get_ms();

		/*
		 * This is a small hack.
		 * When timeout is that small, epoll will either return ready events or quickly return 0,
		 * which means real timeout and we will drop out of the loop.
		 *
		 * It is needed to give a chance for events which are ready, but were not picked up
		 * by epoll_wait() because of small enough buffer size (see @num above).
		 * Even if that buffer is large enough, epoll_wait() may return just a single event
		 * every time it is invoked, and that will slowly eat original timeout (2 seconds or state->node->wait_ts)
		 *
		 * Eventually timeout becomes negative and we give the last chance of 10 msecs.
		 * If nothing fires, we break out of this loop.
		 */
		if (timeout < 0)
			timeout = 10;
	}

	pthread_mutex_lock(&state->lock);
	state->finished = true;

	state->sockets_connected.insert( state->sockets_queue.begin(), state->sockets_queue.end() );
	state->sockets_queue.clear();

	pthread_mutex_unlock(&state->lock);

err_out_put:
	// Timeout! We need to close every socket where we have not connected yet.

	if (err == 0)
		err = -ECONNREFUSED;

	DNET_LOG_INFO(state->node, "dnet_socket_connect: succeed_count: {}, failed_count: {}, total_count: {}, "
	                           "sockets_connected: {}, sockets_queue: {}, states_count: {}, err: {}",
	              state->succeed_count, state->failed_count, state->total_count, state->sockets_connected.size(),
	              state->sockets_queue.size(), states_count, err);

	for (auto it = state->sockets_connected.begin(); it != state->sockets_connected.end(); ++it) {
		const dnet_addr_socket_ptr &socket = *it;

		if (socket->s < 0)
			continue;

		if (!socket->ok) {
			close(socket->s);
			socket->s = -ETIMEDOUT;

			DNET_LOG_ERROR(state->node, "Could not connect to {} because of timeout",
			               dnet_addr_string(&socket->addr));

			dnet_add_to_reconnect_list(state->node, socket->addr, -ETIMEDOUT, state->join);
		}
	}

	if (state->succeed_count) {
		err = state->succeed_count;
	} else if (err >= 0) {
		// this may happen when we have only one socket to connect and connect failed
		// epoll will return positive number (1), but @dnet_process_socket() will fail it,
		// yet error is not reset
		err = -ECONNREFUSED;
	}

	return err;
}

int dnet_socket_create_listening(dnet_node *node, const dnet_addr *addr)
{
	return dnet_addr_socket::create_socket(node, addr, 1);
}

static net_state_list_ptr dnet_check_route_table_victims(struct dnet_node *node, size_t *states_count)
{
	*states_count = 0;

	if (node->flags & DNET_CFG_NO_ROUTE_LIST) {
		return net_state_list_ptr();
	}

	const size_t groups_count_limit = 4096;
	const size_t groups_count_random_limit = node->reconnect_batch_size;

	std::unique_ptr<unsigned[], free_destroyer>
		groups(reinterpret_cast<unsigned *>(calloc(groups_count_limit, sizeof(unsigned))));
	if (!groups) {
		return net_state_list_ptr();
	}

	size_t groups_count = 0;
	pthread_mutex_lock(&node->state_lock);

	struct rb_node *it;
	struct dnet_group *g;
	for (it = rb_first(&node->group_root); it; it = rb_next(it)) {
		g = rb_entry(it, struct dnet_group, group_entry);
		groups[groups_count++] = g->group_id;

		if (groups_count >= groups_count_limit)
			break;
	}
	pthread_mutex_unlock(&node->state_lock);

	struct dnet_id id;
	memset(&id, 0, sizeof(id));
	const size_t route_addr_num = node->route_addr_num;
	const size_t total_states_count = route_addr_num + groups_count_random_limit;

	net_state_list_ptr route_list_states(
		reinterpret_cast<dnet_net_state **>(calloc(total_states_count, sizeof(dnet_net_state *))),
		net_state_list_destroyer(total_states_count)
	);

	if (!route_list_states) {
		return net_state_list_ptr();
	}

	pthread_mutex_lock(&node->reconnect_lock);
	for (size_t i = 0; i < std::min(groups_count, groups_count_random_limit); ++i) {
		int rnd = rand();
		id.group_id = groups[rnd % groups_count];

		memcpy(id.id, &rnd, sizeof(rnd));

		struct dnet_net_state *st = dnet_state_get_first(node, &id);
		if (st) {
			route_list_states[(*states_count)++] = st;
		}
	}

	DNET_LOG_INFO(node, "Requesting route address from {} remote addresses", node->route_addr_num);

	for (size_t i = 0; i < node->route_addr_num; ++i) {
		struct dnet_net_state *st = dnet_state_search_by_addr(node, &node->route_addr[i]);
		if (st) {
			route_list_states[(*states_count)++] = st;
		}
	}
	pthread_mutex_unlock(&node->reconnect_lock);

	return route_list_states;
}

static net_addr_list dnet_reconnect_victims(struct dnet_node *node, int *flags)
{
	net_addr_list addrs;

	dnet_pthread_lock_guard locker(node->reconnect_lock);

	if (!node->reconnect_num)
		return addrs;

	size_t addresses_needed = std::min(node->reconnect_batch_size, size_t(node->reconnect_num));
	addrs.reserve(addresses_needed);

	struct dnet_addr_storage *ast, *tmp;
	list_for_each_entry_safe(ast, tmp, &node->reconnect_list, reconnect_entry) {
		if (addrs.size() == addresses_needed)
			break;

		if (auto st = dnet_state_search_by_addr(node, &ast->addr)) {
			dnet_state_put(st);
			// Address is already connected, throw it away from reconnect_list

		} else {
			addrs.push_back(ast->addr);

			if (ast->__join_state == DNET_JOIN)
				(*flags) |= DNET_CFG_JOIN_NETWORK;
		}

		list_del_init(&ast->reconnect_entry);
		free(ast);
		node->reconnect_num--;
	}

	return addrs;
}

void dnet_reconnect_and_check_route_table(dnet_node *node)
{
	size_t states_count = 0;
	int flags = 0;

	net_state_list_ptr states = dnet_check_route_table_victims(node, &states_count);
	net_addr_list addrs = dnet_reconnect_victims(node, &flags);

	dnet_join_state join = DNET_WANT_RECONNECT;
	if (node->flags & DNET_CFG_JOIN_NETWORK)
		join = DNET_JOIN;

	const bool ask_route_list = !((node->flags | flags) & DNET_CFG_NO_ROUTE_LIST);

	bool at_least_one_exist = false;
	auto sockets = dnet_socket_create_addresses(node, &addrs[0], addrs.size(), ask_route_list, join, &at_least_one_exist);

	if (sockets.empty()) {
		addrs.clear();
	}

	if (states_count > 0 || !sockets.empty()) {
		dnet_socket_connect(node, sockets, join, std::move(states), states_count);
	}
}

/*!
 * In parallel adds all nodes from \a addrs to own route table.
 *
 * Each addition is performed in several steps:
 * \li Connect to specified addr
 * \li Send reverse lookup request
 * \li Receive reverse lookup reply
 * \li Send route-table request if needed
 * 	Send route table request if neither \a flags nor node's flags contain DNET_CFG_NO_ROUTE_LIST bit
 * \li Add all new addresses from route-list reply to the same queue
 */
int dnet_add_state(dnet_node *node, const dnet_addr *addrs, int num, int flags)
{
	const bool ask_route_list = !((node->flags | flags) & DNET_CFG_NO_ROUTE_LIST);

	if (num <= 0)
		return -EINVAL;

	dnet_join_state join = DNET_WANT_RECONNECT;
	if (node->flags & DNET_CFG_JOIN_NETWORK)
		join = DNET_JOIN;

	const size_t addrs_count = num;
	bool at_least_one_exist = false;
	auto sockets = dnet_socket_create_addresses(node, addrs, addrs_count, ask_route_list, join, &at_least_one_exist);
	if (sockets.empty()) {
		// return 0 if we failed to connect to any remote node, but there is at least one node in local route table
		return at_least_one_exist ? 0 : -ENOMEM;
	}

	DNET_LOG_INFO(node, "Trying to connect to {} states of {} original", sockets.size(), addrs_count);

	// sockets are freed by dnet_socket_connect
	int err = dnet_socket_connect(node, sockets, join, net_state_list_ptr(), 0);

	if (ask_route_list) {
		pthread_mutex_lock(&node->reconnect_lock);

		dnet_addr *tmp = reinterpret_cast<dnet_addr *>(realloc(node->route_addr,
					(addrs_count + node->route_addr_num) * sizeof(dnet_addr)));
		if (tmp) {
			const size_t old_count = node->route_addr_num;

			// Copy all addrs to explicit route addrs list
			node->route_addr = tmp;
			memcpy(node->route_addr + node->route_addr_num, addrs, sizeof(dnet_addr) * addrs_count);
			node->route_addr_num += addrs_count;

			// Remove all duplicates
			std::sort(node->route_addr, node->route_addr + node->route_addr_num);
			auto it = std::unique(node->route_addr, node->route_addr + node->route_addr_num);
			node->route_addr_num = it - node->route_addr;

			size_t added_count = node->route_addr_num - old_count;

			DNET_LOG_INFO(node, "Added {} states to explicit route list", added_count);
		} else {
			DNET_LOG_ERROR(node, "Failed to add {} states to explicit route list, err: {}", addrs_count,
			               -ENOMEM);
		}

		pthread_mutex_unlock(&node->reconnect_lock);
	}

	return at_least_one_exist ? std::max(0, err) : err;
}

static int dnet_trans_complete_forward(struct dnet_addr * /*addr*/, struct dnet_cmd *cmd, void *priv) {
	auto t = static_cast<dnet_trans *>(priv);
	int err = -EINVAL;

	if (!is_trans_destroyed(cmd)) {
		const uint64_t size = cmd->size;

		cmd->trans = t->rcv_trans;
		cmd->flags |= DNET_FLAGS_REPLY;

		dnet_convert_cmd(cmd);

		err = dnet_send_data(t->orig, cmd, sizeof(struct dnet_cmd), cmd + 1, size, /*context*/ NULL);
	}

	return err;
}

timespec dnet_time_left_to_timeout(dnet_time &deadline) {
	dnet_time current;
	dnet_current_time(&current);
	if (dnet_time_before(&deadline, &current)) {
		return timespec{0, 0};
	}

	static const long second = 1000000000;

	const long diff = (deadline.tsec - current.tsec) * second + (deadline.tnsec - current.tnsec);

	return timespec{
		diff / second,
		diff % second
	};
}

int dnet_trans_forward(struct dnet_io_req *r, struct dnet_net_state *orig, struct dnet_net_state *forward) {
	dnet_cmd *cmd = static_cast<dnet_cmd *>(r->header);

	auto t = dnet_trans_alloc(orig->n, 0);
	if (!t)
		return -ENOMEM;

	t->rcv_trans = cmd->trans;
	cmd->trans = t->cmd.trans = t->trans = atomic_inc(&orig->n->trans);

	memcpy(&t->cmd, cmd, sizeof(*cmd));

	dnet_convert_cmd(cmd);

	t->wait_ts = [&cmd, &t, &r]() -> timespec {
		using namespace ioremap::elliptics;
		auto data_p = data_pointer::from_raw(r->data, cmd->size);

		dnet_time deadline;
		dnet_empty_time(&deadline);
		if (cmd->cmd == DNET_CMD_WRITE_NEW) {
			dnet_write_request request;
			deserialize(data_p, request);
			deadline = request.deadline;
		} else if (cmd->cmd == DNET_CMD_READ_NEW) {
			dnet_read_request request;
			deserialize(data_p, request);
			deadline = request.deadline;
		}

		if (dnet_time_is_empty(&deadline)) {
			return t->wait_ts;
		} else {
			return dnet_time_left_to_timeout(deadline);
		}
	}();

	if (!t->wait_ts.tv_sec && !t->wait_ts.tv_nsec) {
		return -ETIMEDOUT;
	}

	t->command = cmd->cmd;
	t->complete = dnet_trans_complete_forward;
	t->priv = t;

	t->orig = dnet_state_get(orig);
	t->st = dnet_state_get(forward);

	r->st = forward;

	{
		char saddr[128];
		char daddr[128];

		DNET_LOG_INFO(orig->n, "{}: {}: forwarding trans: {} -> {}, trans: {} -> {}",
		              dnet_dump_id(&t->cmd.id), dnet_cmd_string(t->command),
		              dnet_addr_string_raw(&orig->addr, saddr, sizeof(saddr)),
		              dnet_addr_string_raw(&forward->addr, daddr, sizeof(daddr)),
		              t->rcv_trans, t->trans);
	}

	return dnet_trans_send(t, r);
}

dnet_cmd n2_convert_to_response_cmd(dnet_cmd cmd) {
	cmd.flags = (cmd.flags & ~(DNET_FLAGS_NEED_ACK)) | DNET_FLAGS_REPLY;
	return cmd;
}

n2_repliers n2_make_repliers_via_request_queue(dnet_net_state *st, const dnet_cmd &cmd, n2_repliers repliers) {
	auto enqueue_response = [st, cmd = n2_convert_to_response_cmd(cmd)](std::function<int ()> response_holder) {
		std::unique_ptr<n2_response_info>
			response_info(new n2_response_info{ cmd, std::move(response_holder) });

		auto r = static_cast<dnet_io_req *>(calloc(1, sizeof(dnet_io_req)));
		if (!r)
			return -ENOMEM;

		r->io_req_type = DNET_IO_REQ_TYPED_RESPONSE;
		r->response_info = response_info.release();

		r->st = dnet_state_get(st);
		dnet_schedule_io(st->n, r);

		return 0;
	};

	n2_repliers repliers_wrappers;

	repliers_wrappers.on_reply_error = [on_reply_error = std::move(repliers.on_reply_error),
                                            enqueue_response](int errc) -> int {
		return enqueue_response(std::bind(on_reply_error, errc));
	};

	repliers_wrappers.on_reply = [on_reply = std::move(repliers.on_reply),
	                              enqueue_response](const std::shared_ptr<n2_body> &msg) -> int {
		return enqueue_response(std::bind(on_reply, msg));
	};

	return repliers_wrappers;
}

int n2_complete_trans_via_response_holder(dnet_trans *t, n2_response_info *response_info) {
	return c_exception_guard(response_info->response_holder, t->st->n, __FUNCTION__);
}

// TODO(sabramkin): Try rework to n2_trans_alloc_send. In new mechanic we don't need to separate alloc and send
static int n2_trans_send(dnet_trans *t, n2_request_info *request_info) {
	using namespace ioremap::elliptics;

	struct dnet_net_state *st = t->st;
	struct dnet_test_settings test_settings;
	int err;

	dnet_trans_get(t);

	BOOST_SCOPE_EXIT(&t) {
		dnet_trans_put(t);
	} BOOST_SCOPE_EXIT_END

	pthread_mutex_lock(&st->trans_lock);
	err = dnet_trans_insert_nolock(st, t);
	if (!err) {
		dnet_trans_update_timestamp(t);
		dnet_trans_insert_timer_nolock(st, t);
	}
	pthread_mutex_unlock(&st->trans_lock);
	if (err)
		return err;

	if (t->n->test_settings && !dnet_node_get_test_settings(t->n, &test_settings) &&
	    test_settings.commands_mask & (1 << t->command))
		return err;

	auto repliers_wrappers = n2_make_repliers_via_request_queue(st,
	                                                            request_info->request.cmd,
	                                                            std::move(request_info->repliers));

	n2::net_state_get_protocol(st)->send_request(st,
	                                             std::move(request_info->request),
	                                             std::move(repliers_wrappers));

	return err;
}

int n2_trans_forward(n2_request_info *request_info, struct dnet_net_state *orig, struct dnet_net_state *forward) {
	dnet_cmd *cmd = &request_info->request.cmd;

	std::unique_ptr<dnet_trans, void (*)(dnet_trans *)>
		t(dnet_trans_alloc(orig->n, 0), &dnet_trans_put);
	if (!t) {
		return -ENOMEM;
	}

	auto deadline = request_info->request.deadline;
	if (!dnet_time_is_empty(&deadline)) {
		t->wait_ts = dnet_time_left_to_timeout(deadline);
	}

	if (!t->wait_ts.tv_sec && !t->wait_ts.tv_nsec) {
		return -ETIMEDOUT;
	}

	t->repliers = new n2_repliers; // Will be filled at old_protocol::send_request

	t->rcv_trans = cmd->trans; // TODO(sabramkin): Is it necessary in new mechanic?
	t->trans = cmd->trans = atomic_inc(&orig->n->trans);
	t->cmd = *cmd;
	t->command = cmd->cmd;

	t->orig = dnet_state_get(orig); // TODO(sabramkin): Is it necessary in new mechanic?
	t->st = dnet_state_get(forward);

	{
		char saddr[128];
		char daddr[128];

		DNET_LOG_INFO(orig->n, "{}: {}: forwarding trans: {} -> {}, trans: {} -> {}",
		              dnet_dump_id(&t->cmd.id), dnet_cmd_string(t->command),
		              dnet_addr_string_raw(&orig->addr, saddr, sizeof(saddr)),
		              dnet_addr_string_raw(&forward->addr, daddr, sizeof(daddr)),
		              t->rcv_trans, t->trans);
	}

	return n2_trans_send(t.release(), request_info);
}

int n2_send_error_response(struct dnet_net_state *st,
                           struct n2_request_info *req_info,
                           int errc) {
	auto impl = [&] {
		return req_info->repliers.on_reply_error(errc);
	};
	return c_exception_guard(impl, st->n, __FUNCTION__);
}

class cork_guard_t {
public:
	explicit cork_guard_t(int write_socket)
	: write_socket_(write_socket)
	{
		set_cork(1);
	}

	~cork_guard_t() {
		set_cork(0);
	}

private:
	void set_cork(int cork) {
		setsockopt(write_socket_, IPPROTO_TCP, TCP_CORK, &cork, 4);
	}

	const int write_socket_;
};

static int n2_send_cmd(dnet_net_state *st, dnet_cmd *cmd) {
	return dnet_send_nolock(st,
	                        reinterpret_cast<char *>(cmd) + st->send_offset,
	                        sizeof(dnet_cmd) - st->send_offset);
}

static int n2_send_request_impl(dnet_net_state *st, dnet_io_req *r) {
	using namespace ioremap::elliptics;

	if (st->send_offset == 0) {
		clock_gettime(CLOCK_MONOTONIC_RAW, &st->send_start_ts);
		r->queue_time = DIFF_TIMESPEC(r->queue_start_ts, st->send_start_ts);
	}

	int send_error = 0;
	uint64_t send_time = 0;

	const n2_serialized &serialized = *r->serialized;
	const dnet_cmd &cmd = serialized.cmd;

	uint64_t total_size = sizeof(dnet_cmd) + cmd.size;

	dnet_logger_set_trace_id(cmd.trace_id, cmd.flags & DNET_FLAGS_TRACE_BIT);
	enum dnet_log_level level = st->send_offset == 0 ? DNET_LOG_NOTICE : DNET_LOG_DEBUG;
	DNET_LOG(st->n, level, "%s: %s: sending trans: %lld -> %s/%d: size: %llu, cflags: %s, start-sent: "
			       "%zd/%zd, send-queue-time: %lu usecs",
		 dnet_dump_id(&cmd.id), dnet_cmd_string(cmd.cmd), (unsigned long long)cmd.trans,
		 dnet_addr_string(&st->addr), cmd.backend_id, (unsigned long long)cmd.size,
		 dnet_flags_dump_cflags(cmd.flags), st->send_offset, total_size, r->queue_time);

	dnet_cmd cmd_net = cmd;
	dnet_convert_cmd(&cmd_net);

	if (serialized.chunks.empty()) {
		send_error = n2_send_cmd(st, &cmd_net);

	} else {
		cork_guard_t cork_guard(st->write_s);

		if (st->send_offset < sizeof(dnet_cmd)) {
			send_error = n2_send_cmd(st, &cmd_net);
		}

		if (!send_error) {
			size_t current_block_offset = sizeof(dnet_cmd);

			for (const auto &dp : serialized.chunks) {
				size_t current_block_end_offset = current_block_offset + dp.size();
				if (st->send_offset < current_block_end_offset) /*block hasn't sent*/ {
					auto dp_left = dp.skip(st->send_offset - current_block_offset);
					send_error = dnet_send_nolock(st, dp_left.data(), dp_left.size());
					if (send_error)
						break;
				}

				current_block_offset = current_block_end_offset;
			}
		}
	}

	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	send_time = DIFF_TIMESPEC(st->send_start_ts, ts);
	level = DNET_LOG_DEBUG;
	if (!send_error) {
		level = !(cmd.flags & DNET_FLAGS_MORE) ? DNET_LOG_INFO : DNET_LOG_NOTICE;
		if (r->context) {
			r->context->add({{"send_time", send_time},
					 {"send_queue_time", r->queue_time},
					 {"response_size", total_size},
					});
		}
	}
	DNET_LOG(st->n, level, "%s: %s: sending trans: %lld -> %s/%d: size: %llu, cflags: %s, finish-sent: "
			       "%zd/%zd, send-queue-time: %lu usecs, send-time: %lu usecs",
		 dnet_dump_id(&cmd.id), dnet_cmd_string(cmd.cmd), (unsigned long long)cmd.trans,
		 dnet_addr_string(&st->addr), cmd.backend_id, (unsigned long long)cmd.size,
		 dnet_flags_dump_cflags(cmd.flags), st->send_offset, total_size, r->queue_time, send_time);
	dnet_logger_unset_trace_id();

	/*
	 * Flush TCP output pipeline if we've sent whole request.
	 *
	 * We do not destroy request here, it is postponed to caller.
	 * Function can be called without lock - default call path from network processing thread and
	 * dnet_process_send_single() or under st->send_lock, if queue was empty and dnet_send*() caller directly
	 * invoked this function from dnet_io_req_queue() instead of queuing.
	 */
	if (!send_error) {
		int nodelay = 1;
		setsockopt(st->write_s, IPPROTO_TCP, TCP_NODELAY, &nodelay, 4);
	}

	if (!(cmd.flags & DNET_FLAGS_REPLY)) {
		pthread_mutex_lock(&st->trans_lock);
		auto t = dnet_trans_search(st, cmd.trans);
		if (t) {
			t->stats.send_queue_time = r->queue_time;
			t->stats.send_time = send_time;
		}
		pthread_mutex_unlock(&st->trans_lock);
		dnet_trans_put(t);
	}

	return send_error;
}

int n2_send_request(struct dnet_net_state *st, struct dnet_io_req *r) {
	return c_exception_guard(std::bind(&n2_send_request_impl, st, r), st->n, __FUNCTION__);
}
