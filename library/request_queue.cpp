#include "request_queue.h"

#include <blackhole/attribute.hpp>

#include "murmurhash.h"
#include "monitor/measure_points.h"
#include "example/config.hpp"
#include "logger.hpp"
#include "library/backend.h"

static size_t dnet_id_hash(const dnet_id &key) {
	return MurmurHash64A(reinterpret_cast<const char *>(&key), sizeof(key.id) + sizeof(key.group_id), 0);
}

static bool dnet_id_equal(const dnet_id &lhs, const dnet_id &rhs) {
	return !dnet_id_cmp(&lhs, &rhs);
}

dnet_request_queue::dnet_request_queue()
: m_queue_size(0)
, m_locked_keys(1, &dnet_id_hash, &dnet_id_equal) {
	INIT_LIST_HEAD(&m_queue);
}

dnet_request_queue::~dnet_request_queue() {
	for (auto it = m_lock_pool.begin(); it != m_lock_pool.end(); ++it) {
		delete *it;
	}

	struct dnet_io_req *r, *tmp;
	list_for_each_entry_safe(r, tmp, &m_queue, req_entry) {
		list_del(&r->req_entry);
		dnet_io_req_free(r);
	}
}

void dnet_request_queue::push_request(dnet_io_req *req) {
	gettimeofday(&req->time, NULL);

	{
		std::unique_lock<std::mutex> lock(m_queue_mutex);
		list_add_tail(&req->req_entry, &m_queue);
		++m_queue_size;
	}
	m_queue_wait.notify_one();
}

dnet_io_req *dnet_request_queue::pop_request(dnet_work_io *wio, const char *thread_stat_id) {
	auto r = [&, this]() -> dnet_io_req * {
		std::unique_lock<std::mutex> lock(m_queue_mutex);

		auto r = take_request(wio, thread_stat_id);
		if (!r) {
			m_queue_wait.wait_for(lock, std::chrono::seconds(1));
			r = take_request(wio, thread_stat_id);
		}

		if (r) {
			list_del_init(&r->req_entry);
			--m_queue_size;

			timeval tv;
			gettimeofday(&tv, nullptr);
			timersub(&tv, &r->time, &r->time);
		}

		return r;
	}();

	if (!r) {
		return nullptr;
	}

	HANDY_COUNTER_DECREMENT("io.input.queue.size", 1);

	FORMATTED(HANDY_COUNTER_DECREMENT, ("pool.%s.queue.size", thread_stat_id), 1);
	FORMATTED(HANDY_TIMER_STOP, ("pool.%s.queue.wait_time", thread_stat_id), (uint64_t)r);

	auto cmd = static_cast<dnet_cmd *>(r->header);
	auto st = r->st;
	auto node = st->n;
	const auto timeout = [&node, &cmd]() -> uint64_t {
		// ignore timeout for replies and commands with DNET_FLAGS_NO_QUEUE_TIMEOUT;
		if (cmd->flags & (DNET_FLAGS_NO_QUEUE_TIMEOUT | DNET_FLAGS_REPLY))
			return 0;

		if (cmd->backend_id < 0)
			return dnet_node_get_queue_timeout(node);

		return dnet_backend_get_queue_timeout(node, cmd->backend_id);
	}();
	const auto expired = [&r, timeout, &st]() {
		if (!timeout)
			return false;

		if (st->__need_exit)
			return true;

		return (r->time.tv_sec * 1000000 + r->time.tv_usec) > timeout;
	}();

	if (!expired)
		return r;

	FORMATTED(HANDY_COUNTER_INCREMENT, ("pool.%s.queue.dropped", thread_stat_id), 1);
	{
		ioremap::elliptics::trace_scope trace_scope{cmd->trace_id, cmd->flags & DNET_FLAGS_TRACE_BIT};
		ioremap::elliptics::backend_scope backend_scope{cmd->backend_id};;

		DNET_LOG_ERROR(node, "{}: {}: client: {}: drop request: trans: {}, cflags: {}, "
		                     "queue_time: {} usecs, timeout: {} usecs, need_exit: {}",
		               dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), dnet_state_dump_addr(r->st),
		               cmd->trans, dnet_flags_dump_cflags(cmd->flags),
		               (r->time.tv_sec * 1000000 + r->time.tv_usec), timeout, st->__need_exit);
	}
	pthread_cond_broadcast(&node->io->full_wait);

	release_request(r);
	dnet_io_req_free(r);
	dnet_state_put(st);

	return nullptr;
}

dnet_io_req *dnet_request_queue::take_request(dnet_work_io *wio, const char *thread_stat_id) {
	FORMATTED(HANDY_TIMER_SCOPE, ("pool.%s.search_trans_time", thread_stat_id));

	dnet_work_pool *pool = wio->pool;
	dnet_io_req *it, *tmp;
	uint64_t trans;

	/*
	 * Comment below is only related to client IO threads processing replies from the server.
	 *
	 * At any given moment of time it is forbidden for 2 IO threads to process replies for the same transaction.
	 * This may lead to the situation, when thread 1 processes final ack, while thread 2 is being handling received data.
	 * Thread 1 will free resources, which leads thread 2 to crash the whole process.
	 *
	 * Thus any transaction may only be processed on single thread at any given time.
	 * But it is possible to ping-pong transaction between multiple IO threads as long as each IO thread
	 * processes different transaction reply simultaneously.
	 *
	 * We must set current thread index to -1 to highlight that current thread currently does not perform any task,
	 * so it can be assigned any transaction reply, if it is not already claimed by another thread.
	 *
	 * If we leave here previously processed transaction id, we might stuck, since all threads will wait for those
	 * transactions they are assigned to, thus not allowing any further process, since no thread will be able to
	 * process current request and move to the next one.
	 */
	wio->trans = ~0ULL;

	if (!list_empty(&wio->reply_list)) {
		it = list_first_entry(&wio->reply_list, struct dnet_io_req, req_entry);
		auto cmd = reinterpret_cast<const dnet_cmd *>(it->header);
		trans = cmd->trans;
		wio->trans = trans;
		return it;
	}

	if (!list_empty(&wio->request_list)) {
		it = list_first_entry(&wio->request_list, struct dnet_io_req, req_entry);
		auto cmd = reinterpret_cast<const dnet_cmd *>(it->header);
		trans = cmd->trans;
		wio->trans = trans;
		return it;
	}

	std::unique_lock<std::mutex> lock(m_locks_mutex);

	list_for_each_entry_safe(it, tmp, &m_queue, req_entry) {
		auto cmd = reinterpret_cast<const dnet_cmd *>(it->header);

		/* This is not a transaction reply, process it right now */
		if (!(cmd->flags & DNET_FLAGS_REPLY)) {
			if (cmd->flags & DNET_FLAGS_NOLOCK)
				return it;

			locked_keys_t::iterator it_lock;
			bool inserted;
			std::tie(it_lock, inserted) =
			        m_locked_keys.emplace(cmd->id, reinterpret_cast<dnet_locks_entry *>(nullptr));
			if (inserted) {
				auto lock_entry = take_lock_entry(wio);
				it_lock->second = lock_entry;
				return it;
			} else {
				auto lock_entry = it_lock->second;
				dnet_work_io *owner = lock_entry->owner;
				/* if key is already locked by other pool thread, then move it to request_list of this
				 * thread */
				if (owner)
					list_move_tail(&it->req_entry, &owner->request_list);
			}
		} else {
			trans = cmd->trans;
			bool trans_in_process = false;

			for (int i = 0; i < pool->num; ++i) {
				/* Someone claimed transaction @tid */
				if (pool->wio_list[i].trans == trans) {
					list_move_tail(&it->req_entry, &pool->wio_list[i].reply_list);
					trans_in_process = true;
					break;
				}
			}

			if (!trans_in_process) {
				wio->trans = trans;
				return it;
			}
		}
	}

	return nullptr;
}

void dnet_request_queue::release_request(const dnet_io_req *req) {
	auto cmd = reinterpret_cast<const dnet_cmd *>(req->header);
	if (!(cmd->flags & DNET_FLAGS_REPLY) &&
	    !(cmd->flags & DNET_FLAGS_NOLOCK)) {
		release_key(&cmd->id);
	}
}

void dnet_request_queue::lock_key(const dnet_id *id) {
	std::unique_lock<std::mutex> lock(m_locks_mutex);
	while (1) {
		auto it = m_locked_keys.find(*id);
		if (it == m_locked_keys.end()) {
			break;
		}

		auto lock_entry = it->second;
		lock_entry->unlock_event.wait_for(lock, std::chrono::seconds(1));
	}
	auto lock_entry = take_lock_entry(nullptr);
	m_locked_keys.emplace(*id, lock_entry);
}

void dnet_request_queue::unlock_key(const dnet_id *id) {
	release_key(id);
	m_queue_wait.notify_one();
}

void dnet_request_queue::release_key(const dnet_id *id) {
	std::unique_lock<std::mutex> lock(m_locks_mutex);
	auto it = m_locked_keys.find(*id);
	if (it != m_locked_keys.end()) {
		auto lock_entry = it->second;
		const dnet_work_io *owner = lock_entry->owner;
		/*
		 * Unlock key only if it was locked directly by dnet_oplock() (owner == 0) and
		 * there is no scheduled keys (by take_request()) in request_list
		 * (where all keys have same id as given in argument)
		 * of pool thread (owner != 0).
		 */
		if (owner && !list_empty(&owner->request_list)) {
			return;
		}
		m_locked_keys.erase(it);
		put_lock_entry(lock_entry);
		lock_entry->unlock_event.notify_one();
	}
}

dnet_locks_entry *dnet_request_queue::take_lock_entry(dnet_work_io *wio) {
	if (m_lock_pool.empty()) {
		auto entry = new(std::nothrow) dnet_locks_entry;
		m_lock_pool.push_back(entry);
	}
	auto entry = m_lock_pool.front();
	m_lock_pool.pop_front();
	entry->owner = wio;
	return entry;
}

void dnet_request_queue::put_lock_entry(dnet_locks_entry *entry) {
	m_lock_pool.push_back(entry);
}

size_t dnet_request_queue::size() const {
	return m_queue_size;
}

void dnet_request_queue::notify_all() {
	m_queue_wait.notify_all();
}

dnet_oplock_guard::dnet_oplock_guard(struct dnet_io_pool *pool, const struct dnet_id *id)
: m_pool{pool}
, m_id{id}
, m_locked{false} {
	lock();
}

dnet_oplock_guard::~dnet_oplock_guard() {
	unlock();
}

void dnet_oplock_guard::lock() {
	if (!m_locked) {
		dnet_oplock(m_pool, m_id);
		m_locked = true;
	}
}

void dnet_oplock_guard::unlock() {
	if (m_locked) {
		dnet_opunlock(m_pool, m_id);
		m_locked = false;
	}
}

void dnet_push_request(struct dnet_work_pool *pool, struct dnet_io_req *req) {
	pool->request_queue->push_request(req);
}

struct dnet_io_req *dnet_pop_request(struct dnet_work_io *wio, const char *thread_stat_id) {
	return wio->pool->request_queue->pop_request(wio, thread_stat_id);
}

void dnet_release_request(struct dnet_work_io *wio, const struct dnet_io_req *req) {
	wio->pool->request_queue->release_request(req);
}

void dnet_oplock(struct dnet_io_pool *pool, const struct dnet_id *id) {
	pool->recv_pool.pool->request_queue->lock_key(id);
}

void dnet_opunlock(struct dnet_io_pool *pool, const struct dnet_id *id) {
	pool->recv_pool.pool->request_queue->unlock_key(id);
}

size_t dnet_get_pool_queue_size(struct dnet_work_pool *pool) {
	return pool->request_queue->size();
}

void *dnet_request_queue_create(dnet_node *n) {
	return new(std::nothrow) dnet_request_queue();
}

void dnet_request_queue_destroy(struct dnet_work_pool *pool) {
	delete pool->request_queue;
}
