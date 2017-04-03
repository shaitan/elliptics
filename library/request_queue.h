#ifndef IOREMAP_ELLIPTICS_REQUEST_QUEUE_HPP
#define IOREMAP_ELLIPTICS_REQUEST_QUEUE_HPP

#include "elliptics.h"

#ifdef __cplusplus
#include <list>
#include <unordered_map>
#include <condition_variable>
#include <mutex>
#include <atomic>


struct dnet_locks_entry
{
	std::condition_variable unlock_event;
	dnet_work_io *owner;
};

/*
 * dnet_request_queue is queue of requests with specific key locking semantics: its pop_request()
 * lookups first request with non-locked key in queue, locks this key and returns the request.
 * Also it provides methods for specific key lock/unlock mechanism and provides internal statistics.
 */
class dnet_request_queue
{
public:
	/*!
	 * Constructor: initializes internal state properly
	 */
	dnet_request_queue();
	/*!
	 * Destructor: frees all dnet_locks_entry objects in /a m_lock_pool and destroys all requests in /a m_queue
	 */
	~dnet_request_queue();

	/*!
	 * Puts request \a req into /a m_queue
	 */
	void push_request(dnet_io_req *req);
	/*!
	 * Tries to take first available request with non-locked key and removes it from /a m_queue
	 */
	dnet_io_req *pop_request(dnet_work_io *wio, const char *thread_stat_id);
	/*!
	 * Releases request's /a req key from /a m_locked_keys
	 */
	void release_request(const dnet_io_req *req);

	/*!
	 * Saves key identified by /a id into /a m_locked_keys or waits until key will be unlocked (by calling release_request() or unlock_key())
	 * and signalized using conditional var of dnet_locks_entry object associated with this key in /a m_locked_keys map.
	 */
	void lock_key(const dnet_id *id);
	/*!
	 * Removes key identified by /a id from /a m_locked_keys and notifies waiting threads
	 */
	void unlock_key(const dnet_id *id);

	/*!
	 * Returns size of the queue
	 */
	size_t size() const;

	/*!
	 * Notify all waiters (threads)
	 */
	void notify_all();

private:
	/*
	 * Returns first available request with non-locked key from /a m_queue and saves request's key into /a m_locked_keys
	 */
	dnet_io_req *take_request(dnet_work_io *wio, const char *thread_stat_id);
	/*!
	 * Removes key identified by /a id from /a m_locked_keys
	 */
	void release_key(const dnet_id *id);
	/*!
	 * Takes dnet_locks_entry object from /a m_lock_pool
	 */
	dnet_locks_entry *take_lock_entry(dnet_work_io *wio);
	/*!
	 * Puts back dnet_locks_entry into /a m_lock_pool
	 */
	void put_lock_entry(dnet_locks_entry *entry);

private:
	struct list_head m_queue;
	std::mutex m_queue_mutex;
	std::condition_variable m_queue_wait;

	std::atomic_size_t m_queue_size;

	typedef std::unordered_map<dnet_id, dnet_locks_entry *, size_t(*)(const dnet_id&), bool(*)(const dnet_id&, const dnet_id&)> locked_keys_t;
	locked_keys_t m_locked_keys;
	std::list<dnet_locks_entry *> m_lock_pool;
	std::mutex m_locks_mutex;
};

class dnet_oplock_guard
{
public:
	dnet_oplock_guard(struct dnet_io_pool *pool, const struct dnet_id *id);
	~dnet_oplock_guard();

	void lock();
	void unlock();

private:
	struct dnet_io_pool *m_pool;
	const struct dnet_id *m_id;
	bool m_locked;
};

extern "C" {
#endif // __cplusplus

void *dnet_request_queue_create();
void dnet_request_queue_destroy(struct dnet_work_pool *pool);

void dnet_push_request(struct dnet_work_pool *pool, struct dnet_io_req *req);
struct dnet_io_req *dnet_pop_request(struct dnet_work_io *wio, const char *thread_stat_id);
void dnet_release_request(struct dnet_work_io *wio, const struct dnet_io_req *req);

size_t dnet_get_pool_queue_size(struct dnet_work_pool *pool);

void dnet_oplock(struct dnet_io_pool *pool, const struct dnet_id *id);
void dnet_opunlock(struct dnet_io_pool *pool, const struct dnet_id *id);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IOREMAP_ELLIPTICS_REQUEST_QUEUE_HPP
