#ifndef IOREMAP_ELLIPTICS_BACKEND_H
#define IOREMAP_ELLIPTICS_BACKEND_H

#include "library/elliptics.h"

#ifdef __cplusplus

#include <string>
#include <mutex>
#include <unordered_map>

#include <boost/thread/shared_mutex.hpp>

#include <rapidjson/document.h>

#include "monitor/statistics.hpp"

namespace ioremap { namespace monitor {
struct request;
}} /* namespace ioremap::monitor */

namespace ioremap { namespace cache {
class cache_manager;
}} /* namespace ioremap::cache */

namespace ioremap { namespace elliptics { namespace config {
struct backend_config;
}}} /* namespace ioremap::elliptics::config */

using backend_config = ioremap::elliptics::config::backend_config;

// TODO(shaitan): wrap dnet_backend_callbacks and backend_config::dnet_config_backend by RAII structure
// with API for working with underlying backend
struct dnet_backend {
public:
	dnet_backend(dnet_node *node, std::shared_ptr<backend_config> config);
	~dnet_backend();

	dnet_backend(const dnet_backend &) = delete;
	dnet_backend &operator=(const dnet_backend &) = delete;

	// actual backend's config
	std::shared_ptr<backend_config> config() const { return m_config; }
	// backend's id
	uint32_t backend_id() const;
	// group served by the backend
	uint32_t group_id() const;
	// actual backend's state
	dnet_backend_state state() const { return m_state; }
	// backend's state guard
	boost::shared_mutex &state_mutex() { return m_state_mutex; }
	// return low-level callbacks to underlying backend
	dnet_backend_callbacks &callbacks() { return m_callbacks; }
	// return low-level callbacks to underlying backend
	const dnet_backend_callbacks &callbacks() const { return m_callbacks; }
	// return cache which can be nullptr if cache is disabled
	ioremap::cache::cache_manager *cache() { return m_cache.get(); }
	// return whether read-only mode is enabled
	bool read_only() const { return m_read_only; }
	// enable/disable read-only mode
	void set_read_only(bool read_only = true) { m_read_only = read_only; }
	// return current delay in milliseconds the backend will sleep before handling any request
	uint64_t delay() const { return m_delay; }
	// set backend's delay
	void set_delay(uint64_t delay) { m_delay = delay; }
	// return statistics of handled by the backend commands
	ioremap::monitor::command_stats &command_stats() { return m_command_stats; }
	// return backend's queue_timeout
	uint64_t queue_timeout() const;
	// set backend's verbosity to @level
	void set_verbosity(const dnet_log_level level);
	// return io pool the backend is attached to
	struct dnet_io_pool *io_pool() { return m_pool.get(); }

	// enable (run) backend
	int enable();
	// disable (stop) backend
	int disable();

	// start defragmentation on @level
	int start_defrag(const dnet_backend_defrag_level level);
	// stop defragmentation
	int stop_defrag();

	// start inspection
	int start_inspect();
	// stop inspection
	int stop_inspect();

	// update ids ranges served by the backend
	int set_ids(struct dnet_raw_id *ids, uint32_t ids_count);

	// status and statistics methods
	// fill backend's status
	void fill_status(dnet_backend_status &status);
	// fill backend's statistics for monitor
	void statistics(uint64_t categories, rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator);

private:
	dnet_node						*m_node;
	// backend's config
	std::shared_ptr<backend_config>				m_config;
	// read-only mode of backend
	bool							m_read_only;
	// delay in milliseconds which will slept by backend before handling any request
	uint64_t						m_delay;
	// current backend's state
	dnet_backend_state					m_state;
	// backend's state guard
	boost::shared_mutex					m_state_mutex;
	// time when the backend was enabled last time
	dnet_time						m_last_start;
	// result of last backend's enabling in terms of error code
	int							m_last_start_err;
	// low-level callbacks to underlying backend
	dnet_backend_callbacks					m_callbacks;
	// statistics collected for monitor
	ioremap::monitor::command_stats				m_command_stats;
	// cache. It will be nullptr if cache is disabled
	std::unique_ptr<ioremap::cache::cache_manager>		m_cache;
	// logger with attached backend's attributes
	std::unique_ptr<dnet_logger>				m_log;
	// id of io pool serves the backend. It can be individual or shared.
	std::string						m_pool_id;
	// pointer to io pool serves the backend
	std::shared_ptr<struct dnet_io_pool>			m_pool;

private:
	// change backend's state to @state and check the adequacy of this change
	int change_state(dnet_backend_state state);
	// detach the backend from io pool. If the backend has individual io pool it will lead to pool's shutdown,
	void detach_from_io_pool();

	// statistics methods

	// fill @value with backend's status
	void fill_status(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator);
	// fill @value with backend's statistics
	void fill_backend_stats(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator);
	// fill @value with statistics of backend's io pool
	void fill_io_stats(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator);
	// fill @value with statistics of backend's cache
	void fill_cache_stats(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator);
	// fill @value with statistics of handled by the backend commands
	void fill_commands_stats(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator);
};

struct dnet_backends_manager {
public:
	dnet_backends_manager(dnet_node *node);
	~dnet_backends_manager();

	dnet_backends_manager(const dnet_backends_manager &) = delete;
	dnet_backends_manager &operator=(const dnet_backends_manager &) = delete;

	// create and insert new backend with the given @config
	bool emplace(std::shared_ptr<backend_config> config);
	// return backend with @backend_id. If there is no backend with @backend_id it will return nullptr.
	std::shared_ptr<dnet_backend> get(uint32_t backend_id);
	// disable and remove backend with @backend_id. Returns error code.
	int erase(uint32_t backend_id);
	// disable and remove all backends
	void clear();
	// enable all enabled at start backends. If @parallel is true backends will be enabled via sending
	// asynchronous commands otherwise via synchronous call.
	int init_all(bool parallel);
	// set verbosity to all backends
	void set_verbosity(const dnet_log_level level);
	// return status of all backends
	struct dnet_backend_status_list *get_status();
	// return statistics of backends in accordance with the request
	void statistics(const ioremap::monitor::request &request, rapidjson::Value &value,
	                rapidjson::Document::AllocatorType &allocator);

private:
	dnet_node							*m_node;

	// backend_id -> backend
	std::unordered_map<uint32_t, std::shared_ptr<dnet_backend>>	m_backends;
	boost::shared_mutex						m_backends_mutex;
};

// fill @value with all io pools statistics
void dnet_io_pools_fill_stats(struct dnet_node *node,
                              rapidjson::Value &value,
                              rapidjson::Document::AllocatorType &allocator);

extern "C" {

#else // __cplusplus
struct dnet_backends_manager;
struct dnet_backend;
#endif // __cplusplus

// return @backend's backend_id
uint32_t dnet_backend_get_backend_id(struct dnet_backend *backend);
// return whether backend's read-only mode is on or not
int dnet_backend_read_only(struct dnet_backend *backend);
// sleep specified in @backend delay
void dnet_backend_sleep_delay(struct dnet_backend *backend);
// return low-level callbacks to underlying backend
struct dnet_backend_callbacks *dnet_backend_get_callbacks(struct dnet_backend *backend);

// return io pool backend is attached to
struct dnet_io_pool *__attribute__((weak)) dnet_backend_get_pool(struct dnet_node *node, uint32_t backend_id);
// return io pool's place backend is attached to
struct dnet_work_pool_place *dnet_backend_get_place(struct dnet_node *node, ssize_t backend_id, int nonblocking);
// return backend's queue_timeout
uint64_t __attribute__((weak)) dnet_backend_get_queue_timeout(struct dnet_node *node, ssize_t backend_id);

// update statistics for commands handled by the @backend
void dnet_backend_command_stats_update(struct dnet_backend *backend,
                                       struct dnet_cmd *cmd,
                                       uint64_t size,
                                       int handled_in_cache,
                                       int err,
                                       long diff);
// handle command by @backend
int dnet_backend_process_cmd_raw(struct dnet_backend *backend,
                                 struct dnet_net_state *st,
                                 struct dnet_cmd *cmd,
                                 void *data,
                                 struct dnet_cmd_stats *cmd_stats,
                                 struct dnet_access_context *context);

// handle command by @backend's cache
int dnet_cmd_cache_io(struct dnet_backend *backend,
                      struct dnet_net_state *st,
                      struct dnet_cmd *cmd,
                      char *data,
                      struct dnet_cmd_stats *cmd_stats,
                      struct dnet_access_context *context);

// initialize backends' subsystem, but do not enable any backend
int dnet_backends_init(struct dnet_node *node);
// deinitialize backends' subsystem
void __attribute__((weak)) dnet_backends_destroy(struct dnet_node *node);
// initialize all backends
int dnet_backends_init_all(struct dnet_node *n);
// deinitialize all backends
void dnet_backends_cleanup_all(struct dnet_node *n);
/* find and return a backend with @backend_id with locking its state_mutex, so it should be unlocked after use.
 * If there is no backend with @backend_id or the backend isn't in DNET_BACKEND_ENABLED state, it will return nullptr.
 */
struct dnet_backend *dnet_backends_get_backend_locked(struct dnet_node *node, uint32_t backend_id);
// unlock backend's state_mutex previously locked
void dnet_backend_unlock_state(struct dnet_backend *backend);

// handle DNET_CMD_BACKEND_CONTROL
int dnet_cmd_backend_control(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);
// handle DNET_CMD_BACKEND_STATUS
int dnet_cmd_backend_status(struct dnet_net_state *st, struct dnet_cmd *cmd);
// handle DNET_CMD_BULK_READ_NEW
int dnet_cmd_bulk_read_new(struct dnet_net_state *st,
                           struct dnet_cmd *cmd,
                           void *data,
                           struct dnet_access_context *context);

// add to @queue_size and @threads_count all io pools' queues' sizes and number of threads.
// This is used to suspend net threads if queues are heavily filled
void __attribute__((weak)) dnet_io_pools_check(struct dnet_io_pools_manager *pools_manager,
                                               uint64_t *queue_size,
                                               uint64_t *threads_count);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // IOREMAP_ELLIPTICS_BACKEND_H
