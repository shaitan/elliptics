// TODO(shaitan): review this file and cleanup unused or strange places
// TODO(shaitan): order class & function declaration order and keep it in backend.cpp and common.cpp

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


namespace ioremap { namespace cache {
class cache_manager;
}} /* namespace ioremap::cache */

namespace ioremap { namespace elliptics { namespace config {
struct backend_config;
}}} /* namespace ioremap::elliptics::config */

using backend_config = ioremap::elliptics::config::backend_config;

// TODO(shaitan): wrap dnet_backend_callbacks and backend_config::dnet_config_backend by RAII structure
// with API for working with underlying backend
class dnet_backend {
public:
	dnet_backend(dnet_node *node, std::shared_ptr<backend_config> config);
	~dnet_backend();

	dnet_backend(const dnet_backend &) = delete;
	dnet_backend &operator=(const dnet_backend &) = delete;

	// properties
	std::shared_ptr<backend_config> config() const { return m_config; }

	uint32_t backend_id() const;
	uint32_t group_id() const;

	dnet_backend_state state() const { return m_state; }
	boost::shared_mutex &state_mutex() { return m_state_mutex; }

	dnet_backend_callbacks &callbacks() { return m_callbacks; }
	const dnet_backend_callbacks &callbacks() const { return m_callbacks; }
	ioremap::cache::cache_manager *cache() { return m_cache.get(); }

	bool read_only() const { return m_read_only; }
	void set_read_only(bool read_only = true) { m_read_only = read_only; }

	uint64_t delay() const { return m_delay; }
	void set_delay(uint64_t delay) { m_delay = delay; }

	ioremap::monitor::command_stats &command_stats() { return m_command_stats; }

	uint64_t queue_timeout() const;

	void set_verbosity(const dnet_log_level level);

	struct dnet_io_pool *io_pool() { return m_pool.get(); }


	// actions
	int enable();
	int disable();

	int start_defrag(const dnet_backend_defrag_level level);
	int stop_defrag();

	int set_ids(struct dnet_raw_id *ids, uint32_t ids_count);

	void fill_status(struct dnet_backend_status *status);

	void statistics(uint64_t categories, rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator);

private:
	dnet_node						*m_node;
	std::shared_ptr<backend_config>				m_config;

	bool							m_read_only;

	uint64_t						m_delay;

	dnet_backend_state					m_state;
	boost::shared_mutex					m_state_mutex;

	dnet_time						m_last_start;
	int							m_last_start_err;

	dnet_backend_callbacks					m_callbacks;

	ioremap::monitor::command_stats				m_command_stats;

	std::unique_ptr<ioremap::cache::cache_manager>		m_cache;

	std::unique_ptr<dnet_logger>				m_log;

	std::string						m_pool_id;
	std::shared_ptr<struct dnet_io_pool>			m_pool;

	int change_state(dnet_backend_state state);

	void fill_status(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator);
	void fill_backend_stats(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator);
	void fill_io_stats(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator);
	void fill_cache_stats(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator);
	void fill_commands_stats(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator);
};

class dnet_backends_manager {
public:
	dnet_backends_manager(dnet_node *node);
	~dnet_backends_manager();

	dnet_backends_manager(const dnet_backends_manager &) = delete;
	dnet_backends_manager &operator=(const dnet_backends_manager &) = delete;

	bool add_backend(std::shared_ptr<backend_config> config);
	std::shared_ptr<dnet_backend> get_backend(uint32_t backend_id);
	int remove_backend(uint32_t backend_id);

	int init_all_backends(bool parallel);

	void set_verbosity(const dnet_log_level level);

	struct dnet_backend_status_list *get_status();
	void statistics(uint64_t categories, rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator);

private:
	dnet_node							*m_node;

	std::unordered_map<uint32_t, std::shared_ptr<dnet_backend>>	m_backends;
	boost::shared_mutex						m_backends_mutex;
};

void dnet_io_pools_dump_stats(struct dnet_node *node,
                              rapidjson::Value &value,
                              rapidjson::Document::AllocatorType &allocator);

extern "C" {

#else // __cplusplus

typedef struct dnet_backends_manager dnet_backends_manager;
typedef struct dnet_backend dnet_backend;

#endif // __cplusplus

uint32_t dnet_backend_get_backend_id(struct dnet_backend *backend);
int dnet_backend_read_only(struct dnet_backend *backend);

void dnet_backend_sleep_delay(struct dnet_backend *backend);

struct dnet_backend_callbacks *dnet_backend_get_callbacks(struct dnet_backend *backend);

int dnet_backend_init_all(struct dnet_node *n);
void dnet_backend_cleanup_all(struct dnet_node *n);

int dnet_cmd_backend_control(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);

int dnet_cmd_backend_status(struct dnet_net_state *st, struct dnet_cmd *cmd);

int dnet_cmd_bulk_read_new(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);

struct dnet_io_pool *__attribute__((weak)) dnet_backend_get_pool(struct dnet_node *node, uint32_t backend_id);
struct dnet_work_pool_place *dnet_backend_get_place(struct dnet_node *node, ssize_t backend_id, int nonblocking);
uint64_t __attribute__((weak)) dnet_backend_get_queue_timeout(struct dnet_node *node, ssize_t backend_id);

// TODO(shaitan): avoid using C function here
void dnet_backend_command_stats_update(struct dnet_backend *backend,
                                       struct dnet_cmd *cmd,
                                       uint64_t size,
                                       int handled_in_cache,
                                       int err,
                                       long diff);

int dnet_backend_process_cmd_raw(struct dnet_backend *backend,
                                 struct dnet_net_state *st,
                                 struct dnet_cmd *cmd,
                                 void *data,
                                 struct dnet_cmd_stats *cmd_stats);

void __attribute__((weak)) dnet_io_pools_check(struct dnet_io_pools_manager *pools_manager,
                                               uint64_t *queue_size,
                                               uint64_t *threads_count);

int dnet_backends_init(struct dnet_node *node);
void __attribute__((weak)) dnet_backends_destroy(struct dnet_node *node);
struct dnet_backend *dnet_backends_get_backend(struct dnet_node *node, uint32_t backend_id);

int dnet_cmd_cache_io(struct dnet_backend *backend,
                      struct dnet_net_state *st,
                      struct dnet_cmd *cmd,
                      char *data,
                      struct dnet_cmd_stats *cmd_stats);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // IOREMAP_ELLIPTICS_BACKEND_H
