#include "backend.h"

#include <fcntl.h>
#include <fstream>
#include <memory>

#include <blackhole/wrapper.hpp>

#include "bindings/cpp/functional_p.h"
#include "bindings/cpp/session_internals.hpp"
#include "cache/cache.hpp"
#include "example/config.hpp"
#include "library/logger.hpp"
#include "library/protocol.hpp"
#include "library/request_queue.h"
#include "library/route.h"
#include "monitor/io_stat_provider.hpp"
#include "monitor/monitor.hpp"

// TODO(shaitan): replace using @dnet_io_pool with RAII object
class dnet_io_pools_manager {
public:
	dnet_io_pools_manager(struct dnet_node *node)
	: m_node(node) {}

	std::shared_ptr<struct dnet_io_pool> get(const std::string &pool_id);
	int detach(const std::string &pool_id);

	void statistics(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator);
	void check(uint64_t &queue_size, uint64_t threads_count);

private:
	struct dnet_node							*m_node;

	boost::shared_mutex							m_pools_mutex;
	std::unordered_map<std::string, std::shared_ptr<struct dnet_io_pool>>	m_pools;
};

static std::shared_ptr<struct dnet_io_pool> create_io_pool(struct dnet_node *node,
                                                           const std::string &pool_id,
                                                           const ioremap::elliptics::config::io_pool_config &config) {
	auto pool = std::make_shared<struct dnet_io_pool>();
	memset(pool.get(), 0, sizeof(*pool.get()));

	int err = dnet_work_pool_place_init(&pool->recv_pool);
	if (err) {
		DNET_LOG_ERROR(node, "create_io_pool(pool_id: {}): failed to initialize blocking pool: {} [{}]",
		               pool_id, strerror(-err), err);
		return nullptr;
	}

	err = dnet_work_pool_alloc(&pool->recv_pool, node, config.thread_num, DNET_WORK_IO_MODE_BLOCKING,
	                           pool_id.c_str(), dnet_io_process);
	if (err) {
		DNET_LOG_ERROR(node, "create_io_pool(pool_id: {}): failed to allocate blocking pool: {} [{}]",
		               pool_id, strerror(-err), err);
		dnet_work_pool_place_cleanup(&pool->recv_pool);
		return nullptr;
	}

	err = dnet_work_pool_place_init(&pool->recv_pool_nb);
	if (err) {
		DNET_LOG_ERROR(node, "create_io_pool(pool_id: {}): failed to initialize nonblocking pool: {} [{}]",
		               pool_id, strerror(-err), err);
		dnet_work_pool_exit(&pool->recv_pool);
		dnet_work_pool_place_cleanup(&pool->recv_pool);
		return nullptr;
	}

	err = dnet_work_pool_alloc(&pool->recv_pool_nb, node, config.nonblocking_thread_num,
	                           DNET_WORK_IO_MODE_NONBLOCKING, pool_id.c_str(), dnet_io_process);
	if (err) {
		DNET_LOG_ERROR(node, "create_io_pool(pool_id: {}): failed to allocate nonblocking pool: {} [{}]",
		               pool_id, strerror(-err), err);
		dnet_work_pool_place_cleanup(&pool->recv_pool_nb);
		dnet_work_pool_exit(&pool->recv_pool);
		dnet_work_pool_place_cleanup(&pool->recv_pool);
		return nullptr;
	}

	DNET_LOG_INFO(node, "create_io_pool(pool_id: {}): pool was successfully started", pool_id);

	return std::move(pool);
}

static void stop_io_pool(struct dnet_node *node,
                         std::shared_ptr<struct dnet_io_pool> pool,
                         const std::string &pool_id) {
	DNET_LOG_INFO(node, "stop_io_pool(pool_id: {}): stopping the pool", pool_id);

	pool->recv_pool.pool->need_exit = 1;
	pool->recv_pool_nb.pool->need_exit = 1;

	// notify all threads to make them exit
	pool->recv_pool.pool->request_queue->notify_all();
	pool->recv_pool_nb.pool->request_queue->notify_all();

	dnet_work_pool_exit(&pool->recv_pool);
	dnet_work_pool_exit(&pool->recv_pool_nb);

	DNET_LOG_INFO(node, "stop_io_pool(pool_id: {}): the pool has been stopped", pool_id);
}

std::shared_ptr<struct dnet_io_pool> dnet_io_pools_manager::get(const std::string &pool_id) {
	boost::unique_lock<boost::shared_mutex> guard(m_pools_mutex);
	auto it = m_pools.find(pool_id);
	if (it != m_pools.end())
		return it->second;

	const auto pool_config = dnet_node_get_config_data(m_node)->get_io_pool_config(pool_id);
	auto pool = create_io_pool(m_node, pool_id, pool_config);
	m_pools.emplace(pool_id, pool);

	return std::move(pool);
}

int dnet_io_pools_manager::detach(const std::string &pool_id) {
	boost::unique_lock<boost::shared_mutex> guard(m_pools_mutex);
	auto pool_it = m_pools.find(pool_id);
	if (pool_it == m_pools.end()) {
		DNET_LOG_ERROR(m_node, "dnet_io_pools_manager::detach(pool_id: {}): there is no such pool", pool_id);
		return -ENOENT;
	}

	auto &pool = pool_it->second;

	// stop @pool without any backend attached to it
	if (pool.use_count() == 1) {
		stop_io_pool(m_node, pool, pool_id);
		m_pools.erase(pool_it);
	}

	DNET_LOG_INFO(m_node, "dnet_io_pools_manager::detach(pool_id: {}): finished", pool_id);
	return 0;
}

void dnet_io_pools_manager::statistics(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator) {
	boost::shared_lock<boost::shared_mutex> guard(m_pools_mutex);
	for (auto &item : m_pools) {
		const auto &pool_id = item.first;
		const auto &io_pool = item.second;

		rapidjson::Value pool(rapidjson::kObjectType);
		ioremap::monitor::dump_io_pool_stats(*io_pool, pool, allocator);
		value.AddMember(pool_id.c_str(), allocator, pool, allocator);
	}
}

void dnet_io_pools_manager::check(uint64_t &queue_size, uint64_t threads_count) {
	boost::shared_lock<boost::shared_mutex> guard(m_pools_mutex);
	for (auto &item : m_pools) {
		const auto &io_pool = item.second;
		dnet_check_io_pool(io_pool.get(), &queue_size, &threads_count);
	}
}

static int dnet_ids_generate(struct dnet_node *n, const char *file, unsigned long long storage_free) {
	const unsigned long long size_per_id = 100 * 1024 * 1024 * 1024ULL;
	const size_t num = storage_free / size_per_id + 1;
	dnet_raw_id tmp;
	const char *random_source = "/dev/urandom";
	int err = 0;

	std::ifstream in(random_source, std::ofstream::binary);
	std::ofstream out;

	if (!in) {
		err = -errno;
		DNET_LOG_ERROR(n, "failed to open '{}' as source of ids file '{}'", random_source, file);
		goto err_out_exit;
	}

	out.open(file, std::ofstream::binary | std::ofstream::trunc);
	if (!out) {
		err = -errno;
		DNET_LOG_ERROR(n, "failed to open/create ids file '{}'", file);
		goto err_out_unlink;
	}

	for (size_t i = 0; i < num; ++i) {
		if (!in.read(reinterpret_cast<char *>(tmp.id), sizeof(tmp.id))) {
			err = -errno;
			DNET_LOG_ERROR(n, "failed to read id from '{}'", random_source);
			goto err_out_unlink;
		}

		if (!out.write(reinterpret_cast<char *>(tmp.id), sizeof(tmp.id))) {
			err = -errno;
			DNET_LOG_ERROR(n, "failed to write id into ids file '{}'", file);
			goto err_out_unlink;
		}
	}

	return 0;

err_out_unlink:
	out.close();
	unlink(file);
err_out_exit:
	return err;
}

static struct dnet_raw_id *dnet_ids_init(struct dnet_node *n,
                                         const std::string &hdir,
                                         int *id_num,
                                         unsigned long long storage_free,
                                         struct dnet_addr *cfg_addrs,
                                         uint32_t backend_id) {
	int fd, err, num;
	const char *file = "ids";
	char path[hdir.size() + 1 + strlen(file) + 1]; /* / + null-byte */
	struct stat st;
	struct dnet_raw_id *ids;

	snprintf(path, sizeof(path), "%s/%s", hdir.c_str(), file);

again:
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err = -errno;
		if (err == -ENOENT) {
			if (n->flags & DNET_CFG_KEEPS_IDS_IN_CLUSTER) {
				err = dnet_ids_update(n, 1, path, cfg_addrs, backend_id);
			}

			if (err) {
				err = dnet_ids_generate(n, path, storage_free);
			}

			if (err) {
				goto err_out_exit;
			}

			goto again;
		}

		DNET_LOG_ERROR(n, "failed to open ids file '{}'", (const char *)path);
		goto err_out_exit;
	}

	err = fstat(fd, &st);
	if (err)
		goto err_out_close;

	if (st.st_size % sizeof(struct dnet_raw_id)) {
		DNET_LOG_ERROR(n, "Ids file size ({}) is wrong, must be modulo of raw ID size ({})", st.st_size,
		               sizeof(struct dnet_raw_id));
		goto err_out_close;
	}

	num = st.st_size / sizeof(struct dnet_raw_id);
	if (!num) {
		DNET_LOG_ERROR(n, "No ids read, exiting");
		err = -EINVAL;
		goto err_out_close;
	}

	if (n->flags & DNET_CFG_KEEPS_IDS_IN_CLUSTER) {
		dnet_ids_update(n, 0, path, cfg_addrs, backend_id);
	}

	ids = reinterpret_cast<struct dnet_raw_id *>(malloc(st.st_size));
	if (!ids) {
		err = -ENOMEM;
		goto err_out_close;
	}

	err = read(fd, ids, st.st_size);
	if (err != st.st_size) {
		err = -errno;
		DNET_LOG_ERROR(n, "Failed to read ids file '{}'", (const char *)path);
		goto err_out_free;
	}

	close(fd);

	*id_num = num;
	return ids;

err_out_free:
	free(ids);
err_out_close:
	close(fd);
err_out_exit:
	return nullptr;
}

static const char *elapsed(const dnet_time &start) {
	static __thread char buffer[64];
	dnet_time end;
	dnet_current_time(&end);

	const unsigned long long nano = 1000 * 1000 * 1000;

	const unsigned long long delta = (end.tsec - start.tsec) * nano + end.tnsec - start.tnsec;

	snprintf(buffer, sizeof(buffer), "%lld.%06lld secs", delta / nano, (delta % nano) / 1000);
	return buffer;
}


uint32_t dnet_backend_get_backend_id(struct dnet_backend *backend) {
	return backend->backend_id();
}

int dnet_backend_read_only(struct dnet_backend *backend) {
	return backend->read_only() ? 1 : 0;
}

dnet_backend_callbacks *dnet_backend_get_callbacks(struct dnet_backend *backend) {
	return &backend->callbacks();
}

void dnet_backend_sleep_delay(struct dnet_backend *backend) {
	if (!backend || !backend->delay())
		return;

	std::this_thread::sleep_for(std::chrono::milliseconds(backend->delay()));
}

int dnet_backend_init_all(struct dnet_node *node) {
	if (!node || !node->io || !node->io->backends_manager)
		return -EINVAL;

	return node->io->backends_manager->init_all_backends(node->config_data->parallel_start);
}

void dnet_backend_cleanup_all(struct dnet_node *node) {}

static int dnet_backend_set_ids(dnet_node *node,
                                dnet_backend &backend,
                                std::shared_ptr<backend_config> config,
                                dnet_raw_id *ids,
                                uint32_t ids_count) {
	if (config->history.empty()) {
		DNET_LOG_ERROR(node, "backend_set_ids: backend_id: {}, failed to open temporary ids file: "
		                     "history is not specified",
		               backend.backend_id());
		return -EINVAL;
	}

	char tmp_ids[1024];
	char target_ids[1024];
	snprintf(tmp_ids, sizeof(tmp_ids), "%s/ids_%08x%08x", config->history.c_str(), rand(), rand());
	snprintf(target_ids, sizeof(target_ids), "%s/ids", config->history.c_str());
	int err = 0;

	std::ofstream out(tmp_ids, std::ofstream::binary | std::ofstream::trunc);
	if (!out) {
		err = -errno;
		DNET_LOG_ERROR(node, "backend_set_ids: backend_id: {}, failed to open temporary ids file: {}, err: {}",
		               backend.backend_id(), tmp_ids, err);
		return err;
	}

	try {
		out.write(reinterpret_cast<char *>(ids), ids_count * sizeof(dnet_raw_id));
		out.flush();
		out.close();

		if (!out) {
			err = -errno;
			DNET_LOG_ERROR(
			        node,
			        "backend_set_ids: backend_id: {}, failed to write ids to temporary file: {}, err: {}",
			        backend.backend_id(), tmp_ids, err);
		} else {
			if (!err) {
				boost::shared_lock<boost::shared_mutex> guard(backend.state_mutex());
				switch (backend.state()) {
				case DNET_BACKEND_ENABLED:
					err = std::rename(tmp_ids, target_ids);
					if (err) {
						break;
					}
					err = dnet_route_list_enable_backend(node->route, backend.backend_id(),
					                                     backend.group_id(), ids, ids_count);
					break;
				case DNET_BACKEND_DISABLED:
					err = std::rename(tmp_ids, target_ids);
					break;
				default:
					err = -EBUSY;
					break;
				}
			}
		}
	} catch (...) {
		out.close();
		err = -ENOMEM;
	}

	unlink(tmp_ids);
	return err;
}

static int dnet_backend_create(struct dnet_node *node, uint32_t backend_id) {
	try {
		// check if backend with @backend_id is already initialized
		if (node->io->backends_manager->get_backend(backend_id))
			return 0;

		auto config = dnet_node_get_config_data(node)->get_backend_config(backend_id);
		if (!config)
			return -ENOENT;

		node->io->backends_manager->add_backend(config);
		return 0;
	} catch (const std::exception &e) {
		DNET_LOG_ERROR(node, "failed to add backend: {} : {}", backend_id, e.what());
		return -ENOMEM;
	}
}

static int dnet_cmd_backend_control_dangerous(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data) {
	int err = 0;
	struct dnet_node *node = st->n;
	auto *control = reinterpret_cast<struct dnet_backend_control *>(data);

	if (dnet_backend_command(control->command) == DNET_BACKEND_ENABLE) {
		err = dnet_backend_create(node, control->backend_id);
		if (err) {
			DNET_LOG_ERROR(node, "backend_control: backend creation failed: {}, state: {}: {}",
			               control->backend_id, dnet_state_dump_addr(st), err);
			return err;
		}
	}

	auto backend = node->io->backends_manager->get_backend(control->backend_id);
	if (!backend) {
		DNET_LOG_ERROR(node, "backend_control: there is no such backend: {}, state: {}", control->backend_id,
		               dnet_state_dump_addr(st));
		return -EINVAL;
	}

	if (cmd->size != sizeof(dnet_backend_control) + control->ids_count * sizeof(dnet_raw_id)) {
		DNET_LOG_ERROR(node, "backend_control: command size is not enough for ids, state: {}",
		               dnet_state_dump_addr(st));
		return -EINVAL;
	}

	DNET_LOG_INFO(node, "backend_control: received BACKEND_CONTROL: backend_id: {}, command: {}, state: {}",
	              control->backend_id, control->command, dnet_state_dump_addr(st));

	switch (dnet_backend_command(control->command)) {
	case DNET_BACKEND_ENABLE:
		err = backend->enable();
		break;
	case DNET_BACKEND_DISABLE:
		err = backend->disable();
		break;
	case DNET_BACKEND_REMOVE:
		// disable backend before remove to avoid disabling it inside internal calls
		backend->disable();
		err = node->io->backends_manager->remove_backend(control->backend_id);
		break;
	case DNET_BACKEND_START_DEFRAG:
		err = backend->start_defrag((dnet_backend_defrag_level)control->defrag_level);
		break;
	case DNET_BACKEND_STOP_DEFRAG:
		err = backend->stop_defrag();
		break;
	case DNET_BACKEND_SET_IDS:
		err = backend->set_ids(control->ids, control->ids_count);
		break;
	case DNET_BACKEND_READ_ONLY:
		if (backend->read_only()) {
			err = -EALREADY;
		} else {
			backend->set_read_only();
			err = 0;
		}
		break;
	case DNET_BACKEND_WRITEABLE:
		if (!backend->read_only()) {
			err = -EALREADY;
		} else {
			backend->set_read_only(false);
			err = 0;
		}
		break;
	case DNET_BACKEND_CTL:
		backend->set_delay(control->delay);
		err = 0;
		break;
	default:
		err = -ENOTSUP;
		break;
	}

	char buffer[sizeof(dnet_backend_status_list) + sizeof(dnet_backend_status)];
	memset(buffer, 0, sizeof(buffer));

	dnet_backend_status_list *list = reinterpret_cast<dnet_backend_status_list *>(buffer);
	dnet_backend_status *status = reinterpret_cast<dnet_backend_status *>(list + 1);

	list->backends_count = 1;
	backend->fill_status(status);

	if (err) {
		dnet_send_reply(st, cmd, list, sizeof(buffer), true);
	} else {
		cmd->flags &= ~DNET_FLAGS_NEED_ACK;
		err = dnet_send_reply(st, cmd, list, sizeof(buffer), false);
		if (err) {
			cmd->flags |= DNET_FLAGS_NEED_ACK;
			return 0;
		}
	}

	return err;
}

int dnet_cmd_backend_control(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data) {
	dnet_node *node = st->n;

	if (cmd->size < sizeof(dnet_backend_control)) {
		DNET_LOG_ERROR(node, "backend_control: command size is not enough for dnet_backend_control, state: {}",
		               dnet_state_dump_addr(st));
		return -EINVAL;
	}

	try {
		return dnet_cmd_backend_control_dangerous(st, cmd, data);
	} catch (std::bad_alloc &) {
		DNET_LOG_ERROR(node, "backend_control: insufficient memory");
		return -ENOMEM;
	} catch (std::exception &exc) {
		DNET_LOG_ERROR(node, "backend_control: {}", exc.what());
		return -EINVAL;
	}
}

int dnet_cmd_backend_status(struct dnet_net_state *st, struct dnet_cmd *cmd) {
	std::unique_ptr<dnet_backend_status_list, free_destroyer> list(st->n->io->backends_manager->get_status());

	const size_t size = sizeof(dnet_backend_status_list) + list->backends_count * sizeof(dnet_backend_status);

	cmd->flags &= ~DNET_FLAGS_NEED_ACK;
	int err = dnet_send_reply(st, cmd, list.get(), size, false);
	if (err != 0) {
		cmd->flags |= DNET_FLAGS_NEED_ACK;
	}
	return err;
}

static dnet_logger &get_logger(struct dnet_node *node) {
	return *(dnet_node_get_config_data(node)->logger->inner_logger());
}

dnet_backend::dnet_backend(dnet_node *node, std::shared_ptr<backend_config> config)
: m_node{node}
, m_config(config)
, m_read_only{config->read_only_at_start}
, m_delay{0}
, m_state{DNET_BACKEND_DISABLED}
, m_last_start_err{0}
, m_cache{}
, m_log{new blackhole::wrapper_t{get_logger(node), {{"source", "eblob"}, {"backend_id", m_config->backend_id}}}}
, m_pool_id{} {
	dnet_empty_time(&m_last_start);

	memset(&m_callbacks, 0, sizeof(m_callbacks));
}

dnet_backend::~dnet_backend() {
	disable();
}

uint32_t dnet_backend::backend_id() const {
	return m_config->backend_id;
}

uint32_t dnet_backend::group_id() const {
	return m_config->group_id;
}

uint64_t dnet_backend::queue_timeout() const {
	return m_config->queue_timeout;
}

void dnet_backend::set_verbosity(const dnet_log_level level) {
	boost::shared_lock<boost::shared_mutex> guard(m_state_mutex);
	if (m_state != DNET_BACKEND_ENABLED)
		return;

	m_config->config_backend.set_verbosity(&m_config->config_backend, level);
}

int dnet_backend::enable() {
	m_last_start_err = 0;
	m_delay = 0;

	auto fail = [this](int err) {
		m_cache.reset();
		{
			dnet_current_time(&m_last_start);
			m_last_start_err = err;
			change_state(DNET_BACKEND_DISABLED);
		}
		return err;
	};

	dnet_time start;
	dnet_current_time(&start);

	int err = change_state(DNET_BACKEND_ACTIVATING);
	if (err) {
		DNET_LOG_ERROR(m_node, "dnet_backend::enable(): backend: {}, trying to activate not disabled backend, "
		                       "elapsed: {}: {} [{}]",
		               m_config->backend_id, elapsed(start), strerror(-err), err);
		return err;
	}

	m_config = dnet_node_get_config_data(m_node)->get_backend_config(m_config->backend_id);
	if (!m_config)
		return -ENOENT;

	m_read_only = m_config->read_only_at_start;
	m_config->config_backend.log = m_log.get();

	m_command_stats.clear();

	err = m_config->config_backend.init(&m_config->config_backend, dnet_node_get_verbosity(m_node));
	if (err) {
		DNET_LOG_ERROR(m_node, "dnet_backend::enable(): backend: {}, failed to init backend, "
		                       "elapsed: {}: {} [{}]",
		               m_config->backend_id, elapsed(start), strerror(-err), err);
		return fail(err);
	}

	m_callbacks = m_config->config_backend.cb;

	if (!m_config->pool_id.empty()) {
		// use shared io pool if pool_id is set
		m_pool = m_node->io->pools_manager->get(m_config->pool_id);
	} else {
		// use individual io pool if pool_id isn't set
		m_pool = create_io_pool(m_node, std::to_string(m_config->backend_id), m_config->pool_config);
	}

	if (!m_pool) {
		DNET_LOG_ERROR(m_node, "dnet_backend::enable(): backend: {}, failed to attach backend to io_pool, "
		                       "elapsed: {}: {} [{}]",
		               m_config->backend_id, elapsed(start), strerror(-err), err);
		m_config->config_backend.cleanup(&m_config->config_backend);
		return fail(err);
	}

	m_pool_id = m_config->pool_id.empty() ? std::to_string(m_config->backend_id) : m_config->pool_id;

	if (m_config->cache_config.enable) {
		m_cache.reset(new ioremap::cache::cache_manager(m_node, *this, m_config->cache_config));
		if (!m_cache) {
			err = -ENOMEM;
			DNET_LOG_ERROR(m_node, "dnet_backend::enable(): backend: {}, failed to create cache, "
			                       "elapsed: {}: {} [{}]",
			               m_config->backend_id, elapsed(start), strerror(-err), err);
			m_config->config_backend.cleanup(&m_config->config_backend);
			// TODO(shaitan): detach/disable io_pool
			return fail(err);
		}
	}

	int ids_num = 0;
	auto ids = dnet_ids_init(m_node, m_config->history, &ids_num, m_config->config_backend.storage_free,
	                         m_node->addrs, m_config->backend_id);
	if (ids == nullptr) {
		err = -EINVAL;
		DNET_LOG_ERROR(m_node, "dnet_backend::enable(): backend: {}, history path: {}, failed to initialize "
		                       "ids, elapsed: {}: {} [{}]",
		               m_config->backend_id, m_config->history, elapsed(start), strerror(-err), err);
		m_config->config_backend.cleanup(&m_config->config_backend);
		// TODO(shaitan): detach/disable io_pool
		return fail(err);
	}

	err = dnet_route_list_enable_backend(m_node->route, m_config->backend_id, m_config->group_id, ids, ids_num);
	free(ids);

	if (err) {
		DNET_LOG_ERROR(m_node, "dnet_backend::enable(): backend: {}, failed to add backend to route list, "
		                       "elapsed: {}: {} [{}]",
		               m_config->backend_id, elapsed(start), strerror(-err), err);
		m_config->config_backend.cleanup(&m_config->config_backend);
		// TODO(shaitan): detach/disable io_pool
		return fail(err);
	}

	// TODO(shaitan): cleanup everything in case of error

	DNET_LOG_INFO(m_node, "dnet_backend::enable(): backend: {}, initialized, elapsed: {}", m_config->backend_id,
	              elapsed(start));

	change_state(DNET_BACKEND_ENABLED);
	dnet_current_time(&m_last_start);

	return 0;
}

int dnet_backend::disable() {
	int err = change_state(DNET_BACKEND_DEACTIVATING);
	if (err) {
		DNET_LOG_ERROR(m_node, "dnet_backend::disable(): backend_id: {}, "
		                       "trying to disable not enabled backend: {} [{}]",
		               m_config->backend_id, strerror(-err), err);
		return err;
	}

	dnet_route_list_disable_backend(m_node->route, m_config->backend_id);

	if (!m_config->pool_id.empty()) {
		// detach from shared io pool if pool_id was specified
		m_pool.reset();
		m_node->io->pools_manager->detach(m_pool_id);
	} else {
		// stop individual io pool if no pool_id was specified
		stop_io_pool(m_node, m_pool, m_pool_id);
		m_pool.reset();
	}

	m_pool_id.clear();
	m_cache.reset();
	m_config->config_backend.cleanup(&m_config->config_backend);
	memset(&m_callbacks, 0, sizeof(m_callbacks));

	m_command_stats.clear();

	change_state(DNET_BACKEND_DISABLED);
	return 0;
}

class bulk_read_handler : public std::enable_shared_from_this<bulk_read_handler> {
public:
	explicit bulk_read_handler(struct dnet_net_state *st, const struct dnet_cmd *cmd)
	: m_session(st->n)
	, m_node(st->n)
	, m_state(dnet_state_get(st))
	, m_orig_cmd(*cmd)
	, m_total(0) {
		using namespace ioremap::elliptics;
		m_session.set_exceptions_policy(session::no_exceptions);
		m_session.set_filter(filters::all_with_ack);
		m_session.set_trace_id(cmd->trace_id);
		m_session.set_trace_bit(!!(cmd->flags & DNET_FLAGS_TRACE_BIT));
	}

	void start(const ioremap::elliptics::dnet_bulk_read_request &request) {
		using namespace ioremap::elliptics;

		m_total = request.keys.size();
		for (const auto &id : request.keys) {
			auto backend_id = dnet_state_search_backend(m_node, &id);
			if (backend_id < 0) {
				send_fail_reply(id, backend_id, -ENXIO);
				continue;
			}

			m_backend_keys[backend_id].emplace_back(id);
		}

		m_num_backend_responses.reserve(m_backend_keys.size());
		for (const auto &pair : m_backend_keys) {
			auto &backend_id = pair.first;
			m_num_backend_responses.emplace(backend_id, 0);
		}

		dnet_time current_time;
		dnet_current_time(&current_time);
		if (request.deadline.tsec > current_time.tsec) {
			m_session.set_timeout(request.deadline.tsec - current_time.tsec);
		} else {
			DNET_LOG_ERROR(m_node, "{}: local: expired, skip sending keys to local backends: deadline: {}",
				       dnet_cmd_string(DNET_CMD_BULK_READ_NEW), dnet_print_time(&request.deadline));
			return;
		}

		m_session.set_ioflags(request.ioflags);
		address addr(m_node->addrs[0]);
		for (const auto &pair : m_backend_keys) {
			auto &backend_id = pair.first;
			auto &keys = pair.second;

			m_session.set_direct_id(addr, backend_id);

			auto async = send_bulk_read(m_session, keys, request.read_flags);
			async.connect(
				std::bind(&bulk_read_handler::process, shared_from_this(), backend_id,
					  std::placeholders::_1),
				std::bind(&bulk_read_handler::complete, shared_from_this(), backend_id,
					  std::placeholders::_1)
			);
		}
	}

private:
	void process(uint32_t backend_id, const ioremap::elliptics::callback_result_entry &entry) {
		const auto entry_cmd = entry.command();
		if (entry_cmd->status == 0) {
			const auto data = entry.data();
			dnet_cmd cmd(m_orig_cmd);
			cmd.id = entry_cmd->id;
			cmd.backend_id = backend_id;

			send_reply(cmd, data);
		} else {
			send_fail_reply(entry_cmd->id, backend_id, entry_cmd->status);
		}
		++m_num_backend_responses[backend_id];

		DNET_LOG_NOTICE(m_node, "{}: {}: local: process: status: {}", dnet_dump_id(&entry_cmd->id),
				dnet_cmd_string(DNET_CMD_BULK_READ_NEW), entry_cmd->status);
	}

	void complete(uint32_t backend_id, const ioremap::elliptics::error_info &error) {
		/* Send fail replies for keys which wasn't processed by backend. Keys are read in original order,
		 * so number of read keys can be used as index of last read key.
		 */
		const auto &keys = m_backend_keys[backend_id];
		for (size_t i = m_num_backend_responses[backend_id]; i < keys.size(); ++i) {
			send_fail_reply(keys[i], backend_id, error.code());
		}

		DNET_LOG_NOTICE(m_node, "{}: local: complete: status: {}", dnet_cmd_string(DNET_CMD_BULK_READ_NEW),
				error.code());
	}

	void send_fail_reply(const dnet_id &id, uint32_t backend_id, int err) {
		dnet_cmd cmd(m_orig_cmd);
		cmd.id = id;
		cmd.status = err;
		cmd.backend_id = backend_id;

		send_reply(cmd, {});
	}

	void send_reply(struct dnet_cmd &cmd, const ioremap::elliptics::data_pointer &data) {
		std::lock_guard<std::mutex> gurad(m_mutex);

		const int more = --m_total > 0 ? 1 : 0;
		dnet_send_reply(m_state.get(), &cmd, data.data(), data.size(), more);
	}

private:
	ioremap::elliptics::newapi::session m_session;
	struct dnet_node *m_node;
	ioremap::elliptics::net_state_ptr m_state;
	const struct dnet_cmd m_orig_cmd;
	std::unordered_map<uint32_t, std::vector<dnet_id>> m_backend_keys; // backend_id -> [list of keys]
	std::unordered_map<uint32_t, size_t> m_num_backend_responses;      // backend_id -> num_responses
	size_t m_total;
	std::mutex m_mutex;
};

int dnet_cmd_bulk_read_new(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data) {
	if (cmd->backend_id >= 0) {
		return -ENOTSUP;
	}

	if (!st || !st->n || !st->n->addrs || !data) {
		return -EINVAL;
	}

	using namespace ioremap::elliptics;

	dnet_bulk_read_request request;
	deserialize(data_pointer::from_raw(data, cmd->size), request);

	cmd->flags &= ~DNET_FLAGS_NEED_ACK;
	auto handler = std::make_shared<bulk_read_handler>(st, cmd);
	handler->start(request);

	return 0;
}

int dnet_backend::change_state(dnet_backend_state state) {
	auto set_activating = [this]() {
		switch (m_state) {
		case DNET_BACKEND_DISABLED:
			m_state = DNET_BACKEND_ACTIVATING;
			return 0;
		case DNET_BACKEND_ENABLED:
			return -EALREADY;
		case DNET_BACKEND_ACTIVATING:
			return -EINPROGRESS;
		case DNET_BACKEND_DEACTIVATING:
			return -EAGAIN;
		default:
			return -EINVAL;
		}
	};

	auto set_deactivating = [this]() {
		switch (m_state) {
		case DNET_BACKEND_ENABLED:
			m_state = DNET_BACKEND_DEACTIVATING;
			return 0;
		case DNET_BACKEND_DISABLED:
			return -EALREADY;
		case DNET_BACKEND_ACTIVATING:
			return -EAGAIN;
		case DNET_BACKEND_DEACTIVATING:
			return -EINPROGRESS;
		default:
			return -EINVAL;
		}
	};

	boost::unique_lock<boost::shared_mutex> guard(m_state_mutex);
	switch (state) {
	case DNET_BACKEND_DISABLED:
		m_state = DNET_BACKEND_DISABLED;
		return 0;
	case DNET_BACKEND_ENABLED:
		m_state = DNET_BACKEND_ENABLED;
		return 0;
	case DNET_BACKEND_ACTIVATING:
		return set_activating();
	case DNET_BACKEND_DEACTIVATING:
		return set_deactivating();
	};

	return -EINVAL;
}

int dnet_backend::start_defrag(const dnet_backend_defrag_level level) {
	if (!m_callbacks.defrag_start) {
		return -ENOTSUP;
	}

	return m_callbacks.defrag_start(m_callbacks.command_private, level);
}

int dnet_backend::stop_defrag() {
	if (!m_callbacks.defrag_stop)
		return -ENOTSUP;

	return m_callbacks.defrag_stop(m_callbacks.command_private);
}

int dnet_backend::set_ids(struct dnet_raw_id *ids, uint32_t ids_count) {
	return dnet_backend_set_ids(m_node, *this, m_config, ids, ids_count);
}

void dnet_backend::fill_status(struct dnet_backend_status *status) {
	status->backend_id = m_config->backend_id;

	boost::shared_lock<boost::shared_mutex> guard(m_state_mutex);
	status->state = m_state;
	if (m_state == DNET_BACKEND_ENABLED && m_callbacks.defrag_status)
		status->defrag_state = m_callbacks.defrag_status(m_callbacks.command_private);
	status->last_start = m_last_start;
	status->last_start_err = m_last_start_err;
	status->read_only = m_read_only;
	status->delay = m_delay;
}

void dnet_backend::fill_status(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator) {
	value.AddMember("backend_id", m_config->backend_id, allocator);
	rapidjson::Value status(rapidjson::kObjectType);
	status.AddMember("backend_id",  m_config->backend_id, allocator);
	status.AddMember("state",  (int)m_state, allocator);
	status.AddMember("string_state",  dnet_backend_state_string(m_state), allocator);
	status.AddMember("read_only",  m_read_only, allocator);
	status.AddMember("delay",  m_delay, allocator);
	status.AddMember("group",  m_config->group_id, allocator);
	status.AddMember("pool_id", m_pool_id.c_str(), allocator);
	const auto defrag_state = (m_state == DNET_BACKEND_ENABLED && m_callbacks.defrag_status)
	                                  ? m_callbacks.defrag_status(m_callbacks.command_private)
	                                  : 0;
	status.AddMember("defrag_state", defrag_state, allocator);
	status.AddMember("string_defrag_state", dnet_backend_defrag_state_string(defrag_state), allocator);
	rapidjson::Value last_start(rapidjson::kObjectType);
	{
		last_start.AddMember("tv_sec", m_last_start.tsec, allocator);
		last_start.AddMember("tv_usec", m_last_start.tnsec / 1000, allocator);
	}
	status.AddMember("last_start", last_start, allocator);
	status.AddMember("string_last_time", dnet_print_time(&m_last_start), allocator);
	status.AddMember("last_start_err", m_last_start_err, allocator);
	value.AddMember("status", status, allocator);
}

void dnet_backend::fill_backend_stats(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Document backend(&allocator);
	if (m_state == DNET_BACKEND_ENABLED) {
		char *json_stat = nullptr;
		size_t json_size = 0;
		m_callbacks.storage_stat_json(m_callbacks.command_private, &json_stat, &json_size);
		if (json_stat && json_size) {
			backend.Parse<0>(json_stat);
			auto &config_value = backend["config"];
			config_value.AddMember("group", m_config->group_id, allocator);
			config_value.AddMember("queue_timeout", m_config->queue_timeout, allocator);
		}
		free(json_stat);
	} else {
		if (m_state == DNET_BACKEND_DISABLED) {
			/* load actual config from config file. Load only for disabled backend since
			 * in other state current config is in-use.
			 */
			auto config_data = dnet_node_get_config_data(m_node);
			m_config = config_data->get_backend_config(m_config->backend_id);
			if (!m_config)
				// backend was lost from updated config file, skip it.
				return;
		}

		char *json_stat = nullptr;
		size_t json_size = 0;
		m_config->config_backend.to_json(&m_config->config_backend, &json_stat, &json_size);
		if (json_stat && json_size) {
			rapidjson::Document config_value(&allocator);
			config_value.Parse<0>(json_stat);
			config_value.AddMember("group", m_config->group_id, allocator);
			config_value.AddMember("queue_timeout", m_config->queue_timeout, allocator);
			backend.SetObject();
			backend.AddMember("config", static_cast<rapidjson::Value &>(config_value), allocator);
		}
		free(json_stat);
	}

	if (!backend.IsObject())
		backend.SetObject();

	rapidjson::Document initial_config(&allocator);
	initial_config.Parse<0>(m_config->raw_config.c_str());
	backend.AddMember("initial_config", static_cast<rapidjson::Value &>(initial_config), allocator);

	value.AddMember("backend", static_cast<rapidjson::Value &>(backend), allocator);
}

void dnet_backend::fill_io_stats(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator) {
	if (m_state != DNET_BACKEND_ENABLED)
		return;

	rapidjson::Value io(rapidjson::kObjectType);
	ioremap::monitor::dump_io_pool_stats(*m_pool, io, allocator);
	value.AddMember("io", io, allocator);
}

void dnet_backend::fill_cache_stats(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator) {
	if (m_state != DNET_BACKEND_ENABLED || !m_cache)
		return;

	rapidjson::Value cache;
	m_cache->statistics(cache, allocator);
	value.AddMember("cache", cache, allocator);
}

void dnet_backend::fill_commands_stats(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator) {
	if (m_state != DNET_BACKEND_ENABLED)
		return;

	rapidjson::Value commands_value(rapidjson::kObjectType);
	m_command_stats.commands_report(nullptr, commands_value, allocator);
	value.AddMember("commands", commands_value, allocator);
}

void dnet_backend::statistics(uint64_t categories,
                              rapidjson::Value &value,
                              rapidjson::Document::AllocatorType &allocator) {
	boost::shared_lock<boost::shared_mutex> guard(m_state_mutex);
	fill_status(value, allocator);
	if (categories & DNET_MONITOR_BACKEND)
		fill_backend_stats(value, allocator);
	if (categories & DNET_MONITOR_IO)
		fill_io_stats(value, allocator);
	if (categories & DNET_MONITOR_CACHE)
		fill_cache_stats(value, allocator);
	if (categories & DNET_MONITOR_COMMANDS)
		fill_commands_stats(value, allocator);
}

dnet_backends_manager::dnet_backends_manager(struct dnet_node *node)
: m_node(node) {
	auto data = dnet_node_get_config_data(node);
	for (auto &config : data->backends) {
		add_backend(std::move(config));
	}

	// data->backends has been used and now longer needed, so clear it.
	data->backends.clear();
}

dnet_backends_manager::~dnet_backends_manager() {
	boost::upgrade_lock<boost::shared_mutex> guard(m_backends_mutex);
	for (auto &item: m_backends) {
		auto &backend = item.second;
		backend->disable();
	}

	boost::upgrade_to_unique_lock<boost::shared_mutex> unique_guard(guard);
	m_backends.clear();
}

bool dnet_backends_manager::add_backend(std::shared_ptr<backend_config> config) {
	if (m_backends.find(config->backend_id) != m_backends.end())
		return false;

	m_backends.emplace(config->backend_id, std::make_shared<dnet_backend>(m_node, config));
	return true;
}

std::shared_ptr<dnet_backend> dnet_backends_manager::get_backend(uint32_t backend_id) {
	boost::shared_lock<boost::shared_mutex> guard(m_backends_mutex);

	auto it = m_backends.find(backend_id);
	if (it == m_backends.end())
		return nullptr;

	return it->second;
}

int dnet_backends_manager::remove_backend(uint32_t backend_id) {
	boost::unique_lock<boost::shared_mutex> guard(m_backends_mutex);
	auto it = m_backends.find(backend_id);
	if (it == m_backends.end())
		return -ENOENT;

	m_backends.erase(it);
	return 0;
}

int dnet_backends_manager::init_all_backends(bool parallel) {
	int err = 1;
	bool all_ok = true;

	if (parallel) {
		try {
			using namespace ioremap::elliptics;
			session sess(m_node);
			sess.set_exceptions_policy(session::no_exceptions);
			sess.set_timeout(std::numeric_limits<unsigned>::max() / 2);

			session clean_sess = sess.clean_clone();

			std::vector<async_backend_control_result> results;
			results.reserve(m_backends.size());

			for (const auto &item : m_backends) {
				const auto &backend_id = item.first;
				const auto &backend = item.second;

				if (!backend->config()->enable_at_start)
					continue;

				results.emplace_back(clean_sess.enable_backend(m_node->st->addr, backend_id));
			}

			if (results.size()) {
				async_backend_control_result result =
				        ioremap::elliptics::aggregated(sess, results.begin(), results.end());
				result.wait();

				const int tmp = result.error().code();
				if (!tmp) {
					err = 0;
				} else if (err == 1) {
					DNET_LOG_ERROR(m_node, "Failed to initialize backend: {}", tmp);
					err = tmp;
					all_ok = false;
				}
			} else {
				err = 0;
			}
		} catch (std::bad_alloc &) {
			return -ENOMEM;
		}
	} else {
		for (const auto &item : m_backends) {
			auto &backend = item.second;

			if (!backend->config()->enable_at_start)
				continue;

			const int tmp = backend->enable();
			if (!tmp) {
				err = 0;
			} else if (err == 1) {
				err = tmp;
				all_ok = false;
			}
		}
	}

	if (all_ok) {
		err = 0;
	} else if (err == 1) {
		err = -EINVAL;
	}

	DNET_LOG(m_node, err ? DNET_LOG_ERROR : DNET_LOG_NOTICE,
	         "dnet_backends_manager::init_all_backends(): finished initializing all backends: {}", err);

	return err;
}


void dnet_backends_manager::set_verbosity(const dnet_log_level level) {
	boost::shared_lock<boost::shared_mutex> guard(m_backends_mutex);

	for (const auto &item: m_backends) {
		const auto &backend = item.second;
		backend->set_verbosity(level);
	}
}

struct dnet_backend_status_list *dnet_backends_manager::get_status() {
	boost::shared_lock<boost::shared_mutex> guard(m_backends_mutex);
	auto backends = [this]() {
		std::vector<std::shared_ptr<dnet_backend>> sorted;
		sorted.reserve(m_backends.size());
		for (auto &item : m_backends) {
			sorted.emplace_back(item.second);
		}

		std::sort(sorted.begin(), sorted.end(), [](const std::shared_ptr<dnet_backend> &lhs,
		                                           const std::shared_ptr<dnet_backend> &rhs) {
			return lhs->backend_id() < rhs->backend_id();
		});
		return sorted;
	}();

	const size_t size = sizeof(dnet_backend_status_list) + backends.size() * sizeof(dnet_backend_status);

	auto list = reinterpret_cast<dnet_backend_status_list *>(calloc(1, size));

	size_t i = 0;
	for (auto &backend : backends) {
		backend->fill_status(&list->backends[i++]);
	}
	list->backends_count = i;

	return list;
}

void dnet_backends_manager::statistics(uint64_t categories,
                                       rapidjson::Value &value,
                                       rapidjson::Document::AllocatorType &allocator) {
	value.SetObject();

	boost::shared_lock<boost::shared_mutex> guard(m_backends_mutex);
	for (auto &item: m_backends) {
		const auto backend_id = std::to_string(item.first);
		auto backend = item.second;

		rapidjson::Value backend_value(rapidjson::kObjectType);
		backend->statistics(categories, backend_value, allocator);
		value.AddMember(backend_id.c_str(), allocator, backend_value, allocator);
	}
}

void dnet_io_pools_dump_stats(struct dnet_node *node,
                              rapidjson::Value &value,
                              rapidjson::Document::AllocatorType &allocator) {
	node->io->pools_manager->statistics(value, allocator);
}

void dnet_io_pools_check(struct dnet_io_pools_manager *pools_manager, uint64_t *queue_size, uint64_t *threads_count) {
	if (!pools_manager)
		return;

	pools_manager->check(*queue_size, *threads_count);
}

int dnet_backends_init(struct dnet_node *node) {
	std::unique_ptr<dnet_io_pools_manager> pools{new(std::nothrow) dnet_io_pools_manager(node)};
	if (!pools) {
		DNET_LOG_ERROR(node, "backends: failed to initialize dnet_io_pools_manager");
		return -ENOMEM;
	}

	std::unique_ptr<dnet_backends_manager> backends{new(std::nothrow) dnet_backends_manager(node)};
	if (!backends) {
		DNET_LOG_ERROR(node, "backends: failed to initialize dnet_backends_manager");
		return -ENOMEM;
	}

	node->io->pools_manager = pools.release();
	node->io->backends_manager = backends.release();

	return 0;
}

void dnet_backends_destroy(struct dnet_node *node) {
	delete node->io->backends_manager;
	delete node->io->pools_manager;
}

struct dnet_backend *dnet_backends_get_backend(struct dnet_node *node, uint32_t backend_id) {
	return node->io->backends_manager->get_backend(backend_id).get();
}

struct dnet_io_pool *dnet_backend_get_pool(struct dnet_node *node, uint32_t backend_id) {
	if (!node || !node->io || !node->io->backends_manager)
		return nullptr;

	return node->io->backends_manager->get_backend(backend_id)->io_pool();
}

uint64_t dnet_backend_get_queue_timeout(struct dnet_node *node, ssize_t backend_id) {
	if (!node || !node->io || !node->io->backends_manager)
		return 0;
	if (backend_id < 0)
		return dnet_node_get_queue_timeout(node);

	auto backend = node->io->backends_manager->get_backend(backend_id);
	if (!backend)
		return dnet_node_get_queue_timeout(node);

	return backend->queue_timeout();
}

int dnet_backend_process_cmd_raw(struct dnet_backend *backend,
                                 struct dnet_net_state *st,
                                 struct dnet_cmd *cmd,
                                 void *data,
                                 struct dnet_cmd_stats *cmd_stats) {
	auto &callbacks = backend->callbacks();
	return callbacks.command_handler(st, callbacks.command_private, cmd, data, cmd_stats);
}
