#include "elliptics.h"
#include "monitor/monitor.hpp"
#include "example/config.hpp"
#include "bindings/cpp/functional_p.h"
#include "bindings/cpp/session_internals.hpp"
#include "library/logger.hpp"
#include "library/protocol.hpp"

#include <fstream>
#include <memory>

#include <fcntl.h>

static int dnet_ids_generate(struct dnet_node *n, const char *file, unsigned long long storage_free)
{
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

static struct dnet_raw_id *dnet_ids_init(struct dnet_node *n, const char *hdir, int *id_num,
		unsigned long long storage_free, struct dnet_addr *cfg_addrs, size_t backend_id)
{
	int fd, err, num;
	const char *file = "ids";
	char path[strlen(hdir) + 1 + strlen(file) + 1]; /* / + null-byte */
	struct stat st;
	struct dnet_raw_id *ids;

	snprintf(path, sizeof(path), "%s/%s", hdir, file);

again:
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err = -errno;
		if (err == -ENOENT) {
			if (n->flags & DNET_CFG_KEEPS_IDS_IN_CLUSTER)
				err = dnet_ids_update(n, 1, path, cfg_addrs, backend_id);
			if (err)
				err = dnet_ids_generate(n, path, storage_free);

			if (err)
				goto err_out_exit;

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

	if (n->flags & DNET_CFG_KEEPS_IDS_IN_CLUSTER)
		dnet_ids_update(n, 0, path, cfg_addrs, backend_id);

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
	return NULL;
}

static int dnet_backend_io_init(struct dnet_node *n, struct dnet_backend_io *io,
		int io_thread_num, int nonblocking_io_thread_num)
{
	int err;

	err = dnet_backend_command_stats_init(io);
	if (err) {
		DNET_LOG_ERROR(n, "dnet_backend_io_init: backend: {}, failed to allocate command stat structure: {}",
		               io->backend_id, err);
		goto err_out_exit;
	}

	err = dnet_work_pool_alloc(&io->pool.recv_pool, n, io,
			io_thread_num, DNET_WORK_IO_MODE_BLOCKING,
			dnet_io_process);
	if (err) {
		goto err_out_command_stats_cleanup;
	}

	err = dnet_work_pool_alloc(&io->pool.recv_pool_nb, n, io,
			nonblocking_io_thread_num, DNET_WORK_IO_MODE_NONBLOCKING,
			dnet_io_process);
	if (err) {
		err = -ENOMEM;
		goto err_out_free_recv_pool;
	}

	return 0;

err_out_free_recv_pool:
	n->need_exit = 1;
	dnet_work_pool_exit(&io->pool.recv_pool);
err_out_command_stats_cleanup:
	dnet_backend_command_stats_cleanup(io);
err_out_exit:
	return err;
}

static void dnet_backend_io_cleanup(struct dnet_node *n, struct dnet_backend_io *io)
{
	(void) n;

	dnet_work_pool_exit(&io->pool.recv_pool);
	dnet_work_pool_exit(&io->pool.recv_pool_nb);
	dnet_backend_command_stats_cleanup(io);

	DNET_LOG_NOTICE(n, "dnet_backend_io_cleanup: backend: {}", io->backend_id);
}

static const char *elapsed(const dnet_time &start)
{
	static __thread char buffer[64];
	dnet_time end;
	dnet_current_time(&end);

	const unsigned long long nano = 1000 * 1000 * 1000;

	const unsigned long long delta = (end.tsec - start.tsec) * nano + end.tnsec - start.tnsec;

	snprintf(buffer, sizeof(buffer), "%lld.%06lld secs", delta / nano, (delta % nano) / 1000);
	return buffer;
}

static int dnet_backend_init(struct dnet_node *node, size_t backend_id)
{
	int ids_num;
	struct dnet_raw_id *ids;

	auto backend = node->config_data->backends->get_backend(backend_id);
	if (!backend) {
		DNET_LOG_ERROR(node, "backend_init: backend: {}, invalid backend id", backend_id);
		return -EINVAL;
	}

	dnet_time start;
	dnet_current_time(&start);

	{
		std::lock_guard<std::mutex> guard(*backend->state_mutex);
		if (backend->state != DNET_BACKEND_DISABLED) {
			DNET_LOG_ERROR(
			        node, "backend_init: backend: {}, trying to activate not disabled backend, elapsed: {}",
			        backend_id, elapsed(start));
			switch (backend->state) {
				case DNET_BACKEND_ENABLED:
					return -EALREADY;
				case DNET_BACKEND_ACTIVATING:
					return -EINPROGRESS;
				case DNET_BACKEND_DEACTIVATING:
					return -EAGAIN;
				case DNET_BACKEND_UNITIALIZED:
				default:
					return -EINVAL;
			}
		}
		backend->state = DNET_BACKEND_ACTIVATING;
	}

	DNET_LOG_INFO(node, "backend_init: backend: {}, initializing", backend_id);

	int err;
	dnet_backend_io *backend_io;

	try {
		using namespace ioremap::elliptics::config;
		auto &data = *static_cast<config_data *>(node->config_data);
		auto parser = data.parse_config();
		auto cfg = parser->root();
		const auto backends_config = cfg["backends"];
		bool found = false;

		for (size_t index = 0; index < backends_config.size(); ++index) {
			const auto backend_config = backends_config[index];
			const uint32_t config_backend_id = backend_config.at<uint32_t>("backend_id");
			if (backend_id == config_backend_id) {
				backend->parse(&data, backend_config);
				found = true;
				break;
			}
		}

		if (!found) {
			err = -EBADF;
			DNET_LOG_ERROR(node, "backend_init: backend: {}, have not found backend section in "
			                     "configuration file, elapsed: {}",
			               backend_id, elapsed(start));
			goto err_out_exit;
		}
	} catch (std::bad_alloc &) {
		err = -ENOMEM;
		DNET_LOG_ERROR(node, "backend_init: backend: {}, failed as not enough memory, elapsed: {}", backend_id,
		               elapsed(start));
		goto err_out_exit;
	} catch (std::exception &exc) {
		DNET_LOG_ERROR(node, "backend_init: backend: {}, failed to read configuration file: {}, elapsed: {}",
		               backend_id, exc.what(), elapsed(start));
		err = -EBADF;
		goto err_out_exit;
	}

	backend->config = backend->config_template;
	backend->data.assign(backend->data.size(), '\0');
	backend->config.data = backend->data.data();
	backend->config.log = backend->log.get();

	backend_io = dnet_get_backend_io(node->io, backend_id);
	backend_io->need_exit = 0;
	backend_io->read_only = backend->read_only_at_start;
	backend_io->queue_timeout = backend->queue_timeout;

	for (auto it = backend->options.begin(); it != backend->options.end(); ++it) {
		const dnet_backend_config_entry &entry = *it;
		entry.entry->callback(&backend->config, entry.entry->key, entry.value_template.data());
	}

	err = backend->config.init(&backend->config, dnet_node_get_verbosity(node));
	if (err) {
		DNET_LOG_ERROR(node, "backend_init: backend: {}, failed to init backend: {}, elapsed: {}", backend_id,
		               err, elapsed(start));
		goto err_out_exit;
	}

	backend_io->cb = &backend->config.cb;

	err = dnet_backend_io_init(node, backend_io, backend->io_thread_num, backend->nonblocking_io_thread_num);
	if (err) {
		DNET_LOG_ERROR(node, "backend_init: backend: {}, failed to init io pool, err: {}, elapsed: {}",
		               backend_id, err, elapsed(start));
		goto err_out_backend_cleanup;
	}

	if (backend->cache_config) {
		backend_io->cache = backend->cache = dnet_cache_init(node, backend_io, backend->cache_config.get());
		if (!backend->cache) {
			err = -ENOMEM;
			DNET_LOG_ERROR(node, "backend_init: backend: {}, failed to init cache, err: {}, elapsed: {}",
			               backend_id, err, elapsed(start));
			goto err_out_backend_io_cleanup;
		}
	}

	ids_num = 0;
	ids = dnet_ids_init(node, backend->history.c_str(), &ids_num, backend->config.storage_free, node->addrs, backend_id);
	if (ids == NULL) {
		err = -EINVAL;
		DNET_LOG_ERROR(
		        node,
		        "backend_init: backend: {}, history path: {}, failed to initialize ids, elapsed: {}: {} [{}]",
		        backend_id, backend->history, elapsed(start), strerror(-err), err);
		goto err_out_cache_cleanup;
	}
	err = dnet_route_list_enable_backend(node->route, backend_id, backend->group, ids, ids_num);
	free(ids);

	if (err) {
		DNET_LOG_ERROR(node,
		               "backend_init: backend: {}, failed to add backend to route list, err: {}, elapsed: {}",
		               backend_id, err, elapsed(start));
		goto err_out_cache_cleanup;
	}

	DNET_LOG_INFO(node, "backend_init: backend: {}, initialized, elapsed: {}", backend_id, elapsed(start));

	{
		std::lock_guard<std::mutex> guard(*backend->state_mutex);
		dnet_current_time(&backend->last_start);
		backend->last_start_err = 0;
		backend->state = DNET_BACKEND_ENABLED;
	}
	return 0;

	dnet_route_list_disable_backend(node->route, backend_id);
err_out_cache_cleanup:
	if (backend->cache) {
		/* Set need_exit to stop cache's threads */
		backend_io->need_exit = 1;
		dnet_cache_cleanup(backend->cache);
		backend->cache = NULL;
		backend_io->cache = NULL;
	}
err_out_backend_io_cleanup:
	backend_io->need_exit = 1;
	dnet_backend_io_cleanup(node, backend_io);
	backend_io->cb = nullptr;
err_out_backend_cleanup:
	backend->config.cleanup(&backend->config);
err_out_exit:
	{
		std::lock_guard<std::mutex> guard(*backend->state_mutex);
		dnet_current_time(&backend->last_start);
		backend->last_start_err = err;
		backend->state = DNET_BACKEND_DISABLED;
	}
	return err;
}

static int dnet_backend_cleanup(struct dnet_node *node, size_t backend_id)
{
	auto backend = node->config_data->backends->get_backend(backend_id);
	if (!backend) {
		return -EINVAL;
	}

	{
		std::lock_guard<std::mutex> guard(*backend->state_mutex);
		if (backend->state != DNET_BACKEND_ENABLED) {
			DNET_LOG_ERROR(node, "backend_cleanup: backend: {}, trying to destroy not activated backend",
			               backend_id);
			switch (backend->state) {
				case DNET_BACKEND_DISABLED:
					return -EALREADY;
				case DNET_BACKEND_DEACTIVATING:
					return -EINPROGRESS;
				case DNET_BACKEND_ACTIVATING:
					return -EAGAIN;
				case DNET_BACKEND_UNITIALIZED:
				default:
					return -EINVAL;
			}
		}
		backend->state = DNET_BACKEND_DEACTIVATING;
	}

	DNET_LOG_INFO(node, "backend_cleanup: backend: {}, destroying", backend_id);

	if (node->route)
		dnet_route_list_disable_backend(node->route, backend_id);

	dnet_backend_io *backend_io = node->io ? dnet_get_backend_io(node->io, backend_id) : nullptr;

	// set @need_exit to true to force cache lifecheck thread to exit and slru cache to sync all elements to backend
	// this also leads to IO threads to stop, but since we already removed itself from route table,
	// and cache syncs data to backend either in lifecheck thread or in destructor context,
	// it is safe to set @need_exit early
	if (backend_io)
		backend_io->need_exit = 1;

	DNET_LOG_INFO(node, "backend_cleanup: backend: {}: cleaning cache", backend_id);
	dnet_cache_cleanup(backend->cache);
	backend->cache = NULL;

	DNET_LOG_INFO(node, "backend_cleanup: backend: {}: cleaning io: {:p}", backend_id, (void *)backend_io);
	if (backend_io) {
		dnet_backend_io_cleanup(node, backend_io);
		backend_io->cb = NULL;
	}

	backend->config.cleanup(&backend->config);
	memset(&backend->config.cb, 0, sizeof(backend->config.cb));

	{
		std::lock_guard<std::mutex> guard(*backend->state_mutex);
		backend->state = DNET_BACKEND_DISABLED;
	}

	DNET_LOG_INFO(node, "backend_cleanup: backend: {}, destroyed", backend_id);

	return 0;
}

/* Disable and remove backend */
static int dnet_backend_remove(struct dnet_node *node, size_t backend_id) {
	const int err = dnet_backend_cleanup(node, backend_id);
	if (err && err != -EALREADY) {
		DNET_LOG_INFO(node, "backend_remove: backend: {}, failed to disable backend: {} [{}]", backend_id,
		              strerror(-err), err);
		return err;
	}

	node->config_data->backends->remove_backend(backend_id);

	DNET_LOG_INFO(node, "backend_remove: backend: {}, removed", backend_id);
	return 0;
}


int dnet_backend_create(struct dnet_node *node, size_t backend_id)
{
	auto backends = node->config_data->backends;
	auto backend = backends->get_backend(backend_id);
	if (backend)
		return 0;

	try {
		using namespace ioremap::elliptics::config;
		auto data = static_cast<config_data *>(node->config_data);
		auto parser = data->parse_config();
		auto cfg = parser->root();
		const auto backends_config = cfg["backends"];

		for (size_t index = 0; index < backends_config.size(); ++index) {
			const auto backend_config = backends_config[index];

			if (backend_id == backend_config.at<uint32_t>("backend_id")) {
				backend = dnet_parse_backend(data, backend_id, backend_config);
			}
		}
	} catch (std::bad_alloc &) {
		DNET_LOG_ERROR(node, "backend_create: backend: {}, failed as not enough memory", backend_id);
		return -ENOMEM;
	} catch (std::exception &exc) {
		DNET_LOG_ERROR(node, "backend_create: backend: {}, failed to read configuration file: {}", backend_id,
		               exc.what());
		return -EBADF;
	}

	if (!backend)
		return -ENOENT;

	int err = dnet_server_backend_init(node, backend_id);
	if (!err) {
		backends->add_backend(backend);
	}

	return err;
}

int dnet_backend_init_all(struct dnet_node *node)
{
	int err = 1;
	bool all_ok = true;

	auto backends = node->config_data->backends;
	using namespace ioremap::elliptics::config;
	auto &data = *static_cast<config_data *>(node->config_data);
	auto parser = data.parse_config();
	auto cfg = parser->root();
	const auto backends_config = cfg["backends"];

	if (node->config_data->parallel_start) {
		try {
			using ioremap::elliptics::session;
			using ioremap::elliptics::async_backend_control_result;

			session sess(node);
			sess.set_exceptions_policy(session::no_exceptions);
			sess.set_timeout(std::numeric_limits<unsigned>::max() / 2);

			session clean_sess = sess.clean_clone();

			std::vector<async_backend_control_result> results;


			for (size_t index = 0; index < backends_config.size(); ++index) {
				const auto backend_config = backends_config[index];
				const uint32_t backend_id = backend_config.at<uint32_t>("backend_id");
				auto backend = backends->get_backend(backend_id);
				if (!backend->enable_at_start) {
					backend->parse(&data, backend_config);
					continue;
				}

				results.emplace_back(clean_sess.enable_backend(node->st->addr, backend_id));
			}

			async_backend_control_result result =
				ioremap::elliptics::aggregated(sess, results.begin(), results.end());
			result.wait();

			err = result.error().code();
		} catch (std::bad_alloc &) {
			return -ENOMEM;
		}
	} else {
		for (size_t index = 0; index < backends_config.size(); ++index) {
			const auto backend_config = backends_config[index];
			const uint32_t backend_id = backend_config.at<uint32_t>("backend_id");
			auto backend = backends->get_backend(backend_id);
			if (!backend->enable_at_start) {
				backend->parse(&data, backend_config);
				continue;
			}

			int tmp = dnet_backend_init(node, backend_id);
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

	DNET_LOG(node, err ? DNET_LOG_ERROR : DNET_LOG_NOTICE,
	         "backend_init_all: finished initializing all backends: {}", err);

	return err;
}

void dnet_backend_cleanup_all(struct dnet_node *node) {
	for (auto backend : node->config_data->backends->get_all_backends()) {
		if (backend->state != DNET_BACKEND_DISABLED)
			dnet_backend_cleanup(node, backend->backend_id);
	}
}

static int dnet_backend_set_ids(dnet_node *node, uint32_t backend_id, dnet_raw_id *ids, uint32_t ids_count)
{
	auto backend = node->config_data->backends->get_backend(backend_id);
	if (!backend) {
		return -EINVAL;
	}

	if (backend->history.empty()) {
		DNET_LOG_ERROR(
		        node,
		        "backend_set_ids: backend_id: {}, failed to open temporary ids file: history is not specified",
		        backend_id);
		return -EINVAL;
	}

	char tmp_ids[1024];
	char target_ids[1024];
	snprintf(tmp_ids, sizeof(tmp_ids), "%s/ids_%08x%08x", backend->history.c_str(), rand(), rand());
	snprintf(target_ids, sizeof(target_ids), "%s/ids", backend->history.c_str());
	int err = 0;

	std::ofstream out(tmp_ids, std::ofstream::binary | std::ofstream::trunc);
	if (!out) {
		err = -errno;
		DNET_LOG_ERROR(node, "backend_set_ids: backend_id: {}, failed to open temporary ids file: {}, err: {}",
		               backend_id, tmp_ids, err);
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
			        backend_id, tmp_ids, err);
		} else {

			if (!err) {
				std::lock_guard<std::mutex> guard(*backend->state_mutex);
				switch (backend->state) {
					case DNET_BACKEND_ENABLED:
						err = std::rename(tmp_ids, target_ids);
						if (err)
							break;
						err = dnet_route_list_enable_backend(node->route,
								backend_id, backend->group, ids, ids_count);
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

void backend_fill_status_nolock(struct dnet_node *node, struct dnet_backend_status *status, const struct dnet_backend_info *config_backend)
{
	if (!status || !config_backend)
		return;

	auto backend_id = config_backend->backend_id;
	const dnet_backend_io *io = dnet_get_backend_io(node->io, backend_id);

	const auto &cb = config_backend->config.cb;

	status->backend_id = backend_id;
	status->state = config_backend->state;
	if (config_backend->state == DNET_BACKEND_ENABLED && cb.defrag_status)
		status->defrag_state = cb.defrag_status(cb.command_private);
	status->last_start = config_backend->last_start;
	status->last_start_err = config_backend->last_start_err;
	status->read_only = io->read_only;
	status->delay = io->delay;
}

void dnet_backend_info_manager::backend_fill_status(dnet_node *node, dnet_backend_status *status, size_t backend_id) const
{
	std::shared_ptr<dnet_backend_info> backend;
	{
		std::lock_guard<std::mutex> guard(backends_mutex);
		auto it = backends.find(backend_id);
		if (it != backends.end()) {
			backend = it->second;
		}
	}
	if (backend)
	{
		std::lock_guard<std::mutex> guard(*backend->state_mutex);
		backend_fill_status_nolock(node, status, backend.get());
	}
}

std::shared_ptr<dnet_backend_info> dnet_backend_info_manager::get_backend(size_t backend_id) const
{
	std::lock_guard<std::mutex> guard(backends_mutex);
	auto it = backends.find(backend_id);
	if (it != backends.end()) {
		return it->second;
	}
	return std::shared_ptr<dnet_backend_info>();
}

void dnet_backend_info_manager::add_backend(std::shared_ptr<dnet_backend_info> &backend)
{
	std::lock_guard<std::mutex> guard(backends_mutex);
	backends.insert({backend->backend_id, backend});
}

void dnet_backend_info_manager::remove_backend(size_t backend_id) {
	std::lock_guard<std::mutex> guard(backends_mutex);
	backends.erase(backend_id);
}

void dnet_backend_info_manager::set_verbosity(dnet_log_level level) {
	std::lock_guard<std::mutex> guard(backends_mutex);
	for (auto &backend: backends) {
		if (backend.second->state == DNET_BACKEND_ENABLED) {
			backend.second->config.set_verbosity(&backend.second->config, level);
		}
	}
}

static int dnet_cmd_backend_control_dangerous(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	int err = 0;
	dnet_node *node = st->n;
	struct dnet_backend_control *control = reinterpret_cast<dnet_backend_control *>(data);

	if (dnet_backend_command(control->command) == DNET_BACKEND_ENABLE) {
		err = dnet_backend_create(node, control->backend_id);
		if (err) {
			DNET_LOG_ERROR(node, "backend_control: backend creation failed: {}, state: {}: {}",
			               control->backend_id, dnet_state_dump_addr(st), err);
			return err;
		}
	}

	auto backends = node->config_data->backends;
	auto backend = backends->get_backend(control->backend_id);
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

	if (backend->state == DNET_BACKEND_UNITIALIZED) {
		DNET_LOG_ERROR(node, "backend_control: there is no such backend: {}, state: {}", control->backend_id,
		               dnet_state_dump_addr(st));
		return -EINVAL;
	}

	dnet_backend_io *io = dnet_get_backend_io(node->io, control->backend_id);

	const dnet_backend_callbacks &cb = backend->config.cb;

	switch (dnet_backend_command(control->command)) {
	case DNET_BACKEND_ENABLE:
		err = dnet_backend_init(node, control->backend_id);
		break;
	case DNET_BACKEND_DISABLE:
		err = dnet_backend_cleanup(node, control->backend_id);
		break;
	case DNET_BACKEND_REMOVE:
		err = dnet_backend_remove(node, control->backend_id);
		break;
	case DNET_BACKEND_START_DEFRAG:
		if (cb.defrag_start) {
			err = cb.defrag_start(cb.command_private,
				static_cast<enum dnet_backend_defrag_level>(control->defrag_level));
		} else {
			err = -ENOTSUP;
		}
		break;
	case DNET_BACKEND_STOP_DEFRAG:
		if (cb.defrag_stop) {
			err = cb.defrag_stop(cb.command_private);
		} else {
			err = -ENOTSUP;
		}
		break;
	case DNET_BACKEND_SET_IDS:
		err = dnet_backend_set_ids(st->n, control->backend_id, control->ids, control->ids_count);
		break;
	case DNET_BACKEND_READ_ONLY:
		if (io->read_only) {
			err = -EALREADY;
		} else {
			io->read_only = 1;
			err = 0;
		}
		break;
	case DNET_BACKEND_WRITEABLE:
		if (!io->read_only) {
			err = -EALREADY;
		} else {
			io->read_only = 0;
			err = 0;
		}
		break;
	case DNET_BACKEND_CTL:
		io->delay = control->delay;
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
	backends->backend_fill_status(node, status, control->backend_id);

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

int dnet_cmd_backend_control(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	dnet_node *node = st->n;

	if (cmd->size < sizeof(dnet_backend_control)) {
		DNET_LOG_ERROR(node, "backend_control: command size is not enough for dnet_backend_control, state: {}",
		               dnet_state_dump_addr(st));
		return -EINVAL;
	}

	struct dnet_backend_control *control = reinterpret_cast<dnet_backend_control *>(data);

	try {
		ioremap::elliptics::backend_scope backend_scope{int(control->backend_id)};

		return dnet_cmd_backend_control_dangerous(st, cmd, data);
	} catch (std::bad_alloc &) {
		DNET_LOG_ERROR(node, "backend_control: insufficient memory");
		return -ENOMEM;
	} catch (std::exception &exc) {
		DNET_LOG_ERROR(node, "backend_control: {}", exc.what());
		return -EINVAL;
	}
}

int dnet_cmd_backend_status(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	(void) data;
	dnet_node *node = st->n;

	auto backends = node->config_data->backends->get_all_backends();
	auto cmp_backends = [](const std::shared_ptr<dnet_backend_info> &lhs, const std::shared_ptr<dnet_backend_info> &rhs) -> bool {
		return lhs->backend_id < rhs->backend_id;
	};
	std::sort(backends.begin(), backends.end(), cmp_backends);

	const size_t total_size = sizeof(dnet_backend_status_list) + backends.size() * sizeof(dnet_backend_status);

	std::unique_ptr<dnet_backend_status_list, free_destroyer>
		list(reinterpret_cast<dnet_backend_status_list *>(calloc(1, total_size)));
	if (!list) {
		return -ENOMEM;
	}

	size_t i = 0;

	for (auto &backend : backends) {
		dnet_backend_status &status = list->backends[i];
		node->config_data->backends->backend_fill_status(st->n, &status, backend->backend_id);
		if (status.state != DNET_BACKEND_UNITIALIZED)
			++i;
	}

	list->backends_count = i;

	cmd->flags &= ~DNET_FLAGS_NEED_ACK;

	int err = dnet_send_reply(st, cmd, list.get(), total_size, false);

	if (err != 0) {
		cmd->flags |= DNET_FLAGS_NEED_ACK;
	}

	return err;
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

void dnet_backend_info::parse(ioremap::elliptics::config::config_data *data,
		const kora::config_t &backend)
{
	std::string type = backend.at<std::string>("type");

	dnet_config_backend *backends_info[] = {
		dnet_eblob_backend_info(),
	};

	bool found_backend = false;

	for (size_t i = 0; i < sizeof(backends_info) / sizeof(backends_info[0]); ++i) {
		dnet_config_backend *current_backend = backends_info[i];
		if (type == current_backend->name) {
			config_template = *current_backend;
			config = *current_backend;
			this->data.resize(config.size, '\0');
			found_backend = true;
			break;
		}
	}

	if (!found_backend)
		throw ioremap::elliptics::config::config_error() <<
			backend["type"].path() <<
			" is unknown backend";

	group = backend.at<uint32_t>("group");
	history = backend.at<std::string>("history");
	cache = NULL;

	if (backend.has("cache")) {
		const auto cache = backend["cache"];
		cache_config = ioremap::cache::cache_config::parse(cache);
	} else if (data->cache_config) {
		cache_config = std::unique_ptr<ioremap::cache::cache_config>(new ioremap::cache::cache_config(*data->cache_config));
	}

	io_thread_num = backend.at("io_thread_num", data->cfg_state.io_thread_num);
	nonblocking_io_thread_num = backend.at("nonblocking_io_thread_num", data->cfg_state.nonblocking_io_thread_num);

	// use backend's queue_timeout if it's specified otherwise use global one.
	if (backend.has("queue_timeout")) {
		queue_timeout = ioremap::elliptics::config::parse_queue_timeout(backend);
	} else {
		queue_timeout = data->queue_timeout;
	}

	for (int i = 0; i < config.num; ++i) {
		dnet_config_entry &entry = config.ent[i];
		if (backend.has(entry.key)) {
			const std::string value = [&] () {
				std::ostringstream stream;
				stream << backend[entry.key];
				return stream.str();
			} ();

			dnet_backend_config_entry option = {
				&entry,
				std::move(value)
			};

			options.emplace_back(std::move(option));
		}
	}

	initial_config = kora::to_json(backend.underlying_object());
}
