#ifndef IOREMAP_ELLIPTICS_BACKEND_H
#define IOREMAP_ELLIPTICS_BACKEND_H

#include <elliptics/backends.h>

#ifdef __cplusplus

#include <string>
#include <vector>
#include <memory>
#include <mutex>

#include <kora/config.hpp>
#include <blackhole/wrapper.hpp>

#include <elliptics/error.hpp>

namespace ioremap { namespace elliptics { namespace config {
class config_data;
}}}

namespace ioremap { namespace cache {

struct cache_config
{
	size_t			size;
	size_t			count;
	unsigned		sync_timeout;
	std::vector<size_t>	pages_proportions;

	static std::unique_ptr<cache_config> parse(const kora::config_t &cache);
};

}}

/**
 * This structure holds config value read from config file
 * @entry.key contains config key, @value_template holds value for given key
 *
 * When backend is being initialized, it calls @entry.callback() function for each config entry
 *
 * Please note that backend initialization copies value into temporal copy,
 * since @entry.callback() can modify this data.
 */
struct dnet_backend_config_entry
{
	dnet_config_entry *entry;
	std::string value_template;
};

struct dnet_backend_info
{
	dnet_backend_info(dnet_logger &logger, uint32_t backend_id) :
		log(new blackhole::wrapper_t(logger, {{"source", "eblob"}, {"backend_id", backend_id}})),
		backend_id(backend_id), group(0), cache(NULL),
		enable_at_start(false), read_only_at_start(false),
		state_mutex(new std::mutex), state(DNET_BACKEND_UNITIALIZED),
		io_thread_num(0), nonblocking_io_thread_num(0)
	{
		dnet_empty_time(&last_start);
		last_start_err = 0;
		memset(&config_template, 0, sizeof(config_template));
		memset(&config, 0, sizeof(config));
	}

	dnet_backend_info(const dnet_backend_info &other) = delete;
	dnet_backend_info &operator =(const dnet_backend_info &other) = delete;

	dnet_backend_info(dnet_backend_info &&other) ELLIPTICS_NOEXCEPT :
		config_template(other.config_template),
		log(std::move(other.log)),
		options(std::move(other.options)),
		backend_id(other.backend_id),
		group(other.group),
		cache(other.cache),
		history(other.history),
		enable_at_start(other.enable_at_start),
		read_only_at_start(other.read_only_at_start),
		state_mutex(std::move(other.state_mutex)),
		state(other.state),
		last_start(other.last_start),
		last_start_err(other.last_start_err),
		config(other.config),
		data(std::move(other.data)),
		cache_config(std::move(other.cache_config)),
		io_thread_num(other.io_thread_num),
		nonblocking_io_thread_num(other.nonblocking_io_thread_num)
	{
	}

	dnet_backend_info &operator =(dnet_backend_info &&other) ELLIPTICS_NOEXCEPT
	{
		config_template = other.config_template;
		log = std::move(other.log);
		options = std::move(other.options);
		backend_id = other.backend_id;
		group = other.group;
		cache = other.cache;
		history = other.history;
		enable_at_start = other.enable_at_start;
		read_only_at_start = other.read_only_at_start;
		state_mutex = std::move(other.state_mutex);
		state = other.state;
		last_start = other.last_start;
		last_start_err = other.last_start_err;
		config = other.config;
		data = std::move(other.data);
		cache_config = std::move(other.cache_config);
		io_thread_num = other.io_thread_num;
		nonblocking_io_thread_num = other.nonblocking_io_thread_num;

		return *this;
	}

	void parse(ioremap::elliptics::config::config_data *data, const kora::config_t &config);

	dnet_config_backend config_template;
	std::unique_ptr<dnet_logger> log;
	std::vector<dnet_backend_config_entry> options;
	uint32_t backend_id;
	uint32_t group;
	void *cache;
	std::string history;
	bool enable_at_start;
	bool read_only_at_start;

	std::unique_ptr<std::mutex> state_mutex;
	dnet_backend_state state;
	dnet_time last_start;
	int last_start_err;

	dnet_config_backend config;
	std::vector<char> data;

	std::unique_ptr<ioremap::cache::cache_config> cache_config;
	int io_thread_num;
	int nonblocking_io_thread_num;
	std::string initial_config;
};

class dnet_backend_info_manager
{
public:
	/*
	 * Locks backend with \a backend_id state mutex and fills \a status
	 */
	void backend_fill_status(struct dnet_node *node, struct dnet_backend_status *status, size_t backend_id) const;

	std::vector<std::shared_ptr<dnet_backend_info> > get_all_backends() const
	{
		std::vector<std::shared_ptr<dnet_backend_info> > result;
		std::lock_guard<std::mutex> guard(backends_mutex);
		for (auto it : backends) {
			result.push_back(it.second);
		}
		return result;
	}

	std::shared_ptr<dnet_backend_info> get_backend(size_t backend_id) const;

	void add_backend(std::shared_ptr<dnet_backend_info> &backend);
	void remove_backend(size_t backend_id);

	void set_verbosity(dnet_log_level level);

private:
	std::unordered_map<uint32_t, std::shared_ptr<dnet_backend_info> > backends;
	mutable std::mutex backends_mutex;
};

void backend_fill_status_nolock(struct dnet_node *node, struct dnet_backend_status *status, const struct dnet_backend_info *config_backend);

extern "C" {
#else // __cplusplus
typedef struct dnet_backend_info_manager dnet_backend_info_manager;
struct dnet_io;
#endif // __cplusplus

int dnet_backend_init_all(struct dnet_node *n);
void dnet_backend_cleanup_all(struct dnet_node *n);

int dnet_get_backend_ids(const dnet_backend_info_manager *backends, size_t **backend_ids, size_t *num_backend_ids);

int dnet_cmd_backend_control(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);
int dnet_cmd_backend_status(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);

struct dnet_backend_io *dnet_get_backend_io(struct dnet_io *io, size_t backend_id);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // IOREMAP_ELLIPTICS_BACKEND_H
