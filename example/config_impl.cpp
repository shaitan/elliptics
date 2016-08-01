#include "config.hpp"

#include <fstream>
#include <kora/dynamic.hpp>
#include <kora/config.hpp>

#include "monitor/monitor.hpp"

using namespace ioremap::elliptics::config;

config_data::config_data()
: logger(logger_base, blackhole::log::attributes_t()) {
	dnet_empty_time(&config_timestamp);
}

std::shared_ptr<kora::config_parser_t> config_data::parse_config() {
	struct stat st;
	dnet_time ts;
	memset(&st, 0, sizeof(st));
	if (stat(config_path.c_str(), &st) != 0) {
		int err = -errno;
		throw config_error() << "failed to get stat of config file'" << config_path << "': " << strerror(-err);
	}

	ts.tsec = st.st_mtime;
	ts.tnsec = 0;

	std::unique_lock<std::mutex> locker(parser_mutex);
	if (dnet_time_is_empty(&config_timestamp) ||
	    dnet_time_before(&config_timestamp, &ts)) {
		config_timestamp = ts;
		parser = std::make_shared<kora::config_parser_t>();
		parser->open(config_path);
		return parser;
	} else {
		return parser;
	}
}

