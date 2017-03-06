#include "elliptics.h"
#include "backend.h"
#include "example/config.hpp"

#include <boost/thread/locks.hpp>

uint64_t dnet_node_get_queue_timeout(struct dnet_node *node) {
	if (!node->config_data)
		return 0;

	return dnet_node_get_config_data(node)->queue_timeout;
}

struct dnet_work_pool_place *dnet_backend_get_place(struct dnet_node *node, ssize_t backend_id, int nonblocking) {
	if (!node->io)
		return nullptr;

	if (node->io->backends_manager && backend_id >= 0) {
		auto pool = dnet_backend_get_pool(node, backend_id);
		if (pool) {
			auto place = nonblocking ? &pool->recv_pool_nb : &pool->recv_pool;
			pthread_mutex_lock(&place->lock);
			if (place->pool)
				return place;
			pthread_mutex_unlock(&place->lock);
		}
	}

	auto place = nonblocking ? &node->io->pool.recv_pool_nb : &node->io->pool.recv_pool;
	pthread_mutex_lock(&place->lock);
	return place;
}
