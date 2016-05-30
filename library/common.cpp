#include "elliptics.h"

int dnet_get_backend_ids(const dnet_backend_info_manager *backends, size_t **backend_ids, size_t *num_backend_ids)
{
	if (!backends)
		return -EINVAL;

	auto config_backends = backends->get_all_backends();
	*num_backend_ids = config_backends.size();
	*backend_ids = reinterpret_cast<size_t *>(malloc(*num_backend_ids * sizeof(size_t)));
	if (!*backend_ids)
		return -ENOMEM;

	for (size_t i = 0; i < *num_backend_ids; ++i) {
		(*backend_ids)[i] = config_backends[i]->backend_id;
	}

	return 0;
}

struct dnet_backend_io *dnet_get_backend_io(struct dnet_io *io, size_t backend_id)
{
	struct dnet_backend_io *backend_io = nullptr;

	pthread_rwlock_rdlock(&io->backends_lock);
	if (backend_id < io->backends_count) {
		backend_io = io->backends[backend_id];
	}
	pthread_rwlock_unlock(&io->backends_lock);

	return backend_io;
}
