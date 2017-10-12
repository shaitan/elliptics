/*
 * Copyright 2015+ Kirill Smorodinnikov <shaitkir@gmail.com>
 *
 * This file is part of Elliptics.
 *
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __DNET_EBLOB_BACKEND_H
#define __DNET_EBLOB_BACKEND_H

#include <sys/types.h>

#include <eblob/blob.h>

#include "elliptics/interface.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dnet_config_backend;
struct dnet_cmd_stats;

struct eblob_read_params {
	int			fd;
	int			pad;
	uint64_t		offset;
};

struct eblob_backend_config {
	struct eblob_config		data;
	struct eblob_backend		*eblob;
	dnet_logger			*blog;
	struct eblob_log		log;

	pthread_mutex_t			last_read_lock;
	int64_t				vm_total;		/* squared in bytes */
	int				random_access;
	int				last_read_index;
	struct eblob_read_params	last_reads[100];
};

int dnet_blob_config_to_json(struct dnet_config_backend *b, char **json_stat, size_t *size);

int blob_file_info_new(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd);
int blob_del_new(struct eblob_backend_config *c, struct dnet_cmd *cmd, void *data);
int blob_read_new(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd, void *data,
                  struct dnet_cmd_stats *cmd_stats);
int blob_write_new(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd, void *data,
                   struct dnet_cmd_stats *cmd_stats);
int blob_iterate(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd, void *data);
int blob_send_new(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd, void *data);
int blob_bulk_read_new(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd, void *data,
		       struct dnet_cmd_stats *cmd_stats);

int dnet_read_json_header(int fd, uint64_t offset, uint64_t size, struct dnet_json_header *jhdr);

#ifdef __cplusplus
}
#endif

#endif /* __DNET_EBLOB_BACKEND_H */
