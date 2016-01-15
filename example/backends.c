/*
 * Copyright 2008+ Evgeniy Polyakov <zbr@ioremap.net>
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _XOPEN_SOURCE 600

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elliptics/core.h"
#include "elliptics/packet.h"
#include "elliptics/interface.h"
#include "elliptics/backends.h"
#include "../library/elliptics.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

int backend_storage_size(struct dnet_config_backend *b, const char *root)
{
	struct statvfs s;
	int err;

	err = statvfs(root, &s);
	if (err) {
		err = -errno;
		dnet_backend_log(b->log, DNET_LOG_NOTICE, "Failed to get VFS statistics of '%s': %s [%d].",
		                 root, strerror(errno), errno);
		return err;
	}

	b->storage_size = s.f_frsize * s.f_blocks;
	b->storage_free = s.f_bsize * s.f_bavail;

	return 0;
}

/*
 * Extensions stuff
 */

/*!
 * Initialize allocated extension list
 */
void dnet_ext_list_init(struct dnet_ext_list *elist)
{
	if (elist == NULL)
		return;
	memset(elist, 0, sizeof(struct dnet_ext_list));
	elist->version = DNET_EXT_VERSION_V1;
}

/*!
 * Destroy extension list
 */
void dnet_ext_list_destroy(struct dnet_ext_list *elist) {
	(void) elist;
}

/*!
 * Reads extension header from given fd and offset
 */
int dnet_ext_hdr_read(struct dnet_ext_list_hdr *ehdr, int fd, uint64_t offset)
{
	int err;

	if (ehdr == NULL || fd < 0)
		return -EINVAL;

	err = pread(fd, ehdr, sizeof(struct dnet_ext_list_hdr), offset);
	if (err != sizeof(struct dnet_ext_list_hdr))
		return (err == -1) ? -errno : -EINTR;
	return 0;
}

/*!
 * Reads extension header from given fd and offset
 */
int dnet_ext_hdr_write(const struct dnet_ext_list_hdr *ehdr, int fd, uint64_t offset)
{
	int err;

	if (ehdr == NULL || fd < 0)
		return -EINVAL;

	err = pwrite(fd, ehdr, sizeof(struct dnet_ext_list_hdr), offset);
	if (err != sizeof(struct dnet_ext_list_hdr))
		return (err == -1) ? -errno : -EINTR;
	return 0;
}

/*!
 * Converts representation from host-independed on-disk to host-depended
 * in-memory.
 */
int dnet_ext_hdr_to_list(const struct dnet_ext_list_hdr *ehdr,
		struct dnet_ext_list *elist)
{
	if (ehdr == NULL || elist == NULL)
		return -EINVAL;

	memset(elist, 0, sizeof(struct dnet_ext_list));
	elist->version = ehdr->version;
	elist->timestamp.tsec = dnet_bswap64(ehdr->timestamp.tsec);
	elist->timestamp.tnsec = dnet_bswap64(ehdr->timestamp.tnsec);
	elist->size = dnet_bswap32(ehdr->size);
	elist->flags = dnet_bswap64(ehdr->flags);

	return 0;
}

/*!
 * Converts representation from host-depended in-memory to host-independed
 * on-disk.
 */
int dnet_ext_list_to_hdr(const struct dnet_ext_list *elist,
		struct dnet_ext_list_hdr *ehdr)
{
	if (ehdr == NULL || elist == NULL)
		return -EINVAL;

	memset(ehdr, 0, sizeof(struct dnet_ext_list_hdr));
	ehdr->version = elist->version;
	ehdr->size = dnet_bswap32(elist->size);
	ehdr->flags = dnet_bswap64(elist->flags);
	ehdr->timestamp.tsec = dnet_bswap64(elist->timestamp.tsec);
	ehdr->timestamp.tnsec = dnet_bswap64(elist->timestamp.tnsec);

	return 0;
}

/*!
 * Fills needed fields in \a io with data from given \a elist
 */
int dnet_ext_list_to_io(const struct dnet_ext_list *elist, struct dnet_io_attr *io)
{
	if (elist == NULL || io == NULL)
		return -EINVAL;

	io->timestamp = elist->timestamp;
	io->user_flags = elist->flags;

	return 0;
}

/*!
 * Fills needed fields in \a elist with data from given \a io
 */
int dnet_ext_io_to_list(const struct dnet_io_attr *io, struct dnet_ext_list *elist)
{
	if (elist == NULL || io == NULL)
		return -EINVAL;

	elist->timestamp = io->timestamp;
	elist->flags = io->user_flags;

	return 0;
}
