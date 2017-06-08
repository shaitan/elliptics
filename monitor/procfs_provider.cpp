/*
 * Copyright 2013+ Kirill Smorodinnikov <shaitkir@gmail.com>
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

#include "procfs_provider.hpp"

#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <blackhole/attribute.hpp>

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include "elliptics/interface.h"

#include "library/logger.hpp"

namespace ioremap { namespace monitor {

struct proc_io_stat {
	uint64_t rchar;
	uint64_t wchar;
	uint64_t syscr;
	uint64_t syscw;
	uint64_t read_bytes;
	uint64_t write_bytes;
	uint64_t cancelled_write_bytes;
};

static int fill_proc_io_stat(dnet_node *n, struct proc_io_stat &st) {
	FILE *f;
	int err = 0;
	memset(&st, 0, sizeof(st));

	f = fopen("/proc/self/io", "r");
	if (!f) {
		err = -errno;
		DNET_LOG_ERROR(n, "Failed to open '/proc/self/io': {} [{}]", strerror(errno), errno);
		goto err_out_exit;
	}

	err = fscanf(f, "rchar: %llu\n", (unsigned long long *)&st.rchar);
	err = fscanf(f, "wchar: %llu\n", (unsigned long long *)&st.wchar);
	err = fscanf(f, "syscr: %llu\n", (unsigned long long *)&st.syscr);
	err = fscanf(f, "syscw: %llu\n", (unsigned long long *)&st.syscw);
	err = fscanf(f, "read_bytes: %llu\n", (unsigned long long *)&st.read_bytes);
	err = fscanf(f, "write_bytes: %llu\n", (unsigned long long *)&st.write_bytes);
	err = fscanf(f, "cancelled_write_bytes: %llu\n", (unsigned long long *)&st.cancelled_write_bytes);

	fclose(f);
	err = 0;

err_out_exit:
	return err;
}

struct proc_stat {
	long threads_num;
	long rss;
	unsigned long vsize;
	unsigned long rsslim;
	unsigned long msize;
	unsigned long mresident;
	unsigned long mshare;
	unsigned long mcode;
	unsigned long mdata;
};

static int fill_proc_stat(dnet_node *n, struct proc_stat &st) {
	int err = 0;
	FILE *f;
	memset(&st, 0, sizeof(st));

	f = fopen("/proc/self/stat", "r");
	if (!f) {
		err = -errno;
		DNET_LOG_ERROR(n, "Failed to open '/proc/self/stat': {} [{}]", strerror(errno), errno);
		goto err_out_exit;
	}

	static const char f_str[] = "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %ld %*d %*u %lu %ld %lu";

	err = fscanf(f, f_str, &st.threads_num, &st.vsize, &st.rss, &st.rsslim);
	fclose(f);

	f = fopen("/proc/self/statm", "r");
	if (!f) {
		err = -errno;
		DNET_LOG_ERROR(n, "Failed to open '/proc/self/statm': {} [{}]", strerror(errno), errno);
		goto err_out_exit;
	}

	err = fscanf(f, "%lu %lu %lu %lu %*u %lu", &st.msize, &st.mresident, &st.mshare, &st.mcode, &st.mdata);
	fclose(f);

	err = 0;

err_out_exit:
	return err;
}

struct net_stat {
	uint64_t bytes;
	uint64_t packets;
	uint64_t errors;
};

struct net_interface_stat {
	struct net_stat rx;
	struct net_stat tx;
	int32_t speed;
};

static int fill_proc_net_stat(dnet_node *n, std::map<std::string, net_interface_stat> &st)
{
	char buf[256] = {'\0'};
	net_interface_stat net_stat;
	FILE *f;
	int err = 0;
	struct ifreq ifr;
	struct ethtool_cmd ecmd;
	ecmd.cmd = ETHTOOL_GSET;


	f = fopen("/proc/net/dev", "r");
	if (!f) {
		DNET_LOG_ERROR(n, "Failed to open '/proc/net/dev': {} [{}]", strerror(errno), errno);
		return -errno;
	}

	// skip first 2 headers
	for (int i = 0; i < 2; ++i) {
		if (!fgets(buf, sizeof(buf), f)) {
			DNET_LOG_ERROR(n, "could not read header on '/proc/net/dev'");
			err = -ENOENT;
			goto err_out_exit;
		}
	}

	while (1) {
		err = fscanf(f, "%255s %lu %lu %lu %*u %*u %*u %*u %*u %lu %lu %lu %*u %*u %*u %*u %*u", buf,
			     &net_stat.rx.bytes, &net_stat.rx.packets, &net_stat.rx.errors,
			     &net_stat.tx.bytes, &net_stat.tx.packets, &net_stat.tx.errors);
		if (err < 0) {
			if (ferror(f)) {
				DNET_LOG_ERROR(n, "fscanf failed on '/proc/net/dev': {} [{}]", strerror(errno), errno);
				err = -errno;
				goto err_out_exit;
			} else {
				err = 0;
				break;
			}
		}

		buf[strlen(buf)-1] = '\0'; // erase ':' after interface name
		net_stat.speed = [&] () -> int32_t {
			// memset(&ifr, 0, sizeof(ifr));
			// strcpy(ifr.ifr_name, buf);
			// ifr.ifr_data = (caddr_t)&ecmd;
			// if (ioctl(n->st->accept_s, SIOCETHTOOL, &ifr) == -1) {
			// 	DNET_LOG_ERROR(n, "Cannot get settings for device: {}: {} [{}]", buf,
			// 	               strerror(errno), errno);
				return SPEED_UNKNOWN;
			// }
			// return ethtool_cmd_speed(&ecmd);
		} ();

		st.insert(std::make_pair(buf, net_stat));
	}

err_out_exit:
	fclose(f);
	return err;
}

procfs_provider::procfs_provider(struct dnet_node *node)
: m_node(node)
{}

static void fill_vm(dnet_node *node,
                    rapidjson::Value &stat_value,
                    rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value vm_value(rapidjson::kObjectType);
	int err = 0;
	dnet_vm_stat st;

	err = dnet_get_vm_stat(node->log, &st);
	vm_value.AddMember("error", err, allocator);

	if (!err) {
		vm_value.AddMember("string_error", "", allocator);
		rapidjson::Value la_value(rapidjson::kArrayType);
		for (size_t i = 0; i < 3; ++i) {
			la_value.PushBack(st.la[i], allocator);
		}
		vm_value.AddMember("la", la_value, allocator);

		vm_value.AddMember("total", st.vm_total, allocator);
		vm_value.AddMember("active", st.vm_active, allocator);
		vm_value.AddMember("inactive", st.vm_inactive, allocator);
		vm_value.AddMember("free", st.vm_free, allocator);
		vm_value.AddMember("cached", st.vm_cached, allocator);
		vm_value.AddMember("buffers", st.vm_buffers, allocator);
	} else
		vm_value.AddMember("string_error", strerror(-err), allocator);

	stat_value.AddMember("vm", vm_value, allocator);
}

static void fill_io(dnet_node *node,
                    rapidjson::Value &stat_value,
                    rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value io_stat(rapidjson::kObjectType);
	int err = 0;
	proc_io_stat st;

	err = fill_proc_io_stat(node, st);
	io_stat.AddMember("error", err, allocator);

	if (!err) {
		io_stat.AddMember("string_error", "", allocator);
		io_stat.AddMember("rchar", st.rchar, allocator);
		io_stat.AddMember("wchar", st.wchar, allocator);
		io_stat.AddMember("syscr", st.syscr, allocator);
		io_stat.AddMember("syscw", st.syscw, allocator);
		io_stat.AddMember("read_bytes", st.read_bytes, allocator);
		io_stat.AddMember("write_bytes", st.write_bytes, allocator);
		io_stat.AddMember("cancelled_write_bytes", st.cancelled_write_bytes, allocator);
	} else
		io_stat.AddMember("string_error", strerror(-err), allocator);

	stat_value.AddMember("io", io_stat, allocator);
}

static void fill_stat(dnet_node *node,
                      rapidjson::Value &stat_value,
                      rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value stat_stat(rapidjson::kObjectType);
	int err = 0;
	proc_stat st;

	err = fill_proc_stat(node, st);
	stat_stat.AddMember("error", err, allocator);

	if (!err) {
		stat_stat.AddMember("string_error", "", allocator);
		stat_stat.AddMember("threads_num", st.threads_num, allocator);
		stat_stat.AddMember("rss", st.rss, allocator);
		stat_stat.AddMember("vsize", st.vsize, allocator);
		stat_stat.AddMember("rsslim", st.rsslim, allocator);
		stat_stat.AddMember("msize", st.msize, allocator);
		stat_stat.AddMember("mresident", st.mresident, allocator);
		stat_stat.AddMember("mshare", st.mshare, allocator);
		stat_stat.AddMember("mcode", st.mcode, allocator);
		stat_stat.AddMember("mdata", st.mdata, allocator);
	} else
		stat_stat.AddMember("string_error", strerror(-err), allocator);

	stat_value.AddMember("stat", stat_stat, allocator);
}

static void fill_net_stat(const char *origin,
			  const struct net_stat &ns,
			  rapidjson::Value &stat_value,
			  rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value stat(rapidjson::kObjectType);
	stat.AddMember("bytes", ns.bytes, allocator);
	stat.AddMember("packets", ns.packets, allocator);
	stat.AddMember("errors", ns.errors, allocator);
	stat_value.AddMember(origin, stat, allocator);
}

static void fill_net(dnet_node *node,
                     rapidjson::Value &stat_value,
                     rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value net_stat(rapidjson::kObjectType);
	int err = 0;
	std::map<std::string, net_interface_stat> st;

	err = fill_proc_net_stat(node, st);
	net_stat.AddMember("error", err, allocator);

	if (!err) {
		rapidjson::Value dev_stat(rapidjson::kObjectType);

		for (auto it = st.cbegin(); it != st.cend(); ++it) {
			rapidjson::Value stat(rapidjson::kObjectType);

			const std::string &name = it->first;
			const net_interface_stat &ns = it->second;

			fill_net_stat("receive", ns.rx, stat, allocator);
			fill_net_stat("transmit", ns.tx, stat, allocator);

			stat.AddMember("speed", ns.speed, allocator);

			dev_stat.AddMember(name.c_str(), allocator, stat, allocator);
		}

		net_stat.AddMember("string_error", "", allocator);
		net_stat.AddMember("net_interfaces", dev_stat, allocator);
	} else
		net_stat.AddMember("string_error", strerror(-err), allocator);

	stat_value.AddMember("net", net_stat, allocator);
}

void procfs_provider::statistics(uint64_t categories,
                                 rapidjson::Value &value,
                                 rapidjson::Document::AllocatorType &allocator) const {
	if (!(categories & DNET_MONITOR_PROCFS))
	    return;

	value.SetObject();
	fill_vm(m_node, value, allocator);
	fill_io(m_node, value, allocator);
	fill_stat(m_node, value, allocator);
	fill_net(m_node, value, allocator);
}


}} /* namespace ioremap::monitor */
