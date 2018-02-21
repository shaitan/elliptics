/*
 * Copyright 2018+ Kirill Smorodinnikov <shaitkir@gmail.com>
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

#pragma once

#include "elliptics/packet.h"

#ifdef __cplusplus

#include <atomic>
#include <mutex>

#include <blackhole/attribute.hpp>
#include <blackhole/attributes.hpp>

#include "bindings/cpp/timer.hpp"

struct dnet_node;

struct dnet_access_context {
public:
	explicit dnet_access_context(dnet_node *node);
	~dnet_access_context();

	// attach @attribute to the final log
	void add(blackhole::attribute_t attribute);
	// attach batch of @attributes gto the final log
	void add(std::initializer_list<blackhole::attribute_t> attributes);

	void increment_ref();
	void decrement_ref();
private:
	// print final log
	void print();

	// we have to add reference counter since an instance is created and removed in C
	// by various threads.
	std::atomic<size_t> ref_counter_{0};

	dnet_node *node_;

	// Timer to measure total time spent on the request.
	ioremap::elliptics::util::steady_timer timer_;

	// mutex to synchronize adding attributes from various attributes
	std::mutex mutex_{};
	blackhole::attributes_t attributes_{};
};

extern "C" {
#else
struct dnet_node;
struct dnet_io_req;
struct dnet_access_context;
#endif

// Create dnet_access_context
struct dnet_access_context *dnet_access_context_create(struct dnet_node *node);
// Get new reference to @context
struct dnet_access_context *dnet_access_context_get(struct dnet_access_context *context);
// Remove reference from @context
void dnet_access_access_put(struct dnet_access_context *context);
// Add attribute with @name and @value: overload for int64_t values
void dnet_access_context_add_int(struct dnet_access_context *context, const char *name, int64_t value);
// Add attribute with @name and @value: overload for uint64_t values
void dnet_access_context_add_uint(struct dnet_access_context *context, const char *name, uint64_t value);
// Add attribute with @name and @value: overload for const char* values
void dnet_access_context_add_string(struct dnet_access_context *context, const char *name, const char *value);
// Add trace_id attribute with @value
void dnet_access_context_add_trace_id(struct dnet_access_context *context, uint64_t value);

#ifdef __cplusplus
}
#endif
