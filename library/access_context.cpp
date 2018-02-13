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

#include "access_context.h"

#include "elliptics/interface.h"
#include "logger.hpp"


dnet_access_context::dnet_access_context(dnet_node *node)
: node_(node) {}

dnet_access_context::~dnet_access_context() {
	print();
}


void dnet_access_context::add(blackhole::attribute_t attribute) {
	std::lock_guard<std::mutex> guard(mutex_);
	attributes_.emplace_back(std::move(attribute));
}
void dnet_access_context::add(std::initializer_list<blackhole::attribute_t> attributes) {
	std::lock_guard<std::mutex> guard(mutex_);
	attributes_.insert(attributes_.end(), attributes.begin(), attributes.end());
}

void dnet_access_context::increment_ref() {
	++ref_counter_;
}

void dnet_access_context::print() {
	add({"total_time", timer_.get_us()});
	dnet_log_access(node_, blackhole::attribute_list{attributes_.begin(), attributes_.end()});
}

void dnet_access_context::decrement_ref() {
	if (!--ref_counter_)
		delete this;
}

struct dnet_access_context *dnet_access_context_create(struct dnet_node *node) {
	try {
		return dnet_access_context_get(new dnet_access_context(node));
	} catch (const std::exception &e) {
		DNET_LOG_ERROR(node, "Failed to create access context: {}", e.what());
		return nullptr;
	}
}

struct dnet_access_context *dnet_access_context_get(struct dnet_access_context *context) {
	if (context)
		context->increment_ref();

	return context;
}

void dnet_access_access_put(struct dnet_access_context *context) {
	if (!context)
		return;

	context->decrement_ref();
}

void dnet_access_context_add_int(struct dnet_access_context *context, const char *name, int64_t value) {
	if (!context)
		return;

	context->add({name, value});
}

void dnet_access_context_add_uint(struct dnet_access_context *context, const char *name, uint64_t value) {
	if (!context)
		return;

	context->add({name, value});
}

void dnet_access_context_add_string(struct dnet_access_context *context, const char *name, const char *value) {
	if (!context)
		return;

	context->add({name, std::string(value)});
}
