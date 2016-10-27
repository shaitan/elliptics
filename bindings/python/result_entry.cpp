/*
* 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
* All rights reserved.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*/

#include "result_entry.h"

#include <boost/python.hpp>
#include <boost/python/list.hpp>

#include <elliptics/result_entry.hpp>
#include <elliptics/newapi/result_entry.hpp>
#include <elliptics/interface.h>

#include "elliptics_id.h"
#include "elliptics_time.h"
#include "elliptics_io_attr.h"
#include "py_converters.h"

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {

elliptics_id index_entry_get_index(index_entry &result)
{
	return elliptics_id(result.index);
}

void index_entry_set_index(index_entry &result, const elliptics_id &id)
{
	memcpy(result.index.id, id.id().id, DNET_ID_SIZE);
}

std::string index_entry_get_data(index_entry &result)
{
	return result.data.to_string();
}

void index_entry_set_data(index_entry &result, const std::string& data)
{
	result.data = data_pointer::copy(data);
}

dnet_iterator_response iterator_result_response(iterator_result_entry result)
{
	return *result.reply();
}

std::string iterator_result_response_data(iterator_result_entry result)
{
	return result.reply_data().to_string();
}

static elliptics_id iterator_response_get_key(dnet_iterator_response *response) {
	return elliptics_id(response->key);
}

static elliptics_time iterator_response_get_timestamp(dnet_iterator_response *response) {
	return elliptics_time(response->timestamp);
}

std::string read_result_get_data(read_result_entry &result)
{
	return result.file().to_string();
}

elliptics_id read_result_get_id(read_result_entry &result)
{
	dnet_raw_id id;
	memcpy(id.id, result.io_attribute()->id, sizeof(id.id));
	return elliptics_id(id);
}

elliptics_time read_result_get_timestamp(read_result_entry &result)
{
	return elliptics_time(result.io_attribute()->timestamp);
}

uint64_t read_result_get_user_flags(read_result_entry &result)
{
	return result.io_attribute()->user_flags;
}

uint32_t read_result_get_flags(read_result_entry &result)
{
	return result.io_attribute()->flags;
}

uint64_t read_result_get_offset(read_result_entry &result)
{
	return result.io_attribute()->offset;
}

uint64_t read_result_get_size(read_result_entry &result)
{
	return result.io_attribute()->size;
}

uint64_t read_result_get_total_size(read_result_entry &result) {
	return result.io_attribute()->total_size;
}

elliptics_io_attr read_result_get_io(read_result_entry &result) {
	return elliptics_io_attr(*result.io_attribute());
}

uint64_t read_result_get_record_flags(read_result_entry &result) {
	return result.io_attribute()->record_flags;
}

std::string lookup_result_get_storage_address(const lookup_result_entry &result)
{
	return std::string(dnet_addr_string(result.storage_address()));
}

uint64_t lookup_result_get_size(const lookup_result_entry &result)
{
	return result.file_info()->size;
}

uint64_t lookup_result_get_offset(const lookup_result_entry &result)
{
	return result.file_info()->offset;
}

elliptics_time lookup_result_get_timestamp(const lookup_result_entry &result)
{
	return elliptics_time(result.file_info()->mtime);
}

elliptics_id lookup_result_get_checksum(const lookup_result_entry &result)
{
	dnet_raw_id id;
	memcpy(id.id, result.file_info()->checksum, DNET_CSUM_SIZE);
	return elliptics_id(id);
}

std::string lookup_result_get_filepath(const lookup_result_entry &result)
{
	return std::string(result.file_path());
}

uint64_t lookup_result_get_record_flags(const lookup_result_entry &result) {
	return result.file_info()->record_flags;
}

/*
 * exec_context member access methods
 */

std::string exec_context_get_event(exec_context &context)
{
	return context.event();
}

std::string exec_context_get_data(exec_context &context)
{
	return context.data().to_string();
}

//TODO: flags()

std::string exec_context_get_address(exec_context &context)
{
	return dnet_addr_string(context.address());
}

elliptics_id exec_context_get_src_id(exec_context &context)
{
	const dnet_raw_id *raw = context.src_id();
	return elliptics_id(*raw);
}

int exec_context_get_src_key(exec_context &context)
{
	return context.src_key();
}

//TODO: think about exposing native_data(), is_final(), is_reply(), is_null()

/*
 * exec_result_entry member access methods
 */

exec_context exec_result_get_context(exec_result_entry &result)
{
	return result.context();
}

elliptics_id find_indexes_result_get_id(find_indexes_result_entry &result)
{
	return elliptics_id(result.id);
}

bp::list find_indexes_result_get_indexes(find_indexes_result_entry &result)
{
	return convert_to_list(result.indexes);
}

bool callback_result_is_valid(callback_result_entry &result)
{
	return result.is_valid();
}

bool callback_result_is_ack(callback_result_entry &result)
{
	return result.is_ack();
}

bool callback_result_is_final(callback_result_entry &result)
{
	return result.is_final();
}

int callback_result_status(callback_result_entry &result)
{
	return result.status();
}

error callback_result_error(callback_result_entry &result)
{
	return error(result.error().code(), result.error().message());
}

std::string callback_result_data(callback_result_entry &result)
{
	return result.data().to_string();
}

std::string callback_entry_address(const callback_result_entry &result)
{
	return dnet_addr_string(result.address());
}

int callback_entry_group_id(const callback_result_entry &result)
{
	return result.command()->id.group_id;
}

int callback_entry_backend_id(const callback_result_entry &result) {
	return result.command()->backend_id;
}

uint64_t callback_entry_trace_id(const callback_result_entry &result) {
	return result.command()->trace_id;
}

uint64_t callback_entry_trans(const callback_result_entry &result) {
	return result.command()->trans;
}

uint64_t callback_result_size(callback_result_entry &result)
{
	return result.size();
}

std::string monitor_stat_result_get_statistics(monitor_stat_result_entry &result) {
	return result.statistics();
}

elliptics_id route_entry_get_id(const dnet_route_entry &entry) {
	return elliptics_id(entry.id, entry.group_id);
}

std::string route_entry_get_address(const dnet_route_entry &entry) {
	return std::string(dnet_addr_string(&entry.addr));
}

elliptics_time dnet_backend_status_get_last_start(const dnet_backend_status &result) {
	return elliptics_time(result.last_start);
}

bool dnet_backend_status_get_read_only(const dnet_backend_status &result) {
	return bool(result.read_only);
}

bp::list dnet_backend_status_result_get_backends(const backend_status_result_entry &result) {
	bp::list ret;

	for (size_t i = 0; i < result.count(); ++i) {
		ret.append(result.backend(i));
	}

	return ret;
}

namespace newapi {
using namespace ioremap::elliptics::newapi;

namespace {

elliptics_time dnet_record_info_get_json_timestamp(const dnet_record_info &info) {
	return elliptics_time(info.json_timestamp);
}

elliptics_time dnet_record_info_get_data_timestamp(const dnet_record_info &info) {
	return elliptics_time(info.data_timestamp);
}

std::string callback_result_get_raw(const newapi::callback_result_entry &result) {
	return result.raw().to_string();
}

std::string callback_result_get_raw_data(const newapi::callback_result_entry &result) {
	return result.raw_data().to_string();
}

bp::object lookup_result_get_path(const newapi::lookup_result_entry &result) {
	if (result.status()) {
		return bp::object();
	}

	return bp::object(result.path());
}

bp::object lookup_result_get_record_info(const newapi::lookup_result_entry &result) {
	if (result.status()) {
		return bp::object();
	}

	return bp::object(result.record_info());
}

bp::object read_result_get_record_info(const newapi::read_result_entry &result) {
	if (result.status()) {
		return bp::object();
	}

	return bp::object(result.record_info());
}

bp::object read_result_get_io_info(const newapi::read_result_entry &result) {
	if (result.status()) {
		return bp::object();
	}

	return bp::object(result.io_info());
}

bp::object read_result_get_json(const newapi::read_result_entry &result) {
	if (result.status()) {
		return bp::object();
	}

	return bp::object(result.json().to_string());
}

bp::object read_result_get_data(const newapi::read_result_entry &result) {
	if (result.status()) {
		return bp::object();
	}

	return bp::object(result.data().to_string());
}

uint64_t iterator_result_get_iterator_id(const newapi::iterator_result_entry &result) {
	return result.iterator_id();
}

int iterator_result_get_status(const newapi::iterator_result_entry &result) {
	return result.status();
}

uint64_t iterator_result_get_iterated_keys(const newapi::iterator_result_entry &result) {
	return result.iterated_keys();
}

uint64_t iterator_result_get_total_keys(const newapi::iterator_result_entry &result) {
	return result.total_keys();
}

elliptics_id iterator_result_get_key(const newapi::iterator_result_entry &result) {
	auto key = result.key();
	return elliptics_id(key);
}

dnet_record_info iterator_result_get_record_info(const newapi::iterator_result_entry &result) {
	return result.record_info();
}

uint64_t iterator_result_get_blob_id(const newapi::iterator_result_entry &result) {
	return result.blob_id();
}

std::string iterator_result_get_json(const newapi::iterator_result_entry &result) {
	return result.json().to_string();
}

std::string iterator_result_get_data(const newapi::iterator_result_entry &result) {
	return result.data().to_string();
}

void iterator_container_append(newapi::iterator_result_container &container, newapi::iterator_result_entry &result) {
	container.append(result);
}

void iterator_container_append_old(newapi::iterator_result_container &container, ioremap::elliptics::iterator_result_entry &result) {
	container.append_old(result);
}

void iterator_container_sort(newapi::iterator_result_container &container) {
	container.sort();
}

uint64_t iterator_container_get_count(const newapi::iterator_result_container &container) {
	return container.m_count;
}

iterator_container_item iterator_container_getitem(const newapi::iterator_result_container &container, uint64_t n) {
	if (n >= container.m_count) {
		PyErr_SetString(PyExc_IndexError, "Index out of range");
		bp::throw_error_already_set();
	}
	return container[n];
}

elliptics_id iterator_container_item_key(const newapi::iterator_container_item &item) {
	return elliptics_id(item.key);
}

elliptics_time iterator_container_item_json_timestamp(const newapi::iterator_container_item &item) {
	return elliptics_time(item.json_timestamp);
}

elliptics_time iterator_container_item_data_timestamp(const newapi::iterator_container_item &item) {
	return elliptics_time(item.data_timestamp);
}

} /* unnamed namespace */

} /* namespace newapi */

void init_result_entry() {

	bp::class_<callback_result_entry>("CallbackResultEntry")
		.add_property("is_valid", callback_result_is_valid)
		.add_property("is_ack", callback_result_is_ack)
		.add_property("is_final", callback_result_is_final)
		.add_property("status", callback_result_status)
		.add_property("data", callback_result_data)
		.add_property("size", callback_result_size)
		.add_property("error", callback_result_error)
		.add_property("address", callback_entry_address)
		.add_property("group_id", callback_entry_group_id)
		.add_property("backend_id", callback_entry_backend_id)
		.add_property("trace_id", callback_entry_trace_id)
		.add_property("trans", callback_entry_trans)
	;

	bp::class_<index_entry>("IndexEntry")
		.add_property("index",
		              index_entry_get_index,
		              index_entry_set_index,
		              "index as elliptics.Id")
		.add_property("data",
		              index_entry_get_data,
		              index_entry_set_data,
		              "data associated with the index")
	;

	bp::class_<iterator_result_entry, bp::bases<callback_result_entry> >("IteratorResultEntry")
		.add_property("id", &iterator_result_entry::id,
		              "Iterator integer ID. Which can be used for pausing, continuing and canceling iterator")
		.add_property("response", iterator_result_response,
		              "elliptics.IteratorResultResponse which provides meta information about iterated key")
		.add_property("response_data", iterator_result_response_data,
		              "Data of iterated key. May be empty if elliptics.iterator_flags.data hasn't been specified for iteration.")
	;

	bp::class_<dnet_iterator_response>("IteratorResultResponse",
	                                   bp::no_init)
		.add_property("key", iterator_response_get_key,
		              "elliptics.Id of iterated key")
		.add_property("timestamp", iterator_response_get_timestamp,
		              "elliptics.Time timestamp of iterated key")
		.add_property("user_flags", &dnet_iterator_response::user_flags,
		              "Custom user-defined flags of iterated key")
		.add_property("size", &dnet_iterator_response::size,
		              "Size of iterated key data")
		.add_property("total_keys", &dnet_iterator_response::total_keys,
		              "Number of all keys")
		.add_property("iterated_keys", &dnet_iterator_response::iterated_keys,
		              "Number of iterated keys")
		.add_property("status", &dnet_iterator_response::status,
		              "Status of iterated key:\n"
		              "0 - common key\n"
		              "1 - keepalive response")
		.add_property("record_flags", &dnet_iterator_response::flags,
		              "Backend's flags of the record")
	;

	bp::class_<read_result_entry, bp::bases<callback_result_entry> >("ReadResultEntry")
		.add_property("data", read_result_get_data,
		              "Read data")
		.add_property("id", read_result_get_id,
		              "elliptics.Id of read object")
		.add_property("timestamp", read_result_get_timestamp,
		              "elliptics.Time timestamp of read object")
		.add_property("user_flags", read_result_get_user_flags,
		              "Custom user-defined flags of read object")
		.add_property("flags", read_result_get_flags,
		              "Internal flags of read object")
		.add_property("offset", read_result_get_offset,
		              "Offset with which object has been read")
		.add_property("size", read_result_get_size,
		              "Size of read object data")
		.add_property("total_size", read_result_get_total_size,
		              "Total size of object data")
		.add_property("io_attribute", read_result_get_io,
		              "elliptics.IoAttr of read operation")
		.add_property("record_flags", read_result_get_record_flags,
		              "combination of elliptics.record_flags.*")
	;

	bp::class_<lookup_result_entry, bp::bases<callback_result_entry> >("LookupResultEntry")
		.add_property("storage_address", lookup_result_get_storage_address)
		.add_property("size", lookup_result_get_size,
		              "Size of data")
		.add_property("offset", lookup_result_get_offset,
		              "Offset of operation")
		.add_property("timestamp", lookup_result_get_timestamp,
		              "elliptics.Time timestamp of object")
		.add_property("checksum", lookup_result_get_checksum,
		              "elliptics.Id checksum of object")
		.add_property("filepath", lookup_result_get_filepath,
		              "path to object in the backend")
		.add_property("record_flags", lookup_result_get_record_flags,
		              "combination of elliptics.record_floags.*")
	;

	bp::class_<exec_context>("ExecContext")
		.add_property("event", exec_context_get_event)
		.add_property("data", exec_context_get_data)
		.add_property("src_key", exec_context_get_src_key)
		.add_property("src_id", exec_context_get_src_id)
		.add_property("address", exec_context_get_address)
	;

	bp::class_<exec_result_entry, bp::bases<callback_result_entry> >("ExecResultEntry")
		.add_property("context", exec_result_get_context)
	;

	bp::class_<find_indexes_result_entry>("FindIndexesResultEntry")
		.add_property("id", find_indexes_result_get_id,
		              "elliptics.Id of id which has been found")
		.add_property("indexes", find_indexes_result_get_indexes,
		              "list of elliptics.IndexEntry which associated with the id")
	;

	bp::class_<monitor_stat_result_entry, bp::bases<callback_result_entry> >("MonitorStatResultEntry")
		.add_property("statistics", monitor_stat_result_get_statistics)
	;

	bp::class_<dnet_route_entry>("RouteEntry")
		.add_property("id", route_entry_get_id)
		.add_property("address", route_entry_get_address)
		.add_property("backend_id", &dnet_route_entry::backend_id)
	;

	bp::class_<backend_status_result_entry, bp::bases<callback_result_entry> >("BackendStatusResultEntry")
		.add_property("backends", &dnet_backend_status_result_get_backends)
	;

	bp::class_<dnet_backend_status>("BackendStatus")
		.add_property("backend_id", &dnet_backend_status::backend_id)
		.add_property("state", &dnet_backend_status::state)
		.add_property("defrag_state", &dnet_backend_status::defrag_state)
		.add_property("last_start", dnet_backend_status_get_last_start)
		.add_property("last_start_err", &dnet_backend_status::last_start_err)
		.add_property("read_only", dnet_backend_status_get_read_only)
	;

	bp::object newapiModule(bp::handle<>(bp::borrowed(PyImport_AddModule("core.newapi"))));
	bp::scope().attr("newapi") = newapiModule;
	bp::scope newapi_scope = newapiModule;

	bp::class_<newapi::callback_result_entry, bp::bases<callback_result_entry>>("CallbackResultEntry")
		.add_property("raw", newapi::callback_result_get_raw)
		.add_property("raw_data", newapi::callback_result_get_raw_data)
	;

	bp::class_<dnet_record_info>("RecordInfo",
		"Information about the record",
		bp::no_init)
		.add_property("record_flags", &dnet_record_info::record_flags,
		              "Flags from eblob headers of the record.")
		.add_property("user_flags", &dnet_record_info::user_flags,
		              "Custom user-flags stored in the record headers.")
		.add_property("json_timestamp", newapi::dnet_record_info_get_json_timestamp,
		              "Timestamp of json last modification.")
		.add_property("json_offset", &dnet_record_info::json_offset,
		              "Offset where json starts in file where the record is stored. "
		              "In read result it is unfilled and is set to 0.")
		.add_property("json_size", &dnet_record_info::json_size,
		              "Whole size of the record's json.")
		.add_property("json_capacity", &dnet_record_info::json_capacity,
		              "Size of reserved place for json in the record.")
		.add_property("data_timestamp", newapi::dnet_record_info_get_data_timestamp,
		              "Timestamp of data last modification.")
		.add_property("data_offset", &dnet_record_info::data_offset,
		              "Offset where data starts in file where the record is stored. "
		              "In read result it is unfilled and is set to 0.")
		.add_property("data_size", &dnet_record_info::data_size,
		              "Whole size of the record's data.")
	;

	bp::class_<dnet_io_info>("IOInfo",
		"Information about read operation.",
		bp::no_init)
		.add_property("json_size", &dnet_io_info::json_size,
		              "Size of read json.")
		.add_property("data_offset", &dnet_io_info::data_offset,
		              "Offset in original data with which data part was read.")
		.add_property("data_size", &dnet_io_info::data_size,
		              "Size of data part which was read.")
	;

	bp::class_<newapi::lookup_result_entry, bp::bases<newapi::callback_result_entry>>("LookupResultEntry",
		"Result of lookup which contains information about the key",
		bp::no_init)
		.add_property("path", newapi::lookup_result_get_path,
		              "Absolute path to the file where the key is stored on server-side.")
		.add_property("record_info", newapi::lookup_result_get_record_info,
		              "Information about the key.")
	;

	bp::class_<newapi::read_result_entry, bp::bases<newapi::callback_result_entry>>("ReadResultEntry",
		"Result of read which contains information of read key and read json and/or data.",
		bp::no_init)
		.add_property("record_info", newapi::read_result_get_record_info,
		              "Information of read key.")
		.add_property("io_info", newapi::read_result_get_io_info,
		              "Information of read operation")
		.add_property("json", newapi::read_result_get_json,
		              "Read json if it was requested otherwise it is empty string.")
		.add_property("data", newapi::read_result_get_data,
		              "Read data if it was requested otherwise it is empty string.")
	;

	bp::class_<newapi::iterator_result_entry, bp::bases<newapi::callback_result_entry>>("IteratorResultEntry",
		"Result of iteration which contains information about one iterated key.",
		bp::no_init)
		.add_property("iterator_id", newapi::iterator_result_get_iterator_id,
		              "Id of iterator which can be used for pausing, continuing and canceling of iteration.")
		.add_property("status", newapi::iterator_result_get_status,
		              "Status of key iteration. In most cases it is 0. Negative value "
		              "contains error code of failure which happened with this key iteration. "
		              "Positive value signify that it is system result without "
		              "any important information for users and it should be ignored.")
		.add_property("iterated_keys", newapi::iterator_result_get_iterated_keys,
		              "Number of iterated keys at the moment of this key iteration.")
		.add_property("total_keys", newapi::iterator_result_get_total_keys,
		              "Total number of keys which expected to be iterated. "
		              "It isn't true when some filtering is on, for example, filtering by key-range.")
		.add_property("key", newapi::iterator_result_get_key,
		              "elliptics.Id of iterated key.")
		.add_property("record_info", newapi::iterator_result_get_record_info,
		              "Information about iterated key.")
		.add_property("blob_id", newapi::iterator_result_get_blob_id,
			      "Information about key belonging to a specific blob")
		.add_property("json", newapi::iterator_result_get_json,
		              "Json of iterated key if appropriate flag was set otherwise it is empty string.")
		.add_property("data", newapi::iterator_result_get_data,
		              "Data of iterated key if appropriate flag was set otherwise it is empty string.")
	;

	bp::class_<newapi::iterator_container_item>("IteratorContainerItem",
		"Result of iteration which contains information about one iterated key.",
		bp::no_init)
		.add_property("key", newapi::iterator_container_item_key,
			      "elliptics.Id of iterated key")
		.add_property("status", &newapi::iterator_container_item::status,
			      "Status of iterated key:\n"
			      "0 - common key\n"
			      "1 - keepalive response")
		.add_property("record_flags", &newapi::iterator_container_item::record_flags,
			      "Backend's flags of the record")
		.add_property("user_flags", &newapi::iterator_container_item::user_flags,
			      "Custom user-defined flags of iterated key")
		.add_property("json_timestamp", newapi::iterator_container_item_json_timestamp,
			      "Timestamp of json last modification.")
		.add_property("json_size", &newapi::iterator_container_item::json_size,
			      "Whole size of the record's json.")
		.add_property("json_capacity", &newapi::iterator_container_item::json_capacity,
			      "Size of reserved place for json in the record.")
		.add_property("data_timestamp", newapi::iterator_container_item_data_timestamp,
			      "Timestamp of data last modification.")
		.add_property("data_size", &newapi::iterator_container_item::data_size,
			      "Whole size of the record's data.")
		.add_property("data_offset", &newapi::iterator_container_item::data_offset,
			      "Offset where data starts in file where the record is stored.")
		.add_property("blob_id", &newapi::iterator_container_item::blob_id,
			      "Integer identifier of a key's blob.")
	;

	bp::class_<newapi::iterator_result_container>("IteratorResultContainer",
			bp::init<int>(bp::args("fd")))
		.def(bp::init<int, bool, uint64_t>(bp::args("fd", "sorted", "write_position"),
			"__init__(self, fd, sorted, write_position)\n"
		         "    Initializes iterator result container using existing file descriptor"))
		.def("append", newapi::iterator_container_append,
		     (bp::arg("iterator_result_entry")),
		     "append(iterator_result_entry)\n"
		     "    Appends iterator_result_entry of type elliptics.core.newapi.IteratorResultEntry to the end of the container file")
		.def("append_old", newapi::iterator_container_append_old,
		     (bp::arg("iterator_result_entry")),
		     "append_old(iterator_result_entry)\n"
		     "    Appends iterator_result_entry of type elliptics.core.IteratorResultEntry to the end of the container file")
		.def("sort", newapi::iterator_container_sort,
		     "sort()\n"
		     "    Sorts items of the container file by (key, data_timestamp, json_timestamp, data_size) tuple")
		.def("__len__", newapi::iterator_container_get_count,
		     "x.__len__() <==> len(x)\n"
		     "    Returns the number of items in the container file")
		.def("__getitem__", newapi::iterator_container_getitem,
		     (bp::arg("n")),
		     "x.__getitem__(n) <==> x[n]\n"
		     "    Returns n-th item of the container file of type elliptics.core.newapi.IteratorContainerItem")
	;
}

} } } // namespace ioremap::elliptics::python
