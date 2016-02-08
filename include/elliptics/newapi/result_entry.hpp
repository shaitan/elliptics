#ifndef ELLIPTICS_NEW_RESULT_ENTRY_HPP
#define ELLIPTICS_NEW_RESULT_ENTRY_HPP

#include "elliptics/result_entry.hpp"

namespace ioremap { namespace elliptics { namespace newapi {

class callback_result_entry : public ioremap::elliptics::callback_result_entry {
public:
	callback_result_entry() = default;
	~callback_result_entry() = default;

	data_pointer raw() const;
	data_pointer raw_data() const;
};

class lookup_result_entry : public callback_result_entry {
public:
	lookup_result_entry() = default;
	~lookup_result_entry() = default;

	std::string path() const;
	dnet_record_info info() const;
};

class read_result_entry : public callback_result_entry {
public:
	read_result_entry() = default;
	~read_result_entry() = default;

	dnet_record_info info() const;
	data_pointer json() const;
	data_pointer data() const;
};

typedef lookup_result_entry write_result_entry;
typedef callback_result_entry remove_result_entry;

typedef async_result<lookup_result_entry> async_lookup_result;
typedef std::vector<lookup_result_entry> sync_lookup_result;

typedef async_result<read_result_entry> async_read_result;
typedef std::vector<read_result_entry> sync_read_result;

typedef async_result<write_result_entry> async_write_result;
typedef std::vector<write_result_entry>	sync_write_result;

}}} /* namespace ioremap::elliptics::newapi */

#endif // ELLIPTICS_NEW_RESULT_ENTRY_HPP
