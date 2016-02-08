#ifndef ELLIPTICS_NEW_SESSION_HPP
#define ELLIPTICS_NEW_SESSION_HPP

#include "elliptics/session.hpp"
#include "result_entry.hpp"

namespace ioremap { namespace elliptics { namespace newapi {

class session: public elliptics::session {
public:
	explicit session(const node &);
	explicit session(dnet_node *);
	explicit session(const std::shared_ptr<session_data> &);
	session(const session &);
	session(const elliptics::session &other);
	virtual ~session();

	session clone() const;
	session clean_clone() const;
	session &operator =(const session &other);

	async_lookup_result lookup(const key &id);
	async_read_result read_json(const key &id);
	async_read_result read_data(const key &id, uint64_t offset, uint64_t size);
	async_read_result read(const key &id, uint64_t offset, uint64_t size);

	async_write_result write(const key &id,
	                         const argument_data &json, uint64_t json_capacity,
	                         const argument_data &data, uint64_t data_capacity);

	async_lookup_result write_prepare(const key &id,
	                                  const argument_data &json, uint64_t json_capacity,
	                                  const argument_data &data, uint64_t data_offset, uint64_t data_capacity);

	async_lookup_result write_plain(const key &id,
	                                const argument_data &json,
	                                const argument_data &data, uint64_t data_offset);

	async_lookup_result write_commit(const key &id,
	                                 const argument_data &json,
	                                 const argument_data &data, uint64_t data_offset, uint64_t data_commit_size);
};

}}} /* namespace ioremap::elliptics::newapi */


#endif // ELLIPTICS_NEW_SESSION_HPP
