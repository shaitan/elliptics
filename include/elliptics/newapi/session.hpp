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

	/*!
	 * \overload
	 */
	dnet_time get_timestamp() const;
	void reset_timestamp();

	/*!
	 * Sets json timestamp for given session.
	 * All write operations will use this json timestamp, instead of data timestamp.
	 * If set to zero (default), data timestamp will be used.
	 */
	void set_json_timestamp(const dnet_time &ts);
	dnet_time get_json_timestamp() const;
	void reset_json_timestamp();

	/* Sets cache lifetime in seconds for given session.
	 * Any write operation to the cache with positive cache \a lifetime value forces discarding
	 * of a written key from cache after given \a lifetime period.
	 */
	void set_cache_lifetime(uint64_t lifetime);
	uint64_t get_cache_lifetime() const;

	/* Lookup information for key \a id.
	 */
	async_lookup_result lookup(const key &id);

	/* Removal behaviour depends on the value of a session ioflags.
	 * If DNET_IO_FLAGS_CAS_TIMESTAMP is set then session timestamp is compared with the key's
	 * timestamp. If session timestamp is greater or equal, then the key is removed.
	 * Corrupted replicas will be removed anyway.
	 */
	async_remove_result remove(const key &id);

	/* Read json of key \a id.
	 */
	async_read_result read_json(const key &id);

	/* Read data part of key \a id specified by \a offset and \a size.
	 * Please note, \a size equal to 0 means reading all available data after \a offset.
	 */
	async_read_result read_data(const key &id, uint64_t offset, uint64_t size);

	/* Read json and data of key \a id.
	 * \a offset and \a size specifies part of key's data that should be read.
	 * Please note, \a size equal to 0 means reading all available data after \a offset.
	 */
	async_read_result read(const key &id, uint64_t offset, uint64_t size);

	/* Write \a json and \a data by key \a id.
	 * \a json_capacity specifies size of space that should be reserved for future json.
	 * \a data_capacity specifies size of space that should be reserved for future data.
	 * Please note, both \a json_capacity and \a data_capacity with value 0 means that
	 * no extra space should be reserved.
	 * Record will be available for lookup/read right after write is executed.
	 */
	async_write_result write(const key &id,
	                         const argument_data &json, uint64_t json_capacity,
	                         const argument_data &data, uint64_t data_capacity);

	/* Prepare place for record by \a key,
	 * reserve place with size \a json_capacity for future json and
	 * with \a data_capacity for future data and
	 * write \a json and data part \a data.
	 * \a data should be written with \a data_offset.
	 * Record after prepare will be marked as uncommitted and will be unavailable for lookup/read.
	 */
	async_lookup_result write_prepare(const key &id,
	                                  const argument_data &json, uint64_t json_capacity,
	                                  const argument_data &data, uint64_t data_offset, uint64_t data_capacity);

	/* Write \a json and data part \a data by key \a id.
	 * \a data should be written with \a data_offset.
	 * Record after write_plain remains to be marked as uncommitted and will be unavailable for lookup/read.
	 */
	async_lookup_result write_plain(const key &id,
	                                const argument_data &json,
	                                const argument_data &data, uint64_t data_offset);

	/* Write final \a json and final data part \a data by key \a id.
	 * \a data should be written with \a data_offset.
	 * Record after write_plain will be available for lookup/read.
	 */
	async_lookup_result write_commit(const key &id,
	                                 const argument_data &json,
	                                 const argument_data &data, uint64_t data_offset, uint64_t data_commit_size);

	/* Rewrite json of key \a id by \a json.
	 * If record \a id does not exist, update_json will be failed with -ENOENT.
	 * If record's capacity for json part is less than size of \a json, update_json will be failed with -E2BIG.
	 * Calling update_json with empty \a json will reset stored json to 0 but leave its capacity.
	 */
	async_lookup_result update_json(const key &id, const argument_data &json);


	async_iterator_result start_iterator(const address &addr, uint32_t backend_id, uint64_t flags,
	                                     const std::vector<dnet_iterator_range> &key_ranges,
	                                     const std::tuple<dnet_time, dnet_time> &time_range);

	async_iterator_result server_send(const std::vector<dnet_raw_id> &keys, uint64_t flags, uint64_t chunk_size,
	                                  const int src_group, const std::vector<int> &dst_groups);

	async_iterator_result server_send(const std::vector<std::string> &keys, uint64_t flags, uint64_t chunk_size,
	                                  const int src_group, const std::vector<int> &dst_groups);

	async_iterator_result server_send(const std::vector<key> &keys, uint64_t flags, uint64_t chunk_size,
	                                  const int src_group, const std::vector<int> &dst_groups);
};

}}} /* namespace ioremap::elliptics::newapi */


#endif // ELLIPTICS_NEW_SESSION_HPP
