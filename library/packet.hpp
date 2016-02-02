#include "elliptics/packet.h"

#include <msgpack.hpp>

namespace msgpack
{
#include "elliptics/packet.h"
inline dnet_io_attributes &operator >>(msgpack::object o, dnet_io_attributes &v)
{
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 11)
		throw msgpack::type_error();

	object *p = o.via.array.ptr;
	p[0].convert(&v.flags);
	p[1].convert(&v.user_flags);

	p[2].convert(&v.timestamp.tsec);
	p[3].convert(&v.timestamp.tnsec);

	p[4].convert(&v.cache_lifetime);

	p[5].convert(&v.json_size);
	p[6].convert(&v.json_capacity);

	p[7].convert(&v.data_offset);
	p[8].convert(&v.data_size);
	p[9].convert(&v.data_capacity);
	p[10].convert(&v.data_total_size);
	p[11].convert(&v.record_flags);

	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_io_attributes &v)
{
	o.pack_array(11);
	o.pack(v.flags);
	o.pack(v.user_flags);

	o.pack(v.timestamp.tsec);
	o.pack(v.timestamp.tnsec);

	o.pack(v.cache_lifetime);

	o.pack(v.json_size);
	o.pack(v.json_capacity);

	o.pack(v.data_offset);
	o.pack(v.data_size);
	o.pack(v.data_capacity);
	o.pack(v.data_total_size);
	o.pack(v.record_flags);

	return o;
}

} // namespace msgpack
