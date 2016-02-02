#include "protocol.h"

#include <msgpack.hpp>

namespace msgpack {

inline dnet_io_attr &operator >>(object o, dnet_io_attr &v)
{
	if (o.type != type::ARRAY || o.via.array.size < 12)
		throw type_error();

	object *p = o.via.array.ptr;

	if (p[0].via.raw.size != DNET_ID_SIZE)
		throw type_error();
	memcpy(v.parent, p[0].via.raw.ptr, p[0].via.raw.size);

	if (p[1].via.raw.size != DNET_ID_SIZE)
		throw type_error();
	memcpy(v.id, p[1].via.raw.ptr, p[1].via.raw.size);

	p[2].convert(&v.start);
	p[3].convert(&v.num);

	p[4].convert(&v.timestamp.tsec);
	p[5].convert(&v.timestamp.tnsec);
	p[6].convert(&v.user_flags);

	p[7].convert(&v.total_size);

	p[8].convert(&v.record_flags);

	p[9].convert(&v.flags);
	p[10].convert(&v.offset);
	p[11].convert(&v.size);

	return v;
}

template <typename Stream>
inline packer<Stream> &operator <<(packer<Stream> &o, const dnet_io_attr &v)
{
	o.pack_array(11);

	o.pack_raw(DNET_ID_SIZE);
	o.pack_raw_body((const char*)v.parent, DNET_ID_SIZE);

	o.pack_raw(DNET_ID_SIZE);
	o.pack_raw_body((const char*)v.id, DNET_ID_SIZE);

	o.pack(v.start);
	o.pack(v.num);

	o.pack(v.timestamp.tsec);
	o.pack(v.timestamp.tnsec);
	o.pack(v.user_flags);

	o.pack(v.total_size);

	o.pack(v.record_flags);

	o.pack(v.flags);
	o.pack(v.offset);
	o.pack(v.size);

	return o;
}

} /* namespace msgpack */

int dnet_convert_io(dnet_io_control *ctl) {
	msgpack::sbuffer buffer;
	msgpack::pack(buffer, ctl->io);

	if (ctl->io_raw)
		free(ctl->io_raw);

	ctl->io_raw = calloc(1, buffer.size());
	if (!ctl->io_raw) {
		ctl->io_raw_size = 0;
		return -ENOMEM;
	}

	ctl->io_raw_size = buffer.size();

	memcpy(ctl->io_raw, buffer.data(), buffer.size());
	return 0;
}
