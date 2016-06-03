/*
 * 2015+ Copyright (c) Ivan Chelyubeev <ivan.chelubeev@gmail.com>
 * 2014 Copyright (c) Asier Gutierrez <asierguti@gmail.com>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#ifndef LOCALNODE_SERIALIZATION_TRAITS_HPP
#define LOCALNODE_SERIALIZATION_TRAITS_HPP

#include <msgpack.hpp>
#include <cocaine/traits.hpp>
#include <elliptics/packet.h>
#include <elliptics/utils.hpp>

namespace cocaine { namespace io {

template<>
struct type_traits<ioremap::elliptics::data_pointer> {

    template<class Stream>
    static inline
    void
    pack(msgpack::packer<Stream>& target, const ioremap::elliptics::data_pointer& source) {
        target.pack_raw(source.size());
        target.pack_raw_body(static_cast<const char *>(source.data()), source.size());
    }

    static inline
    void
    unpack(const msgpack::object& source, ioremap::elliptics::data_pointer& target) {
        if (source.type != msgpack::type::RAW) {
            throw msgpack::type_error();
        }
        //XXX: Is it possible to avoid this copy?
        target = ioremap::elliptics::data_pointer::copy(
            source.via.raw.ptr,
            source.via.raw.size
        );
    }
};

}}

namespace msgpack {

//
// Msgpack serialization for structures used by service.
//
// Note: not using cocaine::io::type_traits<> here because input/output
// operators are more universal.
//

// struct dnet_raw_id {
//  uint8_t         id[DNET_ID_SIZE];
// } __attribute__ ((packed));
//
// Defined in elliptics/packet.h.
//
template <typename Stream>
inline msgpack::packer<Stream>& operator <<(msgpack::packer<Stream> &o, const dnet_raw_id &v)
{
    o.pack_array(1);
    o.pack_raw(sizeof(v.id));
    o.pack_raw_body(reinterpret_cast<const char *>(v.id), sizeof(v.id));
    return o;
}
inline dnet_raw_id& operator >>(const msgpack::object &o, dnet_raw_id &v)
{
    if (o.type != msgpack::type::ARRAY || o.via.array.size != 1) {
        throw msgpack::type_error();
    }
    {
        const auto &f = o.via.array.ptr[0];
        if (f.type != msgpack::type::RAW || f.via.raw.size != sizeof(v.id)) {
            throw msgpack::type_error();
        }
        memcpy(&v.id, f.via.raw.ptr, sizeof(v.id));
    }
    return v;
}

// struct dnet_time {
//  uint64_t        tsec, tnsec;
// };
//
// Defined in elliptics/packet.h.
//
template <typename Stream>
inline msgpack::packer<Stream>& operator <<(msgpack::packer<Stream> &o, const dnet_time &v)
{
    o.pack_array(2);
    o.pack_uint64(v.tsec);
    o.pack_uint64(v.tnsec);
    return o;
}
inline dnet_time& operator >>(const msgpack::object &o, dnet_time &v)
{
    if (o.type != msgpack::type::ARRAY || o.via.array.size != 2) {
        throw msgpack::type_error();
    }
    v.tsec = o.via.array.ptr[0].as<uint64_t>();
    v.tnsec = o.via.array.ptr[1].as<uint64_t>();
    return v;
}

// struct dnet_record_info {
//     uint64_t    record_flags;       /* combination of DNET_RECORD_FLAGS_* */
//     uint64_t    user_flags;     /* user-defined flags */
//
//     struct dnet_time json_timestamp;    /* timestamp of stored json */
//     uint64_t    json_offset;        /* offset of json within blob */
//     uint64_t    json_size;      /* size of stored json */
//     uint64_t    json_capacity;      /* reserved space for json */
//
//     struct dnet_time data_timestamp;    /* timestamp of stored data */
//     uint64_t    data_offset;        /* offset of data within the blob */
//     uint64_t    data_size;      /* size of stored data */
//     // uint64_t data_capacity;      /* reserved space for data */
// };
//
// Defined in elliptics/packet.h.
//
template <typename Stream>
inline msgpack::packer<Stream>& operator <<(msgpack::packer<Stream> &o, const dnet_record_info &v)
{
    o.pack_array(9);
    o.pack_uint64(v.record_flags);
    o.pack_uint64(v.user_flags);
    o.pack(v.json_timestamp);
    o.pack_uint64(v.json_offset);
    o.pack_uint64(v.json_size);
    o.pack_uint64(v.json_capacity);
    o.pack(v.data_timestamp);
    o.pack_uint64(v.data_offset);
    o.pack_uint64(v.data_size);
    // o.pack_uint64(v.data_capacity);
    return o;
}
inline dnet_record_info& operator >>(const msgpack::object &o, dnet_record_info &v)
{
    if (o.type != msgpack::type::ARRAY || o.via.array.size != 9) {
        throw msgpack::type_error();
    }
    int N = 0;
    o.via.array.ptr[N++] >> v.record_flags;
    o.via.array.ptr[N++] >> v.user_flags;
    o.via.array.ptr[N++] >> v.json_timestamp;
    o.via.array.ptr[N++] >> v.json_offset;
    o.via.array.ptr[N++] >> v.json_size;
    o.via.array.ptr[N++] >> v.json_capacity;
    o.via.array.ptr[N++] >> v.data_timestamp;
    o.via.array.ptr[N++] >> v.data_offset;
    o.via.array.ptr[N++] >> v.data_size;
    // o.via.array.ptr[N++] >> v.data_capacity;
    return v;
}

// struct dnet_io_info {
//     uint64_t json_size; /* size of json which has been read or written */
//
//     uint64_t data_offset; /* offset with which data part has been read or written */
//     uint64_t data_size; /* size of data part which has been read or written */
// };
//
// Defined in elliptics/packet.h.
//
template <typename Stream>
inline msgpack::packer<Stream>& operator <<(msgpack::packer<Stream> &o, const dnet_io_info &v)
{
    o.pack_array(3);
    o.pack_uint64(v.json_size);
    o.pack_uint64(v.data_offset);
    o.pack_uint64(v.data_size);
    return o;
}
inline dnet_io_info& operator >>(const msgpack::object &o, dnet_io_info &v)
{
    if (o.type != msgpack::type::ARRAY || o.via.array.size != 3) {
        throw msgpack::type_error();
    }
    int N = 0;
    o.via.array.ptr[N++] >> v.json_size;
    o.via.array.ptr[N++] >> v.data_offset;
    o.via.array.ptr[N++] >> v.data_size;
    return v;
}

} // namespace msgpack

#endif // LOCALNODE_SERIALIZATION_TRAITS_HPP
