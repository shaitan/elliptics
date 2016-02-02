#include "test_base.hpp"

#include "library/packet.hpp"
#include "elliptics/utils.hpp"

#define BOOST_TEST_NO_MAIN
#include <boost/test/included/unit_test.hpp>

#include <boost/program_options.hpp>

using namespace ioremap::elliptics;
using namespace boost::unit_test;

static void protocol_test_pack_unpack() {
	auto json = data_pointer::copy("{'a': 10}");
	uint64_t json_capacity = 1024;
	auto data = data_pointer::copy("aaa");
	uint64_t data_capacity = 1024;

	data_pointer raw = [&] () {
		msgpack::sbuffer buffer;

		dnet_io_attributes io;
		io.flags = DNET_IO_FLAGS_JSON
		           | DNET_IO_FLAGS_DATA;
		io.user_flags = 0;
		msgpack::pack(buffer, io);

		dnet_json_attributes j;
		j.size = json.size();
		j.capacity = json_capacity;
		dnet_current_time(&j.timestamp); // get_timestamp(&j.timestamp);
		msgpack::pack(buffer, j);

		dnet_data_attributes d;
		d.size = data.size();
		d.capacity = data_capacity;
		d.offset = 0;
		d.commit_size = data.size();
		dnet_current_time(&d.timestamp); // get_timestamp(&d.timestamp);
		msgpack::pack(buffer, d);

		data_buffer tmp_buffer(buffer.size() + json.size() + data.size());
		tmp_buffer.write(buffer.data(), buffer.size());
		tmp_buffer.write(json.data(), json.size());
		tmp_buffer.write(data.data(), data.size());
		return std::move(tmp_buffer);
	} ();

	{
		size_t offset = 0;
		msgpack::unpacked msg;
		msgpack::unpack(&msg, raw.data<char>(), raw.size(), &offset);
		dnet_io_attributes io;
		msg.get().convert(&io);

		BOOST_REQUIRE_EQUAL(io.flags, DNET_IO_FLAGS_JSON | DNET_IO_FLAGS_DATA);
		BOOST_REQUIRE_EQUAL(io.user_flags, 0);

		dnet_json_attributes j;
		msgpack::unpack(&msg, raw.data<char>(), raw.size(), &offset);
		msg.get().convert(&j);

		BOOST_REQUIRE_EQUAL(j.size, json.size());
		BOOST_REQUIRE_EQUAL(j.capacity, json_capacity);

		dnet_data_attributes d;
		msgpack::unpack(&msg, raw.data<char>(), raw.size(), &offset);
		msg.get().convert(&d);

		BOOST_REQUIRE_EQUAL(d.size, data.size());
		BOOST_REQUIRE_EQUAL(d.capacity, data_capacity);
		BOOST_REQUIRE_EQUAL(d.offset, 0);
		BOOST_REQUIRE_EQUAL(d.commit_size, data.size());

		BOOST_REQUIRE_EQUAL(raw.size(), offset + json.size() + data.size());
	}
}

static bool protocol_register_tests(test_suite *suite) {

	ELLIPTICS_TEST_CASE(protocol_test_pack_unpack);
	return true;
}

static test_suite *protocol_setup_tests(int argc, char *argv[]) {
	namespace bpo = boost::program_options;

	bpo::variables_map vm;
	bpo::options_description generic("Test options");

	std::string path;
	generic.add_options()
			("help", "This help message")
			("path", bpo::value(&path), "Path where to store everything")
			;

	bpo::store(bpo::parse_command_line(argc, argv, generic), vm);
	bpo::notify(vm);

	if (vm.count("help")) {
		std::cerr << generic;
		return NULL;
	}

	auto suite = new test_suite("Local Test Suite");

	protocol_register_tests(suite);

	return suite;

}

int main(int argc, char *argv[]) {
	return unit_test_main(protocol_setup_tests, argc, argv);
}
