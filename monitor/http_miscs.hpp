/*
 * Copyright 2013+ Kirill Smorodinnikov <shaitkir@gmail.com>
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
 * You should have received a copy of the GNU General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __DNET_MONITOR_HTTP_MISCS_H
#define __DNET_MONITOR_HTTP_MISCS_H

#include <string>

namespace ioremap { namespace monitor {

namespace status_strings {
const std::string ok = "HTTP/1.1 200 OK\r\n";
}

namespace content_strings {
const std::string list = R"(<html>
	<body>
		GET <a href='/list'>/list</a> - Retrieves a list of acceptable statistics<br/>
		GET <a href='/all'>/all</a> - Retrieves all statistics from all submodules<br/>
		GET <a href='/cache'>/cache</a> - Retrieves statistics about cache<br/>
		GET <a href='/io'>/io</a> - Retrieves statistics about io statistics<br/>
		GET <a href='/commands'>/commands</a> - Retrieves statistics about commands<br/>
		GET <a href='/io_histograms'>/io_histograms</a> - Retrieves statistics about io histograms<br/>
		GET <a href='/backend'>/backend</a> - Retrieves statistics about backend<br/>
		GET <a href='/stats'>/stats</a> - Retrieves in-process runtime statistics<br/>
		GET <a href='/procfs'>/procfs</a> - Retrieves system statistics about process<br/>
		GET <a href='/top'>/top</a> - Retrieves statistics of top keys ordered by generated traffic<br/>
	</body>
</html>)";
}

/*!
 * Generates HTTP response for @req category with @content
 */
std::string make_reply(uint64_t req, std::string content = "") {
	std::ostringstream ret;
	std::string content_type = "application/json";
	if (req == 0) {
		content = content_strings::list;
		content_type = "text/html";
	}

	ret << status_strings::ok
	    << "Content-Type: " << content_type << "\r\n"
	    << (req != 0 ? "Content-Encoding: deflate\r\n" : "")
	    << "Connection: close\r\n"
	    << "Content-Length: " << content.size() << "\r\n\r\n"
	    << content;

	return ret.str();
}

}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_HTTP_MISCS_H */
