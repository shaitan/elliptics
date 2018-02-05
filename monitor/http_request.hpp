/*
 * Copyright 2018+ Artem Ikchurin <artem.ikchurin@gmail.com>
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

#ifndef ELLIPTICS_HTTP_REQUEST_H
#define ELLIPTICS_HTTP_REQUEST_H

#include <string>
#include <unordered_map>

#include <http_parser.h>

namespace ioremap { namespace monitor {

/*!
 * Handler class which parses incoming raw bytes of HTTP request
 * and extract URL. Also parse URL to path and query.
 */
class http_request {
public:
	http_request();

	/*!
	 * Sign of the end of the http request
	 */
	bool ready() const;

	/*!
	 * Parse new part of http request
	 * Return true if there is no errors in request
	 */
	bool parse(char* buffer, size_t size);

	int error_code() const;
	/*!
	 * Error description
	 */
	std::string error() const;

	/*!
	 * Get resulting path
	 */
	const std::string &path() const;

	/*!
	 * Get resulting query
	 */
	const std::unordered_map<std::string, std::string> &query() const;

	/*!
	 * Get resulting URL
	 */
	const std::string &url() const;

private:
	/*!
	 * URL callback function used by http parser.
	 * Collect all parts of URl from incoming message.
	 */
	static int on_url(http_parser* parser, const char *at, size_t length);

	/*!
	 * Message end callback function used by http parser
	 */
	static int on_message_complete(http_parser* parser);

	/*!
	 * Parse URL to path and query
	 */
	bool parse_url();

	/*!
	 * Result values
	 */
	std::string m_path;
	std::string m_url;
	std::unordered_map<std::string, std::string> m_query;

	/*!
	 * Structs from http_parser lib that process http request
	 */
	http_parser m_parser;
	http_parser_settings m_parser_settings;

	/*!
	 * Error code from uriparser
	 */
	int m_uriparser_error_code;

	/*!
	 * Flag that indicate end of http message
	 */
	bool m_ready;
};

}} /* namespace ioremap::monitor */

#endif /* ELLIPTICS_HTTP_REQUEST_H */
