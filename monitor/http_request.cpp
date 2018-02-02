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

#include "http_request.hpp"

#include <uriparser/Uri.h>

namespace ioremap { namespace monitor {
http_request::http_request() {
	// func http_parser_settings_init missing in package libhttp-parser-dev
	memset(&m_parser_settings, 0, sizeof(m_parser_settings));
	m_parser_settings.on_url = http_request::on_url;
	m_parser_settings.on_message_complete = http_request::on_message_complete;
	m_parser.data = this;
	http_parser_init(&m_parser, HTTP_REQUEST);
	m_ready = false;
	m_uriparser_error_code = URI_SUCCESS;
}

bool http_request::parse(char* buffer, size_t size) {
	size_t parsed = http_parser_execute(&m_parser, &m_parser_settings, buffer, size);
	if (parsed != size)
		return false;
	// At this point http request is processed correctly
	// And if whole http request is received we can parse url
	if (ready())
		return parse_url();
	return true;
}

int http_request::on_url(http_parser* parser, const char *at, size_t length) {
	static_cast<http_request*>(parser->data)->m_url.append(at, length);
	return 0;
}

int http_request::on_message_complete(http_parser* parser) {
	static_cast<http_request *>(parser->data)->m_ready = true;
	return 0;
}

bool http_request::parse_url() {
	m_path.clear();
	m_query.clear();
	UriParserStateA state;
	UriUriA uri;
	state.uri = &uri;
	// parse
	int result = uriParseUriA(&state, m_url.c_str());
	if (result != URI_SUCCESS) {
		uriFreeUriMembersA(&uri);
		m_uriparser_error_code = result;
		return false;
	}
	if (uri.pathHead != nullptr and uri.pathTail != nullptr) {
		for (UriPathSegmentA* path_segment = uri.pathHead;
		     path_segment != nullptr; path_segment = path_segment->next) {
			m_path.append("/");
			m_path.append(std::string(path_segment->text.first,
			                          path_segment->text.afterLast - path_segment->text.first));
		}
	} else {
		m_path = "/";
	}
	if (uri.query.first != nullptr and uri.query.afterLast != nullptr) {
		UriQueryListA * queryList;
		int itemCount = 0;
		result = uriDissectQueryMallocA(&queryList, &itemCount, uri.query.first, uri.query.afterLast);
		if (result == URI_SUCCESS) {
			UriQueryListA* get_param = queryList;
			for (; get_param != nullptr; get_param = get_param->next) {
				m_query.insert({get_param->key, get_param->value != nullptr ? get_param->value : ""});
			}
			// free
			uriFreeQueryListA(queryList);
		} else {
			m_uriparser_error_code = result;
			uriFreeUriMembersA(&uri);
			return false;
		}
	}
	uriFreeUriMembersA(&uri);
	return true;
}

int http_request::error_code() const{
	if (HTTP_PARSER_ERRNO(&m_parser) != http_errno::HPE_OK) {
		return HTTP_PARSER_ERRNO(&m_parser);
	}
	return m_uriparser_error_code;
}

std::string http_request::error() const{
	if (HTTP_PARSER_ERRNO(&m_parser) != http_errno::HPE_OK) {
		return std::string("HTTP_PARSER - ").append(http_errno_description(HTTP_PARSER_ERRNO(&m_parser)));
	}
	// uripapser execute only when there is no error in http_parser
	switch (m_uriparser_error_code) {
		case URI_SUCCESS:
			return "URIPARSER - Success";
		case URI_ERROR_SYNTAX:
			return "URIPARSER - Parsed text violates expected format";
		case URI_ERROR_NULL:
			return "URIPARSER - One of the params passed was NULL";
		case URI_ERROR_MALLOC:
			return "URIPARSER - Requested memory could not be allocated";
		case URI_ERROR_OUTPUT_TOO_LARGE:
			return "URIPARSER - Some output is to large for the receiving buffer";
		case URI_ERROR_NOT_IMPLEMENTED:
			return "URIPARSER - The called function is not implemented yet";
		case URI_ERROR_RANGE_INVALID:
			return "URIPARSER - The parameters passed contained invalid ranges";
		default:
			return "URIPARSER - Unknown error";
	}
}

bool http_request::ready() const {
	return m_ready;
}

const std::string &http_request::url() const {
	return m_url;
}

const std::unordered_map<std::string, std::string> &http_request::query() const {
	return m_query;
};

const std::string &http_request::path() const {
	return m_path;
}

}} /* namespace ioremap::monitor */
