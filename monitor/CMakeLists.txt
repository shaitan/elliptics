ADD_LIBRARY(elliptics_monitor STATIC
            monitor.cpp
            server.cpp
            statistics.cpp
            io_stat_provider.cpp
            backends_stat_provider.cpp
            procfs_provider.cpp
            top.cpp
            http_request.cpp
            )

if(UNIX OR MINGW)
	set_target_properties(elliptics_monitor PROPERTIES COMPILE_FLAGS "-fPIC")
endif()

target_link_libraries(elliptics_monitor
                      ${CMAKE_THREAD_LIBS_INIT}
                      ${Boost_LIBRARIES}
                      elliptics_client
                      elliptics_cache
                      ${HTTP_PARSER_LIBRARIES}
                      ${URIPARSER_LIBRARIES}
                      )
if (WITH_STATS)
    target_link_libraries(elliptics_monitor ${HANDYSTATS_LIBRARY})
endif()
