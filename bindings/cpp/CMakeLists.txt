option(DEVELOPER_BUILD "Enables developer asserts" OFF)

if(DEVELOPER_BUILD)
    add_definitions(-DDEVELOPER_BUILD)
endif(DEVELOPER_BUILD)

find_package(Msgpack REQUIRED)

set(ELLIPTICS_CLIENT_SRCS
    async_result.cpp
    node.cpp
    callback_p.h
    callback.cpp
    functional_p.h
    session.cpp
    session_file.cpp
    result_entry.cpp
    exception.cpp
    key.cpp
    logger.cpp
    newapi/session.cpp
    newapi/result_entry.cpp
    newapi/bulk_remove_handler.cpp
    ../../library/protocol.cpp
    ../../library/compat.c
    ../../library/crypto.c
    ../../library/crypto/sha512.c
    ../../library/dnet_common.c
    ../../library/net.c
    ../../library/net.cpp
    ../../library/node.c
    ../../library/notify_common.c
    ../../library/pool.c
    ../../library/request_queue.cpp
    ../../library/rbtree.c
    ../../library/trans.c
    ../../library/tests.c
    ../../library/common.cpp
    ../../library/access_context.cpp
# Added includes for better IDE's experience
    ../../include/elliptics/interface.h
    ../../include/elliptics/utils.hpp
    ../../include/elliptics/cppdef.h
    ../../include/elliptics/backends.h
    ../../include/elliptics/session.hpp
    ../../include/elliptics/result_entry.hpp
    ../../include/elliptics/core.h
    ../../include/elliptics/debug.hpp
    ../../include/elliptics/error.hpp
    ../../include/elliptics/async_result.hpp
    ../../include/elliptics/packet.h
    )
add_library(elliptics_client SHARED ${ELLIPTICS_CLIENT_SRCS})
set_target_properties(elliptics_client PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    LINKER_LANGUAGE CXX
    )
target_link_libraries(elliptics_client
                      ${BLACKHOLE_LIBRARIES}
                      ${CMAKE_THREAD_LIBS_INIT}
                      ${MSGPACK_LIBRARIES}
                      ${Boost_THREAD_LIBRARY}
                      ${Boost_SYSTEM_LIBRARY}
                      ${Boost_FILESYSTEM_LIBRARY}
                      ${Boost_IOSTREAMS_LIBRARY})
if (WITH_STATS)
    target_link_libraries(elliptics_client ${HANDYSTATS_LIBRARY})
endif()

install(TARGETS elliptics_client
    EXPORT EllipticsTargets
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
