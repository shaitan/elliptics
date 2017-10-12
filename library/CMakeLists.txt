set(ELLIPTICS_SRCS
    dnet.c
    notify.c
    server.c
    route.cpp
    ../example/config.hpp
    ../example/config.cpp
    )

add_library(elliptics_ids STATIC ids.cpp)
if(UNIX OR MINGW)
    set_target_properties(elliptics_ids PROPERTIES COMPILE_FLAGS "-fPIC")
endif()

add_library(elliptics SHARED ${ELLIPTICS_SRCS})
set_target_properties(elliptics PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    LINKER_LANGUAGE CXX
    )
target_link_libraries(elliptics
    ${ELLIPTICS_LIBRARIES}
    ${EBLOB_LIBRARIES}
    elliptics_common
    elliptics_backends
    elliptics_cache
    elliptics_ids
    elliptics_monitor
    elliptics_client
    kora-util
    )

install(TARGETS elliptics
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
