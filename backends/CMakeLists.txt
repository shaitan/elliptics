add_library(elliptics_backends STATIC
            backends.c
            backend.cpp
            eblob_backend.c
            eblob_backend.cpp)

if(UNIX OR MINGW)
    set_target_properties(elliptics_backends PROPERTIES COMPILE_FLAGS "-fPIC")
endif()

target_link_libraries(elliptics_backends elliptics_client)
