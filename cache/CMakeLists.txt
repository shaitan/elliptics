ADD_LIBRARY(elliptics_cache STATIC
            treap.hpp
            slru_cache.cpp
            cache.cpp
            local_session.cpp)

if(UNIX OR MINGW)
    set_target_properties(elliptics_cache PROPERTIES COMPILE_FLAGS "-fPIC")
endif()
