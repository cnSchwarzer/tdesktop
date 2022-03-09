# This file is part of Desktop App Toolkit,
# a set of libraries for developing nice desktop applications.
#
# For license and copyright information please follow this link:
# https://github.com/desktop-app/legal/blob/master/LEGAL
 
add_library(lib_secgram SHARED)
add_library(desktop-app::lib_secgram ALIAS lib_secgram)
init_target(lib_secgram)

get_filename_component(src_loc . REALPATH)

nice_target_sources(lib_secgram ${src_loc}
PRIVATE
    secgram/ws.hpp
    secgram/json.hpp
    secgram/secgram.hpp
    secgram/secgram.cpp
    secgram/SecgramCipher.hpp
    secgram/SecgramConfigServer.hpp
    secgram/SecgramConfigServer.cpp
    secgram/SecgramCore.hpp
    secgram/SecgramCore.cpp
    secgram/SecgramData.hpp
) 

set_property(TARGET lib_secgram PROPERTY CXX_STANDARD 20)

set_target_properties(lib_secgram PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

target_include_directories(lib_secgram
PUBLIC
    ${src_loc}
)  
 
target_link_libraries(lib_secgram
PRIVATE 
    desktop-app::external_boringssl
    desktop-app::external_qt
)

if(NOT CMAKE_SYSTEM_NAME MATCHES "Darwin|Windows")
  set_target_properties(lib_secgram PROPERTIES INSTALL_RPATH "$ORIGIN")
endif()