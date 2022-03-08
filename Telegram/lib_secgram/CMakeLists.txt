# This file is part of Desktop App Toolkit,
# a set of libraries for developing nice desktop applications.
#
# For license and copyright information please follow this link:
# https://github.com/desktop-app/legal/blob/master/LEGAL

add_library(lib_secgram OBJECT)
add_library(desktop-app::lib_secgram ALIAS lib_secgram)
init_target(lib_secgram)

get_filename_component(src_loc . REALPATH)

nice_target_sources(lib_secgram ${src_loc}
PRIVATE
    secgram/ws.hpp
    secgram/json.hpp
    secgram/SecgramCipher.hpp
    secgram/SecgramConfigServer.hpp
    secgram/SecgramConfigServer.cpp
    secgram/SecgramCore.hpp
    secgram/SecgramCore.cpp
    secgram/SecgramData.hpp
)

target_include_directories(lib_secgram
PUBLIC
    ${src_loc}
) 