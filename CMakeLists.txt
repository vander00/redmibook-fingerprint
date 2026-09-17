cmake_minimum_required(VERSION 3.13)

option(FINGERPRINT_OCV_USE_VCPKG "Use the bundled vcpkg toolchain" ON)

if(FINGERPRINT_OCV_USE_VCPKG)
    set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake)
    set(LIBEVENT_FIND_PACKAGE ON)
endif()

project(fingerprint-ocv)

include(CTest)

find_package(PkgConfig REQUIRED)

set(JINX_NO_TESTS ON)
set(JINX_NO_INSTALL ON)
set(JINX_NO_EXAMPLES ON)
set(JINX_BUILD_DBUS ON)
set(JINX_BUILD_USB ON)
set(JINX_BUILD_OPENSSL ON)

# The pinned Jinx revision contains an unused template member that modern GCC
# diagnoses eagerly in every translation unit that includes its headers.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fpermissive>)
endif()

add_subdirectory(jinx)
add_subdirectory(asyncusb)
add_subdirectory(asyncdbus)
add_subdirectory(src)
