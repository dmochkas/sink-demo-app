cmake_minimum_required(VERSION 3.10)
project(sink-demo-app C)

include(config.cmake)

set(CMAKE_VERBOSE_MAKEFILE ON)

set(AHOI_SERIAL_LIB "ahoi-serial-lib::ahoi-serial-lib")
set(SCHC_FULL_SDK_LIB "schc-full-sdk::schc-full-sdk")
set(ZLOG_LIB "zlog::zlog")

find_package(ahoi-serial-lib REQUIRED)
find_package(schc-full-sdk REQUIRED)
find_package(zlog REQUIRED)

add_subdirectory(src)
