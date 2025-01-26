cmake_minimum_required(VERSION 3.10.0)
project(kernelresolver)

if(NOT DEFINED ANDROID_TOOL_BASE)
    message("no ANDROID_TOOL_BASE, setting to working directory")
    set(ANDROID_TOOL_BASE ${CMAKE_CURRENT_SOURCE_DIR})
    set(CMAKE_CXX_STANDARD 17)

    if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        set(MY_HOST_COMPILER xnu)
        if (CMAKE_OSX_ARCHITECTURES STREQUAL "")
            set(CMAKE_OSX_ARCHITECTURES "arm64")
        endif()
        set(ARCH ${CMAKE_OSX_ARCHITECTURES})
        # set(CMAKE_XCODE_BUILD_SYSTEM 13)
        add_definitions(-DARM64_BOARD_CONFIG_T8101=1 -DXNU_KERNEL_PRIVATE -D__DARWIN_UNIX03=1)
        add_definitions(-D__ARM_16K_PG__)
        set(RW_DRIVER rw_kext)
    else()
        message( FATAL_ERROR "need to be compiling from a valid host, can't be ${CMAKE_SYSTEM_NAME}" )
    endif()
endif()

add_library(${PROJECT_NAME} STATIC kernel_resolver.c)

target_include_directories(${PROJECT_NAME} PRIVATE
# need this just for the mac kernel base definition
    ${ANDROID_TOOL_BASE}/xnu/rw_kext/include
# need this for the kernel read write
    ${ANDROID_TOOL_BASE}/common/krw_util/krw_util
# need this for the safe_bail helpers
    ${ANDROID_TOOL_BASE}/common/local_util)
