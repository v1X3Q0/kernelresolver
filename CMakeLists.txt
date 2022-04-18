project(kernelresolver)

if(NOT DEFINED ANDROID_TOOL_BASE)
    message(FATAL_ERROR "need ANDROID_TOOL_BASE")
endif()

add_library(${PROJECT_NAME} STATIC kernel_resolver.c)

target_include_directories(${PROJECT_NAME} PRIVATE
# need this just for the mac kernel base definition
    ${ANDROID_TOOL_BASE}/xnu/rw_kext/include
# need this for the kernel read write
    ${ANDROID_TOOL_BASE}/common/krw_util/krw_util
# need this for the safe_bail helpers
    ${ANDROID_TOOL_BASE}/common/local_util)
