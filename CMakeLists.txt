cmake_minimum_required(VERSION 3.20)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    if(DEFINED ENV{VITASDK})
        set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
    else()
        message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
    endif()
endif()

project(SnoopItUp)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3 -std=gnu99")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fno-rtti -fno-exceptions")

add_executable(snoopitup
    main.c
)

target_link_libraries(snoopitup
    taihen_stub
    SceLibKernel_stub
    SceSysmodule_stub
    SceIofilemgr_stub
    SceRtcForDriver_stub
)

set_target_properties(snoopitup
    PROPERTIES LINK_FLAGS "-nostdlib"
)

vita_create_self(snoopitup.suprx snoopitup
    CONFIG ${CMAKE_SOURCE_DIR}/config.yml
)
