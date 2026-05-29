cmake_minimum_required(VERSION 3.10)
project(WireDownLinux)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CORE_SOURCES
    ../../core/src/Engine.cpp
)

set(LINUX_SOURCES
    LinuxSystem.cpp
    LinuxTransport.cpp
    LinuxNetwork.cpp
    main.cpp
)

add_executable(wiredown-linux ${CORE_SOURCES} ${LINUX_SOURCES})
target_link_libraries(wiredown-linux pthread)
