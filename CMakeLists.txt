cmake_minimum_required(VERSION 3.14)
project(DarkNexus)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include_directories(${PROJECT_SOURCE_DIR}/include)

add_executable(dark_nexus
    src/main.cpp
    src/threadpool.cpp
    src/logger.cpp
    src/utils.cpp
    src/network.cpp
    src/scanner.cpp
    src/intel.cpp
    src/osint.cpp
    src/traceroute.cpp
    src/subdomain.cpp
)

target_link_libraries(dark_nexus pthread)
