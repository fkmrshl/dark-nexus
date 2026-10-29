cmake_minimum_required(VERSION 3.15)
project(dark_nexus VERSION 2.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(DARK_NEXUS_BUILD_APP "Build the network toolkit (requires network libraries)" ON)
include(CTest)

if(BUILD_TESTING)
    find_package(Python3 QUIET COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        add_test(NAME installer COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/installer_tests.py)
    endif()
    add_executable(cli_tests src/cli.cpp tests/cli_tests.cpp)
    target_include_directories(cli_tests PRIVATE include)
    target_compile_options(cli_tests PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME cli_parser COMMAND cli_tests)
    add_executable(thread_pool_tests tests/thread_pool_tests.cpp)
    target_include_directories(thread_pool_tests PRIVATE include)
    target_link_libraries(thread_pool_tests PRIVATE pthread)
    add_test(NAME thread_pool COMMAND thread_pool_tests)
    add_executable(process_tests src/process.cpp tests/process_tests.cpp)
    target_include_directories(process_tests PRIVATE include)
    target_compile_options(process_tests PRIVATE -Wall -Wextra -Wpedantic)
    target_link_libraries(process_tests PRIVATE pthread)
    add_test(NAME process_supervisor COMMAND process_tests)
    add_executable(terminal_tests src/terminal.cpp tests/terminal_tests.cpp)
    target_include_directories(terminal_tests PRIVATE include)
    target_compile_options(terminal_tests PRIVATE -UNDEBUG)
    target_link_libraries(terminal_tests PRIVATE pthread)
    add_test(NAME terminal_output COMMAND terminal_tests)
endif()

if(NOT DARK_NEXUS_BUILD_APP)
    return()
endif()

include(FetchContent)
FetchContent_Declare(c-ares
    GIT_REPOSITORY https://github.com/c-ares/c-ares.git
    GIT_TAG cares-1_28_1
    GIT_SHALLOW TRUE)
set(CARES_STATIC ON CACHE BOOL "" FORCE)
set(CARES_STATIC_PIC ON CACHE BOOL "" FORCE)
set(CARES_SHARED OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(c-ares)

# System packages work on distributions that do not ship static OpenSSL archives.
find_package(OpenSSL REQUIRED)
find_package(CURL QUIET)
if(CURL_FOUND)
    set(DARK_NEXUS_CURL CURL::libcurl)
else()
    FetchContent_Declare(curl
        GIT_REPOSITORY https://github.com/curl/curl.git
        GIT_TAG curl-8_7_1
        GIT_SHALLOW TRUE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
    set(HTTP_ONLY ON CACHE BOOL "" FORCE)
    set(CURL_USE_OPENSSL ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(curl)
    set(DARK_NEXUS_CURL libcurl)
endif()
find_package(nlohmann_json 3.11.3 QUIET)
if(NOT nlohmann_json_FOUND)
    FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
    FetchContent_MakeAvailable(json)
endif()
find_package(PkgConfig REQUIRED)
pkg_check_modules(URING REQUIRED IMPORTED_TARGET liburing)
find_library(LIBCAP_LIB cap)
if(NOT LIBCAP_LIB)
    message(FATAL_ERROR "Missing libcap development package (libcap-dev / libcap-devel).")
endif()

file(GLOB SOURCES CONFIGURE_DEPENDS "src/*.cpp")
add_executable(dark_nexus ${SOURCES})
target_include_directories(dark_nexus PRIVATE include)
target_compile_definitions(dark_nexus PRIVATE HAVE_OPENSSL)
target_compile_options(dark_nexus PRIVATE
    -O2 -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2
    -Wformat -Wformat-security -fno-common -fno-plt -pipe -Wall -Wextra -pthread)
target_link_options(dark_nexus PRIVATE -pie -Wl,-O1,--sort-common,--as-needed -Wl,-z,relro,-z,now,-z,noexecstack)
target_link_libraries(dark_nexus PRIVATE c-ares::cares_static ${DARK_NEXUS_CURL}
    OpenSSL::SSL OpenSSL::Crypto PkgConfig::URING ${LIBCAP_LIB} pthread nlohmann_json::nlohmann_json)

if(BUILD_TESTING)
    add_executable(dns_query_tests src/dns_query.cpp tests/dns_query_tests.cpp)
    target_include_directories(dns_query_tests PRIVATE include)
    target_compile_options(dns_query_tests PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME dns_reply_parser COMMAND dns_query_tests)
    add_executable(dns_engine_tests tests/dns_engine_tests.cpp src/terminal.cpp)
    target_include_directories(dns_engine_tests PRIVATE include)
    target_compile_options(dns_engine_tests PRIVATE -Wall -Wextra -Wpedantic)
    target_link_libraries(dns_engine_tests PRIVATE c-ares::cares_static ${DARK_NEXUS_CURL}
        PkgConfig::URING pthread nlohmann_json::nlohmann_json)
    add_test(NAME dns_engine COMMAND dns_engine_tests)
    set_tests_properties(dns_engine PROPERTIES TIMEOUT 30)
    add_executable(subdomain_sources_tests tests/subdomain_sources_tests.cpp src/subdomain_generate.cpp
        src/subdomain_passive.cpp src/environment.cpp src/dns_query.cpp src/globals.cpp)
    target_include_directories(subdomain_sources_tests PRIVATE include src)
    target_compile_options(subdomain_sources_tests PRIVATE -Wall -Wextra -Wpedantic)
    target_link_libraries(subdomain_sources_tests PRIVATE c-ares::cares_static ${DARK_NEXUS_CURL}
        nlohmann_json::nlohmann_json pthread)
    add_test(NAME subdomain_sources COMMAND subdomain_sources_tests)
    add_executable(doctor_tests src/environment.cpp src/doctor.cpp src/terminal.cpp tests/doctor_tests.cpp)
    target_include_directories(doctor_tests PRIVATE include)
    target_compile_options(doctor_tests PRIVATE -Wall -Wextra -Wpedantic)
    target_link_libraries(doctor_tests PRIVATE ${LIBCAP_LIB} nlohmann_json::nlohmann_json pthread)
    add_test(NAME doctor_environment COMMAND doctor_tests)
    add_executable(traceroute_packet_tests tests/traceroute_packet_tests.cpp)
    target_include_directories(traceroute_packet_tests PRIVATE include)
    target_compile_options(traceroute_packet_tests PRIVATE -UNDEBUG -ffunction-sections -fdata-sections)
    target_link_options(traceroute_packet_tests PRIVATE -Wl,--gc-sections)
    target_link_libraries(traceroute_packet_tests PRIVATE c-ares::cares_static pthread)
    add_test(NAME traceroute_packets COMMAND traceroute_packet_tests)
    add_executable(port_flags_tests src/port_scan.cpp src/terminal.cpp tests/port_flags_tests.cpp)
    target_include_directories(port_flags_tests PRIVATE include)
    target_link_libraries(port_flags_tests PRIVATE c-ares::cares_static pthread)
    add_test(NAME port_flag_behavior COMMAND port_flags_tests)
    add_executable(output_tests src/output.cpp src/terminal.cpp tests/output_tests.cpp)
    target_include_directories(output_tests PRIVATE include)
    target_link_libraries(output_tests PRIVATE c-ares::cares_static nlohmann_json::nlohmann_json)
    add_test(NAME report_output COMMAND output_tests)
    if(Python3_Interpreter_FOUND)
        add_executable(subdomain_http_fixture tests/subdomain_http_fixture.cpp src/subdomain_http.cpp src/globals.cpp)
        target_include_directories(subdomain_http_fixture PRIVATE include src)
        target_compile_options(subdomain_http_fixture PRIVATE -Wall -Wextra -Wpedantic)
        target_link_libraries(subdomain_http_fixture PRIVATE c-ares::cares_static
            ${DARK_NEXUS_CURL} nlohmann_json::nlohmann_json pthread)
        add_test(NAME subdomain_http COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/subdomain_http_tests.py $<TARGET_FILE:subdomain_http_fixture>)
        set_tests_properties(subdomain_http PROPERTIES TIMEOUT 30)
        add_executable(subdomain_integration_fixture src/subdomain.cpp src/subdomain_generate.cpp
            src/environment.cpp src/dns_query.cpp src/output.cpp src/terminal.cpp src/globals.cpp
            tests/subdomain_integration.cpp)
        target_include_directories(subdomain_integration_fixture PRIVATE include src)
        target_compile_options(subdomain_integration_fixture PRIVATE -Wall -Wextra -Wpedantic)
        target_link_libraries(subdomain_integration_fixture PRIVATE c-ares::cares_static
            ${DARK_NEXUS_CURL} ${LIBCAP_LIB} nlohmann_json::nlohmann_json pthread)
        add_test(NAME subdomain_pipeline COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/subdomain_integration.py $<TARGET_FILE:subdomain_integration_fixture>)
        set_tests_properties(subdomain_pipeline PROPERTIES TIMEOUT 120)
        add_test(NAME cli_integration COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_integration.py $<TARGET_FILE:dark_nexus>)
        add_test(NAME doctor_integration COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/doctor_integration.py $<TARGET_FILE:dark_nexus>)
        add_test(NAME dns_whois_integration COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/dns_whois_integration.py $<TARGET_FILE:dark_nexus>)
        add_test(NAME subdomain_cli_integration COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/subdomain_cli_integration.py $<TARGET_FILE:dark_nexus>)
        set_tests_properties(subdomain_cli_integration PROPERTIES TIMEOUT 120)
    endif()
endif()
