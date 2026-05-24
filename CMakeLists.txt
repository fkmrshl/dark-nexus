cmake_minimum_required(VERSION 3.15)
project(dark_nexus VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -fno-common -fno-plt -pipe -Wall -Wextra -pthread")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -Wl,-O1,--sort-common,--as-needed -Wl,-z,relro,-z,now,-z,noexecstack")

include_directories(include)

include(FetchContent)

FetchContent_Declare(
  c-ares
  GIT_REPOSITORY https://github.com/c-ares/c-ares.git
  GIT_TAG        cares-1_28_1
)
set(CARES_STATIC ON CACHE BOOL "" FORCE)
set(CARES_SHARED OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(c-ares)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

FetchContent_Declare(
  curl
  GIT_REPOSITORY https://github.com/curl/curl.git
  GIT_TAG        curl-8_7_1
)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(CURL_STATICLIB ON CACHE BOOL "" FORCE)
set(HTTP_ONLY ON CACHE BOOL "" FORCE)
set(CURL_USE_OPENSSL ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(curl)

find_package(PkgConfig REQUIRED)
pkg_check_modules(URING REQUIRED liburing)

find_library(LIBCAP_LIB cap)
if(NOT LIBCAP_LIB)
    message(FATAL_ERROR "Missing libcap-dev! Please install it using: sudo apt install libcap-dev")
endif()

file(GLOB SOURCES "src/*.cpp")

add_executable(dark_nexus ${SOURCES})

target_compile_definitions(dark_nexus PRIVATE HAVE_OPENSSL)

target_link_libraries(dark_nexus
    PRIVATE
    c-ares::cares_static
    libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
    ${URING_LIBRARIES}
    ${LIBCAP_LIB}
    pthread
)
target_include_directories(dark_nexus PRIVATE ${URING_INCLUDE_DIRS})

# Download wordlist if it does not exist
set(WORDLIST_URL "https://raw.githubusercontent.com/fkmrshl/dark-nexus/main/best-dns-wordlist.txt")
set(WORDLIST_FILE "${CMAKE_SOURCE_DIR}/best-dns-wordlist.txt")

if(NOT EXISTS "${WORDLIST_FILE}")
    message(STATUS "Downloading DNS wordlist...")
    file(DOWNLOAD "${WORDLIST_URL}" "${WORDLIST_FILE}"
         STATUS download_status)
    list(GET download_status 0 status_code)
    if(NOT status_code EQUAL 0)
        message(WARNING "Failed to download best-dns-wordlist.txt")
    endif()
endif()

add_custom_command(TARGET dark_nexus POST_BUILD
    COMMAND sudo setcap cap_net_raw=eip $<TARGET_FILE:dark_nexus> || true
    COMMENT "Applying cap_net_raw to executable"
)
