cmake_minimum_required(VERSION 3.16)
project(desupatch LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(desupatch WIN32
    src/main.cpp
    src/common.cpp
    src/certs.cpp
    src/hosts.cpp
    src/proxy.cpp
    src/connector.cpp
)

target_compile_definitions(desupatch PRIVATE
    UNICODE
    _UNICODE
    _WIN32_WINNT=0x0A00
)

if(MSVC)
    target_compile_options(desupatch PRIVATE /utf-8 /W3 /permissive-)
    target_link_options(desupatch PRIVATE
        "/MANIFEST:EMBED"
        "/MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/app.manifest"
        "/MANIFESTUAC:NO"
    )
endif()

target_link_libraries(desupatch PRIVATE
    ws2_32
    crypt32
    ncrypt
    secur32
    winhttp
    dnsapi
    iphlpapi
    comctl32
    shell32
    advapi32
    user32
    gdi32
    shlwapi
    ole32
)
