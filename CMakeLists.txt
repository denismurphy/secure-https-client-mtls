cmake_minimum_required(VERSION 3.29)

project(secure-https-client-mtls C)

set(CMAKE_C_STANDARD 23)

find_package(MbedTLS REQUIRED)

add_executable(secure-https-client-mtls main.c
        main.h
        certs.h
        certs.c)

# Link mbedTLS libraries
target_link_libraries(${PROJECT_NAME} PRIVATE MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)

# Include mbedTLS headers
target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_INCLUDE_DIRS})