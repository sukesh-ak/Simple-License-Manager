cmake_minimum_required(VERSION 3.12)
project(licensemanager)

# Add the path to vcpkg toolchain file
set(CMAKE_TOOLCHAIN_FILE "./vcpkg/scripts/buildsystems/vcpkg.cmake")

# Find required package
find_package(OpenSSL REQUIRED)

# Add your source files here
set(SOURCE_FILES src/main.cpp)

# Create the executable
add_executable(licensemanager ${SOURCE_FILES})

# Link against the required library
target_link_libraries(licensemanager PRIVATE OpenSSL::Crypto)
