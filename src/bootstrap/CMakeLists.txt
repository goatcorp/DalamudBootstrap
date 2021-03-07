set(CMAKE_CXX_STANDARD 20)

file(GLOB BOOTSTRAP_HEADER_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*")
file(GLOB BOOTSTRAP_SOURCE_FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/*.c*")

add_executable(DalamudBootstrap ${BOOTSTRAP_HEADER_FILES} ${BOOTSTRAP_SOURCE_FILES})

target_link_libraries(DalamudBootstrap fmt spdlog)