
add_executable(intro main.cpp)
target_link_libraries(
  intro
  PUBLIC project_options project_warnings
#  PRIVATE CLI11::CLI11 fmt::fmt spdlog::spdlog
)

target_include_directories(intro PRIVATE "${CMAKE_BINARY_DIR}/configured_files/include")
