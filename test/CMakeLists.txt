cmake_minimum_required(VERSION 3.15...3.23)

find_package(doctest REQUIRED)

add_executable(test_main test_main.cpp)
target_link_libraries(test_main PUBLIC doctest::doctest)
target_link_libraries(test_main PRIVATE myproject::project_options)
