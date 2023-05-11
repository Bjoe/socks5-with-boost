
add_executable(bs5)

target_sources(bs5
    PRIVATE
    main.cpp
    options.hpp
    server.cpp
    server.hpp
    session.cpp
    session.hpp

    sockmap/tbpf.h
    sockmap/tbpf.c
    sockmap/sockmap-ebpf.c

    iosubmit.h
)
target_link_libraries(
  bs5
  PUBLIC project_options project_warnings

  Boost::headers
  Boost::program_options
  Boost::log
  Microsoft.GSL::GSL
#  PRIVATE CLI11::CLI11 fmt::fmt spdlog::spdlog
)

target_include_directories(bs5 PRIVATE "${CMAKE_BINARY_DIR}/configured_files/include")
