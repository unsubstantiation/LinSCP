# LinSCP - CMake wrapper over the pure-Rust Cargo workspace.
#
#   cmake -S . -B build && cmake --build build
#   ctest --test-dir build --output-on-failure
#
# The primary build is pure-Rust: `cargo build --workspace` and
# `cargo test --workspace`. This file exists as a convenience wrapper so
# that the existing CMake/CTest workflow and the Debian source package's
# `cmake -S . -B build` expectation keep working, and so that CI can
# exercise CTest evidence lines via `cargo test` under the hood.
#
# Previous releases built the C++17 client (source/linux/*.cpp + libssh) here;
# that implementation has been retired - the engine now lives in crates/*
# (linscp-proto, linscp-engine, linscp-platform) and the UI in ui/.

cmake_minimum_required(VERSION 3.25)
project(LinSCP VERSION 1.0 LANGUAGES C CXX)

# The Rust workspace builds cross-platform (Linux, Windows, Android) with
# cargo alone. Keep a platform check for historical expectations, but do not
# block non-Linux hosts that only run `cargo check --target aarch64-linux-android`.
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(STATUS "LinSCP pure-Rust workspace builds on ${CMAKE_SYSTEM_NAME}; C++ Makefile no longer required. Using cargo wrapper.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Thin wrapper: cargo is the real build system.
find_program(CARGO cargo REQUIRED)
find_program(NPM npm)

# Build the Rust workspace (produces target/release/linscp + linscp-gui)
add_custom_target(linscp ALL
  COMMAND ${CARGO} build --release --workspace
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMENT "Building pure-Rust workspace with cargo"
  VERBATIM)

# Unit tests via cargo test (instead of linscp-unittest C++ binary)
enable_testing()
add_test(NAME unit-tests
  COMMAND ${CARGO} test --workspace --all-targets --quiet
)
set_tests_properties(unit-tests PROPERTIES
  LABELS "unit"
)

# The C++ source tree under source/linux/ is retained for regression-suite
# reference and for the historical Make/CMake wrapper, but production code
# now lives in crates/. The former `linscp-frontend` static library,
# `source/linux/tests/UnitTest.cpp`, and `source/linux/main.cpp` are no longer
# built here - they are exercised via `cargo test` and the live Python suites
# against target/release/linscp.

# Preserve CTest suite names for CI evidence parsing: wrap the Python suites
# so that `ctest --output-on-failure` still reports script/live cases.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  add_test(NAME script-tests
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/source/linux/tests/ScriptTest.py ${CMAKE_SOURCE_DIR}/target/release/linscp)
  add_test(NAME live-sftp-tests
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/source/linux/tests/LiveSftpTest.py ${CMAKE_SOURCE_DIR}/target/release/linscp)
  add_test(NAME live-tunnel-tests
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/source/linux/tests/LiveTunnelTest.py ${CMAKE_SOURCE_DIR}/target/release/linscp)
  add_test(NAME live-s3-tests
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/source/linux/tests/LiveS3Test.py ${CMAKE_SOURCE_DIR}/target/release/linscp)
  add_test(NAME live-dav-tests
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/source/linux/tests/LiveDavTest.py ${CMAKE_SOURCE_DIR}/target/release/linscp)
  add_test(NAME live-scp-tests
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/source/linux/tests/LiveScpTest.py ${CMAKE_SOURCE_DIR}/target/release/linscp)
  add_test(NAME live-curl-tests
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/source/linux/tests/LiveCurlTest.py ${CMAKE_SOURCE_DIR}/target/release/linscp)
endif()

if(NPM)
  add_test(NAME client-tests
    COMMAND ${NPM} --prefix ${CMAKE_SOURCE_DIR}/ui run test --if-present)
endif()

# Install the Rust binaries (cargo install layout) plus the shared
# documentation, desktop and automation files that every installer ships.
# TheChecker (tools/check_platform_conversion.py:INSTALLED_FILES) requires
# all three installers (make, cmake, debian) to mention the same set.
install(PROGRAMS ${CMAKE_SOURCE_DIR}/target/release/linscp
  DESTINATION bin)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/target/release/linscp-gui
  DESTINATION bin)
install(FILES ${CMAKE_SOURCE_DIR}/docs/linscp.1 DESTINATION share/man/man1)
install(FILES ${CMAKE_SOURCE_DIR}/debian/linscp.desktop DESTINATION share/applications)
install(FILES ${CMAKE_SOURCE_DIR}/debian/linscp.png DESTINATION share/pixmaps)
install(FILES ${CMAKE_SOURCE_DIR}/debian/linscp.svg DESTINATION share/icons/hicolor/scalable/apps)
install(FILES ${CMAKE_SOURCE_DIR}/automation/LinSCP.psm1 DESTINATION share/linscp/automation)
install(FILES ${CMAKE_SOURCE_DIR}/automation/dotnet/LinSCP/LinSCP.csproj
              ${CMAKE_SOURCE_DIR}/automation/dotnet/LinSCP/Session.cs
              ${CMAKE_SOURCE_DIR}/automation/dotnet/LinSCP/LinSCPCompat.cs
        DESTINATION share/linscp/dotnet)
