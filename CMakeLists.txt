# Linux build of LinSCP with CMake.
#
#   cmake -S . -B build && cmake --build build
#   ctest --test-dir build --output-on-failure
#
# The supported build - the one the Debian package uses - is the plain
# Makefile, `make -C source/linux`, which produces the same binary; this
# file exists so that the CMake/CTest workflow is available as well.
#
# SSH, SFTP and SCP are served by libssh: the transport, authentication
# and host key policy live in source/linux/Session.cpp, and the SFTP v3
# protocol itself (including the copy-data and check-file-name
# extensions) is spoken by source/linux/SftpClient.cpp over a libssh
# subsystem channel. Every other protocol goes through the curl backend
# in source/linux/ProtocolClient.cpp.

# 3.25 is Debian 13 (trixie), the oldest release this project supports.
cmake_minimum_required(VERSION 3.25)
project(LinSCP VERSION 1.0 LANGUAGES C CXX)

# The platform layer uses Linux-only services (inotify, /proc/self/exe,
# SO_PEERCRED) and the packaged launcher assumes Linux desktop conventions.
# Do not let another POSIX host accidentally produce an untested build.
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "LinSCP supports Linux only (found ${CMAKE_SYSTEM_NAME})")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(FRONTEND source/linux)

set(FRONTEND_SOURCES
  ${FRONTEND}/Session.cpp
  ${FRONTEND}/SessionStore.cpp
  ${FRONTEND}/ListingParse.cpp
  ${FRONTEND}/FtpClient.cpp
  ${FRONTEND}/ScpClient.cpp
  ${FRONTEND}/TransferPresets.cpp
  ${FRONTEND}/SyncPlanner.cpp
  ${FRONTEND}/Editor.cpp
  ${FRONTEND}/ProtocolClient.cpp
  ${FRONTEND}/S3SigV4.cpp
  ${FRONTEND}/S3Client.cpp
  ${FRONTEND}/SshTunnel.cpp
  ${FRONTEND}/Script.cpp
  ${FRONTEND}/ScriptParams.cpp
  ${FRONTEND}/Console.cpp
  ${FRONTEND}/LocalFs.cpp
  ${FRONTEND}/PathUtil.cpp
  ${FRONTEND}/Platform.cpp
  ${FRONTEND}/Texts.cpp
  ${FRONTEND}/TextMode.cpp
  ${FRONTEND}/SshKeys.cpp
  ${FRONTEND}/PpkKey.cpp
  ${FRONTEND}/SftpClient.cpp
  ${FRONTEND}/HashUtil.c
)

add_library(linscp-frontend STATIC ${FRONTEND_SOURCES})
target_include_directories(linscp-frontend PUBLIC ${FRONTEND})

add_executable(linscp ${FRONTEND}/main.cpp)
target_link_libraries(linscp PRIVATE linscp-frontend)

enable_testing()
add_executable(linscp-unittest ${FRONTEND}/tests/UnitTest.cpp)
target_link_libraries(linscp-unittest PRIVATE linscp-frontend)
add_test(NAME unit-tests COMMAND linscp-unittest)

# Server-free script regressions and the offline upstream gap inventory.
# Python is optional for a C++-only build; CI always provides it.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  add_test(NAME script-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/${FRONTEND}/tests/ScriptTest.py
    $<TARGET_FILE:linscp>)
  # Individual cases skip themselves where their dependency is
  # missing, but a suite that skips every case has checked
  # nothing, which is the failure mode this repository guards
  # against (see the ran=0 properties below and the Makefile
  # workflow's greps).
  add_test(NAME live-sftp-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/${FRONTEND}/tests/LiveSftpTest.py
    $<TARGET_FILE:linscp>)
  # Starts the throwaway S3 endpoint in tests/ over TLS; standard-library
  # only, with botocore an optional extra one test skips without.
  # The SCP engine talks to a throwaway sshd it starts itself; the suite
  # skips loudly where sshd, ssh-keygen or the server's scp binary is absent.
  add_test(NAME live-scp-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/${FRONTEND}/tests/LiveScpTest.py
    $<TARGET_FILE:linscp>)
  add_test(NAME live-s3-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/${FRONTEND}/tests/LiveS3Test.py
    $<TARGET_FILE:linscp>)
  # The WebDAV endpoint is standard-library-only and the client speaks
  # plain HTTP, so this suite needs nothing but curl.
  add_test(NAME live-dav-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/${FRONTEND}/tests/LiveDavTest.py
    $<TARGET_FILE:linscp>)
  # FTP/FTPS use optional pyftpdlib and pyOpenSSL; the suite reports those
  # dependency limits as skips.
  add_test(NAME live-curl-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/${FRONTEND}/tests/LiveCurlTest.py
    $<TARGET_FILE:linscp>)
  # A live suite that ran no case prints 'ran=0' in its evidence
  # line, and ctest fails the test on that pattern: a suite that
  # quietly did less is the failure mode this repository guards
  # against, and the Makefile workflow's grep enforces the same
  # contract. The timeout bounds a suite whose throwaway server
  # hangs, which would otherwise eat the default 1500 seconds.
  set_tests_properties(live-sftp-tests live-scp-tests live-s3-tests
    live-dav-tests live-curl-tests PROPERTIES
    FAIL_REGULAR_EXPRESSION "ran=0 "
    TIMEOUT 600)
  add_test(NAME gui-search-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/source/gui/tests/RemoteSearchTest.py)
  add_test(NAME gui-local-editor-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/source/gui/tests/LocalEditorTest.py)
  add_test(NAME gui-browser-upload-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/source/gui/tests/BrowserUploadTest.py)
  add_test(NAME gui-desktop-uri-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/source/gui/tests/DesktopUriTest.py)
  add_test(NAME gui-security-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/source/gui/tests/SecurityTest.py)
  add_test(NAME gui-terminal-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/source/gui/tests/TerminalTest.py)
  # The PowerShell module harness: static checks always run, while the
  # live Pester cases skip themselves without pwsh (the suite still
  # reports ran>0, so no ran=0 guard is needed here).
  add_test(NAME powershell-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/automation/test_psmodule.py
    $<TARGET_FILE:linscp>)
  add_test(NAME translation-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/test_translations.py)
  add_test(NAME parity-checker-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/test_parity_inventory.py)
  add_test(NAME parity-inventory COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/check_upstream_parity.py)
  # The guard that keeps this a Linux-only client: it reads the sources
  # and refuses a Windows construct, a file of another platform, an
  # installer that disagrees with the others, and an error message that
  # contradicts the template it is filled into.
  add_test(NAME platform-conversion-check COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/check_platform_conversion.py)
  add_test(NAME platform-conversion-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/test_platform_conversion.py)
  # The other half of 'this is a Linux client': a Wayland desktop, where an
  # application that only asks for $DISPLAY finds no display at all. It
  # refuses a display-server decision that reads one variable, a terminal that
  # may not draw on this compositor, a helper only one display server answers,
  # a desktop entry a compositor cannot act on, and the console and graphical
  # clients disagreeing about what a session is.
  add_test(NAME wayland-compatibility-check COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/check_wayland_compatibility.py)
  add_test(NAME wayland-compatibility-tests COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/test_wayland_compatibility.py)
endif()

# Browser workflow tests are available when the optional node/jsdom test
# dependency is installed. The client itself still needs neither at runtime.
find_program(NODE_EXECUTABLE node)
if(NODE_EXECUTABLE)
  execute_process(COMMAND ${NODE_EXECUTABLE} -e "require.resolve('jsdom')"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    RESULT_VARIABLE JSDOM_RESULT OUTPUT_QUIET ERROR_QUIET)
  if(JSDOM_RESULT EQUAL 0)
    add_test(NAME gui-client-tests COMMAND ${NODE_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/source/gui/tests/ClientTest.js)
    add_test(NAME gui-localization-tests COMMAND ${NODE_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/source/gui/tests/LocalizationTest.js)
  else()
    message(STATUS "Browser tests not registered: install jsdom@29 to run them")
  endif()
endif()

# ---- libssh + OpenSSL (SSH/SFTP/SCP transport and hashes) ---------------
find_package(ZLIB REQUIRED)
find_package(libssh REQUIRED)
find_package(OpenSSL REQUIRED)
find_path(ARGON2_INCLUDE_DIR argon2.h REQUIRED)
find_library(ARGON2_LIBRARY NAMES argon2 REQUIRED)
target_include_directories(linscp-frontend PRIVATE ${ARGON2_INCLUDE_DIR})
target_link_libraries(linscp-frontend PUBLIC ssh OpenSSL::Crypto ${ARGON2_LIBRARY})

# GSSAPI stays compiled out, as in the Makefile build: libssh may have
# it, but this client's settings refuse it by name (see SshTunnel.cpp).
target_compile_definitions(linscp-frontend PRIVATE NO_GSSAPI)
target_compile_options(linscp-frontend PRIVATE -Wall)

# ---- install -------------------------------------------------------------
# The same layout the Debian package and 'make -C source/linux install'
# produce: the console client and the GUI launcher in bin/, the GUI's
# Python modules, command templates and web client under share/linscp/gui/,
# the PowerShell module under share/linscp/automation/, the manual page,
# the desktop entry and the icons. Nothing else is installed: this client
# has no library, no header and no other platform's surface.
install(TARGETS linscp RUNTIME DESTINATION bin)
install(PROGRAMS source/gui/linscp-gui DESTINATION bin)
install(FILES docs/linscp.1 DESTINATION share/man/man1)
install(FILES debian/linscp.desktop DESTINATION share/applications)
install(FILES debian/linscp.png DESTINATION share/pixmaps)
install(FILES debian/linscp.svg DESTINATION share/icons/hicolor/scalable/apps)
install(FILES source/gui/linscp_gui.py source/gui/linscp_crypto.py
  DESTINATION share/linscp/gui
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
# The command templates the graphical client starts with: without this
# file an installed client offers an empty list, where a run from the
# source tree offers the shipped ones.
install(FILES source/gui/explorer-commands.json DESTINATION share/linscp/gui)
install(DIRECTORY source/gui/web/ DESTINATION share/linscp/gui/web)
install(FILES automation/LinSCP.psm1 DESTINATION share/linscp/automation)
