# Convenience wrapper for the native Tauri desktop application.
cmake_minimum_required(VERSION 3.25)
project(LinSCP VERSION 1.0 LANGUAGES NONE)
find_program(CARGO cargo REQUIRED)
find_program(NPM npm REQUIRED)
add_custom_target(linscp ALL
  COMMAND ${NPM} --prefix ui ci --no-audit --no-fund
  COMMAND ${NPM} --prefix ui run build
  COMMAND ${CARGO} build --release -p linscp-tauri --features native-shell
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  VERBATIM)
enable_testing()
add_test(NAME rust-tests COMMAND ${CARGO} test --workspace --all-targets)
set_tests_properties(rust-tests PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME ui-tests COMMAND ${NPM} --prefix ui test)
set_tests_properties(ui-tests PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
install(PROGRAMS ${CMAKE_SOURCE_DIR}/target/release/linscp-gui DESTINATION bin)
install(FILES ${CMAKE_SOURCE_DIR}/debian/linscp.desktop DESTINATION share/applications)
install(FILES ${CMAKE_SOURCE_DIR}/debian/linscp.png DESTINATION share/pixmaps)
install(FILES ${CMAKE_SOURCE_DIR}/debian/linscp.svg DESTINATION share/icons/hicolor/scalable/apps)
