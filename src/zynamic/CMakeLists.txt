file(GLOB_RECURSE Zynamic RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.hpp)

add_library(Zynamic STATIC
  ${Zynamic}
)

target_include_directories(Zynamic
PUBLIC
  $<INSTALL_INTERFACE:include>
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
PRIVATE
  "${VS}/DIA SDK/include"
)

target_link_directories(Zynamic
PUBLIC
  "${VS}/DIA SDK/lib"
)

target_link_libraries(Zynamic
PUBLIC
  diaguids
  Zydis
)

target_compile_definitions(Zynamic
PRIVATE
  -DBIN=L"${ZYNAMIC_BIN}"s
  -DDST=L"${CMAKE_PROJECT_NAME}"s
  -DDIA=L"${VS}/DIA SDK/bin/msdia140.dll"
)

install(TARGETS Zynamic EXPORT Zynamic-targets LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(DIRECTORY "${PROJECT_SOURCE_DIR}/include/" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
