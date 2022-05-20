set(sources
  Zynamic.cpp
)
set(headers
  ${PROJECT_SOURCE_DIR}/include/Zynamic/Zynamic
)

# Map extensionless files to Microsoft Visual C++
set_source_files_properties(${headers}
PROPERTIES
  CXX HEADER_FILE_ONLY
)

add_library(Zynamic
  ${sources}
  ${headers}
)

target_include_directories(Zynamic
PUBLIC
  $<INSTALL_INTERFACE:include>
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>

PRIVATE
  "${VS}/DIA SDK/include"
)

target_link_directories(Zynamic
PRIVATE
  "${VS}/DIA SDK/lib"
)

target_link_libraries(Zynamic
PUBLIC
  diaguids
  Zydis
)

target_compile_features(Zynamic
PRIVATE
  cxx_std_17
)

target_compile_options(Zynamic
PRIVATE
  /MP
  /Zi
)

target_compile_definitions(Zynamic
PRIVATE
  -DBIN=L"${ZYNAMIC_BIN}"s
  -DDST=L"${CMAKE_PROJECT_NAME}"s
  -DDIA=L"${VS}/DIA SDK/bin/msdia140.dll"
)

