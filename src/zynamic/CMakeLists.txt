file(GLOB_RECURSE Zynamic RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.hpp)

add_library(Zynamic STATIC
  ${Zynamic}
)

set_property(TARGET Zynamic 
PROPERTY 
  VS_DPI_AWARE "PerMonitor"
)

target_include_directories(Zynamic
PUBLIC
  "C:/Program Files/Microsoft Visual Studio/2022/Community/DIA SDK/include"
  .
)

target_link_directories(Zynamic
PUBLIC
  "C:/Program Files/Microsoft Visual Studio/2022/Community/DIA SDK/lib"
)

target_link_libraries(Zynamic
PUBLIC
  diaguids
  Zydis
  Boost::boost
)

target_link_options(Zynamic
PRIVATE
  /DYNAMICBASE:NO /NXCOMPAT:NO /SAFESEH:NO /INCREMENTAL:NO /LARGEADDRESSAWARE /LAST:.text
)

target_create_vcxproj_filters(Zynamic)
