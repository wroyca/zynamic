file(GLOB_RECURSE Zynamic RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.hpp)

add_executable(Zynamic
  ${Zynamic}
)

set_property(TARGET Zynamic 
PROPERTY 
  VS_DPI_AWARE "PerMonitor"
)

target_include_directories(Zynamic
PRIVATE
  .
)

target_link_options(Zynamic
PRIVATE
  /DYNAMICBASE:NO /NXCOMPAT:NO /SAFESEH:NO /INCREMENTAL:NO /LARGEADDRESSAWARE /LAST:.text
)

target_create_vcxproj_filters(Zynamic)
