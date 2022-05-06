file(GLOB_RECURSE Zynamic RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp)

add_library(Zynamic STATIC
  ${Zynamic}
)

target_include_directories(Zynamic
PUBLIC .
  "C:/Program Files/Microsoft Visual Studio/2022/Community/DIA SDK/include"
)

target_link_directories(Zynamic
PUBLIC
  "C:/Program Files/Microsoft Visual Studio/2022/Community/DIA SDK/lib"
)

target_link_libraries(Zynamic
PUBLIC
  diaguids
  Zydis
)

target_create_vcxproj_filters(Zynamic)
