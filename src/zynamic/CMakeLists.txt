file(GLOB_RECURSE Zynamic RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp)

add_library(Zynamic STATIC
  ${Zynamic}
)

target_include_directories(Zynamic
PRIVATE
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

target_compile_definitions(Zynamic
PRIVATE
  -DAPP=\"${ZYNAMIC_APP}\"
  -DSRC=L"${ZYNAMIC_SRC}"s
  -DDST=L"${CMAKE_PROJECT_NAME}"s
)

target_vcxproj_filters(Zynamic)
