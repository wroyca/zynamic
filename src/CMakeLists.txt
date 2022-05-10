set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED ZYNAMIC_APP)
  set(ZYNAMIC_APP "")
  set(ZYNAMIC_SRC "")
  set(ZYNAMIC_OUT "")
endif()

add_subdirectory(zynamic)
