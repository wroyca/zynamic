set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (MASTER_PROJECT)
  set(ZYNAMIC_OUT "")
  set(ZYNAMIC_BIN "")
endif()

add_subdirectory(zynamic)
