set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(
  /MP # Enables parallel builds.
  $<$<CONFIG:Debug>:/Zi> # Produces a separate PDB file that contains all the symbolic debugging information.
)

add_subdirectory(zynamic)
