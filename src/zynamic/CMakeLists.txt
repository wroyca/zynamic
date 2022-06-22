set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

set(sources
  view/main_window.cpp
  main.cpp
)

set(headers
  view/main_window.hpp
)

set(ui
  view/main_window.ui
)

add_executable(Zynamic
  ${sources}
  ${headers}
  ${ui}
)

target_link_libraries(Zynamic
PUBLIC
  Qt6::Widgets
  Zydis
)

target_compile_features(Zynamic
PRIVATE
  cxx_std_20
)

target_compile_options(Zynamic
PRIVATE
  /MP
  /Zi
)
