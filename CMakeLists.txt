cmake_minimum_required(VERSION 3.23.1 FATAL_ERROR)
project(Zynamic LANGUAGES CXX)

option(CMAKE_SUBMODULES "Initialize submodules in the repository." ON)
option(CMAKE_VCXPROJ_FILTERS "Initialize vcxproj.filters in the solution." ON)
option(ZYDIS_BUILD_TOOLS "Compile optional Zydis tools" OFF)
option(ZYDIS_BUILD_EXAMPLES "Compile optional Zydis examples" OFF)

# Initialize submodules in the repository.
find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
  if(CMAKE_SUBMODULES)
    execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} RESULT_VARIABLE RESULT)
    if(NOT RESULT EQUAL "0")
      message(FATAL_ERROR "git submodule update --init --recursive failed with ${GIT_SUBMOD_RESULT}, please checkout submodules.")
    endif()
  endif()
endif()

# Initialize vcxproj.filters in the solution.
function(target_vcxproj_filters target)
  if(CMAKE_VCXPROJ_FILTERS)
    get_target_property(sources "${target}" SOURCES)
    foreach(filename IN LISTS sources)
      get_filename_component(path "${filename}" PATH)
      string(REPLACE "/" "\\" group "${path}")
      source_group("${group}" FILES "${filename}")
    endforeach()
  endif()
endfunction()

# Disable in-source builds.
if ("${CMAKE_BINARY_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
  message(FATAL_ERROR "In-source builds are disabled to avoid cluttering the source tree with generated CMake files. Please create a build subdirectory and use `cmake ..` inside it.\n" "NOTE: You must delete both CMakeCache.txt and CMakeFiles/* before continuing.")
endif()

# Locate Visual Studio installation.
find_program(_vswhere_tool NAMES vswhere PATHS "$ENV{ProgramFiles\(x86\)}/Microsoft Visual Studio/Installer")
if (NOT ${vswhere})
  message(FATAL_ERROR "Could not locate vswhere.exe - unable to source vc redistributable")
endif()
execute_process(COMMAND "${_vswhere_tool}" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath OUTPUT_VARIABLE _vs_install_loc_out RESULT_VARIABLE _vs_where_exitcode OUTPUT_STRIP_TRAILING_WHITESPACE)
file(TO_CMAKE_PATH "${_vs_install_loc_out}" _vs_install_loc)
string(REPLACE "\\" "/" VS "${_vs_install_loc_out}")

add_subdirectory(externals/zydis)
add_subdirectory(src)
