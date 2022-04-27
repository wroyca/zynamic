file(GLOB_RECURSE reflective_pe RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp)

add_library(reflective_pe STATIC
    ${reflective_pe}
)

target_precompile_headers(reflective_pe
PRIVATE
    ${CMAKE_CXX_PCH}
)

target_create_vcxproj_filters(reflective_pe)

#

add_library(reflective_pe_xp STATIC
    ${reflective_pe}
)

target_precompile_headers(reflective_pe_xp
PRIVATE
    ${CMAKE_CXX_PCH}
)

set_target_properties(reflective_pe_xp
PROPERTIES
  VS_PLATFORM_TOOLSET "v90"
)

target_create_vcxproj_filters(reflective_pe_xp)
