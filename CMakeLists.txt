project(expr_jit)
cmake_minimum_required(VERSION 3.3)

add_library(expr_jit
    expr_jit.h
    expr_jit.cpp
)

target_include_directories(expr_jit PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test 
    test.cpp
    utest.h
)

target_link_libraries(test expr_jit)


if("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
  set_target_properties(expr_jit test PROPERTIES
    COMPILE_FLAGS "-Wall -Werror"
)
elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
set_target_properties(expr_jit test PROPERTIES
    COMPILE_FLAGS "/W3 /WX -DNOMINMAX"
)
endif()
