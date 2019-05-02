cmake_minimum_required(VERSION 3.10)

find_program(LEX_EXECUTABLE lex)
if(LEX_EXECUTABLE STREQUAL "LEX_EXE-NOTFOUND")
    message(FATAL_ERROR "lex is not found")
endif(LEX_EXECUTABLE STREQUAL "LEX_EXE-NOTFOUND")

find_program(YACC_EXECUTABLE yacc)
if(YACC_EXECUTABLE STREQUAL "YACC_EXECUTABLE-NOTFOUND")
    message(FATAL_ERROR "yacc is not found")
endif(YACC_EXECUTABLE STREQUAL "YACC_EXECUTABLE-NOTFOUND")

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/scanner_testanything.c
  COMMAND ${LEX_EXECUTABLE}
  ARGS -o${CMAKE_CURRENT_BINARY_DIR}/scanner_testanything.c
       ${CMAKE_CURRENT_SOURCE_DIR}/testanything.l)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser_testanything.c
  COMMAND ${YACC_EXECUTABLE}
  ARGS -o ${CMAKE_CURRENT_BINARY_DIR}/parser_testanything.c
		${CMAKE_CURRENT_SOURCE_DIR}/testanything.y
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/scanner_testanything.c)

set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/parser_testanything.c GENERATED)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(parser
    parser_testanything.c
    scanner_testanything.c
    parse_common.c
)
