# https://github.com/lperkov/cmocka-hello/
# cmakelint

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(testres)
# enable_testing()
SET(SOURCES testres.c
parse_common.c
parse_junit.c
parse_subunit_v1.c
parse_subunit_v2.c
parse_testanything.c
ui_common.c
ui_console.c
ui_http.c
sha1.c)
SET(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/../)
# SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/../build/modules")
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

# add_subdirectory(src)
# add_subdirectory(test)

#INCLUDE(FindEXPAT)
#FIND_PACKAGE(EXPAT REQUIRED)
#INCLUDE_DIRECTORIES(${EXPAT_INCLUDE_DIRS})
#TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${EXPAT_LIBRARIES})

#INCLUDE(FindCMocka)
#FIND_PACKAGE(CMOCKA REQUIRED)
#INCLUDE_DIRECTORIES(${LIBCMOCKA_INCLUDE_DIR})
#TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${LIBCMOCKA_LIBRARIES})

ADD_DEFINITIONS(-Wall -Werror --std=gnu99 -Wmissing-declarations)
ADD_EXECUTABLE(${PROJECT_NAME} ${SOURCES})
FILE(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)
INSTALL(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)


FIND_PROGRAM(LEX flex)
IF(LEX STREQUAL "LEX-NOTFOUND")
    MESSAGE(FATAL_ERROR "lex is not found")
ENDIF()

FIND_PROGRAM(YACC yacc)
IF(YACC STREQUAL "YACC-NOTFOUND")
    MESSAGE(FATAL_ERROR "yacc is not found")
ENDIF()

MACRO(YACC_FILE _filename)
    GET_FILENAME_COMPONENT(_basename ${_filename} NAME_WE)
    ADD_CUSTOM_COMMAND(
        OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/${_basename}.c
                ${CMAKE_CURRENT_BINARY_DIR}/${_basename}.h
        COMMAND ${YACC_EXE} -d
                --output=${_basename}.c
                ${CMAKE_CURRENT_SOURCE_DIR}/${_filename}
        DEPENDS ${_filename}
    )
ENDMACRO()

MACRO(LEX_FILE _filename)
    GET_FILENAME_COMPONENT(_basename ${_filename} NAME_WE)
    ADD_CUSTOM_COMMAND(
        OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/${_basename}.c
        COMMAND ${LEX_EXE}
                -o${_basename}.c
                ${CMAKE_CURRENT_SOURCE_DIR}/${_filename}
        DEPENDS ${_filename}
    )
ENDMACRO()

# YACC_FILE(config_yacc.y)
# LEX_FILE(config_lex.l)

# add_executable(my_parsing_exe
#     config_yacc.c
#     config_lex.c
# )
