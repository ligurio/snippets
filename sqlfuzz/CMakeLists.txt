cmake_minimum_required (VERSION 3.10.2)

project (sql_fuzzer)

set(SQL_FUZZER_SRC disabled_queries_parser.cc
                   disabled_queries_parser.h
                   shadow_table_fuzzer.cc
                   sql_expr_fuzzer.cc
                   sql_fuzzer.cc
                   sql_generate_corpus.cc
                   sql_multithreaded_fuzzer.cc
                   sql_printf_fuzzer.cc
                   sql_query_proto_to_string.cc
                   sql_query_proto_to_string.h
                   sql_run_queries.cc
                   sql_run_queries.h
                   sql_strftime_fuzzer.cc)

# add_definitions(${FUSE_DEFINITIONS})
add_executable(${PROJECT_NAME} ${SQL_FUZZER_SRC})
# target_include_directories(${PROJECT_NAME} PRIVATE ${FUSE_INCLUDE_DIRS})
# target_link_libraries(${PROJECT_NAME} ${FUSE_LIBRARIES})

target_compile_options(${PROJECT_NAME} PUBLIC -D_FILE_OFFSET_BITS=64 -Wall -Wextra -Wno-unused-parameter)
target_compile_options(${PROJECT_NAME} PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++11 -D_FILE_OFFSET_BITS=64>)
