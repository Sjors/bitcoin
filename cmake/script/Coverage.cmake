# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include(${CMAKE_CURRENT_LIST_DIR}/CoverageInclude.cmake)

if(DEFINED JOBS)
  list(APPEND CMAKE_CTEST_COMMAND -j ${JOBS})
endif()

execute_process(
  COMMAND ${CMAKE_CTEST_COMMAND} --build-config Coverage
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
  COMMAND_ERROR_IS_FATAL ANY
)
execute_process(
  COMMAND ${LCOV_COMMAND} --capture --directory src --test-name test_sv2 --output-file test_sv2.info
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
  COMMAND_ERROR_IS_FATAL ANY
)
execute_process(
  COMMAND ${LCOV_COMMAND} --zerocounters --directory src
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
  COMMAND_ERROR_IS_FATAL ANY
)
execute_process(
  COMMAND ${LCOV_FILTER_COMMAND} test_sv2.info test_sv2_filtered.info
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
  COMMAND_ERROR_IS_FATAL ANY
)
execute_process(
  COMMAND ${LCOV_COMMAND} --add-tracefile test_sv2_filtered.info --output-file test_sv2_filtered.info
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
  COMMAND_ERROR_IS_FATAL ANY
)
execute_process(
  COMMAND ${LCOV_COMMAND} --add-tracefile baseline_filtered.info --add-tracefile test_sv2_filtered.info --output-file test_sv2_coverage.info
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
  COMMAND_ERROR_IS_FATAL ANY
)
execute_process(
  COMMAND ${GENHTML_COMMAND} test_sv2_coverage.info --output-directory test_sv2.coverage
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
  COMMAND_ERROR_IS_FATAL ANY
)
execute_process(
  COMMAND ${LCOV_COMMAND} --zerocounters --directory src
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
  COMMAND_ERROR_IS_FATAL ANY
)
execute_process(
  COMMAND ${LCOV_COMMAND} --add-tracefile baseline_filtered.info --add-tracefile test_sv2_filtered.info --output-file total_coverage.info
  COMMAND ${GREP_EXECUTABLE} "%"
  COMMAND ${AWK_EXECUTABLE} "{ print substr($3,2,50) \"/\" $5 }"
  OUTPUT_FILE coverage_percent.txt
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
  COMMAND_ERROR_IS_FATAL ANY
)
execute_process(
  COMMAND ${GENHTML_COMMAND} total_coverage.info --output-directory total.coverage
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
  COMMAND_ERROR_IS_FATAL ANY
)
