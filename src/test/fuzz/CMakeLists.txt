# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_subdirectory(util)

add_executable(fuzz)

target_link_libraries(fuzz
  core_interface
  fuzzer_interface
  test_fuzz
  bitcoin_cli
  bitcoin_common
  bitcoin_util
  secp256k1
  Boost::headers
)

if(WITH_SV2)
  target_sources(fuzz
  PRIVATE
    sv2_noise.cpp
  )
  target_link_libraries(fuzz
    bitcoin_sv2
  )
endif()
