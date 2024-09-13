# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(bitcoin_sv2 STATIC EXCLUDE_FROM_ALL
  noise.cpp
  transport.cpp
)

target_link_libraries(bitcoin_sv2
  PRIVATE
    core_interface
    bitcoin_clientversion
    bitcoin_crypto
    $<$<PLATFORM_ID:Windows>:ws2_32>
)

if (BUILD_SV2_LIB)
  install(FILES bitcoinsv2.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

  configure_file(${PROJECT_SOURCE_DIR}/libbitcoinsv2.pc.in ${PROJECT_BINARY_DIR}/libbitcoinsv2.pc @ONLY)
  install(FILES ${PROJECT_BINARY_DIR}/libbitcoinsv2.pc DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

endif()
