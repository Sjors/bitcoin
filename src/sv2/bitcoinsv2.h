// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SV2_BITCOINSV2_H
#define BITCOIN_SV2_BITCOINSV2_H

#ifndef __cplusplus
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#else
#include <cstddef>
#include <cstdint>
#endif // __cplusplus


#if !defined(BITCOINSV2_GNUC_PREREQ)
#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define BITCOINSV2_GNUC_PREREQ(_maj, _min) \
    ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((_maj) << 16) + (_min))
#else
#define BITCOINSV2_GNUC_PREREQ(_maj, _min) 0
#endif
#endif

/* Warning attributes */
#if defined(__GNUC__) && BITCOINSV2_GNUC_PREREQ(3, 4)
#define BITCOINSV2_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#else
#define BITCOINSV2_WARN_UNUSED_RESULT
#endif
#if !defined(BITCOINSV2_BUILD) && defined(__GNUC__) && BITCOINSV2_GNUC_PREREQ(3, 4)
#define BITCOINSV2_ARG_NONNULL(_x) __attribute__((__nonnull__(_x)))
#else
#define BITCOINSV2_ARG_NONNULL(_x)
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * ------ Context ------
 *
 * The library provides Stratum v2 functionality.
 *
 * ------ Error handling ------
 *
 * TODO
 *
 * ------ Pointer and argument conventions ------
 *
 * TODO
 */

// TODO: some actual methods

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif // BITCOIN_SV2_BITCOINSV2_H
