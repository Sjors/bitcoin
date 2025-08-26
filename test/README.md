This directory contains integration tests that test bitcoind and its
utilities in their entirety. It does not contain unit tests, which
can be found in [/src/test](/src/test), etc.

This directory contains the following sets of tests:

- [fuzz](/test/fuzz) A runner to execute all fuzz targets from
  [/src/test/fuzz](/src/test/fuzz).
- [lint](/test/lint/) which perform various static analysis checks.

The fuzz tests, functional
tests and lint scripts can be run as explained in the sections below.

# Running tests locally

Before tests can be run locally, Bitcoin Core must be built.  See the [building instructions](/doc#building) for help.

The following examples assume that the build directory is named `build`.

## Fuzz tests

See [/doc/fuzzing.md](/doc/fuzzing.md)

## Lint tests

See the README in [test/lint](/test/lint).

