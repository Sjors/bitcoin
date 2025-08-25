# FreeBSD Build Guide

**Updated for FreeBSD [14.3](https://www.freebsd.org/releases/14.3R/announce/)**

This guide describes how to build bitcoind, command-line utilities, and GUI on FreeBSD.

## Preparation

### 1. Install Required Dependencies
Run the following as root to install the base dependencies for building.

```bash
pkg install boost-libs cmake git libevent pkgconf
```

SQLite is required for the wallet:

```bash
pkg install sqlite3
```

To build Bitcoin Core without the wallet, use `-DENABLE_WALLET=OFF`.

Cap'n Proto is needed for IPC functionality.:

```bash
pkg install capnproto
```

Compile with `-DENABLE_IPC=OFF` if you do not need IPC functionality.

See [dependencies.md](dependencies.md) for a complete overview.

### 2. Clone Bitcoin Repo
Now that `git` and all the required dependencies are installed, let's clone the Bitcoin Core repository to a directory. All build scripts and commands will run from this directory.
```bash
git clone https://github.com/bitcoin/bitcoin.git
```

### 3. Install Optional Dependencies

#### Notifications
###### ZeroMQ

Bitcoin Core can provide notifications via ZeroMQ. If the package is installed, support will be compiled in.
```bash
pkg install libzmq4
```

#### Test Suite Dependencies
There is an included test suite that is useful for testing code changes when developing.
To run the test suite (recommended), you will need to have Python 3 installed:

```bash
pkg install python3 databases/py-sqlite3 net/py-pyzmq
```
---

## Building Bitcoin Core

### 1. Configuration

There are many ways to configure Bitcoin Core, here are a few common examples:

Run `cmake -B build -LH` to see the full list of available options.

##### No Wallet or GUI
```bash
cmake -B build -DENABLE_WALLET=OFF
```

### 2. Compile

```bash
cmake --build build     # Append "-j N" for N parallel jobs.
ctest --test-dir build  # Append "-j N" for N parallel tests. Some tests are disabled if Python 3 is not available.
```
