// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_NET_H
#define BITCOIN_TEST_UTIL_NET_H

#include <compat/compat.h>
#include <netmessagemaker.h>
#include <net.h>
#include <netaddress.h>
#include <node/connection_types.h>
#include <span.h>
#include <sync.h>
#include <util/sock.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

class FastRandomContext;

constexpr ServiceFlags ALL_SERVICE_FLAGS[]{
    NODE_NONE,
    NODE_NETWORK,
    NODE_BLOOM,
    NODE_WITNESS,
    NODE_COMPACT_FILTERS,
    NODE_NETWORK_LIMITED,
    NODE_P2P_V2,
};

constexpr ConnectionType ALL_CONNECTION_TYPES[]{
    ConnectionType::INBOUND,
    ConnectionType::OUTBOUND_FULL_RELAY,
    ConnectionType::MANUAL,
    ConnectionType::FEELER,
    ConnectionType::BLOCK_RELAY,
    ConnectionType::ADDR_FETCH,
};

constexpr auto ALL_NETWORKS = std::array{
    Network::NET_UNROUTABLE,
    Network::NET_IPV4,
    Network::NET_IPV6,
    Network::NET_ONION,
    Network::NET_I2P,
    Network::NET_CJDNS,
    Network::NET_INTERNAL,
};

/**
 * A mocked Sock alternative that succeeds on all operations.
 * Returns infinite amount of 0x0 bytes on reads.
 */
class ZeroSock : public Sock
{
public:
    ZeroSock();

    ~ZeroSock() override;

    ssize_t Send(const void*, size_t len, int) const override;

    ssize_t Recv(void* buf, size_t len, int flags) const override;

    int Connect(const sockaddr*, socklen_t) const override;

    int Bind(const sockaddr*, socklen_t) const override;

    int Listen(int) const override;

    std::unique_ptr<Sock> Accept(sockaddr* addr, socklen_t* addr_len) const override;

    int GetSockOpt(int level, int opt_name, void* opt_val, socklen_t* opt_len) const override;

    int SetSockOpt(int, int, const void*, socklen_t) const override;

    int GetSockName(sockaddr* name, socklen_t* name_len) const override;

    bool SetNonBlocking() const override;

    bool IsSelectable() const override;

    bool Wait(std::chrono::milliseconds timeout,
              Event requested,
              Event* occurred = nullptr) const override;

    bool WaitMany(std::chrono::milliseconds timeout, EventsPerSock& events_per_sock) const override;

private:
    ZeroSock& operator=(Sock&& other) override;
};

/**
 * A mocked Sock alternative that returns a statically contained data upon read and succeeds
 * and ignores all writes. The data to be returned is given to the constructor and when it is
 * exhausted an EOF is returned by further reads.
 */
class StaticContentsSock : public ZeroSock
{
public:
    explicit StaticContentsSock(const std::string& contents);

    /**
     * Return parts of the contents that was provided at construction until it is exhausted
     * and then return 0 (EOF).
     */
    ssize_t Recv(void* buf, size_t len, int flags) const override;

    bool IsConnected(std::string&) const override
    {
        return true;
    }

private:
    StaticContentsSock& operator=(Sock&& other) override;

    const std::string m_contents;
    mutable size_t m_consumed{0};
};

/**
 * A mocked Sock alternative that allows providing the data to be returned by Recv()
 * and inspecting the data that has been supplied to Send().
 */
class DynSock : public ZeroSock
{
public:
    /**
     * Unidirectional bytes or CNetMessage queue (FIFO).
     */
    class Pipe
    {
    public:
        /**
         * Get bytes and remove them from the pipe.
         * @param[in] buf Destination to write bytes to.
         * @param[in] len Write up to this number of bytes.
         * @param[in] flags Same as the flags of `recv(2)`. Just `MSG_PEEK` is honored.
         * @return The number of bytes written to `buf`. `0` if `Eof()` has been called.
         * If no bytes are available then `-1` is returned and `errno` is set to `EAGAIN`.
         */
        ssize_t GetBytes(void* buf, size_t len, int flags = 0) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

        /**
         * Push bytes to the pipe.
         */
        void PushBytes(const void* buf, size_t len) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

        /**
         * Signal end-of-file on the receiving end (`GetBytes()` or `GetNetMsg()`).
         */
        void Eof() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    private:
        /**
         * Return when there is some data to read or EOF has been signaled.
         * @param[in,out] lock Unique lock that must have been derived from `m_mutex` by `WAIT_LOCK(m_mutex, lock)`.
         */
        void WaitForDataOrEof(UniqueLock<Mutex>& lock) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

        Mutex m_mutex;
        std::condition_variable m_cond;
        std::vector<uint8_t> m_data GUARDED_BY(m_mutex);
        bool m_eof GUARDED_BY(m_mutex){false};
    };

    struct Pipes {
        Pipe recv;
        Pipe send;
    };

    /**
     * A basic thread-safe queue, used for queuing sockets to be returned by Accept().
     */
    class Queue
    {
    public:
        using S = std::unique_ptr<DynSock>;

        void Push(S s) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
        {
            LOCK(m_mutex);
            m_queue.push(std::move(s));
        }

        std::optional<S> Pop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
        {
            LOCK(m_mutex);
            if (m_queue.empty()) {
                return std::nullopt;
            }
            S front{std::move(m_queue.front())};
            m_queue.pop();
            return front;
        }

        bool Empty() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
        {
            LOCK(m_mutex);
            return m_queue.empty();
        }

    private:
        mutable Mutex m_mutex;
        std::queue<S> m_queue GUARDED_BY(m_mutex);
    };

    /**
     * Create a new mocked sock.
     * @param[in] pipes Send/recv pipes used by the Send() and Recv() methods.
     * @param[in] accept_sockets Sockets to return by the Accept() method.
     */
    explicit DynSock(std::shared_ptr<Pipes> pipes, std::shared_ptr<Queue> accept_sockets);

    ~DynSock();

    ssize_t Recv(void* buf, size_t len, int flags) const override;

    ssize_t Send(const void* buf, size_t len, int) const override;

    std::unique_ptr<Sock> Accept(sockaddr* addr, socklen_t* addr_len) const override;

    bool Wait(std::chrono::milliseconds timeout,
              Event requested,
              Event* occurred = nullptr) const override;

    bool WaitMany(std::chrono::milliseconds timeout, EventsPerSock& events_per_sock) const override;

private:
    DynSock& operator=(Sock&&) override;

    std::shared_ptr<Pipes> m_pipes;
    std::shared_ptr<Queue> m_accept_sockets;
};

#endif // BITCOIN_TEST_UTIL_NET_H
