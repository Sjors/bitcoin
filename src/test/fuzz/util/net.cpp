// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/util/net.h>

#include <compat/compat.h>
#include <netaddress.h>
#include <node/protocol_version.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/util.h>
#include <test/util/net.h>
#include <util/sock.h>
#include <util/time.h>

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

FuzzedSock::FuzzedSock(FuzzedDataProvider& fuzzed_data_provider)
    : Sock{fuzzed_data_provider.ConsumeIntegralInRange<SOCKET>(INVALID_SOCKET - 1, INVALID_SOCKET)},
      m_fuzzed_data_provider{fuzzed_data_provider},
      m_selectable{fuzzed_data_provider.ConsumeBool()},
      m_time{MockableSteadyClock::INITIAL_MOCK_TIME}
{
    ElapseTime(std::chrono::seconds(0)); // start mocking the steady clock.
}

FuzzedSock::~FuzzedSock()
{
    // Sock::~Sock() will be called after FuzzedSock::~FuzzedSock() and it will call
    // close(m_socket) if m_socket is not INVALID_SOCKET.
    // Avoid closing an arbitrary file descriptor (m_socket is just a random very high number which
    // theoretically may concide with a real opened file descriptor).
    m_socket = INVALID_SOCKET;
}

void FuzzedSock::ElapseTime(std::chrono::milliseconds duration) const
{
    m_time += duration;
    MockableSteadyClock::SetMockTime(m_time);
}

FuzzedSock& FuzzedSock::operator=(Sock&& other)
{
    assert(false && "Move of Sock into FuzzedSock not allowed.");
    return *this;
}

ssize_t FuzzedSock::Send(const void* data, size_t len, int flags) const
{
    constexpr std::array send_errnos{
        EACCES,
        EAGAIN,
        EALREADY,
        EBADF,
        ECONNRESET,
        EDESTADDRREQ,
        EFAULT,
        EINTR,
        EINVAL,
        EISCONN,
        EMSGSIZE,
        ENOBUFS,
        ENOMEM,
        ENOTCONN,
        ENOTSOCK,
        EOPNOTSUPP,
        EPIPE,
        EWOULDBLOCK,
    };
    if (m_fuzzed_data_provider.ConsumeBool()) {
        return len;
    }
    const ssize_t r = m_fuzzed_data_provider.ConsumeIntegralInRange<ssize_t>(-1, len);
    if (r == -1) {
        SetFuzzedErrNo(m_fuzzed_data_provider, send_errnos);
    }
    return r;
}

ssize_t FuzzedSock::Recv(void* buf, size_t len, int flags) const
{
    // Have a permanent error at recv_errnos[0] because when the fuzzed data is exhausted
    // SetFuzzedErrNo() will always return the first element and we want to avoid Recv()
    // returning -1 and setting errno to EAGAIN repeatedly.
    constexpr std::array recv_errnos{
        ECONNREFUSED,
        EAGAIN,
        EBADF,
        EFAULT,
        EINTR,
        EINVAL,
        ENOMEM,
        ENOTCONN,
        ENOTSOCK,
        EWOULDBLOCK,
    };
    assert(buf != nullptr || len == 0);

    // Do the latency before any of the "return" statements.
    if (m_fuzzed_data_provider.ConsumeBool() && std::getenv("FUZZED_SOCKET_FAKE_LATENCY") != nullptr) {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }

    if (len == 0 || m_fuzzed_data_provider.ConsumeBool()) {
        const ssize_t r = m_fuzzed_data_provider.ConsumeBool() ? 0 : -1;
        if (r == -1) {
            SetFuzzedErrNo(m_fuzzed_data_provider, recv_errnos);
        }
        return r;
    }

    size_t copied_so_far{0};

    if (!m_peek_data.empty()) {
        // `MSG_PEEK` was used in the preceding `Recv()` call, copy the first bytes from `m_peek_data`.
        const size_t copy_len{std::min(len, m_peek_data.size())};
        std::memcpy(buf, m_peek_data.data(), copy_len);
        copied_so_far += copy_len;
        if ((flags & MSG_PEEK) == 0) {
            m_peek_data.erase(m_peek_data.begin(), m_peek_data.begin() + copy_len);
        }
    }

    if (copied_so_far == len) {
        return copied_so_far;
    }

    auto new_data = ConsumeRandomLengthByteVector(m_fuzzed_data_provider, len - copied_so_far);
    if (new_data.empty()) return copied_so_far;

    std::memcpy(reinterpret_cast<uint8_t*>(buf) + copied_so_far, new_data.data(), new_data.size());
    copied_so_far += new_data.size();

    if ((flags & MSG_PEEK) != 0) {
        m_peek_data.insert(m_peek_data.end(), new_data.begin(), new_data.end());
    }

    if (copied_so_far == len || m_fuzzed_data_provider.ConsumeBool()) {
        return copied_so_far;
    }

    // Pad to len bytes.
    std::memset(reinterpret_cast<uint8_t*>(buf) + copied_so_far, 0x0, len - copied_so_far);

    return len;
}

int FuzzedSock::Connect(const sockaddr*, socklen_t) const
{
    // Have a permanent error at connect_errnos[0] because when the fuzzed data is exhausted
    // SetFuzzedErrNo() will always return the first element and we want to avoid Connect()
    // returning -1 and setting errno to EAGAIN repeatedly.
    constexpr std::array connect_errnos{
        ECONNREFUSED,
        EAGAIN,
        ECONNRESET,
        EHOSTUNREACH,
        EINPROGRESS,
        EINTR,
        ENETUNREACH,
        ETIMEDOUT,
    };
    if (m_fuzzed_data_provider.ConsumeBool()) {
        SetFuzzedErrNo(m_fuzzed_data_provider, connect_errnos);
        return -1;
    }
    return 0;
}

int FuzzedSock::Bind(const sockaddr*, socklen_t) const
{
    // Have a permanent error at bind_errnos[0] because when the fuzzed data is exhausted
    // SetFuzzedErrNo() will always set the global errno to bind_errnos[0]. We want to
    // avoid this method returning -1 and setting errno to a temporary error (like EAGAIN)
    // repeatedly because proper code should retry on temporary errors, leading to an
    // infinite loop.
    constexpr std::array bind_errnos{
        EACCES,
        EADDRINUSE,
        EADDRNOTAVAIL,
        EAGAIN,
    };
    if (m_fuzzed_data_provider.ConsumeBool()) {
        SetFuzzedErrNo(m_fuzzed_data_provider, bind_errnos);
        return -1;
    }
    return 0;
}

int FuzzedSock::Listen(int) const
{
    // Have a permanent error at listen_errnos[0] because when the fuzzed data is exhausted
    // SetFuzzedErrNo() will always set the global errno to listen_errnos[0]. We want to
    // avoid this method returning -1 and setting errno to a temporary error (like EAGAIN)
    // repeatedly because proper code should retry on temporary errors, leading to an
    // infinite loop.
    constexpr std::array listen_errnos{
        EADDRINUSE,
        EINVAL,
        EOPNOTSUPP,
    };
    if (m_fuzzed_data_provider.ConsumeBool()) {
        SetFuzzedErrNo(m_fuzzed_data_provider, listen_errnos);
        return -1;
    }
    return 0;
}

std::unique_ptr<Sock> FuzzedSock::Accept(sockaddr* addr, socklen_t* addr_len) const
{
    constexpr std::array accept_errnos{
        ECONNABORTED,
        EINTR,
        ENOMEM,
    };
    if (m_fuzzed_data_provider.ConsumeBool()) {
        SetFuzzedErrNo(m_fuzzed_data_provider, accept_errnos);
        return std::unique_ptr<FuzzedSock>();
    }
    return std::make_unique<FuzzedSock>(m_fuzzed_data_provider);
}

int FuzzedSock::GetSockOpt(int level, int opt_name, void* opt_val, socklen_t* opt_len) const
{
    constexpr std::array getsockopt_errnos{
        ENOMEM,
        ENOBUFS,
    };
    if (m_fuzzed_data_provider.ConsumeBool()) {
        SetFuzzedErrNo(m_fuzzed_data_provider, getsockopt_errnos);
        return -1;
    }
    if (opt_val == nullptr) {
        return 0;
    }
    std::memcpy(opt_val,
                ConsumeFixedLengthByteVector(m_fuzzed_data_provider, *opt_len).data(),
                *opt_len);
    return 0;
}

int FuzzedSock::SetSockOpt(int, int, const void*, socklen_t) const
{
    constexpr std::array setsockopt_errnos{
        ENOMEM,
        ENOBUFS,
    };
    if (m_fuzzed_data_provider.ConsumeBool()) {
        SetFuzzedErrNo(m_fuzzed_data_provider, setsockopt_errnos);
        return -1;
    }
    return 0;
}

int FuzzedSock::GetSockName(sockaddr* name, socklen_t* name_len) const
{
    constexpr std::array getsockname_errnos{
        ECONNRESET,
        ENOBUFS,
    };
    if (m_fuzzed_data_provider.ConsumeBool()) {
        SetFuzzedErrNo(m_fuzzed_data_provider, getsockname_errnos);
        return -1;
    }
    assert(name_len);
    const auto bytes{ConsumeRandomLengthByteVector(m_fuzzed_data_provider, *name_len)};
    if (bytes.size() < (int)sizeof(sockaddr)) return -1;
    std::memcpy(name, bytes.data(), bytes.size());
    *name_len = bytes.size();
    return 0;
}

bool FuzzedSock::SetNonBlocking() const
{
    constexpr std::array setnonblocking_errnos{
        EBADF,
        EPERM,
    };
    if (m_fuzzed_data_provider.ConsumeBool()) {
        SetFuzzedErrNo(m_fuzzed_data_provider, setnonblocking_errnos);
        return false;
    }
    return true;
}

bool FuzzedSock::IsSelectable() const
{
    return m_selectable;
}

bool FuzzedSock::Wait(std::chrono::milliseconds timeout, Event requested, Event* occurred) const
{
    constexpr std::array wait_errnos{
        EBADF,
        EINTR,
        EINVAL,
    };
    if (m_fuzzed_data_provider.ConsumeBool()) {
        SetFuzzedErrNo(m_fuzzed_data_provider, wait_errnos);
        return false;
    }
    if (occurred != nullptr) {
        // We simulate the requested event as occurred when ConsumeBool()
        // returns false. This avoids simulating endless waiting if the
        // FuzzedDataProvider runs out of data.
        *occurred = m_fuzzed_data_provider.ConsumeBool() ? 0 : requested;
    }
    ElapseTime(timeout);
    return true;
}

bool FuzzedSock::WaitMany(std::chrono::milliseconds timeout, EventsPerSock& events_per_sock) const
{
    for (auto& [sock, events] : events_per_sock) {
        (void)sock;
        // We simulate the requested event as occurred when ConsumeBool()
        // returns false. This avoids simulating endless waiting if the
        // FuzzedDataProvider runs out of data.
        events.occurred = m_fuzzed_data_provider.ConsumeBool() ? 0 : events.requested;
    }
    ElapseTime(timeout);
    return true;
}

bool FuzzedSock::IsConnected(std::string& errmsg) const
{
    if (m_fuzzed_data_provider.ConsumeBool()) {
        return true;
    }
    errmsg = "disconnected at random by the fuzzer";
    return false;
}
