// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/net.h>

#include <net.h>
#include <netaddress.h>
#include <netmessagemaker.h>
#include <node/connection_types.h>
#include <protocol.h>
#include <random.h>
#include <serialize.h>
#include <span.h>
#include <sync.h>

#include <chrono>
#include <optional>
#include <vector>

// Have different ZeroSock (or others that inherit from it) objects have different
// m_socket because EqualSharedPtrSock compares m_socket and we want to avoid two
// different objects comparing as equal.
static std::atomic<SOCKET> g_mocked_sock_fd{0};

ZeroSock::ZeroSock() : Sock{g_mocked_sock_fd++} {}

// Sock::~Sock() would try to close(2) m_socket if it is not INVALID_SOCKET, avoid that.
ZeroSock::~ZeroSock() { m_socket = INVALID_SOCKET; }

ssize_t ZeroSock::Send(const void*, size_t len, int) const { return len; }

ssize_t ZeroSock::Recv(void* buf, size_t len, int flags) const
{
    memset(buf, 0x0, len);
    return len;
}

int ZeroSock::Connect(const sockaddr*, socklen_t) const { return 0; }

int ZeroSock::Bind(const sockaddr*, socklen_t) const { return 0; }

int ZeroSock::Listen(int) const { return 0; }

std::unique_ptr<Sock> ZeroSock::Accept(sockaddr* addr, socklen_t* addr_len) const
{
    if (addr != nullptr) {
        // Pretend all connections come from 5.5.5.5:6789
        memset(addr, 0x00, *addr_len);
        const socklen_t write_len = static_cast<socklen_t>(sizeof(sockaddr_in));
        if (*addr_len >= write_len) {
            *addr_len = write_len;
            sockaddr_in* addr_in = reinterpret_cast<sockaddr_in*>(addr);
            addr_in->sin_family = AF_INET;
            memset(&addr_in->sin_addr, 0x05, sizeof(addr_in->sin_addr));
            addr_in->sin_port = htons(6789);
        }
    }
    return std::make_unique<ZeroSock>();
}

int ZeroSock::GetSockOpt(int level, int opt_name, void* opt_val, socklen_t* opt_len) const
{
    std::memset(opt_val, 0x0, *opt_len);
    return 0;
}

int ZeroSock::SetSockOpt(int, int, const void*, socklen_t) const { return 0; }

int ZeroSock::GetSockName(sockaddr* name, socklen_t* name_len) const
{
    std::memset(name, 0x0, *name_len);
    return 0;
}

bool ZeroSock::SetNonBlocking() const { return true; }

bool ZeroSock::IsSelectable() const { return true; }

bool ZeroSock::Wait(std::chrono::milliseconds timeout, Event requested, Event* occurred) const
{
    if (occurred != nullptr) {
        *occurred = requested;
    }
    return true;
}

bool ZeroSock::WaitMany(std::chrono::milliseconds timeout, EventsPerSock& events_per_sock) const
{
    for (auto& [sock, events] : events_per_sock) {
        (void)sock;
        events.occurred = events.requested;
    }
    return true;
}

ZeroSock& ZeroSock::operator=(Sock&& other)
{
    assert(false && "Move of Sock into ZeroSock not allowed.");
    return *this;
}

StaticContentsSock::StaticContentsSock(const std::string& contents)
    : m_contents{contents}
{
}

ssize_t StaticContentsSock::Recv(void* buf, size_t len, int flags) const
{
    const size_t consume_bytes{std::min(len, m_contents.size() - m_consumed)};
    std::memcpy(buf, m_contents.data() + m_consumed, consume_bytes);
    if ((flags & MSG_PEEK) == 0) {
        m_consumed += consume_bytes;
    }
    return consume_bytes;
}

StaticContentsSock& StaticContentsSock::operator=(Sock&& other)
{
    assert(false && "Move of Sock into StaticContentsSock not allowed.");
    return *this;
}

ssize_t DynSock::Pipe::GetBytes(void* buf, size_t len, int flags)
{
    WAIT_LOCK(m_mutex, lock);

    if (m_data.empty()) {
        if (m_eof) {
            return 0;
        }
        errno = EAGAIN; // Same as recv(2) on a non-blocking socket.
        return -1;
    }

    const size_t read_bytes{std::min(len, m_data.size())};

    std::memcpy(buf, m_data.data(), read_bytes);
    if ((flags & MSG_PEEK) == 0) {
        m_data.erase(m_data.begin(), m_data.begin() + read_bytes);
    }

    return read_bytes;
}

void DynSock::Pipe::PushBytes(const void* buf, size_t len)
{
    LOCK(m_mutex);
    const uint8_t* b = static_cast<const uint8_t*>(buf);
    m_data.insert(m_data.end(), b, b + len);
    m_cond.notify_all();
}

void DynSock::Pipe::Eof()
{
    LOCK(m_mutex);
    m_eof = true;
    m_cond.notify_all();
}

void DynSock::Pipe::WaitForDataOrEof(UniqueLock<Mutex>& lock)
{
    Assert(lock.mutex() == &m_mutex);

    m_cond.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
        AssertLockHeld(m_mutex);
        return !m_data.empty() || m_eof;
    });
}

DynSock::DynSock(std::shared_ptr<Pipes> pipes, std::shared_ptr<Queue> accept_sockets)
    : m_pipes{pipes}, m_accept_sockets{accept_sockets}
{
}

DynSock::~DynSock()
{
    m_pipes->send.Eof();
}

ssize_t DynSock::Recv(void* buf, size_t len, int flags) const
{
    return m_pipes->recv.GetBytes(buf, len, flags);
}

ssize_t DynSock::Send(const void* buf, size_t len, int) const
{
    m_pipes->send.PushBytes(buf, len);
    return len;
}

std::unique_ptr<Sock> DynSock::Accept(sockaddr* addr, socklen_t* addr_len) const
{
    ZeroSock::Accept(addr, addr_len);
    return m_accept_sockets->Pop().value_or(nullptr);
}

bool DynSock::Wait(std::chrono::milliseconds timeout,
                   Event requested,
                   Event* occurred) const
{
    EventsPerSock ev;
    ev.emplace(this, Events{requested});
    const bool ret{WaitMany(timeout, ev)};
    if (occurred != nullptr) {
        *occurred = ev.begin()->second.occurred;
    }
    return ret;
}

bool DynSock::WaitMany(std::chrono::milliseconds timeout, EventsPerSock& events_per_sock) const
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    bool at_least_one_event_occurred{false};

    for (;;) {
        // Check all sockets for readiness without waiting.
        for (auto& [sock, events] : events_per_sock) {
            if ((events.requested & Sock::SEND) != 0) {
                // Always ready for Send().
                events.occurred |= Sock::SEND;
                at_least_one_event_occurred = true;
            }

            if ((events.requested & Sock::RECV) != 0) {
                auto dyn_sock = reinterpret_cast<const DynSock*>(sock.get());
                uint8_t b;
                if (dyn_sock->m_pipes->recv.GetBytes(&b, 1, MSG_PEEK) == 1 || !dyn_sock->m_accept_sockets->Empty()) {
                    events.occurred |= Sock::RECV;
                    at_least_one_event_occurred = true;
                }
            }
        }

        if (at_least_one_event_occurred || std::chrono::steady_clock::now() > deadline) {
            break;
        }

        std::this_thread::sleep_for(10ms);
    }

    return true;
}

DynSock& DynSock::operator=(Sock&&)
{
    assert(false && "Move of Sock into DynSock not allowed.");
    return *this;
}
