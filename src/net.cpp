// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net.h>

#include <clientversion.h>
#include <common/args.h>
#include <common/netif.h>
#include <compat/compat.h>
#include <consensus/consensus.h>
#include <crypto/sha256.h>
#include <key.h>
#include <logging.h>
#include <memusage.h>
#include <netaddress.h>
#include <netbase.h>
#include <random.h>
#include <scheduler.h>
#include <util/fs.h>
#include <util/sock.h>
#include <util/strencodings.h>
#include <util/thread.h>
#include <util/threadinterrupt.h>
#include <util/trace.h>
#include <util/translation.h>
#include <util/vector.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <functional>
#include <optional>
#include <unordered_map>

TRACEPOINT_SEMAPHORE(net, closed_connection);
TRACEPOINT_SEMAPHORE(net, evicted_inbound_connection);
TRACEPOINT_SEMAPHORE(net, inbound_connection);
TRACEPOINT_SEMAPHORE(net, outbound_connection);
TRACEPOINT_SEMAPHORE(net, outbound_message);

/** Maximum number of block-relay-only anchor connections */
static constexpr size_t MAX_BLOCK_RELAY_ONLY_ANCHORS = 2;
static_assert (MAX_BLOCK_RELAY_ONLY_ANCHORS <= static_cast<size_t>(MAX_BLOCK_RELAY_ONLY_CONNECTIONS), "MAX_BLOCK_RELAY_ONLY_ANCHORS must not exceed MAX_BLOCK_RELAY_ONLY_CONNECTIONS.");

/** Used to pass flags to the Bind() function */
enum BindFlags {
    BF_NONE         = 0,
    BF_REPORT_ERROR = (1U << 0),
    /**
     * Do not call AddLocal() for our special addresses, e.g., for incoming
     * Tor connections, to prevent gossiping them over the network.
     */
    BF_DONT_ADVERTISE = (1U << 1),
};

const std::string NET_MESSAGE_TYPE_OTHER = "*other*";

//
// Global state variables
//
bool fDiscover = true;
bool fListen = true;
GlobalMutex g_maplocalhost_mutex;
std::map<CNetAddr, LocalServiceInfo> mapLocalHost GUARDED_BY(g_maplocalhost_mutex);
std::string strSubVersion;

size_t CSerializedNetMsg::GetMemoryUsage() const noexcept
{
    return sizeof(*this) + memusage::DynamicUsage(m_type) + memusage::DynamicUsage(data);
}

size_t CNetMessage::GetMemoryUsage() const noexcept
{
    return sizeof(*this) + memusage::DynamicUsage(m_type) + m_recv.GetMemoryUsage();
}

class CNetCleanup
{
public:
    CNetCleanup() = default;

    ~CNetCleanup()
    {
#ifdef WIN32
        // Shutdown Windows Sockets
        WSACleanup();
#endif
    }
};
static CNetCleanup instance_of_cnetcleanup;
