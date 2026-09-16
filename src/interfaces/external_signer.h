// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_EXTERNAL_SIGNER_H
#define BITCOIN_INTERFACES_EXTERNAL_SIGNER_H

#include <interfaces/types.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace interfaces {

//! Interface to an external signing service such as HWI, which registers
//! itself over IPC via Init::registerExternalSigner. Methods mirror the
//! commands described in doc/external-signer.md.
//!
//! Expected failures (user cancelled on the device, unknown fingerprint,
//! device unplugged) are reported through the bool return value and error
//! output parameter. Transport failures throw ipc::Exception.
class ExternalSignerService
{
public:
    virtual ~ExternalSignerService() = default;

    //! List available signing devices.
    virtual std::vector<ExternalSignerInfo> enumerate(const std::string& chain) = 0;

    //! Get receive and change descriptors for a BIP44 account.
    virtual bool getDescriptors(const std::string& fingerprint,
                                const std::string& chain,
                                int32_t account,
                                std::vector<std::string>& receive,
                                std::vector<std::string>& internal,
                                std::string& error) = 0;

    //! Display an address, given by its descriptor, on the device screen.
    virtual bool displayAddress(const std::string& fingerprint,
                                const std::string& chain,
                                const std::string& descriptor,
                                std::string& address,
                                std::string& error) = 0;

    //! Sign a raw serialized PSBT, returning the (partially) signed PSBT.
    virtual bool signTransaction(const std::string& fingerprint,
                                 const std::string& chain,
                                 const std::vector<unsigned char>& psbt,
                                 std::vector<unsigned char>& signed_psbt,
                                 std::string& error) = 0;
};

} // namespace interfaces

//! Set, replace or (with nullptr) clear the process-wide external signer
//! service registered over IPC. Thread safe. A registered service takes
//! precedence over the -signer command. Defined in external_signer.cpp.
void SetRegisteredSignerService(std::shared_ptr<interfaces::ExternalSignerService> service);

//! Get the external signer service registered over IPC, or nullptr if there
//! is none. Returns a copy so the service stays alive for the duration of a
//! call even if it is concurrently replaced.
std::shared_ptr<interfaces::ExternalSignerService> GetRegisteredSignerService();

#endif // BITCOIN_INTERFACES_EXTERNAL_SIGNER_H
