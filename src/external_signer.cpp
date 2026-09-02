// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <external_signer.h>

#include <chainparams.h>
#include <common/run_command.h>
#include <core_io.h>
#include <interfaces/external_signer.h>
#include <ipc/exception.h>
#include <psbt.h>
#include <sync.h>
#include <util/strencodings.h>
#include <util/subprocess.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

static GlobalMutex g_signer_service_mutex;
static std::shared_ptr<interfaces::ExternalSignerService> g_signer_service GUARDED_BY(g_signer_service_mutex);

void SetRegisteredSignerService(std::shared_ptr<interfaces::ExternalSignerService> service)
{
    LOCK(g_signer_service_mutex);
    g_signer_service = std::move(service);
}

std::shared_ptr<interfaces::ExternalSignerService> GetRegisteredSignerService()
{
    LOCK(g_signer_service_mutex);
    return g_signer_service;
}

ExternalSigner::ExternalSigner(std::vector<std::string> command, std::string chain, std::string fingerprint, std::string name)
    : m_command{std::move(command)}, m_chain{std::move(chain)}, m_fingerprint{std::move(fingerprint)}, m_name{std::move(name)} {}

ExternalSigner::ExternalSigner(std::shared_ptr<interfaces::ExternalSignerService> service, std::string chain, std::string fingerprint, std::string name)
    : m_service{std::move(service)}, m_chain{std::move(chain)}, m_fingerprint{std::move(fingerprint)}, m_name{std::move(name)} {}

std::vector<std::string> ExternalSigner::NetworkArg() const
{
    return {"--chain", m_chain};
}

bool ExternalSigner::Enumerate(const std::string& command, std::vector<ExternalSigner>& signers, const std::string& chain)
{
    // A signer service registered over IPC takes precedence over -signer.
    if (auto service{GetRegisteredSignerService()}) {
        try {
            for (const interfaces::ExternalSignerInfo& info : service->enumerate(chain)) {
                if (info.fingerprint.size() != 8 || !IsHex(info.fingerprint)) {
                    throw std::runtime_error("IPC external signer returned invalid fingerprint, must be 8 hex characters");
                }
                // Skip duplicate signer
                bool duplicate{false};
                for (const ExternalSigner& signer : signers) {
                    if (signer.m_fingerprint == info.fingerprint) duplicate = true;
                }
                if (duplicate) continue;
                signers.emplace_back(service, chain, info.fingerprint, info.name);
            }
            return true;
        } catch (const ipc::Exception&) {
            // The signer process disconnected. Clear the registration and
            // fall back to the -signer command, if any.
            SetRegisteredSignerService(nullptr);
        }
    }
    if (command.empty()) return true;

    // Call <command> enumerate
    std::vector<std::string> cmd_args = Cat(subprocess::util::split(command), {"enumerate"});

    const UniValue result = RunCommandParseJSON(cmd_args, "");
    if (!result.isArray()) {
        throw std::runtime_error(strprintf("'%s' received invalid response, expected array of signers", command));
    }
    for (const UniValue& signer : result.getValues()) {
        // Check for error
        const UniValue& error = signer.find_value("error");
        if (!error.isNull()) {
            if (!error.isStr()) {
                throw std::runtime_error(strprintf("'%s' error", command));
            }
            throw std::runtime_error(strprintf("'%s' error: %s", command, error.getValStr()));
        }
        // Check if fingerprint is present
        const UniValue& fingerprint = signer.find_value("fingerprint");
        if (fingerprint.isNull()) {
            throw std::runtime_error(strprintf("'%s' received invalid response, missing signer fingerprint", command));
        }
        const std::string& fingerprintStr{fingerprint.get_str()};
        if (fingerprintStr.size() != 8 || !IsHex(fingerprintStr)) {
            throw std::runtime_error(strprintf("'%s' received invalid fingerprint, must be 8 hex characters", command));
        }
        // Skip duplicate signer
        bool duplicate = false;
        for (const ExternalSigner& signer : signers) {
            if (signer.m_fingerprint.compare(fingerprintStr) == 0) duplicate = true;
        }
        if (duplicate) continue;
        std::string name;
        const UniValue& model_field = signer.find_value("model");
        if (model_field.isStr() && model_field.getValStr() != "") {
            name += model_field.getValStr();
        }
        signers.emplace_back(subprocess::util::split(command), chain, fingerprintStr, name);
    }
    return true;
}

UniValue ExternalSigner::DisplayAddress(const std::string& descriptor) const
{
    if (m_service) {
        UniValue result{UniValue::VOBJ};
        std::string address;
        std::string error;
        try {
            if (!m_service->displayAddress(m_fingerprint, m_chain, descriptor, address, error)) {
                result.pushKV("error", error);
                return result;
            }
        } catch (const ipc::Exception& e) {
            SetRegisteredSignerService(nullptr);
            result.pushKV("error", strprintf("External signer disconnected: %s", e.what()));
            return result;
        }
        result.pushKV("address", address);
        return result;
    }
    return RunCommandParseJSON(Cat(m_command, Cat(Cat({"--fingerprint", m_fingerprint}, NetworkArg()), {"displayaddress", "--desc", descriptor})), "");
}

UniValue ExternalSigner::GetDescriptors(const int account)
{
    if (m_service) {
        std::vector<std::string> receive;
        std::vector<std::string> internal;
        std::string error;
        try {
            if (!m_service->getDescriptors(m_fingerprint, m_chain, account, receive, internal, error)) {
                throw std::runtime_error(strprintf("External signer failed to get descriptors: %s", error));
            }
        } catch (const ipc::Exception& e) {
            SetRegisteredSignerService(nullptr);
            throw std::runtime_error(strprintf("External signer disconnected: %s", e.what()));
        }
        UniValue result{UniValue::VOBJ};
        UniValue receive_descriptors{UniValue::VARR};
        UniValue internal_descriptors{UniValue::VARR};
        for (const std::string& descriptor : receive) receive_descriptors.push_back(descriptor);
        for (const std::string& descriptor : internal) internal_descriptors.push_back(descriptor);
        result.pushKV("receive", std::move(receive_descriptors));
        result.pushKV("internal", std::move(internal_descriptors));
        return result;
    }
    return RunCommandParseJSON(Cat(m_command, Cat(Cat({"--fingerprint", m_fingerprint}, NetworkArg()), {"getdescriptors", "--account", strprintf("%d", account)})), "");
}

bool ExternalSigner::SignTransaction(PartiallySignedTransaction& psbtx, std::string& error)
{
    // Serialize the PSBT
    DataStream ssTx{};
    ssTx << psbtx;
    // parse ExternalSigner master fingerprint
    std::vector<unsigned char> parsed_m_fingerprint = ParseHex(m_fingerprint);
    // Check if signer fingerprint matches any input master key fingerprint
    auto matches_signer_fingerprint = [&](const PSBTInput& input) {
        for (const auto& entry : input.hd_keypaths) {
            if (std::ranges::equal(parsed_m_fingerprint, entry.second.fingerprint)) return true;
        }
        for (const auto& entry : input.m_tap_bip32_paths) {
            if (std::ranges::equal(parsed_m_fingerprint, entry.second.second.fingerprint)) return true;
        }
        return false;
    };

    if (!std::any_of(psbtx.inputs.begin(), psbtx.inputs.end(), matches_signer_fingerprint)) {
        error = "Signer fingerprint " + m_fingerprint + " does not match any of the inputs:\n" + EncodeBase64(ssTx.str());
        return false;
    }

    std::optional<PartiallySignedTransaction> signer_psbtx;
    if (m_service) {
        std::vector<unsigned char> signed_psbt;
        try {
            const std::string raw{ssTx.str()};
            if (!m_service->signTransaction(m_fingerprint, m_chain, std::vector<unsigned char>(raw.begin(), raw.end()), signed_psbt, error)) {
                return false;
            }
        } catch (const ipc::Exception& e) {
            SetRegisteredSignerService(nullptr);
            error = strprintf("External signer disconnected: %s", e.what());
            return false;
        }
        util::Result<PartiallySignedTransaction> decoded = DecodeRawPSBT(MakeByteSpan(signed_psbt));
        if (!decoded) {
            error = strprintf("TX decode failed %s", util::ErrorString(decoded).original);
            return false;
        }
        signer_psbtx = std::move(*decoded);
    } else {
        const std::vector<std::string> command = Cat(m_command, Cat({"--stdin", "--fingerprint", m_fingerprint}, NetworkArg()));
        const std::string stdinStr = "signtx " + EncodeBase64(ssTx.str());

        const UniValue signer_result = RunCommandParseJSON(command, stdinStr);

        if (signer_result.find_value("error").isStr()) {
            error = signer_result.find_value("error").get_str();
            return false;
        }

        if (!signer_result.find_value("psbt").isStr()) {
            error = "Unexpected result from signer";
            return false;
        }

        util::Result<PartiallySignedTransaction> decoded = DecodeBase64PSBT(signer_result.find_value("psbt").get_str());
        if (!decoded) {
            error = strprintf("TX decode failed %s", util::ErrorString(decoded).original);
            return false;
        }
        signer_psbtx = std::move(*decoded);
    }

    psbtx = *signer_psbtx;

    return true;
}
