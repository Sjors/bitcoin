// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_EXTERNAL_SIGNER_SCRIPTPUBKEYMAN_H
#define BITCOIN_WALLET_EXTERNAL_SIGNER_SCRIPTPUBKEYMAN_H

#include <wallet/scriptpubkeyman.h>

#include <memory>
#include <util/result.h>

struct bilingual_str;

namespace wallet {
class ExternalSignerScriptPubKeyMan : public DescriptorScriptPubKeyMan
{
  public:
  ExternalSignerScriptPubKeyMan(WalletStorage& storage, WalletDescriptor& descriptor, int64_t keypool_size)
      :   DescriptorScriptPubKeyMan(storage, descriptor, keypool_size)
      {}
  ExternalSignerScriptPubKeyMan(WalletStorage& storage, int64_t keypool_size)
      :   DescriptorScriptPubKeyMan(storage, keypool_size)
      {}

  /** Provide a descriptor at setup time
  * Returns false if already setup or setup fails, true if setup is successful
  */
  bool SetupDescriptor(WalletBatch& batch, std::unique_ptr<Descriptor>desc);

  static util::Result<ExternalSigner> GetExternalSigner();

  /**
  * Display address on the device and verify that the returned value matches.
  * @returns nothing or an error message
  */
 util::Result<void> DisplayAddress(const CTxDestination& dest, const ExternalSigner& signer) const;

  /**
   * Display an address belonging to a registered BIP388 policy and verify the
   * device echoes the same address.
   * @param[in] dest                 expected destination
   * @param[in] signer               external signer to talk to
   * @param[in] name                 registered policy name
   * @param[in] descriptor_template  BIP388 descriptor template (with @N placeholders)
   * @param[in] keys_info            key with origin for each @N participant
   * @param[in] hmac                 hex hmac the device returned at registration time
   * @param[in] change               whether `dest` lives on the change chain
   * @param[in] index                address index within the chain
   */
  util::Result<void> DisplayAddressPolicy(const CTxDestination& dest,
                                          const ExternalSigner& signer,
                                          const std::string& name,
                                          const std::string& descriptor_template,
                                          const std::vector<std::string>& keys_info,
                                          const std::string& hmac,
                                          bool change,
                                          uint32_t index) const;

  std::optional<common::PSBTError> FillPSBT(PartiallySignedTransaction& psbt, const PrecomputedTransactionData& txdata, std::optional<int> sighash_type = std::nullopt, bool sign = true, bool bip32derivs = false, int* n_signed = nullptr, bool finalize = true) const override;

  /**
   * Sign a PSBT through an external signer scoped to a registered
   * BIP388 wallet policy. Used for descriptors (e.g. MuSig2) that
   * require the policy + hmac to be present at sign time so the device
   * can verify the request against what was registered. Mirrors
   * `DisplayAddressPolicy` for the signing path.
   * @param[in,out] psbt                PSBT to fill / sign
   * @param[in]     txdata              precomputed sighash data
   * @param[in]     sighash_type        sighash type to use when signing
   * @param[in]     sign                whether to sign
   * @param[in]     bip32derivs         whether to fill bip32 derivation info
   * @param[out]    n_signed            number of inputs signed by this SPKM
   * @param[in]     finalize            whether to finalize if possible
   * @param[in]     signer              external signer to talk to
   * @param[in]     name                registered policy name
   * @param[in]     descriptor_template BIP388 descriptor template
   * @param[in]     keys_info           key with origin for each @N participant
   * @param[in]     hmac                hex hmac the device returned at registration time
   */
  std::optional<common::PSBTError> FillPSBTPolicy(PartiallySignedTransaction& psbt,
                                                  const PrecomputedTransactionData& txdata,
                                                  std::optional<int> sighash_type,
                                                  bool sign,
                                                  bool bip32derivs,
                                                  int* n_signed,
                                                  bool finalize,
                                                  ExternalSigner& signer,
                                                  const std::string& name,
                                                  const std::string& descriptor_template,
                                                  const std::vector<std::string>& keys_info,
                                                  const std::string& hmac) const;

  /**
   * Register BIP388 wallet policy.
   * @param[in] name policy name to display on the signer
   * @param[in] descriptor_template BIP388 descriptor template
   * @param[in] keys_info key with origin for each participant
   * @returns hmac or an error message
   */
  util::Result<std::string> RegisterPolicy(const ExternalSigner& signer,
                                           const std::string& name,
                                           const std::string& descriptor_template,
                                           const std::vector<std::string>& keys_info) const;
};
} // namespace wallet
#endif // BITCOIN_WALLET_EXTERNAL_SIGNER_SCRIPTPUBKEYMAN_H
