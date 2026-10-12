# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

@0x9d361755b28835a4;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("ipc::capnp::messages");

using Proxy = import "/mp/proxy.capnp";
$Proxy.include("interfaces/external_signer.h");
$Proxy.includeTypes("ipc/capnp/signer-types.h");

struct SignerInfo $Proxy.wrap("interfaces::ExternalSignerInfo") {
    fingerprint @0 :Text;
    name @1 :Text;
}

# External signing service (e.g. HWI), registered by a client via
# Init.registerExternalSigner. The node is the caller of these methods, from
# worker threads, so no Proxy.Context parameters are needed. There is no
# destroy method: the capability lives for as long as the registration, and
# its teardown must not make remote calls.
interface ExternalSignerService $Proxy.wrap("interfaces::ExternalSignerService") {
    enumerate @0 (chain :Text) -> (result :List(SignerInfo));
    getDescriptors @1 (fingerprint :Text, chain :Text, account :Int32) -> (receive :List(Text), internal :List(Text), error :Text, result :Bool);
    displayAddress @2 (fingerprint :Text, chain :Text, descriptor :Text) -> (address :Text, error :Text, result :Bool);
    signTransaction @3 (fingerprint :Text, chain :Text, psbt :Data) -> (signedPsbt :Data, error :Text, result :Bool);
}
