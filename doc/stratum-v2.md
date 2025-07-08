# Stratum v2

## Design

The Stratum v2 protocol specification can be found here: https://stratumprotocol.org/specification

Bitcoin Core (or a sidecar application connected to it via IPC) performs the
Template Provider role, and for that it implements the Template Distribution
Protocol. When launched with `-sv2` we listen for connections from either a
Job Declarator client (JDF) or a Pool (pool default template or for solo mining).

A JDC probably runs on the same machine. A different possible use case is where
a miner relies on a node run by someone else to provide the templates. This is
currently not safe for the node operator, see the section on DoS.

The Template Provider send the JDC (or Pool) a new block template whenever our
tip is updated, or when mempool fees have increased sufficiently. If the pool
finds a block, we attempt to broadcast it based on a cached template.

Communication with other roles uses the Noise Protocol, which has been implemented
to the extent necessary.

### Advantage over getblocktemplate RPC

Although under the hood the Template Provider uses `CreateNewBlock()` just like
the `getblocktemplate` RPC, there's a number of advantages in running a
server with a stateful connection, and avoiding JSON RPC in general.

1. Stateful, so we can have back-and-forth, e.g. requesting transaction data,
   processing a block solution.
2. Less (de)serializing and data sent over the wire, compared to plain text JSON
3. Encrypted, safer (for now: less unsafe) to expose on the public internet
4. Push based: new template is sent immediately when a new block is found rather
   than at the next poll interval. Combined with Cluster Mempool this can
   hopefully be done for higher fee templates too.
5. Low friction deployment with other Stratum v2 software / devices

### Message flow(s)

See the [Message Types](https://stratumprotocol.org/specification/08-Message-Types/)
and [Protocol Overview](https://stratumprotocol.org/specification/03-Protocol-Overview/)
section of the spec for all messages and their details.

When a Job Declarator client connects to us, it first sends a  `SetupConnection`
message. We reply with `SetupConnection.Success` unless something went wrong,
e.g. version mismatch, in which case we reply with `SetupConnection.Error`.

Next the client sends us their `CoinbaseOutputConstraints`. If this is invalid
we disconnect. Otherwise we start the cycle below that repeats with every block.

We send a `NewTemplate` message with `future_template` set `true`, immedidately
followed by `SetNewPrevHash`. We _don't_ send any transaction information
at this point. The Job Declarator client uses this to announce upstream that
it wants to declare a new template.

In the simplest setup with SRI the Job Declarator client doubles as a proxy and
sends these two messages to all connected mining devices. They will keep
working on their previous job until the `SetNewPrevHash` message arrives.
Future implementations could provide an empty or speculative template before
a new block is found.

Meanwhile the pool will request, via the Job Declarator client, the transaction
lists belonging to the template: `RequestTransactionData`. In case of a problem
we reply with `RequestTransactionData.Error`. Otherwise we reply with the full[0]
transaction data in `RequestTransactionData.Success`.

When we find a template with higher fees, we send a `NewTemplate` message
with `future_template` set to `false`. This is _not_ followed by `SetNewPrevHash`.

Finally, if we find an actual block, the client sends us `SubmitSolution`.
We then lookup the template (may not be the most recent one), reconstruct
the block and broadcast it. The pool will do the same.

`[0]`: When the Job Declarator client communicates with the Job Declarator
server there is an intermediate message which sends short transaction ids
first, followed by a `ProvideMissingTransactions` message. The spec could be
modified to introduce a similar message here. This is especially useful when
the Template Provider runs on a different machine than the Job Declarator
client. Erlay might be useful here too, in a later stage.

### Noise Protocol

As detailed in the [Protocol Security](https://stratumprotocol.org/specification/04-Protocol-Security/)
section of the spec, Stratum v2 roles use the Noise Protocol to communicate.

We only implement the parts needed for inbound connections, although not much
code would be needed to support outbound connections as well if this is required later.

The spec was written before BIP 324 peer-to-peer encryption was introduced. It
has much in common with Noise, but for the purposes of Stratum v2 it currently
lacks authentication. Perhaps a future version of Stratum will use this. Since
we only communicate with the Job Declarator role, a transition to BIP 324 would
not require waiting for the entire mining ecosystem to adopt it.

An alternative to implementing the Noise Protocol in Bitcoin Core is to use a
unix socket instead and rely on the user to install a separate tool to convert
to this protocol. This approach is implemented in https://github.com/Sjors/bitcoin/pull/48,
but could also be provided as part of SRI.

### Mempool monitoring

The current design calls `CreateNewBlock()` internally every `-sv2interval` seconds.
We then broadcast the resulting block template if fees have increased enough to make
it worth the overhead (`-sv2feedelta`). A pool may have additional rate limiting in
place.

This is better than the Stratum v1 model of a polling call to the `getblocktemplate` RPC.
It avoids (de)serializing JSON, uses an encrypted connection and only sends data
over the wire if fees increased.

But it's still a poll based model, as opposed to the push based approach
whenever a new block arrives. It would be better if a new template is generated
as soon as a potentially revenue-increasing transaction is added to the mempool.
The Cluster Mempool project might enable that.

### DoS and privacy

The current Template Provider should not be run on the public internet with
unlimited access. It is not hardened against DoS attacks, nor against mempool probing.

There's currently no limit to the number of Job Declarator clients that can connect,
which could exhaust memory. There's also no limit to the amount of raw transaction
data that can be requested.

Templates reveal what is in the mempool without any delay or randomization.

Future improvements should aim to reduce or eliminate the above concerns such
that any node can run a Template Provider as a public service.

## Usage

Using this in a production environment is not yet recommended, but see the testing guide below.

### Build

Follow the instructions in [build-unix.md](build-unix.md), [build-osx.md](build-osx.md).

### Parameters

See also `bitcoind --help`.

Start Bitcoin Core with `-sv2` to start a Template Provider server with default settings.
The listening port can be changed with `-sv2port`.

By default it only accepts connections from localhost. This can be changed
using `-sv2bind`. See DoS and Privacy above.

Use `-debug=sv2` to see Stratum v2 related log messages. Set `-loglevel=sv2:trace`
to see which messages are exchanged with the Job Declarator client.

The frequency at which new templates are generated can be controlled with
`-sv2interval`. The new templates are only submitted to connected clients if
they are for a new block, or if fees have increased by at least `-sv2feedelta`.

You may increase `-sv2interval`` to something your node can handle, and then
adjust `-sv2feedelta` to limit back and forth with the pool.

## Testing Guide

Unfortunately testing still requires quite a few moving parts, and each setup has
its own merits and issues.

To get help with the stratum side of things, this Discord may be useful: https://discord.gg/fsEW23wFYs

The Stratum Reference Implementation (SRI) provides example implementations of
the various (other) Stratum v2 roles: https://github.com/stratum-mining/stratum

You can set up an entire pool on your own machine. You can also connect to an
existing pool and only run a limited set of roles on your machine, e.g. the
Job Declarator client and Translator (v1 to v2).

SRI includes a v1 and v2 CPU miner, but at the time of writing neither seems to work.
Another CPU miner that does work, when used with the Translator: https://github.com/pooler/cpuminer

### Regtest

TODO

This is also needed for functional test suite coverage. It's also the only test
network doesn't need a standalone CPU miner or ASIC.

Perhaps a mock Job Declarator client can be added. We also need a way mine a given
block template, akin to `generate`.

To make testing easier it should be possible to use a connection without Noise Protocol.

### Testnet

The difficulty on testnet4 varies wildly, but typically much too high for CPU mining.
Even when using a relatively cheap second hand miner, e.g. an S9, it could take
weeks to find a block.

The above means it's difficult to test the `SubmitSolution` message.

#### Bring your own ASIC, use external testnet pool

This uses an existing testnet pool. There's no need to create an account anywhere.
The pool does not pay out the testnet coins it generates. It also currently
doesn't censor anything, so you can't test the (solo mining) fallback behavior.

First start the node:

```
build/bin/bitcoind -testnet4 -sv2 -debug=sv2
```

Build and run a Job Declarator client: [stratum-mining/stratum/tree/main/roles/jd-client](https://github.com/stratum-mining/stratum/tree/main/roles/jd-client

This client connects to your node to receive new block templates and then "declares"
them to a Job Declarator server. Additionally it connects to the pool itself.

Copy [jdc-config-hosted-example.toml](https://github.com/stratum-mining/stratum/blob/main/roles/jd-client/config-examples/jdc-config-hosted-example.toml)
to e.g. `~/.stratum/testnet4-jdc.toml`, change `tp_address` to `127.0.0.1:48336` and comment out `tp_authority_public_key`.

The `coinbase_outputs` is used for fallback to solo mining. Generate an address
of any type and then use the `getaddressinfo` RPC to find its public key.

Finally you most likely need to use the v1 to v2 translator: [stratum-mining/stratum/tree/main/roles/translator](https://github.com/stratum-mining/stratum/tree/main/roles/translator),
even when you have a stratum v2 capable miner (see notes on ASIC's and Firmware below).

You need to point the translator to your job declarator client, which in turn takes
care of connecting to the pool. Try [tproxy-config-local-jdc-example.toml](https://github.com/stratum-mining/stratum/blob/main/roles/translator/tproxy-config-local-jdc-example.toml).

As soon as you turn on the translator, the Bitcoin Core log should show a `SetupConnection` [message](https://github.com/stratum-mining/sv2-spec/blob/main/08-Message-Types.md).

Now point your ASIC to the translator. At this point you should be seeing
`NewTemplate`, `SetNewPrevHash` and `SetNewPrevHash` messages.

If the pool is down, notify someone on the above mentioned Discord.

### SRI Signet

Unlike testnet4, signet(s) use the regular difficulty adjustment mechanism.
Although the default signet has very low difficulty, you can't mine on it,
because to do so requires signing blocks using a private key that only two people have.

The SRI team operates a signet that does not require signatures:

```ini
[signet]
signetchallenge=51      # OP_TRUE
connect=75.119.150.111
```

Unlike regtest this network does have difficulty (adjustment). This allows you to
test if e.g. pool software correctly sets and adjusts the share difficulty for each
participant. Although for the Template Provider role this is not relevant.

You can also create your own custom unsigned signet using the above configuration,
just make to _not_ connect to the SRI signet because it might reorg your own chain.

See [signet/README.md](../contrib/signet/README.md).

#### Mining

The cleanest setup involves two connected nodes, each with their own data
directory: one for the pool and one for the miner. By selectively breaking the
connection you can inspect how unknown transactions in the template are requested
by the pool, and how a newly found block is submitted is submitted both by the
pool and the miner.

However things should work fine with just one node.

Start the miner node first, with a GUI for convenience:

```sh
build/bin/qt/bitcoin-qt -datadir=$HOME/.stratum/bitcoin -signet
```

Suggested config for the pool node:

```ini
[signet]
signetchallenge=51      # OP_TRUE
server=0
listen=0
connect=75.119.150.111  # SRI
```

The above disables its RPC server and p2p listening to avoid a port conflict.

Start the pool node:

```sh
build/bin/bitcoind -datadir=$HOME/.stratum/bitcoin-pool -signet
```

Configure an SRI pool:

```
cd roles/pool
mkdir -p ~/.stratum
cp
```

Start the SRI pool:

```sh
cargo run -p pool_sv2 -- -c ~/.stratum/signet-pool.toml
```

For the Job Declarator _client_ and Translator, see Testnet above.

Now use the [CPU miner](https://github.com/pooler/cpuminer) and point it to the translator:

```
./minerd -a sha256d -o stratum+tcp://localhost:34255 -q -D -P
```

You can also a BitAxe, but please do so only for a few minutes at a time
to prevent increasing the difficulty too much for others.

### Mainnet

See testnet for how to use an external pool. See signet for how to configure your own pool.

Pools that support Stratum v2 on mainnet:

* Braiins: unclear if they are currently compatible with latest spec. URL's are
           listed [here](https://academy.braiins.com/en/braiins-pool/stratum-v2-manual/#servers-and-ports). There's no Job Declarator server.
* DEMAND : No account needed for solo mining. Both the pool and Job Declarator
           server are at `dmnd.work:2000`. Requires a custom SRI branch, see [instructions](https://dmnd.work/#solo-mine).

### Notes on ASIC's and Firmware:

#### BraiinsOS

* v22.08.1 uses an (incompatible) older version of Stratum v2
* v23.12 is untested (and not available on S9)
* v22.08.1 when used in Stratum v1 mode, does not work with the SRI Translator

#### Antminer stock OS

This should work with the Translator, but has not been tested.
