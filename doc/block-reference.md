# Witness v2 Taproot with block references

This document specifies the consensus rules for witness version 2 outputs
with a 32-byte program, as implemented in this prototype. Activation
parameters are out of scope; on regtest the rules are always active.

## Motivation

A transaction that is valid on both sides of a chain split can be replayed.
Holders who want to spend on one side only currently need a coin whose
history already differs between the two chains, such as a coinbase
descendant. A block reference lets any spender opt in to validity on one
chain, at the cost of a few witness bytes, with no coordination with anyone
else.

## Rules

A witness v2 output with a 32-byte program is spent under the
[BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) and
[BIP342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
rules, with one addition.

### Block reference annex

If the spend carries an annex and the first byte after the `0x50` annex
marker is `0x01`, the annex is a *block reference*:

    0x50 || 0x01 || height (4 bytes, little endian) || further bytes (ignored)

An annex shorter than 6 bytes whose second byte is `0x01` makes the spend
invalid. Bytes after the height have no consensus meaning, exactly like the
rest of the annex today. Annexes whose second byte is not `0x01` keep their
BIP341 treatment: no meaning, always valid.

The type byte `0x01` means "this input references the block at `height`".
This document attaches two effects to the reference; future rules may attach
more.

### Maturity and activation

A block containing the transaction at height `H` is invalid unless
`height + 100 <= H` for every block reference in the transaction. The
constant is `COINBASE_MATURITY`. As a consequence the referenced block is at
least 100 deep, and a transaction with a block reference is exactly as safe
against reorganisation as a spend of a matured coinbase output.

A reference to a block below the activation height of these rules is
invalid. Before activation, witness v2 spends are anyone-can-spend and an
annex has no meaning, exactly as for any other undefined witness version;
neither rule in this document applies to blocks before activation. (The
mempool applies the witness v2 rules as policy regardless.)

### Signature message

Every signature checked for an input with a block reference, on the key
path or in tapscript, is over the BIP341 message with `ext_flag` bit 1 set
(so `spend_type` gains the value 4) and the 32-byte hash of the block at
`height` in the active chain appended after the message, after the BIP342
extension if present.

Since the hash of the referenced block is part of the message and not of
the transaction, a signature made for one chain does not verify on any chain
whose block at that height differs, nor on a chain that computes the plain
BIP341 message. An input without a block reference is signed exactly as a
witness v1 input and is valid on every chain.

## Non-consensus considerations

- The annex is committed to by every signature on the input, so a third
  party cannot add, remove, or alter a block reference on a signed input.
  A script-path spend that checks no signature can carry a reference, but
  it then only imposes the maturity rule.
- A transaction with a block reference never expires. It becomes invalid
  only if a reorganisation removes the referenced block, which requires a
  reorganisation of at least 100 blocks.
- Wallets that want a spend to be specific to the current chain should
  reference the most recent eligible block, that is the block at
  `tip - 99`.
- Policy: a block reference annex of exactly 6 bytes is standard for v2
  spends. All other annexes remain non-standard. A transaction whose
  reference is not yet mature is rejected from the mempool with a
  retryable, non-punishable error, like a premature coinbase spend.
