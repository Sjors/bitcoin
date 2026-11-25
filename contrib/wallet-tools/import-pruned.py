#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Restore wallet transactions on a pruned node.

A pruned node cannot rescan blocks it has already deleted, so a descriptor
that is imported into a fresh wallet with an old timestamp ends up with no
transaction history. This tool reconstructs the missing transactions from
other sources and hands them to the wallet with the `importprunedfunds` RPC,
which only needs the raw transaction and a merkle proof against a block
header the node still has.

Modes:

  --utxo    Scan the node's own UTXO set with `scantxoutset` using the
            wallet's descriptors. For every unspent output found, fetch the
            containing block from a peer with `getblockfrompeer` when it has
            been pruned, build the proof with `gettxoutproof` and import the
            transaction. This restores every coin the wallet currently owns,
            so the balance is correct, but transactions that were fully
            spent before the scan are not recovered.

The node is reached through bitcoin-cli, so pass the same network and
connection options you would pass on the command line:

  import-pruned.py --cli "bitcoin-cli -signet" --wallet restored --utxo
"""

import argparse
import json
import logging
import re
import shlex
import subprocess
import sys
import time
from decimal import Decimal
from typing import Any, Optional

# Peers advertising NODE_NETWORK_LIMITED only serve the most recent blocks,
# so historical blocks have to come from a NODE_NETWORK peer.
REQUIRED_SERVICES = {"NETWORK", "WITNESS"}


class RpcError(Exception):
    def __init__(self, code: Optional[int], message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class BitcoinCli:
    def __init__(self, basecmd: list[str], wallet: Optional[str]):
        self.basecmd = basecmd
        self.wallet = wallet

    def __call__(self, *args: Any, wallet: bool = False) -> Any:
        cmd = list(self.basecmd)
        if wallet and self.wallet is not None:
            cmd.append(f"-rpcwallet={self.wallet}")
        cmd += [arg if isinstance(arg, str) else json.dumps(arg) for arg in args]
        logging.debug("Calling bitcoin-cli: %r", cmd)
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            err = res.stderr.strip()
            m = re.match(r"error code: (-?\d+)\s*error message:\s*(.*)", err, re.DOTALL)
            if m:
                raise RpcError(int(m.group(1)), m.group(2).strip())
            raise RpcError(None, err or f"bitcoin-cli exited with status {res.returncode}")
        out = res.stdout.strip()
        try:
            return json.loads(out, parse_float=Decimal)
        except json.JSONDecodeError:
            return out


class Unspent:
    def __init__(self, obj: dict[str, Any]):
        self.txid: str = obj["txid"]
        self.vout: int = obj["vout"]
        self.amount: Decimal = obj["amount"]
        self.height: int = obj["height"]
        self.blockhash: str = obj["blockhash"]
        self.desc: str = obj["desc"]
        self.index = derivation_index(self.desc)


def derivation_index(desc: str) -> int:
    """Best-effort extraction of the child index from the key origin of a
    specialized descriptor as returned by scantxoutset, e.g.
    wpkh([d34db33f/84h/0h/0h/0/5]02...)#checksum -> 5. Used only to order
    imports so that the wallet's keypool is topped up in the same order a
    rescan would, so a wrong guess merely costs an extra pass."""
    m = re.search(r"\[[0-9a-fA-F]{8}((?:/[0-9]+['h]?)+)\]", desc)
    if not m:
        return 0
    last = m.group(1).rsplit("/", 1)[1]
    return int(last.rstrip("'h"))


def select_peers(cli: BitcoinCli, height: int) -> list[int]:
    """Peer ids that can plausibly serve a block at the given height, best
    candidates first."""
    peers = []
    for peer in cli("getpeerinfo"):
        if not REQUIRED_SERVICES.issubset(peer.get("servicesnames", [])):
            continue
        if peer.get("connection_type") in ("feeler", "addr-fetch"):
            continue
        if peer.get("synced_blocks", -1) < height:
            continue
        # Prefer outbound peers, which we selected ourselves.
        rank = 0 if not peer.get("inbound") else 1
        peers.append((rank, peer["id"]))
    return [peer_id for _, peer_id in sorted(peers)]


def get_txoutproof(cli: BitcoinCli, txids: list[str], blockhash: str, height: int, timeout: float) -> Optional[str]:
    """Build a merkle proof for txids, fetching the block from a peer first
    when it has been pruned. Returns None when no peer delivered it."""
    try:
        return cli("gettxoutproof", txids, blockhash)
    except RpcError as e:
        if "not available" not in e.message:
            raise
    peers = select_peers(cli, height)
    if not peers:
        logging.error("No connected peer advertises NODE_NETWORK; cannot fetch block %s", blockhash)
        return None
    for peer_id in peers:
        try:
            cli("getblockfrompeer", blockhash, peer_id)
        except RpcError as e:
            logging.warning("getblockfrompeer from peer %d failed: %s", peer_id, e.message)
            continue
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(0.5)
            try:
                # The block may be pruned again at any time, so build the
                # proof as soon as the data is there rather than probing.
                proof = cli("gettxoutproof", txids, blockhash)
            except RpcError as e:
                if "not available" in e.message:
                    continue
                raise
            logging.info("Fetched block %d (%s) from peer %d", height, blockhash, peer_id)
            return proof
        logging.warning("Peer %d did not deliver block %s within %.0fs", peer_id, blockhash, timeout)
    return None


def scan_utxo_set(cli: BitcoinCli, lookahead: int) -> tuple[list[Unspent], dict[str, int]]:
    """Returns the wallet's unspent outputs and, per ranged descriptor, the
    last index that was scanned."""
    descriptors = cli("listdescriptors", wallet=True)["descriptors"]
    if not descriptors:
        sys.exit("The wallet has no descriptors to scan for")
    scanobjects = []
    scan_end: dict[str, int] = {}
    for d in descriptors:
        if "range" in d:
            end = d["range"][1] + lookahead
            scanobjects.append({"desc": d["desc"], "range": [d["range"][0], end]})
            scan_end[d["desc"]] = end
        else:
            scanobjects.append(d["desc"])
    logging.info("Scanning the UTXO set for %d descriptor(s); this can take a while", len(scanobjects))
    result = cli("scantxoutset", "start", scanobjects)
    if not result["success"]:
        sys.exit("scantxoutset did not complete")
    unspents = [Unspent(u) for u in result["unspents"]]
    logging.info("Found %d unspent output(s) totalling %s at height %d",
                 len(unspents), result["total_amount"], result["height"])
    return unspents, scan_end


def import_utxos(cli: BitcoinCli, unspents: list[Unspent], timeout: float, dry_run: bool) -> int:
    """Import the transactions behind unspents; returns the number of
    outputs that could not be imported."""
    # Import in derivation order so the wallet extends its keypool the way a
    # rescan would; blocks are processed in order of their lowest index.
    unspents.sort(key=lambda u: (u.index, u.height, u.txid, u.vout))
    blocks: dict[str, list[Unspent]] = {}
    for u in unspents:
        blocks.setdefault(u.blockhash, []).append(u)

    failures = 0
    pending: list[tuple[Unspent, str, str]] = []  # (unspent, rawtx, proof) deferred to a later pass
    imported: set[str] = set()
    for blockhash, outputs in blocks.items():
        height = outputs[0].height
        txids = sorted({u.txid for u in outputs})
        if dry_run:
            for u in outputs:
                print(f"{u.txid}:{u.vout} {u.amount} height={u.height} index={u.index}")
            continue
        known = []
        for txid in txids:
            try:
                cli("gettransaction", txid, wallet=True)
                known.append(txid)
            except RpcError:
                pass
        if known:
            logging.info("Skipping %d transaction(s) in block %d already in the wallet", len(known), height)
            imported.update(known)
        txids = [t for t in txids if t not in known]
        if not txids:
            continue
        proof = get_txoutproof(cli, txids, blockhash, height, timeout)
        if proof is None:
            logging.error("Could not obtain block %d (%s); skipping %d transaction(s)", height, blockhash, len(txids))
            failures += len(txids)
            continue
        for txid in txids:
            rawtx = cli("getrawtransaction", txid, False, blockhash)
            u = next(o for o in outputs if o.txid == txid)
            try:
                cli("importprunedfunds", rawtx, proof, wallet=True)
                imported.add(txid)
                logging.info("Imported %s (block %d)", txid, height)
            except RpcError as e:
                if "No addresses in wallet correspond" in e.message:
                    pending.append((u, rawtx, proof))
                else:
                    logging.error("importprunedfunds failed for %s: %s", txid, e.message)
                    failures += 1

    # Earlier imports may have extended the keypool far enough for these.
    while pending:
        progress = False
        remaining = []
        for u, rawtx, proof in pending:
            try:
                cli("importprunedfunds", rawtx, proof, wallet=True)
                imported.add(u.txid)
                progress = True
                logging.info("Imported %s (block %d) on retry", u.txid, u.height)
            except RpcError:
                remaining.append((u, rawtx, proof))
        pending = remaining
        if not progress:
            for u, _, _ in pending:
                logging.error("Wallet does not recognize %s:%d (index %d); the gap to the previous used "
                              "index exceeds the keypool size", u.txid, u.vout, u.index)
            failures += len(pending)
            break

    if not dry_run:
        total = sum(u.amount for u in unspents if u.txid in imported)
        logging.info("%d transaction(s) in the wallet, %d output(s) worth %s; %d failure(s)",
                     len(imported), sum(1 for u in unspents if u.txid in imported), total, failures)
    return failures


def check_lookahead(cli: BitcoinCli, scan_end: dict[str, int]) -> None:
    """The imports extend the wallet's keypool. If it now reaches beyond what
    was scanned, there may be further outputs we did not look for."""
    for d in cli("listdescriptors", wallet=True)["descriptors"]:
        if "range" in d and d["desc"] in scan_end and d["range"][1] > scan_end[d["desc"]]:
            logging.warning("The keypool of %s now extends to index %d but only indexes up to %d were "
                            "scanned; rerun to pick up any outputs beyond that", d["desc"], d["range"][1], scan_end[d["desc"]])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cli", default="bitcoin-cli", help="bitcoin-cli command, including network and connection options")
    parser.add_argument("--wallet", help="wallet to import into (-rpcwallet)")
    parser.add_argument("--utxo", action="store_true", help="restore unspent outputs from the node's UTXO set")
    parser.add_argument("--lookahead", type=int, default=1000,
                        help="scan this many indexes beyond each descriptor's current range (default: %(default)s)")
    parser.add_argument("--timeout", type=float, default=60, help="seconds to wait for a peer to deliver a block (default: %(default)s)")
    parser.add_argument("--dry-run", action="store_true", help="list what would be imported without fetching blocks or importing")
    parser.add_argument("--debug", action="store_true", help="print every bitcoin-cli invocation")
    parser.add_argument("--quiet", action="store_true", help="only print warnings and errors")
    args = parser.parse_args()

    logging.basicConfig(format="%(levelname)s: %(message)s",
                        level=logging.DEBUG if args.debug else logging.WARNING if args.quiet else logging.INFO)

    if not args.utxo:
        parser.error("no mode selected; use --utxo")

    cli = BitcoinCli(shlex.split(args.cli), args.wallet)
    try:
        info = cli("getblockchaininfo")
        if info["initialblockdownload"]:
            sys.exit("Node is still in initial block download")
        if not info["pruned"]:
            logging.warning("Node is not pruned; a plain rescanblockchain would restore full history")
        unspents, scan_end = scan_utxo_set(cli, args.lookahead)
        failures = import_utxos(cli, unspents, args.timeout, args.dry_run)
        if not args.dry_run:
            check_lookahead(cli, scan_end)
    except RpcError as e:
        sys.exit(f"RPC error: {e.message}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
