#!/usr/bin/env python3
# Copyright (c) 2026 Sjors Provoost
# Distributed under the BSD 2-Clause License.
"""Independent, variable-time reference for the interactive anti-exfil draft.

This code is for specification and test-vector generation, not production signing.
The ordinary BIP340 signature it produces has no anti-exfil data on chain.
"""

import hashlib

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y != v or y == 0):
        return None
    if a == b:
        slope = 3 * x * x * pow(2 * y, -1, P) % P
    else:
        slope = (v - y) * pow(u - x, -1, P) % P
    new_x = (slope * slope - x - u) % P
    return new_x, (slope * (x - new_x) - y) % P


def point_mul(k, point=G):
    result = None
    while k:
        if k & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        k >>= 1
    return result


def b32(value):
    return value.to_bytes(32, "big")


def tagged_hash(tag, data):
    digest = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(digest + digest + data).digest()


def scalar(data):
    if len(data) != 32 or not 1 <= int.from_bytes(data, "big") < N:
        raise ValueError("scalar must be 32 bytes in [1, n-1]")
    return int.from_bytes(data, "big")


def compressed(point):
    if point is None:
        raise ValueError("point at infinity")
    return bytes([2 + point[1] % 2]) + b32(point[0])


def parse_point(encoded):
    if len(encoded) != 33 or encoded[0] not in (2, 3):
        raise ValueError("invalid compressed point")
    x = int.from_bytes(encoded[1:], "big")
    if x >= P:
        raise ValueError("invalid x coordinate")
    square = (x * x * x + 7) % P
    y = pow(square, (P + 1) // 4, P)
    if y * y % P != square:
        raise ValueError("point not on curve")
    if y % 2 != encoded[0] % 2:
        y = P - y
    return x, y


def normalized_key(secret_key):
    secret = scalar(secret_key)
    point = point_mul(secret)
    if point[1] % 2:
        secret = N - secret
        point = point[0], P - point[1]
    return secret, point


def host_commit(rho):
    scalar(rho)
    return tagged_hash("BIP-EXFIL/host", rho)


def original_nonce(secret_key, message, host_commitment):
    if len(message) != 32 or len(host_commitment) != 32:
        raise ValueError("message and commitment must be 32 bytes")
    secret, point = normalized_key(secret_key)
    mask = tagged_hash("BIP0340/aux", host_commitment)
    masked = bytes(a ^ b for a, b in zip(b32(secret), mask))
    nonce_hash = tagged_hash("BIP-EXFIL/nonce", masked + b32(point[0]) + message)
    nonce = int.from_bytes(nonce_hash, "big") % N
    if nonce == 0:
        raise ValueError("zero original nonce")
    return nonce


def signer_commit(secret_key, message, host_commitment):
    return compressed(point_mul(original_nonce(secret_key, message, host_commitment)))


def bip340_verify(public_key, message, signature):
    try:
        if len(public_key) != 32 or len(message) != 32 or len(signature) != 64:
            return False
        point = parse_point(b"\x02" + public_key)
        x = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        if x >= P or s >= N:
            return False
        challenge_hash = tagged_hash("BIP0340/challenge", signature[:32] + public_key + message)
        challenge = int.from_bytes(challenge_hash, "big") % N
        result = point_add(point_mul(s), point_mul(N - challenge, point))
        return result is not None and result[1] % 2 == 0 and result[0] == x
    except ValueError:
        return False


def signer_sign(secret_key, message, rho):
    secret, public = normalized_key(secret_key)
    nonce = (original_nonce(secret_key, message, host_commit(rho)) + scalar(rho)) % N
    if nonce == 0:
        raise ValueError("zero combined nonce")
    point = point_mul(nonce)
    if point[1] % 2:
        nonce = N - nonce
    challenge_hash = tagged_hash("BIP0340/challenge", b32(point[0]) + b32(public[0]) + message)
    challenge = int.from_bytes(challenge_hash, "big") % N
    signature = b32(point[0]) + b32((nonce + challenge * secret) % N)
    if not bip340_verify(b32(public[0]), message, signature):
        raise ValueError("signature verification failed")
    return signature


def host_verify(public_key, message, rho, signer_nonce, signature):
    try:
        combined = point_add(parse_point(signer_nonce), point_mul(scalar(rho)))
        return (
            combined is not None
            and signature[:32] == b32(combined[0])
            and bip340_verify(public_key, message, signature)
        )
    except ValueError:
        return False
