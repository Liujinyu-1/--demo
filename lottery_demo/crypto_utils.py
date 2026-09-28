"""Cryptographic primitives for the verifiable lottery demo.

All hashes are SM3.  Fields are length-prefixed so that concatenation is
unambiguous.  Domain bytes separate commitments, leaves, internal nodes,
empty leaves, seeds, scores, and ledger blocks.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Iterable


def sm3(data: bytes) -> bytes:
    return hashlib.new("sm3", data).digest()


def sm3_hex(data: bytes) -> str:
    return sm3(data).hex()


def field(value: str | bytes) -> bytes:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return len(raw).to_bytes(4, "big") + raw


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def normalize_participant(name: str, id_number: str, contact: str) -> dict[str, str]:
    return {
        "name": " ".join(name.strip().split()),
        "id_number": id_number.strip().upper(),
        "contact": contact.strip(),
    }


def data_commitment(
    batch_id: str,
    name: str,
    id_number: str,
    contact: str,
    salt_hex: str,
) -> str:
    data = normalize_participant(name, id_number, contact)
    payload = (
        b"\x10"
        + field("DATA-V1")
        + field(batch_id)
        + field(canonical_json(data))
        + field(bytes.fromhex(salt_hex))
    )
    return sm3_hex(payload)


def leaf_hash(batch_id: str, lottery_no: str, commitment: str) -> str:
    return sm3_hex(
        b"\x00"
        + field(batch_id)
        + field(lottery_no)
        + field(bytes.fromhex(commitment))
    )


def empty_leaf(batch_id: str, position: int) -> str:
    return sm3_hex(
        b"\x02" + field(batch_id) + position.to_bytes(8, "big", signed=False)
    )


def parent_hash(left_hex: str, right_hex: str) -> str:
    return sm3_hex(b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


@dataclass(frozen=True)
class ProofStep:
    side: str
    hash: str


class MerkleTree:
    def __init__(self, batch_id: str, leaves: Iterable[str]):
        real = list(leaves)
        if not real:
            raise ValueError("默克尔树至少需要一个真实叶子")
        size = 1 << math.ceil(math.log2(len(real))) if len(real) > 1 else 1
        padded = real + [empty_leaf(batch_id, i) for i in range(len(real), size)]
        self.batch_id = batch_id
        self.real_count = len(real)
        self.levels: list[list[str]] = [padded]
        while len(self.levels[-1]) > 1:
            level = self.levels[-1]
            self.levels.append(
                [parent_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
            )

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    def proof(self, index: int) -> list[ProofStep]:
        if not 0 <= index < self.real_count:
            raise IndexError("参与者叶子下标超出范围")
        result: list[ProofStep] = []
        cursor = index
        for level in self.levels[:-1]:
            sibling = cursor ^ 1
            result.append(
                ProofStep(side="right" if cursor % 2 == 0 else "left", hash=level[sibling])
            )
            cursor //= 2
        return result


def verify_proof(leaf: str, proof: Iterable[ProofStep | dict], expected_root: str) -> bool:
    current = leaf
    for item in proof:
        side = item.side if isinstance(item, ProofStep) else item["side"]
        sibling = item.hash if isinstance(item, ProofStep) else item["hash"]
        current = (
            parent_hash(current, sibling)
            if side == "right"
            else parent_hash(sibling, current)
        )
    return current == expected_root


def final_seed(
    batch_id: str, merkle_root: str, beacon_round: int, beacon_randomness: str, rule_hash: str
) -> str:
    return sm3_hex(
        b"\x20"
        + field("LOTTERY-SEED-V1")
        + field(batch_id)
        + field(bytes.fromhex(merkle_root))
        + beacon_round.to_bytes(8, "big", signed=False)
        + field(bytes.fromhex(beacon_randomness))
        + field(bytes.fromhex(rule_hash))
    )


def lottery_score(batch_id: str, seed: str, lottery_no: str) -> str:
    return sm3_hex(
        b"\x30"
        + field("LOTTERY-SCORE-V1")
        + field(batch_id)
        + field(bytes.fromhex(seed))
        + field(lottery_no)
    )

