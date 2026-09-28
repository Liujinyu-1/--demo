from __future__ import annotations

import json
from copy import deepcopy

from crypto_utils import canonical_json, field, sm3_hex


def block_digest(height: int, previous_hash: str, tx_type: str, payload: dict, timestamp: str) -> str:
    return sm3_hex(
        b"\x40"
        + height.to_bytes(8, "big")
        + field(previous_hash)
        + field(tx_type)
        + field(canonical_json(payload))
        + field(timestamp)
    )


def block_digest_v2(
    height: int,
    previous_hash: str,
    batch_id: str,
    stage: str,
    tx_type: str,
    data_hash: str,
    state_hash: str,
    business_previous_hash: str,
    timestamp: str,
) -> str:
    """计算V2区块头哈希；任何头字段或区块体变化都会改变结果。"""
    return sm3_hex(
        b"\x41"
        + field("LOTTERY-BLOCK-V2")
        + height.to_bytes(8, "big")
        + field(bytes.fromhex(previous_hash))
        + field(batch_id)
        + field(stage)
        + field(tx_type)
        + field(bytes.fromhex(data_hash))
        + field(bytes.fromhex(state_hash))
        + field(bytes.fromhex(business_previous_hash))
        + field(timestamp)
    )


STAGES = {
    "GENESIS": "SYSTEM",
    "CREATE_BATCH": "RULE",
    "REGISTER": "REGISTRATION",
    "REVIEW": "REGISTRATION",
    "CLOSE": "CLOSED",
    "FREEZE": "FROZEN",
    "BEACON": "RANDOM_READY",
    "DRAW": "DRAWN",
    "AUDIT": "AUDITED",
}


def append_block(
    conn,
    tx_type: str,
    payload: dict,
    timestamp: str,
    state_snapshot: dict | None = None,
) -> str:
    last = conn.execute(
        "SELECT height, block_hash FROM ledger_blocks ORDER BY height DESC LIMIT 1"
    ).fetchone()
    height = 0 if last is None else last["height"] + 1
    previous_hash = "0" * 64 if last is None else last["block_hash"]
    stored_payload = deepcopy(payload)
    stored_payload["state_snapshot"] = state_snapshot or {}
    batch_id = str(stored_payload.get("batch_id", "__SYSTEM__"))
    stage = str((state_snapshot or {}).get("status") or STAGES.get(tx_type, tx_type))
    business_last = conn.execute(
        "SELECT block_hash FROM ledger_blocks WHERE batch_id=? "
        "ORDER BY height DESC LIMIT 1",
        (batch_id,),
    ).fetchone()
    business_previous_hash = (
        "0" * 64 if business_last is None else business_last["block_hash"]
    )
    data_hash = sm3_hex(canonical_json(stored_payload))
    state_hash = sm3_hex(canonical_json(stored_payload["state_snapshot"]))
    block_hash = block_digest_v2(
        height,
        previous_hash,
        batch_id,
        stage,
        tx_type,
        data_hash,
        state_hash,
        business_previous_hash,
        timestamp,
    )
    conn.execute(
        """INSERT INTO ledger_blocks(
            height, previous_hash, tx_type, payload_json, timestamp, block_hash,
            batch_id, stage, data_hash, state_hash, business_previous_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            height,
            previous_hash,
            tx_type,
            canonical_json(stored_payload).decode("utf-8"),
            timestamp,
            block_hash,
            batch_id,
            stage,
            data_hash,
            state_hash,
            business_previous_hash,
        ),
    )
    return block_hash


def verify_ledger(conn) -> tuple[bool, str]:
    previous = "0" * 64
    business_previous: dict[str, str] = {}
    rows = conn.execute("SELECT * FROM ledger_blocks ORDER BY height").fetchall()
    for expected_height, row in enumerate(rows):
        if row["height"] != expected_height:
            return False, f"区块高度不连续：期望{expected_height}，实际{row['height']}"
        if row["previous_hash"] != previous:
            return False, f"第{expected_height}块的前序哈希不匹配"
        payload = json.loads(row["payload_json"])
        if row["data_hash"]:
            data_hash = sm3_hex(canonical_json(payload))
            if data_hash != row["data_hash"]:
                return False, f"第{expected_height}块的区块体摘要不匹配"
            state_hash = sm3_hex(canonical_json(payload.get("state_snapshot", {})))
            if state_hash != row["state_hash"]:
                return False, f"第{expected_height}块的状态摘要不匹配"
            batch_id = row["batch_id"] or "__SYSTEM__"
            expected_business_previous = business_previous.get(batch_id, "0" * 64)
            if row["business_previous_hash"] != expected_business_previous:
                return False, f"第{expected_height}块的批次业务前序哈希不匹配"
            expected = block_digest_v2(
                row["height"],
                row["previous_hash"],
                batch_id,
                row["stage"],
                row["tx_type"],
                row["data_hash"],
                row["state_hash"],
                row["business_previous_hash"],
                row["timestamp"],
            )
            business_previous[batch_id] = row["block_hash"]
        else:
            # V1记录仍可验证，便于从旧项目平滑升级。
            expected = block_digest(
                row["height"], row["previous_hash"], row["tx_type"], payload, row["timestamp"]
            )
            legacy_batch_id = str(payload.get("batch_id", "__SYSTEM__"))
            business_previous[legacy_batch_id] = row["block_hash"]
        if expected != row["block_hash"]:
            return False, f"第{expected_height}块内容被修改"
        previous = row["block_hash"]
    return True, f"{len(rows)}个区块的全局链与批次业务链全部通过校验"


def export_chain(conn, batch_id: str | None = None) -> list[dict]:
    sql = "SELECT * FROM ledger_blocks"
    params: tuple = ()
    if batch_id is not None:
        sql += " WHERE batch_id=?"
        params = (batch_id,)
    sql += " ORDER BY height"
    return [
        {
            "height": row["height"],
            "previous_hash": row["previous_hash"],
            "block_hash": row["block_hash"],
            "batch_id": row["batch_id"],
            "stage": row["stage"],
            "tx_type": row["tx_type"],
            "timestamp": row["timestamp"],
            "data_hash": row["data_hash"],
            "state_hash": row["state_hash"],
            "business_previous_hash": row["business_previous_hash"],
            "payload": json.loads(row["payload_json"]),
        }
        for row in conn.execute(sql, params).fetchall()
    ]


def find_payload(conn, tx_type: str, batch_id: str) -> dict | None:
    rows = conn.execute(
        "SELECT payload_json FROM ledger_blocks WHERE tx_type=? ORDER BY height DESC",
        (tx_type,),
    ).fetchall()
    for row in rows:
        payload = json.loads(row["payload_json"])
        if payload.get("batch_id") == batch_id:
            return payload
    return None
