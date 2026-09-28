"""生成一个包含128名参与者的完整多区块摇号证据链。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app import create_app
from database import connect
from ledger import export_chain, verify_ledger


def parse_args():
    parser = argparse.ArgumentParser(description="生成128人多区块摇号演示")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("multiblock_output"),
        help="数据库、名单和区块链JSON的输出目录",
    )
    parser.add_argument("--participants", type=int, default=128)
    parser.add_argument("--winners", type=int, default=8)
    return parser.parse_args()


def main():
    args = parse_args()
    if args.participants < args.winners or args.winners < 1:
        raise SystemExit("参与人数必须不少于中签人数，且中签人数至少为1")

    args.output.mkdir(parents=True, exist_ok=True)
    database_path = args.output / "multiblock_chain.sqlite3"
    if database_path.exists():
        raise SystemExit(
            f"{database_path} 已存在。请换一个 --output 目录，以免覆盖已有证据链。"
        )

    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database_path),
            "BEACON_KEY": str(args.output / "demo_beacon_ed25519.key"),
            "MANIFEST_DIR": str(args.output / "manifests"),
            "SECRET_KEY": "multiblock-demo-only",
        }
    )
    client = app.test_client()
    batch_id = "MULTIBLOCK-128-001"
    client.post(
        "/batches",
        data={
            "batch_id": batch_id,
            "title": "128人多区块公平摇号演示",
            "winner_count": str(args.winners),
            "beacon_round": "2026092801",
        },
    )
    with connect(database_path) as db:
        batch = db.execute(
            "SELECT * FROM batches WHERE batch_id=?", (batch_id,)
        ).fetchone()

    for index in range(1, args.participants + 1):
        client.post(
            f"/batches/{batch['id']}/register",
            data={
                "name": f"模拟参与者{index:03d}",
                "id_number": f"SIM-ID-{index:06d}",
                "contact": f"139{index:08d}",
            },
        )

    with connect(database_path) as db:
        participant_ids = [
            row["id"]
            for row in db.execute(
                "SELECT id FROM participants WHERE batch_db_id=? ORDER BY id",
                (batch["id"],),
            )
        ]
    for participant_id in participant_ids:
        client.post(f"/participants/{participant_id}/approve")

    client.post(f"/batches/{batch['id']}/close")
    client.post(f"/batches/{batch['id']}/freeze")
    client.post(f"/batches/{batch['id']}/beacon")
    client.post(f"/batches/{batch['id']}/draw")
    client.post(f"/batches/{batch['id']}/seal-audit")

    with connect(database_path) as db:
        valid, detail = verify_ledger(db)
        blocks = export_chain(db)
        batch_blocks = [block for block in blocks if block["batch_id"] == batch_id]
        latest_batch = db.execute(
            "SELECT * FROM batches WHERE id=?", (batch["id"],)
        ).fetchone()

    export_path = args.output / "chain_export.json"
    export_path.write_text(
        json.dumps(
            {
                "valid": valid,
                "detail": detail,
                "batch_id": batch_id,
                "batch_status": latest_batch["status"],
                "global_block_count": len(blocks),
                "batch_block_count": len(batch_blocks),
                "blocks": blocks,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"整链验证：{valid}，{detail}")
    print(f"批次状态：{latest_batch['status']}")
    print(f"全局区块数：{len(blocks)}，本批次区块数：{len(batch_blocks)}")
    print(f"数据库：{database_path.resolve()}")
    print(f"区块链JSON：{export_path.resolve()}")


if __name__ == "__main__":
    main()
