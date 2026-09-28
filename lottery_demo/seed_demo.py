"""Create one completed sample lottery in an empty/default database."""

from app import app
from database import connect


SAMPLE = [
    ("张三", "330100200001010001", "13800000001"),
    ("李四", "330100200001010002", "13800000002"),
    ("王五", "330100200001010003", "13800000003"),
    ("赵六", "330100200001010004", "13800000004"),
    ("陈七", "330100200001010005", "13800000005"),
    ("周八", "330100200001010006", "13800000006"),
]


def main():
    client = app.test_client()
    with connect(app.config["DATABASE"]) as db:
        existing = db.execute("SELECT id FROM batches WHERE batch_id='DEMO-2026-001'").fetchone()
    if existing:
        print("示例批次已存在，请直接运行 python app.py")
        return

    client.post(
        "/batches",
        data={
            "batch_id": "DEMO-2026-001",
            "title": "公平可验证摇号演示",
            "winner_count": "2",
            "beacon_round": "1001",
        },
    )
    with connect(app.config["DATABASE"]) as db:
        batch = db.execute("SELECT * FROM batches WHERE batch_id='DEMO-2026-001'").fetchone()

    for name, id_number, contact in SAMPLE:
        client.post(
            f"/batches/{batch['id']}/register",
            data={"name": name, "id_number": id_number, "contact": contact},
        )

    with connect(app.config["DATABASE"]) as db:
        ids = [row["id"] for row in db.execute("SELECT id FROM participants WHERE batch_db_id=?", (batch["id"],))]
    for participant_id in ids:
        client.post(f"/participants/{participant_id}/approve")

    client.post(f"/batches/{batch['id']}/close")
    client.post(f"/batches/{batch['id']}/freeze")
    client.post(f"/batches/{batch['id']}/beacon")
    client.post(f"/batches/{batch['id']}/draw")
    result = client.get(f"/api/batches/{batch['id']}/audit").get_json()
    print(f"示例批次已生成：{result['batch_id']}，审计通过={result['passed']}")
    print("请运行 python app.py，然后访问 http://127.0.0.1:5000")


if __name__ == "__main__":
    main()

