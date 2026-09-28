from __future__ import annotations

import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from beacon import DemoBeacon
from crypto_utils import (
    MerkleTree,
    canonical_json,
    data_commitment,
    final_seed,
    leaf_hash,
    lottery_score,
    sm3_hex,
    verify_proof,
)
from database import connect, init_database
from ledger import append_block, export_chain, find_payload, verify_ledger


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


STATUS_LABELS = {
    "REGISTRATION": "报名中",
    "CLOSED": "报名已截止",
    "FROZEN": "名单已冻结",
    "RANDOM_READY": "随机数已就绪",
    "DRAWN": "已完成摇号",
    "AUDITED": "已审计封存",
    "ABORTED": "已中止",
}


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    base_dir = Path(__file__).resolve().parent
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("LOTTERY_SECRET", "dev-only-change-me"),
        DATABASE=str(Path(app.instance_path) / "lottery.sqlite3"),
        BEACON_KEY=str(Path(app.instance_path) / "demo_beacon_ed25519.key"),
        MANIFEST_DIR=str(base_dir / "data" / "manifests"),
    )
    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["MANIFEST_DIR"]).mkdir(parents=True, exist_ok=True)
    init_database(app.config["DATABASE"])
    with connect(app.config["DATABASE"]) as bootstrap_db:
        if bootstrap_db.execute("SELECT COUNT(*) c FROM ledger_blocks").fetchone()["c"] == 0:
            now = utc_now()
            append_block(
                bootstrap_db,
                "GENESIS",
                {
                    "batch_id": "__SYSTEM__",
                    "chain_name": "CHAIN-LOTTERY-EVIDENCE-V2",
                    "hash_algorithm": "SM3",
                    "description": "多区块公平可验证摇号证据链",
                },
                now,
                {"status": "SYSTEM", "protocol_version": 2},
            )
            bootstrap_db.commit()

    def get_db():
        if "db" not in g:
            g.db = connect(app.config["DATABASE"])
        return g.db

    @app.teardown_appcontext
    def close_db(_error=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def beacon_service() -> DemoBeacon:
        return DemoBeacon(app.config["BEACON_KEY"])

    def get_batch_or_404(batch_db_id: int):
        row = get_db().execute("SELECT * FROM batches WHERE id=?", (batch_db_id,)).fetchone()
        if row is None:
            abort(404)
        return row

    def participants_for(batch_db_id: int, status: str | None = None):
        sql = "SELECT * FROM participants WHERE batch_db_id=?"
        params: list[object] = [batch_db_id]
        if status:
            sql += " AND status=?"
            params.append(status)
        sql += " ORDER BY lottery_no"
        return get_db().execute(sql, params).fetchall()

    def build_tree(batch):
        people = participants_for(batch["id"], "APPROVED")
        leaves = [leaf_hash(batch["batch_id"], p["lottery_no"], p["commitment"]) for p in people]
        if not leaves:
            raise ValueError("没有审核通过的参与者")
        return people, MerkleTree(batch["batch_id"], leaves), leaves

    def snapshot(batch_id: str, status: str, **extra) -> dict:
        """生成写入区块头状态摘要的公开业务状态快照。"""
        db = get_db()
        batch = db.execute(
            "SELECT id, winner_count FROM batches WHERE batch_id=?", (batch_id,)
        ).fetchone()
        counts = {"total": 0, "pending": 0, "approved": 0, "rejected": 0}
        if batch is not None:
            rows = db.execute(
                "SELECT status, COUNT(*) c FROM participants "
                "WHERE batch_db_id=? GROUP BY status",
                (batch["id"],),
            ).fetchall()
            counts["total"] = sum(row["c"] for row in rows)
            for row in rows:
                counts[row["status"].lower()] = row["c"]
        result = {
            "status": status,
            "participant_counts": counts,
            "winner_count": batch["winner_count"] if batch is not None else None,
        }
        result.update(extra)
        return result

    def make_manifest(batch, people, leaves):
        return {
            "version": "LOTTERY-MANIFEST-V1",
            "batch_id": batch["batch_id"],
            "participant_count": len(people),
            "participants": [
                {
                    "position": index,
                    "lottery_no": person["lottery_no"],
                    "commitment": person["commitment"],
                    "leaf_hash": leaves[index],
                }
                for index, person in enumerate(people)
            ],
        }

    def audit_batch(batch) -> list[dict]:
        db = get_db()
        checks: list[dict] = []

        def add(name: str, passed: bool, detail: str):
            checks.append({"name": name, "passed": bool(passed), "detail": detail})

        ledger_ok, ledger_detail = verify_ledger(db)
        add("账本哈希链", ledger_ok, ledger_detail)

        rule_hash = sm3_hex(batch["rule_json"].encode("utf-8"))
        add("规则哈希", rule_hash == batch["rule_hash"], f"重算值：{rule_hash}")

        if batch["status"] in {"FROZEN", "RANDOM_READY", "DRAWN", "AUDITED"}:
            people, tree, leaves = build_tree(batch)
            add("参与人数", len(people) >= batch["winner_count"], f"有效{len(people)}人，中签{batch['winner_count']}人")
            add("默克尔树根", tree.root == batch["merkle_root"], f"重算树根：{tree.root}")
            manifest = make_manifest(batch, people, leaves)
            manifest_hash = sm3_hex(canonical_json(manifest))
            add("名单文件哈希", manifest_hash == batch["manifest_hash"], f"重算值：{manifest_hash}")
            freeze_anchor = find_payload(db, "FREEZE", batch["batch_id"])
            anchor_ok = bool(
                freeze_anchor
                and freeze_anchor.get("merkle_root") == batch["merkle_root"]
                and freeze_anchor.get("manifest_hash") == batch["manifest_hash"]
            )
            add("冻结账本锚定", anchor_ok, "树根和名单哈希与FREEZE交易一致" if anchor_ok else "未找到一致的FREEZE交易")

            commitments_ok = all(
                data_commitment(
                    batch["batch_id"], p["name"], p["id_number"], p["contact"], p["salt"]
                )
                == p["commitment"]
                for p in people
            )
            add("内部数据承诺", commitments_ok, "所有审核通过记录均可由原始资料与盐值复算")

        if batch["beacon_json"]:
            pulse = json.loads(batch["beacon_json"])
            beacon_ok = DemoBeacon.verify(pulse)
            add("随机信标签名", beacon_ok, f"本地演示信标轮次：{pulse.get('round')}")
            add("预定信标轮次", pulse.get("round") == batch["beacon_round"], f"预定轮次：{batch['beacon_round']}")
            seed = final_seed(
                batch["batch_id"],
                batch["merkle_root"],
                batch["beacon_round"],
                pulse["randomness"],
                batch["rule_hash"],
            )
            add("最终种子", seed == batch["seed"], f"重算种子：{seed}")

        if batch["status"] in {"DRAWN", "AUDITED"}:
            people = participants_for(batch["id"], "APPROVED")
            ranked = sorted(
                [(lottery_score(batch["batch_id"], batch["seed"], p["lottery_no"]), p["lottery_no"]) for p in people],
                key=lambda item: (item[0], item[1]),
            )
            stored = [(p["score"], p["lottery_no"]) for p in sorted(people, key=lambda p: p["rank"])]
            add("完整排名复算", ranked == stored, f"共复算{len(ranked)}个随机分值")
            winners = {number for _, number in ranked[: batch["winner_count"]]}
            stored_winners = {p["lottery_no"] for p in people if p["is_winner"]}
            add("中签名单", winners == stored_winners, f"复算中签人数：{len(winners)}")
            draw_anchor = find_payload(db, "DRAW", batch["batch_id"])
            add("结果账本锚定", bool(draw_anchor and draw_anchor.get("seed") == batch["seed"]), "结果种子与DRAW交易一致")
        return checks

    @app.template_filter("short_hash")
    def short_hash(value):
        if not value:
            return "-"
        return f"{value[:10]}…{value[-8:]}"

    @app.template_filter("status_label")
    def status_label(value):
        return STATUS_LABELS.get(value, value)

    @app.template_filter("mask_name")
    def mask_name(value):
        if not value:
            return "-"
        return value[0] + "*" * max(1, len(value) - 1)

    @app.get("/")
    def index():
        batches = get_db().execute("SELECT * FROM batches ORDER BY id DESC").fetchall()
        ledger_ok, ledger_detail = verify_ledger(get_db())
        return render_template("index.html", batches=batches, ledger_ok=ledger_ok, ledger_detail=ledger_detail)

    @app.post("/batches")
    def create_batch_route():
        batch_id = request.form.get("batch_id", "").strip().upper()
        title = request.form.get("title", "").strip()
        try:
            winners = int(request.form.get("winner_count", "0"))
            beacon_round = int(request.form.get("beacon_round", "1"))
            if winners < 1 or beacon_round < 1:
                raise ValueError
        except ValueError:
            flash("中签人数和信标轮次必须为正整数", "error")
            return redirect(url_for("index"))
        if not batch_id or not title:
            flash("批次编号和标题不能为空", "error")
            return redirect(url_for("index"))

        rules = {
            "version": "LOTTERY-RULE-V1",
            "hash": "SM3",
            "participant_order": "lottery_no ASC",
            "score_order": "score ASC, lottery_no ASC",
            "winner_count": winners,
            "beacon_network": "LOCAL-SIGNED-DEMO-BEACON",
            "beacon_round": beacon_round,
            "leaf": "SM3(0x00||batchID||lotteryNo||commitment)",
            "parent": "SM3(0x01||left||right)",
            "empty": "SM3(0x02||batchID||position)",
            "seed": "SM3(LOTTERY-SEED-V1||batchID||root||round||B||ruleHash)",
            "score": "SM3(LOTTERY-SCORE-V1||batchID||seed||lotteryNo)",
        }
        rule_json = canonical_json(rules).decode("utf-8")
        now = utc_now()
        db = get_db()
        try:
            cursor = db.execute(
                "INSERT INTO batches(batch_id,title,winner_count,status,rule_json,rule_hash,beacon_round,created_at) VALUES (?,?,?,?,?,?,?,?)",
                (batch_id, title, winners, "REGISTRATION", rule_json, sm3_hex(rule_json.encode()), beacon_round, now),
            )
            append_block(
                db,
                "CREATE_BATCH",
                {"batch_id": batch_id, "title": title, "rule_hash": sm3_hex(rule_json.encode())},
                now,
                snapshot(batch_id, "REGISTRATION", rule_locked=True),
            )
            db.commit()
            flash("摇号批次已创建，规则哈希已写入演示账本", "success")
            return redirect(url_for("batch_detail", batch_db_id=cursor.lastrowid))
        except sqlite3.IntegrityError:
            flash("批次编号已存在", "error")
            return redirect(url_for("index"))

    @app.get("/batches/<int:batch_db_id>")
    def batch_detail(batch_db_id):
        batch = get_batch_or_404(batch_db_id)
        people = participants_for(batch_db_id)
        blocks = get_db().execute(
            "SELECT * FROM ledger_blocks WHERE batch_id=? "
            "ORDER BY height DESC LIMIT 40",
            (batch["batch_id"],),
        ).fetchall()
        return render_template("batch.html", batch=batch, people=people, blocks=blocks)

    @app.post("/batches/<int:batch_db_id>/register")
    def register(batch_db_id):
        batch = get_batch_or_404(batch_db_id)
        if batch["status"] != "REGISTRATION":
            flash("当前批次已经停止报名", "error")
            return redirect(url_for("batch_detail", batch_db_id=batch_db_id))
        name = request.form.get("name", "").strip()
        id_number = request.form.get("id_number", "").strip().upper()
        contact = request.form.get("contact", "").strip()
        if not all((name, id_number, contact)):
            flash("姓名、证件号和联系方式不能为空", "error")
            return redirect(url_for("batch_detail", batch_db_id=batch_db_id))
        salt = secrets.token_hex(32)
        commitment = data_commitment(batch["batch_id"], name, id_number, contact, salt)
        lottery_no = f"{batch['batch_id']}-{secrets.token_hex(4).upper()}"
        now = utc_now()
        db = get_db()
        try:
            cursor = db.execute(
                "INSERT INTO participants(batch_db_id,lottery_no,name,id_number,contact,salt,commitment,status,registered_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (batch_db_id, lottery_no, name, id_number, contact, salt, commitment, "PENDING", now),
            )
            append_block(
                db,
                "REGISTER",
                {"batch_id": batch["batch_id"], "lottery_no": lottery_no, "commitment": commitment, "status": "PENDING"},
                now,
                snapshot(batch["batch_id"], "REGISTRATION"),
            )
            db.commit()
            flash(f"报名已提交，摇号编号：{lottery_no}。请保存回执中的盐值。", "success")
            return redirect(url_for("receipt", participant_id=cursor.lastrowid))
        except sqlite3.IntegrityError:
            flash("同一证件号不能在同一批次重复报名", "error")
            return redirect(url_for("batch_detail", batch_db_id=batch_db_id))

    @app.get("/participants/<int:participant_id>/receipt")
    def receipt(participant_id):
        person = get_db().execute("SELECT * FROM participants WHERE id=?", (participant_id,)).fetchone()
        if person is None:
            abort(404)
        batch = get_batch_or_404(person["batch_db_id"])
        return render_template("receipt.html", batch=batch, person=person)

    @app.get("/participants/<int:participant_id>/receipt.json")
    def receipt_json(participant_id):
        person = get_db().execute("SELECT * FROM participants WHERE id=?", (participant_id,)).fetchone()
        if person is None:
            abort(404)
        batch = get_batch_or_404(person["batch_db_id"])
        payload = {
            "version": "LOTTERY-RECEIPT-V1",
            "batch_id": batch["batch_id"],
            "lottery_no": person["lottery_no"],
            "registered_at": person["registered_at"],
            "commitment": person["commitment"],
            "salt": person["salt"],
            "status": person["status"],
        }
        response = app.response_class(canonical_json(payload), mimetype="application/json")
        response.headers["Content-Disposition"] = f"attachment; filename=receipt-{person['lottery_no']}.json"
        return response

    @app.post("/participants/<int:participant_id>/<decision>")
    def review_participant(participant_id, decision):
        if decision not in {"approve", "reject"}:
            abort(404)
        person = get_db().execute("SELECT * FROM participants WHERE id=?", (participant_id,)).fetchone()
        if person is None:
            abort(404)
        batch = get_batch_or_404(person["batch_db_id"])
        if batch["status"] not in {"REGISTRATION", "CLOSED"} or person["status"] != "PENDING":
            flash("当前记录不能再审核", "error")
            return redirect(url_for("batch_detail", batch_db_id=batch["id"]))
        status = "APPROVED" if decision == "approve" else "REJECTED"
        now = utc_now()
        db = get_db()
        db.execute("UPDATE participants SET status=?, reviewed_at=? WHERE id=?", (status, now, participant_id))
        append_block(
            db,
            "REVIEW",
            {"batch_id": batch["batch_id"], "lottery_no": person["lottery_no"], "status": status},
            now,
            snapshot(batch["batch_id"], batch["status"]),
        )
        db.commit()
        flash("审核状态已更新并记录到账本", "success")
        return redirect(url_for("batch_detail", batch_db_id=batch["id"]))

    @app.post("/batches/<int:batch_db_id>/close")
    def close_batch(batch_db_id):
        batch = get_batch_or_404(batch_db_id)
        if batch["status"] != "REGISTRATION":
            flash("只有报名中的批次可以关闭", "error")
        else:
            now = utc_now()
            db = get_db()
            db.execute("UPDATE batches SET status='CLOSED', closed_at=? WHERE id=?", (now, batch_db_id))
            append_block(
                db,
                "CLOSE",
                {"batch_id": batch["batch_id"]},
                now,
                snapshot(batch["batch_id"], "CLOSED", registration_closed=True),
            )
            db.commit()
            flash("报名入口已关闭；截止前的待审核申请仍可完成审核", "success")
        return redirect(url_for("batch_detail", batch_db_id=batch_db_id))

    @app.post("/batches/<int:batch_db_id>/freeze")
    def freeze_batch(batch_db_id):
        batch = get_batch_or_404(batch_db_id)
        if batch["status"] != "CLOSED":
            flash("只有Closed状态可以冻结名单", "error")
            return redirect(url_for("batch_detail", batch_db_id=batch_db_id))
        pending = get_db().execute("SELECT COUNT(*) c FROM participants WHERE batch_db_id=? AND status='PENDING'", (batch_db_id,)).fetchone()["c"]
        if pending:
            flash(f"仍有{pending}条待审核记录，不能冻结", "error")
            return redirect(url_for("batch_detail", batch_db_id=batch_db_id))
        try:
            people, tree, leaves = build_tree(batch)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("batch_detail", batch_db_id=batch_db_id))
        if len(people) < batch["winner_count"]:
            flash("有效参与人数小于中签人数，不能冻结", "error")
            return redirect(url_for("batch_detail", batch_db_id=batch_db_id))
        manifest = make_manifest(batch, people, leaves)
        manifest_hash = sm3_hex(canonical_json(manifest))
        manifest_path = Path(app.config["MANIFEST_DIR"]) / f"batch-{batch_db_id}-manifest.json"
        manifest_path.write_bytes(canonical_json(manifest))
        now = utc_now()
        db = get_db()
        for person, leaf in zip(people, leaves):
            db.execute("UPDATE participants SET leaf_hash=? WHERE id=?", (leaf, person["id"]))
        db.execute(
            "UPDATE batches SET status='FROZEN', frozen_at=?, merkle_root=?, manifest_hash=? WHERE id=?",
            (now, tree.root, manifest_hash, batch_db_id),
        )
        append_block(
            db,
            "FREEZE",
            {"batch_id": batch["batch_id"], "participant_count": len(people), "winner_count": batch["winner_count"], "merkle_root": tree.root, "manifest_hash": manifest_hash, "beacon_round": batch["beacon_round"]},
            now,
            snapshot(
                batch["batch_id"],
                "FROZEN",
                merkle_root=tree.root,
                manifest_hash=manifest_hash,
            ),
        )
        db.commit()
        flash("最终名单、顺序和默克尔树根已经冻结", "success")
        return redirect(url_for("batch_detail", batch_db_id=batch_db_id))

    @app.post("/batches/<int:batch_db_id>/beacon")
    def emit_beacon(batch_db_id):
        batch = get_batch_or_404(batch_db_id)
        if batch["status"] != "FROZEN":
            flash("必须先冻结名单，再产生随机信标", "error")
            return redirect(url_for("batch_detail", batch_db_id=batch_db_id))
        pulse = beacon_service().emit(batch["batch_id"], batch["beacon_round"])
        if not DemoBeacon.verify(pulse):
            flash("随机信标签名自检失败", "error")
            return redirect(url_for("batch_detail", batch_db_id=batch_db_id))
        seed = final_seed(batch["batch_id"], batch["merkle_root"], batch["beacon_round"], pulse["randomness"], batch["rule_hash"])
        now = utc_now()
        db = get_db()
        db.execute("UPDATE batches SET status='RANDOM_READY', beacon_json=?, seed=? WHERE id=?", (canonical_json(pulse).decode(), seed, batch_db_id))
        append_block(
            db,
            "BEACON",
            {"batch_id": batch["batch_id"], "round": batch["beacon_round"], "pulse_hash": pulse["pulse_hash"], "randomness": pulse["randomness"], "seed": seed},
            now,
            snapshot(
                batch["batch_id"],
                "RANDOM_READY",
                merkle_root=batch["merkle_root"],
                beacon_round=batch["beacon_round"],
                seed=seed,
            ),
        )
        db.commit()
        flash("指定轮次的带签名演示信标已产生，最终种子已绑定名单树根", "success")
        return redirect(url_for("batch_detail", batch_db_id=batch_db_id))

    @app.post("/batches/<int:batch_db_id>/draw")
    def draw(batch_db_id):
        batch = get_batch_or_404(batch_db_id)
        if batch["status"] != "RANDOM_READY":
            flash("随机信标验证通过后才能摇号", "error")
            return redirect(url_for("batch_detail", batch_db_id=batch_db_id))
        people = participants_for(batch_db_id, "APPROVED")
        ranking = sorted(
            [(lottery_score(batch["batch_id"], batch["seed"], p["lottery_no"]), p) for p in people],
            key=lambda item: (item[0], item[1]["lottery_no"]),
        )
        db = get_db()
        winners = []
        for rank, (score, person) in enumerate(ranking, start=1):
            is_winner = rank <= batch["winner_count"]
            db.execute("UPDATE participants SET score=?, rank=?, is_winner=? WHERE id=?", (score, rank, int(is_winner), person["id"]))
            if is_winner:
                winners.append(person["lottery_no"])
        now = utc_now()
        db.execute("UPDATE batches SET status='DRAWN', drawn_at=? WHERE id=?", (now, batch_db_id))
        ranking_hash = sm3_hex(canonical_json([{"rank": i + 1, "lottery_no": p["lottery_no"], "score": s} for i, (s, p) in enumerate(ranking)]))
        append_block(
            db,
            "DRAW",
            {"batch_id": batch["batch_id"], "seed": batch["seed"], "ranking_hash": ranking_hash, "winners": winners},
            now,
            snapshot(
                batch["batch_id"],
                "DRAWN",
                merkle_root=batch["merkle_root"],
                seed=batch["seed"],
                ranking_hash=ranking_hash,
                result_locked=True,
            ),
        )
        db.commit()
        flash("摇号完成，完整排名和中签结果均可独立复算", "success")
        return redirect(url_for("batch_detail", batch_db_id=batch_db_id))

    @app.get("/batches/<int:batch_db_id>/manifest")
    def download_manifest(batch_db_id):
        batch = get_batch_or_404(batch_db_id)
        if not batch["manifest_hash"]:
            abort(404)
        path = Path(app.config["MANIFEST_DIR"]) / f"batch-{batch_db_id}-manifest.json"
        return send_file(path, as_attachment=True, download_name=f"{batch['batch_id']}-manifest.json")

    @app.get("/batches/<int:batch_db_id>/audit")
    def audit_page(batch_db_id):
        batch = get_batch_or_404(batch_db_id)
        checks = audit_batch(batch)
        return render_template("audit.html", batch=batch, checks=checks)

    @app.get("/api/batches/<int:batch_db_id>/audit")
    def audit_api(batch_db_id):
        batch = get_batch_or_404(batch_db_id)
        checks = audit_batch(batch)
        return jsonify({"batch_id": batch["batch_id"], "status": batch["status"], "passed": all(x["passed"] for x in checks), "checks": checks})

    @app.post("/batches/<int:batch_db_id>/seal-audit")
    def seal_audit(batch_db_id):
        batch = get_batch_or_404(batch_db_id)
        if batch["status"] != "DRAWN":
            flash("只有完成摇号的批次可以生成审计区块", "error")
            return redirect(url_for("batch_detail", batch_db_id=batch_db_id))
        checks = audit_batch(batch)
        passed = all(item["passed"] for item in checks)
        if not passed:
            flash("当前审计未通过，不能封存审计区块", "error")
            return redirect(url_for("audit_page", batch_db_id=batch_db_id))
        db = get_db()
        if find_payload(db, "AUDIT", batch["batch_id"]):
            flash("该批次已经生成审计区块", "error")
            return redirect(url_for("batch_detail", batch_db_id=batch_db_id))
        now = utc_now()
        report_hash = sm3_hex(canonical_json(checks))
        db.execute("UPDATE batches SET status='AUDITED' WHERE id=?", (batch_db_id,))
        append_block(
            db,
            "AUDIT",
            {
                "batch_id": batch["batch_id"],
                "passed": True,
                "check_count": len(checks),
                "audit_report_hash": report_hash,
            },
            now,
            snapshot(
                batch["batch_id"],
                "AUDITED",
                audit_report_hash=report_hash,
                chain_verified=True,
            ),
        )
        db.commit()
        flash("审计报告摘要已形成最终区块", "success")
        return redirect(url_for("batch_detail", batch_db_id=batch_db_id))

    @app.get("/chain")
    def chain_explorer():
        db = get_db()
        chain_ok, chain_detail = verify_ledger(db)
        blocks = export_chain(db)
        return render_template(
            "chain.html", blocks=blocks, chain_ok=chain_ok, chain_detail=chain_detail
        )

    @app.get("/api/chain")
    def chain_api():
        db = get_db()
        batch_id = request.args.get("batch_id")
        chain_ok, chain_detail = verify_ledger(db)
        return jsonify(
            {
                "valid": chain_ok,
                "detail": chain_detail,
                "blocks": export_chain(db, batch_id),
            }
        )

    @app.get("/batches/<int:batch_db_id>/verify/<lottery_no>")
    def verify_participant(batch_db_id, lottery_no):
        batch = get_batch_or_404(batch_db_id)
        if not batch["merkle_root"]:
            flash("名单尚未冻结，暂时没有默克尔证明", "error")
            return redirect(url_for("batch_detail", batch_db_id=batch_db_id))
        people, tree, leaves = build_tree(batch)
        index = next((i for i, p in enumerate(people) if p["lottery_no"] == lottery_no), None)
        if index is None:
            abort(404)
        person = people[index]
        proof = tree.proof(index)
        proof_ok = verify_proof(leaves[index], proof, batch["merkle_root"])
        recomputed_commitment = data_commitment(batch["batch_id"], person["name"], person["id_number"], person["contact"], person["salt"])
        recomputed_score = lottery_score(batch["batch_id"], batch["seed"], person["lottery_no"]) if batch["seed"] else None
        return render_template("verify.html", batch=batch, person=person, proof=proof, proof_ok=proof_ok, recomputed_commitment=recomputed_commitment, recomputed_score=recomputed_score)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=True)
