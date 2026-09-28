import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import create_app
from crypto_utils import MerkleTree, ProofStep, sm3_hex, verify_proof
from database import connect
from probability_simulation import run_simulation
from ledger import verify_ledger


class CryptoTests(unittest.TestCase):
    def test_sm3_known_vector(self):
        self.assertEqual(
            sm3_hex(b"abc"),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        )

    def test_merkle_proof_and_tamper_detection(self):
        leaves = [sm3_hex(f"leaf-{i}".encode()) for i in range(5)]
        tree = MerkleTree("BATCH-1", leaves)
        proof = tree.proof(3)
        self.assertTrue(verify_proof(leaves[3], proof, tree.root))
        bad = list(proof)
        bad[0] = ProofStep(side=bad[0].side, hash="00" * 32)
        self.assertFalse(verify_proof(leaves[3], bad, tree.root))

    def test_probability_simulation_is_reproducible(self):
        rows_a, summary_a, _ = run_simulation(8, 80, 1, "UNIT-TEST-SEED")
        rows_b, summary_b, _ = run_simulation(8, 80, 1, "UNIT-TEST-SEED")
        self.assertEqual(sum(row["win_count"] for row in rows_a), 80)
        self.assertAlmostEqual(
            sum(row["observed_probability"] for row in rows_a), 1.0
        )
        self.assertEqual(rows_a, rows_b)
        self.assertEqual(
            summary_a["reproducibility_digest"],
            summary_b["reproducibility_digest"],
        )


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE": str(root / "test.sqlite3"),
                "BEACON_KEY": str(root / "beacon.key"),
                "MANIFEST_DIR": str(root / "manifests"),
                "SECRET_KEY": "test",
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def test_complete_lottery_and_audit(self):
        response = self.client.post(
            "/batches",
            data={"batch_id": "TEST-001", "title": "测试摇号", "winner_count": "2", "beacon_round": "42"},
        )
        self.assertEqual(response.status_code, 302)
        with connect(self.app.config["DATABASE"]) as db:
            batch = db.execute("SELECT * FROM batches WHERE batch_id='TEST-001'").fetchone()

        for i in range(4):
            response = self.client.post(
                f"/batches/{batch['id']}/register",
                data={"name": f"用户{i}", "id_number": f"ID{i:04d}", "contact": f"1380000{i:04d}"},
            )
            self.assertEqual(response.status_code, 302)

        with connect(self.app.config["DATABASE"]) as db:
            participant_ids = [row["id"] for row in db.execute("SELECT id FROM participants")]
        for participant_id in participant_ids:
            self.client.post(f"/participants/{participant_id}/approve")

        self.client.post(f"/batches/{batch['id']}/close")
        self.client.post(f"/batches/{batch['id']}/freeze")
        self.client.post(f"/batches/{batch['id']}/beacon")
        self.client.post(f"/batches/{batch['id']}/draw")

        result = self.client.get(f"/api/batches/{batch['id']}/audit").get_json()
        self.assertTrue(result["passed"], result)
        with connect(self.app.config["DATABASE"]) as db:
            winners = db.execute("SELECT COUNT(*) c FROM participants WHERE is_winner=1").fetchone()["c"]
            self.assertEqual(winners, 2)
            first = db.execute("SELECT * FROM participants ORDER BY lottery_no LIMIT 1").fetchone()
        page = self.client.get(f"/batches/{batch['id']}/verify/{first['lottery_no']}")
        self.assertEqual(page.status_code, 200)
        self.assertIn("证明有效".encode("utf-8"), page.data)

        seal = self.client.post(f"/batches/{batch['id']}/seal-audit")
        self.assertEqual(seal.status_code, 302)
        chain = self.client.get("/api/chain").get_json()
        self.assertTrue(chain["valid"], chain)
        self.assertEqual(chain["blocks"][0]["tx_type"], "GENESIS")
        for previous, current in zip(chain["blocks"], chain["blocks"][1:]):
            self.assertEqual(current["previous_hash"], previous["block_hash"])
        with connect(self.app.config["DATABASE"]) as db:
            status = db.execute(
                "SELECT status FROM batches WHERE id=?", (batch["id"],)
            ).fetchone()["status"]
            self.assertEqual(status, "AUDITED")

    def test_chain_detects_payload_tampering(self):
        self.client.post(
            "/batches",
            data={
                "batch_id": "TAMPER-001",
                "title": "篡改检测",
                "winner_count": "1",
                "beacon_round": "7",
            },
        )
        with connect(self.app.config["DATABASE"]) as db:
            row = db.execute(
                "SELECT height, payload_json FROM ledger_blocks "
                "WHERE tx_type='CREATE_BATCH'"
            ).fetchone()
            original = row["payload_json"]
            db.execute(
                "UPDATE ledger_blocks SET payload_json=? WHERE height=?",
                ('{"batch_id":"TAMPERED"}', row["height"]),
            )
            valid, detail = verify_ledger(db)
            self.assertFalse(valid)
            self.assertIn("区块体摘要不匹配", detail)
            db.execute(
                "UPDATE ledger_blocks SET payload_json=? WHERE height=?",
                (original, row["height"]),
            )


if __name__ == "__main__":
    unittest.main()
