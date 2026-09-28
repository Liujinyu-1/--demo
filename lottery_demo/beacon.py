"""A locally signed beacon used only to make the demo runnable offline.

This proves authenticity and tamper detection, but it is not a distributed
threshold beacon.  The web UI and README state this limitation explicitly.
"""

from __future__ import annotations

import base64
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from crypto_utils import canonical_json, sm3_hex


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class DemoBeacon:
    def __init__(self, key_path: str | Path):
        self.key_path = Path(key_path)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        if self.key_path.exists():
            raw = self.key_path.read_bytes()
            self.private_key = Ed25519PrivateKey.from_private_bytes(raw)
        else:
            self.private_key = Ed25519PrivateKey.generate()
            raw = self.private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            self.key_path.write_bytes(raw)

    @property
    def public_key_b64(self) -> str:
        raw = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return base64.b64encode(raw).decode("ascii")

    @property
    def public_key_fingerprint(self) -> str:
        return sm3_hex(base64.b64decode(self.public_key_b64))

    def emit(self, batch_id: str, round_number: int, previous_hash: str = "") -> dict:
        body = {
            "network": "LOCAL-SIGNED-DEMO-BEACON",
            "batch_id": batch_id,
            "round": int(round_number),
            "timestamp": utc_now(),
            "previous_hash": previous_hash,
            "randomness": secrets.token_hex(32),
        }
        signature = self.private_key.sign(canonical_json(body))
        pulse = {
            **body,
            "public_key": self.public_key_b64,
            "signature": base64.b64encode(signature).decode("ascii"),
        }
        pulse["pulse_hash"] = sm3_hex(canonical_json(pulse))
        return pulse

    @staticmethod
    def verify(pulse: dict) -> bool:
        try:
            signed_fields = {
                key: pulse[key]
                for key in (
                    "network",
                    "batch_id",
                    "round",
                    "timestamp",
                    "previous_hash",
                    "randomness",
                )
            }
            public_key = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(pulse["public_key"])
            )
            public_key.verify(
                base64.b64decode(pulse["signature"]), canonical_json(signed_fields)
            )
            check = dict(pulse)
            pulse_hash = check.pop("pulse_hash")
            return sm3_hex(canonical_json(check)) == pulse_hash
        except (KeyError, ValueError, TypeError):
            return False
        except Exception:
            return False

