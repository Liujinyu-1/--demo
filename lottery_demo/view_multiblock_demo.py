"""启动Web界面并直接查看随项目附带的128人多区块示例链。"""

from pathlib import Path

from app import create_app


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "multiblock_output"

app = create_app(
    {
        "DATABASE": str(OUTPUT / "multiblock_chain.sqlite3"),
        "BEACON_KEY": str(OUTPUT / "viewer_beacon_ed25519.key"),
        "MANIFEST_DIR": str(OUTPUT / "manifests"),
        "SECRET_KEY": "viewer-demo-only",
    }
)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
