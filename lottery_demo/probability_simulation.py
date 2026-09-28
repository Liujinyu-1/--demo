"""对公平可验证摇号算法进行可复现的概率实验。

默认生成128名模拟参与者，独立执行12800轮摇号，每轮抽取1人，
并导出每个人的中签次数、实验概率、理论概率及偏差。
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import time
from dataclasses import dataclass
from pathlib import Path

from crypto_utils import (
    MerkleTree,
    canonical_json,
    data_commitment,
    final_seed,
    leaf_hash,
    lottery_score,
    sm3_hex,
)


DEFAULT_MASTER_SEED = "CHAIN-LOTTERY-PROBABILITY-TEST-V1"


@dataclass(frozen=True)
class SimParticipant:
    index: int
    lottery_no: str
    name: str
    id_number: str
    contact: str
    salt: str
    commitment: str
    leaf_hash: str


def derive_hex(label: str, master_seed: str, number: int) -> str:
    """从固定主种子派生32字节测试值，使实验可以完全复现。"""
    payload = canonical_json(
        {"domain": label, "master_seed": master_seed, "number": number}
    )
    return sm3_hex(payload)


def build_dataset(
    participant_count: int, batch_id: str, master_seed: str
) -> tuple[list[SimParticipant], MerkleTree]:
    if participant_count < 2:
        raise ValueError("参与人数必须至少为2")

    participants: list[SimParticipant] = []
    for index in range(1, participant_count + 1):
        lottery_no = f"SIM-{index:04d}"
        name = f"模拟参与者{index:03d}"
        id_number = f"TEST-ID-{index:06d}"
        contact = f"139{index:08d}"
        salt = derive_hex("PARTICIPANT-SALT-V1", master_seed, index)
        commitment = data_commitment(
            batch_id, name, id_number, contact, salt
        )
        participant_leaf = leaf_hash(batch_id, lottery_no, commitment)
        participants.append(
            SimParticipant(
                index=index,
                lottery_no=lottery_no,
                name=name,
                id_number=id_number,
                contact=contact,
                salt=salt,
                commitment=commitment,
                leaf_hash=participant_leaf,
            )
        )

    participants.sort(key=lambda item: item.lottery_no)
    tree = MerkleTree(batch_id, [item.leaf_hash for item in participants])
    return participants, tree


def run_simulation(
    participant_count: int = 128,
    run_count: int = 12_800,
    winner_count: int = 1,
    master_seed: str = DEFAULT_MASTER_SEED,
) -> tuple[list[dict], dict, list[SimParticipant]]:
    if run_count < 1:
        raise ValueError("实验轮数必须至少为1")
    if not 1 <= winner_count <= participant_count:
        raise ValueError("每轮中签人数必须在1至参与人数之间")

    batch_id = (
        f"PROB-{participant_count}-{run_count}-{winner_count}-"
        f"{sm3_hex(master_seed.encode('utf-8'))[:12]}"
    )
    participants, tree = build_dataset(participant_count, batch_id, master_seed)
    rule = {
        "algorithm": "SM3 independent score ascending",
        "batch_id": batch_id,
        "participant_count": participant_count,
        "run_count": run_count,
        "winner_count": winner_count,
        "tie_breaker": "lottery_no ascending",
    }
    rule_hash = sm3_hex(canonical_json(rule))
    win_counts = [0] * participant_count
    started = time.perf_counter()

    for round_number in range(1, run_count + 1):
        # 这是离线测试信标：每轮输出均由固定主种子和轮次唯一决定。
        beacon_randomness = derive_hex(
            "SIMULATED-BEACON-V1", master_seed, round_number
        )
        seed = final_seed(
            batch_id,
            tree.root,
            round_number,
            beacon_randomness,
            rule_hash,
        )
        ranking = sorted(
            (
                lottery_score(batch_id, seed, participant.lottery_no),
                participant.lottery_no,
                position,
            )
            for position, participant in enumerate(participants)
        )
        for _, _, position in ranking[:winner_count]:
            win_counts[position] += 1

    elapsed_seconds = time.perf_counter() - started
    theoretical_probability = winner_count / participant_count
    expected_wins = run_count * theoretical_probability
    binomial_std = math.sqrt(
        run_count * theoretical_probability * (1 - theoretical_probability)
    )
    rows: list[dict] = []

    for participant, wins in zip(participants, win_counts):
        observed_probability = wins / run_count
        probability_deviation = observed_probability - theoretical_probability
        rows.append(
            {
                "participant_index": participant.index,
                "lottery_no": participant.lottery_no,
                "name": participant.name,
                "win_count": wins,
                "observed_probability": observed_probability,
                "observed_percentage": observed_probability * 100,
                "theoretical_probability": theoretical_probability,
                "theoretical_percentage": theoretical_probability * 100,
                "probability_deviation": probability_deviation,
                "relative_deviation": (
                    probability_deviation / theoretical_probability
                    if theoretical_probability
                    else 0.0
                ),
                "z_score": (
                    (wins - expected_wins) / binomial_std if binomial_std else 0.0
                ),
            }
        )

    mean_wins = sum(win_counts) / participant_count
    population_std = math.sqrt(
        sum((value - mean_wins) ** 2 for value in win_counts)
        / participant_count
    )
    chi_square = sum(
        (value - expected_wins) ** 2 / expected_wins for value in win_counts
    )
    reproducibility_payload = [
        {"lottery_no": row["lottery_no"], "win_count": row["win_count"]}
        for row in rows
    ]
    summary = {
        "experiment": "面向社会资源配置的可复现公平随机摇号概率实验",
        "batch_id": batch_id,
        "participant_count": participant_count,
        "run_count": run_count,
        "winner_count_per_run": winner_count,
        "total_wins": sum(win_counts),
        "expected_total_wins": run_count * winner_count,
        "theoretical_probability_per_person": theoretical_probability,
        "theoretical_percentage_per_person": theoretical_probability * 100,
        "expected_wins_per_person": expected_wins,
        "mean_wins": mean_wins,
        "minimum_wins": min(win_counts),
        "maximum_wins": max(win_counts),
        "population_standard_deviation_of_wins": population_std,
        "maximum_absolute_probability_deviation": max(
            abs(row["probability_deviation"]) for row in rows
        ),
        "chi_square_statistic": chi_square,
        "chi_square_degrees_of_freedom": participant_count - 1,
        "merkle_root": tree.root,
        "rule_hash": rule_hash,
        "master_seed": master_seed,
        "reproducibility_digest": sm3_hex(
            canonical_json(reproducibility_payload)
        ),
        "elapsed_seconds": elapsed_seconds,
        "interpretation": (
            "观察概率应围绕理论概率波动；有限轮实验不要求每个人次数完全相同。"
        ),
    }
    return rows, summary, participants


def write_results(
    output_dir: Path,
    rows: list[dict],
    summary: dict,
    participants: list[SimParticipant],
) -> tuple[Path, Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "participant_probabilities.csv"
    summary_path = output_dir / "simulation_summary.json"
    dataset_path = output_dir / "participants_128.json"

    with csv_path.open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    public_dataset = [
        {
            "participant_index": item.index,
            "lottery_no": item.lottery_no,
            "name": item.name,
            "commitment": item.commitment,
            "leaf_hash": item.leaf_hash,
        }
        for item in participants
    ]
    dataset_path.write_text(
        json.dumps(public_dataset, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return csv_path, summary_path, dataset_path


def print_summary(summary: dict, rows: list[dict], paths: tuple[Path, Path, Path]) -> None:
    print("\n=== 概率实验完成 ===")
    print(f"参与人数：{summary['participant_count']}")
    print(f"实验轮数：{summary['run_count']}")
    print(f"每轮中签人数：{summary['winner_count_per_run']}")
    print(
        "每人理论概率："
        f"{summary['theoretical_percentage_per_person']:.6f}%"
    )
    print(f"每人理论中签次数：{summary['expected_wins_per_person']:.2f}")
    print(
        f"实际次数范围：{summary['minimum_wins']} 至 "
        f"{summary['maximum_wins']}"
    )
    print(f"卡方统计量：{summary['chi_square_statistic']:.6f}")
    print(f"结果复现摘要：{summary['reproducibility_digest']}")
    print(f"耗时：{summary['elapsed_seconds']:.3f} 秒")

    print("\n中签次数最多的5人：")
    for row in sorted(rows, key=lambda item: (-item["win_count"], item["lottery_no"]))[:5]:
        print(
            f"  {row['lottery_no']}  {row['win_count']:4d} 次  "
            f"{row['observed_percentage']:.6f}%"
        )
    print("中签次数最少的5人：")
    for row in sorted(rows, key=lambda item: (item["win_count"], item["lottery_no"]))[:5]:
        print(
            f"  {row['lottery_no']}  {row['win_count']:4d} 次  "
            f"{row['observed_percentage']:.6f}%"
        )

    print("\n输出文件：")
    for path in paths:
        print(f"  {path.resolve()}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="运行可复现的公平随机摇号概率实验"
    )
    parser.add_argument("--participants", type=int, default=128, help="参与人数")
    parser.add_argument("--runs", type=int, default=12_800, help="实验轮数")
    parser.add_argument("--winners", type=int, default=1, help="每轮中签人数")
    parser.add_argument(
        "--master-seed",
        default=DEFAULT_MASTER_SEED,
        help="控制测试数据和模拟信标的固定主种子",
    )
    parser.add_argument(
        "--output", type=Path, default=Path("output"), help="结果输出目录"
    )
    parser.add_argument("--quiet", action="store_true", help="不打印汇总信息")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows, summary, participants = run_simulation(
        participant_count=args.participants,
        run_count=args.runs,
        winner_count=args.winners,
        master_seed=args.master_seed,
    )
    paths = write_results(args.output, rows, summary, participants)
    if not args.quiet:
        print_summary(summary, rows, paths)


if __name__ == "__main__":
    main()
