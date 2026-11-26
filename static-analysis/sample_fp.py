"""B6. 관련 CWE 오탐(정상 구역의 지적)에서 유형 분류용 표본을 뽑는다.

judge.py가 _runs/<실행이름>/fp_candidates.csv에 쓴 오탐 후보에서, 도구마다 (CWE, 검사 이름) 묶음을
골고루 덮도록 뽑는다. 같은 씨앗(--seed)이면 같은 표본이 나온다.

- 연습 표본(코드북을 만들 때 본 표본): results/fp_sample.csv
    python static-analysis/sample_fp.py --run all-20261121 --per-tool 5 --seed 20261121
- 검증 표본(코드북 v1을 고정한 뒤, 연습 표본을 빼고 새로 뽑음. docs/B_판정기록.md J16):
    python static-analysis/sample_fp.py --run all-20261121 --set 검증 --out results/fp_holdout.csv \\
        --exclude results/fp_sample.csv --per-tool 8 --seed 20261126

다시 실행해도 이미 채운 열(유형, 이유, 분류한 주체, 사람 판정 등)은 지우지 않는다.
검증 표본은 사람 판정 칸(human_*)을 먼저 채우고, 그 뒤에 에이전트 판정 칸(agent_*)을 채운다.
--show는 표본 줄 앞뒤 코드를 보여 준다.
"""

import argparse
import csv
import random
from collections import defaultdict
from pathlib import Path

from judge import read  # 윈도 경로 길이 제한을 피해 읽기

HERE = Path(__file__).resolve().parent
JULIET = HERE / "_juliet" / "C"
TOOLS = ["cppcheck", "clang-tidy", "flawfinder"]
KEY = ("case_id", "tool", "file", "line", "rule")
# 표본 종류마다 비워 두고 사람·에이전트가 채울 열
EXTRA = {
    "연습": ["fp_type", "reason", "set", "classified_by", "classified_at", "codebook", "human_fp_type", "human_by"],
    "검증": ["set", "codebook", "human_fp_type", "human_reason", "human_by", "human_at",
             "agent_fp_type", "agent_reason", "agent_model", "agent_at"],
}


def key(r: dict) -> tuple:
    return tuple(str(r[k]) for k in KEY)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--per-tool", type=int, default=5)
    ap.add_argument("--seed", type=int, default=20261121)
    ap.add_argument("--set", choices=list(EXTRA), default="연습")
    ap.add_argument("--out", default="results/fp_sample.csv", help="static-analysis/ 기준 경로")
    ap.add_argument("--exclude", action="append", default=[], help="이 표본 파일에 있는 지적은 뽑지 않음")
    ap.add_argument("--show", action="store_true", help="표본 줄 앞뒤 코드 보이기")
    args = ap.parse_args()
    out = HERE / args.out

    with open(HERE / "_runs" / args.run / "fp_candidates.csv", encoding="utf-8", newline="") as f:
        cand = list(csv.DictReader(f))
    with open(HERE / "juliet_cases.csv", encoding="utf-8", newline="") as f:
        files = {r["case_id"]: r["files"].split(";") for r in csv.DictReader(f)}

    excluded = set()
    for ex in args.exclude:
        with open(HERE / ex, encoding="utf-8", newline="") as f:
            excluded |= {key(r) for r in csv.DictReader(f)}
    pool = [r for r in cand if key(r) not in excluded]

    old = {}
    if out.exists():
        with open(out, encoding="utf-8", newline="") as f:
            old = {key(r): r for r in csv.DictReader(f)}

    rng = random.Random(args.seed)
    sample = []
    for tool in TOOLS:
        groups = defaultdict(list)
        for r in pool:
            if r["tool"] == tool:
                groups[(r["cwe_id"], r["rule"])].append(r)
        if not groups:
            continue
        keys = sorted(groups)
        rng.shuffle(keys)
        # 묶음마다 하나씩, 묶음이 모자라면 다시 돌며 채운다
        picked, i = [], 0
        while len(picked) < min(args.per_tool, sum(map(len, groups.values()))):
            g = groups[keys[i % len(keys)]]
            rest = [r for r in g if r not in picked]
            if rest:
                picked.append(rng.choice(rest))
            i += 1
        sample += picked

    rows = []
    for n, r in enumerate(sample, 1):
        prev = old.get(key(r), {})
        row = {"no": n, **r}
        for col in EXTRA[args.set]:
            row[col] = prev.get(col, "")
        row["set"] = row["set"] or args.set
        rows.append(row)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"오탐 후보 {len(cand)}건(제외 {len(cand) - len(pool)}건)에서 {args.set} 표본 {len(rows)}건 → "
          f"{out.relative_to(HERE.parent)}")

    if args.show:
        for r in rows:
            src = next(JULIET / p for p in files[r["case_id"]] if p.endswith("/" + r["file"]))
            lines = read(src, errors="replace").splitlines()
            ln = int(r["line"])
            print(f"\n== {r['no']}. {r['tool']} {r['rule']} CWE-{r['finding_cwes']} | {r['case_id']} {r['file']}:{ln}")
            print(f"   {r['message']}")
            for i in range(max(1, ln - 8), min(len(lines), ln + 3) + 1):
                print(f"{'>' if i == ln else ' '}{i:4} {lines[i - 1]}")


if __name__ == "__main__":
    main()
