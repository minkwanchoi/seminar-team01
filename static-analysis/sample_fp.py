"""B6. 관련 CWE 오탐(정상 구역의 지적)에서 유형 분류용 표본을 뽑는다.

judge.py가 _runs/<실행이름>/fp_candidates.csv에 쓴 오탐 후보에서, 도구마다 (CWE, 검사 이름) 묶음을
골고루 덮도록 뽑는다. 같은 씨앗(--seed)이면 같은 표본이 나온다.
뽑은 표본은 results/fp_sample.csv에 쓰고, 그 행에 붙은 지적 줄 앞뒤 코드를 함께 보여 준다.
유형(fp_type)과 이유(reason)는 사람이 코드를 읽고 채운다. 이미 채운 행은 덮어쓰지 않는다.

실행: python static-analysis/sample_fp.py --run all-20261121 [--per-tool 5] [--seed 20261121]
"""

import argparse
import csv
import random
from collections import defaultdict
from pathlib import Path

from judge import read  # 윈도 경로 길이 제한을 피해 읽기

HERE = Path(__file__).resolve().parent
JULIET = HERE / "_juliet" / "C"
OUT = HERE / "results" / "fp_sample.csv"
TOOLS = ["cppcheck", "clang-tidy", "flawfinder"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--per-tool", type=int, default=5)
    ap.add_argument("--seed", type=int, default=20261121)
    ap.add_argument("--show", action="store_true", help="표본 줄 앞뒤 코드 보이기")
    args = ap.parse_args()

    with open(HERE / "_runs" / args.run / "fp_candidates.csv", encoding="utf-8", newline="") as f:
        cand = list(csv.DictReader(f))
    with open(HERE / "juliet_cases.csv", encoding="utf-8", newline="") as f:
        files = {r["case_id"]: r["files"].split(";") for r in csv.DictReader(f)}

    old = {}
    if OUT.exists():
        with open(OUT, encoding="utf-8", newline="") as f:
            old = {(r["case_id"], r["tool"], r["file"], r["line"], r["rule"]): r for r in csv.DictReader(f)}

    rng = random.Random(args.seed)
    sample = []
    for tool in TOOLS:
        groups = defaultdict(list)
        for r in cand:
            if r["tool"] == tool:
                groups[(r["cwe_id"], r["rule"])].append(r)
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
        k = (r["case_id"], r["tool"], r["file"], r["line"], r["rule"])
        prev = old.get(k, {})
        rows.append({"no": n, **r, "fp_type": prev.get("fp_type", ""), "reason": prev.get("reason", "")})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"오탐 후보 {len(cand)}건에서 표본 {len(rows)}건 → {OUT.relative_to(HERE.parent)}")

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
