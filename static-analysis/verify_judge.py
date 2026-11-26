"""B6 판정 결과 검산. judge.py를 돌린 뒤 실행하며, 하나라도 어긋나면 멈춘다(종료 코드 1).

1단계 규칙 예시: examples/의 가짜 케이스와 세 도구의 가짜 출력을 judge.py의 함수로 읽어,
          판정 규칙 문장(docs/B_판정기록.md J7~J11)으로 손으로 따진 examples/expected_judge.csv와
          한 칸씩 맞춘다(구역, 도구 출력 읽기, clang-tidy 대응표, 관련 CWE, 탐지·오탐 분류).
          틀리면 2단계로 가지 않는다.
2단계 다른 경로로 다시 집계: results/detection_by_case.csv(케이스 × 도구 판정)에서
          judge.py의 집계 코드를 쓰지 않고 CWE별 탐지율, 세 도구 합집합, 제도별 충족 항목 수를
          다시 세어 results/의 detection_by_cwe.csv·regime_coverage.csv와 맞춘다.
          매핑이나 케이스 목록을 바꾸고 judge.py를 다시 돌리지 않았으면 여기서 걸린다.
3단계 보고 수치: 보고서·페이지에 쓴 수치(expected_b6.csv)와 맞춘다.

실행: python static-analysis/verify_judge.py
순서: select_cases.py → run_tools.py(WSL) → judge.py → verify_judge.py
도구 출력(_runs/)이 없어도 돈다. 판정 자체(도구 출력 → detection_by_case)를 다시 하지는 않는다.
"""

import csv
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
EX = HERE / "examples"
RES = HERE / "results"
DATA = ROOT / "data"
UNION = "세 도구 합집합"

sys.path.insert(0, str(HERE))
import judge  # noqa: E402  1단계에서 judge.py의 함수를 그대로 시험한다


def read_csv(path: Path) -> list[dict]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def ids(cell: str) -> set[int]:
    return {int(x) for x in (cell or "").split(";") if x.strip()}


class Check:
    def __init__(self):
        self.n = 0
        self.bad = []

    def eq(self, name: str, got, want) -> None:
        self.n += 1
        if got != want:
            self.bad.append(f"  {name}: 결과 {got!r} ≠ 기대 {want!r}")

    def report(self, stage: str) -> None:
        if self.bad:
            print(f"✗ {stage}: {len(self.bad)}/{self.n}개 어긋남")
            print("\n".join(self.bad))
            sys.exit(1)
        print(f"✓ {stage}: {self.n}개 값이 모두 같음")


# ── 1단계 ──
def stage1(rel: "judge.Relations") -> None:
    c = Check()
    reg = judge.regions(EX / "example_case.c")
    ct_map = judge.load_ct_map()
    found = {
        "cppcheck": list(judge.parse_cppcheck(judge.read(EX / "example_cppcheck.xml", encoding="utf-8"))),
        "flawfinder": list(judge.parse_flawfinder(judge.read(EX / "example_flawfinder.csv", encoding="utf-8"))),
        "clang-tidy": list(judge.parse_clang_tidy(judge.read(EX / "example_clang_tidy.txt", encoding="utf-8"), ct_map)),
    }

    def cwes_at(tool: str, line: int) -> set[int]:
        return set().union(*[f["cwes"] for f in found[tool] if f["line"] == line])

    for r in read_csv(EX / "expected_judge.csv"):
        t, inp, want = r["test"], r["input"], r["expected"]
        name = f"{t} {inp}"
        if t == "region":
            c.eq(name, reg.get(int(inp), "other"), want)
        elif t == "parse":
            tool, what = inp.split(":")
            if what == "count":
                c.eq(name, len(found[tool]), int(want))
            else:
                c.eq(name, cwes_at(tool, int(what)), ids(want))
        elif t == "ct_map":
            rule, msg = inp.split("|", 1)
            c.eq(name, judge.ct_cwes(ct_map, rule, msg), ids(want))
        elif t == "related":
            f, targets = inp.split("|")
            c.eq(name, rel.related(int(f), ids(targets)), want == "True")
        elif t == "classify":
            where, targets = inp.split("|")
            tool, line = where.split(":")
            cw = cwes_at(tool, int(line))
            if not any(rel.related(x, ids(targets)) for x in cw):
                got = "무관"
            else:
                got = {"bad": "TP", "good": "FP"}.get(reg.get(int(line), "other"), "기타")
            c.eq(name, got, want)
        else:
            c.eq(name, "알 수 없는 test", t)
    c.report("1단계 규칙 예시")


# ── 2단계 ──
def stage2() -> dict:
    c = Check()
    case = read_csv(RES / "detection_by_case.csv")
    tools = sorted({r["tool"] for r in case} - {UNION})

    # 세 도구 합집합 행이 도구별 행과 맞는가
    per = defaultdict(dict)
    for r in case:
        per[r["case_id"]][r["tool"]] = r
    for cid, d in per.items():
        u = d[UNION]
        for col in ("analyzable", "detected", "exact_line"):
            c.eq(f"합집합 {cid} {col}", u[col], str(max(int(d[t][col]) for t in tools)))
        c.eq(f"합집합 {cid} false_positives", int(u["false_positives"]), sum(int(d[t]["false_positives"]) for t in tools))

    # CWE별 탐지율 다시 세기
    agg = defaultdict(lambda: [0, 0, 0, 0, 0])
    for r in case:
        a = agg[(r["cwe_id"], r["match"], r["b2_cwe"], r["tool"])]
        a[0] += 1
        a[1] += int(r["analyzable"])
        a[2] += int(r["detected"])
        a[3] += int(r["exact_line"])
        a[4] += int(r["false_positives"])
    saved = read_csv(RES / "detection_by_cwe.csv")
    c.eq("detection_by_cwe 행 수", len(saved), len(agg))
    for r in saved:
        a = agg.get((r["cwe_id"], r["match"], r["b2_cwe"], r["tool"]))
        if a is None:
            c.eq(f"detection_by_cwe {r['cwe_id']} {r['tool']}", "다시 센 결과에 없음", "있음")
            continue
        got = [int(r["cases"]), int(r["analyzable"]), int(r["detected"]), int(r["exact_line"]), int(r["false_positives"])]
        c.eq(f"detection_by_cwe CWE-{r['cwe_id']} {r['tool']}", got, a)
        rate = f"{a[2] / a[1]:.3f}" if a[1] else ""
        c.eq(f"detection_by_cwe CWE-{r['cwe_id']} {r['tool']} 탐지율", r["detection_rate"], rate)

    # 제도별 충족 항목 수 다시 세기: 매핑 CSV를 직접 읽어 항목 단위로
    by_b2 = defaultdict(lambda: [0, 0, 0, 0])  # (b2, tool) → 정확 케이스, 정확 탐지, 하위 케이스, 하위 탐지
    for r in case:
        if r["analyzable"] != "1":
            continue
        for b in ids(r["b2_cwe"]):
            v = by_b2[(b, r["tool"])]
            k = 0 if r["match"] == "정확" else 2
            v[k] += 1
            v[k + 1] += int(r["detected"])
    m44 = read_csv(DATA / "mapping_manual44.csv")
    m49 = read_csv(DATA / "mapping_mois49.csv")
    s44 = set().union(*[ids(r["cwe_ids"]) for r in m44])
    s49 = set().union(*[ids(r["cwe_ids"]) for r in m49])
    regimes = {
        "매뉴얼 보안약점 44": [ids(r["cwe_ids"]) for r in m44],
        "행안부 49": [ids(r["cwe_ids"]) for r in m49],
        "두 제도 공통": [{x} for x in s44 & s49],
        "두 제도 합집합": [{x} for x in s44 | s49],
    }
    mine = {}
    for name, items in regimes.items():
        for tool in tools + [UNION]:
            def flag(item, test):
                return any(test(by_b2.get((b, tool), [0, 0, 0, 0])) for b in item)
            mine[(name, tool)] = {
                "items": len(items),
                "testable": sum(flag(i, lambda v: v[0] + v[2] > 0) for i in items),
                "testable_exact": sum(flag(i, lambda v: v[0] > 0) for i in items),
                "met_any": sum(flag(i, lambda v: v[1] + v[3] > 0) for i in items),
                "met_exact_any": sum(flag(i, lambda v: v[1] > 0) for i in items),
                "met_exact_half": sum(flag(i, lambda v: v[0] > 0 and v[1] / v[0] >= 0.5) for i in items),
            }
    cov = read_csv(RES / "regime_coverage.csv")
    c.eq("regime_coverage 행 수", len(cov), len(mine))
    for r in cov:
        want = mine.get((r["regime"], r["tool"]))
        got = {k: int(r[k]) for k in ("items", "testable", "testable_exact", "met_any", "met_exact_any", "met_exact_half")}
        c.eq(f"regime_coverage {r['regime']} {r['tool']}", got, want)
    c.report("2단계 다른 경로로 다시 집계")
    return {"case": case, "cov": cov}


# ── 3단계 ──
def stage3(d: dict) -> None:
    c = Check()
    case, cov = d["case"], d["cov"]
    cases = read_csv(HERE / "juliet_cases.csv")
    fp = read_csv(RES / "fp_by_rule.csv")
    got = {
        "cases.total": len(cases),
        "cases.exact": sum(r["match"] == "정확" for r in cases),
        "cases.child": sum(r["match"] == "하위" for r in cases),
        "clang-tidy.unanalyzable_cases": sum(r["tool"] == "clang-tidy" and r["analyzable"] == "0" for r in case),
        "fp.total": sum(int(r["false_positives"]) for r in fp),
    }
    for m, k in (("정확", "exact"), ("하위", "child")):
        rs = [r for r in case if r["tool"] == UNION and r["match"] == m]
        got[f"union.{k}.detected"] = sum(int(r["detected"]) for r in rs)
        got[f"union.{k}.analyzable"] = sum(int(r["analyzable"]) for r in rs)
    for t in ("cppcheck", "clang-tidy", "flawfinder"):
        got[f"fp.{t}"] = sum(int(r["false_positives"]) for r in fp if r["tool"] == t)
    for r in cov:
        if r["tool"] == UNION:
            for k in ("testable_exact", "met_exact_any", "met_exact_half", "met_any"):
                got[f"{r['regime']}.{k}"] = int(r[k])
    for r in read_csv(HERE / "expected_b6.csv"):
        c.eq(r["check"], got.get(r["check"], "결과에 없음"), int(r["expected"]))
    c.report("3단계 보고 수치")


def main() -> None:
    rel = judge.Relations(judge.latest_cwe_version())
    stage1(rel)
    d = stage2()
    stage3(d)


if __name__ == "__main__":
    main()
