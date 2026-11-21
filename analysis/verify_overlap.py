"""겹침 분석 결과 검산. overlap.py를 돌린 뒤 실행하며, 하나라도 어긋나면 멈춘다(종료 코드 1).

1단계 손계산 예시: data/examples/의 작은 목록을 overlap.py의 함수로 계산해,
          사람이 손으로 센 data/examples/expected.csv와 한 칸씩 맞춘다. 틀리면 2단계로 가지 않는다.
2단계 다른 경로로 다시 계산: 원자료(언어별 뷰 CSV, 매핑 CSV)를 pandas 없이 표준 라이브러리로
          다시 읽어 집합을 만들고, 저장된 overlap_pairs·summary·common.csv와 맞춘다.
          매핑을 고치고 overlap.py를 다시 돌리지 않았으면 여기서 걸린다.
3단계 보고 수치: 보고서·README에 적은 수치(data/expected_counts.csv의 '결과' 행)와 맞춘다.

실행: python analysis/verify_overlap.py
순서: check_inputs.py → overlap.py --all-versions → verify_overlap.py
"""

import csv
import sys
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import overlap  # noqa: E402  1단계에서 overlap.py의 함수를 그대로 시험한다

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
EXAMPLES = DATA / "examples"
CWE_DIR = DATA / "cwe"


def read_csv(path: Path) -> list[dict]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def mapping_ids(path: Path) -> set[int]:
    return {int(x) for r in read_csv(path) for x in (r["cwe_ids"] or "").split(";") if x.strip()}


def view_ids(path: Path) -> set[int]:
    return {int(r["cwe_id"]) for r in read_csv(path)}


class Report:
    def __init__(self):
        self.failures: list[str] = []
        self.passed = 0

    def check(self, label: str, expected, actual, names=("기대", "실제")) -> None:
        if str(expected) == str(actual):
            self.passed += 1
        else:
            self.failures.append(f"{label}: {names[0]} {expected!r}, {names[1]} {actual!r}")

    def stop_if_failed(self, stage: str) -> None:
        if self.failures:
            print(f"\n멈춤({stage}): 어긋난 값 {len(self.failures)}개")
            for f in self.failures:
                print(" -", f)
            sys.exit(1)
        print(f"{stage}: 통과 (누적 {self.passed}개)")


def stage1_examples(rep: Report) -> None:
    sets = {k: overlap.cwe_ids_from_mapping(EXAMPLES / f"list_{k.lower()}.csv") for k in "ABC"}
    got = {(r["set_a"], r["set_b"]): r for r in overlap.pair_table(sets).to_dict("records")}
    for exp in read_csv(EXAMPLES / "expected.csv"):
        row = got.get((exp["set_a"], exp["set_b"]))
        if row is None:
            rep.failures.append(f"예시 {exp['set_a']}·{exp['set_b']}: 결과에 쌍이 없음")
            continue
        for col in ["size_a", "size_b", "intersection", "union", "only_a", "only_b", "shared_cwes"]:
            rep.check(f"예시 {exp['set_a']}·{exp['set_b']} {col}", exp[col], row[col])
        rep.check(f"예시 {exp['set_a']}·{exp['set_b']} jaccard", float(exp["jaccard"]), float(row["jaccard"]))
    summary = {r["set"]: r for r in overlap.summary_table(sets).to_dict("records")}
    for name, unique in {"A": "1;2", "B": "5", "C": "6"}.items():
        rep.check(f"예시 {name} 고유 번호", unique, summary[name]["unique_cwes"])
    rep.check("예시 공통 번호", "4", ";".join(map(str, sorted(set.intersection(*sets.values())))))
    rep.stop_if_failed("1단계 손계산 예시")


def domestic_sets(vdir: Path) -> dict[str, set[int]]:
    """overlap.py의 국내 목록 다섯 개(기본 설정: Java 포함)를 다른 경로로 다시 만든다."""
    return {
        "매뉴얼·C (CWE-658)": view_ids(vdir / "cwe_658.csv"),
        "매뉴얼·C++ (CWE-659)": view_ids(vdir / "cwe_659.csv"),
        "매뉴얼·Java (CWE-660)": view_ids(vdir / "cwe_660.csv"),
        "매뉴얼 보안약점 44": mapping_ids(DATA / "mapping_manual44.csv"),
        "행안부 49": mapping_ids(DATA / "mapping_mois49.csv"),
    }


SAVED = ("다시 계산", "저장된 결과")


def stage2_recompute(rep: Report) -> dict[str, dict[str, int]]:
    figures: dict[str, dict[str, int]] = {}
    for vdir in sorted(p for p in CWE_DIR.glob("v*") if p.is_dir()):
        v = vdir.name.removeprefix("v")
        sets = domestic_sets(vdir)
        saved_pairs = {(r["set_a"], r["set_b"]): r for r in read_csv(vdir / "overlap_pairs.csv")}
        rep.check(f"{v} 쌍 수", len(list(combinations(sets, 2))), len(saved_pairs), SAVED)
        for a, b in combinations(sets, 2):
            row = saved_pairs.get((a, b))
            if row is None:
                rep.failures.append(f"{v} {a}·{b}: overlap_pairs.csv에 쌍이 없음")
                continue
            inter, union = sets[a] & sets[b], sets[a] | sets[b]
            tag = f"{v} {a}·{b}"
            rep.check(f"{tag} 교집합", len(inter), row["intersection"], SAVED)
            rep.check(f"{tag} 합집합", len(union), row["union"], SAVED)
            rep.check(f"{tag} Jaccard", round(len(inter) / len(union), 4), float(row["jaccard"]), SAVED)
            rep.check(f"{tag} 공유 번호", ";".join(map(str, sorted(inter))), row["shared_cwes"], SAVED)
        for r in read_csv(vdir / "overlap_summary.csv"):
            ids = sets[r["set"]]
            others = set().union(*(s for n, s in sets.items() if n != r["set"]))
            rep.check(f"{v} {r['set']} 크기", len(ids), r["size"], SAVED)
            rep.check(f"{v} {r['set']} 고유", len(ids - others), r["unique"], SAVED)
        common = set.intersection(*sets.values())
        saved_common = {int(r["cwe_id"]) for r in read_csv(vdir / "overlap_common.csv")}
        rep.check(f"{v} 공통 번호", sorted(common), sorted(saved_common), SAVED)

        lang = sets["매뉴얼·C (CWE-658)"] | sets["매뉴얼·C++ (CWE-659)"] | sets["매뉴얼·Java (CWE-660)"]
        figures[v] = {
            "domestic.unique_cwe": len(set().union(*sets.values())),
            "domestic.common": len(common),
            "lang_views.union": len(lang),
            "lang_views.and_mois49": len(lang & sets["행안부 49"]),
            "manual44.and_mois49": len(sets["매뉴얼 보안약점 44"] & sets["행안부 49"]),
        }
    rep.stop_if_failed("2단계 다른 경로로 다시 계산")
    return figures


def stage3_reported(rep: Report, figures: dict[str, dict[str, int]]) -> None:
    for r in read_csv(DATA / "expected_counts.csv"):
        if r["stage"] != "결과":
            continue
        got = figures.get(r["cwe_version"], {}).get(r["check"], "(계산 안 됨)")
        rep.check(f"보고 수치 {r['check']} (CWE {r['cwe_version']})", r["expected"], got)
    rep.stop_if_failed("3단계 보고 수치")


def main() -> None:
    rep = Report()
    stage1_examples(rep)
    figures = stage2_recompute(rep)
    stage3_reported(rep, figures)
    print("\n모든 검산 통과")


if __name__ == "__main__":
    main()
