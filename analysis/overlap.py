"""B3. 제도 간 CWE 겹침 분석.

data/의 CWE 목록과 제도별 매핑을 읽어 CWE × 제도 매트릭스를 만들고,
제도 쌍별 교집합·Jaccard 유사도, 제도별 고유 항목, 전 제도 공통 항목을 계산한다.

실행: python analysis/overlap.py [--exclude-java] [--with-local]

공개할 수 없는 자료는 local/mapping_*.csv로 두고 커밋하지 않는다(.gitignore).
--with-local을 주면 그 자료까지 넣어 비교하고, 결과는 공개 결과(data/)와 섞이지 않게 local/out/에 쓴다.
"""

import argparse
from itertools import combinations
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
LOCAL_DIR = ROOT / "local"  # .gitignore 대상. 공개·재배포할 수 없는 자료


def cwe_ids_from_list(filename: str) -> set[int]:
    return set(pd.read_csv(DATA_DIR / filename)["cwe_id"].astype(int))


def cwe_ids_from_mapping(path: Path) -> set[int]:
    """매핑 파일의 cwe_ids 열(세미콜론 구분, 1:N)을 CWE 번호 집합으로 펼친다."""
    df = pd.read_csv(path, dtype=str)
    ids = set()
    for cell in df["cwe_ids"].dropna():
        ids.update(int(x) for x in cell.split(";") if x.strip())
    return ids


def load_sets(exclude_java: bool, with_local: bool) -> dict[str, set[int]]:
    """비교할 제도(집합)를 순서대로 읽는다. local/의 비공개 집합은 with_local일 때만 넣는다."""
    candidates = [
        ("매뉴얼·C (CWE-658)", lambda: cwe_ids_from_list("cwe_658.csv")),
        ("매뉴얼·C++ (CWE-659)", lambda: cwe_ids_from_list("cwe_659.csv")),
    ]
    if not exclude_java:
        candidates.append(("매뉴얼·Java (CWE-660)", lambda: cwe_ids_from_list("cwe_660.csv")))
    candidates += [
        # 학술 인용 기준에 따라 CWE 번호만 출처와 함께 인용한 목록(data/README.md 참고)
        ("매뉴얼 보안약점 44", lambda: cwe_ids_from_mapping(DATA_DIR / "mapping_manual44.csv")),
        ("행안부 49", lambda: cwe_ids_from_mapping(DATA_DIR / "mapping_mois49.csv")),
        ("CWE Top 25 (2025)", lambda: cwe_ids_from_list("cwe_top25_2025.csv")),
    ]
    if with_local:
        private = sorted(LOCAL_DIR.glob("mapping_*.csv"))
        if not private:
            raise SystemExit(f"{LOCAL_DIR}에 mapping_*.csv가 없습니다. 공개 자료만 비교하려면 --with-local 없이 실행하세요")
        for path in private:
            candidates.append((f"(비공개) {path.stem.removeprefix('mapping_')}",
                               lambda path=path: cwe_ids_from_mapping(path)))
    sets = {}
    for name, load in candidates:
        ids = load()
        if ids:
            sets[name] = ids
        else:
            print(f"[건너뜀] {name}: 매핑이 아직 비어 있음")
    return sets


def build_matrix(sets: dict[str, set[int]]) -> pd.DataFrame:
    pillars = pd.read_csv(DATA_DIR / "cwe_pillar.csv")
    all_ids = sorted(set().union(*sets.values()))
    m = pd.DataFrame({"cwe_id": all_ids})
    m.insert(1, "cwe", "CWE-" + m["cwe_id"].astype(str))
    m = m.merge(pillars[["cwe_id", "name", "abstraction", "pillar", "pillar_name"]],
                on="cwe_id", how="left")
    categories = pd.read_csv(DATA_DIR / "cwe_category.csv")
    m = m.merge(categories[["cwe_id", "category", "category_ko"]], on="cwe_id", how="left")
    # 원문이 인용했지만 CWE 4.20에서 폐기된 번호(예: 247)는 두 뷰 어디에도 없다
    m = m.fillna({"name": "(CWE 4.20에서 폐기됨)", "abstraction": "Deprecated",
                  "pillar": "폐기", "pillar_name": "CWE 4.20에서 폐기된 번호",
                  "category": "Deprecated", "category_ko": "폐기된 번호"})
    for name, ids in sets.items():
        m[name] = m["cwe_id"].isin(ids).astype(int)
    m["n_sets"] = m[list(sets)].sum(axis=1)
    return m


def pair_table(sets: dict[str, set[int]]) -> pd.DataFrame:
    rows = []
    for a, b in combinations(sets, 2):
        inter = sets[a] & sets[b]
        union = sets[a] | sets[b]
        rows.append({
            "set_a": a, "set_b": b,
            "size_a": len(sets[a]), "size_b": len(sets[b]),
            "intersection": len(inter), "union": len(union),
            "jaccard": round(len(inter) / len(union), 4),
            "only_a": len(sets[a] - sets[b]), "only_b": len(sets[b] - sets[a]),
            "shared_cwes": ";".join(str(i) for i in sorted(inter)),
        })
    return pd.DataFrame(rows)


def summary_table(sets: dict[str, set[int]]) -> pd.DataFrame:
    rows = []
    for name, ids in sets.items():
        others = set().union(*(s for n, s in sets.items() if n != name))
        unique = ids - others
        rows.append({
            "set": name, "size": len(ids), "unique": len(unique),
            "unique_cwes": ";".join(str(i) for i in sorted(unique)),
        })
    return pd.DataFrame(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--exclude-java", action="store_true",
                        help="CWE-660(Java)을 비교에서 뺀다. 매뉴얼 취약점 점검이 세 뷰를 모두 쓰므로 기본은 포함")
    parser.add_argument("--with-local", action="store_true",
                        help="local/mapping_*.csv의 비공개 자료까지 넣고, 결과를 local/out/에 쓴다")
    args = parser.parse_args()

    sets = load_sets(args.exclude_java, args.with_local)
    out = LOCAL_DIR / "out" if args.with_local else DATA_DIR
    out.mkdir(parents=True, exist_ok=True)
    matrix = build_matrix(sets)
    pairs = pair_table(sets)
    summary = summary_table(sets)
    common = matrix[matrix["n_sets"] == len(sets)]

    matrix.to_csv(out / "overlap_matrix.csv", index=False, encoding="utf-8")
    pairs.to_csv(out / "overlap_pairs.csv", index=False, encoding="utf-8")
    summary.to_csv(out / "overlap_summary.csv", index=False, encoding="utf-8")
    common.to_csv(out / "overlap_common.csv", index=False, encoding="utf-8")

    pd.set_option("display.width", 200)
    print(f"[{'로컬(비공개 포함) → local/out/' if args.with_local else '공개 → data/'}]")
    print(f"비교한 제도 {len(sets)}개, 전체 CWE {len(matrix)}개, 전 제도 공통 {len(common)}개\n")
    print(summary[["set", "size", "unique"]].to_string(index=False))
    print()
    print(pairs[["set_a", "set_b", "intersection", "union", "jaccard"]].to_string(index=False))


if __name__ == "__main__":
    main()
