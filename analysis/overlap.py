"""B3. 국내 시험 목록 간 CWE 겹침 분석.

data/cwe/vX.Y/의 CWE 목록(버전별)과 data/의 매핑을 읽어 CWE × 목록 매트릭스를 만든다.
겹침(쌍별 교집합·Jaccard 유사도, 고유 항목, 공통 항목)은 국내 목록끼리만 계산하고,
해외 목록(Top 25, SEI CERT C·C++, CISQ)은 참고 사례로 두어 국내 목록이 얼마나 덮는지만 계산한다.

실행: python analysis/overlap.py [--cwe-version 4.20 | --all-versions] [--exclude-java] [--with-local]
결과는 그 버전 폴더(data/cwe/vX.Y/overlap_*.csv)에 쓴다. 버전을 생략하면 data/cwe/versions.csv의 최신 버전.

공개할 수 없는 자료는 local/mapping_*.csv로 두고 커밋하지 않는다(.gitignore).
--with-local을 주면 그 자료까지 넣어 비교하고, 결과는 공개 결과(data/)와 섞이지 않게 local/out/에 쓴다.
"""

import argparse
from itertools import combinations
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
CWE_DIR = DATA_DIR / "cwe"
LOCAL_DIR = ROOT / "local"  # .gitignore 대상. 공개·재배포할 수 없는 자료
VDIR = CWE_DIR  # 분석할 CWE 버전 폴더. main()에서 정한다


def versions() -> list[str]:
    vs = pd.read_csv(CWE_DIR / "versions.csv", dtype=str)["version"]
    return sorted(vs, key=lambda v: tuple(int(x) for x in v.split(".")))


def cwe_ids_from_list(filename: str) -> set[int]:
    """버전 폴더의 뷰 목록. Top 25처럼 연도별 목록은 data/에 있다."""
    path = VDIR / filename if (VDIR / filename).exists() else DATA_DIR / filename
    return set(pd.read_csv(path)["cwe_id"].astype(int))


def cwe_ids_from_mapping(path: Path) -> set[int]:
    """매핑 파일의 cwe_ids 열(세미콜론 구분, 1:N)을 CWE 번호 집합으로 펼친다."""
    df = pd.read_csv(path, dtype=str)
    ids = set()
    for cell in df["cwe_ids"].dropna():
        ids.update(int(x) for x in cell.split(";") if x.strip())
    return ids


REFERENCE = ["CWE Top 25 (2025)", "SEI CERT C·C++", "CISQ 품질 측정"]  # 해외 참고 사례


def load_sets(exclude_java: bool, with_local: bool) -> dict[str, set[int]]:
    """비교할 목록(집합)을 순서대로 읽는다. local/의 비공개 집합은 with_local일 때만 넣는다."""
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
    ]
    if with_local:
        private = sorted(LOCAL_DIR.glob("mapping_*.csv"))
        if not private:
            raise SystemExit(f"{LOCAL_DIR}에 mapping_*.csv가 없습니다. 공개 자료만 비교하려면 --with-local 없이 실행하세요")
        for path in private:
            candidates.append((f"(비공개) {path.stem.removeprefix('mapping_')}",
                               lambda path=path: cwe_ids_from_mapping(path)))
    # 해외 참고 사례(MITRE 공식 뷰). CERT C와 C++는 한 집합으로 묶는다
    candidates += [
        ("CWE Top 25 (2025)", lambda: cwe_ids_from_list("cwe_top25_2025.csv")),
        ("SEI CERT C·C++", lambda: cwe_ids_from_list("cwe_cert_c.csv") | cwe_ids_from_list("cwe_cert_cpp.csv")),
        ("CISQ 품질 측정", lambda: cwe_ids_from_list("cwe_cisq.csv")),
    ]
    sets = {}
    for name, load in candidates:
        ids = load()
        if ids:
            sets[name] = ids
        else:
            print(f"[건너뜀] {name}: 매핑이 아직 비어 있음")
    return sets


def split_sets(sets: dict[str, set[int]]) -> tuple[dict[str, set[int]], dict[str, set[int]]]:
    domestic = {n: s for n, s in sets.items() if n not in REFERENCE}
    reference = {n: s for n, s in sets.items() if n in REFERENCE}
    return domestic, reference


def build_matrix(sets: dict[str, set[int]]) -> pd.DataFrame:
    pillars = pd.read_csv(VDIR / "cwe_pillar.csv")
    all_ids = sorted(set().union(*sets.values()))
    m = pd.DataFrame({"cwe_id": all_ids})
    m.insert(1, "cwe", "CWE-" + m["cwe_id"].astype(str))
    m = m.merge(pillars[["cwe_id", "name", "abstraction", "pillar", "pillar_name"]],
                on="cwe_id", how="left")
    categories = pd.read_csv(VDIR / "cwe_category.csv")
    m = m.merge(categories[["cwe_id", "category", "category_ko"]], on="cwe_id", how="left")
    # 원문이 인용했지만 이 버전에서 폐기되었거나 아직 없는 번호(예: 4.20의 247)는 연구 관점 뷰에 없다
    version = VDIR.name.removeprefix("v")
    catalog = pd.read_csv(VDIR / "cwe_all.csv").set_index("cwe_id")
    for i in m.index[m["pillar"].isna()]:
        cid = m.at[i, "cwe_id"]
        if cid in catalog.index:
            m.at[i, "name"] = catalog.at[cid, "name"]  # MITRE 이름이 "DEPRECATED: …"로 시작함
            label, note = "폐기", f"CWE {version}에서 폐기된 번호"
        else:
            m.at[i, "name"] = f"(CWE {version}에 없는 번호)"
            label, note = "없음", f"CWE {version}에 없는 번호"
        m.loc[i, ["abstraction", "pillar", "pillar_name"]] = ["Deprecated", label, note]
    m = m.fillna({"category": "Deprecated", "category_ko": "폐기·없는 번호"})
    for name, ids in sets.items():
        m[name] = m["cwe_id"].isin(ids).astype(int)
    domestic, _ = split_sets(sets)
    m["n_sets"] = m[list(domestic)].sum(axis=1)  # 국내 목록 중 몇 개에 들어 있는지
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


def reference_table(sets: dict[str, set[int]]) -> pd.DataFrame:
    """해외 참고 사례마다 국내 목록이 덮는 CWE 수와 비율."""
    domestic, reference = split_sets(sets)
    groups = {
        "domestic": set().union(*domestic.values()),
        "manual": set().union(*(s for n, s in domestic.items() if n.startswith("매뉴얼"))),
        "mois": domestic.get("행안부 49", set()),
    }
    rows = []
    for name, ids in reference.items():
        row = {"reference": name, "size": len(ids)}
        for key, g in groups.items():
            row[f"covered_{key}"] = len(ids & g)
            row[f"pct_{key}"] = round(100 * len(ids & g) / len(ids), 1)
        row["missing_cwes"] = ";".join(str(i) for i in sorted(ids - groups["domestic"]))
        rows.append(row)
    return pd.DataFrame(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--exclude-java", action="store_true",
                        help="CWE-660(Java)을 비교에서 뺀다. 매뉴얼 취약점 점검이 세 뷰를 모두 쓰므로 기본은 포함")
    parser.add_argument("--with-local", action="store_true",
                        help="local/mapping_*.csv의 비공개 자료까지 넣고, 결과를 local/out/vX.Y/에 쓴다")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--cwe-version", help="분석할 CWE 버전(예: 4.10). 생략하면 최신 버전")
    group.add_argument("--all-versions", action="store_true", help="data/cwe/versions.csv의 모든 버전을 분석")
    args = parser.parse_args()

    known = versions()
    targets = known if args.all_versions else [args.cwe_version or known[-1]]
    for version in targets:
        if version not in known:
            raise SystemExit(f"CWE {version} 자료가 없습니다. 먼저 python analysis/fetch_cwe.py {version}")
        run(version, args)


def run(version: str, args) -> None:
    global VDIR
    VDIR = CWE_DIR / f"v{version}"
    sets = load_sets(args.exclude_java, args.with_local)
    domestic, _ = split_sets(sets)
    out = LOCAL_DIR / "out" / f"v{version}" if args.with_local else VDIR
    out.mkdir(parents=True, exist_ok=True)
    matrix = build_matrix(sets)
    pairs = pair_table(domestic)
    summary = summary_table(domestic)
    common = matrix[matrix["n_sets"] == len(domestic)]
    reference = reference_table(sets)

    matrix.to_csv(out / "overlap_matrix.csv", index=False, encoding="utf-8")
    pairs.to_csv(out / "overlap_pairs.csv", index=False, encoding="utf-8")
    summary.to_csv(out / "overlap_summary.csv", index=False, encoding="utf-8")
    common.to_csv(out / "overlap_common.csv", index=False, encoding="utf-8")
    reference.to_csv(out / "overlap_reference.csv", index=False, encoding="utf-8")

    pd.set_option("display.width", 200)
    print(f"[CWE {version} · {'로컬(비공개 포함)' if args.with_local else '공개'} → {out.relative_to(ROOT)}]")
    n_domestic = int((matrix["n_sets"] > 0).sum())
    print(f"국내 목록 {len(domestic)}개, 국내 CWE {n_domestic}개, 국내 공통 {len(common)}개"
          f" (해외 참고 사례까지 합친 전체 {len(matrix)}개)\n")
    print(summary[["set", "size", "unique"]].to_string(index=False))
    print()
    print(pairs[["set_a", "set_b", "intersection", "union", "jaccard"]].to_string(index=False))
    print()
    print(reference.drop(columns="missing_cwes").to_string(index=False))


if __name__ == "__main__":
    main()
