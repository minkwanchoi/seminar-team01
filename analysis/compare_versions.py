"""CWE 버전 사이에 비교 결과가 어떻게 달라지는지 정리한다.

data/cwe/vX.Y/overlap_*.csv(analysis/overlap.py 결과)를 읽어 두 파일을 만든다.
  data/cwe/version_summary.csv  버전마다 핵심 수치(뷰 크기, 공통 수, Jaccard, 참고 사례 대비 비율 등)
  data/cwe/version_diff.csv     인접한 두 버전 사이에 목록마다 늘거나 빠진 CWE

실행: python analysis/compare_versions.py
"""

from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
CWE_DIR = DATA_DIR / "cwe"
FIXED = {"cwe_id", "cwe", "name", "abstraction", "pillar", "pillar_name", "category", "category_ko", "n_sets"}
MANUAL44, MOIS, C_VIEW = "매뉴얼 보안약점 44", "행안부 49", "매뉴얼·C (CWE-658)"


def versions() -> pd.DataFrame:
    df = pd.read_csv(CWE_DIR / "versions.csv", dtype=str)
    order = sorted(df["version"], key=lambda v: tuple(int(x) for x in v.split(".")))
    return df.set_index("version").loc[order].reset_index()


def sets_of(version: str) -> dict[str, set[int]]:
    m = pd.read_csv(CWE_DIR / f"v{version}" / "overlap_matrix.csv")
    return {c: set(m.loc[m[c] == 1, "cwe_id"]) for c in m.columns if c not in FIXED}


def jaccard(a: set, b: set) -> float:
    return round(len(a & b) / len(a | b), 4) if a | b else 0.0


def summary_row(version: str, release: str) -> dict:
    vdir = CWE_DIR / f"v{version}"
    s = sets_of(version)
    views = [c for c in s if c.startswith("매뉴얼·")]
    view_union = set().union(*(s[c] for c in views))
    common = pd.read_csv(vdir / "overlap_common.csv")["cwe_id"].tolist()
    ref = pd.read_csv(vdir / "overlap_reference.csv").set_index("reference")
    flags = pd.read_csv(DATA_DIR / "mapping_manual44.csv", dtype=str)
    flagged = {int(x) for x in flags.loc[flags["overlap_flag"] == "O", "cwe_ids"]}
    domestic = set().union(*(ids for n, ids in s.items() if n not in ref.index))
    row = {"version": version, "release_date": release}
    for c in views:
        row[f"size_{c.split('(')[1].rstrip(')').replace('CWE-', 'cwe')}"] = len(s[c])
    row.update({
        "view_union": len(view_union),
        "domestic_total": len(domestic),
        "domestic_common": len(common),
        "domestic_common_cwes": ";".join(map(str, common)),
        "manual44_mois_common": len(s[MANUAL44] & s[MOIS]),
        "manual44_mois_jaccard": jaccard(s[MANUAL44], s[MOIS]),
        "c_mois_common": len(s[C_VIEW] & s[MOIS]),
        "c_mois_jaccard": jaccard(s[C_VIEW], s[MOIS]),
        "views_mois_common": len(view_union & s[MOIS]),
        "manual44_flagged": len(flagged),
        "manual44_flagged_outside_views": len(flagged - view_union),
        "manual44_flagged_outside_cwes": ";".join(map(str, sorted(flagged - view_union))),
    })
    for name, r in ref.iterrows():
        key = {"CWE Top 25 (2025)": "top25", "SEI CERT C·C++": "cert", "CISQ 품질 측정": "cisq"}[name]
        row[f"{key}_covered"] = int(r["covered_domestic"])
        row[f"{key}_size"] = int(r["size"])
    return row


def main() -> None:
    vs = versions()
    summary = pd.DataFrame([summary_row(v, d) for v, d in zip(vs["version"], vs["release_date"])])
    summary.to_csv(CWE_DIR / "version_summary.csv", index=False, encoding="utf-8")

    rows = []
    order = vs["version"].tolist()
    for old, new in zip(order, order[1:]):
        a, b = sets_of(old), sets_of(new)
        for name in b:
            if name not in a:
                continue
            added, removed = sorted(b[name] - a[name]), sorted(a[name] - b[name])
            rows.append({"from": old, "to": new, "list": name, "size_from": len(a[name]), "size_to": len(b[name]),
                         "added": len(added), "removed": len(removed),
                         "added_cwes": ";".join(map(str, added)), "removed_cwes": ";".join(map(str, removed))})
    diff = pd.DataFrame(rows, columns=["from", "to", "list", "size_from", "size_to", "added", "removed",
                                       "added_cwes", "removed_cwes"])
    diff.to_csv(CWE_DIR / "version_diff.csv", index=False, encoding="utf-8")

    pd.set_option("display.width", 200)
    print(summary.drop(columns=[c for c in summary.columns if c.endswith("_cwes")]).T.to_string())
    print()
    print(diff[["from", "to", "list", "size_from", "size_to", "added", "removed"]].to_string(index=False))


if __name__ == "__main__":
    main()
