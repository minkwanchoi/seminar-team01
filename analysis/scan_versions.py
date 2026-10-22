"""여러 CWE 버전을 훑어 언어별 뷰 크기와 매뉴얼 44 '중복' 표시의 뷰 포함 여부를 정리한다.

버전마다 전체 분석(data/cwe/vX.Y/)을 만들지 않고, 가볍게 몇 가지 수치만 센다.
매뉴얼 보안약점 점검 목록의 "중복여부" O 표시가 CWE 버전 차이로 설명되는지 확인하려는 것이다.
결과: data/cwe/version_scan.csv

실행: python analysis/scan_versions.py [--from 2.9] [--to 4.20] [--cache 내려받은_파일을_둘_폴더]
버전 파일은 MITRE 아카이브(https://cwe.mitre.org/data/archive.html)에서 받으며 저장소에는 넣지 않는다.
"""

import argparse
import re
import sys
import tempfile
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cwe_xml import Catalog  # noqa: E402
from fetch_cwe import BASE, get  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"


def archive_versions() -> list[str]:
    found = set(re.findall(r"cwec_v([0-9.]+)\.xml\.zip", get(f"{BASE}/data/archive.html").text))
    return sorted(found, key=lambda v: tuple(int(x) for x in v.split(".")))


def key(v: str) -> tuple:
    return tuple(int(x) for x in v.split("."))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--from", dest="start", default="2.9", help="처음 버전(기본 2.9, CWE-660이 매뉴얼에 들어오기 전)")
    parser.add_argument("--to", dest="end", help="마지막 버전(기본 최신)")
    parser.add_argument("--cache", type=Path, help="버전 파일을 받아 둘 폴더(다시 실행할 때 재사용)")
    args = parser.parse_args()

    flags = pd.read_csv(DATA_DIR / "mapping_manual44.csv", dtype=str)
    flagged = {int(x) for x in flags.loc[flags["overlap_flag"] == "O", "cwe_ids"]}
    cache = args.cache or Path(tempfile.mkdtemp(prefix="cwe_scan_"))
    cache.mkdir(parents=True, exist_ok=True)

    targets = [v for v in archive_versions()
               if key(v) >= key(args.start) and (not args.end or key(v) <= key(args.end))]
    rows = []
    for v in targets:
        path = cache / f"cwec_v{v}.xml.zip"
        if not path.exists():
            path.write_bytes(get(f"{BASE}/data/xml/cwec_v{v}.xml.zip").content)
        cat = Catalog.from_zip(path.read_bytes())
        views = {vid: cat.view_members(vid) if vid in cat.views else set() for vid in (658, 659, 660)}
        union = set().union(*views.values())
        outside = sorted(flagged - union)
        rows.append({"version": v, "release_date": cat.date, "weaknesses": len(cat.weaknesses),
                     "size_cwe658": len(views[658]), "size_cwe659": len(views[659]), "size_cwe660": len(views[660]),
                     "view_union": len(union), "manual44_flagged": len(flagged),
                     "manual44_flagged_in_views": len(flagged & union),
                     "manual44_flagged_outside_views": len(outside),
                     "manual44_flagged_outside_cwes": ";".join(map(str, outside))})
        print(f"CWE {v} ({cat.date}): 뷰 합집합 {len(union)}, '중복' 표시 중 뷰 밖 {len(outside)}", flush=True)

    out = DATA_DIR / "cwe" / "version_scan.csv"
    pd.DataFrame(rows).to_csv(out, index=False, encoding="utf-8")
    always = set.intersection(*(set(map(int, r["manual44_flagged_outside_cwes"].split(";"))) for r in rows if r["manual44_flagged_outside_cwes"]))
    print(f"\n{out.relative_to(ROOT)}: {len(rows)}개 버전. 모든 버전에서 뷰 밖: {sorted(always)}")


if __name__ == "__main__":
    main()
