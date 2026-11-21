"""B5. Juliet C/C++ 1.3에서 B2 매핑(매뉴얼 보안약점 44, 행안부 49)에 등장하는 CWE의 케이스를 고른다.

입력
- static-analysis/_juliet/C/manifest.xml : NIST SARD Juliet C/C++ 1.3 (git 제외, README.md의 받는 법 참고)
- data/mapping_manual44.csv, data/mapping_mois49.csv : B2 매핑
- CWE 버전 파일(cwec_vX.Y.xml.zip) : 하위 CWE 관계(연구 관점 뷰 CWE-1000의 ChildOf)를 읽는 데 쓴다.
  프로젝트 루트에 있으면 그것을, 없으면 data/cwe/versions.csv의 MITRE 주소에서 받는다.

고르는 기준
- 맞춤 방식(match)
  - 정확: 케이스의 CWE 번호가 B2 매핑에 그대로 있다
  - 하위: 케이스의 CWE가 B2 매핑 번호의 하위 약점이다(CWE-1000 ChildOf를 따라 올라가 만남).
    예: Juliet CWE-121(스택 버퍼 오버플로)은 B2의 CWE-119 아래에 있다.
    B6에서는 '정확'과 '하위'를 나누어 집계한다.
- 흐름 변형(flow variant)은 기본형 01만 고른다(selected=1).
  01은 제어·데이터 흐름이 가장 단순한 형태라서 "도구가 그 약점을 아는가"를 본다.
  02~84 변형은 summary의 all_cases로 규모만 남긴다.
- Windows 전용 케이스(파일 이름에 w32)도 목록에 남기고 platform=windows로 표시한다.
  clang-tidy는 리눅스에서 windows.h가 없어 이 케이스를 끝까지 분석하지 못할 수 있다.

출력
- static-analysis/juliet_cases.csv   : 고른 케이스(흐름 변형 01) 한 줄에 하나
- static-analysis/juliet_summary.csv : CWE별 케이스 규모(전체·Windows 전용·01)

실행: python static-analysis/select_cases.py [--cwe-version 4.20]
"""

import argparse
import csv
import io
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
JULIET = HERE / "_juliet" / "C"
DATA = ROOT / "data"

sys.path.insert(0, str(ROOT / "analysis"))
from cwe_xml import Catalog, _local  # noqa: E402


def mapping_ids(path: Path) -> set[int]:
    ids = set()
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            ids.update(int(x) for x in (row["cwe_ids"] or "").split(";") if x.strip())
    return ids


def latest_cwe_version() -> str:
    with open(DATA / "cwe" / "versions.csv", encoding="utf-8", newline="") as f:
        vs = [r["version"] for r in csv.DictReader(f)]
    return max(vs, key=lambda v: tuple(int(x) for x in v.split(".")))


def load_catalog(version: str) -> Catalog:
    local = ROOT / f"cwec_v{version}.xml.zip"
    if local.exists():
        return Catalog.from_zip(local.read_bytes())
    url = f"https://cwe.mitre.org/data/xml/cwec_v{version}.xml.zip"
    print(f"CWE {version} 파일을 받습니다: {url}")
    with urllib.request.urlopen(url) as r:
        return Catalog.from_zip(r.read())


def ancestors_in(cat: Catalog, targets: set[int]) -> dict[int, set[int]]:
    """약점마다, CWE-1000 ChildOf를 따라 올라가며 만나는 targets 번호."""
    parents = defaultdict(set)
    for i, w in cat.weaknesses.items():
        for rel in w.iter():
            if (_local(rel.tag) == "Related_Weakness" and rel.get("Nature") == "ChildOf"
                    and rel.get("View_ID") == "1000"):
                parents[i].add(int(rel.get("CWE_ID")))
    out = {}
    for start in cat.weaknesses:
        seen, stack = set(), list(parents[start])
        while stack:
            p = stack.pop()
            if p not in seen:
                seen.add(p)
                stack.extend(parents[p])
        out[start] = seen & targets
    return out


def file_index() -> dict[str, str]:
    """파일 이름 → testcases/ 아래 상대 경로(큰 CWE는 s01, s02 … 하위 폴더로 나뉜다)."""
    return {p.name: p.relative_to(JULIET).as_posix() for p in (JULIET / "testcases").rglob("*")
            if p.suffix in (".c", ".cpp", ".h")}


CASE_RE = re.compile(r"^(CWE(\d+)_[^_].*?__.+?_(\d{2}))(?:[a-z]|_bad|_good\w*)?\.(c|cpp|h)$")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cwe-version", default=None, help="하위 관계를 읽을 CWE 버전(기본: 최신)")
    args = ap.parse_args()
    version = args.cwe_version or latest_cwe_version()

    manifest = JULIET / "manifest.xml"
    if not manifest.exists():
        raise SystemExit(f"{manifest}가 없습니다. static-analysis/README.md의 'Juliet 받기'를 먼저 하세요.")

    m44 = mapping_ids(DATA / "mapping_manual44.csv")
    m49 = mapping_ids(DATA / "mapping_mois49.csv")
    b2 = m44 | m49
    cat = load_catalog(version)
    anc = ancestors_in(cat, b2)
    paths = file_index()

    cases, summary = [], defaultdict(lambda: {"all_cases": 0, "windows_cases": 0, "v01_cases": 0})
    for tc in ET.parse(manifest).getroot().iter("testcase"):
        files = [f.get("path") for f in tc.iter("file")]
        m = CASE_RE.match(files[0])
        if not m:
            raise SystemExit(f"케이스 이름을 해석하지 못했습니다: {files[0]}")
        case_id, cwe, flow = m.group(1), int(m.group(2)), m.group(3)
        if cwe in b2:
            match, hit = "정확", {cwe}
        elif anc.get(cwe):
            match, hit = "하위", anc[cwe]
        else:
            continue
        windows = any("w32" in f for f in files)
        s = summary[(cwe, match, ";".join(map(str, sorted(hit))))]
        s["all_cases"] += 1
        s["windows_cases"] += windows
        if flow != "01":
            continue
        s["v01_cases"] += 1
        flaws = [f"{f.get('path')}:{fl.get('line')}" for f in tc.iter("file") for fl in f.iter("flaw")]
        flaw_cwes = sorted({int(re.match(r"CWE-(\d+)", fl.get("name")).group(1)) for fl in tc.iter("flaw")})
        cases.append({
            "case_id": case_id,
            "cwe_id": cwe,
            "match": match,
            "b2_cwe": ";".join(map(str, sorted(hit))),
            "in_manual44": int(bool(hit & m44)),
            "in_mois49": int(bool(hit & m49)),
            "language": "cpp" if any(f.endswith(".cpp") for f in files) else "c",
            "platform": "windows" if windows else "any",
            "flow_variant": flow,
            "files": ";".join(paths[f] for f in files),
            "flaw_cwes": ";".join(map(str, flaw_cwes)),
            "flaw_lines": ";".join(flaws),
            "selected": 1,
        })

    cases.sort(key=lambda r: (r["cwe_id"], r["case_id"]))
    with open(HERE / "juliet_cases.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(cases[0]))
        w.writeheader()
        w.writerows(cases)

    names = {i: el.get("Name") for i, el in cat.weaknesses.items()}
    with open(HERE / "juliet_summary.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cwe_id", "name", "match", "b2_cwe", "in_manual44", "in_mois49",
                    "all_cases", "windows_cases", "v01_cases", "cwe_version"])
        for (cwe, match, hit), s in sorted(summary.items()):
            hs = {int(x) for x in hit.split(";")}
            w.writerow([cwe, names.get(cwe, ""), match, hit, int(bool(hs & m44)), int(bool(hs & m49)),
                        s["all_cases"], s["windows_cases"], s["v01_cases"], version])

    exact = [r for r in cases if r["match"] == "정확"]
    print(f"B2 매핑 CWE {len(b2)}개 중 Juliet에 정확히 있는 것 "
          f"{len({r['cwe_id'] for r in exact})}개, 하위로 이어지는 Juliet CWE "
          f"{len({r['cwe_id'] for r in cases}) - len({r['cwe_id'] for r in exact})}개 (CWE {version} 기준)")
    print(f"고른 케이스(흐름 변형 01): 정확 {len(exact)}개, 하위 {len(cases) - len(exact)}개, "
          f"그중 Windows 전용 {sum(r['platform'] == 'windows' for r in cases)}개")


if __name__ == "__main__":
    main()
