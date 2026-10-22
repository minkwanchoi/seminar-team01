"""B1. MITRE CWE 목록 수집 및 정제 (CWE 버전별).

MITRE의 CWE 버전 파일(cwec_vX.Y.xml.zip)을 내려받아, 이 연구가 쓰는 뷰와 범주를
data/cwe/vX.Y/ 아래 CSV로 정리하고 data/cwe/versions.csv에 버전 정보를 적는다.
버전 파일은 내려받아 계산에만 쓰고 저장소에는 넣지 않는다.

실행:
  python analysis/fetch_cwe.py                 # 최신 버전
  python analysis/fetch_cwe.py 4.10            # 버전 번호로
  python analysis/fetch_cwe.py https://cwe.mitre.org/data/xml/cwec_v4.21.xml.zip   # 링크로
  python analysis/fetch_cwe.py --top25 https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
"""

import argparse
import html
import re
import sys
import time
from datetime import date
from pathlib import Path

import pandas as pd
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cwe_xml import Catalog  # noqa: E402

BASE = "https://cwe.mitre.org"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
CWE_DIR = DATA_DIR / "cwe"
VERSIONS_CSV = CWE_DIR / "versions.csv"

# 뷰 번호 → 출력 파일 이름(버전 폴더 안)
VIEWS = {
    658: "cwe_658.csv",  # Weaknesses in Software Written in C
    659: "cwe_659.csv",  # Weaknesses in Software Written in C++
    660: "cwe_660.csv",  # Weaknesses in Software Written in Java
    # 해외 참고 사례
    1154: "cwe_cert_c.csv",    # Weaknesses Addressed by the SEI CERT C Coding Standard
    868: "cwe_cert_cpp.csv",   # Weaknesses Addressed by the SEI CERT C++ Coding Standard (2016 Version)
    1305: "cwe_cisq.csv",      # CISQ Quality Measures (2020)
    1344: "cwe_owasp2021.csv", # Weaknesses in OWASP Top Ten (2021). 비교 집합이 아니라 보고서 참고용
}
REQUIRED_VIEWS = {658, 659, 660, 1154, 868, 1305}

# 상위 범주(Pillar)를 찾을 때 쓰는 연구 관점 뷰
RESEARCH_VIEW = 1000

# 성격별 묶음에 쓰는 뷰. 모든 약점을 22개 범주 중 정확히 하나에 넣는다(CWE 4.12부터 있음)
CATEGORY_VIEW = 1400
CATEGORY_KO = {
    1396: "접근 제어", 1397: "비교", 1398: "구성요소 상호작용", 1399: "메모리 안전",
    1401: "동시성", 1402: "암호화", 1403: "노출된 자원", 1404: "파일 처리",
    1405: "예외 상황 처리", 1406: "입력값 검증", 1407: "특수 요소 중화", 1408: "잘못된 계산",
    1409: "주입(Injection)", 1410: "제어 흐름 관리", 1411: "데이터 진위 검증",
    1412: "부적절한 코딩 관행", 1413: "보호 메커니즘 실패", 1414: "난수",
    1415: "자원 제어", 1416: "자원 생애주기 관리", 1417: "민감정보 노출",
    1418: "보안 설계 원칙 위반",
}

# Top 25는 연도별 목록이라 CWE 버전과 따로 관리한다(data/cwe_top25_YYYY.csv)
TOP25_PAGE = f"{BASE}/top25/archive/2025/2025_cwe_top25.html"


def get(url: str, tries: int = 3) -> requests.Response:
    # MITRE 서버가 큰 파일을 받는 도중 연결을 끊는 일이 있어 몇 번 다시 시도한다
    for attempt in range(1, tries + 1):
        try:
            resp = requests.get(url, timeout=180, headers={"User-Agent": "seminar-team01 research"})
            resp.raise_for_status()
            return resp
        except requests.RequestException:
            if attempt == tries:
                raise
            time.sleep(5 * attempt)


def latest_version() -> str:
    m = re.search(r"CWE List Version ([0-9.]+)", get(f"{BASE}/data/index.html").text)
    if not m:
        raise SystemExit("MITRE 사이트에서 최신 CWE 버전을 찾지 못했습니다. 버전 번호나 링크를 직접 주세요")
    return m.group(1)


def resolve_source(arg: str | None) -> tuple[str, str]:
    """버전 번호·링크·생략을 받아 (버전, 내려받을 링크)를 돌려준다."""
    if arg and arg.startswith("http"):
        m = re.search(r"cwec_v([0-9.]+)\.xml\.zip", arg)
        if not m:
            raise SystemExit("링크는 MITRE 버전 파일(…/cwec_vX.Y.xml.zip) 주소여야 합니다")
        return m.group(1), arg
    version = arg or latest_version()
    return version, f"{BASE}/data/xml/cwec_v{version}.xml.zip"


def version_dir(version: str) -> Path:
    return CWE_DIR / f"v{version}"


def known_versions() -> pd.DataFrame:
    if VERSIONS_CSV.exists():
        return pd.read_csv(VERSIONS_CSV, dtype=str)
    return pd.DataFrame(columns=["version", "release_date", "source", "retrieved", "category_source", "note"])


def sort_versions(versions) -> list[str]:
    return sorted(versions, key=lambda v: tuple(int(x) for x in v.split(".")))


def build_version(version: str, url: str) -> dict:
    print(f"CWE {version} 내려받는 중: {url}")
    cat = Catalog.from_zip(get(url).content)
    if cat.version != version:
        raise SystemExit(f"파일 안의 버전({cat.version})이 요청한 버전({version})과 다릅니다")
    out = version_dir(version)
    out.mkdir(parents=True, exist_ok=True)

    cat.weakness_table().to_csv(out / "cwe_all.csv", index=False, encoding="utf-8")
    for view_id, filename in VIEWS.items():
        if view_id not in cat.views:
            if view_id in REQUIRED_VIEWS:
                raise SystemExit(f"CWE {version}에 필요한 뷰 CWE-{view_id}가 없습니다")
            print(f"  CWE-{view_id}: 이 버전에 없음, 건너뜀")
            continue
        df = cat.view_table(view_id)
        df.to_csv(out / filename, index=False, encoding="utf-8")
        print(f"  {filename}: {len(df)}개")

    pillars = cat.pillar_table(RESEARCH_VIEW)
    pillars.to_csv(out / "cwe_pillar.csv", index=False, encoding="utf-8")
    print(f"  cwe_pillar.csv: {len(pillars)}개, Pillar {pillars['pillar_id'].nunique()}개")

    note = ""
    if CATEGORY_VIEW in cat.views:
        categories = cat.category_table(CATEGORY_VIEW, CATEGORY_KO)
        category_source = version
    else:
        # 성격별 범주 뷰가 없는 옛 버전은, 이 뷰가 있는 가장 가까운 버전의 분류를 빌려 쓴다
        donors = [v for v in sort_versions(known_versions()["version"])
                  if v != version and known_versions().set_index("version").loc[v, "category_source"] == v]
        if not donors:
            raise SystemExit(f"CWE {version}에는 CWE-{CATEGORY_VIEW}가 없습니다. 4.12 이후 버전을 먼저 수집하세요")
        category_source = donors[0]
        categories = pd.read_csv(version_dir(category_source) / "cwe_category.csv")
        note = f"CWE-{CATEGORY_VIEW}가 없어 CWE {category_source}의 성격별 범주를 적용"
        print(f"  {note}")
    categories.to_csv(out / "cwe_category.csv", index=False, encoding="utf-8")
    print(f"  cwe_category.csv: {len(categories)}개")

    return {"version": version, "release_date": cat.date, "source": url,
            "retrieved": date.today().isoformat(), "category_source": category_source, "note": note}


def save_version_row(row: dict) -> None:
    df = known_versions()
    df = pd.concat([df[df["version"] != row["version"]], pd.DataFrame([row])], ignore_index=True)
    df = df.set_index("version").loc[sort_versions(df["version"])].reset_index()
    df.to_csv(VERSIONS_CSV, index=False, encoding="utf-8")


def fetch_top25(page_url: str) -> None:
    """Top 25 페이지 표에서 순위·점수·KEV 건수·전년 대비 순위 변동을 읽어 data/cwe_top25_YYYY.csv로 쓴다."""
    year = re.search(r"/(\d{4})/", page_url).group(1)
    page = get(page_url).text
    table = page[page.index('<table id="Detail"'):]
    table = table[: table.index("</table>")]
    cell = r'\s*<td[^>]*>(.*?)</td>'
    row = re.compile(r"<tr>" + cell * 6 + r"\s*</tr>", re.S)
    rows = []
    for rank, cwe, name, score, kev, change in row.findall(table):
        change = html.unescape(change).strip()
        rows.append({
            "rank": int(re.sub(r"<[^>]+>", "", rank)),
            "cwe_id": int(re.search(r"CWE-(\d+)", cwe).group(1)),
            "name": html.unescape(re.sub(r"<[^>]+>", "", name)).strip(),
            "score": float(score),
            "kev_cves": int(kev),
            # 전년 목록에 없던 항목은 MITRE 표에 N/A로 적혀 있다
            "rank_change": "new" if change == "N/A" else change,
        })
    df = pd.DataFrame(rows).sort_values("rank")
    if len(df) != 25:
        raise SystemExit(f"Top 25 표에서 {len(df)}개를 읽었습니다. 페이지 형식을 확인하세요")
    df.insert(2, "cwe", "CWE-" + df["cwe_id"].astype(str))
    df.to_csv(DATA_DIR / f"cwe_top25_{year}.csv", index=False, encoding="utf-8")
    print(f"cwe_top25_{year}.csv: {len(df)}개 ({page_url})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", nargs="?", help="CWE 버전 번호(예: 4.10) 또는 버전 파일 링크. 생략하면 최신 버전")
    parser.add_argument("--top25", metavar="URL", help="CWE Top 25 연도별 페이지 링크. 주면 Top 25도 다시 받는다")
    args = parser.parse_args()

    CWE_DIR.mkdir(parents=True, exist_ok=True)
    version, url = resolve_source(args.source)
    save_version_row(build_version(version, url))
    if args.top25:
        fetch_top25(args.top25)
    print(f"CWE {version} → {version_dir(version).relative_to(DATA_DIR.parent)}")


if __name__ == "__main__":
    main()
