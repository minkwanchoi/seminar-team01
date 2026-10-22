"""B1. MITRE CWE 목록 수집 및 정제.

MITRE에서 CWE 뷰(CWE-658/659/660)와 최신 CWE Top 25를 내려받아
data/cwe_*.csv로 정리한다.

실행: python analysis/fetch_cwe.py
"""

import html
import io
import re
import time
import zipfile
from datetime import date
from pathlib import Path

import pandas as pd
import requests

BASE = "https://cwe.mitre.org"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# 뷰 번호 → 출력 파일 이름
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

# 최신 Top 25: 연도와 MITRE 뷰 번호
TOP25_YEAR = 2025
TOP25_VIEW = 1435
# 상위 범주(Pillar)를 찾을 때 쓰는 연구 관점 뷰
RESEARCH_VIEW = 1000

# 성격별 묶음에 쓰는 뷰. 모든 약점을 22개 범주 중 정확히 하나에 넣는다
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

TOP25_PAGE =f"{BASE}/top25/archive/{TOP25_YEAR}/{TOP25_YEAR}_cwe_top25.html"

KEEP_COLUMNS = {
    "CWE-ID": "cwe_id",
    "Name": "name",
    "Weakness Abstraction": "abstraction",
    "Status": "status",
}


def get(url: str, tries: int = 3) -> requests.Response:
    # MITRE 서버가 큰 파일을 받는 도중 연결을 끊는 일이 있어 몇 번 다시 시도한다
    for attempt in range(1, tries + 1):
        try:
            resp = requests.get(url, timeout=120, headers={"User-Agent": "seminar-team01 research"})
            resp.raise_for_status()
            return resp
        except requests.RequestException:
            if attempt == tries:
                raise
            time.sleep(5 * attempt)


def fetch_cwe_version() -> str:
    m = re.search(r"CWE List Version ([0-9.]+)", get(f"{BASE}/data/index.html").text)
    return m.group(1) if m else "unknown"


def read_view_csv(view_id: int) -> pd.DataFrame:
    """뷰 CSV(zip)를 내려받아 모든 열을 그대로 읽는다."""
    raw = get(f"{BASE}/data/csv/{view_id}.csv.zip").content
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        name = next(n for n in zf.namelist() if n.endswith(".csv"))
        # MITRE CSV는 행 끝에 여분의 쉼표가 있어 index_col=False로 읽는다
        return pd.read_csv(zf.open(name), index_col=False, dtype=str)


def fetch_view(view_id: int) -> pd.DataFrame:
    """뷰 CSV(zip)를 내려받아 핵심 열만 남긴다."""
    df = read_view_csv(view_id)
    df = df[list(KEEP_COLUMNS)].rename(columns=KEEP_COLUMNS)
    df["cwe_id"] = df["cwe_id"].astype(int)
    df.insert(1, "cwe", "CWE-" + df["cwe_id"].astype(str))
    return df.sort_values("cwe_id").reset_index(drop=True)


def fetch_top25_ranks() -> pd.DataFrame:
    """Top 25 페이지 표에서 순위·점수·KEV 건수·전년 대비 순위 변동을 읽는다."""
    page = get(TOP25_PAGE).text
    table = page[page.index('<table id="Detail"'):]
    table = table[: table.index("</table>")]
    cell = r'\s*<td[^>]*>(.*?)</td>'
    row = re.compile(r"<tr>" + cell * 6 + r"\s*</tr>", re.S)
    rows = []
    for rank, cwe, _name, score, kev, change in row.findall(table):
        change = html.unescape(change).strip()
        rows.append({
            "rank": int(re.sub(r"<[^>]+>", "", rank)),
            "cwe_id": int(re.search(r"CWE-(\d+)", cwe).group(1)),
            "score": float(score),
            "kev_cves": int(kev),
            # 전년 목록에 없던 항목은 MITRE 표에 N/A로 적혀 있다
            "rank_change": "new" if change == "N/A" else change,
        })
    return pd.DataFrame(rows)


def fetch_pillars() -> pd.DataFrame:
    """연구 관점 뷰(CWE-1000)의 기본(Primary) 부모를 따라 올라가 CWE마다 최상위 Pillar를 찾는다."""
    df = read_view_csv(RESEARCH_VIEW)
    parent, info = {}, {}
    for _, row in df.iterrows():
        cid = int(row["CWE-ID"])
        info[cid] = (row["Name"], row["Weakness Abstraction"])
        m = re.search(r"NATURE:ChildOf:CWE ID:(\d+):VIEW ID:1000:ORDINAL:Primary",
                      str(row["Related Weaknesses"]))
        if m:
            parent[cid] = int(m.group(1))

    rows = []
    for cid in sorted(info):
        top, seen = cid, set()
        while top in parent and top not in seen:
            seen.add(top)
            top = parent[top]
        rows.append({
            "cwe_id": cid,
            "name": info[cid][0],
            "abstraction": info[cid][1],
            "pillar_id": top,
            "pillar": f"CWE-{top}",
            "pillar_name": info.get(top, ("", ""))[0],
        })
    return pd.DataFrame(rows)


def fetch_categories() -> pd.DataFrame:
    """CWE-1400 뷰 XML에서 범주마다 소속 CWE를 읽어 CWE → 성격별 범주 표를 만든다."""
    raw = get(f"{BASE}/data/xml/views/{CATEGORY_VIEW}.xml.zip").content
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        xml = zf.read(next(n for n in zf.namelist() if n.endswith(".xml"))).decode("utf-8")
    rows = []
    for cid, name, body in re.findall(r'<Category ID="(\d+)" Name="([^"]+)"[^>]*>(.*?)</Category>', xml, re.S):
        cid = int(cid)
        if cid not in CATEGORY_KO:
            continue
        for member in re.findall(rf'<Has_Member CWE_ID="(\d+)" View_ID="{CATEGORY_VIEW}"', body):
            rows.append({
                "cwe_id": int(member),
                "category_id": cid,
                "category": name.replace("Comprehensive Categorization: ", ""),
                "category_ko": CATEGORY_KO[cid],
            })
    df = pd.DataFrame(rows).drop_duplicates("cwe_id")
    return df.sort_values("cwe_id").reset_index(drop=True)


def main() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    version = fetch_cwe_version()
    today = date.today().isoformat()
    sources = []

    for view_id, filename in VIEWS.items():
        df = fetch_view(view_id)
        df.to_csv(DATA_DIR / filename, index=False, encoding="utf-8")
        sources.append((filename, f"CWE-{view_id}", len(df), f"{BASE}/data/csv/{view_id}.csv.zip"))
        print(f"{filename}: {len(df)}개")

    members = fetch_view(TOP25_VIEW)
    ranks = fetch_top25_ranks()
    if set(members["cwe_id"]) != set(ranks["cwe_id"]) or len(ranks) != 25:
        raise SystemExit("Top 25 뷰 CSV와 순위 표의 CWE 목록이 다릅니다")
    top25 = ranks.merge(members, on="cwe_id")
    top25 = top25[["rank", "cwe_id", "cwe", "name", "abstraction", "status",
                   "score", "kev_cves", "rank_change"]].sort_values("rank")
    filename = f"cwe_top25_{TOP25_YEAR}.csv"
    top25.to_csv(DATA_DIR / filename, index=False, encoding="utf-8")
    sources.append((filename, f"{TOP25_YEAR} CWE Top 25 (CWE-{TOP25_VIEW})", len(top25), TOP25_PAGE))
    print(f"{filename}: {len(top25)}개")

    pillars = fetch_pillars()
    pillars.to_csv(DATA_DIR / "cwe_pillar.csv", index=False, encoding="utf-8")
    sources.append(("cwe_pillar.csv", f"CWE-{RESEARCH_VIEW} 기본 부모 체인의 최상위 Pillar",
                    len(pillars), f"{BASE}/data/csv/{RESEARCH_VIEW}.csv.zip"))
    print(f"cwe_pillar.csv: {len(pillars)}개, Pillar {pillars['pillar_id'].nunique()}개")

    categories = fetch_categories()
    categories.to_csv(DATA_DIR / "cwe_category.csv", index=False, encoding="utf-8")
    sources.append(("cwe_category.csv", f"CWE-{CATEGORY_VIEW} 성격별 범주(Comprehensive Categorization)",
                    len(categories), f"{BASE}/data/xml/views/{CATEGORY_VIEW}.xml.zip"))
    print(f"cwe_category.csv: {len(categories)}개, 범주 {categories['category_id'].nunique()}개")

    meta = pd.DataFrame(sources, columns=["file", "source", "count", "url"])
    meta["cwe_version"] = version
    meta["retrieved"] = today
    meta.to_csv(DATA_DIR / "cwe_sources.csv", index=False, encoding="utf-8")
    print(f"CWE List Version {version}, 수집일 {today}")


if __name__ == "__main__":
    main()
