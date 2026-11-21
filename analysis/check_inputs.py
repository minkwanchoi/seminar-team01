"""분석 전 입력 점검. 매핑 CSV의 모양과 개수를 기준값과 맞춰 보고, 다르면 멈춘다.

overlap.py를 돌리기 전에 실행한다. 점검하는 것:
  1. 모양: 필요한 열, 빈 cwe_ids, 숫자가 아닌 번호, 한 행 안의 중복 번호, 순번(no) 중복, 허용하지 않은 status·decision 값
  2. 개수: 행 수, 고유 CWE 수, 중복여부 O 표시 수 → data/expected_counts.csv의 '입력' 기준값
  3. 버전: data/cwe/vX.Y/cwe_all.csv에 없거나 폐기된 번호 → 같은 파일의 버전별 기준값

기준값은 원문과 대조해 정한 값이다. 원문 대조로 매핑을 고쳤으면 expected_counts.csv도
같은 커밋에서 고치고 basis 열에 이유를 적는다(기준값을 결과에 맞춰 슬쩍 바꾸지 않는다).

실행: python analysis/check_inputs.py
결과: 모든 점검의 기대값·실제값·판정을 화면에 출력. 하나라도 어긋나면 종료 코드 1.
pandas를 쓰지 않고 표준 라이브러리 csv로 읽는다(overlap.py와 다른 경로로 읽어 검산이 되게).
"""

import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
CWE_DIR = DATA / "cwe"

MAPPINGS = {
    "manual44": {"file": "mapping_manual44.csv",
                 "columns": ["cwe_ids", "name", "overlap_flag", "mapping_note", "source", "status"]},
    "mois49": {"file": "mapping_mois49.csv",
               "columns": ["no", "category", "item", "cwe_ids", "source_page", "mapping_note", "status"]},
}
STATUS = {"확인", "2차 자료(원문 대조 필요)"}
DECISION = {"채택", "판단 후 채택", "수정 후 채택", "보류", "미확인"}
ID_CELL = re.compile(r"^\d+(;\d+)*$")


def read_csv(path: Path) -> list[dict]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def ids_of(rows: list[dict]) -> list[int]:
    return [int(x) for r in rows for x in (r.get("cwe_ids") or "").split(";") if x.strip().isdigit()]


def join(ids) -> str:
    return ";".join(str(i) for i in sorted(ids))


def main() -> int:
    problems: list[str] = []   # 모양 점검에서 나온 문제(기준값 없이 항상 실패)
    actual: dict[tuple[str, str], str] = {}  # (check, cwe_version) → 실제값

    for key, spec in MAPPINGS.items():
        path = DATA / spec["file"]
        rows = read_csv(path)
        header = list(rows[0].keys()) if rows else []
        missing_cols = [c for c in spec["columns"] if c not in header]
        if missing_cols:
            problems.append(f"{spec['file']}: 열 없음 {missing_cols}")
        for n, r in enumerate(rows, start=2):  # 2 = 머리줄 다음 줄 번호
            cell = (r.get("cwe_ids") or "").strip()
            where = f"{spec['file']} {n}행"
            if not cell:
                problems.append(f"{where}: cwe_ids가 비어 있음")
            elif not ID_CELL.match(cell):
                problems.append(f"{where}: cwe_ids '{cell}'에 숫자·세미콜론 외의 글자가 있음")
            else:
                parts = cell.split(";")
                if len(parts) != len(set(parts)):
                    problems.append(f"{where}: 한 행 안에 같은 CWE가 두 번 있음 ({cell})")
            if r.get("status") not in STATUS:
                problems.append(f"{where}: status '{r.get('status')}'는 허용 값 {sorted(STATUS)}이 아님")
            if "decision" in r and r["decision"] not in DECISION:
                problems.append(f"{where}: decision '{r['decision']}'는 허용 값 {sorted(DECISION)}이 아님")
        if "no" in header:
            nos = [r["no"] for r in rows]
            dup = sorted({x for x in nos if nos.count(x) > 1}, key=int)
            if dup:
                problems.append(f"{spec['file']}: 순번(no) 중복 {dup}")
            if nos != [str(i) for i in range(1, len(nos) + 1)]:
                problems.append(f"{spec['file']}: 순번(no)이 1부터 차례대로가 아님")

        ids = ids_of(rows)
        actual[(f"{key}.rows", "")] = str(len(rows))
        actual[(f"{key}.unique_cwe", "")] = str(len(set(ids)))
        if "overlap_flag" in header:
            actual[(f"{key}.overlap_flag_O", "")] = str(sum(r["overlap_flag"] == "O" for r in rows))

        for vdir in sorted(p for p in CWE_DIR.glob("v*") if p.is_dir()):
            version = vdir.name.removeprefix("v")
            catalog = {int(r["cwe_id"]): r["status"] for r in read_csv(vdir / "cwe_all.csv")}
            uniq = set(ids)
            actual[(f"{key}.not_in_catalog", version)] = join(uniq - catalog.keys())
            actual[(f"{key}.deprecated", version)] = join(i for i in uniq if catalog.get(i) == "Deprecated")

    expected = [r for r in read_csv(DATA / "expected_counts.csv") if r["stage"] == "입력"]
    failed = 0
    print("점검 / CWE 버전 / 기대 / 실제 / 판정")
    for r in expected:
        k = (r["check"], r["cwe_version"])
        got = actual.pop(k, "(계산 안 됨)")
        ok = got == r["expected"]
        failed += not ok
        print(f"{r['check']:28} {r['cwe_version'] or '-':5} {r['expected'] or '(없음)':>8} {got or '(없음)':>8}  {'통과' if ok else '불일치'}")
    for (check, version), got in sorted(actual.items()):  # 기준값이 없는 점검(새 버전 폴더 등)
        failed += 1
        print(f"{check:28} {version or '-':5} {'(기준 없음)':>8} {got or '(없음)':>8}  기준값 필요")

    if problems:
        print("\n모양 점검에서 나온 문제:")
        for p in problems:
            print(" -", p)
    if failed or problems:
        print(f"\n멈춤: 기준과 다른 값 {failed}개, 모양 문제 {len(problems)}개. "
              "원문과 다시 대조하고, 매핑이 맞다면 data/expected_counts.csv의 기준값과 근거를 함께 고친다.")
        return 1
    print(f"\n통과: 입력 점검 {len(expected)}개, 모양 문제 없음")
    return 0


if __name__ == "__main__":
    sys.exit(main())
