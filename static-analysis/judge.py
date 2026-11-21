"""B6. 정적 분석 도구 출력으로 탐지·오탐을 판정하고 제도별 충족도를 집계한다.

입력
- static-analysis/_runs/<실행이름>/ : run_tools.py 결과(git 제외)
- static-analysis/juliet_cases.csv : B5에서 고른 케이스
- static-analysis/clang_tidy_cwe.csv : clang-tidy 검사 이름 → CWE (연구팀이 정한 대응표)
- data/mapping_manual44.csv, data/mapping_mois49.csv : 제도별 요구 CWE
- CWE 버전 파일(cwec_vX.Y.xml.zip) : CWE 사이 상하 관계

판정 규칙(README.md "탐지 판정" 참고)
- 구역: Juliet 파일은 #ifndef OMITBAD … #endif 안이 결함 구역, #ifndef OMITGOOD … #endif 안이 정상 구역이다.
  main(INCLUDEMAIN)과 그 밖의 줄은 '기타'로 둔다.
- 지적의 CWE가 케이스와 '관련'인가: 케이스 CWE, 매니페스트의 결함 CWE, 케이스를 맞춘 B2 번호 가운데
  하나와 같거나, CWE-1000 ChildOf로 이어지는 상위·하위(Pillar 제외)이면 관련으로 본다.
  예: CWE-121 케이스(B2 번호 119)에서 flawfinder의 CWE-120 지적은 119의 하위라서 관련이다.
- 탐지(TP): 결함 구역 안에 관련 CWE 지적이 하나라도 있음. 그중 매니페스트 결함 줄과 같은 줄이면 '정확한 줄'.
- 오탐(FP): 정상 구역 안의 관련 CWE 지적. Juliet의 정상 구역은 그 약점을 고친 코드라서 같은 약점 지적은 오탐이다.
- 분석 불가: clang-tidy가 컴파일 오류(헤더 없음 등)를 낸 파일은 그 도구의 분모에서 뺀다.

출력(static-analysis/results/)
- detection_by_case.csv : 케이스 × 도구 판정
- detection_by_cwe.csv : CWE × 도구 탐지율(세 도구 합집합 포함)
- b2_cwe_detection.csv : B2 CWE마다 도구별 탐지 여부
- regime_coverage.csv : '1회 분석 → 제도별 충족 항목 수'
- fp_candidates.csv : 관련 CWE 오탐 전체(표본 추출용, 커밋하지 않음 → _runs/에 씀)

실행: python static-analysis/judge.py --run all-20261121 [--cwe-version 4.20]
"""

import argparse
import csv
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
JULIET = HERE / "_juliet" / "C"
DATA = ROOT / "data"
OUT = HERE / "results"
TOOLS = ["cppcheck", "clang-tidy", "flawfinder"]
UNION = "세 도구 합집합"

sys.path.insert(0, str(HERE))
from select_cases import latest_cwe_version, load_catalog, mapping_ids  # noqa: E402
from cwe_xml import _local  # noqa: E402

# cppcheck가 도구 동작 정보로 내는 항목(코드 지적이 아님)
CPPCHECK_SKIP = {"missingInclude", "missingIncludeSystem", "checkersReport", "toomanyconfigs",
                 "normalCheckLevelMaxBranches", "unmatchedSuppression", "syntaxError", "internalAstError",
                 "preprocessorErrorDirective", "unknownMacro"}


# ── CWE 관계 ──
class Relations:
    def __init__(self, version: str):
        cat = load_catalog(version)
        self.pillars = {i for i, w in cat.weaknesses.items() if w.get("Abstraction") == "Pillar"}
        parents = defaultdict(set)
        for i, w in cat.weaknesses.items():
            for rel in w.iter():
                if (_local(rel.tag) == "Related_Weakness" and rel.get("Nature") == "ChildOf"
                        and rel.get("View_ID") == "1000"):
                    parents[i].add(int(rel.get("CWE_ID")))
        self.parents = parents
        self._anc = {}

    def ancestors(self, c: int) -> set[int]:
        if c not in self._anc:
            seen, stack = set(), list(self.parents.get(c, ()))
            while stack:
                p = stack.pop()
                if p not in seen:
                    seen.add(p)
                    stack.extend(self.parents.get(p, ()))
            self._anc[c] = seen - self.pillars
        return self._anc[c]

    def related(self, finding: int, targets: set[int]) -> bool:
        if finding in self.pillars:
            return False
        return any(finding == t or finding in self.ancestors(t) or t in self.ancestors(finding) for t in targets)


# ── 파일 구역 ──
def regions(path: Path) -> dict[int, str]:
    """줄 번호 → 'bad' | 'good' | 'other'. 바깥쪽 OMITBAD/OMITGOOD 블록만 본다."""
    out, stack, inmain = {}, [], False
    for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        s = line.strip()
        if s.startswith("#ifdef INCLUDEMAIN"):
            inmain = True
        if re.match(r"#\s*if", s):
            tag = "bad" if (s.startswith("#ifndef OMITBAD") and not inmain) else \
                  "good" if (s.startswith("#ifndef OMITGOOD") and not inmain) else None
            stack.append(tag)
            out[n] = "other"
            continue
        if re.match(r"#\s*endif", s):
            if stack:
                stack.pop()
            out[n] = "other"
            continue
        cur = next((t for t in stack if t), None)
        out[n] = cur or "other"
    return out


# ── 도구 출력 읽기 ──
def parse_cppcheck(text: str):
    if not text.strip():
        return
    root = ET.fromstring(text)
    for e in root.iter("error"):
        if e.get("id") in CPPCHECK_SKIP or e.get("severity") == "information":
            continue
        loc = e.find("location")
        if loc is None:
            continue
        cwe = int(e.get("cwe")) if e.get("cwe") else None
        yield {"file": Path(loc.get("file")).name, "line": int(loc.get("line")), "rule": e.get("id"),
               "cwes": {cwe} if cwe else set(), "message": e.get("msg")}


CT_RE = re.compile(r"^(\S+?):(\d+):\d+: (warning|error): (.*) \[([\w\-.,]+)\]$")


def ct_cwes(ct_map: dict, rule: str, message: str) -> set[int]:
    """대응표에서 검사 이름이 같고 메시지 조건(정규식, 비면 모두)에 맞는 첫 줄의 CWE."""
    for pattern, cwes in ct_map.get(rule, []):
        if not pattern or re.search(pattern, message):
            return cwes
    return set()


def parse_clang_tidy(text: str, ct_map: dict):
    for line in text.splitlines():
        m = CT_RE.match(line)
        if not m or m.group(3) != "warning":
            continue
        for rule in m.group(5).split(","):
            yield {"file": Path(m.group(1)).name, "line": int(m.group(2)), "rule": rule,
                   "cwes": ct_cwes(ct_map, rule, m.group(4)), "message": m.group(4)}


def parse_flawfinder(text: str):
    for r in csv.DictReader(text.splitlines()):
        yield {"file": Path(r["File"]).name, "line": int(r["Line"]), "rule": r["Name"],
               "cwes": {int(x) for x in re.findall(r"CWE-(\d+)", r["CWEs"] or "")},
               "message": r["Warning"]}


def load_ct_map() -> dict[str, list[tuple[str, set[int]]]]:
    """검사 이름 → [(메시지 정규식, CWE 집합), …] (파일 순서대로)."""
    m = defaultdict(list)
    with open(HERE / "clang_tidy_cwe.csv", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            m[r["check"]].append((r["message_regex"] or "",
                                  {int(x) for x in (r["cwe_ids"] or "").split(";") if x.strip()}))
    return dict(m)


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--cwe-version", default=None)
    args = ap.parse_args()
    version = args.cwe_version or latest_cwe_version()
    rundir = HERE / "_runs" / args.run
    rel = Relations(version)
    ct_map = load_ct_map()

    with open(HERE / "juliet_cases.csv", encoding="utf-8", newline="") as f:
        cases = {r["case_id"]: r for r in csv.DictReader(f) if r["selected"] == "1"}
    with open(rundir / "status.csv", encoding="utf-8", newline="") as f:
        status = list(csv.DictReader(f))

    # 케이스 × 도구 판정
    judged = {}  # (case, tool) → dict
    fp_rows, unmapped = [], defaultdict(int)
    region_cache = {}
    for s in status:
        case = cases.get(s["case_id"])
        if case is None:
            continue
        tool = s["tool"]
        key = (case["case_id"], tool)
        j = judged.setdefault(key, {"files": 0, "unanalyzable": 0, "tp": 0, "tp_exact_line": 0, "fp": 0,
                                    "findings": 0, "tp_rules": set()})
        j["files"] += 1
        if tool == "clang-tidy" and s["compile_error"] == "1":
            j["unanalyzable"] += 1
            continue
        src = next(JULIET / p for p in case["files"].split(";") if p.endswith("/" + s["file"]))
        if src not in region_cache:
            region_cache[src] = regions(src)
        reg = region_cache[src]
        text = (ROOT / s["output"]).read_text(encoding="utf-8")
        parser = {"cppcheck": parse_cppcheck, "clang-tidy": lambda t: parse_clang_tidy(t, ct_map),
                  "flawfinder": parse_flawfinder}[tool]
        targets = ({int(case["cwe_id"])} | {int(x) for x in case["flaw_cwes"].split(";") if x}
                   | {int(x) for x in case["b2_cwe"].split(";")})
        flaw_lines = {int(x.rsplit(":", 1)[1]) for x in case["flaw_lines"].split(";")
                      if x.rsplit(":", 1)[0] == s["file"]}
        for fd in parser(text):
            if fd["file"] != s["file"]:
                continue  # 헤더(testcasesupport)에서 나온 지적
            j["findings"] += 1
            if tool == "clang-tidy" and fd["rule"] not in ct_map:
                unmapped[fd["rule"]] += 1
            if not any(rel.related(c, targets) for c in fd["cwes"]):
                continue
            where = reg.get(fd["line"], "other")
            if where == "bad":
                j["tp"] += 1
                j["tp_rules"].add(fd["rule"])
                j["tp_exact_line"] += fd["line"] in flaw_lines
            elif where == "good":
                j["fp"] += 1
                fp_rows.append({"case_id": case["case_id"], "cwe_id": case["cwe_id"], "match": case["match"],
                                "tool": tool, "file": s["file"], "line": fd["line"], "rule": fd["rule"],
                                "finding_cwes": ";".join(map(str, sorted(fd["cwes"]))), "message": fd["message"]})

    # 케이스별 표
    case_rows = []
    for (cid, tool), j in sorted(judged.items()):
        c = cases[cid]
        analyzable = j["unanalyzable"] < j["files"]
        case_rows.append({
            "case_id": cid, "cwe_id": c["cwe_id"], "match": c["match"], "b2_cwe": c["b2_cwe"],
            "platform": c["platform"], "language": c["language"], "tool": tool,
            "analyzable": int(analyzable), "detected": int(analyzable and j["tp"] > 0),
            "exact_line": int(analyzable and j["tp_exact_line"] > 0), "false_positives": j["fp"],
            "findings": j["findings"], "detecting_rules": ";".join(sorted(j["tp_rules"])),
        })
    # 세 도구 합집합: 한 도구라도 탐지하면 탐지, 한 도구라도 분석했으면 분석 가능
    by_case = defaultdict(list)
    for r in case_rows:
        by_case[r["case_id"]].append(r)
    for cid, rs in sorted(by_case.items()):
        c = cases[cid]
        case_rows.append({
            "case_id": cid, "cwe_id": c["cwe_id"], "match": c["match"], "b2_cwe": c["b2_cwe"],
            "platform": c["platform"], "language": c["language"], "tool": UNION,
            "analyzable": max(r["analyzable"] for r in rs), "detected": max(r["detected"] for r in rs),
            "exact_line": max(r["exact_line"] for r in rs), "false_positives": sum(r["false_positives"] for r in rs),
            "findings": sum(r["findings"] for r in rs), "detecting_rules": "",
        })
    write_csv(OUT / "detection_by_case.csv", case_rows)

    tools_all = TOOLS + [UNION]
    # CWE별 탐지율
    agg = defaultdict(lambda: {"cases": 0, "analyzable": 0, "detected": 0, "exact_line": 0, "fp": 0})
    for r in case_rows:
        a = agg[(int(r["cwe_id"]), r["match"], r["b2_cwe"], r["tool"])]
        a["cases"] += 1
        a["analyzable"] += r["analyzable"]
        a["detected"] += r["detected"]
        a["exact_line"] += r["exact_line"]
        a["fp"] += r["false_positives"]
    cwe_rows = []
    for (cwe, match, b2, tool), a in sorted(agg.items(), key=lambda kv: (kv[0][0], tools_all.index(kv[0][3]))):
        cwe_rows.append({"cwe_id": cwe, "match": match, "b2_cwe": b2, "tool": tool, "cases": a["cases"],
                         "analyzable": a["analyzable"], "detected": a["detected"],
                         "detection_rate": f"{a['detected'] / a['analyzable']:.3f}" if a["analyzable"] else "",
                         "exact_line": a["exact_line"], "false_positives": a["fp"]})
    write_csv(OUT / "detection_by_cwe.csv", cwe_rows)

    # 제도 항목별: B2 CWE 하나 = 요구 항목 하나. 정확·하위 케이스를 나눠 센다
    m44, m49 = mapping_ids(DATA / "mapping_manual44.csv"), mapping_ids(DATA / "mapping_mois49.csv")
    item = defaultdict(lambda: {"exact_cases": 0, "exact_detected": 0, "child_cases": 0, "child_detected": 0})
    for r in case_rows:
        if not r["analyzable"]:
            continue
        for b in map(int, r["b2_cwe"].split(";")):
            it = item[(b, r["tool"])]
            k = "exact" if r["match"] == "정확" else "child"
            it[f"{k}_cases"] += 1
            it[f"{k}_detected"] += r["detected"]
    item_rows = []
    for b in sorted(m44 | m49):
        for tool in tools_all:
            it = item.get((b, tool), {"exact_cases": 0, "exact_detected": 0, "child_cases": 0, "child_detected": 0})
            ec, ed, cc, cd = it["exact_cases"], it["exact_detected"], it["child_cases"], it["child_detected"]
            item_rows.append({
                "b2_cwe": b, "in_manual44": int(b in m44), "in_mois49": int(b in m49), "tool": tool,
                "exact_cases": ec, "exact_detected": ed, "exact_rate": f"{ed / ec:.3f}" if ec else "",
                "child_cases": cc, "child_detected": cd, "child_rate": f"{cd / cc:.3f}" if cc else "",
                "testable": int(ec + cc > 0),
                "met_any": int(ed + cd > 0),                         # 정확·하위 중 한 건이라도 탐지
                "met_exact_any": int(ed > 0),                        # 같은 번호 케이스를 한 건이라도 탐지
                "met_exact_half": int(ec > 0 and ed / ec >= 0.5),    # 같은 번호 케이스의 절반 이상 탐지
            })
    write_csv(OUT / "b2_cwe_detection.csv", item_rows)

    # 1회 분석 → 제도별 충족 항목 수
    # 매뉴얼 44와 행안부 49는 제도 문서의 '항목' 단위로 센다. 행안부 항목 하나에 CWE가 여러 개면(예: 94;95)
    # 그중 하나라도 시험 가능·충족이면 그 항목을 시험 가능·충족으로 본다.
    # 두 제도의 공통·합집합은 항목 구성이 달라 CWE 단위로 센다.
    cwe_res = {(r["b2_cwe"], r["tool"]): r for r in item_rows}

    def regime_items(path: Path, label: str) -> list[tuple[str, set[int]]]:
        with open(path, encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        return [(r.get("item") or r.get("name") or label,
                 {int(x) for x in (r["cwe_ids"] or "").split(";") if x.strip()}) for r in rows]

    regimes = [("매뉴얼 보안약점 44", "항목", regime_items(DATA / "mapping_manual44.csv", "")),
               ("행안부 49", "항목", regime_items(DATA / "mapping_mois49.csv", "")),
               ("두 제도 공통", "CWE", [(str(c), {c}) for c in sorted(m44 & m49)]),
               ("두 제도 합집합", "CWE", [(str(c), {c}) for c in sorted(m44 | m49)])]
    keys = ["testable", "met_any", "met_exact_any", "met_exact_half"]
    cov_rows = []
    for name, unit, items in regimes:
        for tool in tools_all:
            counts = dict.fromkeys(keys, 0)
            counts["testable_exact"] = 0
            for _, ids in items:
                rs = [cwe_res[(c, tool)] for c in ids if (c, tool) in cwe_res]
                for k in keys:
                    counts[k] += int(any(r[k] for r in rs))
                counts["testable_exact"] += int(any(r["exact_cases"] > 0 for r in rs))
            cov_rows.append({"regime": name, "unit": unit, "tool": tool, "items": len(items),
                             "testable": counts["testable"], "testable_exact": counts["testable_exact"],
                             "met_any": counts["met_any"], "met_exact_any": counts["met_exact_any"],
                             "met_exact_half": counts["met_exact_half"]})
    write_csv(OUT / "regime_coverage.csv", cov_rows)

    if fp_rows:
        write_csv(rundir / "fp_candidates.csv", fp_rows)
        by_rule = defaultdict(lambda: {"false_positives": 0, "cases": set(), "cwes": set()})
        for r in fp_rows:
            b = by_rule[(r["tool"], r["rule"])]
            b["false_positives"] += 1
            b["cases"].add(r["case_id"])
            b["cwes"].add(int(r["cwe_id"]))
        write_csv(OUT / "fp_by_rule.csv", [
            {"tool": t, "rule": rule, "false_positives": b["false_positives"], "cases": len(b["cases"]),
             "case_cwes": ";".join(map(str, sorted(b["cwes"])))}
            for (t, rule), b in sorted(by_rule.items(), key=lambda kv: (TOOLS.index(kv[0][0]), -kv[1]["false_positives"]))])
    if unmapped:
        write_csv(rundir / "clang_tidy_unmapped.csv",
                  [{"check": k, "count": v} for k, v in sorted(unmapped.items(), key=lambda kv: -kv[1])])

    for r in cov_rows:
        if r["tool"] == UNION:
            print(f"{r['regime']}: {r['unit']} {r['items']}, 시험 가능 {r['testable']}, "
                  f"한 건이라도 탐지 {r['met_any']}, 같은 번호 절반 이상 {r['met_exact_half']}")
    print(f"관련 CWE 오탐 {len(fp_rows)}건, CWE 대응이 없는 clang-tidy 검사 {len(unmapped)}종")


if __name__ == "__main__":
    main()
