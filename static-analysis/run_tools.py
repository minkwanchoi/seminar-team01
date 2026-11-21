"""B5. 고른 Juliet 케이스에 정적 분석 도구 세 개(cppcheck, clang-tidy, flawfinder)를 돌린다.

WSL 우분투(또는 리눅스)에서 실행한다. 표준 라이브러리만 쓴다.
설치와 버전은 static-analysis/README.md 참고.

  python3 static-analysis/run_tools.py --case CWE476_NULL_Pointer_Dereference__int_01   # 케이스 하나
  python3 static-analysis/run_tools.py --cwe 476                                       # CWE 하나
  python3 static-analysis/run_tools.py --all                                           # juliet_cases.csv 전체
  옵션: --tools cppcheck,flawfinder  --platform any  --match 정확  --name 실행이름  --jobs 4

결과는 static-analysis/_runs/<실행이름>/ 에 쓴다(git 제외).
- <도구>/<파일>.{xml,txt,csv} : 도구 원래 출력
- status.csv : 케이스·도구·파일마다 종료 코드, 걸린 시간, 지적 수(대략), 컴파일 오류 여부
- run_log.txt : 도구 버전, 실행 명령, 요약. 경로는 프로젝트 기준 상대 경로로 적는다
탐지 여부 판정(결함 줄과 지적 줄 맞추기)은 B6에서 한다.
"""

import argparse
import csv
import datetime as dt
import os
import platform
import re
import shlex
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
JULIET = HERE / "_juliet" / "C"
SUPPORT = JULIET / "testcasesupport"
CASES = HERE / "juliet_cases.csv"
TOOLS = ["cppcheck", "clang-tidy", "flawfinder"]

# clang-tidy에서 켜는 검사. 보안·버그 관련 묶음만 쓴다
CLANG_TIDY_CHECKS = "-*,clang-analyzer-*,bugprone-*,cert-*"


def rel(p: Path | str) -> str:
    """로그에는 프로젝트 기준 상대 경로만 남긴다."""
    return os.path.relpath(p, ROOT).replace(os.sep, "/")


def command(tool: str, src: Path, lang: str) -> list[str]:
    if tool == "cppcheck":
        return ["cppcheck", "--enable=warning,style,performance,portability", "--inconclusive",
                "--xml", "--xml-version=2", "--suppress=missingIncludeSystem",
                f"--language={'c++' if lang == 'cpp' else 'c'}", f"-I{SUPPORT}", str(src)]
    if tool == "clang-tidy":
        std = "-std=c++11" if lang == "cpp" else "-std=gnu99"
        return ["clang-tidy", "--quiet", f"--checks={CLANG_TIDY_CHECKS}", str(src), "--",
                "-x", "c++" if lang == "cpp" else "c", std, f"-I{SUPPORT}"]
    if tool == "flawfinder":
        return ["flawfinder", "--csv", "--minlevel=0", "--dataonly", str(src)]
    raise ValueError(tool)


EXT = {"cppcheck": "xml", "clang-tidy": "txt", "flawfinder": "csv"}


def count_findings(tool: str, text: str) -> tuple[int, bool]:
    """(지적 수, 컴파일 오류 여부). 대략 센다 — 정확한 판정은 B6."""
    if tool == "cppcheck":
        ids = re.findall(r'<error id="([^"]+)"', text)
        skip = {"missingInclude", "missingIncludeSystem", "checkersReport", "toomanyconfigs", "normalCheckLevelMaxBranches"}
        return sum(i not in skip for i in ids), "syntaxError" in ids
    if tool == "clang-tidy":
        warns = re.findall(r"^\S+:\d+:\d+: (warning|error): .*\[([\w\-.,]+)\]$", text, re.M)
        compile_err = any(k == "error" and "clang-diagnostic-error" in c for k, c in warns)
        return sum(k == "warning" for k, _ in warns), compile_err
    if tool == "flawfinder":
        rows = list(csv.reader(text.splitlines()))
        return max(len(rows) - 1, 0), False
    return 0, False


def version(tool: str) -> str:
    try:
        out = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=30)
        lines = [l.strip() for l in (out.stdout + out.stderr).splitlines() if l.strip()]
        vline = next((l for l in lines if re.search(r"\d+\.\d+", l)), lines[0] if lines else "")
        return vline
    except FileNotFoundError:
        return "설치 안 됨"


def run_one(tool: str, case: dict, src: Path, outdir: Path) -> dict:
    cmd = command(tool, src, case["language"])
    t0 = time.perf_counter()
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    secs = time.perf_counter() - t0
    # cppcheck는 결과 XML을 stderr에, 나머지는 stdout에 낸다. clang-tidy의 컴파일 오류 줄도 stdout에 섞인다
    text = p.stderr if tool == "cppcheck" else p.stdout + (p.stderr if tool == "clang-tidy" else "")
    out = outdir / tool / f"{src.name}.{EXT[tool]}"  # Juliet 파일 이름에 케이스 이름이 들어 있다
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text.replace(str(JULIET) + "/", ""), encoding="utf-8")
    n, compile_err = count_findings(tool, text)
    return {"case_id": case["case_id"], "cwe_id": case["cwe_id"], "match": case["match"],
            "platform": case["platform"], "tool": tool, "file": src.name, "returncode": p.returncode,
            "seconds": f"{secs:.2f}", "findings": n, "compile_error": int(compile_err),
            "output": rel(out), "command": " ".join(shlex.quote(rel(c) if c.startswith(str(ROOT)) else c)
                                                   for c in (x.replace(f"-I{SUPPORT}", f"-I{rel(SUPPORT)}") for x in cmd))}


def main() -> None:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--case", action="append", help="case_id (여러 번 줄 수 있음)")
    g.add_argument("--cwe", type=int, action="append", help="Juliet CWE 번호")
    g.add_argument("--all", action="store_true")
    ap.add_argument("--tools", default=",".join(TOOLS))
    ap.add_argument("--platform", choices=["any", "windows"], help="이 플랫폼 케이스만")
    ap.add_argument("--match", choices=["정확", "하위"], help="이 맞춤 방식만")
    ap.add_argument("--name", default=dt.datetime.now().strftime("%Y%m%d-%H%M%S"))
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    args = ap.parse_args()

    if not SUPPORT.exists():
        sys.exit(f"{rel(SUPPORT)}가 없습니다. README.md의 'Juliet 받기'를 먼저 하세요.")
    tools = [t for t in args.tools.split(",") if t]
    with open(CASES, encoding="utf-8", newline="") as f:
        cases = [r for r in csv.DictReader(f) if r["selected"] == "1"]
    if args.case:
        cases = [r for r in cases if r["case_id"] in set(args.case)]
    elif args.cwe:
        cases = [r for r in cases if int(r["cwe_id"]) in set(args.cwe)]
    if args.platform:
        cases = [r for r in cases if r["platform"] == args.platform]
    if args.match:
        cases = [r for r in cases if r["match"] == args.match]
    if not cases:
        sys.exit("고른 케이스가 없습니다. case_id와 juliet_cases.csv를 확인하세요.")

    outdir = HERE / "_runs" / args.name
    outdir.mkdir(parents=True, exist_ok=True)
    jobs = []
    for c in cases:
        for f in c["files"].split(";"):
            if f.endswith((".c", ".cpp")):
                jobs += [(t, c, JULIET / f) for t in tools]
    started = dt.datetime.now().astimezone()
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        rows = list(ex.map(lambda j: run_one(*j, outdir), jobs))
    rows.sort(key=lambda r: (r["case_id"], r["file"], tools.index(r["tool"])))

    with open(outdir / "status.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    lines = [
        "# B5 정적 분석 실행 기록",
        f"실행 이름: {args.name}",
        f"시작: {started.isoformat(timespec='seconds')}",
        f"환경: {platform.system()} {platform.release()} / Python {platform.python_version()}",
        f"Juliet: C/C++ 1.3 ({rel(JULIET)})",
        "도구 버전:",
        *[f"  - {t}: {version(t)}" for t in tools],
        f"clang-tidy 검사: {CLANG_TIDY_CHECKS}",
        f"케이스 {len(cases)}개, 실행 {len(rows)}건",
        "",
        "케이스 | 파일 | 도구 | 종료 코드 | 지적 수 | 컴파일 오류 | 초",
    ]
    for r in rows:
        lines.append(f"{r['case_id']} | {r['file']} | {r['tool']} | {r['returncode']} | {r['findings']} | "
                     f"{'예' if r['compile_error'] == 1 else '아니오'} | {r['seconds']}")
    lines += ["", "실행 명령:"]
    for r in rows:
        lines.append(f"  [{r['tool']}] {r['command']}")
    (outdir / "run_log.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    by_tool = {t: [r for r in rows if r["tool"] == t] for t in tools}
    for t, rs in by_tool.items():
        print(f"{t}: {len(rs)}건, 지적 있음 {sum(int(r['findings']) > 0 for r in rs)}건, "
              f"컴파일 오류 {sum(r['compile_error'] for r in rs)}건")
    print(f"결과: {rel(outdir)}")


if __name__ == "__main__":
    main()
