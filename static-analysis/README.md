# 정적 분석 실증 환경 (B5)

RQ3 "하나의 정적 분석 결과가 여러 제도의 요구를 함께 채울 수 있는가"를 보려고, NIST SARD의 Juliet C/C++ 1.3 시험 코드에 공개 정적 분석 도구 세 개를 돌리는 환경입니다. 이 폴더는 케이스 고르기와 도구 실행(B5), 탐지 판정과 집계(B6)를 다룹니다. B6 결과와 해석은 [docs/정적분석_결과.md](../docs/정적분석_결과.md)에 있습니다.

> 결과는 **도구 성능 평가가 아니라 "여러 제도 충족도의 예시"** 로만 해석합니다(기획안 위험 대응). 공개 도구 세 개와 기본형 케이스만 쓰므로, 상용 도구나 실제 무기체계 코드의 결과를 대신하지 않습니다.

## 파일

| 파일 | 내용 |
|---|---|
| `select_cases.py` | Juliet 매니페스트와 B2 매핑(`data/mapping_manual44.csv`, `data/mapping_mois49.csv`)으로 케이스를 고름 |
| `juliet_cases.csv` | 고른 케이스 목록(흐름 변형 01) |
| `juliet_summary.csv` | CWE별 Juliet 케이스 규모(전체·Windows 전용·01) |
| `run_tools.py` | 고른 케이스에 cppcheck, clang-tidy, flawfinder를 돌림 |
| `logs/` | 실행 확인 기록(케이스 하나로 세 도구가 도는 것을 확인한 로그) |
| `judge.py` | (B6) 도구 출력으로 탐지·오탐을 판정하고 제도별 충족도를 집계 |
| `clang_tidy_cwe.csv` | (B6) clang-tidy 검사 이름(과 메시지) → CWE 대응표. 연구팀이 정함 |
| `sample_fp.py` | (B6) 오탐 후보에서 유형 분류용 표본을 뽑음 |
| `results/` | (B6) 판정·집계 결과. 해석은 [docs/정적분석_결과.md](../docs/정적분석_결과.md) |
| `_juliet/`, `_runs/` | Juliet 원본과 도구 원래 출력. **git에 넣지 않음** |

## 1. 환경

WSL 우분투 24.04에서 돌립니다. clang-tidy가 C 표준 헤더를 찾아야 해서 윈도에서 직접 돌리는 것보다 깔끔합니다.

```bash
sudo apt-get update
sudo apt-get install -y cppcheck clang-tidy clang flawfinder build-essential
```

확인한 버전(우분투 24.04 기본 저장소)은 `logs/`의 실행 기록 첫머리에 적혀 있습니다. 도구 버전이 바뀌면 결과도 바뀔 수 있으니, B6 결과에는 실행 기록의 버전을 함께 적습니다.

| 도구 | 하는 일 | 라이선스 |
|---|---|---|
| cppcheck | 의미 분석(널 포인터, 메모리 누수, 경계 초과 등) | GPL-3.0 |
| clang-tidy (clang-analyzer 포함) | 경로 민감 분석(`clang-analyzer-*`)과 버그·CERT 규칙(`bugprone-*`, `cert-*`) | Apache-2.0 WITH LLVM-exception |
| flawfinder | 위험 함수 호출을 찾는 어휘 분석. 결과에 CWE 번호를 붙임 | GPL-2.0-or-later |

세 도구는 설치해서 **실행만** 하고, 저장소에 넣거나 재배포하지 않습니다. 그래서 `requirements.txt`에도 넣지 않습니다(GPL 도구를 저장소 의존성으로 만들지 않기 위함).

## 2. Juliet 받기

| 항목 | 값 |
|---|---|
| 이름 | Juliet C/C++ 1.3 (NIST SARD Test suite #112, NSA Center for Assured Software 제작, 2017. 10. 1.) |
| 파일 | `2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip` (약 146 MB) |
| 주소 | https://samate.nist.gov/SARD/test-suites/112 |
| SHA-256 | `ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb` |
| 이용 조건 | 미국 저작권법 17 USC 105에 따라 저작권 보호 대상이 아니며(퍼블릭 도메인), 미국 밖에서는 CC0 1.0으로 제공 |

프로젝트 루트에서(윈도 Git Bash나 WSL 어느 쪽이든):

```bash
mkdir -p static-analysis/_juliet && cd static-analysis/_juliet
curl -L -o juliet-1.3.zip https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip
sha256sum juliet-1.3.zip   # 위 SHA-256과 같은지 확인
unzip -q juliet-1.3.zip    # → _juliet/C/ (testcases, testcasesupport, manifest.xml)
```

`_juliet/`과 `_runs/`는 `static-analysis/.gitignore`로 제외합니다. Juliet은 이용 조건상 문제는 없지만 6만 개가 넘는 파일이라 저장소에 넣지 않습니다.

## 3. 케이스 고르기

```bash
python static-analysis/select_cases.py            # 하위 관계는 최신 CWE 버전(data/cwe/versions.csv) 기준
python static-analysis/select_cases.py --cwe-version 4.10
```

기준은 다음과 같습니다.

1. **맞춤 방식(match)**
   - **정확:** 케이스의 CWE가 B2 매핑(매뉴얼 보안약점 44, 행안부 49)에 그대로 있음
   - **하위:** 케이스의 CWE가 B2 번호의 하위 약점임(연구 관점 뷰 CWE-1000의 ChildOf를 따라 올라가 만남). 예: Juliet CWE-121(스택 버퍼 오버플로)·122(힙 버퍼 오버플로)는 B2의 CWE-119 아래, CWE-401(메모리 누수)은 CWE-404 아래
   - B6에서는 두 방식을 **나누어** 집계합니다. "하위"는 제도가 상위 번호로 요구하는 약점을 도구가 더 구체적인 번호로 잡는 경우를 보려는 것입니다.
2. **흐름 변형:** 기본형 `01`만 고릅니다. 01은 제어·데이터 흐름이 가장 단순한 형태라서 "도구가 그 약점 자체를 아는가"를 봅니다. 02~84 변형의 규모는 `juliet_summary.csv`의 `all_cases`에 남깁니다.
3. **Windows 전용 케이스**(파일 이름에 `w32`)는 빼지 않고 `platform=windows`로 표시합니다. 리눅스의 clang-tidy는 `windows.h`가 없어 이 케이스를 끝까지 분석하지 못할 수 있으며, 그 경우 실행 기록에 "컴파일 오류"로 남습니다.

CWE 4.20 기준 결과(2026. 11. 21.):

| 구분 | 값 |
|---|---|
| B2 매핑 CWE(44 ∪ 49) | 72개 |
| 그중 Juliet에 같은 번호가 있는 CWE | 27개 |
| B2 번호의 하위로 이어지는 Juliet CWE | 34개 |
| 고른 케이스(흐름 변형 01) | 1,285개 = 정확 439 + 하위 846 |
| 그중 Windows 전용 | 158개 |

B2의 나머지 45개 CWE(예: 89 SQL 삽입, 79 XSS, 352 CSRF, 502 역직렬화)는 Juliet C/C++에 케이스가 없습니다. 웹·자바 성격의 약점이 많아서이며, 이 실증으로는 그 항목의 충족도를 말할 수 없습니다.

`juliet_cases.csv`의 열:

| 열 | 뜻 |
|---|---|
| `case_id` | 케이스 이름(파일 이름에서 a·b… 접미사와 확장자를 뺀 것) |
| `cwe_id` | Juliet이 분류한 CWE |
| `match`, `b2_cwe` | 맞춤 방식과, 맞춘 B2 번호 |
| `in_manual44`, `in_mois49` | 맞춘 B2 번호가 각 목록에 있는지(1/0) |
| `language`, `platform`, `flow_variant` | c/cpp, any/windows, 01 |
| `files` | `_juliet/C/` 기준 파일 경로(여러 파일이면 `;`) |
| `flaw_cwes`, `flaw_lines` | 매니페스트에 적힌 결함 CWE와 줄(`파일:줄`). B6의 탐지 판정 기준 |

## 4. 도구 돌리기

WSL에서 프로젝트 폴더로 가서 실행합니다(표준 라이브러리만 씀).

```bash
cd /mnt/d/26_2_신흥기술_실습/team_project
python3 static-analysis/run_tools.py --case CWE476_NULL_Pointer_Dereference__int_01 --name smoke
python3 static-analysis/run_tools.py --cwe 476 --cwe 415
python3 static-analysis/run_tools.py --all --platform any --name all-any
```

도구별 설정:

| 도구 | 명령의 핵심 |
|---|---|
| cppcheck | `--enable=warning,style,performance,portability --inconclusive --xml --xml-version=2 -I testcasesupport` |
| clang-tidy | `--checks=-*,clang-analyzer-*,bugprone-*,cert-*`, 컴파일 옵션 `-std=gnu99`(C)·`-std=c++11`(C++), `-I testcasesupport` |
| flawfinder | `--csv --minlevel=0 --dataonly` |

`INCLUDEMAIN`이나 `OMITBAD`·`OMITGOOD`는 정의하지 않습니다. 결함 함수(bad)와 정상 함수(good)를 한 파일에서 함께 분석해야 B6에서 bad 쪽 지적은 탐지, good 쪽 지적은 오탐으로 나눌 수 있습니다.

결과는 `_runs/<실행 이름>/`에 쌓입니다.

- `<도구>/<파일>.{xml,txt,csv}`: 도구 원래 출력
- `status.csv`: 케이스·도구·파일마다 종료 코드, 걸린 시간, 지적 수(대략), 컴파일 오류 여부
- `run_log.txt`: 도구 버전, 실행 명령, 요약(경로는 프로젝트 기준 상대 경로)

확인용 실행 기록은 `logs/`로 옮겨 커밋합니다.

### 실행 확인 (2026. 11. 21.)

`logs/smoke-20261121_*`: cppcheck 2.13.0, clang-tidy 18.1.3, flawfinder 2.0.19로 세 케이스를 돌렸습니다. 세 도구 모두 세 케이스에서 끝까지 실행됐습니다(9건).

| 케이스 | 매니페스트 결함 줄 | 본 것 |
|---|---|---|
| `CWE476_NULL_Pointer_Dereference__int_01` (C) | 30행 | cppcheck `nullPointer`(CWE-476)와 clang-tidy `clang-analyzer-core.NullDereference`가 30행을 짚음. flawfinder는 `main`의 `srand`(85행)만 지적 |
| `CWE416_Use_After_Free__new_delete_array_char_01` (C++) | 38행 | clang-tidy `clang-analyzer-cplusplus.NewDelete`가 38행의 해제 뒤 사용을 지적. cppcheck는 지적 없음 |
| `CWE78_OS_Command_Injection__char_connect_socket_w32_execv_01` (Windows 전용) | 137행 | clang-tidy가 `process.h`를 찾지 못해 컴파일 오류로 표시됨(예상한 한계). cppcheck·flawfinder는 실행됨 |

아직 탐지 판정은 하지 않았습니다(B6). 지적 수는 도구 출력에서 센 대략값입니다.

## 5. 한계

- Juliet은 인공 시험 코드라 실제 무기체계 코드보다 결함이 단순하고 뚜렷합니다.
- 흐름 변형 01만 쓰므로 복잡한 흐름에서의 탐지력은 보지 않습니다.
- B2 매핑 72개 중 27개만 같은 번호의 Juliet 케이스가 있습니다. "하위" 맞춤은 CWE 버전의 관계에 따라 달라질 수 있습니다(`--cwe-version`으로 바꿔 볼 수 있음).
- 매니페스트의 결함 줄은 bad 함수 안의 대표 줄이라, 도구가 같은 결함을 다른 줄에서 지적하면 B6에서 판정 규칙(같은 함수 안이면 탐지 등)을 따로 정해야 합니다.
