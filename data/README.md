# data — CWE 기준 목록과 제도별 매핑

> **연구 목적 안내:** 이 자료는 ‘신흥기술 실습’ 수업 팀 프로젝트(seminar-team01)의 연구·교육 목적 결과물입니다. 방위사업청·행정안전부 등 관계 기관의 공식 입장이나 해석이 아닙니다. 인용한 자료의 권리는 각 원저작자에게 있으며, 연구에 필요한 최소 범위로 출처를 밝혀 실었습니다.

> **분석 범위:** 공개적으로 확인할 수 있는 요구 목록만 비교합니다. 비공개 기준, 2차 자료, CWE 버전 고정, 번호 일치 방식에 따른 한계는 [docs/B_분석범위와_한계.md](../docs/B_분석범위와_한계.md)에 정리했습니다.

## 출처와 이용 조건

이 폴더의 데이터는 아래 조건에 따라 씁니다. 새 자료를 넣을 때는 이 표에 이용 조건을 먼저 확인해 적습니다.

| 자료 | 해당 파일 | 이용 조건 |
|---|---|---|
| MITRE CWE (The MITRE Corporation, 2023, 2025, 2026) | `cwe/` 아래 버전별 CSV, `cwe_top25_2025.csv`의 CWE 번호·이름·범주 | CWE Terms of Use. 연구·개발·상업 목적의 무상 이용을 허락하되, 사본에 MITRE의 저작권 표시와 이용약관을 함께 실어야 함(아래 고지) |
| 「소프트웨어 개발보안 가이드」(행정안전부 & 한국인터넷진흥원, 2021a) | `mapping_mois49.csv`의 항목 분류·항목명·참고 CWE. `source_page`에 인쇄 쪽 번호 | 공공누리 제1유형(출처표시). 교차 확인: 「소프트웨어 보안약점 진단가이드」(행정안전부 & 한국인터넷진흥원, 2021b) |
| 「무기체계 소프트웨어 개발 및 관리 매뉴얼」 보안약점 점검 목록 44개 (방위사업청, 2024, 부록 7, pp. 7-10–7-11) | `mapping_manual44.csv`의 CWE 번호와 중복여부 표시 | 방위사업청 홈페이지 업무게시판에 공개된 현행본(제2024-6호, 2024. 12. 26.) 원문과 대조. 게시판에 공공누리 표시가 없고 사이트에 "All Rights Reserved"가 적혀 있어 공공누리 이용 허락이 아닌 인용 규정에만 근거함. 본문·부록에는 별도 이용 조건 표시가 없고, "복제/복사 및 배포 금지"는 부록 1·2 제안요청서 양식에만 있음. 별책(방위사업청, 2020)의 발췌 승인 조항은 이 목록과 무관함. 학술 인용 기준(저작권법 제28조)에 따라 분석에 필요한 최소 범위만 출처를 밝혀 인용 |

**MITRE CWE 고지**

> CWE™ is free to use by any organization or individual for any research, development, and/or commercial purposes, per the CWE Terms of Use. The MITRE Corporation hereby grants you a non-exclusive, royalty-free license to use CWE for research, development, and commercial purposes. Any copy you make for such purposes is authorized on the condition that you reproduce MITRE's copyright designation and this license in any such copy.
>
> Copyright © 2006–2026, The MITRE Corporation. CWE and the CWE logo are trademarks of The MITRE Corporation. https://cwe.mitre.org/about/termsofuse.html

### 참고문헌 (APA 7판)

방위사업청. (2020). *무기체계 소프트웨어 개발 및 관리 매뉴얼 별책: 무기체계 소프트웨어 기술문서 작성가이드*. https://www.hansung.ac.kr/bbs/vvna/1669/2943/download.do

행정안전부, & 한국인터넷진흥원. (2021a). *소프트웨어 개발보안 가이드*. https://www.kisa.or.kr/2060204/form?postSeq=5

행정안전부, & 한국인터넷진흥원. (2021b). *소프트웨어 보안약점 진단가이드*. https://www.kisa.or.kr/2060204/form?postSeq=9

방위사업청. (2024). *무기체계 소프트웨어 개발 및 관리 매뉴얼* (방위사업청 매뉴얼 제2024-6호). https://dapa.go.kr/dapa/doc/selectDocList.do?menuSeq=3042&bbsSeq=462&ctgrySeq=214

MDS인텔리전스. (2026, 2월 20일). *[CodeSonar] 무기체계 소프트웨어 개발 매뉴얼 內 보안 약점 대응 방안* [기술노트]. https://www.mdsit.co.kr/mdsit/ko/support/tech-notes/0phmk817fr5rr

The MITRE Corporation. (2025). *2025 CWE Top 25 most dangerous software weaknesses*. https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html

The MITRE Corporation. (2023). *Common Weakness Enumeration (CWE) list* (Version 4.10) [Data set]. https://cwe.mitre.org/data/xml/cwec_v4.10.xml.zip

The MITRE Corporation. (2026). *Common Weakness Enumeration (CWE) list* (Version 4.20) [Data set]. https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip

> 매뉴얼 44개는 처음에 MDS인텔리전스(2026)의 기술노트에서 재인용했다가, 2026. 10. 22. 현행본(제2024-6호) 원문을 확보해 직접 인용으로 바꿨습니다. 44개 번호와 중복여부 표시 25개가 기술노트와 모두 같았습니다.

## 1. CWE 기준 목록 (B1, 버전별)

MITRE CWE에서 받은 기준 목록입니다. **CWE 버전마다 폴더를 따로 둡니다.** 지금은 매뉴얼 시험확인서 예시 양식이 적은 **4.10**과 최신 **4.20**이 있습니다.

```
data/cwe/versions.csv          수집한 버전, 발표일, 원본 링크, 수집일, 성격별 범주 출처
data/cwe/version_summary.csv   버전마다 핵심 수치 (analysis/compare_versions.py)
data/cwe/version_diff.csv      인접 버전 사이에 목록마다 늘거나 빠진 CWE
data/cwe/version_scan.csv      MITRE 아카이브의 여러 버전(2.9~최신)에서 언어별 뷰 크기만 센 결과 (analysis/scan_versions.py)
data/cwe/v4.10/  data/cwe/v4.20/   아래 표의 파일과 그 버전의 겹침 분석 결과(overlap_*.csv)
```

- **원본:** MITRE의 버전 파일(`https://cwe.mitre.org/data/xml/cwec_vX.Y.xml.zip`)에서 계산합니다. 원본 XML은 계산에만 쓰고 저장소에 넣지 않습니다.
- **검증:** 4.20을 이 방법으로 계산한 결과는 MITRE가 주는 뷰별 CSV와 아래 8개 뷰 모두 번호가 같았습니다. 이름은 XML 쪽이 더 정확합니다(예: CWE-38의 역슬래시).
- **언어별 뷰(658·659·660):** 조건으로 정의된 뷰라, 그 버전의 약점 중 적용 언어(`Applicable_Platforms/Language`)가 C·C++·Java인 것을 셉니다.
- **나머지 뷰:** 범주를 거쳐 약점을 담는 뷰라, 범주 구성원과 그 뷰 안의 하위 관계(ChildOf)를 따라갑니다.

| 버전 폴더의 파일 | 내용 | 4.10 | 4.20 |
|---|---|---|---|
| `cwe_658.csv` | CWE-658 Weaknesses in Software Written in C | 82 | 103 |
| `cwe_659.csv` | CWE-659 Weaknesses in Software Written in C++ | 86 | 97 |
| `cwe_660.csv` | CWE-660 Weaknesses in Software Written in Java | 77 | 84 |
| `cwe_cert_c.csv` | 해외 참고 사례: CWE-1154 Weaknesses Addressed by the SEI CERT C Coding Standard | 78 | 78 |
| `cwe_cert_cpp.csv` | 해외 참고 사례: CWE-868 Weaknesses Addressed by the SEI CERT C++ Coding Standard (2016 Version) | 95 | 95 |
| `cwe_cisq.csv` | 해외 참고 사례: CWE-1305 CISQ Quality Measures (2020) | 138 | 138 |
| `cwe_owasp2021.csv` | 참고용: CWE-1344 Weaknesses in OWASP Top Ten (2021). 비교 집합에는 넣지 않음 | 182 | 182 |
| `cwe_pillar.csv` | CWE별 최상위 범주(Pillar). 연구 관점 뷰 CWE-1000에서 기본(Primary) 부모를 따라 올라간 결과 | 933 | 944 |
| `cwe_category.csv` | CWE별 성격별 범주(CWE-1400, 22개 범주). 한글 범주명(`category_ko`)은 팀이 붙인 번역 | 944 | 944 |
| `cwe_all.csv` | 그 버전의 모든 약점과 상태(폐기 여부 확인용) | 958 | 969 |

- **CWE-1400은 4.12부터 있습니다.** 그래서 4.10에는 4.20의 성격별 범주를 적용했습니다(`versions.csv`의 `category_source`).
- **Top 25는 연도별 목록이라 버전 폴더 밖에 둡니다.** `data/cwe_top25_2025.csv`(뷰 CWE-1435, 25개)를 모든 버전에서 같이 씁니다.

### 열

- 공통: `cwe_id`(숫자), `cwe`(`CWE-79` 형식), `name`, `abstraction`(Pillar·Class·Base·Variant·Compound), `status`
- Top 25 추가: `rank`, `score`, `kev_cves`(CISA KEV에 오른 CVE 수), `rank_change`(2024년 대비 순위 변동, 2024 목록에 없던 항목은 `new`)
- `cwe_pillar.csv`: `cwe_id`, `name`, `abstraction`, `pillar_id`, `pillar`, `pillar_name`

## 2. 제도별 CWE 매핑 (B2)

| 파일 | 내용 | 상태 |
|---|---|---|
| `mapping_mois49.csv` | 행안부·KISA 「소프트웨어 개발보안 가이드」(2021. 12. 29.) 구현단계 보안약점 49개 | 원문 확인(49개 항목, CWE 61개) |
| `mapping_manual44.csv` | 방사청 매뉴얼 보안약점 점검 목록 44개(제2022-6호에서 추가, 현행 제2024-6호 부록 7) | 원문 확인. CWE 번호와 중복여부 표시만 인용 |

### 열

`no`(원문 순번), `category`(원문 분류), `item`(원문 항목명), `cwe_ids`(세미콜론으로 구분한 CWE 번호), `mapping_note`(매핑이 애매한 이유), `source_page`(근거 문서와 쪽), `status`(`확인` 또는 `2차 자료(원문 대조 필요)`).

### 매핑 기준

1. **원문이 적은 CWE를 그대로 씁니다.** 가이드나 매뉴얼이 항목마다 참조한 CWE 번호를 옮기고, 우리가 판단해 번호를 더하거나 빼지 않습니다.
2. **1:N을 허용합니다.** 한 항목이 CWE 여러 개를 참조하면 모두 적습니다(예: 암호화되지 않은 중요정보 → 311;312;319). 겹침을 셀 때는 항목이 아니라 CWE 번호 단위로 셉니다.
3. **상위·하위 CWE로 넓히지 않습니다.** 원문이 Class 수준(예: CWE-119)을 적었으면 그 번호만 쓰고, 하위 Base·Variant(120·121·122·125·787 등)로 펼치지 않습니다. 이 때문에 Top 25처럼 하위 번호를 쓰는 목록과의 겹침은 실제보다 작게 나올 수 있으며, 보고서에 이 한계를 적습니다.
4. **원문에 번호가 없거나 애매하면** `mapping_note`에 이유를 적고, 팀원 A와 합의한 결과를 그 열에 남깁니다.
5. **확인 상태를 행마다 남깁니다.** 원문 PDF와 대조한 행만 `status`를 `확인`으로 바꿉니다.

### 아직 남은 일

- `mapping_mois49.csv`는 KISA 자료실의 「소프트웨어 개발보안 가이드」(2021. 12. 29.) PDF에서 항목마다 "참고자료"에 적힌 CWE 번호를 옮겼습니다. 같은 자료실의 「소프트웨어 보안약점 진단가이드」(2021)와 교차 확인한 결과, 49개 중 46개가 같았습니다. 다른 3개는 다음과 같이 처리했습니다.
  - 36번(오류 메시지 정보노출): 진단가이드는 209만 적음. 개발보안 가이드의 209;497을 씀.
  - 43번(역직렬화): 진단가이드는 CWE-918(SSRF)을 적었는데, 항목 내용과 맞지 않는 오기로 보고 개발보안 가이드의 502를 씀.
  - 48번(DNS lookup): 진단가이드는 247만 적음. 개발보안 가이드의 350;247을 씀. CWE-247은 CWE 4.20에서 폐기되어 350으로 통합된 번호라, 분석 결과에서는 범주가 "폐기"로 표시됩니다.
  - 초안에서 바뀐 항목: 2·9·22·36·44·48·49번의 CWE, 7·29번의 항목명. 22번은 초안에 있던 311이 원문에 없어 뺐습니다.
- **매뉴얼 보안약점 44개는 학술 인용 기준으로 싣습니다.** 현행본(제2024-6호) 부록 7 "소프트웨어 신뢰성/보안성 시험 절차"의 보안약점 점검 목록(7-10~7-11쪽)과 대조했습니다. 분석에 필요한 최소 범위(CWE 번호와 중복여부 표시)만 출처를 밝혀 인용하며, 이 목록은 겹침 분석의 입력 데이터로 쓰기 위한 것이지 목록만 따로 배포하려는 것이 아닙니다. 매뉴얼 원문 PDF는 저장소에 올리지 않습니다.
  - 열: `cwe_ids`(CWE 번호), `name`(MITRE CWE 4.20 명칭, 매뉴얼 문장이 아님), `overlap_flag`(원 표의 "중복여부" 표시 O. 원문 주석: 코딩규칙 점검·취약점 점검 항목과 중복되는 규칙. 언어별 뷰만 가리키는 것이 아님, 3절 참고), `mapping_note`(우리 분석: CWE 4.20 뷰 포함 여부), `source`(출처와 쪽), `status`(`확인`). 원 표의 순서·모양은 옮기지 않고 CWE 번호 순으로 정렬했습니다.
  - 목록은 제2022-6호(2022. 12. 2.)에서 추가되었고, 현행본 제2024-6호(2024. 12. 26.)에도 같은 44개가 있습니다.

## 3. 겹침 분석 결과 (B3)

`analysis/overlap.py`가 버전 폴더(`data/cwe/vX.Y/`)마다 만드는 파일입니다. 직접 고치지 말고 스크립트를 다시 실행합니다.

겹침(쌍별·고유·공통)은 국내 목록 다섯 개(매뉴얼 C·C++·Java 뷰, 매뉴얼 보안약점 44, 행안부 49)끼리만 계산합니다. 해외 목록(CWE Top 25, SEI CERT C·C++, CISQ 품질 측정)은 국내 시험 기준이 아니므로 참고 사례로 두고, 국내 목록이 얼마나 덮는지만 계산합니다.

| 파일 | 내용 |
|---|---|
| `overlap_matrix.csv` | CWE × 목록 0/1 매트릭스(국내 목록과 해외 참고 사례 열 모두). `n_sets`는 국내 목록 중 몇 개에 들어 있는지(해외 참고 사례에만 있으면 0). Pillar, 성격별 범주(`category`, `category_ko`) 포함. 그 버전에서 폐기되었거나 아직 없는 번호는 `pillar`가 `폐기`·`없음` |
| `overlap_pairs.csv` | 국내 목록 쌍별 크기, 교집합, 합집합, Jaccard 유사도, 한쪽에만 있는 수 |
| `overlap_summary.csv` | 국내 목록별 항목 수, 다른 국내 목록에는 없는 고유 항목 수 |
| `overlap_common.csv` | 국내 목록 모두에 공통인 CWE |
| `overlap_reference.csv` | 해외 참고 사례별 크기, 국내 목록 전체·매뉴얼·행안부 49가 덮는 수와 비율(`covered_*`, `pct_*`), 국내 목록에 없는 CWE(`missing_cwes`) |

### 버전 간 비교에서 확인한 것

| | CWE 4.10 | CWE 4.20 |
|---|---|---|
| 언어별 뷰 합집합(658∪659∪660) | 142 | 169 |
| 언어별 뷰 ∩ 행안부 49 | 15 | 16 |
| 매뉴얼 44 ∩ 행안부 49 | 33 | 33 |
| 매뉴얼 44의 "중복" 표시 25개 중 언어별 뷰에 없는 수 | 10 | 9 |

- 매뉴얼 보안약점 점검 목록이 "중복"으로 표시한 25개 가운데 언어별 뷰에 없는 번호는 CWE 버전에 따라 다릅니다. MITRE 아카이브의 32개 버전(2.9~4.20)을 훑어 보니 2.9~3.4.1은 11개, 4.0~4.16은 10개(CWE-209가 뷰에 들어옴), 4.17 이후는 9개(CWE-190이 들어옴)였습니다(`data/cwe/version_scan.csv`). 매뉴얼이 어느 버전을 기준으로 표시했는지는 원문에 없습니다. 다만 367·369·390·400·404·489·497·628·755의 9개는 조사한 모든 버전에서 언어별 뷰에 없으므로 버전 차이로 설명되지 않고, 원문 주석("코딩규칙점검 및 취약점점검 항목과 중복되는 규칙")대로 코딩규칙 점검과 겹친다는 표시로 봅니다.
- 같은 방법으로 센 CWE 3.2의 언어별 뷰 합집합은 136개로, 최민관(2019)이 같은 버전으로 센 수와 같습니다.

## 다시 만들기

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt
.venv/Scripts/python analysis/fetch_cwe.py 4.20
.venv/Scripts/python analysis/fetch_cwe.py 4.10
.venv/Scripts/python analysis/overlap.py --all-versions
.venv/Scripts/python analysis/compare_versions.py
.venv/Scripts/python analysis/scan_versions.py
.venv/Scripts/python analysis/plot_overlap.py
```

**새 CWE 버전 추가:** 버전 번호나 MITRE 버전 파일 링크를 주고, 분석·비교·그림을 다시 실행합니다. 버전을 생략하면 MITRE 사이트의 최신 버전을 받습니다.

```bash
.venv/Scripts/python analysis/fetch_cwe.py https://cwe.mitre.org/data/xml/cwec_v4.21.xml.zip
```

**브라우저에서 바로 보기:** 연구도구 페이지의 "CWE 파일 불러오기" 절에서 MITRE 아카이브(https://cwe.mitre.org/data/archive.html)의 버전 파일(`.xml.zip` 또는 `.xml`)을 고르면, 위와 같은 규칙으로 브라우저 안에서 계산해 그 버전으로 페이지를 다시 그립니다. 파일은 서버로 보내지 않으며, 결과는 저장소에 남지 않습니다(CSV로 내려받을 수 있음). 4.20과 4.10 파일로 시험해 저장소의 결과와 같음을 확인했습니다.

- 새 버전 결과를 만든 뒤 `version_diff.csv`에서 국내 목록 번호 중 폐기·삭제된 것이 있는지 사람이 확인합니다.
- 그림(`figures/`)은 보고서용이라 최신 버전 하나로만 만듭니다. 다른 버전은 `plot_overlap.py --cwe-version 4.10`으로 만듭니다.
- **Top 25 새 연도:** `fetch_cwe.py --top25 <Top 25 연도별 페이지 링크>`로 받고, 분석 스크립트의 Top 25 이름을 그 연도로 바꿉니다.

공개할 수 없는 자료를 팀 안에서만 함께 비교하려면 `local/mapping_*.csv`로 두고(커밋되지 않음) `analysis/overlap.py --with-local`, `analysis/plot_overlap.py --with-local` 순서로 실행합니다. 결과는 `local/out/vX.Y/`, `local/figures/`에 생깁니다.

macOS·Linux에서는 `.venv/Scripts/python` 대신 `.venv/bin/python`을 씁니다. 매뉴얼 취약점 점검이 CWE-658·659·660을 모두 쓰므로 Java(CWE-660)도 기본으로 비교에 넣습니다. C/C++만 보려면 `analysis/overlap.py --exclude-java`로 실행합니다.
