# 출처와 이용 조건 (NOTICE)

> **관리 규칙:** 이 파일이 이용 조건의 기준 문서입니다. 연구도구 페이지(`overlap.html`)의 "출처와 이용 조건" 절은 이 파일과 같은 내용을 담으며, **두 곳은 같은 커밋에서 함께 고칩니다.** 다른 문서는 이 파일로 연결만 합니다. 새 자료를 넣을 때는 이용 조건을 먼저 확인해 아래 표에 적은 뒤 씁니다.
>
> 갱신일: 2026. 10. 22.

## 연구 목적 안내

이 저장소와 연구도구 페이지는 ‘신흥기술 실습’ 수업 팀 프로젝트(seminar-team01)의 연구·교육 목적 결과물입니다. 방위사업청·행정안전부·한국인터넷진흥원 등 관계 기관의 공식 입장이나 해석이 아닙니다. 인용한 자료의 권리는 각 원저작자에게 있으며, 연구에 필요한 최소 범위로 출처를 밝혀 실었습니다.

## 자료별 이용 조건

| 자료 | 원 출처의 이용 조건 | 이 저장소에서 쓰는 범위 | 지키는 방법 |
|---|---|---|---|
| MITRE CWE List(4.10, 4.20)와 2025 CWE Top 25 | CWE Terms of Use: 연구·개발·상업 목적의 무상 이용 허락. 사본마다 MITRE 저작권 표시와 이용허락 문구를 함께 실어야 함 | CWE 번호·이름·추상화 수준·상태, 뷰·범주 구성, Top 25 순위·점수(`data/cwe/`, `data/cwe_top25_2025.csv`, 그림, 페이지) | 아래 MITRE 고지 원문을 이 파일과 페이지에 게재. 페이지에서 내려받는 CSV 첫 줄에 저작권 표시와 약관 주소 |
| 「소프트웨어 개발보안 가이드」(행정안전부·한국인터넷진흥원, 2021. 12. 29.) | 공공누리 제1유형(출처표시). 게시물 표기: "한국인터넷진흥원이 창작한 소프트웨어 개발 보안 가이드 저작물은 공공누리 출처표시 조건에 따라 이용할 수 있습니다." | 구현단계 보안약점 49개의 분류·항목명·참고 CWE(`data/mapping_mois49.csv`) | 저작물명·저작자(한국인터넷진흥원)·공공누리 유형·원문 주소 표시 |
| 「소프트웨어 보안약점 진단가이드」(행정안전부·한국인터넷진흥원, 2021) | 게시물에 공공누리 표시를 확인하지 못함 | 교차 확인에만 씀. 내용은 싣지 않고, 개발보안 가이드와 다른 3개 항목의 CWE 번호만 `data/README.md`에 서술 | 출처 표시 |
| 「무기체계 소프트웨어 개발 및 관리 매뉴얼」(방위사업청 매뉴얼 제2024-6호, 2024. 12. 26.) | 방위사업청 업무게시판 공개. 공공누리 표시 없음, 사이트 하단 "All Rights Reserved". 부록 1·2 제안요청서 양식에만 "복제/복사 및 배포 금지" 표기 | 부록 7 보안약점 점검 목록의 **CWE 번호와 중복여부 표시만**(`data/mapping_manual44.csv`). 이름은 MITRE 명칭을 쓰고, 원 표의 순서·모양은 옮기지 않음. 정의·주석 문장 몇 개를 문서에서 짧게 인용 | 아래 "매뉴얼 이용 근거" 참고. 원문 파일은 저장소와 페이지에 올리지 않음 |
| 같은 매뉴얼의 이전 판(2020)과 별책(기술문서 작성가이드) | 위와 같음 | 한계 설명에서 서지 정보만 인용 | 방위사업청 업무게시판 주소로 출처 표시 |
| 논문·기사·보고서(참고문헌 목록) | 일반 저작물 | 짧은 인용과 요약 | 본문 인용 표시와 APA 7판 참고문헌 |
| JSZip 3.10.1 | MIT 라이선스 | 페이지에서 .zip 파일을 열 때만 cdnjs에서 실행 중에 불러옴 | 저장소에 포함하거나 재배포하지 않음 |
| MITRE 원본 XML, 매뉴얼·가이드 원문 PDF | 위 각 조건 | 분석 계산에만 쓰고 저장소에 넣지 않음 | `.gitignore`·`.git/info/exclude`로 제외 |

## 매뉴얼 이용 근거

매뉴얼 보안약점 점검 목록은 다음 근거로 최소 범위만 씁니다. 연구팀의 법 조문 해석이며 법률 자문이 아닙니다.

1. **저작권법 제24조의2 제1항(공공저작물의 자유이용):** 국가가 업무상 작성하여 공표한 저작물은 허락 없이 이용할 수 있습니다. 방위사업청은 국가기관이고, 매뉴얼은 업무상 작성해 홈페이지에 공표한 문서입니다. 다만 같은 항 단서 제1호(국가안전보장에 관련되는 정보를 포함하는 경우)는 예외이므로, 공개 게시물이라도 이 단서에 해당하는지는 단정하지 않습니다.
2. **보충적으로 제28조(공표된 저작물의 인용):** 연구를 위하여 정당한 범위 안에서 공정한 관행에 합치되게 인용합니다. 그래서 CWE 번호와 중복여부 표시만 싣고, 목록은 분석 재현용 입력 데이터로만 두며 페이지에 내려받기 링크를 두지 않습니다.
3. **제37조(출처의 명시):** 위 근거로 이용할 때 출처를 명시합니다.

방위사업청이 이용 범위에 이의를 제기하면 해당 파일을 내리고 협의합니다.

## MITRE CWE 고지

> CWE™ is free to use by any organization or individual for any research, development, and/or commercial purposes, per the CWE Terms of Use. The MITRE Corporation hereby grants you a non-exclusive, royalty-free license to use CWE for research, development, and commercial purposes. Any copy you make for such purposes is authorized on the condition that you reproduce MITRE's copyright designation and this license in any such copy.
>
> Copyright © 2006–2026, The MITRE Corporation. CWE and the CWE logo are trademarks of The MITRE Corporation. https://cwe.mitre.org/about/termsofuse.html

## 원 출처

- MITRE CWE: https://cwe.mitre.org/data/archive.html (버전 파일), https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
- 소프트웨어 개발보안 가이드: https://www.kisa.or.kr/2060204/form?postSeq=5
- 소프트웨어 보안약점 진단가이드: https://www.kisa.or.kr/2060204/form?postSeq=9
- 무기체계 소프트웨어 개발 및 관리 매뉴얼(현행본·이전 판·별책): https://dapa.go.kr/dapa/doc/selectDocList.do?menuSeq=3042&bbsSeq=462&ctgrySeq=214
- JSZip: https://github.com/Stuk/jszip (MIT)

## 문의·삭제 요청

이용 범위에 문제가 있다고 보시면 팀 저장소 이슈(https://github.com/suyoungi/seminar-team01/issues)로 알려 주세요. 확인하는 동안 해당 자료를 내립니다.
