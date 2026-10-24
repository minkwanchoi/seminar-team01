"""CWE 버전 파일(XML)에서 이 연구가 쓰는 뷰와 범주를 계산한다.

MITRE는 최신 버전만 뷰별 CSV로 주고, 지난 버전은 전체 XML(cwec_vX.Y.xml.zip)로만 남긴다.
그래서 어느 버전이든 같은 방법으로 다시 만들 수 있도록 XML 하나에서 모두 계산한다.

- 언어별 뷰(CWE-658·659·660)는 조건(Filter)으로 정의된다:
  Applicable_Platforms/Language/@Name 이 해당 언어인 약점
- 나머지 뷰(1154·868·1305·1400 등)는 범주(Category)를 거쳐 약점을 담는 그래프 뷰다:
  뷰 → 범주 → (범주 →) 약점 순으로 Has_Member(View_ID가 그 뷰인 것)를 따라간다
- 상위 범주(Pillar)는 연구 관점 뷰 CWE-1000의 기본(Primary) ChildOf 부모를 따라 올라간다
"""

import io
import re
import zipfile
import xml.etree.ElementTree as ET

import pandas as pd

LANG_VIEWS = {658: "C", 659: "C++", 660: "Java"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class Catalog:
    def __init__(self, xml_bytes: bytes):
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError:
            # 옛 버전(2.x) 파일 일부는 xhtml: 접두어를 선언하지 않고 쓴다. 루트에 선언을 넣고 다시 읽는다
            head = re.search(rb"<Weakness_Catalog\b", xml_bytes)
            fixed = (xml_bytes[:head.end()] + b' xmlns:xhtml="http://www.w3.org/1999/xhtml"'
                     + xml_bytes[head.end():])
            root = ET.fromstring(fixed)
        self.version = root.get("Version") or root.get("Catalog_Version")  # 옛 스키마는 Catalog_*
        self.date = root.get("Date") or root.get("Catalog_Date")
        self.weaknesses: dict[int, ET.Element] = {}
        self.categories: dict[int, ET.Element] = {}
        self.views: dict[int, ET.Element] = {}
        for el in root.iter():
            tag = _local(el.tag)
            if tag == "Weakness":
                self.weaknesses[int(el.get("ID"))] = el
            elif tag == "Category":
                self.categories[int(el.get("ID"))] = el
            elif tag == "View":
                self.views[int(el.get("ID"))] = el

    @classmethod
    def from_zip(cls, data: bytes) -> "Catalog":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            name = next(n for n in zf.namelist() if n.endswith(".xml"))
            return cls(zf.read(name))

    # ── 약점 정보 ──
    def weakness_table(self) -> pd.DataFrame:
        rows = [{"cwe_id": i, "name": w.get("Name"), "abstraction": w.get("Abstraction"),
                 "status": w.get("Status"), "replaced_by": self._replaced_by(w)} for i, w in self.weaknesses.items()]
        df = pd.DataFrame(rows).sort_values("cwe_id").reset_index(drop=True)
        df.insert(1, "cwe", "CWE-" + df["cwe_id"].astype(str))
        return df

    def _replaced_by(self, w: ET.Element) -> str:
        """폐기된 약점이면 설명에 적힌 옮겨 간 번호(예: 'duplicate of CWE-350' → '350')를 돌려준다."""
        if w.get("Status") != "Deprecated":
            return ""
        desc = next((el for el in w.iter() if _local(el.tag) == "Description"), None)
        m = re.search(r"CWE-(\d+)", "".join(desc.itertext()) if desc is not None else "")
        return m.group(1) if m else ""

    def _languages(self, w: ET.Element) -> set[str]:
        # 스키마 7(4.x)은 Name, 옛 스키마(2.x)는 Language_Name 속성을 쓴다
        return {el.get("Name") or el.get("Language_Name") for el in w.iter()
                if _local(el.tag) == "Language" and (el.get("Name") or el.get("Language_Name"))}

    def _members(self, el: ET.Element, view_id: int) -> list[int]:
        return [int(m.get("CWE_ID")) for m in el.iter()
                if _local(m.tag) == "Has_Member" and m.get("View_ID") == str(view_id)]

    # ── 뷰 구성원(약점 번호 집합) ──
    def view_members(self, view_id: int) -> set[int]:
        if view_id not in self.views:
            raise KeyError(f"CWE {self.version}에 뷰 CWE-{view_id}가 없습니다")
        if view_id in LANG_VIEWS:
            lang = LANG_VIEWS[view_id]
            return {i for i, w in self.weaknesses.items() if lang in self._languages(w)}
        found, stack, seen = set(), self._members(self.views[view_id], view_id), set()
        while stack:
            cid = stack.pop()
            if cid in seen:
                continue
            seen.add(cid)
            if cid in self.weaknesses:
                found.add(cid)
            elif cid in self.categories:
                stack.extend(self._members(self.categories[cid], view_id))
        # 그래프 뷰는 그 뷰 안의 ChildOf 관계(View_ID가 그 뷰)로 하위 약점을 더 담는다(예: CISQ 1305)
        children = {}
        for i, w in self.weaknesses.items():
            for rel in w.iter():
                if (_local(rel.tag) == "Related_Weakness" and rel.get("Nature") == "ChildOf"
                        and rel.get("View_ID") == str(view_id)):
                    children.setdefault(int(rel.get("CWE_ID")), set()).add(i)
        stack = list(found | seen)
        while stack:
            for child in children.get(stack.pop(), ()):
                if child not in found:
                    found.add(child)
                    stack.append(child)
        return found

    def view_table(self, view_id: int) -> pd.DataFrame:
        ids = self.view_members(view_id)
        return self.weakness_table().drop(columns="replaced_by").query("cwe_id in @ids").reset_index(drop=True)

    # ── 상위 범주(Pillar), 연구 관점 뷰 CWE-1000 기준 ──
    def pillar_table(self, research_view: int = 1000) -> pd.DataFrame:
        parent = {}
        for i, w in self.weaknesses.items():
            for rel in w.iter():
                if (_local(rel.tag) == "Related_Weakness" and rel.get("Nature") == "ChildOf"
                        and rel.get("View_ID") == str(research_view) and rel.get("Ordinal") == "Primary"):
                    parent[i] = int(rel.get("CWE_ID"))
                    break
        info = {i: (w.get("Name"), w.get("Abstraction")) for i, w in self.weaknesses.items()
                if w.get("Status") != "Deprecated"}
        rows = []
        for cid in sorted(info):
            top, seen = cid, set()
            while top in parent and top not in seen:
                seen.add(top)
                top = parent[top]
            rows.append({"cwe_id": cid, "name": info[cid][0], "abstraction": info[cid][1],
                         "pillar_id": top, "pillar": f"CWE-{top}",
                         "pillar_name": info.get(top, ("", ""))[0]})
        return pd.DataFrame(rows)

    # ── 성격별 범주(CWE-1400) ──
    def category_table(self, view_id: int, names_ko: dict[int, str]) -> pd.DataFrame:
        rows = []
        for cid in self._members(self.views[view_id], view_id):
            cat = self.categories.get(cid)
            if cat is None or cid not in names_ko:
                continue
            name = re.sub(r"^Comprehensive Categorization: ", "", cat.get("Name"))
            for member in self._members(cat, view_id):
                rows.append({"cwe_id": member, "category_id": cid, "category": name,
                             "category_ko": names_ko[cid]})
        df = pd.DataFrame(rows).drop_duplicates("cwe_id")
        return df.sort_values("cwe_id").reset_index(drop=True)
