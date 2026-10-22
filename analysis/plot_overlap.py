"""B4. 겹침 분석 결과 시각화.

analysis/overlap.py가 만든 data/overlap_*.csv를 읽어 figures/에 SVG 그림 다섯 장을 만든다.
겹침 그림(1~4)은 국내 목록만 그리고, 해외 목록은 참고 사례 그림(5)에만 쓴다.
  1. venn_domestic.svg           매뉴얼 취약점 점검(CWE-658·659·660) · 매뉴얼 보안약점 44 · 행안부 49 벤 다이어그램
  2. jaccard_heatmap.svg         국내 목록 쌍별 Jaccard 유사도 히트맵
  3. pillar_share.svg            국내 목록별 CWE의 상위 범주(Pillar) 구성비
  4. category_by_set.svg         성격별 범주(CWE-1400)마다 국내 목록이 요구하는 CWE 수
  5. reference_coverage.svg      해외 참고 사례의 CWE를 국내 목록이 덮는 정도

실행: python analysis/plot_overlap.py [--with-local]

--with-local을 주면 비공개 자료까지 넣은 local/out/의 결과로 그려 local/figures/에 쓴다(커밋하지 않음).
"""

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
from matplotlib import font_manager  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402
from matplotlib_venn import venn3  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
FIG_DIR = ROOT / "figures"

# 차트 색: 범주 1~3번(청·주황·청록), 크기는 파랑 한 색의 명도 단계
SERIES = ["#2a78d6", "#eb6834", "#1baf7a"]
NONE_FILL = "#d6d5ce"  # 국내 목록에 없는 부분
SEQ_BLUE = ["#f4f8fd", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
INK, INK_2, MUTED, GRID = "#0b0b0b", "#52514e", "#898781", "#e1e0d9"

# 운영체제마다 있는 한글 글꼴만 골라 쓴다(없는 글꼴을 적으면 경고가 쏟아짐)
_installed = {f.name for f in font_manager.fontManager.ttflist}
KOREAN_FONTS = [f for f in ("Malgun Gothic", "Apple SD Gothic Neo", "NanumGothic") if f in _installed]

plt.rcParams.update({
    "font.family": KOREAN_FONTS + ["sans-serif"],
    "axes.unicode_minus": False,
    "svg.fonttype": "none",  # 글자를 경로가 아닌 텍스트로 남겨 웹에서 선명하게 보이게 함
    "svg.hashsalt": "seminar-team01",  # 다시 만들어도 SVG 내부 ID가 바뀌지 않게 고정
    "text.color": INK, "axes.labelcolor": INK_2,
    "xtick.color": INK_2, "ytick.color": INK_2,
    "axes.edgecolor": GRID, "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
})

MOIS = "행안부 49"
MANUAL44 = "매뉴얼 보안약점 44"
REFERENCE = ["CWE Top 25 (2025)", "SEI CERT C·C++", "CISQ 품질 측정"]  # 해외 참고 사례


def set_columns(matrix: pd.DataFrame) -> list[str]:
    """국내 목록 열만 돌려준다(해외 참고 사례 열은 뺀다)."""
    fixed = {"cwe_id", "cwe", "name", "abstraction", "pillar", "pillar_name",
             "category", "category_ko", "n_sets"}
    return [c for c in matrix.columns if c not in fixed and c not in REFERENCE]


def ids_of(matrix: pd.DataFrame, cols: list[str]) -> set[int]:
    return set(matrix.loc[matrix[cols].max(axis=1) == 1, "cwe_id"])


def plot_venn(matrix: pd.DataFrame, names: list[str]) -> None:
    # 매뉴얼 취약점 점검의 언어별 뷰(C·C++·Java)를 하나로 합친다
    view_cols = [n for n in names if n.startswith("매뉴얼·")]
    views = ids_of(matrix, view_cols)
    langs = "·".join(c.removeprefix("매뉴얼·").split(" (")[0] for c in view_cols)
    manual44 = ids_of(matrix, [MANUAL44])
    mois = ids_of(matrix, [MOIS])

    fig, ax = plt.subplots(figsize=(7, 5.6))
    v = venn3([views, manual44, mois],
              set_labels=(f"매뉴얼 취약점 점검\n{langs} 뷰 ({len(views)})",
                          f"매뉴얼 보안약점 44\n({len(manual44)} CWE)",
                          f"행안부 49개 항목\n({len(mois)} CWE)"),
              set_colors=SERIES, alpha=0.55, ax=ax)
    for patch in v.patches:
        if patch is not None:
            patch.set_edgecolor("#fcfcfb")
            patch.set_linewidth(2)
    for text in v.subset_labels:
        if text is not None:
            text.set_fontsize(12)
    ax.set_title("국내 목록 세 묶음의 겹침\n(CWE 번호 단위, CWE 4.20 기준)", fontsize=12, color=INK)
    fig.savefig(FIG_DIR / "venn_domestic.svg", bbox_inches="tight", metadata={"Date": None})
    plt.close(fig)


def plot_jaccard(pairs: pd.DataFrame, names: list[str]) -> None:
    grid = pd.DataFrame(1.0, index=names, columns=names)
    for _, r in pairs.iterrows():
        grid.loc[r["set_a"], r["set_b"]] = grid.loc[r["set_b"], r["set_a"]] = r["jaccard"]

    cmap = LinearSegmentedColormap.from_list("seq_blue", SEQ_BLUE)
    fig, ax = plt.subplots(figsize=(7, 5.6))
    ax.imshow(grid.values, cmap=cmap, vmin=0, vmax=1)
    ax.set_xticks(range(len(names)), names, rotation=30, ha="right")
    ax.set_yticks(range(len(names)), names)
    for i in range(len(names)):
        for j in range(len(names)):
            val = grid.values[i, j]
            ax.text(j, i, "—" if i == j else f"{val:.2f}", ha="center", va="center",
                    fontsize=11, color="#fcfcfb" if val >= 0.5 else INK)
    ax.set_xticks([x - 0.5 for x in range(1, len(names))], minor=True)
    ax.set_yticks([y - 0.5 for y in range(1, len(names))], minor=True)
    ax.grid(which="minor", color="#fcfcfb", linewidth=2)
    ax.tick_params(which="both", length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("국내 목록 쌍별 Jaccard 유사도 (교집합 ÷ 합집합, CWE 번호 단위)", fontsize=12, color=INK)
    fig.savefig(FIG_DIR / "jaccard_heatmap.svg", bbox_inches="tight", metadata={"Date": None})
    plt.close(fig)


def plot_pillar_share(matrix: pd.DataFrame, names: list[str]) -> None:
    pillars = (matrix[["pillar", "pillar_name"]].drop_duplicates()
               .sort_values("pillar").reset_index(drop=True))
    share = pd.DataFrame(index=pillars["pillar"], columns=names, dtype=float)
    for n in names:
        sub = matrix[matrix[n] == 1]
        share[n] = sub["pillar"].value_counts(normalize=True).reindex(share.index).fillna(0) * 100
    labels = [f"{p} {nm}" if p.startswith("CWE-") else nm
              for p, nm in zip(pillars["pillar"], pillars["pillar_name"])]

    cmap = LinearSegmentedColormap.from_list("seq_blue", SEQ_BLUE)
    fig, ax = plt.subplots(figsize=(9, 6.2))
    ax.imshow(share.values, cmap=cmap, vmin=0, vmax=max(50, share.values.max()), aspect="auto")
    ax.set_xticks(range(len(names)), names, rotation=30, ha="right")
    ax.set_yticks(range(len(labels)), labels, fontsize=9)
    for i in range(share.shape[0]):
        for j in range(share.shape[1]):
            val = share.values[i, j]
            ax.text(j, i, f"{val:.0f}%" if val else "·", ha="center", va="center", fontsize=10,
                    color="#fcfcfb" if val >= 30 else (INK if val else MUTED))
    ax.set_xticks([x - 0.5 for x in range(1, len(names))], minor=True)
    ax.set_yticks([y - 0.5 for y in range(1, len(labels))], minor=True)
    ax.grid(which="minor", color="#fcfcfb", linewidth=2)
    ax.tick_params(which="both", length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("국내 목록별 CWE의 상위 범주(Pillar) 구성비 (열마다 합계 100%)", fontsize=12, color=INK)
    fig.savefig(FIG_DIR / "pillar_share.svg", bbox_inches="tight", metadata={"Date": None})
    plt.close(fig)


def plot_category(matrix: pd.DataFrame, names: list[str]) -> None:
    """성격별 범주(CWE-1400) × 국내 목록. 칸 숫자는 CWE 개수, 색은 그 목록 안에서 차지하는 비율."""
    cats = (matrix.groupby("category_ko")[names].sum()
            .assign(_total=lambda d: d.sum(axis=1))
            .sort_values("_total", ascending=False).drop(columns="_total"))
    share = cats.div(cats.sum(axis=0), axis=1) * 100

    cmap = LinearSegmentedColormap.from_list("seq_blue", SEQ_BLUE)
    fig, ax = plt.subplots(figsize=(9, 0.42 * len(cats) + 1.6))
    ax.imshow(share.values, cmap=cmap, vmin=0, vmax=max(40, share.values.max()), aspect="auto")
    ax.set_xticks(range(len(names)), names, rotation=30, ha="right")
    ax.set_yticks(range(len(cats)), cats.index, fontsize=10)
    for i in range(cats.shape[0]):
        for j in range(cats.shape[1]):
            n, pct = int(cats.values[i, j]), share.values[i, j]
            ax.text(j, i, str(n) if n else "·", ha="center", va="center", fontsize=10,
                    color="#fcfcfb" if pct >= 25 else (INK if n else MUTED))
    ax.set_xticks([x - 0.5 for x in range(1, len(names))], minor=True)
    ax.set_yticks([y - 0.5 for y in range(1, len(cats))], minor=True)
    ax.grid(which="minor", color="#fcfcfb", linewidth=2)
    ax.tick_params(which="both", length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("성격별 범주(CWE-1400)마다 국내 목록이 요구하는 CWE 수\n(숫자는 개수, 색은 그 목록 안에서의 비율)",
                 fontsize=12, color=INK)
    fig.savefig(FIG_DIR / "category_by_set.svg", bbox_inches="tight", metadata={"Date": None})
    plt.close(fig)


def plot_reference(matrix: pd.DataFrame, names: list[str]) -> None:
    """해외 참고 사례마다 CWE를 매뉴얼·행안부 49가 덮는 정도(가로 누적 막대, 개수)."""
    manual = ids_of(matrix, [n for n in names if n.startswith("매뉴얼")])
    mois = ids_of(matrix, [MOIS])
    refs = [r for r in REFERENCE if r in matrix.columns]
    parts = {"매뉴얼과 행안부 49 모두": [], "매뉴얼에만": [], "행안부 49에만": [], "국내 목록에 없음": []}
    for r in refs:
        ids = ids_of(matrix, [r])
        parts["매뉴얼과 행안부 49 모두"].append(len(ids & manual & mois))
        parts["매뉴얼에만"].append(len((ids & manual) - mois))
        parts["행안부 49에만"].append(len((ids & mois) - manual))
        parts["국내 목록에 없음"].append(len(ids - manual - mois))

    fig, ax = plt.subplots(figsize=(8, 3.2))
    left = [0] * len(refs)
    for (label, vals), color in zip(parts.items(), SERIES + [NONE_FILL]):
        ax.barh(range(len(refs)), vals, left=left, color=color, height=0.55, label=label,
                edgecolor="#fcfcfb", linewidth=2)
        for i, v in enumerate(vals):
            if v >= 6:
                ax.text(left[i] + v / 2, i, str(v), ha="center", va="center", fontsize=10,
                        color=INK if color == NONE_FILL else "#fcfcfb")
        left = [a + b for a, b in zip(left, vals)]
    for i, total in enumerate(left):
        covered = total - parts["국내 목록에 없음"][i]
        ax.text(total + 2, i, f"{covered}/{total} ({covered / total:.0%})", va="center", fontsize=10, color=INK_2)
    ax.set_yticks(range(len(refs)), refs)
    ax.invert_yaxis()
    ax.set_xlim(0, max(left) * 1.25)
    ax.set_xlabel("CWE 수")
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.legend(ncol=4, fontsize=9, frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.28))
    ax.set_title("해외 참고 사례의 CWE를 국내 목록이 덮는 정도 (막대 끝: 국내 목록에 있는 수/전체)",
                 fontsize=12, color=INK)
    fig.savefig(FIG_DIR / "reference_coverage.svg", bbox_inches="tight", metadata={"Date": None})
    plt.close(fig)


def main() -> None:
    global FIG_DIR
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--with-local", action="store_true",
                        help="local/out/의 비공개 포함 결과로 그려 local/figures/에 쓴다")
    args = parser.parse_args()
    src = ROOT / "local" / "out" if args.with_local else DATA_DIR
    if args.with_local:
        FIG_DIR = ROOT / "local" / "figures"
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    matrix = pd.read_csv(src / "overlap_matrix.csv")
    pairs = pd.read_csv(src / "overlap_pairs.csv")
    names = set_columns(matrix)

    plot_venn(matrix, names)
    plot_jaccard(pairs, names)
    plot_pillar_share(matrix, names)
    plot_category(matrix, names)
    plot_reference(matrix, names)
    for f in sorted(FIG_DIR.glob("*.svg")):
        print(f.relative_to(ROOT))


if __name__ == "__main__":
    main()
