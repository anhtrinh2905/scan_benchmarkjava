#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""So sánh các "nút vặn" cấu hình của Metis trên cùng một tập BenchmarkJava.

Mỗi variant chỉ đổi MỘT (hoặc gộp vài) tham số trong metis_engine, giữ nguyên
scan model, tập test, và --triage. Mỗi variant chạy `review_code` MỘT LẦN DUY
NHẤT trên đúng 100 test file (qua metis_engine.review_code_include_paths) —
bắt buộc phải gộp vào một tiến trình vì `max_workers` chỉ có tác dụng khi nhiều
file được review CÙNG một tiến trình Metis (review_service.py: ThreadPoolExecutor
dùng chung cho cả lần gọi `review_code`).

Precision/recall tính từ ground truth (expectedresults-1.2.csv) — không có
LLM-judge, nhất quán với bench.py. Script này TÁI DÙNG trực tiếp các hàm đã
kiểm chứng của bench.py (load_config, load_ground_truth, select_tests,
score_run, aggregate, load_usage, BenchError...) bằng cách import thẳng nó
làm module — hai file nằm cùng thư mục nên không cần gói riêng.

  ./scripts/sweep.py                      # 5 variant × 100 test — TỐN KÉM, sẽ hỏi xác nhận
  ./scripts/sweep.py --dry-run            # xem config + lệnh sẽ chạy, không gọi LLM
  ./scripts/sweep.py --only baseline rounds_3
  ./scripts/sweep.py --sample 20          # scope nhỏ hơn để thử nghiệm rẻ trước
  ./scripts/sweep.py --rescore            # chỉ chấm lại từ kết quả đã có, không gọi Metis

Variant chạy TUẦN TỰ (không song song với nhau): mỗi variant đã tự dùng
max_workers riêng để review 100 file bên trong nó, và chạy nhiều variant cùng
lúc sẽ làm méo phép đo wall-clock (tranh chấp rate-limit giữa các variant).
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench as bm  # noqa: E402  (tái dùng động cơ đã kiểm chứng của bench.py)

OUT_DIR = bm.ROOT / "data" / "results" / "sweep"
DEFAULT_SAMPLE_SIZE = 100

# --------------------------------------------------------------------------
# Ma trận variant — mỗi variant deep-merge override này vào BASE_ENGINE.
# Giá trị "gốc" khớp với default đóng gói của Metis: max_workers=5,
# model_tools.max_rounds=6, reachability_max_paths_per_sink=3.
# --------------------------------------------------------------------------

BASE_ENGINE: dict = {
    "max_token_length": 250000,
    "max_workers": 5,
    "llm_max_retries": 5,
    "triage_checkpoint_every": 50,
    "triage_tool_timeout_seconds": 30,
    "reachability_reasoning_effort": "medium",
    "reachability_max_paths_per_sink": 3,
    "model_tools": {"max_rounds": 6},
}

VARIANTS: dict[str, dict] = {
    "baseline": {},
    "workers_10": {"max_workers": 10},
    "rounds_3": {"model_tools": {"max_rounds": 3}},
    "reach_1": {"reachability_max_paths_per_sink": 1},
    "lean_combo": {
        "max_workers": 10,
        "model_tools": {"max_rounds": 3},
        "reachability_max_paths_per_sink": 1,
    },
}

VARIANT_NOTES: dict[str, str] = {
    "baseline": "(không đổi gì) — mốc so sánh",
    "workers_10": "max_workers 5 -> 10 (nút THỜI GIAN)",
    "rounds_3": "model_tools.max_rounds 6 -> 3 (nút TOKEN)",
    "reach_1": "reachability_max_paths_per_sink 3 -> 1 (nút TOKEN)",
    "lean_combo": "gộp cả 3 nút trên",
}


def deep_merge(base: dict, override: dict) -> dict:
    """Deep-merge `override` vào `base` (sửa tại chỗ). Dict lồng nhau thì merge
    sâu; còn lại thì ghi đè. Trả về base."""
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base


# --------------------------------------------------------------------------
# metis.yaml cho từng variant
# --------------------------------------------------------------------------


def render_variant_yaml(cfg: dict[str, str], engine_override: dict,
                        include_paths: list[str]) -> str:
    """Sinh metis.yaml cho một variant.

    Dùng json.dumps() cho TOÀN BỘ nội dung: JSON là tập con hợp lệ của YAML,
    kể cả object/array lồng nhau, nên không cần PyYAML để deep-merge rồi
    serialize `metis_engine` (vốn có khoá lồng `model_tools` + danh sách
    `review_code_include_paths` hàng trăm phần tử).
    """
    engine = deep_merge(copy.deepcopy(BASE_ENGINE), engine_override)
    engine["review_code_include_paths"] = include_paths
    config = {
        "llm_provider": {
            "name": "openai",
            "model": cfg["CUSTOM_SCAN_MODEL"],
            "base_url": cfg["OPENCODE_BASE_URL"],
            "api_key_env": "OPENCODE_API_KEY",
        },
        "metis_engine": engine,
        "memory": {"enabled": False},
        "query": {"similarity_top_k": 5, "max_tokens": 5000, "temperature": 0.0},
    }
    return (
        "# Sinh tự động bởi sweep.py — mọi sửa tay sẽ bị ghi đè.\n"
        "# API key KHÔNG nằm trong file này; Metis đọc từ biến môi trường "
        "OPENCODE_API_KEY.\n"
        + json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    )


def include_paths_for(test_names: list[str]) -> list[str]:
    """review_code_include_paths là mẫu gitignore-style, TƯƠNG ĐỐI so với
    codebase-path (repository.py:161-164) — đường dẫn đủ (có "/") nên được
    coi là neo từ gốc, khớp CHÍNH XÁC file đó, không khớp nhầm file khác."""
    return [
        (bm.TESTCODE_DIR / f"{name}.java").relative_to(bm.BENCH_DIR).as_posix()
        for name in test_names
    ]


def variant_signature(cfg: dict[str, str], engine_override: dict,
                      test_names: list[str]) -> dict:
    """Chữ ký cấu hình. Cache chỉ hợp lệ khi chữ ký khớp — đổi model, override,
    hay tập test là kết quả cũ phải hết hạn, không được dùng lại im lặng."""
    tests_digest = hashlib.sha256(",".join(sorted(test_names)).encode()).hexdigest()[:16]
    return {
        "scan_model": cfg["CUSTOM_SCAN_MODEL"],
        "base_url": cfg["OPENCODE_BASE_URL"],
        "engine_override": engine_override,
        "tests_digest": tests_digest,
    }


# --------------------------------------------------------------------------
# Chạy một variant
# --------------------------------------------------------------------------


def variant_command(config_path: Path, chroma_dir: Path, sarif_path: Path,
                    json_path: Path) -> list[str]:
    return [
        "uv", "run", "--project", str(bm.METIS_DIR), "metis",
        "--codebase-path", str(bm.BENCH_DIR),
        "--config", str(config_path),
        "--chroma-dir", str(chroma_dir),
        "--tools", "navigation",
        "--log-level", "ERROR",
        "--non-interactive",
        "--command", "review_code",
        "--output-file", str(sarif_path),
        "--output-file", str(json_path),
        "--triage",
    ]


def run_variant(name: str, engine_override: dict, cfg: dict[str, str],
                test_names: list[str], env: dict[str, str], force: bool) -> dict:
    """Chạy review_code một lần cho variant `name`. Trả về
    {sarif, wall_clock, usage, cached}. Ném BenchError nếu hỏng."""
    variant_dir = OUT_DIR / name
    sarif_path = variant_dir / "review.sarif"
    json_path = variant_dir / "review.json"
    meta_path = variant_dir / "runmeta.json"
    log_path = variant_dir / "run.log"
    work_dir = variant_dir / ".work"

    signature = variant_signature(cfg, engine_override, test_names)

    if sarif_path.is_file() and meta_path.is_file() and not force:
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            json.loads(sarif_path.read_text(encoding="utf-8"))
            if meta.get("signature") == signature:
                print(f"    [cache] {variant_dir.relative_to(bm.ROOT)}")
                return {"sarif": sarif_path, "wall_clock": meta.get("wall_clock_seconds"),
                        "usage": meta.get("usage"), "cached": True}
            print("    [cache hết hạn: cấu hình đã đổi] chạy lại")
        except (json.JSONDecodeError, OSError):
            pass

    variant_dir.mkdir(parents=True, exist_ok=True)
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    sarif_path.unlink(missing_ok=True)
    meta_path.unlink(missing_ok=True)

    config_path = variant_dir / "metis.yaml"
    config_path.write_text(
        render_variant_yaml(cfg, engine_override, include_paths_for(test_names)),
        encoding="utf-8",
    )

    cmd = variant_command(config_path, work_dir / ".chromadb", sarif_path, json_path)
    print(f"    $ {' '.join(cmd)}", flush=True)
    start = time.monotonic()
    proc = subprocess.run(cmd, cwd=work_dir, env=env, capture_output=True, text=True)
    wall = round(time.monotonic() - start, 2)

    log_path.write_text(
        f"$ {' '.join(cmd)}\n  (cwd: {work_dir})\n\n"
        f"--- exit code: {proc.returncode} | wall-clock: {wall}s ---\n"
        f"\n--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n",
        encoding="utf-8",
    )

    # Không tin exit code một mình — kiểm tra sản phẩm thực tế (bench.py:
    # run_metis áp dụng cùng nguyên tắc, xem commands.py:90-92).
    if proc.returncode != 0:
        raise bm.BenchError(
            f"Metis thoát với mã {proc.returncode} cho variant {name}.\n"
            f"  log: {log_path}\n{bm._tail(proc.stderr or proc.stdout)}"
        )
    if not sarif_path.is_file():
        raise bm.BenchError(
            f"Variant {name} không sinh SARIF (dù exit 0).\n"
            f"  log: {log_path}\n{bm._tail(proc.stdout + proc.stderr)}"
        )
    try:
        json.loads(sarif_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise bm.BenchError(f"SARIF hỏng cho variant {name}: {exc}\n  file: {sarif_path}") from exc

    usage = bm.load_usage(work_dir / "results")
    meta_path.write_text(json.dumps({
        "signature": signature,
        "wall_clock_seconds": wall,
        "usage": usage,
        "ran_at": bm._utc_now(),
    }, indent=2), encoding="utf-8")

    shutil.rmtree(work_dir, ignore_errors=True)

    return {"sarif": sarif_path, "wall_clock": wall, "usage": usage, "cached": False}


# --------------------------------------------------------------------------
# Đọc SARIF gộp (nhiều file trong một lần review_code) và chấm điểm
# --------------------------------------------------------------------------


def extract_findings_by_test(sarif_path: Path,
                             test_names: list[str]) -> tuple[dict[str, list[dict]], int]:
    """Nhóm finding theo test, dựa vào artifactLocation.uri của mỗi result.

    Khác với bench.py (mỗi SARIF chỉ ứng với đúng 1 test nên không cần đọc uri),
    ở đây MỘT SARIF chứa finding của cả 100 file — bắt buộc phải tách theo tên
    test rút ra từ uri.
    """
    payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    buckets: dict[str, list[dict]] = {name: [] for name in test_names}
    unmatched = 0
    for run in payload.get("runs") or []:
        for result in run.get("results") or []:
            props = result.get("properties") or {}
            locations = result.get("locations") or []
            uri, line, snippet = "", 0, ""
            if locations:
                physical = locations[0].get("physicalLocation") or {}
                uri = str((physical.get("artifactLocation") or {}).get("uri") or "")
                region = physical.get("region") or {}
                try:
                    line = int(region.get("startLine") or 0)
                except (TypeError, ValueError):
                    line = 0
                snippet = str((region.get("snippet") or {}).get("text") or "")

            match = re.search(r"(BenchmarkTest\d+)", uri)
            test_name = match.group(1) if match else None
            finding = {
                "cwe_raw": props.get("cwe"),
                "cwes": bm.cwe_numbers(props.get("cwe")),
                "severity": props.get("severity"),
                "status": str(props.get("metisTriageStatus") or "valid").strip().lower(),
                "triaged": bool(props.get("metisTriaged")),
                "triage_reason": props.get("metisTriageReason"),
                "line": line,
                "snippet": snippet,
                "issue": str((result.get("message") or {}).get("text") or "").strip(),
            }
            if test_name and test_name in buckets:
                buckets[test_name].append(finding)
            else:
                unmatched += 1
    return buckets, unmatched


def triage_precision(findings: list[dict]) -> dict | None:
    """Precision suy ra từ nhãn metisTriageStatus của chính Metis (miễn phí,
    không cần ground truth)."""
    statuses = [f["status"] for f in findings if f["triaged"]]
    if not statuses:
        return None
    tp = sum(1 for s in statuses if s == "valid")
    fp = sum(1 for s in statuses if s == "invalid")
    return {
        "with_status": len(statuses),
        "tp_like": tp,
        "fp_like": fp,
        "inconclusive": sum(1 for s in statuses if s == "inconclusive"),
        "precision": (tp / (tp + fp)) if (tp + fp) else None,
    }


def score_variant(buckets: dict[str, list[dict]], truth: dict[str, dict]) -> dict:
    """Chấm từng test bằng bm.score_run() (tái dùng nguyên logic strict/lenient
    của bench.py), rồi tổng hợp strict/lenient qua toàn bộ tập test."""
    per_test = {test: bm.score_run(findings, truth[test])
                for test, findings in buckets.items()}
    strict = bm.aggregate([r["outcome_strict"] for r in per_test.values()])
    lenient = bm.aggregate([r["outcome_lenient"] for r in per_test.values()])
    return {"strict": strict, "lenient": lenient, "per_test": per_test}


# --------------------------------------------------------------------------
# Báo cáo
# --------------------------------------------------------------------------


def build_report(rows: list[dict]) -> tuple[str, str]:
    lines = [
        "# So sánh sweep Metis",
        "",
        f"_Sinh lúc {bm._utc_now()}_",
        "",
        "| Variant | Thời gian (phút) | Total token | Findings | Triage-prec "
        "| GT-precision | GT-recall |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        note = VARIANT_NOTES.get(row["variant"], "")
        minutes_text = "n/a" if row["minutes"] is None else f"{row['minutes']:.1f}"
        tokens_text = "n/a" if row["total_tokens"] is None else str(row["total_tokens"])
        findings_text = "n/a" if row["findings"] is None else str(row["findings"])
        lines.append(
            f"| {row['variant']} ({note}) | {minutes_text} "
            f"| {tokens_text} "
            f"| {findings_text} "
            f"| {bm._pct(row['triage_prec'])} "
            f"| {bm._pct(row['gt_precision'])} | {bm._pct(row['gt_recall'])} |"
        )
    lines.append("")
    lines.append("> Precision/recall tính từ ground truth (expectedresults-1.2.csv), "
                 "cột strict (`inconclusive` = vẫn tính là báo cáo). Không dùng LLM-judge.")
    lines.append("")

    cols = ["variant", "minutes", "total_tokens", "findings",
            "triage_prec", "gt_precision", "gt_recall", "gt_tp", "gt_fp", "gt_fn", "gt_tn"]
    csv_lines = [",".join(cols)]
    for row in rows:
        csv_lines.append(",".join(
            "" if row.get(c) is None else str(row[c]) for c in cols
        ))

    return "\n".join(lines) + "\n", "\n".join(csv_lines) + "\n"


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="So sánh 5 variant cấu hình Metis trên cùng một tập BenchmarkJava.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--only", nargs="+", metavar="VARIANT",
                        help=f"Chỉ chạy các variant này. Có sẵn: {', '.join(VARIANTS)}.")
    parser.add_argument("--sample", type=int, default=DEFAULT_SAMPLE_SIZE, metavar="N",
                        help=f"Số test ĐẦU TIÊN theo thứ tự tên dùng làm scope sweep "
                             f"(mặc định {DEFAULT_SAMPLE_SIZE}, cùng tập với bench.py).")
    parser.add_argument("--force", action="store_true",
                        help="Bỏ qua cache của variant, chạy lại từ đầu.")
    parser.add_argument("--dry-run", action="store_true",
                        help="In config + lệnh sẽ chạy cho từng variant rồi thoát. "
                             "Không gọi LLM.")
    parser.add_argument("--rescore", action="store_true",
                        help="Chỉ chấm lại từ SARIF đã có trong results/sweep/<variant>/, "
                             "không gọi Metis.")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Không hỏi xác nhận trước khi sweep.")
    args = parser.parse_args()

    variant_names = list(VARIANTS)
    if args.only:
        unknown = [n for n in args.only if n not in VARIANTS]
        if unknown:
            raise bm.BenchError(f"Variant không tồn tại: {', '.join(unknown)}. "
                                f"Có sẵn: {', '.join(VARIANTS)}.")
        variant_names = args.only

    cfg = bm.load_config()
    truth = bm.load_ground_truth()
    test_names = bm.select_tests(truth, args.sample)
    if not test_names:
        raise bm.BenchError("Không tìm thấy test nào có file .java.")

    if not shutil.which("uv"):
        raise bm.BenchError("Không tìm thấy `uv` trong PATH.")
    if not (bm.METIS_DIR / "pyproject.toml").is_file():
        raise bm.BenchError(f"Không tìm thấy project Metis tại {bm.METIS_DIR}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if args.dry_run:
        print(f"# Scope: {len(test_names)} test ({test_names[0]} -> {test_names[-1]})\n")
        for name in variant_names:
            engine_override = VARIANTS[name]
            variant_dir = OUT_DIR / name
            print(f"## variant: {name}  —  {VARIANT_NOTES[name]}")
            print(f"   engine override: {engine_override or '(không có)'}")
            yaml_preview = render_variant_yaml(cfg, engine_override,
                                               include_paths_for(test_names[:3]) + ["... (còn lại bị cắt bớt để xem trước)"])
            print(yaml_preview)
            cmd = variant_command(variant_dir / "metis.yaml", variant_dir / ".work" / ".chromadb",
                                  variant_dir / "review.sarif", variant_dir / "review.json")
            print("   $ " + " ".join(cmd) + "\n")
        print(f"# Tổng: {len(variant_names)} variant × {len(test_names)} test/variant "
              f"= {len(variant_names) * len(test_names)} file-review, chạy TUẦN TỰ.")
        return 0

    total_reviews = len(variant_names) * len(test_names)
    if total_reviews and not args.yes and not args.rescore and sys.stdin.isatty():
        print(f"Scope: {len(test_names)} test ({test_names[0]} -> {test_names[-1]})")
        print(f"Variant sẽ chạy: {', '.join(variant_names)}")
        print(f"\n{len(variant_names)} variant × {len(test_names)} test — mỗi variant là "
              f"MỘT LẦN QUÉT ĐẦY ĐỦ (tốn hàng triệu token / hàng chục phút).")
        answer = input("Tiếp tục? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Đã huỷ.")
            return 0

    env = os.environ.copy()
    env.update(cfg)

    rows: list[dict] = []
    first = True
    for name in variant_names:
        engine_override = VARIANTS[name]
        print(f"\n=== variant: {name}  ({VARIANT_NOTES[name]}) ===")

        try:
            if args.rescore:
                variant_dir = OUT_DIR / name
                sarif_path = variant_dir / "review.sarif"
                if not sarif_path.is_file():
                    raise bm.BenchError(f"--rescore nhưng thiếu {sarif_path}")
                meta_path = variant_dir / "runmeta.json"
                meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.is_file() else {}
                outcome = {"sarif": sarif_path, "wall_clock": meta.get("wall_clock_seconds"),
                           "usage": meta.get("usage")}
            else:
                outcome = run_variant(name, engine_override, cfg, test_names, env, args.force)
        except bm.BenchError as exc:
            # Variant đầu tiên fail-fast (thường là lỗi cấu hình/auth, áp dụng cho
            # mọi variant còn lại) — các variant sau lỗi thì bỏ qua, không huỷ cả sweep.
            if first:
                raise bm.BenchError(f"Variant đầu tiên ({name}) thất bại — dừng trước khi "
                                    f"chạy {len(variant_names) - 1} variant còn lại.\n{exc}")
            print(f"  LỖI, bỏ qua variant này: {exc}", file=sys.stderr)
            rows.append({"variant": name, "minutes": None, "total_tokens": None,
                        "findings": None, "triage_prec": None,
                        "gt_precision": None, "gt_recall": None,
                        "gt_tp": None, "gt_fp": None, "gt_fn": None, "gt_tn": None,
                        "error": str(exc)})
            continue
        first = False

        buckets, unmatched = extract_findings_by_test(outcome["sarif"], test_names)
        if unmatched:
            print(f"  ! {unmatched} finding không khớp tên test nào trong scope "
                  "(bỏ khỏi mọi phép tính)", file=sys.stderr)
        all_findings = [f for findings in buckets.values() for f in findings]

        scored = score_variant(buckets, truth)
        tri = triage_precision(all_findings)
        usage = outcome.get("usage") or {}
        seconds = usage.get("duration_seconds") or outcome.get("wall_clock")

        row = {
            "variant": name,
            "minutes": round(seconds / 60, 1) if seconds else None,
            "total_tokens": usage.get("total_tokens"),
            "findings": len(all_findings),
            "triage_prec": tri["precision"] if tri else None,
            "gt_precision": scored["strict"]["precision"],
            "gt_recall": scored["strict"]["recall"],
            "gt_tp": scored["strict"]["TP"], "gt_fp": scored["strict"]["FP"],
            "gt_fn": scored["strict"]["FN"], "gt_tn": scored["strict"]["TN"],
        }
        rows.append(row)

        variant_dir = OUT_DIR / name
        (variant_dir / "detail.json").write_text(json.dumps({
            "variant": name, "engine_override": engine_override,
            "wall_clock_seconds": outcome.get("wall_clock"), "usage": usage,
            "triage_precision": tri, "ground_truth": scored,
            "unmatched_findings": unmatched,
        }, indent=2, ensure_ascii=False), encoding="utf-8")

        print(f"  -> {row['minutes']} phút | {row['total_tokens']} token | "
              f"{row['findings']} finding | triage={bm._pct(row['triage_prec'])} | "
              f"GT precision={bm._pct(row['gt_precision'])} recall={bm._pct(row['gt_recall'])}")

    md, csv_text = build_report(rows)
    (OUT_DIR / "compare.md").write_text(md, encoding="utf-8")
    (OUT_DIR / "compare.csv").write_text(csv_text, encoding="utf-8")
    (OUT_DIR / "compare.json").write_text(json.dumps(rows, indent=2, ensure_ascii=False),
                                          encoding="utf-8")

    print("\n" + md)
    print(f"Bảng so sánh: {OUT_DIR / 'compare.md'}")
    print(f"             {OUT_DIR / 'compare.csv'}")

    if any(r.get("error") for r in rows):
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except bm.BenchError as exc:
        print(f"\nLỗi: {exc}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\nĐã huỷ.", file=sys.stderr)
        sys.exit(130)
