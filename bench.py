#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Chạy Metis trên một tập nhỏ OWASP BenchmarkJava, đo và chấm điểm.

Đo ba thứ:
  1) Thời gian  — wall-clock + started/ended trong usage json của Metis
  2) Token      — native từ results/metis_usage_*.json
  3) Precision/recall — đối chiếu với ground truth (expectedresults-1.2.csv)

Không có LLM-judge: mọi con số đều quy chiếu về một đáp án duy nhất là CSV.

Một lệnh duy nhất:
  ./bench.py                      # scan + chấm điểm
  ./bench.py --dry-run            # xem trước, không gọi LLM
  ./bench.py --repeat 3           # đo độ ổn định
  ./bench.py --tag baseline       # ghi vào results/baseline/

Chỉ dùng stdlib. Metis chạy môi trường riêng (Python 3.12+) do `uv run --project`
tự dựng ở lần đầu.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------
# Đường dẫn
# --------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent
METIS_DIR = ROOT / "metis"
BENCH_DIR = ROOT / "BenchmarkJava"
TESTCODE_DIR = BENCH_DIR / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
EXPECTED_CSV = BENCH_DIR / "expectedresults-1.2.csv"
RESULTS_ROOT = ROOT / "results"
ENV_FILE = ROOT / ".env"

# --------------------------------------------------------------------------
# Chọn tập test: N test ĐẦU TIÊN theo thứ tự tên (BenchmarkTest00001 trở đi).
# Ground truth KHÔNG hardcode — tra từ expectedresults CSV.
#
# CẢNH BÁO VỀ TÍNH ĐẠI DIỆN: 100 test đầu KHÔNG phản ánh phân bố của Benchmark.
# Toàn bộ 2740 test là 52% có lỗ hổng / 48% an toàn, nhưng 100 test đầu là
# 75/25 — và xss (8 test) lẫn ldapi (3 test) không có lấy một ca an toàn nào.
# Hệ quả: FPR và precision chỉ dựa trên 25 mẫu âm, sai số lớn; recall thì đáng
# tin hơn. Đọc số liệu theo hướng đó.
# --------------------------------------------------------------------------

DEFAULT_SAMPLE_SIZE = 100


def select_tests(truth: dict[str, dict], size: int) -> list[str]:
    """N test đầu tiên theo thứ tự tên, chỉ lấy test thực sự có file .java."""
    names = sorted(name for name in truth
                   if (TESTCODE_DIR / f"{name}.java").is_file())
    return names[:size] if size else names


# CUSTOM_SCAN_MODEL — model Metis dùng để QUÉT.
# Không có CUSTOM_SCAN_BASE_URL riêng trong .env: endpoint và key dùng chung tên
# CUSTOM_JUDGE_* (di sản từ week1) nhưng ở đây chúng phục vụ model QUÉT.
# CUSTOM_JUDGE_MODEL không còn cần — harness không có LLM-judge nữa.
ENV_KEYS = (
    "CUSTOM_SCAN_MODEL",
    "CUSTOM_JUDGE_BASE_URL",
    "CUSTOM_JUDGE_API_KEY",
)

# Metis chỉ có một rule SARIF (AI001) và ghi loại lỗ hổng vào properties.cwe dưới
# dạng chuỗi tự do do model sinh. Model thường trả một CWE họ hàng thay vì đúng
# con số Benchmark kỳ vọng, nên cần bảng chấp nhận tương đương.
CWE_ALIASES: dict[int, set[int]] = {
    89: {89, 564, 943},            # sqli
    78: {78, 77, 88},              # cmdi
    22: {22, 23, 36, 73},          # pathtraver
    79: {79, 80, 83},              # xss
    327: {327, 326, 328, 916},     # crypto
    328: {328, 327, 326, 916},     # hash
    330: {330, 335, 338},          # weakrand
    501: {501},                    # trustbound
    614: {614, 1004},              # securecookie
    90: {90},                      # ldapi
    643: {643},                    # xpathi
}


class BenchError(RuntimeError):
    """Lỗi khiến không thể tiếp tục."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# .env
# --------------------------------------------------------------------------


def parse_env_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise BenchError(f"Không tìm thấy file .env: {path}")
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def load_config() -> dict[str, str]:
    values = parse_env_file(ENV_FILE)
    missing = [k for k in ENV_KEYS if not values.get(k)]
    if missing:
        raise BenchError(
            "Thiếu (hoặc rỗng) trong .env: " + ", ".join(missing) + f"\n  file: {ENV_FILE}"
        )
    return {k: values[k] for k in ENV_KEYS}


# --------------------------------------------------------------------------
# metis.yaml
# --------------------------------------------------------------------------


def render_metis_yaml(cfg: dict[str, str], max_workers: int, max_rounds: int) -> str:
    """Sinh metis.yaml.

    `--config` THAY THẾ hoàn toàn config mặc định của Metis (configuration.py:261),
    không merge, nên file này phải tự đủ.

    API key không bao giờ được ghi ra đĩa: dùng `api_key_env` để Metis tự đọc từ
    biến môi trường (providers/config.py:102-107).

    Cố ý KHÔNG đặt `reachability_confirmation_model`: để Metis dùng đúng một
    model (scan model) cho cả review lẫn validate.

    json.dumps() dùng để quote chuỗi — YAML là superset của JSON nên luôn hợp lệ,
    và ta không cần thêm PyYAML làm dependency.
    """
    q = json.dumps
    return f"""# Sinh tự động bởi bench.py — mọi sửa tay sẽ bị ghi đè.
# API key KHÔNG nằm trong file này; Metis đọc từ biến môi trường CUSTOM_JUDGE_API_KEY.

llm_provider:
  name: "openai"
  model: {q(cfg["CUSTOM_SCAN_MODEL"])}
  base_url: {q(cfg["CUSTOM_JUDGE_BASE_URL"])}
  api_key_env: "CUSTOM_JUDGE_API_KEY"

metis_engine:
  max_token_length: 250000
  max_workers: {max_workers}
  llm_max_retries: 5
  triage_checkpoint_every: 50
  triage_tool_timeout_seconds: 30
  reachability_reasoning_effort: "medium"
  model_tools:
    max_rounds: {max_rounds}

memory:
  enabled: false

# Không khai báo embedding_provider: tool `index` bị tắt nên Metis không cần
# embeddings (configuration.py:138-142). Tránh phải nhúng cả 2740 file.

query:
  similarity_top_k: 5
  max_tokens: 5000
  temperature: 0.0
"""


# --------------------------------------------------------------------------
# Ground truth
# --------------------------------------------------------------------------


def load_ground_truth() -> dict[str, dict]:
    if not EXPECTED_CSV.is_file():
        raise BenchError(f"Không tìm thấy ground truth: {EXPECTED_CSV}")
    truth: dict[str, dict] = {}
    with EXPECTED_CSV.open(encoding="utf-8", newline="") as handle:
        for row in csv.reader(handle):
            if len(row) < 4 or row[0].lstrip().startswith("#"):
                continue
            try:
                cwe = int(row[3].strip())
            except ValueError:
                continue
            truth[row[0].strip()] = {
                "category": row[1].strip(),
                "expected": row[2].strip().lower() == "true",
                "cwe": cwe,
            }
    return truth


def accepted_cwes(cwe: int) -> set[int]:
    return CWE_ALIASES.get(cwe, set()) | {cwe}


def describe_sample(tests: list[str], truth: dict[str, dict]) -> str:
    """Bảng phân bố của tập test — để thấy độ lệch trước khi đốt tiền."""
    buckets: dict[str, list[int]] = {}
    for test in tests:
        info = truth[test]
        row = buckets.setdefault(info["category"], [0, 0])
        row[0 if info["expected"] else 1] += 1
    lines = [f"# Tập test: {len(tests)} test đầu tiên ({tests[0]} -> {tests[-1]})",
             f"#   {'category':<14}{'có lỗ hổng':>11}{'an toàn':>9}{'tổng':>7}"]
    for category in sorted(buckets, key=lambda c: (-sum(buckets[c]), c)):
        t, f = buckets[category]
        lines.append(f"#   {category:<14}{t:>11}{f:>9}{t + f:>7}")
    total_t = sum(v[0] for v in buckets.values())
    total_f = sum(v[1] for v in buckets.values())
    lines.append(f"#   {'TỔNG':<14}{total_t:>11}{total_f:>9}{total_t + total_f:>7}")
    if total_f and total_t / (total_t + total_f) > 0.6:
        lines.append(f"#   ! Lệch về phía có-lỗ-hổng ({total_t}/{total_t + total_f}). "
                     "FPR/precision dựa trên ít mẫu âm -> sai số lớn.")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Chạy Metis
# --------------------------------------------------------------------------


def metis_command(test: str, sarif_path: Path, json_path: Path, config_path: Path,
                  chroma_dir: Path, triage: bool) -> list[str]:
    java_file = TESTCODE_DIR / f"{test}.java"
    cmd = [
        "uv", "run", "--project", str(METIS_DIR), "metis",
        "--codebase-path", str(BENCH_DIR),
        "--config", str(config_path),
        "--chroma-dir", str(chroma_dir),
        "--tools", "navigation",
        "--log-level", "ERROR",
        "--non-interactive",
        # entry.py:283 tách chuỗi này bằng whitespace — đường dẫn không được có khoảng trắng.
        "--command", f"review_file {java_file}",
        "--output-file", str(sarif_path),
        "--output-file", str(json_path),
    ]
    if triage:
        cmd.append("--triage")
    return cmd


def run_signature(cfg: dict[str, str], triage: bool, max_rounds: int) -> dict:
    """Chữ ký cấu hình. Cache chỉ hợp lệ khi chữ ký khớp — đổi model hay tắt
    triage là kết quả cũ phải bị coi là hết hạn, không được dùng lại im lặng."""
    return {
        "scan_model": cfg["CUSTOM_SCAN_MODEL"],
        "base_url": cfg["CUSTOM_JUDGE_BASE_URL"],
        "triage": triage,
        "max_rounds": max_rounds,
    }


def work_dir_for(run_dir: Path, test: str) -> Path:
    """CWD riêng cho mỗi test.

    Hai lý do: (1) Metis ghi usage vào `results/metis_usage_*.json` TƯƠNG ĐỐI VỚI
    CWD (usage/runtime.py:143) — tách CWD là tách được token theo từng test;
    (2) chạy song song nhiều tiến trình Metis thì mỗi tiến trình cần chroma dir
    riêng, nếu không chúng ghi đè nhau.
    """
    return run_dir / ".work" / test


def run_metis(test: str, run_dir: Path, config_path: Path,
              env: dict[str, str], triage: bool, force: bool,
              signature: dict) -> dict:
    """Chạy một lần review. Trả về dict {sarif, wall_clock, usage}."""
    sarif_path = run_dir / f"{test}.sarif"
    json_path = run_dir / f"{test}.json"
    meta_path = run_dir / f"{test}.runmeta.json"
    log_path = run_dir / "logs" / f"{test}.log"
    work_dir = work_dir_for(run_dir, test)

    if sarif_path.is_file() and meta_path.is_file() and not force:
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            json.loads(sarif_path.read_text(encoding="utf-8"))
            if meta.get("signature") == signature:
                print(f"    [cache] {sarif_path.relative_to(ROOT)}")
                return {"sarif": sarif_path, "wall_clock": meta.get("wall_clock_seconds"),
                        "usage": meta.get("usage"), "cached": True}
            print("    [cache hết hạn: cấu hình đã đổi] chạy lại")
        except (json.JSONDecodeError, OSError):
            pass

    java_file = TESTCODE_DIR / f"{test}.java"
    if not java_file.is_file():
        raise BenchError(f"Không tìm thấy source: {java_file}")

    run_dir.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    sarif_path.unlink(missing_ok=True)
    meta_path.unlink(missing_ok=True)

    cmd = metis_command(test, sarif_path, json_path, config_path,
                        work_dir / ".chromadb", triage)
    start = time.monotonic()
    proc = subprocess.run(cmd, cwd=work_dir, env=env, capture_output=True, text=True)
    wall = round(time.monotonic() - start, 2)

    log_path.write_text(
        f"$ {' '.join(cmd)}\n  (cwd: {work_dir})\n\n"
        f"--- exit code: {proc.returncode} | wall-clock: {wall}s ---\n"
        f"\n--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n",
        encoding="utf-8",
    )

    # Metis trả exit 0 kể cả khi review_file bỏ qua file không tồn tại
    # (commands.py:90-92 return sớm, không ghi output). Không tin exit code —
    # kiểm tra sản phẩm thực tế.
    if proc.returncode != 0:
        raise BenchError(
            f"Metis thoát với mã {proc.returncode} cho {test}.\n"
            f"  log: {log_path}\n{_tail(proc.stderr or proc.stdout)}"
        )
    if not sarif_path.is_file():
        raise BenchError(
            f"Metis không ghi SARIF cho {test} (dù exit 0).\n"
            f"  log: {log_path}\n{_tail(proc.stdout + proc.stderr)}"
        )
    try:
        json.loads(sarif_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BenchError(f"SARIF hỏng cho {test}: {exc}\n  file: {sarif_path}") from exc

    usage = load_usage(work_dir / "results")
    meta_path.write_text(json.dumps({
        "signature": signature,
        "wall_clock_seconds": wall,
        "usage": usage,
        "ran_at": _utc_now(),
    }, indent=2), encoding="utf-8")

    # Đã rút hết thứ cần từ work_dir -> xoá, tránh để lại 100 thư mục chroma.
    # Chỉ xoá khi thành công; thất bại thì giữ lại để còn soi.
    shutil.rmtree(work_dir, ignore_errors=True)

    return {"sarif": sarif_path, "wall_clock": wall, "usage": usage, "cached": False}


def load_usage(results_dir: Path) -> dict | None:
    """Đọc file usage mới nhất `metis_usage_*.json` do Metis tự sinh."""
    if not results_dir.is_dir():
        return None
    files = sorted(results_dir.glob("metis_usage_*.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return None
    try:
        payload = json.loads(files[0].read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    totals = payload.get("totals") or {}
    duration = None
    started, ended = _parse_dt(payload.get("started_at")), _parse_dt(payload.get("ended_at"))
    if started and ended:
        duration = round((ended - started).total_seconds(), 2)
    return {
        "input_tokens": totals.get("input_tokens"),
        "output_tokens": totals.get("output_tokens"),
        "total_tokens": totals.get("total_tokens"),
        "duration_seconds": duration,
    }


def _parse_dt(value: object):
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _tail(text: str, lines: int = 15) -> str:
    kept = [ln for ln in (text or "").splitlines() if ln.strip()][-lines:]
    return "\n".join("  | " + ln for ln in kept)


# --------------------------------------------------------------------------
# Đọc SARIF
# --------------------------------------------------------------------------


def cwe_numbers(raw: object) -> list[int]:
    """Rút số CWE từ chuỗi tự do do model sinh (vd "CWE-89", "CWE-89/564").

    Trả list (không phải set) để payload còn serialize được sang JSON.
    """
    if not isinstance(raw, str):
        return []
    return sorted({int(n) for n in re.findall(r"\d{1,4}", raw)})


def extract_findings(sarif_path: Path) -> list[dict]:
    payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    findings: list[dict] = []
    for run in payload.get("runs") or []:
        for result in run.get("results") or []:
            props = result.get("properties") or {}
            line, snippet = 0, ""
            locations = result.get("locations") or []
            if locations:
                region = ((locations[0].get("physicalLocation") or {}).get("region") or {})
                try:
                    line = int(region.get("startLine") or 0)
                except (TypeError, ValueError):
                    line = 0
                snippet = str((region.get("snippet") or {}).get("text") or "")
            findings.append({
                "cwe_raw": props.get("cwe"),
                "cwes": cwe_numbers(props.get("cwe")),
                "severity": props.get("severity"),
                "confidence": props.get("confidence"),
                "reasoning": props.get("reasoning") or props.get("why"),
                "mitigation": props.get("mitigation"),
                # Không triage -> không có nhãn -> coi như tool vẫn khẳng định finding.
                "status": str(props.get("metisTriageStatus") or "valid").strip().lower(),
                "triaged": bool(props.get("metisTriaged")),
                "triage_reason": props.get("metisTriageReason"),
                "line": line,
                "snippet": snippet,
                "issue": str((result.get("message") or {}).get("text") or "").strip(),
            })
    return findings


# --------------------------------------------------------------------------
# Precision #3 — ground truth (thứ week1 không có)
# --------------------------------------------------------------------------


def score_run(findings: list[dict], truth: dict) -> dict:
    """Chấm một lần chạy của một test theo ground truth.

    Hai cột, khác nhau ở cách xử lý nhãn `inconclusive`
    (Metis triage trả valid/invalid/inconclusive — adjudication.py:40):
      strict : inconclusive = VẪN báo cáo (tool chưa loại bỏ)
      lenient: inconclusive = coi như đã loại
    """
    accepted = accepted_cwes(truth["cwe"])
    on_target = [f for f in findings if accepted.intersection(f["cwes"])]
    off_target = [f for f in findings if not accepted.intersection(f["cwes"])]

    reported_strict = any(f["status"] != "invalid" for f in on_target)
    reported_lenient = any(f["status"] == "valid" for f in on_target)

    return {
        "expected": truth["expected"],
        "strict": reported_strict,
        "lenient": reported_lenient,
        "outcome_strict": _outcome(truth["expected"], reported_strict),
        "outcome_lenient": _outcome(truth["expected"], reported_lenient),
        "on_target": len(on_target),
        "off_target": len([f for f in off_target if f["status"] != "invalid"]),
        "total": len(findings),
        "dismissed": len([f for f in findings if f["status"] == "invalid"]),
        "inconclusive": len([f for f in findings if f["status"] == "inconclusive"]),
        "findings": findings,
    }


def _outcome(expected: bool, reported: bool) -> str:
    if expected and reported:
        return "TP"
    if expected and not reported:
        return "FN"
    if not expected and reported:
        return "FP"
    return "TN"


def aggregate(outcomes: list[str]) -> dict:
    counts = {k: outcomes.count(k) for k in ("TP", "FP", "FN", "TN")}
    tp, fp, fn, tn = counts["TP"], counts["FP"], counts["FN"], counts["TN"]
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    return {**counts, "precision": precision, "recall": recall, "fpr": fpr,
            "youden": (recall - fpr) if (recall is not None and fpr is not None) else None}


# --------------------------------------------------------------------------
# Báo cáo
# --------------------------------------------------------------------------


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _metis_version() -> str:
    pyproject = METIS_DIR / "pyproject.toml"
    if pyproject.is_file():
        match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject.read_text(encoding="utf-8"), re.M)
        if match:
            return match.group(1)
    return "unknown"


def _git_sha(path: Path) -> str:
    try:
        proc = subprocess.run(["git", "-C", str(path), "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, timeout=10)
        if proc.returncode == 0:
            return proc.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "n/a"


def build_markdown(summary: dict, results: dict, truth: dict) -> str:
    lines: list[str] = []
    add = lines.append
    tok = summary["tokens"]
    gt = summary["ground_truth"]

    add("# Metis vs OWASP BenchmarkJava — scorecard")
    add("")
    add("| | |")
    add("|---|---|")
    add(f"| Thời điểm | {summary['generated_at']} |")
    add(f"| Scan model | `{summary['scan_model']}` |")
    add(f"| Metis | v{summary['metis_version']} (git {summary['metis_git']}) |")
    add(f"| Triage | {'bật' if summary['triage'] else 'TẮT'} |")
    add(f"| Số test × lặp | {len(results)} × {summary['repeat']} "
        f"= {len(results) * summary['repeat']} lần scan |")
    scanned = sorted(results)
    add(f"| Tập test | {len(scanned)} test: `{scanned[0]}` → `{scanned[-1]}` |")
    if summary.get("errors"):
        add(f"| Test lỗi | **{len(summary['errors'])}** (bị loại khỏi mọi phép tính) |")
    add("")

    add("## Chi phí")
    add("")
    add("| Chỉ số | Giá trị |")
    add("|---|---:|")
    add(f"| Findings (thô) | **{summary['total_findings']}** |")
    wall = summary.get("wall_clock_seconds")
    add(f"| Wall-clock | **{wall / 60:.1f} phút** ({wall:.0f}s) |" if wall else "| Wall-clock | n/a |")
    dur = summary.get("metis_duration_seconds")
    add(f"| Metis duration (native) | {dur / 60:.1f} phút |" if dur else "| Metis duration | n/a |")
    total_tok = tok.get("total_tokens")
    if total_tok:
        add(f"| Token | **{total_tok / 1e6:.2f}M** ({tok['input_tokens'] / 1e6:.2f}M in "
            f"/ {tok['output_tokens'] / 1e6:.3f}M out) |")
    else:
        add(f"| Token | n/a (source={tok.get('source')}) |")
    add("")

    add("## Precision / Recall (đối chiếu ground truth)")
    add("")
    add("| Chỉ số | strict | lenient |")
    add("|---|---:|---:|")
    for key in ("TP", "FP", "FN", "TN"):
        add(f"| {key} | {gt['strict'][key]} | {gt['lenient'][key]} |")
    add(f"| **Precision** | **{_pct(gt['strict']['precision'])}** "
        f"| **{_pct(gt['lenient']['precision'])}** |")
    add(f"| **Recall (TPR)** | **{_pct(gt['strict']['recall'])}** "
        f"| **{_pct(gt['lenient']['recall'])}** |")
    add(f"| FPR | {_pct(gt['strict']['fpr'])} | {_pct(gt['lenient']['fpr'])} |")
    add(f"| Youden (TPR−FPR) | {_pct(gt['strict']['youden'])} | {_pct(gt['lenient']['youden'])} |")
    add("")
    add("Đơn vị là **mỗi file test**, không phải mỗi finding: một file có 3 finding "
        "vẫn chỉ tính một TP. Finding off-target (CWE khác CWE kỳ vọng) không vào "
        "TP/FP, chỉ được đếm riêng như nhiễu.")
    add("")
    add("**strict** = `inconclusive` tính là *vẫn báo cáo* (thứ dev thực sự phải đọc). "
        "**lenient** = `inconclusive` tính là *đã loại* (kịch bản tốt nhất). "
        "Chênh lệch giữa hai cột = mức độ do dự của model.")
    add("")

    add("## Theo category")
    add("")
    add("| Category | Test | TP | FP | FN | TN | Recall | FPR | Youden |")
    add("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    by_category: dict[str, list[str]] = {}
    for test, runs in results.items():
        by_category.setdefault(truth[test]["category"], []).extend(
            r["outcome_strict"] for r in runs)
    for category in sorted(by_category, key=lambda c: (-len(by_category[c]), c)):
        agg = aggregate(by_category[category])
        n_tests = len({t for t in results if truth[t]["category"] == category})
        add(f"| {category} | {n_tests} | {agg['TP']} | {agg['FP']} | {agg['FN']} | {agg['TN']} "
            f"| {_pct(agg['recall'])} | {_pct(agg['fpr'])} | {_pct(agg['youden'])} |")
    add("")
    add("_Cột strict. Bảng đầy đủ từng test nằm trong `bench_summary.json` "
        "(`ground_truth.per_test`)._")
    add("")

    # Với cỡ mẫu lớn, liệt kê đủ 100 test là vô dụng — chỉ những ca SAI mới đáng đọc.
    mismatches = [(test, run) for test, runs in results.items() for run in runs
                  if run["outcome_strict"] not in ("TP", "TN")]
    add(f"## Ca sai ({len(mismatches)})")
    add("")
    if not mismatches:
        add("_Không có. Mọi test đều khớp ground truth ở cột strict._")
    else:
        add("| Test | Loại | CWE | Ground truth | run | strict | lenient | on-target | do dự |")
        add("|---|---|---|---|---:|---|---|---:|---:|")
        for test, run in mismatches:
            info = truth[test]
            add(f"| `{test}` | {info['category']} | {info['cwe']} "
                f"| {'có lỗ hổng' if info['expected'] else 'an toàn'} | {run['run']} "
                f"| **{run['outcome_strict']}** | {run['outcome_lenient']} "
                f"| {run['on_target']} | {run['inconclusive']} |")
        add("")
        add("**FN** = bỏ sót lỗ hổng thật. **FP** = báo nhầm trên file an toàn.")
    add("")

    errors = summary.get("errors") or []
    if errors:
        add(f"## Test chạy lỗi ({len(errors)})")
        add("")
        add("| Test | run | Lỗi |")
        add("|---|---:|---|")
        for err in errors:
            add(f"| `{err['test']}` | {err['run']} | {err['error'][:160]} |")
        add("")
        add("_Các test này bị loại khỏi mọi phép tính ở trên._")
        add("")

    add("## Độ ổn định")
    add("")
    if summary["repeat"] < 2:
        add("_Chạy 1 lần — không đo được. Dùng `--repeat 3` để đánh giá._")
    else:
        unstable = [(t, runs) for t, runs in results.items()
                    if len({r["outcome_strict"] for r in runs}) > 1
                    or len({r["outcome_lenient"] for r in runs}) > 1]
        add(f"{len(results) - len(unstable)}/{len(results)} test cho kết quả nhất quán "
            f"qua {summary['repeat']} lần chạy.")
        add("")
        if unstable:
            add("| Test | strict | lenient |")
            add("|---|---|---|")
            for test, runs in unstable:
                add(f"| `{test}` | {'/'.join(r['outcome_strict'] for r in runs)} "
                    f"| {'/'.join(r['outcome_lenient'] for r in runs)} |")
    add("")

    add("## Chi tiết finding (chỉ các ca sai)")
    add("")
    if not mismatches:
        add("_Không có ca sai nào._")
    for test in dict.fromkeys(t for t, _ in mismatches):
        add(f"### `{test}` — {truth[test]['category']}, CWE-{truth[test]['cwe']}, "
            f"{'có lỗ hổng' if truth[test]['expected'] else 'an toàn'}")
        add("")
        any_finding = False
        for run in results[test]:
            for finding in run["findings"]:
                any_finding = True
                matched = accepted_cwes(truth[test]["cwe"]).intersection(finding["cwes"])
                add(f"- **run {run['run']}** · dòng {finding['line']} · CWE `{finding['cwe_raw']}` "
                    f"({'on-target' if matched else 'off-target'}) · severity `{finding['severity']}` "
                    f"· triage **{finding['status']}**")
                if finding["issue"]:
                    add(f"  - {finding['issue']}")
                if finding.get("triage_reason"):
                    add(f"  - _triage:_ {finding['triage_reason']}")
        if not any_finding:
            add("_Metis không báo finding nào cho file này._")
        add("")

    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Quét OWASP BenchmarkJava bằng Metis, đo token/thời gian và chấm "
                    "precision/recall theo ground truth.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--tag", default="baseline", metavar="TÊN",
                        help="Tên cấu hình; kết quả vào results/<TÊN>/ (mặc định baseline).")
    parser.add_argument("--sample", type=int, default=DEFAULT_SAMPLE_SIZE, metavar="N",
                        help=f"Quét N test ĐẦU TIÊN theo thứ tự tên "
                             f"(mặc định {DEFAULT_SAMPLE_SIZE}; 0 = toàn bộ 2740 test).")
    parser.add_argument("--parallel", type=int, default=4, metavar="N",
                        help="Số tiến trình Metis chạy song song (mặc định 4).")
    parser.add_argument("--max-failures", type=int, default=10, metavar="N",
                        help="Dừng khi số test lỗi vượt ngưỡng này (mặc định 10).")
    parser.add_argument("--repeat", type=int, default=1, metavar="N",
                        help="Số lần chạy lại mỗi test để đo độ ổn định (mặc định 1).")
    parser.add_argument("--only", action="append", metavar="SUB",
                        help="Chỉ chạy test có tên chứa chuỗi này. Lặp lại được.")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Không hỏi xác nhận trước khi chạy mẻ lớn.")
    parser.add_argument("--no-triage", action="store_true",
                        help="Tắt khâu triage của Metis (bẫy FP sẽ mất ý nghĩa).")
    parser.add_argument("--force", action="store_true",
                        help="Bỏ qua cache, chạy lại từ đầu.")
    parser.add_argument("--dry-run", action="store_true",
                        help="In metis.yaml và các lệnh sẽ chạy rồi thoát. Không gọi LLM.")
    parser.add_argument("--rescore", action="store_true",
                        help="Chỉ chấm lại từ SARIF đã có, không gọi Metis.")
    parser.add_argument("--max-workers", type=int, default=2, metavar="N",
                        help="metis_engine.max_workers (mặc định 2).")
    parser.add_argument("--max-rounds", type=int, default=6, metavar="N",
                        help="metis_engine.model_tools.max_rounds (mặc định 6).")
    parser.add_argument("--out", type=Path, default=None, metavar="FILE",
                        help="Đường dẫn bench_summary.json (mặc định trong thư mục tag).")
    args = parser.parse_args()

    if args.repeat < 1:
        raise BenchError("--repeat phải >= 1")
    if args.parallel < 1:
        raise BenchError("--parallel phải >= 1")

    triage = not args.no_triage
    cfg = load_config()
    truth = load_ground_truth()

    tests = select_tests(truth, args.sample)
    if not tests:
        raise BenchError("Không tìm thấy test nào có file .java.")
    if args.only:
        filtered = [t for t in tests if any(sub in t for sub in args.only)]
        if not filtered:
            raise BenchError(f"--only {args.only} không khớp test nào trong "
                             f"{len(tests)} test đầu tiên ({tests[0]} -> {tests[-1]}).")
        tests = filtered

    unknown = [t for t in tests if t not in truth]
    if unknown:
        raise BenchError(f"Không có ground truth cho: {', '.join(unknown)}")
    if not shutil.which("uv"):
        raise BenchError("Không tìm thấy `uv` trong PATH.")
    if not (METIS_DIR / "pyproject.toml").is_file():
        raise BenchError(f"Không tìm thấy project Metis tại {METIS_DIR}")
    # entry.py:283 tách --command bằng whitespace.
    if " " in str(TESTCODE_DIR):
        raise BenchError(f"Đường dẫn source có khoảng trắng, Metis sẽ parse sai:\n  {TESTCODE_DIR}")

    out_dir = RESULTS_ROOT / args.tag
    out_dir.mkdir(parents=True, exist_ok=True)
    config_path = out_dir / "metis.yaml"
    summary_path = args.out or (out_dir / "bench_summary.json")
    yaml_text = render_metis_yaml(cfg, args.max_workers, args.max_rounds)
    signature = run_signature(cfg, triage, args.max_rounds)
    total_scans = len(tests) * args.repeat

    if args.dry_run:
        print(f"# metis.yaml sẽ được ghi vào {config_path}")
        print("# (không chứa API key — Metis đọc từ biến môi trường)\n")
        print(yaml_text)
        print(describe_sample(tests, truth))
        example = tests[0]
        run_dir = out_dir / "run1"
        print("\n# Lệnh mẫu (test đầu tiên):\n")
        print(f"  (cwd: {work_dir_for(run_dir, example)})")
        print("  " + " ".join(metis_command(
            example, run_dir / f"{example}.sarif", run_dir / f"{example}.json",
            config_path, work_dir_for(run_dir, example) / ".chromadb", triage)) + "\n")
        print(f"# Tổng: {total_scans} lần gọi review_file "
              f"({len(tests)} test × {args.repeat} lần), {args.parallel} tiến trình song song.")
        print(f"# Summary sẽ ghi vào: {summary_path}")
        return 0

    if total_scans > 20 and not args.yes and not args.rescore and sys.stdin.isatty():
        print(describe_sample(tests, truth))
        answer = input(f"\n{total_scans} lần gọi Metis. Tiếp tục? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Đã huỷ.")
            return 0

    if not args.rescore:
        config_path.write_text(yaml_text, encoding="utf-8")

    env = os.environ.copy()
    env.update(cfg)

    results: dict[str, list[dict]] = {t: [] for t in tests}
    errors: list[dict] = []
    wall_total = 0.0
    metis_duration_total = 0.0
    tokens = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    usage_seen = False

    def load_cached(test: str, run_dir: Path) -> dict:
        sarif_path = run_dir / f"{test}.sarif"
        if not sarif_path.is_file():
            raise BenchError(f"--rescore nhưng thiếu {sarif_path}")
        meta_path = run_dir / f"{test}.runmeta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.is_file() else {}
        return {"sarif": sarif_path, "wall_clock": meta.get("wall_clock_seconds"),
                "usage": meta.get("usage")}

    def execute(job: tuple[int, str]) -> tuple[int, str, dict | None, str | None]:
        run_idx, test = job
        run_dir = out_dir / f"run{run_idx}"
        try:
            if args.rescore:
                return run_idx, test, load_cached(test, run_dir), None
            return run_idx, test, run_metis(test, run_dir, config_path, env,
                                            triage, args.force, signature), None
        except BenchError as exc:
            return run_idx, test, None, str(exc)

    def absorb(run_idx: int, test: str, outcome: dict) -> dict:
        nonlocal wall_total, metis_duration_total, usage_seen
        wall_total += outcome.get("wall_clock") or 0.0
        usage = outcome.get("usage") or {}
        if usage.get("total_tokens"):
            usage_seen = True
            for key in tokens:
                tokens[key] += usage.get(key) or 0
            metis_duration_total += usage.get("duration_seconds") or 0.0
        scored = score_run(extract_findings(outcome["sarif"]), truth[test])
        scored["run"] = run_idx
        results[test].append(scored)
        return scored

    jobs = [(run_idx, test) for run_idx in range(1, args.repeat + 1) for test in tests]

    # Job đầu chạy đơn lẻ và fail-fast: sai key/base_url/model thì lộ ngay,
    # không đốt 100 lần gọi rồi mới báo. Từ job thứ hai trở đi mới song song và
    # chịu lỗi — ở cỡ 100 file, một lỗi mạng lẻ tẻ không được phép giết cả mẻ.
    first_run, first_test = jobs[0]
    print(f"[1/{len(jobs)}] {first_test} (smoke) ...", flush=True)
    _, _, outcome, error = execute(jobs[0])
    if error:
        raise BenchError(f"Smoke test thất bại — dừng trước khi chạy {len(jobs) - 1} "
                         f"lần còn lại.\n{error}")
    scored = absorb(first_run, first_test, outcome)
    print(f"    -> strict={scored['outcome_strict']}  lenient={scored['outcome_lenient']}"
          f"  ({scored['total']} finding)")

    rest = jobs[1:]
    if rest:
        print(f"\nChạy {len(rest)} lần còn lại, {args.parallel} tiến trình song song ...")
        done = 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as pool:
            futures = [pool.submit(execute, job) for job in rest]
            try:
                for future in concurrent.futures.as_completed(futures):
                    run_idx, test, outcome, error = future.result()
                    done += 1
                    if error:
                        errors.append({"test": test, "run": run_idx, "error": error})
                        print(f"[{done}/{len(jobs)}] {test} LỖI: {error.splitlines()[0]}",
                              file=sys.stderr, flush=True)
                        if len(errors) > args.max_failures:
                            for pending in futures:
                                pending.cancel()
                            raise BenchError(
                                f"Quá {args.max_failures} test lỗi — dừng. "
                                f"Xem log trong {out_dir}/run*/logs/.")
                        continue
                    scored = absorb(run_idx, test, outcome)
                    print(f"[{done}/{len(jobs)}] {test} "
                          f"{scored['outcome_strict']}/{scored['outcome_lenient']} "
                          f"({scored['total']} finding)", flush=True)
            except KeyboardInterrupt:
                for pending in futures:
                    pending.cancel()
                raise

    # Test lỗi hoàn toàn (không lần chạy nào thành công) bị loại khỏi mọi phép tính.
    dropped = [t for t in tests if not results[t]]
    for test in dropped:
        del results[test]
    if dropped:
        print(f"\n! {len(dropped)} test không có kết quả nào, đã loại: "
              f"{', '.join(dropped[:5])}{' ...' if len(dropped) > 5 else ''}",
              file=sys.stderr)
    if not results:
        raise BenchError("Không test nào chạy thành công.")

    all_findings = [f for runs in results.values() for r in runs for f in r["findings"]]

    # --- tổng hợp ---
    gt_strict = aggregate([r["outcome_strict"] for runs in results.values() for r in runs])
    gt_lenient = aggregate([r["outcome_lenient"] for runs in results.values() for r in runs])

    summary = {
        "generated_at": _utc_now(),
        "tag": args.tag,
        "scan_model": cfg["CUSTOM_SCAN_MODEL"],
        "base_url": cfg["CUSTOM_JUDGE_BASE_URL"],
        "metis_version": _metis_version(),
        "metis_git": _git_sha(METIS_DIR),
        "triage": triage,
        "max_rounds": args.max_rounds,
        "max_workers": args.max_workers,
        "parallel": args.parallel,
        "repeat": args.repeat,
        "sample_size": args.sample,
        "selection": "first-N-by-name",
        "tests": sorted(results),
        "errors": errors,
        "total_findings": len(all_findings),
        "wall_clock_seconds": round(wall_total, 2) if wall_total else None,
        "metis_duration_seconds": round(metis_duration_total, 2) if metis_duration_total else None,
        "tokens": ({"source": "metis_native", **tokens} if usage_seen
                   else {"source": "unavailable",
                         "note": "Metis không xuất metis_usage_*.json"}),
        "ground_truth": {
            "source": EXPECTED_CSV.name,
            "strict": gt_strict,
            "lenient": gt_lenient,
            "per_test": {
                test: {
                    "category": truth[test]["category"],
                    "cwe": truth[test]["cwe"],
                    "expected_vulnerable": truth[test]["expected"],
                    "runs": [{k: v for k, v in r.items() if k != "findings"} for r in runs],
                }
                for test, runs in results.items()
            },
        },
        "findings": {
            test: [{"run": r["run"], **{k: v for k, v in f.items()}} for r in runs
                   for f in r["findings"]]
            for test, runs in results.items()
        },
    }

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "scorecard.md").write_text(build_markdown(summary, results, truth), encoding="utf-8")

    tok = summary["tokens"]
    print(f"\nFindings: {summary['total_findings']}")
    if wall_total:
        print(f"Wall-clock: {wall_total / 60:.1f} phút")
    if tok.get("total_tokens"):
        print(f"Token: {tok['total_tokens']:,} (in={tok['input_tokens']:,} out={tok['output_tokens']:,})")
    print(f"Precision: strict={_pct(gt_strict['precision'])} "
          f"lenient={_pct(gt_lenient['precision'])}")
    print(f"Recall:    strict={_pct(gt_strict['recall'])} "
          f"lenient={_pct(gt_lenient['recall'])}")
    print(f"\nSummary:   {summary_path}")
    print(f"Scorecard: {out_dir / 'scorecard.md'}")

    mismatched = [(test, r["run"], r["outcome_strict"])
                  for test, runs in results.items() for r in runs
                  if r["outcome_strict"] not in ("TP", "TN")]
    if mismatched:
        print("\nKhông khớp ground truth (cột strict):")
        for test, run_idx, outcome in mismatched:
            print(f"  - {test} run{run_idx}: {outcome}")
        return 1
    print("\nTất cả khớp ground truth (cột strict).")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BenchError as exc:
        print(f"\nLỗi: {exc}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\nĐã huỷ.", file=sys.stderr)
        sys.exit(130)
