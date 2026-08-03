#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""So sánh các KIẾN TRÚC discovery khác nhau trên cùng tập BenchmarkJava.

`sweep.py` chỉ vặn nút hiệu năng *bên trong* một kiến trúc cố định
(harness + prompt) và đã chạm diminishing returns. Script này hỏi câu khác:
hiệu suất đến từ **LLM reasoning trong agent loop** hay từ **static analysis**,
và cái nào cho ROI tốt hơn trên mỗi token?

  A prompt_only  --tools none,       không --triage, review_code
  B harness      --tools navigation, --triage,       review_code
  C static       Semgrep -> metis --command "triage <sarif>"  (LLM chỉ verify)
  B_union_C      gộp OFFLINE SARIF của B và C — dẫn xuất, không gọi LLM

Từng có arm D (harness + AST) nhưng đã bỏ: `tree_sitter` trong Metis là
`status: planned`, không có `implementation:`, nên `--tools tree_sitter` bị
`parse_engine_tools` từ chối. Tool active duy nhất còn lại là `index`, mà nó
cần embedding — router hiện tại không phục vụ embeddings.

Chấm điểm bằng ground truth (expectedresults-1.2.csv) — không LLM-judge, nhất
quán với bench.py/sweep.py. Tái dùng trực tiếp động cơ đã kiểm chứng của
bench.py (load_config, load_ground_truth, select_tests, score_run, aggregate,
load_usage, cwe_numbers, BenchError...) bằng cách import thẳng nó làm module.

  ./scripts/ablation.py                    # 3 arm × 100 test — TỐN KÉM, sẽ hỏi xác nhận
  ./scripts/ablation.py --dry-run          # in lệnh sẽ chạy (kể cả Semgrep), không gọi LLM
  ./scripts/ablation.py --only harness static
  ./scripts/ablation.py --sample 6 -y      # smoke rẻ trước khi đốt tiền
  ./scripts/ablation.py --rescore          # chỉ chấm lại từ SARIF đã có

Arm chạy TUẦN TỰ: mỗi arm đã tự dùng max_workers riêng bên trong, chạy song
song sẽ làm méo phép đo wall-clock (tranh chấp rate-limit giữa các arm).
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

OUT_DIR = bm.ROOT / "data" / "results" / "ablation"
DEFAULT_SAMPLE_SIZE = 100

# Ruleset Semgrep cho arm `static`. Đổi giá trị này là chữ ký cache của arm
# dùng Semgrep hết hạn (xem arm_signature) — không có chuyện dùng lại im lặng
# kết quả quét bằng ruleset khác.
SEMGREP_RULESETS: list[str] = [
    "p/java",
    "p/owasp-top-ten",
    str(bm.ROOT / "data" / "rules" / "benchmarkjava"),
]

# Semgrep phải tải rule từ registry qua mạng -> hỏng nhất thời là chuyện thường.
# KHÔNG đưa hai hằng này vào arm_signature: số lần thử lại không làm đổi kết
# quả phép quét, chỉ đổi xác suất lấy được nó.
SEMGREP_ATTEMPTS = 3
SEMGREP_RETRY_SLEEP = 5.0

# Bump khi sửa logic rút CWE trong normalize_semgrep_sarif — nó nằm trong chữ ký
# cache, nên bump là mọi kết quả arm C cũ hết hạn thay vì được dùng lại kèm CWE sai.
NORMALIZER_VERSION = 2

# Arm dẫn xuất: gộp offline finding của `harness` và `static`. Metis CLI không
# có đường nạp seed finding từ SAST ngoài vào `review_code`, nên phép "hai cơ
# chế bổ sung cho nhau" chỉ đo được bằng cách gộp hai SARIF đã có.
UNION_ARM = "B_union_C"
UNION_SOURCES = ("harness", "static")

# --------------------------------------------------------------------------
# Ma trận thí nghiệm — MỘT CHỖ DUY NHẤT định nghĩa các arm.
#
#   tools   : giá trị cho --tools (None = không truyền cờ, Metis dùng default)
#   command : giá trị cho --command; "triage" là template, đường dẫn SARIF
#             được điền lúc chạy (run_arm)
#   triage  : có thêm cờ --triage hay không (chỉ có nghĩa với lệnh review_*)
#   engine  : "metis" | "semgrep+metis" — quyết định nhánh nào của run_arm
#   note    : mô tả ngắn, in ra báo cáo
#
# BASE_ENGINE giữ NGUYÊN giá trị của sweep.py:58-67 để arm `harness` đúng bằng
# variant `baseline` của sweep — nếu lệch, phép kiểm chứng chéo (GT-precision/
# recall của hai script phải khớp) mất ý nghĩa.
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

ARMS: dict[str, dict] = {
    "prompt_only": {
        "tools": "none",
        "command": "review_code",
        "triage": False,
        "engine": "metis",
        "note": "A — LLM trần, không tool, không triage (sàn dưới)",
    },
    "harness": {
        "tools": "navigation",
        "command": "review_code",
        "triage": True,
        "engine": "metis",
        "note": "B — harness đầy đủ (= baseline sweep)",
    },
    "static": {
        # Lệnh `triage` không dùng model_tool để tìm kiếm như review_code, nhưng
        # vẫn chạy qua cùng engine — truyền navigation cho khớp default của
        # Metis và để chữ ký cache ghi rõ ràng thay vì "không biết".
        "tools": "navigation",
        "command": "triage",
        "triage": False,
        "engine": "semgrep+metis",
        "note": "C — Semgrep tìm, LLM chỉ verify",
    },
}

ARM_NOTES: dict[str, str] = {name: spec["note"] for name, spec in ARMS.items()}
ARM_NOTES[UNION_ARM] = ("dẫn xuất — gộp offline SARIF của "
                        f"`{UNION_SOURCES[0]}` ∪ `{UNION_SOURCES[1]}`")

# Thứ tự "tốt nhất -> tệ nhất" khi hai finding cùng (test, cwe) gặp nhau lúc
# gộp union: giữ lại nhãn nào KHẲNG ĐỊNH finding mạnh nhất. Union là phép hợp
# của hai cơ chế phát hiện, nên một bên nói "valid" thì union nói "valid".
STATUS_RANK = {"valid": 0, "inconclusive": 1, "invalid": 2}


# --------------------------------------------------------------------------
# metis.yaml cho từng arm
# --------------------------------------------------------------------------


# Cố tình KHÔNG có deep_merge/engine-override như sweep.py: mọi arm phải dùng
# chung một BASE_ENGINE. Thêm một nút cấu hình cấp YAML vào đây là mở đường cho
# đúng cái confound mà thí nghiệm này tồn tại để loại bỏ — khi đó không còn biết
# chênh lệch đến từ KIẾN TRÚC hay từ tham số.


def render_arm_yaml(cfg: dict[str, str], include_paths: list[str]) -> str:
    """Sinh metis.yaml cho một arm.

    Mọi arm dùng CHUNG một metis_engine (BASE_ENGINE): điểm khác nhau giữa các
    arm nằm ở cờ CLI (--tools / --command / --triage), không nằm trong YAML.
    Đó chính là điều kiện để phép thí nghiệm cô lập đúng biến "cơ chế
    discovery" thay vì trộn lẫn với nút hiệu năng mà sweep.py đã đo.

    Dùng json.dumps() cho TOÀN BỘ nội dung: JSON là tập con hợp lệ của YAML,
    kể cả object/array lồng nhau, nên không cần PyYAML.
    """
    engine = copy.deepcopy(BASE_ENGINE)
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
        "# Sinh tự động bởi ablation.py — mọi sửa tay sẽ bị ghi đè.\n"
        "# API key KHÔNG nằm trong file này; Metis đọc từ biến môi trường "
        "OPENCODE_API_KEY.\n"
        + json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    )


def include_paths_for(test_names: list[str]) -> list[str]:
    """review_code_include_paths là mẫu gitignore-style, TƯƠNG ĐỐI so với
    codebase-path (repository.py:161-164) — đường dẫn đủ (có "/") nên được coi
    là neo từ gốc, khớp CHÍNH XÁC file đó, không khớp nhầm file khác."""
    return [rel_java_path(name) for name in test_names]


def rel_java_path(test: str) -> str:
    return (bm.TESTCODE_DIR / f"{test}.java").relative_to(bm.BENCH_DIR).as_posix()


# --------------------------------------------------------------------------
# Lệnh + chữ ký cache
# --------------------------------------------------------------------------


def arm_command(spec: dict, config_path: Path, chroma_dir: Path,
                sarif_path: Path, json_path: Path | None,
                command_text: str | None = None) -> list[str]:
    """Lệnh Metis cho một arm.

    Khác sweep.py:164-178 (hardcode `--tools navigation` / `review_code` /
    `--triage`), ở đây cả ba đều lấy từ ARMS — đó là toàn bộ biến độc lập của
    thí nghiệm này.
    """
    cmd = [
        "uv", "run", "--project", str(bm.METIS_DIR), "metis",
        "--codebase-path", str(bm.BENCH_DIR),
        "--config", str(config_path),
        "--chroma-dir", str(chroma_dir),
    ]
    if spec.get("tools") is not None:
        cmd += ["--tools", str(spec["tools"])]
    cmd += [
        "--log-level", "ERROR",
        "--non-interactive",
        # entry.py:283 tách chuỗi này bằng whitespace — đường dẫn không được
        # có khoảng trắng (guard trong main()).
        "--command", command_text or str(spec["command"]),
        "--output-file", str(sarif_path),
    ]
    if json_path is not None:
        cmd += ["--output-file", str(json_path)]
    if spec.get("triage"):
        cmd.append("--triage")
    return cmd


def assert_local_semgrep_configs() -> None:
    """Nổ sớm nếu path ruleset local thiếu YAML (tránh Semgrep exit 0 + FN im lặng)."""
    for ruleset in SEMGREP_RULESETS:
        path = Path(ruleset)
        if not path.is_absolute() and not path.exists():
            # Registry packs (`p/java`, …) không phải path trên đĩa.
            continue
        if not path.is_dir():
            if path.is_absolute() or path.exists():
                raise bm.BenchError(
                    f"Ruleset Semgrep local không phải thư mục: {path}")
            continue
        yamls = list(path.glob("*.yaml")) + list(path.glob("*.yml"))
        if not yamls:
            raise bm.BenchError(
                f"Ruleset Semgrep local rỗng (không có *.yaml/*.yml): {path}")


def semgrep_command(sarif_out: Path, test_names: list[str]) -> list[str]:
    """Lệnh Semgrep, chạy với cwd=BENCH_DIR.

    Target là danh sách đường dẫn TƯƠNG ĐỐI của đúng các file trong scope: vừa
    giới hạn phép quét đúng tập test (không quét cả 2740 file), vừa khiến
    artifactLocation.uri trong SARIF trùng khớp với --codebase-path mà Metis
    dùng ở các arm khác — nhờ vậy extract_findings_by_test() tách được theo
    tên test y hệt nhau cho mọi arm.
    """
    assert_local_semgrep_configs()
    cmd = ["semgrep", "scan", "--sarif", "--output", str(sarif_out),
           "--metrics=off", "--quiet", "--no-git-ignore", "--disable-version-check"]
    for ruleset in SEMGREP_RULESETS:
        cmd += ["--config", ruleset]
    cmd += [rel_java_path(name) for name in test_names]
    return cmd


def uses_semgrep(spec: dict) -> bool:
    return "semgrep" in str(spec.get("engine", ""))


def _semgrep_version() -> str:
    """Version của binary semgrep, để đưa vào chữ ký cache. 'unknown' nếu không hỏi được."""
    try:
        proc = subprocess.run(["semgrep", "--version"], capture_output=True,
                              text=True, timeout=30)
        return (proc.stdout or "").strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def arm_signature(cfg: dict[str, str], spec: dict, test_names: list[str]) -> dict:
    """Chữ ký cấu hình. Cache chỉ hợp lệ khi chữ ký khớp.

    So với sweep.py:146-156, chữ ký này BẮT BUỘC gồm thêm `tools`/`command`/
    `triage` + ruleset Semgrep: đó chính là các biến phân biệt các arm. Bê
    nguyên chữ ký của sweep sang đây thì mọi arm có chữ ký GIỐNG HỆT nhau
    và arm thứ hai trở đi sẽ lặng lẽ đọc cache của arm đầu — sai kết quả mà
    không có lấy một dòng cảnh báo.
    """
    tests_digest = hashlib.sha256(",".join(sorted(test_names)).encode()).hexdigest()[:16]
    return {
        # Ba thứ dưới đây ĐỔI KẾT QUẢ nhưng trước đó không có trong chữ ký:
        #  - metis version/commit: `git -C metis pull` giữa hai arm là bảng lặng
        #    lẽ trộn hai phiên bản engine mà mọi arm vẫn in [cache].
        #  - semgrep version: 560 rule tải từ registry, drift độc lập với tên pool.
        #  - NORMALIZER_VERSION: cache của arm C lưu triaged.sarif, mà CWE trong
        #    đó do normalize_semgrep_sarif sinh ra. Sửa bug rút CWE rồi chạy lại
        #    -> [cache] và báo cáo lại đúng các CWE sai cũ. Bump hằng này khi sửa
        #    logic rút CWE.
        "metis_version": bm._metis_version(),
        "metis_git": bm._git_sha(bm.METIS_DIR),
        "semgrep_version": _semgrep_version() if uses_semgrep(spec) else None,
        "normalizer_version": NORMALIZER_VERSION,
        "scan_model": cfg["CUSTOM_SCAN_MODEL"],
        "base_url": cfg["OPENCODE_BASE_URL"],
        "engine": spec.get("engine"),
        "tools": spec.get("tools"),
        "command": spec.get("command"),
        "triage": bool(spec.get("triage")),
        # Chỉ arm dùng Semgrep mới phụ thuộc ruleset — đưa vào chữ ký của arm
        # thuần-LLM sẽ làm chúng hết hạn oan mỗi lần đổi ruleset.
        "semgrep_rulesets": list(SEMGREP_RULESETS) if uses_semgrep(spec) else None,
        "base_engine": BASE_ENGINE,
        "tests_digest": tests_digest,
    }


# --------------------------------------------------------------------------
# Semgrep: quét + chuẩn hoá CWE
# --------------------------------------------------------------------------


def run_semgrep(arm_dir: Path, test_names: list[str], env: dict[str, str]) -> tuple[Path, float]:
    """Quét Semgrep, ghi `semgrep.raw.sarif`. Trả (đường dẫn, wall-clock giây).

    File raw KHÔNG BAO GIỜ bị ghi đè bởi khâu chuẩn hoá hay triage phía sau —
    nó là bằng chứng gốc để đối chiếu khi nghi kết quả sai.
    """
    raw_path = arm_dir / "semgrep.raw.sarif"
    log_path = arm_dir / "semgrep.log"

    cmd = semgrep_command(raw_path, test_names)
    print(f"    $ semgrep scan --config {' --config '.join(SEMGREP_RULESETS)} "
          f"... ({len(test_names)} file)", flush=True)

    # Semgrep tải ~560 rule từ registry qua MẠNG trước khi quét, nên hỏng nhất
    # thời là chuyện bình thường: đã gặp một lần exit 2 sau 98s với stdout/stderr
    # RỖNG SẠCH (vì --quiet), rồi cùng lệnh y hệt chạy lại thành công ngay.
    # Để một arm chết vì cái đó là mất cả run 2 tiếng của các arm trước.
    # wall = thời gian của lần thử THÀNH CÔNG, không cộng dồn các lần hỏng: cột
    # "Phút" dùng để so chi phí KIẾN TRÚC giữa các arm, nhét thời gian treo mạng
    # vào đó là đổ lỗi network lên đầu arm static.
    wall = 0.0
    proc = None
    log_path.write_text(
        f"$ {' '.join(cmd[:12])} ... ({len(test_names)} target)\n"
        f"  (cwd: {bm.BENCH_DIR})\n",
        encoding="utf-8",
    )
    for attempt in range(1, SEMGREP_ATTEMPTS + 1):
        raw_path.unlink(missing_ok=True)
        start = time.monotonic()
        proc = subprocess.run(cmd, cwd=bm.BENCH_DIR, env=env,
                              capture_output=True, text=True)
        wall = round(time.monotonic() - start, 2)

        # APPEND, không ghi đè: bằng chứng của lần hỏng là đúng thứ mà vòng retry
        # tồn tại để giải thích. Ghi đè nó là xoá mất lý do phải retry.
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(
                f"\n=== lần thử {attempt}/{SEMGREP_ATTEMPTS} ===\n"
                f"--- exit code: {proc.returncode} | wall-clock: {wall}s ---\n"
                f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n"
            )
        if proc.returncode == 0 and raw_path.is_file():
            break
        if attempt < SEMGREP_ATTEMPTS:
            print(f"      Semgrep exit {proc.returncode} — thử lại "
                  f"({attempt + 1}/{SEMGREP_ATTEMPTS})", flush=True)
            time.sleep(SEMGREP_RETRY_SLEEP)

    if proc.returncode != 0:
        raise bm.BenchError(
            f"Semgrep thoát với mã {proc.returncode} sau {SEMGREP_ATTEMPTS} lần thử.\n"
            f"  log: {log_path}\n{bm._tail(proc.stderr or proc.stdout)}"
        )
    if not raw_path.is_file():
        raise bm.BenchError(
            f"Semgrep không ghi SARIF (dù exit 0).\n"
            f"  log: {log_path}\n{bm._tail(proc.stdout + proc.stderr)}"
        )
    try:
        json.loads(raw_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise bm.BenchError(f"SARIF Semgrep hỏng: {exc}\n  file: {raw_path}") from exc

    return raw_path, wall


def normalize_semgrep_sarif(raw_path: Path, out_path: Path) -> dict:
    """Bơm `result.properties.cwe` vào SARIF Semgrep, ghi ra file MỚI.

    Semgrep để `result.properties` RỖNG; CWE nằm ở
    `runs[].tool.driver.rules[].properties.tags` dưới dạng chuỗi dài kiểu
    "CWE-22: Improper Limitation of a Pathname ... ('Path Traversal')".
    Nối result với rule qua `result.ruleId` == `rule.id`.

    Phải rút CHUỖI NGẮN "CWE-22", không nhét cả tag: bm.cwe_numbers() chạy
    re.findall(r"\\d{1,4}") nên cả tag sẽ kéo theo mọi con số trong phần mô tả
    (vd "A01:2021" -> 1, 2021) và biến finding on-target thành rác. Và phải là
    `str`: cwe_numbers() trả [] ngay lập tức nếu input là list.

    Thiếu bước này arm C ra đúng 0 on-target — mọi test thành FN/TN.
    """
    payload = json.loads(raw_path.read_text(encoding="utf-8"))
    # `results_without_cwe` đếm theo RESULT, `rules_without_cwe` là danh sách RULE
    # riêng biệt. Trước đây một biến bị in ra với nhãn "rule" trong khi nó đếm
    # result: một rule sinh 13 result thì in ra "13 rule không tag CWE" — khiến
    # bước verify thủ công trong spec ("số rule thiếu CWE khớp con số script log")
    # không bao giờ đạt được.
    stats = {"results": 0, "with_cwe": 0, "results_without_cwe": 0, "rule_unknown": 0}
    rules_without_cwe: set[str] = set()
    rules_unknown: set[str] = set()

    for run in payload.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        rule_tags: dict[str, list] = {}
        for source in [driver] + list(driver.get("extensions") or []):
            for rule in source.get("rules") or []:
                rule_id = str(rule.get("id") or "")
                if rule_id:
                    rule_tags[rule_id] = ((rule.get("properties") or {}).get("tags") or [])

        for result in run.get("results") or []:
            stats["results"] += 1
            rule_id = str(result.get("ruleId") or "")
            if rule_id not in rule_tags:
                stats["rule_unknown"] += 1
                rules_unknown.add(rule_id)
                tags: list = []
            else:
                tags = rule_tags[rule_id]
            ids = []
            for tag in tags:
                match = re.match(r"(CWE-\d+)", str(tag))
                if match and match.group(1) not in ids:
                    ids.append(match.group(1))
            if ids:
                stats["with_cwe"] += 1
            elif rule_id in rule_tags:
                stats["results_without_cwe"] += 1
                rules_without_cwe.add(rule_id)
            # Giữ finding kể cả khi không có CWE: nó vẫn là nhiễu mà dev phải
            # đọc, chỉ là sẽ rơi vào off_target khi chấm.
            result.setdefault("properties", {})["cwe"] = ",".join(ids)

    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    stats["rules_without_cwe"] = sorted(rules_without_cwe)
    stats["rules_unknown"] = sorted(rules_unknown)
    return stats


def assert_semgrep_run_clean(raw_path: Path) -> None:
    """Nổ nếu Semgrep báo lỗi từng phần dù exit 0.

    Semgrep exit 0 khi một rule hoặc một file timeout / parse lỗi, và `--quiet`
    che hết cảnh báo ở stderr. File đó sẽ không sinh finding -> arm C ăn một FN
    mà không có lấy một dòng cảnh báo. Vì 42/100 test trong scope vốn dĩ đã có 0
    finding, một lỗi từng phần là KHÔNG THỂ phân biệt với một miss thật.
    SARIF của Semgrep có sẵn hai trường này để nói ra chuyện đó.
    """
    payload = json.loads(raw_path.read_text(encoding="utf-8"))
    problems: list[str] = []
    for run in payload.get("runs") or []:
        for inv in run.get("invocations") or []:
            if inv.get("executionSuccessful") is False:
                problems.append("invocations[].executionSuccessful = false")
            for note in inv.get("toolExecutionNotifications") or []:
                level = str(note.get("level") or "").lower()
                if level in ("error", "warning"):
                    text = ((note.get("message") or {}).get("text") or "")[:200]
                    problems.append(f"[{level}] {text}")
    if problems:
        raise bm.BenchError(
            "Semgrep exit 0 nhưng báo lỗi/cảnh báo khi thực thi — một số file "
            "hoặc rule đã không chạy, arm static sẽ mất recall một cách âm thầm:\n"
            + "\n".join(f"    {p}" for p in problems[:10])
            + f"\n  file: {raw_path}"
        )


def assert_fully_triaged(sarif_path: Path, name: str) -> None:
    """Nổ nếu SARIF của arm triage chỉ được annotate MỘT PHẦN.

    Metis flush kết quả từng phần ra file mỗi `triage_checkpoint_every` finding
    (triage_service_exec.py:256-273). Bị kill giữa đường là còn lại một file hợp
    lệ, parse được, nhưng chỉ triaged một nửa. Các result còn lại không có
    `metisTriageStatus` -> extract_findings_by_test mặc định cho chúng `"valid"`
    -> FP phồng lên và strict trùng lenient một cách sai lệch. Cache và --rescore
    đều đọc đúng file này, nên phải chặn ở cả hai đường.
    """
    payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    results = [r for run in payload.get("runs") or []
               for r in (run.get("results") or [])]
    if not results:
        return
    untriaged = [r for r in results
                 if not (r.get("properties") or {}).get("metisTriaged")]
    if untriaged:
        raise bm.BenchError(
            f"Arm {name}: {len(untriaged)}/{len(results)} result trong "
            f"{sarif_path.name} CHƯA được triage — file là kết quả của một lần "
            f"triage bị ngắt giữa đường (checkpoint). Chấm nó sẽ mặc định các "
            f"result đó thành `valid` và thổi phồng FP.\n"
            f"  Xoá {sarif_path} rồi chạy lại arm này (không dùng --rescore)."
        )


def assert_not_triaged(sarif_path: Path) -> None:
    """Chặn việc triage đè lên SARIF đã annotate.

    Metis BỎ QUA mọi result đã có `properties.metisTriaged` truthy (trừ khi
    --include-triaged) — nạp nhầm file đã triaged vào sẽ chạy hết 0 finding,
    exit 0, và im lặng cho ra kết quả y hệt lần trước. Thà nổ ở đây.
    """
    payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    already = sum(1 for run in payload.get("runs") or []
                  for result in run.get("results") or []
                  if (result.get("properties") or {}).get("metisTriaged"))
    if already:
        raise bm.BenchError(
            f"{already} result trong {sarif_path} đã có properties.metisTriaged — "
            "triage lại sẽ bị Metis bỏ qua toàn bộ và trả kết quả rỗng một cách im lặng. "
            "Xoá file rồi chạy lại với --force."
        )


# --------------------------------------------------------------------------
# Chạy một arm
# --------------------------------------------------------------------------


def arm_paths(name: str, spec: dict) -> dict[str, Path]:
    arm_dir = OUT_DIR / name
    findings_name = "triaged.sarif" if uses_semgrep(spec) else "review.sarif"
    return {
        "dir": arm_dir,
        "findings": arm_dir / findings_name,
        "json": arm_dir / "review.json",
        "meta": arm_dir / "runmeta.json",
        "log": arm_dir / "run.log",
        "work": arm_dir / ".work",
        "config": arm_dir / "metis.yaml",
        "raw": arm_dir / "semgrep.raw.sarif",
        "normalized": arm_dir / "semgrep.normalized.sarif",
    }


def read_cache(name: str, paths: dict[str, Path], signature: dict, force: bool,
               spec: dict) -> dict | None:
    if force or not (paths["findings"].is_file() and paths["meta"].is_file()):
        return None
    try:
        meta = json.loads(paths["meta"].read_text(encoding="utf-8"))
        json.loads(paths["findings"].read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if meta.get("signature") != signature:
        print("    [cache hết hạn: cấu hình đã đổi] chạy lại")
        return None
    if uses_semgrep(spec):
        assert_fully_triaged(paths["findings"], name)
    print(f"    [cache] {paths['dir'].relative_to(bm.ROOT)}")
    return {
        "sarif": paths["findings"],
        "wall_clock": meta.get("wall_clock_seconds"),
        "semgrep_seconds": meta.get("semgrep_seconds"),
        "usage": meta.get("usage"),
        "semgrep_stats": meta.get("semgrep_stats"),
        "cached": True,
    }


def run_metis(name: str, cmd: list[str], paths: dict[str, Path],
              env: dict[str, str], expect: Path,
              expect_llm_calls: bool = True) -> tuple[float, dict | None]:
    """Chạy một tiến trình Metis, verify SẢN PHẨM chứ không tin exit code.

    entry.py:446-455 nuốt exit code: `run_non_interactive` trả về mã lỗi nhưng
    hàm bọc ngoài `return` trong khối try nên `raise SystemExit(exit_code)`
    phía sau finally không bao giờ chạy — Metis exit 0 kể cả khi lệnh hỏng.
    Cách duy nhất để biết là kiểm tra artifact có tồn tại và parse được không
    (bench.py:344-357, sweep.py:234-247 cùng nguyên tắc).
    """
    print(f"    $ {' '.join(cmd)}", flush=True)
    start = time.monotonic()
    proc = subprocess.run(cmd, cwd=paths["work"], env=env, capture_output=True, text=True)
    wall = round(time.monotonic() - start, 2)

    paths["log"].write_text(
        f"$ {' '.join(cmd)}\n  (cwd: {paths['work']})\n\n"
        f"--- exit code: {proc.returncode} | wall-clock: {wall}s ---\n"
        f"\n--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n",
        encoding="utf-8",
    )

    if proc.returncode != 0:
        raise bm.BenchError(
            f"Metis thoát với mã {proc.returncode} cho arm {name}.\n"
            f"  log: {paths['log']}\n{bm._tail(proc.stderr or proc.stdout)}"
        )
    if not expect.is_file():
        raise bm.BenchError(
            f"Arm {name} không sinh {expect.name} (dù exit 0).\n"
            f"  log: {paths['log']}\n{bm._tail(proc.stdout + proc.stderr)}"
        )
    try:
        json.loads(expect.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise bm.BenchError(f"SARIF hỏng cho arm {name}: {exc}\n  file: {expect}") from exc

    # Metis ghi results/metis_usage_*.json TƯƠNG ĐỐI VỚI CWD (usage/runtime.py:143)
    # -> phải đọc TRƯỚC khi xoá .work/, nếu không mất sạch số liệu token.
    usage = bm.load_usage(paths["work"] / "results")

    # SARIF hợp lệ nhưng 0 token = KHÔNG có lời gọi LLM nào thành công.
    # review_service bắt mọi lỗi provider thành WARNING ("Review graph failed
    # for N candidates; returning no findings for this chunk") rồi trả về
    # danh sách rỗng — Metis vẫn ghi SARIF đúng chuẩn, vẫn exit 0, và arm sẽ
    # được chấm 0 finding như thể model thật sự không tìm thấy gì. Đó là dạng
    # hỏng nguy hiểm nhất của cả pipeline này: nó không giống lỗi, nó giống
    # một kết quả. Chặn ở đây, và ĐỪNG ghi runmeta (nếu không lần sau cache
    # sẽ đóng băng luôn kết quả rỗng).
    # NGOẠI LỆ: với arm triage mà Semgrep tìm được 0 finding, 0 token là kết quả
    # HỢP LỆ, không phải lỗi. Đã truy vết: triage_service_exec.py:227 return sớm
    # khi không có finding -> không gọi LLM -> entry.py:146 bỏ qua việc ghi
    # metis_usage_*.json vì has_usage() false -> load_usage trả None. Trong khi
    # triage_service_exec.py:282 VẪN ghi triaged.sarif hợp lệ. Spec (I/O matrix)
    # yêu cầu ca này phải chấm bình thường, mọi test thành FN/TN.
    if expect_llm_calls and not (usage or {}).get("total_tokens"):
        raise bm.BenchError(
            f"Arm {name} tiêu tốn 0 token — mọi lời gọi LLM đã thất bại "
            f"(Metis nuốt lỗi provider thành WARNING và vẫn exit 0).\n"
            f"  Chạy lại lệnh trong log với --log-level DEBUG --verbose để xem "
            f"lỗi thật (thường là sai model/base_url/API key).\n"
            f"  log: {paths['log']}"
        )
    return wall, usage


def run_arm(name: str, spec: dict, cfg: dict[str, str], test_names: list[str],
            env: dict[str, str], force: bool) -> dict:
    """Chạy một arm. Trả {sarif, wall_clock, semgrep_seconds, usage,
    semgrep_stats, cached}. Ném BenchError nếu hỏng."""
    paths = arm_paths(name, spec)
    signature = arm_signature(cfg, spec, test_names)

    cached = read_cache(name, paths, signature, force, spec)
    if cached is not None:
        return cached

    paths["dir"].mkdir(parents=True, exist_ok=True)
    if paths["work"].exists():
        shutil.rmtree(paths["work"])
    paths["work"].mkdir(parents=True, exist_ok=True)
    paths["findings"].unlink(missing_ok=True)
    paths["meta"].unlink(missing_ok=True)

    paths["config"].write_text(render_arm_yaml(cfg, include_paths_for(test_names)),
                               encoding="utf-8")

    semgrep_seconds: float | None = None
    semgrep_stats: dict | None = None

    if uses_semgrep(spec):
        # --- nhánh C: Semgrep tìm -> Metis chỉ verify ---
        raw_path, semgrep_seconds = run_semgrep(paths["dir"], test_names, env)
        assert_semgrep_run_clean(raw_path)
        semgrep_stats = normalize_semgrep_sarif(raw_path, paths["normalized"])
        print(f"    semgrep: {semgrep_stats['results']} finding, "
              f"{semgrep_stats['with_cwe']} có CWE, "
              f"{semgrep_stats['results_without_cwe']} result từ rule không tag CWE "
              f"({len(semgrep_stats['rules_without_cwe'])} rule), "
              f"{semgrep_stats['rule_unknown']} result không tra được rule "
              f"({semgrep_seconds}s, 0 token)")
        # `triage` mặc định GHI ĐÈ file input tại chỗ — bắt buộc --output-file
        # trỏ sang file khác, nếu không SARIF đã chuẩn hoá bị phá.
        assert_not_triaged(paths["normalized"])
        command_text = f"triage {paths['normalized']}"
        cmd = arm_command(spec, paths["config"], paths["work"] / ".chromadb",
                          paths["findings"], None, command_text)
    else:
        # --- nhánh A/B: review_code một lần cho cả tập test ---
        cmd = arm_command(spec, paths["config"], paths["work"] / ".chromadb",
                          paths["findings"], paths["json"])

    # Semgrep 0 finding -> triage không gọi LLM -> 0 token là HỢP LỆ, không phải
    # lỗi provider. Chỉ nhánh review mới bắt buộc phải có token.
    expect_llm_calls = not (uses_semgrep(spec) and not (semgrep_stats or {}).get("results"))
    wall, usage = run_metis(name, cmd, paths, env, paths["findings"],
                            expect_llm_calls=expect_llm_calls)

    paths["meta"].write_text(json.dumps({
        "signature": signature,
        "wall_clock_seconds": wall,
        "semgrep_seconds": semgrep_seconds,
        "usage": usage,
        "semgrep_stats": semgrep_stats,
        "ran_at": bm._utc_now(),
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    shutil.rmtree(paths["work"], ignore_errors=True)

    return {"sarif": paths["findings"], "wall_clock": wall,
            "semgrep_seconds": semgrep_seconds, "usage": usage,
            "semgrep_stats": semgrep_stats, "cached": False}


# --------------------------------------------------------------------------
# Đọc SARIF gộp và chấm điểm
# --------------------------------------------------------------------------


def extract_findings_by_test(sarif_path: Path,
                             test_names: list[str]) -> tuple[dict[str, list[dict]], int]:
    """Nhóm finding theo test, dựa vào artifactLocation.uri của mỗi result.

    Một SARIF ở đây chứa finding của cả trăm file (dù là của review_code hay
    của Semgrep) nên bắt buộc phải tách theo tên test rút từ uri.
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
                # Không triage -> không có nhãn -> coi như tool vẫn khẳng định
                # finding. Nhờ default này arm A (không --triage) có
                # strict == lenient, đúng như kỳ vọng.
                "status": str(props.get("metisTriageStatus") or "valid").strip().lower(),
                "triaged": bool(props.get("metisTriaged")),
                "triage_reason": props.get("metisTriageReason"),
                "rule_id": result.get("ruleId"),
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
    không cần ground truth). Arm không triage -> None."""
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


def score_arm(buckets: dict[str, list[dict]], truth: dict[str, dict]) -> dict:
    """Chấm từng test bằng bm.score_run() (tái dùng nguyên logic strict/lenient
    của bench.py), rồi tổng hợp qua toàn bộ tập test. bm.aggregate() đã trả sẵn
    fpr + youden nên không tự tính lại."""
    per_test = {test: bm.score_run(findings, truth[test])
                for test, findings in buckets.items()}
    strict = bm.aggregate([r["outcome_strict"] for r in per_test.values()])
    lenient = bm.aggregate([r["outcome_lenient"] for r in per_test.values()])
    return {"strict": strict, "lenient": lenient, "per_test": per_test}


# --------------------------------------------------------------------------
# Arm dẫn xuất: B ∪ C
# --------------------------------------------------------------------------


def cwe_class(cwes: list[int]) -> frozenset[int]:
    """Lớp tương đương CWE của một finding, mở rộng theo bm.CWE_ALIASES.

    So khớp bằng tuple CWE CHÍNH XÁC là sai: Semgrep trả CWE-326 ở chỗ ground
    truth ghi CWE-327, và 6/560 rule mang nhiều tag nên cho ra "CWE-327,CWE-328".
    Với khoá chính xác thì cùng một lỗ hổng bị đếm thành hai, `both` tụt xuống và
    `only_a`/`only_b` phồng lên — mà đó lại đúng là con số DUY NHẤT arm union tồn
    tại để đo. bench.py:86-98 có sẵn bảng alias chính vì hai cơ chế gọi tên khác
    nhau cho cùng một lớp lỗi.
    """
    expanded: set[int] = set()
    for cwe in cwes:
        expanded |= bm.accepted_cwes(cwe)
    return frozenset(expanded)


def derive_union(buckets_a: dict[str, list[dict]],
                 buckets_b: dict[str, list[dict]]) -> tuple[dict[str, list[dict]], dict]:
    """Gộp finding của hai arm theo (test, LỚP TƯƠNG ĐƯƠNG CWE).

    Hai finding cùng test và CWE thuộc cùng lớp tương đương là CÙNG một lỗ hổng
    được hai cơ chế phát hiện độc lập — đếm hai lần sẽ thổi phồng "số finding"
    của union mà không thêm thông tin gì. Finding KHÔNG có CWE thì giữ nguyên
    tất cả: chúng không so sánh được với nhau nên gộp là mất mát thật.

    Trùng khoá -> giữ nhãn khẳng định mạnh nhất (valid > inconclusive >
    invalid): union là phép HỢP của hai cơ chế phát hiện.

    `collapsed_a`/`collapsed_b` đếm số finding bị gộp mất TRONG CÙNG một arm.
    Không có nó thì cột `findings` của union (đã gộp) không so được với cột
    `findings` của arm nguồn (thô) mà chẳng ai biết lệch bao nhiêu.
    """
    merged: dict[str, list[dict]] = {}
    stats = {"only_a": 0, "only_b": 0, "both": 0, "no_cwe": 0,
             "collapsed_a": 0, "collapsed_b": 0, "alias_matched": 0}

    for test in buckets_a:
        by_key: dict[tuple, dict] = {}
        # Lớp tương đương CWE tích luỹ cho từng khoá đã mở.
        key_class: dict[tuple, set[int]] = {}
        seen_per_source: dict[tuple, dict[str, int]] = {}
        # Nguồn phải theo dõi TÁCH RỜI khỏi finding được giữ lại: một arm có
        # thể tự nó báo hai finding cùng CWE trên cùng file, và đó KHÔNG phải
        # bằng chứng hai cơ chế cùng tìm ra — đếm nó vào "both" sẽ bịa ra mức
        # trùng lặp không có thật giữa hai arm.
        sources_by_key: dict[tuple, set[str]] = {}
        loose: list[dict] = []
        for source, findings in (("a", buckets_a.get(test) or []),
                                 ("b", buckets_b.get(test) or [])):
            for finding in findings:
                item = dict(finding, source=source)
                if not item["cwes"]:
                    stats["no_cwe"] += 1
                    loose.append(item)
                    continue
                expanded = cwe_class(item["cwes"])
                # Khớp với khoá đã mở nếu lớp tương đương GIAO nhau.
                key = next((k for k, kexp in key_class.items() if kexp & expanded), None)
                if key is None:
                    key = tuple(item["cwes"])
                    key_class[key] = set(expanded)
                else:
                    if tuple(item["cwes"]) != key:
                        stats["alias_matched"] += 1
                    key_class[key] |= expanded

                sources_by_key.setdefault(key, set()).add(source)
                counts = seen_per_source.setdefault(key, {})
                counts[source] = counts.get(source, 0) + 1
                if counts[source] > 1:
                    stats[f"collapsed_{source}"] += 1

                current = by_key.get(key)
                if current is None or (STATUS_RANK.get(item["status"], 3)
                                       < STATUS_RANK.get(current["status"], 3)):
                    by_key[key] = item

        for key, item in by_key.items():
            sources = sources_by_key[key]
            item["source"] = "both" if len(sources) > 1 else next(iter(sources))
            stats["both" if item["source"] == "both"
                  else f"only_{item['source']}"] += 1
        merged[test] = list(by_key.values()) + loose

    return merged, stats


# --------------------------------------------------------------------------
# Pareto + báo cáo
# --------------------------------------------------------------------------


def youden_per_million(youden: float | None, tokens: int | None) -> float | None:
    if youden is None or not tokens:
        return None
    return youden / (tokens / 1e6)


def pareto_front(rows: list[dict]) -> set[str]:
    """Tập arm không bị arm nào khác thống trị.

    Arm X bị Y thống trị khi Y có Youden(strict) >= và token <= của X, với ít
    nhất một chiều tốt hơn hẳn. Arm thiếu số liệu (lỗi) không tham gia.
    """
    candidates = [r for r in rows
                  if r.get("youden_strict") is not None and r.get("total_tokens") is not None]
    front: set[str] = set()
    for row in candidates:
        dominated = any(
            other is not row
            and other["youden_strict"] >= row["youden_strict"]
            and other["total_tokens"] <= row["total_tokens"]
            and (other["youden_strict"] > row["youden_strict"]
                 or other["total_tokens"] < row["total_tokens"])
            for other in candidates
        )
        if not dominated:
            front.add(row["arm"])
    return front


def recommend(rows: list[dict], front: set[str]) -> str:
    """Đúng MỘT dòng đề xuất, kèm lý do định lượng."""
    usable = [r for r in rows
              if r["arm"] in front and r.get("youden_per_1m") is not None]
    if not usable:
        return ("**Đề xuất: không có** — chưa arm nào có đủ cả Youden lẫn số token "
                "để so sánh (xem cột lỗi).")
    # Youden <= 0 nghĩa là arm KHÔNG khá hơn đoán bừa (recall <= FPR). Xếp hạng
    # ROI trên một tập như thế sẽ đề xuất arm tệ nhất chỉ vì nó rẻ nhất, và câu
    # "ROI cao nhất" thành ra vô nghĩa với số điểm âm.
    if not any(r["youden_strict"] > 0 for r in usable):
        return ("**Đề xuất: không có** — không arm nào có Youden(strict) > 0, tức "
                "không arm nào khá hơn đoán bừa trên scope này. Xếp hạng ROI sẽ "
                "chỉ đề xuất arm rẻ nhất trong số các arm đều tệ.")
    # "ROI cao nhất" / "Youden cao nhất" là vô nghĩa khi chỉ có MỘT arm chấm được:
    # cả hai so sánh nhất đều rỗng, mà câu văn lại đọc y như một so sánh đủ bộ.
    scored_all = [r for r in rows if r.get("youden_strict") is not None]
    if len(scored_all) < 2:
        only = scored_all[0]
        return (f"**Đề xuất: không kết luận được** — chỉ có `{only['arm']}` chấm "
                f"được (Youden strict {bm._pct(only['youden_strict'])}, "
                f"{(only['total_tokens'] or 0) / 1e6:.3f}M token). Cần ít nhất hai "
                f"arm mới nói được arm nào đáng tiền hơn.")
    winner = max(usable, key=lambda r: r["youden_per_1m"])
    scored = [r for r in rows if r.get("youden_strict") is not None]
    # Hoà điểm -> ưu tiên arm RẺ hơn, để không bao giờ sinh ra câu vô nghĩa kiểu
    # "phải trả 8.7× token để đổi lấy +0.0 điểm Youden".
    best_youden = max(scored, key=lambda r: (r["youden_strict"],
                                             -(r["total_tokens"] or 0)))

    text = (f"**Đề xuất: `{winner['arm']}`** — ROI cao nhất: "
            f"{winner['youden_per_1m'] * 100:.1f} điểm Youden trên mỗi 1M token "
            f"(Youden strict {bm._pct(winner['youden_strict'])} "
            f"với {(winner['total_tokens'] or 0) / 1e6:.3f}M token)")
    if best_youden["arm"] != winner["arm"]:
        delta = (best_youden["youden_strict"] - winner["youden_strict"]) * 100
        winner_tokens = winner["total_tokens"] or 0
        best_tokens = best_youden["total_tokens"] or 0
        ratio = (best_tokens / winner_tokens) if winner_tokens else float("inf")
        text += (f". Arm điểm cao nhất là `{best_youden['arm']}` "
                 f"({bm._pct(best_youden['youden_strict'])}) nhưng phải trả "
                 f"{ratio:.1f}× token để đổi lấy +{delta:.1f} điểm Youden")
    else:
        text += " — đồng thời cũng là arm có Youden(strict) cao nhất"
    return text + "."


REPORT_COLS = ["arm", "youden_strict", "youden_lenient", "precision", "recall", "fpr",
               "total_tokens", "minutes", "youden_per_1m", "pareto",
               "findings", "triage_prec", "gt_tp", "gt_fp", "gt_fn", "gt_tn", "error"]


def build_report(rows: list[dict], test_names: list[str], front: set[str],
                 arms_requested: list[str] | None = None,
                 union_skip_note: str | None = None) -> tuple[str, str, str]:
    """Trả (markdown, csv, json)."""
    scope = (f"{len(test_names)} test ({test_names[0]} → {test_names[-1]})"
             if test_names else "0 test")
    lines = [
        "# Ablation — kiến trúc discovery nào đáng tiền?",
        "",
        f"_Sinh lúc {bm._utc_now()} · scope {scope} · "
        f"ruleset Semgrep: {', '.join(SEMGREP_RULESETS)}_",
        "",
    ]
    # Báo cáo phải TỰ NÓI ra là nó không đầy đủ. Không có dòng này thì một lần
    # chạy --only đọc y như một so sánh hoàn tất.
    if arms_requested is not None and set(arms_requested) != set(ARMS):
        lines += [
            f"> ⚠ **Chạy một phần**: chỉ có {', '.join(arms_requested)} "
            f"(đủ bộ là {', '.join(ARMS)}). Đừng đọc bảng này như một so sánh "
            f"hoàn chỉnh.",
            "",
        ]
    if union_skip_note:
        lines += [f"> ⚠ {union_skip_note.lstrip('! ')}", ""]
    lines += [
        "| Arm | Youden(strict) | Youden(lenient) | Precision | Recall | FPR "
        "| Token | Phút | Youden/1M | Pareto |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|:--:|",
    ]
    for row in rows:
        if row.get("error"):
            lines.append(f"| {row['arm']} | LỖI | | | | | | | | |")
            continue
        tokens_text = "n/a" if row["total_tokens"] is None else f"{row['total_tokens']:,}"
        minutes_text = "n/a" if row["minutes"] is None else f"{row['minutes']:.1f}"
        ypm = row.get("youden_per_1m")
        ypm_text = "n/a" if ypm is None else f"{ypm * 100:.1f}"
        lines.append(
            f"| {row['arm']} | {bm._pct(row['youden_strict'])} "
            f"| {bm._pct(row['youden_lenient'])} | {bm._pct(row['precision'])} "
            f"| {bm._pct(row['recall'])} | {bm._pct(row['fpr'])} "
            f"| {tokens_text} | {minutes_text} | {ypm_text} "
            f"| {'**✓**' if row['arm'] in front else ''} |"
        )
    scored = [r for r in rows if not r.get("error")]
    if scored and all(r["fpr"] is None for r in scored):
        lines += [
            "",
            "> ⚠ **Scope này không có lấy một test AN TOÀN nào** → FPR không định "
            "nghĩa được → Youden và Pareto đều `n/a`. Bảng trên chỉ đọc được cột "
            "Recall. Cần scope đủ lớn để có mẫu âm (100 test đầu có 25 mẫu âm).",
        ]
    lines += ["", recommend(rows, front), ""]

    lines.append("## Chú thích từng arm")
    lines.append("")
    for row in rows:
        note = ARM_NOTES.get(row["arm"], "")
        suffix = f" — LỖI: {str(row['error']).splitlines()[0]}" if row.get("error") else ""
        lines.append(f"- `{row['arm']}` — {note}{suffix}")
    lines += [
        "",
        "> **Youden/1M** = (recall − FPR) × 100 chia cho số token tính bằng triệu. "
        "Cột Pareto đánh dấu arm không bị arm nào khác vừa cao điểm hơn vừa rẻ hơn.",
        "",
        f"> `{UNION_ARM}` là arm **dẫn xuất**: nó gộp offline SARIF đã có của "
        f"`{UNION_SOURCES[0]}` và `{UNION_SOURCES[1]}`, không gọi thêm LLM lần nào. "
        "Token và phút của nó vì thế được ghi bằng **TỔNG** của hai arm nguồn — "
        "phải chạy cả hai mới có nó, nên cột Youden/1M mới trung thực.",
        "",
        "> `static` tốn 0 token cho khâu Semgrep (chỉ tốn wall-clock, đã cộng vào "
        "cột Phút); toàn bộ token của nó là của khâu `triage`.",
        "",
        "> Precision/recall/FPR lấy từ cột **strict** (`inconclusive` = vẫn tính là "
        "báo cáo), đối chiếu ground truth `expectedresults-1.2.csv`. Không LLM-judge. "
        "Đơn vị là mỗi FILE test, không phải mỗi finding.",
        "",
        "> Arm `prompt_only` không chạy triage nên mọi finding mặc định `valid` → "
        "strict phải bằng lenient. Nếu hai cột lệch nhau là logic status mặc định sai.",
        "",
    ]

    csv_lines = [",".join(REPORT_COLS)]
    for row in rows:
        cells = []
        for col in REPORT_COLS:
            value = row["arm"] in front if col == "pareto" else row.get(col)
            # Text lỗi của BenchError là NHIỀU DÒNG (có \n và cả đường dẫn log).
            # Nhét thô vào CSV là file vỡ: hàng bị tách ra thành nhiều dòng, cột
            # lệch, không parse được nữa. Đã xảy ra thật với arm static exit 2.
            cell = "" if value is None else str(value)
            cell = re.sub(r"\s*\n\s*", " ⏎ ", cell).replace(",", ";")
            cells.append(cell)
        csv_lines.append(",".join(cells))

    json_rows = [dict(row, pareto=row["arm"] in front) for row in rows]
    payload = {
        "generated_at": bm._utc_now(),
        "scope": {"count": len(test_names),
                  "first": test_names[0] if test_names else None,
                  "last": test_names[-1] if test_names else None},
        "semgrep_rulesets": SEMGREP_RULESETS,
        "pareto_front": sorted(front),
        "recommendation": recommend(rows, front),
        "arms": json_rows,
    }
    return ("\n".join(lines) + "\n",
            "\n".join(csv_lines) + "\n",
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


def blank_row(name: str, error: str) -> dict:
    row = {col: None for col in REPORT_COLS}
    row["arm"] = name
    row["error"] = error
    return row


def make_row(name: str, scored: dict, findings: int, triage_prec: float | None,
             tokens: int | None, seconds: float | None) -> dict:
    strict, lenient = scored["strict"], scored["lenient"]
    return {
        "arm": name,
        "youden_strict": strict["youden"],
        "youden_lenient": lenient["youden"],
        "precision": strict["precision"],
        "recall": strict["recall"],
        "fpr": strict["fpr"],
        "total_tokens": tokens,
        "minutes": round(seconds / 60, 1) if seconds else None,
        "youden_per_1m": youden_per_million(strict["youden"], tokens),
        "findings": findings,
        "triage_prec": triage_prec,
        "gt_tp": strict["TP"], "gt_fp": strict["FP"],
        "gt_fn": strict["FN"], "gt_tn": strict["TN"],
        "error": None,
    }


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="So sánh 3 kiến trúc discovery (prompt-only / harness / static) "
                    "cộng arm dẫn xuất B∪C, trên cùng một tập BenchmarkJava, "
                    "xuất Pareto frontier.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--only", nargs="+", metavar="ARM",
                        help=f"Chỉ chạy các arm này. Có sẵn: {', '.join(ARMS)}.")
    parser.add_argument("--sample", type=int, default=DEFAULT_SAMPLE_SIZE, metavar="N",
                        help=f"Số test ĐẦU TIÊN theo thứ tự tên dùng làm scope "
                             f"(mặc định {DEFAULT_SAMPLE_SIZE}, cùng tập với bench.py/sweep.py).")
    parser.add_argument("--force", action="store_true",
                        help="Bỏ qua cache của arm, chạy lại từ đầu.")
    parser.add_argument("--dry-run", action="store_true",
                        help="In cấu hình + lệnh sẽ chạy cho từng arm rồi thoát. "
                             "Không gọi LLM, không ghi gì vào results/ablation/.")
    parser.add_argument("--rescore", action="store_true",
                        help="Chỉ chấm lại từ SARIF đã có trong results/ablation/<arm>/, "
                             "không gọi Metis/Semgrep.")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Không hỏi xác nhận trước khi chạy.")
    return parser.parse_args()


def preflight(arm_names: list[str]) -> None:
    if not shutil.which("uv"):
        raise bm.BenchError("Không tìm thấy `uv` trong PATH.")
    if not (bm.METIS_DIR / "pyproject.toml").is_file():
        raise bm.BenchError(f"Không tìm thấy project Metis tại {bm.METIS_DIR}")
    if any(uses_semgrep(ARMS[n]) for n in arm_names) and not shutil.which("semgrep"):
        raise bm.BenchError("Không tìm thấy `semgrep` trong PATH (cần cho arm `static`).")
    # entry.py:283 tách --command bằng whitespace: mọi đường dẫn xuất hiện trong
    # --command (file .java, file .sarif để triage) phải sạch khoảng trắng.
    for path in (bm.BENCH_DIR, bm.TESTCODE_DIR, bm.METIS_DIR, OUT_DIR):
        if " " in str(path):
            raise bm.BenchError(
                f"Đường dẫn có khoảng trắng, Metis sẽ parse sai --command:\n  {path}")


def do_dry_run(cfg: dict[str, str], arm_names: list[str], test_names: list[str],
               truth: dict[str, dict]) -> int:
    """In mọi thứ sẽ chạy. KHÔNG tạo bất cứ file/thư mục nào dưới OUT_DIR —
    dry-run mà để lại rác thì lần chạy thật sau đó không còn sạch."""
    print(f"# Scope: {len(test_names)} test ({test_names[0]} -> {test_names[-1]})")
    print(f"# OUT_DIR (sẽ KHÔNG được tạo ở chế độ dry-run): {OUT_DIR}\n")
    print(bm.describe_sample(test_names, truth) + "\n")

    preview_yaml = render_arm_yaml(
        cfg, include_paths_for(test_names[:3]) + ["... (còn lại bị cắt bớt để xem trước)"])
    print("## metis.yaml dùng CHUNG cho mọi arm "
          "(khác biệt giữa các arm nằm ở cờ CLI, không ở YAML)")
    print(preview_yaml)

    for name in arm_names:
        spec = ARMS[name]
        paths = arm_paths(name, spec)
        print(f"## arm: {name}  —  {spec['note']}")
        print(f"   tools={spec['tools']!r} command={spec['command']!r} "
              f"triage={spec['triage']} engine={spec['engine']}")
        if uses_semgrep(spec):
            cmd = semgrep_command(paths["raw"], test_names)
            head = cmd[:cmd.index("--config")] + [
                arg for r in SEMGREP_RULESETS for arg in ("--config", r)]
            print(f"   (cwd: {bm.BENCH_DIR})")
            print("   $ " + " ".join(head)
                  + f" <{len(test_names)} đường dẫn .java tương đối>")
            command_text = f"triage {paths['normalized']}"
            print("   $ " + " ".join(arm_command(
                spec, paths["config"], paths["work"] / ".chromadb",
                paths["findings"], None, command_text)) + "\n")
        else:
            print("   $ " + " ".join(arm_command(
                spec, paths["config"], paths["work"] / ".chromadb",
                paths["findings"], paths["json"])) + "\n")

    print(f"## arm dẫn xuất: {UNION_ARM}  —  {ARM_NOTES[UNION_ARM]}")
    print("   (không có lệnh — gộp offline SARIF của "
          f"{UNION_SOURCES[0]} và {UNION_SOURCES[1]}, 0 token)\n")
    print(f"# Tổng: {len(arm_names)} arm × {len(test_names)} test = "
          f"{len(arm_names) * len(test_names)} file-review, chạy TUẦN TỰ.")
    return 0


def load_rescore(name: str, spec: dict, signature: dict) -> dict:
    paths = arm_paths(name, spec)
    if not paths["findings"].is_file():
        raise bm.BenchError(f"--rescore nhưng thiếu {paths['findings']}")
    try:
        json.loads(paths["findings"].read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        # Tiến trình bị kill giữa lúc ghi -> SARIF cắt cụt. Chỉ kiểm tra tồn tại
        # là không đủ; phải parse được, nếu không traceback thô sẽ bay ra ngoài
        # tầng xử lý BenchError và cả run mất báo cáo.
        raise bm.BenchError(f"--rescore nhưng SARIF hỏng: {paths['findings']}\n  {exc}") from exc
    try:
        meta = (json.loads(paths["meta"].read_text(encoding="utf-8"))
                if paths["meta"].is_file() else {})
    except (json.JSONDecodeError, OSError):
        meta = {}

    # Chấm lại SARIF của scope KHÁC là dạng sai tệ nhất: 94 test không có trong
    # SARIF sẽ lặng lẽ thành FN/TN và bảng vẫn in ra như số liệu chính thức.
    old_digest = (meta.get("signature") or {}).get("tests_digest")
    if old_digest and old_digest != signature["tests_digest"]:
        raise bm.BenchError(
            f"--rescore nhưng arm {name} được chạy trên TẬP TEST KHÁC "
            f"(digest {old_digest} != {signature['tests_digest']}).\n"
            f"  Chấm lại sẽ tính mọi test ngoài SARIF thành FN/TN. Dùng đúng "
            f"--sample của lần chạy gốc, hoặc bỏ --rescore để chạy lại."
        )
    if uses_semgrep(spec):
        assert_fully_triaged(paths["findings"], name)
    return {"sarif": paths["findings"], "wall_clock": meta.get("wall_clock_seconds"),
            "semgrep_seconds": meta.get("semgrep_seconds"), "usage": meta.get("usage"),
            "semgrep_stats": meta.get("semgrep_stats"), "cached": True}


def main() -> int:
    args = parse_args()

    # bm.select_tests coi size=0 là "lấy TẤT CẢ" -> `--sample 0` sẽ lặng lẽ chạy
    # 3 arm trên cả 2740 test. Với chi phí ~48k token/test đó là hoá đơn khổng lồ
    # từ một cú gõ nhầm. Chặn thẳng.
    if args.sample <= 0:
        raise bm.BenchError(
            f"--sample phải >= 1 (nhận {args.sample}). Giá trị 0 bị bench.py hiểu "
            f"là 'lấy toàn bộ 2740 test' — gần như chắc chắn không phải ý bạn."
        )

    arm_names = list(ARMS)
    if args.only:
        unknown = [n for n in args.only if n not in ARMS]
        if unknown:
            hint = ""
            if UNION_ARM in unknown:
                hint = (f" `{UNION_ARM}` là arm DẪN XUẤT, không chạy riêng được — "
                        f"nó tự xuất hiện khi cả {' và '.join(UNION_SOURCES)} có mặt.")
            raise bm.BenchError(f"Arm không tồn tại: {', '.join(unknown)}. "
                                f"Có sẵn: {', '.join(ARMS)}.{hint}")
        # Trùng tên -> arm bị chấm hai lần và báo cáo có hai dòng y hệt.
        arm_names = list(dict.fromkeys(args.only))

    cfg = bm.load_config()
    truth = bm.load_ground_truth()
    test_names = bm.select_tests(truth, args.sample)
    if not test_names:
        raise bm.BenchError("Không tìm thấy test nào có file .java.")

    # --rescore không gọi semgrep hay uv -> đòi chúng có mặt là chặn oan việc
    # chấm lại trên máy chỉ có sẵn artifact.
    if not args.rescore:
        preflight(arm_names)

    if args.dry_run:
        return do_dry_run(cfg, arm_names, test_names, truth)

    if not args.yes and not args.rescore and sys.stdin.isatty():
        print(bm.describe_sample(test_names, truth))
        print(f"Scope: {len(test_names)} test ({test_names[0]} -> {test_names[-1]})")
        print(f"Arm sẽ chạy: {', '.join(arm_names)}")
        print(f"\n{len(arm_names)} arm × {len(test_names)} test — mỗi arm là MỘT LẦN "
              f"QUÉT ĐẦY ĐỦ (tốn hàng triệu token / hàng chục phút).")
        answer = input("Tiếp tục? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Đã huỷ.")
            return 0

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.update(cfg)

    rows: list[dict] = []
    buckets_by_arm: dict[str, dict[str, list[dict]]] = {}
    cost_by_arm: dict[str, tuple[int | None, float | None]] = {}
    first = True

    for name in arm_names:
        spec = ARMS[name]
        print(f"\n=== arm: {name}  ({spec['note']}) ===")

        try:
            outcome = (load_rescore(name, spec, arm_signature(cfg, spec, test_names))
                       if args.rescore
                       else run_arm(name, spec, cfg, test_names, env, args.force))
        except bm.BenchError as exc:
            # Arm ĐẦU TIÊN lỗi -> thường là lỗi cấu hình/auth, áp cho mọi arm
            # còn lại: dừng cả run thay vì đốt tiền ba lần nữa để cùng ngã.
            # Trừ --rescore: nó không gọi tiến trình nào, không tốn đồng nào,
            # nên một arm thiếu artifact không phải lý do huỷ cả phép chấm lại.
            if first and not args.rescore:
                raise bm.BenchError(f"Arm đầu tiên ({name}) thất bại — dừng trước khi "
                                    f"chạy {len(arm_names) - 1} arm còn lại.\n{exc}")
            print(f"  LỖI, bỏ qua arm này: {exc}", file=sys.stderr)
            rows.append(blank_row(name, str(exc)))
            continue
        first = False

        buckets, unmatched = extract_findings_by_test(outcome["sarif"], test_names)
        if unmatched:
            print(f"  ! {unmatched} finding không khớp tên test nào trong scope "
                  "(bỏ khỏi mọi phép tính)", file=sys.stderr)
        buckets_by_arm[name] = buckets
        all_findings = [f for findings in buckets.values() for f in findings]

        scored = score_arm(buckets, truth)
        tri = triage_precision(all_findings)
        usage = outcome.get("usage") or {}
        tokens = usage.get("total_tokens")
        seconds = usage.get("duration_seconds") or outcome.get("wall_clock")
        if seconds is not None:
            # Semgrep tốn 0 token nhưng KHÔNG tốn 0 thời gian — bỏ qua là nói dối
            # về chi phí thật của arm static.
            seconds += outcome.get("semgrep_seconds") or 0.0
        cost_by_arm[name] = (tokens, seconds)

        row = make_row(name, scored, len(all_findings), tri["precision"] if tri else None,
                       tokens, seconds)
        rows.append(row)

        (arm_paths(name, spec)["dir"] / "detail.json").write_text(json.dumps({
            "arm": name, "spec": spec, "semgrep_rulesets": SEMGREP_RULESETS,
            "wall_clock_seconds": outcome.get("wall_clock"),
            "semgrep_seconds": outcome.get("semgrep_seconds"),
            "semgrep_stats": outcome.get("semgrep_stats"),
            "usage": usage, "triage_precision": tri, "ground_truth": scored,
            "unmatched_findings": unmatched,
        }, indent=2, ensure_ascii=False), encoding="utf-8")

        print(f"  -> Youden strict={bm._pct(row['youden_strict'])} "
              f"lenient={bm._pct(row['youden_lenient'])} | "
              f"P={bm._pct(row['precision'])} R={bm._pct(row['recall'])} "
              f"FPR={bm._pct(row['fpr'])} | {row['total_tokens']} token | "
              f"{row['minutes']} phút | {row['findings']} finding")

    # --- arm dẫn xuất B ∪ C ---
    union_skip_note: str | None = None
    if all(src in buckets_by_arm for src in UNION_SOURCES):
        print(f"\n=== arm: {UNION_ARM}  ({ARM_NOTES[UNION_ARM]}) ===")
        merged, union_stats = derive_union(buckets_by_arm[UNION_SOURCES[0]],
                                           buckets_by_arm[UNION_SOURCES[1]])
        scored = score_arm(merged, truth)
        all_findings = [f for findings in merged.values() for f in findings]
        tokens_parts = [cost_by_arm[src][0] for src in UNION_SOURCES]
        seconds_parts = [cost_by_arm[src][1] for src in UNION_SOURCES]
        # Thiếu số liệu của MỘT arm nguồn -> tổng phải là None, không phải tổng
        # phần còn lại. Cộng nửa chi phí rồi dán nhãn "TỔNG" sẽ khiến union
        # thắng Pareto và thắng cả dòng đề xuất một cách gian lận.
        tokens = None if any(t is None for t in tokens_parts) else sum(tokens_parts)
        seconds = None if any(s is None for s in seconds_parts) else sum(seconds_parts)
        tri = triage_precision(all_findings)
        row = make_row(UNION_ARM, scored, len(all_findings),
                       tri["precision"] if tri else None, tokens, seconds)
        rows.append(row)

        union_dir = OUT_DIR / UNION_ARM
        union_dir.mkdir(parents=True, exist_ok=True)
        (union_dir / "detail.json").write_text(json.dumps({
            "arm": UNION_ARM, "derived_from": list(UNION_SOURCES),
            "merge_stats": union_stats,
            "cost_note": "token/phút = TỔNG của hai arm nguồn; phép gộp tự nó tốn 0 token",
            "total_tokens": tokens, "seconds": seconds,
            "ground_truth": scored,
        }, indent=2, ensure_ascii=False), encoding="utf-8")

        print(f"  gộp: chỉ {UNION_SOURCES[0]}={union_stats['only_a']} · "
              f"chỉ {UNION_SOURCES[1]}={union_stats['only_b']} · "
              f"cả hai={union_stats['both']} · không CWE={union_stats['no_cwe']} "
              f"(khớp qua alias CWE={union_stats['alias_matched']}; "
              f"gộp trong cùng arm: {UNION_SOURCES[0]}={union_stats['collapsed_a']}, "
              f"{UNION_SOURCES[1]}={union_stats['collapsed_b']})")
        print(f"  -> Youden strict={bm._pct(row['youden_strict'])} "
              f"lenient={bm._pct(row['youden_lenient'])} | "
              f"P={bm._pct(row['precision'])} R={bm._pct(row['recall'])} "
              f"FPR={bm._pct(row['fpr'])} | {row['total_tokens']} token (tổng B+C) | "
              f"{row['findings']} finding")
    else:
        # KHÔNG được im lặng khi có --only: bảng thiếu dòng B_union_C mà không nói
        # gì thì đọc y như một so sánh đã hoàn tất. Người đọc không phân biệt được
        # "union không chạy" với "union chạy mà chẳng ra gì".
        missing = [s for s in UNION_SOURCES if s not in buckets_by_arm]
        note = (f"! Bỏ qua {UNION_ARM}: thiếu arm nguồn {', '.join(missing)} "
                f"(cần cả {' và '.join(UNION_SOURCES)}).")
        print(f"\n{note}", file=sys.stderr)
        union_skip_note = note

    # KHÔNG arm nào chấm được -> bảng chỉ toàn dòng LỖI, không mang thông tin gì.
    # Ghi nó ra là ĐÈ MẤT báo cáo tốt của lần chạy trước bằng một cái vô dụng —
    # đã xảy ra thật: `--sample 6 --rescore` trên artifact 100 test làm cả 3 arm
    # lỗi digest rồi xoá sạch bảng so sánh 100 test vừa chạy 2 tiếng.
    if not any(r.get("youden_strict") is not None for r in rows):
        raise bm.BenchError(
            "Không arm nào chấm được — không ghi báo cáo, để giữ nguyên "
            f"{OUT_DIR / 'compare.md'} của lần chạy trước.\n  Lỗi từng arm:\n"
            + "\n".join(f"    {r['arm']}: {r.get('error')}" for r in rows)
        )

    front = pareto_front(rows)
    md, csv_text, json_text = build_report(rows, test_names, front,
                                           arms_requested=arm_names,
                                           union_skip_note=union_skip_note)
    # Chạy `--only` một arm rồi ghi đè compare.md của lần chạy đủ là mất bảng so
    # sánh hoàn chỉnh — thứ duy nhất mà cả script này tồn tại để tạo ra. Ghi ra
    # tên khác và nói rõ.
    suffix = f".{'+'.join(arm_names)}" if args.only else ""
    if suffix:
        print(f"\n! --only đang bật -> ghi ra compare{suffix}.* để KHÔNG đè bảng "
              f"so sánh đầy đủ.", file=sys.stderr)
    (OUT_DIR / f"compare{suffix}.md").write_text(md, encoding="utf-8")
    (OUT_DIR / f"compare{suffix}.csv").write_text(csv_text, encoding="utf-8")
    (OUT_DIR / f"compare{suffix}.json").write_text(json_text, encoding="utf-8")

    print("\n" + md)
    print(f"Bảng so sánh: {OUT_DIR / f'compare{suffix}.md'}")
    print(f"              {OUT_DIR / f'compare{suffix}.csv'}")
    print(f"              {OUT_DIR / f'compare{suffix}.json'}")

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
