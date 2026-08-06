#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests>=2.34.2", "scikit-learn>=1.9.0"]
# ///
"""Chạy Security Analysis Agent trên một tập cảnh báo đã chuẩn hoá và ghi báo cáo.

Script này KHÔNG chứa logic phân tích. Toàn bộ luật gộp nhóm, kẹp mức nghiêm
trọng, lược đồ phản hồi và cách xử lý thất bại nằm trong `src/security_agent.py`
(flow/05-contract.md, v1.7). Ở đây chỉ có: đọc tham số, hỏi xác nhận trước khi
tiêu tiền, in tiến độ, và ánh xạ `meta.status` sang mã thoát. Nếu thấy cần cài
thêm logic vào file này thì chỗ đúng của nó là module, không phải chỗ này.

  ./scripts/analyze.py                       # 111 cảnh báo trong data/kb/alerts.jsonl — TỐN PHÍ, sẽ hỏi
  ./scripts/analyze.py --no-llm              # chạy tất định, 0 lần gọi mạng, output lặp lại giống hệt
  ./scripts/analyze.py --limit 3 -y          # chỉ đưa 3 nhóm nặng nhất cho mô hình
  ./scripts/analyze.py --from-run bench/baseline --no-llm
  ./scripts/analyze.py --input tests/fixtures/alerts_mixed.jsonl --no-llm

Mã thoát bám đúng bảng trạng thái của hợp đồng:

  0  ok        có phát hiện (hoặc --no-llm), báo cáo dùng được
  0  empty     đầu vào rỗng/không tồn tại — KHÔNG phải "không có lỗ hổng"
  2  invalid_input  đọc được dòng nào cũng hỏng; không ghi phát hiện nào
  3  degraded  bật LLM nhưng MỌI nhóm đều phải rơi về fallback
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

# Import sau khi chỉnh sys.path. bench.py được tái dùng cho bộ đọc .env đã kiểm chứng —
# sweep.py cũng import nó theo đúng cách này, để không có bộ đọc .env thứ tư trong repo.
import bench as bm

import security_agent as sa

EXIT_CODES = {"ok": 0, "empty": 0, "invalid_input": 2, "degraded": 3}


def seed_env_from_dotenv() -> None:
    """Nạp .env cho các biến CHƯA có trong môi trường. Biến đã export thắng, nên
    `OPENCODE_BASE_URL=... ./scripts/analyze.py` vẫn ép được endpoint hỏng để thử
    kịch bản degraded."""
    try:
        values = bm.parse_env_file(bm.ENV_FILE)
    except bm.BenchError:
        return
    for key, value in values.items():
        if value:
            os.environ.setdefault(key, value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Phân tích cảnh báo bảo mật thành báo cáo JSONL đọc được bằng tiếng Việt.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--input", type=Path, default=sa.KB_ALERTS_PATH, metavar="PATH",
                        help="File JSONL cảnh báo đã chuẩn hoá (mặc định data/kb/alerts.jsonl).")
    source.add_argument("--from-run", metavar="KIND/NAME",
                        help="Nạp thẳng từ một thư mục run qua normalizer v1.1,\n"
                             "ví dụ bench/baseline. Loại trừ lẫn nhau với --input.")
    parser.add_argument("--out", type=Path, default=sa.ANALYSIS_DIR, metavar="DIR",
                        help="Thư mục ghi report.jsonl + report.meta.json (mặc định data/analysis).")
    parser.add_argument("--limit", type=int, default=None, metavar="N",
                        help="Chỉ đưa N nhóm nặng nhất cho mô hình; phần còn lại vẫn thành\n"
                             "phát hiện fallback nên phép cộng bảo toàn vẫn đúng.")
    parser.add_argument("--top-k", type=int, default=3, metavar="N",
                        help="Số tài liệu KB lấy cho mỗi nhóm (mặc định 3).")
    parser.add_argument("--min-score", type=float, default=0.05, metavar="F",
                        help="Ngưỡng tương đồng KB (mặc định 0.05).")
    parser.add_argument("--no-llm", action="store_true",
                        help="Chạy tất định: 0 lần gọi mạng, output lặp lại giống hệt từng byte.")
    parser.add_argument("--model", default=None, metavar="ID",
                        help="Ghi đè mô hình phân tích (mặc định CUSTOM_SCAN_MODEL).")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Bỏ qua bước hỏi xác nhận chi phí.")
    return parser


def print_summary(report: sa.AnalysisReport, written: sa.WriteResult) -> None:
    meta = report.meta

    # Phép cộng bảo toàn, in ra dưới dạng biểu thức đã tính: mỗi dòng đọc vào phải
    # nằm ở đúng một trong ba chỗ, nếu không thì có thứ gì đó đã bị rơi âm thầm.
    occurrences = sum(finding.evidence.occurrence_count for finding in report.findings)
    total = occurrences + meta.exact_duplicates_removed + meta.alerts_skipped
    print(f"\nBảo toàn: {occurrences} + {meta.exact_duplicates_removed} + "
          f"{meta.alerts_skipped} == {meta.alerts_read} -> "
          f"{total == meta.alerts_read} (meta.accounted_for={meta.accounted_for})")

    print(f"Trạng thái: {meta.status}")
    print(f"Nguồn vào: {meta.input_source} "
          f"({meta.alerts_read} dòng đọc, {meta.alerts_valid} hợp lệ, "
          f"{meta.alerts_skipped} bỏ qua) -> {meta.groups} nhóm -> {meta.findings} phát hiện")

    if meta.skipped:
        print("Dòng bị bỏ qua:")
        for record in meta.skipped:
            print(f"  - dòng {record.line_no}: {record.reason}")
            print(f"      {record.raw}")

    # Xếp theo SEVERITY_RANK, không theo SEVERITIES (là một set — thứ tự lặp đổi
    # giữa các tiến trình, cột số sẽ nhảy chỗ mỗi lần chạy).
    order = sorted(sa.SEVERITY_RANK, key=lambda name: -sa.SEVERITY_RANK[name])
    by_severity = {level: 0 for level in order}
    for finding in report.findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
    print("Theo mức độ: " + ", ".join(f"{k}={v}" for k, v in by_severity.items()))

    sources = {"llm": 0, "fallback": 0}
    for finding in report.findings:
        sources[finding.analysis_source] += 1
    print(f"Nguồn phân tích: llm={sources['llm']}, fallback={sources['fallback']}")

    print(f"Lần gọi mô hình: {meta.llm_calls}, thất bại: {meta.llm_failures}")
    if meta.llm_failure_reasons:
        for reason, count in meta.llm_failure_reasons.items():
            print(f"  - {reason}: {count}")
    if meta.dropped_kb_ids:
        print(f"  - doc_id mô hình bịa ra, đã loại: {meta.dropped_kb_ids}")

    print(f"Token: {meta.total_tokens}  |  Thời gian: {meta.duration_seconds}s")
    if meta.prompt_sha256:
        print(f"Prompt: {meta.prompt_path} v{meta.prompt_version} sha256={meta.prompt_sha256}")
    print(f"Ghi ra: {written.jsonl_path}")
    print(f"        {written.meta_path}")

    if meta.status == "empty":
        print("\nĐầu vào RỖNG (không phải 'không tìm thấy lỗ hổng') — "
              "hãy kiểm tra lại đường dẫn --input.")
    elif meta.status == "invalid_input":
        print("\nMọi dòng đọc được đều hỏng — không ghi phát hiện nào. "
              "Xem danh sách dòng bị bỏ qua ở trên.")
    elif meta.status == "degraded":
        print("\nSUY GIẢM: bật LLM nhưng MỌI nhóm đều rơi về fallback. "
              "Báo cáo vẫn được ghi và mọi phát hiện đều gắn nhãn fallback, "
              "nhưng đây KHÔNG phải một lần chạy thành công.")


def main() -> int:
    args = build_parser().parse_args()

    if args.top_k < 1:
        raise SystemExit("--top-k phải >= 1")
    if args.limit is not None and args.limit < 0:
        raise SystemExit("--limit phải >= 0")

    if not args.no_llm:
        seed_env_from_dotenv()

    # Ước lượng trước khi tiêu tiền: nạp và gộp nhóm (cả hai đều thuần/chỉ đọc) để
    # biết chính xác sẽ gọi bao nhiêu lần, rồi mới hỏi. FR5 guard shape.
    load = sa.load_alerts(input_path=args.input, from_run=args.from_run)
    groups = sa.group_alerts(load.alerts)
    estimate = sa.estimate_analysis_cost(groups, limit=args.limit, model=args.model)

    if not args.no_llm and estimate.call_count > 0:
        print(estimate.warning_text)
        if not args.yes and sys.stdin.isatty():
            answer = input(f"\n{estimate.call_count} lần gọi trả phí. Tiếp tục? [y/N] ")
            if answer.strip().lower() not in ("y", "yes"):
                print("Đã huỷ.")
                return 0

    def progress(position: int, total: int, group_key: str) -> None:
        # flush bắt buộc: stdout của tiến trình con bị đệm theo khối, thiếu flush thì
        # cả cột tiến độ chỉ hiện ra lúc chạy xong (lỗi đã ghi trong README).
        print(f"[{position}/{total}] {group_key}", flush=True)

    report = sa.analyze(
        input_path=args.input,
        from_run=args.from_run,
        top_k=args.top_k,
        min_score=args.min_score,
        limit=args.limit,
        no_llm=args.no_llm,
        model=args.model,
        progress=progress,
    )
    written = sa.write_report(report, out_dir=args.out)
    print_summary(report, written)
    return EXIT_CODES[report.meta.status]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except sa.PromptMissingError as exc:
        print(f"\nLỗi: {exc}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\nĐã huỷ.", file=sys.stderr)
        sys.exit(130)
