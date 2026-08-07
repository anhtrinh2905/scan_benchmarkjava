#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests>=2.34.2", "scikit-learn>=1.9.0"]
# ///
"""Dựng sẵn câu trả lời cho các câu hỏi gợi ý của trang Hỏi đáp.

Bảy nút gợi ý trong `report_chat.SUGGESTED_QUESTIONS` là một danh sách đóng, hỏi về một
báo cáo chỉ đổi khi chạy lại `scripts/analyze.py`. Bắt mỗi người xem đợi hai lần gọi mô
hình (~20s) để nhận lại đúng đoạn văn mô hình đã viết hôm qua là trả tiền cho một thứ
người đọc không nhận được gì thêm — trừ thời gian chờ.

Script này chạy từng câu một lần với mô hình thật, rồi ghi lời văn kèm **mô hình nào viết,
tốn bao nhiêu token, mất bao lâu** vào `data/analysis/chat_cache.json`. Trang web đọc file
đó và trả lời tức thì.

Chỉ có LỜI VĂN được cache. Mọi con số vẫn do `report_query` tính lại mỗi lần mở trang —
xem `report_chat.prebaked_answer()`: nó chạy lại truy vấn, đối chiếu lại từng con số trong
lời văn với bảng vừa tính, và bỏ cache nếu hai bên không khớp.

  ./scripts/bake_chat.py                  # bake cả 7 câu bằng mô hình thật — TỐN PHÍ, sẽ hỏi
  ./scripts/bake_chat.py -y               # không hỏi
  ./scripts/bake_chat.py --no-llm         # bake bằng đường tất định (0 token) — để thử, không tốn tiền
  ./scripts/bake_chat.py --only "Tổng quan báo cáo này có gì?"
  ./scripts/bake_chat.py --show           # in cache hiện có rồi thoát

Mã thoát:

  0  bake xong, mọi câu đều có câu trả lời
  1  không có báo cáo để bake (chạy `./scripts/analyze.py` trước)
  3  bake xong nhưng MỌI câu đều rơi về đường tất định — cache dùng được, chỉ là không
     có câu nào do mô hình viết; giống hệt nghĩa của `degraded` ở analyze.py
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

# Cùng một bộ đọc .env đã kiểm chứng mà analyze.py dùng — repo không cần bộ thứ tư.
import bench as bm

import report_chat
import security_agent as sa


def seed_env_from_dotenv() -> None:
    """Nạp .env cho các biến CHƯA có trong môi trường; biến đã export thắng."""
    try:
        values = bm.parse_env_file(bm.ENV_FILE)
    except bm.BenchError:
        return
    for key, value in values.items():
        if value:
            os.environ.setdefault(key, value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Dựng sẵn câu trả lời cho các câu hỏi gợi ý của trang Hỏi đáp.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=report_chat.CHAT_CACHE_PATH,
        help=f"file cache cần ghi (mặc định: {report_chat.CHAT_CACHE_PATH})",
    )
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=sa.ANALYSIS_DIR,
        help="thư mục chứa report.jsonl (mặc định: data/analysis)",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="CÂU HỎI",
        help="chỉ bake câu này (lặp lại được); mặc định bake cả bảy câu gợi ý",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="bake bằng đường tất định — 0 lần gọi mạng, 0 token, kết quả lặp lại giống hệt",
    )
    parser.add_argument("-y", "--yes", action="store_true", help="không hỏi xác nhận")
    parser.add_argument("--show", action="store_true", help="in cache hiện có rồi thoát")
    return parser


def show_cache(path: Path) -> int:
    payload = report_chat.load_prebaked(path)
    if not payload:
        print(f"Chưa có cache dùng được ở {path}")
        return 0
    print(f"Cache: {path}")
    print(f"  bake lúc      : {payload.get('baked_at')}")
    print(f"  vân tay báo cáo: {payload.get('report_fingerprint')}")
    for entry in payload.get("entries", []):
        print(
            f"  - {entry.get('question')}\n"
            f"      mô hình {entry.get('model') or '—'} · "
            f"{entry.get('tokens', 0):,} token · {entry.get('elapsed_seconds', 0):.1f}s · "
            f"lời văn: {entry.get('answer_source')}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    seed_env_from_dotenv()

    if args.show:
        return show_cache(args.out)

    try:
        report = sa.load_report(args.report_dir)
    except sa.ReportCorruptError as exc:
        print(f"Báo cáo hỏng, không đọc được: {exc}", file=sys.stderr)
        return 1
    if report is None:
        print(
            f"Không có báo cáo nào ở {args.report_dir} — chạy ./scripts/analyze.py trước.",
            file=sys.stderr,
        )
        return 1

    questions = list(args.only) or list(report_chat.SUGGESTED_QUESTIONS)
    use_llm = not args.no_llm and report_chat.model_available() and bool(report_chat.default_model())

    if not args.no_llm and not use_llm:
        print(
            "Không có OPENCODE_API_KEY/OPENCODE_BASE_URL/CUSTOM_SCAN_MODEL — "
            "bake bằng đường tất định.",
            file=sys.stderr,
        )

    if use_llm and not args.yes:
        # Cùng một luật với analyze.py: hỏi trước khi tiêu tiền, không hỏi lại sau.
        print(f"Sắp gọi mô hình {report_chat.default_model()} cho {len(questions)} câu hỏi")
        print("(2 lần gọi mỗi câu: chọn truy vấn + viết lời) — TỐN PHÍ.")
        if input("Tiếp tục? [y/N] ").strip().lower() not in {"y", "yes"}:
            print("Đã huỷ.")
            return 0

    turns = []
    for index, question in enumerate(questions, start=1):
        print(f"[{index}/{len(questions)}] {question}", flush=True)
        turn = report_chat.answer(question, report, use_llm=use_llm)
        turns.append(turn)
        print(
            f"      lời văn: {turn.answer_source} · truy vấn: {turn.route_source} · "
            f"{turn.tokens:,} token · {turn.elapsed_seconds:.1f}s"
        )
        for note in turn.notes:
            print(f"      ! {note}")

    # Merged over whatever is already there, so `--only` re-bakes one question without
    # throwing away the other six.
    payload = report_chat.bake_payload(
        report, turns, existing=report_chat.load_prebaked(args.out)
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    from_model = sum(1 for turn in turns if turn.answer_source == "llm")
    total_tokens = sum(turn.tokens for turn in turns)
    total_seconds = sum(turn.elapsed_seconds for turn in turns)
    print()
    print(f"Ghi ra: {args.out}")
    print(f"Vân tay báo cáo: {payload['report_fingerprint']}")
    print(
        f"{len(turns)} câu · {from_model} câu do mô hình viết, "
        f"{len(turns) - from_model} câu từ mẫu · {total_tokens:,} token · {total_seconds:.1f}s"
    )

    # Bake bằng --no-llm là lựa chọn có chủ ý, không phải sự cố, nên nó không phải degraded.
    if use_llm and from_model == 0:
        print(
            "MỌI câu đều rơi về mẫu — cache vẫn dùng được nhưng không có lời văn nào "
            "do mô hình viết.",
            file=sys.stderr,
        )
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
