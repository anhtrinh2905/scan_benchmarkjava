# Scan BenchmarkJava bằng Metis

Chạy Metis trên [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava), đo thời gian / token và chấm precision–recall theo ground truth (`expectedresults-1.2.csv`). Không dùng LLM-judge.

Phạm vi mặc định: **100 test đầu** (`BenchmarkTest00001` …) — 75 TP / 25 FP.

## Yêu cầu

| Thành phần | Ghi chú |
| --- | --- |
| [`uv`](https://docs.astral.sh/uv/) | Bắt buộc — script chạy qua `uv run` |
| `metis/` | Clone [arm/metis](https://github.com/arm/metis) ở thư mục gốc repo |
| `BenchmarkJava/` | Clone [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) ở thư mục gốc repo |
| `semgrep` | Chỉ cần cho `scripts/ablation.py` (arm `static`) |
| OpenCode API key | Model quét qua OpenAI-compatible endpoint |

Đường dẫn workspace **không được có khoảng trắng** (Metis tách `--command` theo whitespace).

## Cấu hình

```bash
cp .env.example .env
# Điền OPENCODE_API_KEY; chỉnh CUSTOM_SCAN_MODEL / OPENCODE_BASE_URL nếu cần
```

| Biến | Ý nghĩa |
| --- | --- |
| `CUSTOM_SCAN_MODEL` | Model id dùng để quét (ví dụ `deepseek-v4-flash`) |
| `OPENCODE_BASE_URL` | Base URL OpenAI-compatible (mặc định OpenCode Go) |
| `OPENCODE_API_KEY` | API key |

## Chạy nhanh

Xem trước lệnh (không gọi LLM):

```bash
./scripts/bench.py --dry-run
./scripts/sweep.py --dry-run
./scripts/ablation.py --dry-run
```

Smoke rẻ trước khi full:

```bash
./scripts/bench.py --sample 6 -y
./scripts/sweep.py --sample 6 -y
./scripts/ablation.py --sample 6 -y
```

## Ba lần chạy chính

| Lần | Script | Mục đích | Lệnh |
| --- | --- | --- | --- |
| 1 | `scripts/bench.py` | Baseline Metis (`review_file` × N) | `./scripts/bench.py --sample 100 -y` |
| 2 | `scripts/sweep.py` | So variant tham số (`review_code` một lần / variant) | `./scripts/sweep.py --sample 100 -y` |
| 3 | `scripts/ablation.py` | So discovery: prompt / harness / Semgrep | `./scripts/ablation.py --sample 100 -y` |

`-y` bỏ bước hỏi xác nhận. Full run tốn token và thời gian.

### 1. Baseline — `scripts/bench.py`

```bash
./scripts/bench.py --sample 100 -y
./scripts/bench.py --tag baseline --repeat 3 -y   # đo ổn định run-to-run
./scripts/bench.py --rescore                      # chỉ chấm lại từ SARIF đã có
./scripts/bench.py --force                        # bỏ cache, chạy lại
```

Kết quả: `results/<tag>/` (mặc định `results/baseline/`) — `bench_summary.json`, scorecard markdown, SARIF từng test.

Cờ hay dùng: `--parallel`, `--only SUB`, `--no-triage`, `--max-workers`, `--max-rounds`.

### 2. Sweep — `scripts/sweep.py`

5 variant tuần tự: `baseline`, `workers_10`, `rounds_3`, `reach_1`, `lean_combo`.

```bash
./scripts/sweep.py --sample 100 -y
./scripts/sweep.py --only baseline rounds_3 -y
./scripts/sweep.py --rescore
./scripts/sweep.py --force
```

Kết quả: `results/sweep/<variant>/` + `results/sweep/compare.{md,csv,json}`.

### 3. Ablation — `scripts/ablation.py`

| Arm | Cấu hình |
| --- | --- |
| `prompt_only` | `--tools none`, không triage |
| `harness` | `--tools navigation`, có triage (= baseline sweep) |
| `static` | Semgrep → Metis `triage` |
| `B_union_C` | Gộp offline SARIF harness ∪ static (0 token thêm) |

```bash
./scripts/ablation.py --sample 100 -y
./scripts/ablation.py --only harness static -y
./scripts/ablation.py --rescore
./scripts/ablation.py --force
```

Kết quả: `results/ablation/<arm>/` + `results/ablation/compare.{md,csv,json}` (Pareto / Youden per 1M token).

## Ghi chú

- Lần chạy sau với cùng tham số sẽ dùng **cache** (`[cache]`) — thêm `--force` để chạy lại.
- `--rescore` chỉ đọc SARIF đã có, không gọi Metis/Semgrep.
- Báo cáo phân tích kết quả: xem `2026-07-29_TrinhThiLanAnh_Week1.md`.

## Giao diện Streamlit (đang xây dựng)

Dự án giờ có `pyproject.toml`/`uv.lock` ở gốc (dependency đầu tiên: `streamlit`) — 3 script
CLI ở trên vẫn chạy y nguyên qua `uv run --script`, không phụ thuộc vào file này.

```bash
uv sync
uv run streamlit run app.py   # mở http://localhost:8501
```

Hiện tại mới có trang khung (scaffold) — chọn scan/variant/sample, chạy nền, và xem kết
quả ngay trên UI sẽ lần lượt lên ở các card tiếp theo.
