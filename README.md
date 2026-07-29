# Scan BenchmarkJava bằng Metis

Chạy Metis trên [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava), đo thời gian / token và chấm precision–recall theo ground truth (`expectedresults-1.2.csv`). Không dùng LLM-judge.

Phạm vi mặc định: **100 test đầu** (`BenchmarkTest00001` …) — 75 TP / 25 FP.

## Yêu cầu

| Thành phần | Ghi chú |
| --- | --- |
| [`uv`](https://docs.astral.sh/uv/) | Bắt buộc — script chạy qua `uv run` |
| `metis/` | Clone [arm/metis](https://github.com/arm/metis) cạnh các script |
| `BenchmarkJava/` | Clone [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) cạnh các script |
| `semgrep` | Chỉ cần cho `ablation.py` (arm `static`) |
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
./bench.py --dry-run
./sweep.py --dry-run
./ablation.py --dry-run
```

Smoke rẻ trước khi full:

```bash
./bench.py --sample 6 -y
./sweep.py --sample 6 -y
./ablation.py --sample 6 -y
```

## Ba lần chạy chính

| Lần | Script | Mục đích | Lệnh |
| --- | --- | --- | --- |
| 1 | `bench.py` | Baseline Metis (`review_file` × N) | `./bench.py --sample 100 -y` |
| 2 | `sweep.py` | So variant tham số (`review_code` một lần / variant) | `./sweep.py --sample 100 -y` |
| 3 | `ablation.py` | So discovery: prompt / harness / Semgrep | `./ablation.py --sample 100 -y` |

`-y` bỏ bước hỏi xác nhận. Full run tốn token và thời gian.

### 1. Baseline — `bench.py`

```bash
./bench.py --sample 100 -y
./bench.py --tag baseline --repeat 3 -y   # đo ổn định run-to-run
./bench.py --rescore                      # chỉ chấm lại từ SARIF đã có
./bench.py --force                        # bỏ cache, chạy lại
```

Kết quả: `results/<tag>/` (mặc định `results/baseline/`) — `bench_summary.json`, scorecard markdown, SARIF từng test.

Cờ hay dùng: `--parallel`, `--only SUB`, `--no-triage`, `--max-workers`, `--max-rounds`.

### 2. Sweep — `sweep.py`

5 variant tuần tự: `baseline`, `workers_10`, `rounds_3`, `reach_1`, `lean_combo`.

```bash
./sweep.py --sample 100 -y
./sweep.py --only baseline rounds_3 -y
./sweep.py --rescore
./sweep.py --force
```

Kết quả: `results/sweep/<variant>/` + `results/sweep/compare.{md,csv,json}`.

### 3. Ablation — `ablation.py`

| Arm | Cấu hình |
| --- | --- |
| `prompt_only` | `--tools none`, không triage |
| `harness` | `--tools navigation`, có triage (= baseline sweep) |
| `static` | Semgrep → Metis `triage` |
| `B_union_C` | Gộp offline SARIF harness ∪ static (0 token thêm) |

```bash
./ablation.py --sample 100 -y
./ablation.py --only harness static -y
./ablation.py --rescore
./ablation.py --force
```

Kết quả: `results/ablation/<arm>/` + `results/ablation/compare.{md,csv,json}` (Pareto / Youden per 1M token).

## Ghi chú

- Lần chạy sau với cùng tham số sẽ dùng **cache** (`[cache]`) — thêm `--force` để chạy lại.
- `--rescore` chỉ đọc SARIF đã có, không gọi Metis/Semgrep.
- Báo cáo phân tích kết quả: xem `2026-07-29_TrinhThiLanAnh_Week1.md`.
