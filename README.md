# Scan BenchmarkJava bằng Metis

**Live demo:** [https://scan-benchmarkjava-production.up.railway.app](https://scan-benchmarkjava-production.up.railway.app)
(bản public, read-only — chỉ xem Results + Knowledge Base, không chạy được scan, xem mục [Deploy](#deploy-railway-chế-độ-read-only))

Chạy Metis trên [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava), đo thời gian / token và chấm precision–recall theo ground truth (`expectedresults-1.2.csv`). Không dùng LLM-judge.

Phạm vi mặc định: **100 test đầu** (`BenchmarkTest00001` …) — 75 TP / 25 FP.

## Hướng dẫn chạy dự án

### Yêu cầu


| Thành phần                         | Ghi chú                                                                                                                 |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `[uv](https://docs.astral.sh/uv/)` | Bắt buộc — script và app chạy qua `uv run`                                                                              |
| `metis/`                           | Clone [arm/metis](https://github.com/arm/metis) ở thư mục gốc repo (không thuộc repo này)                               |
| `BenchmarkJava/`                   | Clone [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) ở thư mục gốc repo (không thuộc repo này) |
| `semgrep`                          | Chỉ cần cho `scripts/ablation.py` (arm `static`)                                                                        |
| OpenCode API key                   | Model quét qua OpenAI-compatible endpoint                                                                               |


Đường dẫn workspace **không được có khoảng trắng** (Metis tách `--command` theo whitespace).

### Cài đặt & cấu hình

```bash
git clone https://github.com/anhtrinh2905/scan_benchmarkjava.git
cd scan_benchmarkjava
uv sync

cp .env.example .env
# Điền OPENCODE_API_KEY; chỉnh CUSTOM_SCAN_MODEL / OPENCODE_BASE_URL nếu cần
```


| Biến                | Ý nghĩa                                           |
| ------------------- | ------------------------------------------------- |
| `CUSTOM_SCAN_MODEL` | Model id dùng để quét (ví dụ `deepseek-v4-pro`)   |
| `OPENCODE_BASE_URL` | Base URL OpenAI-compatible (mặc định OpenCode Go) |
| `OPENCODE_API_KEY`  | API key                                           |




### Chạy giao diện Streamlit

```bash
uv run streamlit run src/app.py   # mở http://localhost:8501
```



### Chạy các script quét

```bash
./scripts/bench.py --sample 100 -y      # 1. Baseline
./scripts/sweep.py --sample 100 -y      # 2. Sweep tham số
./scripts/ablation.py --sample 100 -y   # 3. Ablation discovery
```

Chi tiết từng script — xem mục [Ba lần chạy chính](#ba-lần-chạy-chính) bên dưới.

## Cấu trúc thư mục

Chỉ liệt kê phần đã commit lên GitHub (`git ls-files`); `metis/` và `BenchmarkJava/` là clone ngoài, bị `.gitignore`.


| Thư mục / File               | Vai trò                                                                                                                                  |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `src/`                       | Ứng dụng Streamlit: `app.py`, `scan_runner.py`, `kb_search.py`, `alert_normalizer.py`                                                    |
| `scripts/`                   | Công cụ dòng lệnh cho dev: `bench.py`, `sweep.py`, `ablation.py` — không phải app                                                        |
| `data/kb/`                   | Kho tri thức (Knowledge Base): docs OWASP Top 10, ví dụ lỗ hổng, rule Semgrep tham khảo                                                  |
| `data/rules/`                | Rule Semgrep tùy biến cho BenchmarkJava (dùng ở arm `static` của ablation)                                                               |
| `data/results/`              | Kết quả quét đã bake sẵn (`bench_summary.json`, `scorecard.md`, `compare.*`, `detail.json`) — phục vụ trang Results khi deploy read-only |
| `docs/specs/`                | Spec kỹ thuật (`spec-ablation-runner.md`)                                                                                                |
| `tests/e2e/`                 | Kiểm thử tự động — smoke test Playwright trên bản deploy                                                                                 |
| `reports/`                   | Báo cáo tuần đã nộp (`2026-07-29_..._Week1.md`, …) — cố định, không sửa lại sau khi nộp                                                  |
| `.streamlit/`                | Config Streamlit (`config.toml`)                                                                                                         |
| `Dockerfile`, `railway.toml` | Build & deploy Railway                                                                                                                   |
| `pyproject.toml`, `uv.lock`  | Quản lý dependency bằng `uv`                                                                                                             |




## Ba lần chạy chính


| Lần | Script                | Mục đích                                             | Lệnh                                    |
| --- | --------------------- | ---------------------------------------------------- | --------------------------------------- |
| 1   | `scripts/bench.py`    | Baseline Metis (`review_file` × N)                   | `./scripts/bench.py --sample 100 -y`    |
| 2   | `scripts/sweep.py`    | So variant tham số (`review_code` một lần / variant) | `./scripts/sweep.py --sample 100 -y`    |
| 3   | `scripts/ablation.py` | So discovery: prompt / harness / Semgrep             | `./scripts/ablation.py --sample 100 -y` |


`-y` bỏ bước hỏi xác nhận. Full run tốn token và thời gian.

### 1. Baseline — `scripts/bench.py`

```bash
./scripts/bench.py --sample 100 -y
./scripts/bench.py --tag baseline --repeat 3 -y   # đo ổn định run-to-run
./scripts/bench.py --rescore                      # chỉ chấm lại từ SARIF đã có
./scripts/bench.py --force                        # bỏ cache, chạy lại
```

Kết quả: `data/results/<tag>/` (mặc định `data/results/baseline/`) — `bench_summary.json`, scorecard markdown, SARIF từng test.

Cờ hay dùng: `--parallel`, `--only SUB`, `--no-triage`, `--max-workers`, `--max-rounds`.

### 2. Sweep — `scripts/sweep.py`

5 variant tuần tự: `baseline`, `workers_10`, `rounds_3`, `reach_1`, `lean_combo`.

```bash
./scripts/sweep.py --sample 100 -y
./scripts/sweep.py --only baseline rounds_3 -y
./scripts/sweep.py --rescore
./scripts/sweep.py --force
```

Kết quả: `data/results/sweep/<variant>/` + `data/results/sweep/compare.{md,csv,json}`.

### 3. Ablation — `scripts/ablation.py`


| Arm           | Cấu hình                                           |
| ------------- | -------------------------------------------------- |
| `prompt_only` | `--tools none`, không triage                       |
| `harness`     | `--tools navigation`, có triage (= baseline sweep) |
| `static`      | Semgrep → Metis `triage`                           |
| `B_union_C`   | Gộp offline SARIF harness ∪ static (0 token thêm)  |


```bash
./scripts/ablation.py --sample 100 -y
./scripts/ablation.py --only harness static -y
./scripts/ablation.py --rescore
./scripts/ablation.py --force
```

Kết quả: `data/results/ablation/<arm>/` + `data/results/ablation/compare.{md,csv,json}` (Pareto / Youden per 1M token).

## Ghi chú

- Lần chạy sau với cùng tham số sẽ dùng **cache** (`[cache]`) — thêm `--force` để chạy lại.
- `--rescore` chỉ đọc SARIF đã có, không gọi Metis/Semgrep.
- Báo cáo phân tích kết quả: xem `reports/`.



## Deploy (Railway, chế độ read-only)

Bản deploy dùng chung **công khai, không cần đăng nhập** — và **không chạy được scan**,
**không giữ** `OPENCODE_API_KEY`. Nó chỉ phục vụ Results + Knowledge Base từ dữ liệu đã bake
sẵn trong image. Cái giữ an toàn là instance không làm được gì, chứ không phải khó truy cập.
Muốn quét thật thì chạy local như phần [Hướng dẫn chạy dự án](#hướng-dẫn-chạy-dự-án) trên.

Đang chạy tại: [https://scan-benchmarkjava-production.up.railway.app](https://scan-benchmarkjava-production.up.railway.app)


| Biến môi trường    | Đặt ở đâu               | Ý nghĩa                                                                                                         |
| ------------------ | ----------------------- | --------------------------------------------------------------------------------------------------------------- |
| `SCAN_UI_READONLY` | Dockerfile đặt sẵn `=1` | `1`/`true`/`yes` → chặn scan ở tầng `scan_runner`, không chỉ ẩn nút. Giá trị khác (kể cả gõ sai) → chế độ local |
| `PORT`             | Railway tự đặt          | Cổng Streamlit lắng nghe                                                                                        |


Các bước:

1. Push repo lên GitHub.
2. Railway → **New Project** → **Deploy from GitHub repo** → chọn repo này. `railway.toml`
  khai báo sẵn builder `dockerfile` và healthcheck `/_stcore/health`.
3. **Variables** → không cần thêm gì. Đặc biệt không thêm `OPENCODE_API_KEY`.
4. **Settings → Networking** → Generate Domain.

Chạy thử image y hệt bản deploy ở máy local:

```bash
docker build -t scan-benchmarkjava .
docker run --rm -p 8501:8501 scan-benchmarkjava

railway up --detach #Re-deploy
```

Bỏ `-e SCAN_UI_READONLY` về `0` nếu muốn container chạy đầy đủ — nhưng khi đó phải tự mount
`metis/` + `BenchmarkJava/` và cấp API key, vì image không chứa chúng.

## Hạn chế đã biết

Rủi ro/nợ kỹ thuật đã cân nhắc và chấp nhận có chủ đích, không phải bị bỏ sót:

- **Bản deploy công khai, không có access control.** Cổng mật khẩu đã bị gỡ khỏi code
(không chỉ tắt) sau khi cân nhắc: nội dung public chỉ là scorecard (model, thời gian,
token, precision/recall) và tài liệu OWASP công khai — không có chuỗi dạng
credential. Cái giữ an toàn là instance không chạy được scan và không giữ
`OPENCODE_API_KEY`, không phải việc khó truy cập. Muốn khoá lại phải thêm code lại từ
đầu, vì cơ chế đã bị xoá chứ không phải tắt.
- **Một lần quét lỗi ngay từ đầu (model từ chối request) trông y hệt một lần quét sạch
trong mọi kết quả hiển thị.** Từng xảy ra khi model quét trả lỗi 403 và Metis vẫn thoát
mã 0 với `reviews: []`, khiến `sweep.py` ghi nhận nhầm 3 variant là "chạy hợp lệ, 0%
recall". Chỉ phát hiện được bằng cách so token count thủ công giữa các run. Đã khắc phục
tạm bằng cách đổi model quét; **chưa khắc phục tận gốc** — hệ thống vẫn không tự cảnh báo
khi `usage.total_tokens == 0` mà `len(per_test) > 0`.
- **Thanh tiến trình (progress bar) đứng yên khi quét ít hơn 3 file** vì một dòng `print`
ở `bench.py` thiếu `flush=True`, nên log không tới nơi cho tới khi tiến trình kết thúc.
Cách sửa chỉ là thêm một keyword argument, nhưng chưa áp dụng vì nằm ngoài phạm vi các
card đã khoá file `scripts/*.py`.

