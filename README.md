# Scan BenchmarkJava bằng Metis

**Live demo:** [https://scan-benchmarkjava-production.up.railway.app](https://scan-benchmarkjava-production.up.railway.app)
(bản public, read-only — chỉ xem Results + Knowledge Base, không chạy được scan, xem mục [Deploy](#deploy-railway-chế-độ-read-only))

Chạy Metis trên [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava), đo thời gian / token và chấm precision–recall theo ground truth (`expectedresults-1.2.csv`). Không dùng LLM-judge.

Phạm vi mặc định: **100 test đầu** (`BenchmarkTest00001` …) — 75 TP / 25 FP.

## Hướng dẫn chạy dự án

### Yêu cầu


| Thành phần                         | Ghi chú                                                                                                                 |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| [`uv`](https://docs.astral.sh/uv/) | Bắt buộc — script và app chạy qua `uv run`                                                                              |
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
| `src/app.py`                 | Ứng dụng Streamlit chính — điều khiển scan, xem Results/Matrix/Knowledge Base                                                           |
| `src/scan_runner.py`         | Seam gọi Metis (chạy scan nền, đọc SARIF/summary) — `app.py` chỉ đọc qua đây, không tự parse file kết quả                               |
| `src/kb_search.py`           | Search Knowledge Base: keyword (TF-IDF/cosine) + semantic (embedding OPENCODE, fallback TF-IDF+LSA)                                     |
| `src/alert_normalizer.py`    | **Chuẩn hóa alert** — gộp SARIF (semgrep) và `bench_summary.json` (Metis) về một schema `Alert` phẳng, xem chi tiết [bên dưới](#chuẩn-hóa-alert-alert_normalizerpy) |
| `src/security_agent.py`      | **Agent phân tích bảo mật** — gộp nhóm cảnh báo, tra KB, gọi mô hình đúng 1 lần/nhóm, sinh báo cáo, xem [bên dưới](#agent-phân-tích-bảo-mật-security_agentpy) |
| `src/prompts/`               | System prompt của agent (`security_analyst.md`) — file nguồn có version, hash vào mọi báo cáo                                            |
| `scripts/`                   | Công cụ dòng lệnh cho dev: `bench.py`, `sweep.py`, `ablation.py`, `analyze.py` — không phải app                                          |
| `data/kb/`                   | Kho tri thức (Knowledge Base): docs OWASP Top 10, ví dụ lỗ hổng, rule Semgrep tham khảo                                                  |
| `data/rules/`                | Rule Semgrep tùy biến cho BenchmarkJava (dùng ở arm `static` của ablation)                                                               |
| `data/results/`              | Kết quả quét đã bake sẵn (`bench_summary.json`, `scorecard.md`, `compare.*`, `detail.json`) — phục vụ trang Results khi deploy read-only |
| `data/analysis/`             | Báo cáo phân tích đã sinh sẵn (`report.jsonl` + `report.meta.json`) — phục vụ trang Security Report khi deploy read-only                 |
| `docs/specs/`                | Spec kỹ thuật (`spec-ablation-runner.md`)                                                                                                |
| `tests/`                     | Test đơn vị của agent (`test_security_agent.py`, 76 test, mock toàn bộ mạng) + fixture                                                   |
| `tests/e2e/`                 | Kiểm thử tự động — smoke test Playwright trên bản deploy                                                                                 |
| `reports/`                   | Báo cáo tuần đã nộp (`2026-07-29_..._Week1.md`, …) — cố định, không sửa lại sau khi nộp                                                  |
| `.streamlit/`                | Config Streamlit (`config.toml`)                                                                                                         |
| `Dockerfile`, `railway.toml` | Build & deploy Railway                                                                                                                   |
| `pyproject.toml`, `uv.lock`  | Quản lý dependency bằng `uv`                                                                                                             |




### Chuẩn hóa alert (`alert_normalizer.py`)

`src/alert_normalizer.py` là module thư viện độc lập (không có `st.*`, không tự chạy) —
đưa kết quả từ 2 nguồn khác định dạng về **một schema `Alert` phẳng** để Knowledge Base
đọc chung, không phải viết riêng logic parse cho từng tool:

| Hàm | Input | Chuẩn hóa từ |
| --- | --- | --- |
| `normalize_sarif(sarif_path, tool)` | file SARIF (`.sarif`/`.json`) | Semgrep — đọc `runs[].results[]`, suy `severity` từ SARIF `level` (mặc định `medium` nếu rule không set), tách `CWE-\d+` từ message |
| `normalize_bench_summary(summary_path)` | `bench_summary.json` | Metis — đọc `findings{test_name: [...]}`, map thẳng `severity`/`cwe_raw`/`line` do Metis đã trả có cấu trúc |
| `append_alerts(alerts, out_path=...)` | `list[Alert]` | Ghi nối (append) JSONL — hàm **duy nhất có side effect**, mặc định ghi vào `data/kb/alerts.jsonl` |

Schema `Alert` (dataclass): `tool` (`semgrep`/`metis`), `severity` (`critical`/`high`/`medium`/`low`/`info`), `file_or_url`, `title`, `description`, `rule_id`, `cwe`, `line`, `source_path`.

Hiện tại chưa có script/CLI nào gọi module này — đây là seam chuẩn bị cho card Knowledge
Base sắp tới (đọc `data/kb/alerts.jsonl` để hiển thị alert đã chuẩn hóa cạnh doc OWASP).
Muốn chạy thử chuẩn hóa thủ công:

```bash
cd src   # alert_normalizer.py import flat (như scan_runner.py/kb_search.py), cần chạy từ src/
```

```python
from pathlib import Path
from alert_normalizer import normalize_sarif, normalize_bench_summary, append_alerts

# đường dẫn tính từ repo root (ROOT trong alert_normalizer.py = parent.parent của src/)
alerts = normalize_sarif(Path("../data/results/ablation/static/semgrep.normalized.sarif"), tool="semgrep")
alerts += normalize_bench_summary(Path("../data/results/baseline/bench_summary.json"))
append_alerts(alerts)   # ghi nối vào data/kb/alerts.jsonl
```

Cả hai file input ở ví dụ trên là kết quả cục bộ sau khi chạy `scripts/ablation.py`/`scripts/bench.py`
(`semgrep.normalized.sarif` không nằm trong danh sách tracked của `data/results/`, xem
`.gitignore`) — chạy script tương ứng trước nếu máy bạn chưa có file này.

### Agent phân tích bảo mật (`security_agent.py`)

Biến `data/kb/alerts.jsonl` thành một báo cáo người đọc được: gộp cảnh báo cùng loại thành
nhóm, tra kho tri thức, gọi mô hình **đúng một lần cho mỗi nhóm**, rồi ghi ra JSONL. Không
tool-calling, không đa lượt — chi phí biết trước được, và phần lớn logic kiểm thử được offline.

Mô hình chỉ viết phần diễn giải. **File, số dòng, rule_id và CWE luôn do code điền** — mô hình
thậm chí không được nhận đường dẫn trong prompt, và nếu nó tự bịa ra thì đoạn đó bị vứt. Mức
nghiêm trọng và độ tin cậy mà mô hình trả về chỉ là *đề xuất*: Python kẹp mức nghiêm trọng
trong ±1 bậc so với mức công cụ tự báo, và ép sàn độ tin cậy khi bằng chứng mỏng.

```bash
./scripts/analyze.py                       # 111 cảnh báo — TỐN PHÍ, sẽ hỏi xác nhận
./scripts/analyze.py --no-llm              # tất định, 0 gọi mạng, output lặp lại giống hệt
./scripts/analyze.py --limit 3 -y          # chỉ đưa 3 nhóm nặng nhất cho mô hình
./scripts/analyze.py --from-run bench/baseline --no-llm
```

| Cờ | Mặc định | Ý nghĩa |
| --- | --- | --- |
| `--input PATH` | `data/kb/alerts.jsonl` | File JSONL cảnh báo đã chuẩn hóa |
| `--from-run KIND/NAME` | — | Nạp thẳng từ thư mục run qua `alert_normalizer` (loại trừ với `--input`) |
| `--out DIR` | `data/analysis` | Nơi ghi `report.jsonl` + `report.meta.json` |
| `--limit N` | — | Chỉ đưa N nhóm nặng nhất cho mô hình; phần còn lại vẫn thành phát hiện fallback |
| `--top-k N` | `3` | Số tài liệu KB lấy cho mỗi nhóm |
| `--min-score F` | `0.05` | Ngưỡng tương đồng KB |
| `--no-llm` | tắt | Chạy tất định, 0 lần gọi mạng |
| `--model ID` | `CUSTOM_SCAN_MODEL` | Ghi đè mô hình phân tích |
| `-y` / `--yes` | tắt | Bỏ bước hỏi xác nhận chi phí |

**Ba mã thoát** — thất bại phải phân biệt được, kể cả với script chỉ đọc mã thoát:

| Mã | Trạng thái | Nghĩa |
| --- | --- | --- |
| `0` | `ok` / `empty` | Có phát hiện; hoặc đầu vào **rỗng** (không phải "không có lỗ hổng") |
| `2` | `invalid_input` | Đọc được dòng nào cũng hỏng — mỗi dòng được liệt kê kèm số dòng và lý do |
| `3` | `degraded` | Bật LLM nhưng **mọi** nhóm đều rơi về fallback |

**System prompt:** `src/prompts/security_analyst.md` — file nguồn có `version:`, được hash
SHA-256 vào mọi báo cáo và từng phát hiện, nên "output thay đổi" luôn có lời giải thích. Nằm
trong `src/` chứ không phải `docs/` vì `.dockerignore` loại `/docs/`. Thiếu file hoặc file rỗng
→ agent từ chối chạy, không có prompt mặc định ẩn.

**Báo cáo ghi ra:** `data/analysis/report.jsonl` (JSONL thuần, mỗi dòng một phát hiện, nên
`wc -l` = số phát hiện) + `data/analysis/report.meta.json` (mọi giá trị theo lần chạy —
timestamp, token, thời gian — nằm hết ở đây, nhờ vậy file phát hiện ổn định từng byte giữa hai
lần chạy `--no-llm`). Cả hai **được commit vào git**: bản deploy không giữ API key nên không
thể tự sinh báo cáo.

Xem kết quả tại trang **Security Report** của app, hoặc trên bản deploy:
[/security-report](https://scan-benchmarkjava-production.up.railway.app/security-report).

Chạy test của agent (offline, 0 lần gọi mạng, không cần API key):

```bash
uv run pytest tests/test_security_agent.py -q
```

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
**không giữ** `OPENCODE_API_KEY`. Nó chỉ phục vụ Results + Matrix + Security Report +
Knowledge Base từ dữ liệu đã bake sẵn trong image. Cái giữ an toàn là instance không làm được
gì, chứ không phải khó truy cập. Muốn quét thật thì chạy local như phần
[Hướng dẫn chạy dự án](#hướng-dẫn-chạy-dự-án) trên.

Vì không có API key, bản deploy cũng **không thể tự sinh báo cáo phân tích** — nó chỉ hiển thị
`data/analysis/report.jsonl` đã được commit và nướng vào image, đúng như nó hiển thị kết quả
quét mà không tự quét được. Muốn báo cáo mới thì chạy `./scripts/analyze.py` ở local rồi commit
lại kết quả.

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
trong mọi kết quả hiển thị — đã vá ở agent phân tích, VẪN CHƯA vá ở ba script quét.**
Từng xảy ra khi model quét trả lỗi 403 và Metis vẫn thoát mã 0 với `reviews: []`, khiến
`sweep.py` ghi nhận nhầm 3 variant là "chạy hợp lệ, 0% recall". Chỉ phát hiện được bằng
cách so token count thủ công giữa các run.
  - **Đã vá — chỉ trong `src/security_agent.py`:** một phản hồi `2xx` khai
    `usage.total_tokens == 0` bị coi là **thất bại** (`zero_tokens`), nhóm đó rơi về
    fallback có nhãn, và nếu mọi nhóm đều rơi thì cả lần chạy thành `degraded` + thoát mã
    `3`. Kiểm chứng bằng một HTTP server thật trả 200 với thân JSON hợp lệ nhưng 0 token.
  - **Chưa vá — `scripts/bench.py`, `scripts/sweep.py`, `scripts/ablation.py`:** ba script
    này *vẫn* không tự cảnh báo khi `usage.total_tokens == 0` mà `len(per_test) > 0`. Sự cố
    gốc xảy ra ở chính chúng, và chúng vẫn có thể ghi nhận một lần quét 0 token là hợp lệ.
    Vá một chỗ không phải vá cả nhà.
- **Truy hồi kho tri thức chỉ là TF-IDF từ khoá, và KB mới có 23 tài liệu.** 74/93 phát hiện
(79.6%) trích dẫn được tài liệu KB. 19 phát hiện còn lại đều *đã* được truy hồi 3 tài liệu
nhưng mô hình không trích dẫn cái nào — đúng, vì đó là kết quả trùng từ vựng chứ không đúng
chủ đề (ví dụ `insecure-cookie` trả về cho `CWE-15`). Con số này đo **độ phủ của KB**, không
đo chất lượng agent. Xem `DEBT.md`.
- **Chất lượng lời giải thích chưa được đo.** Không có tập đánh giá, không có người chấm.
Những gì đã kiểm chứng là các thuộc tính máy kiểm tra được (0 đường dẫn bịa, 0 mã KB không
tồn tại, 93/93 dòng đúng lược đồ, output `--no-llm` giống hệt từng byte) — còn "dễ hiểu" thì
hiện là một tuyên bố, không phải một phép đo.
- **Thanh tiến trình (progress bar) đứng yên khi quét ít hơn 3 file** vì một dòng `print`
ở `bench.py` thiếu `flush=True`, nên log không tới nơi cho tới khi tiến trình kết thúc.
Cách sửa chỉ là thêm một keyword argument, nhưng chưa áp dụng vì nằm ngoài phạm vi các
card đã khoá file `scripts/*.py`.

