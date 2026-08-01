# Metis vs OWASP BenchmarkJava — scorecard

| | |
|---|---|
| Thời điểm | 2026-08-01T04:04:43.981390+00:00 |
| Scan model | `deepseek-v4-flash` |
| Metis | v1.5.0 (git 14cce32) |
| Triage | bật |
| Số test × lặp | 6 × 1 = 6 lần scan |
| Tập test | 6 test: `BenchmarkTest00001` → `BenchmarkTest00006` |

## Chi phí

| Chỉ số | Giá trị |
|---|---:|
| Findings (thô) | **8** |
| Wall-clock | **16.5 phút** (988s) |
| Metis duration (native) | 14.0 phút |
| Token | **0.08M** (0.06M in / 0.019M out) |

## Precision / Recall (đối chiếu ground truth)

| Chỉ số | strict | lenient |
|---|---:|---:|
| TP | 3 | 1 |
| FP | 0 | 0 |
| FN | 3 | 5 |
| TN | 0 | 0 |
| **Precision** | **100.0%** | **100.0%** |
| **Recall (TPR)** | **50.0%** | **16.7%** |
| FPR | n/a | n/a |
| Youden (TPR−FPR) | n/a | n/a |

Đơn vị là **mỗi file test**, không phải mỗi finding: một file có 3 finding vẫn chỉ tính một TP. Finding off-target (CWE khác CWE kỳ vọng) không vào TP/FP, chỉ được đếm riêng như nhiễu.

**strict** = `inconclusive` tính là *vẫn báo cáo* (thứ dev thực sự phải đọc). **lenient** = `inconclusive` tính là *đã loại* (kịch bản tốt nhất). Chênh lệch giữa hai cột = mức độ do dự của model.

## Theo category

| Category | Test | TP | FP | FN | TN | Recall | FPR | Youden |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| pathtraver | 2 | 2 | 0 | 0 | 0 | 100.0% | n/a | n/a |
| cmdi | 1 | 0 | 0 | 1 | 0 | 0.0% | n/a | n/a |
| crypto | 1 | 1 | 0 | 0 | 0 | 100.0% | n/a | n/a |
| hash | 1 | 0 | 0 | 1 | 0 | 0.0% | n/a | n/a |
| trustbound | 1 | 0 | 0 | 1 | 0 | 0.0% | n/a | n/a |

_Cột strict. Bảng đầy đủ từng test nằm trong `bench_summary.json` (`ground_truth.per_test`)._

## Ca sai (3)

| Test | Loại | CWE | Ground truth | run | strict | lenient | on-target | do dự |
|---|---|---|---|---:|---|---|---:|---:|
| `BenchmarkTest00003` | hash | 328 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00004` | trustbound | 501 | có lỗ hổng | 1 | **FN** | FN | 0 | 1 |
| `BenchmarkTest00006` | cmdi | 78 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |

**FN** = bỏ sót lỗ hổng thật. **FP** = báo nhầm trên file an toàn.

## Độ ổn định

_Chạy 1 lần — không đo được. Dùng `--repeat 3` để đánh giá._

## Chi tiết finding (chỉ các ca sai)

### `BenchmarkTest00003` — hash, CWE-328, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00004` — trustbound, CWE-501, có lỗ hổng

- **run 1** · dòng 57 · CWE `CWE-807` (off-target) · severity `High` · triage **inconclusive**
  - User-controlled cookie value used as session attribute key without validation
  - _triage:_ Inconclusive because the triage model did not return a valid decision payload.

### `BenchmarkTest00006` — cmdi, CWE-78, có lỗ hổng

_Metis không báo finding nào cho file này._

