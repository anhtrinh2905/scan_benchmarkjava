# Metis vs OWASP BenchmarkJava — scorecard

| | |
|---|---|
| Thời điểm | 2026-07-31T03:47:31.379417+00:00 |
| Scan model | `deepseek-v4-flash` |
| Metis | v1.5.0 (git 59dff7c) |
| Triage | bật |
| Số test × lặp | 6 × 1 = 6 lần scan |
| Tập test | 6 test: `BenchmarkTest00001` → `BenchmarkTest00006` |

## Chi phí

| Chỉ số | Giá trị |
|---|---:|
| Findings (thô) | **8** |
| Wall-clock | **5.4 phút** (323s) |
| Metis duration (native) | 5.2 phút |
| Token | **0.18M** (0.15M in / 0.032M out) |

## Precision / Recall (đối chiếu ground truth)

| Chỉ số | strict | lenient |
|---|---:|---:|
| TP | 5 | 5 |
| FP | 0 | 0 |
| FN | 1 | 1 |
| TN | 0 | 0 |
| **Precision** | **100.0%** | **100.0%** |
| **Recall (TPR)** | **83.3%** | **83.3%** |
| FPR | n/a | n/a |
| Youden (TPR−FPR) | n/a | n/a |

Đơn vị là **mỗi file test**, không phải mỗi finding: một file có 3 finding vẫn chỉ tính một TP. Finding off-target (CWE khác CWE kỳ vọng) không vào TP/FP, chỉ được đếm riêng như nhiễu.

**strict** = `inconclusive` tính là *vẫn báo cáo* (thứ dev thực sự phải đọc). **lenient** = `inconclusive` tính là *đã loại* (kịch bản tốt nhất). Chênh lệch giữa hai cột = mức độ do dự của model.

## Theo category

| Category | Test | TP | FP | FN | TN | Recall | FPR | Youden |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| pathtraver | 2 | 2 | 0 | 0 | 0 | 100.0% | n/a | n/a |
| cmdi | 1 | 1 | 0 | 0 | 0 | 100.0% | n/a | n/a |
| crypto | 1 | 1 | 0 | 0 | 0 | 100.0% | n/a | n/a |
| hash | 1 | 0 | 0 | 1 | 0 | 0.0% | n/a | n/a |
| trustbound | 1 | 1 | 0 | 0 | 0 | 100.0% | n/a | n/a |

_Cột strict. Bảng đầy đủ từng test nằm trong `bench_summary.json` (`ground_truth.per_test`)._

## Ca sai (1)

| Test | Loại | CWE | Ground truth | run | strict | lenient | on-target | do dự |
|---|---|---|---|---:|---|---|---:|---:|
| `BenchmarkTest00003` | hash | 328 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |

**FN** = bỏ sót lỗ hổng thật. **FP** = báo nhầm trên file an toàn.

## Độ ổn định

_Chạy 1 lần — không đo được. Dùng `--repeat 3` để đánh giá._

## Chi tiết finding (chỉ các ca sai)

### `BenchmarkTest00003` — hash, CWE-328, có lỗ hổng

_Metis không báo finding nào cho file này._

