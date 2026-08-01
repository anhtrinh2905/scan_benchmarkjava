# Metis vs OWASP BenchmarkJava — scorecard

| | |
|---|---|
| Thời điểm | 2026-08-01T07:47:46.383132+00:00 |
| Scan model | `deepseek-v4-pro` |
| Metis | v1.5.0 (git 0d6673a) |
| Triage | bật |
| Số test × lặp | 2 × 1 = 2 lần scan |
| Tập test | 2 test: `BenchmarkTest00001` → `BenchmarkTest00002` |

## Chi phí

| Chỉ số | Giá trị |
|---|---:|
| Findings (thô) | **5** |
| Wall-clock | **4.2 phút** (252s) |
| Metis duration (native) | 4.1 phút |
| Token | **0.17M** (0.15M in / 0.017M out) |

## Precision / Recall (đối chiếu ground truth)

| Chỉ số | strict | lenient |
|---|---:|---:|
| TP | 2 | 2 |
| FP | 0 | 0 |
| FN | 0 | 0 |
| TN | 0 | 0 |
| **Precision** | **100.0%** | **100.0%** |
| **Recall (TPR)** | **100.0%** | **100.0%** |
| FPR | n/a | n/a |
| Youden (TPR−FPR) | n/a | n/a |

Đơn vị là **mỗi file test**, không phải mỗi finding: một file có 3 finding vẫn chỉ tính một TP. Finding off-target (CWE khác CWE kỳ vọng) không vào TP/FP, chỉ được đếm riêng như nhiễu.

**strict** = `inconclusive` tính là *vẫn báo cáo* (thứ dev thực sự phải đọc). **lenient** = `inconclusive` tính là *đã loại* (kịch bản tốt nhất). Chênh lệch giữa hai cột = mức độ do dự của model.

## Theo category

| Category | Test | TP | FP | FN | TN | Recall | FPR | Youden |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| pathtraver | 2 | 2 | 0 | 0 | 0 | 100.0% | n/a | n/a |

_Cột strict. Bảng đầy đủ từng test nằm trong `bench_summary.json` (`ground_truth.per_test`)._

## Ca sai (0)

_Không có. Mọi test đều khớp ground truth ở cột strict._

## Độ ổn định

_Chạy 1 lần — không đo được. Dùng `--repeat 3` để đánh giá._

## Chi tiết finding (chỉ các ca sai)

_Không có ca sai nào._
