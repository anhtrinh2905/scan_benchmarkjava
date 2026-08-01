# Metis vs OWASP BenchmarkJava — scorecard

| | |
|---|---|
| Thời điểm | 2026-07-31T02:54:01.330632+00:00 |
| Scan model | `deepseek-v4-flash` |
| Metis | v1.5.0 (git 59dff7c) |
| Triage | bật |
| Số test × lặp | 6 × 1 = 6 lần scan |
| Tập test | 6 test: `BenchmarkTest00001` → `BenchmarkTest00006` |

## Chi phí

| Chỉ số | Giá trị |
|---|---:|
| Findings (thô) | **7** |
| Wall-clock | **5.0 phút** (302s) |
| Metis duration (native) | 4.8 phút |
| Token | **0.21M** (0.19M in / 0.026M out) |

## Precision / Recall (đối chiếu ground truth)

| Chỉ số | strict | lenient |
|---|---:|---:|
| TP | 4 | 4 |
| FP | 0 | 0 |
| FN | 2 | 2 |
| TN | 0 | 0 |
| **Precision** | **100.0%** | **100.0%** |
| **Recall (TPR)** | **66.7%** | **66.7%** |
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
| trustbound | 1 | 0 | 0 | 1 | 0 | 0.0% | n/a | n/a |

_Cột strict. Bảng đầy đủ từng test nằm trong `bench_summary.json` (`ground_truth.per_test`)._

## Ca sai (2)

| Test | Loại | CWE | Ground truth | run | strict | lenient | on-target | do dự |
|---|---|---|---|---:|---|---|---:|---:|
| `BenchmarkTest00003` | hash | 328 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00004` | trustbound | 501 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |

**FN** = bỏ sót lỗ hổng thật. **FP** = báo nhầm trên file an toàn.

## Độ ổn định

_Chạy 1 lần — không đo được. Dùng `--repeat 3` để đánh giá._

## Chi tiết finding (chỉ các ca sai)

### `BenchmarkTest00003` — hash, CWE-328, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00004` — trustbound, CWE-501, có lỗ hổng

- **run 1** · dòng 55 · CWE `CWE-565` (off-target) · severity `Medium` · triage **valid**
  - Trust boundary violation: attacker-controlled cookie value is used as a session attribute name without validation, enabling session pollution or overwriting of security-relevant session data.
  - _triage:_ Verdict: The finding is valid; a client-controlled, URL-decoded cookie value is used directly as the HttpSession attribute name without validation. Evidence: doPost reads request cookies (line 55), extracts the 'BenchmarkTest00004' cookie value via URLDecoder.decode (line 61), and passes that decoded string as the attribute name to request.getSession().setAttribute(param, "10340") immediately after, matching the snippet's setAttribute line. Gap: none.

