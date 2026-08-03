# Metis vs OWASP BenchmarkJava — scorecard

| | |
|---|---|
| Thời điểm | 2026-07-31T02:51:02.160822+00:00 |
| Scan model | `deepseek-v4-flash` |
| Metis | v1.5.0 (git 59dff7c) |
| Triage | bật |
| Số test × lặp | 6 × 1 = 6 lần scan |
| Tập test | 6 test: `BenchmarkTest00001` → `BenchmarkTest00006` |

## Chi phí

| Chỉ số | Giá trị |
|---|---:|
| Findings (thô) | **9** |
| Wall-clock | **5.0 phút** (298s) |
| Metis duration (native) | 4.7 phút |
| Token | **0.19M** (0.16M in / 0.028M out) |

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
| hash | 1 | 1 | 0 | 0 | 0 | 100.0% | n/a | n/a |
| trustbound | 1 | 0 | 0 | 1 | 0 | 0.0% | n/a | n/a |

_Cột strict. Bảng đầy đủ từng test nằm trong `bench_summary.json` (`ground_truth.per_test`)._

## Ca sai (1)

| Test | Loại | CWE | Ground truth | run | strict | lenient | on-target | do dự |
|---|---|---|---|---:|---|---|---:|---:|
| `BenchmarkTest00004` | trustbound | 501 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |

**FN** = bỏ sót lỗ hổng thật. **FP** = báo nhầm trên file an toàn.

## Độ ổn định

_Chạy 1 lần — không đo được. Dùng `--repeat 3` để đánh giá._

## Chi tiết finding (chỉ các ca sai)

### `BenchmarkTest00004` — trustbound, CWE-501, có lỗ hổng

- **run 1** · dòng 57 · CWE `CWE-565` (off-target) · severity `Medium` · triage **valid**
  - Client-controlled cookie value used as the name of a session attribute (trust boundary violation / session state manipulation)
  - _triage:_ Verdict: Valid - attacker-controlled cookie value flows unvalidated into the session attribute name in HttpSession.setAttribute. Evidence: request.getCookies() at :55 yields client-controlled cookies; the loop at :58-64 selects the cookie named 'BenchmarkTest00004' and assigns its URL-decoded value to param at :61; the snippet then shows request.getSession().setAttribute(param, "10340"), using param as the attribute key with no validation or whitelist between decode and setAttribute. Gap: none.
- **run 1** · dòng 41 · CWE `CWE-20` (off-target) · severity `Low` · triage **valid**
  - Cookie Path and Domain attributes are derived from client-controlled request data
  - _triage:_ Verdict: The cookie Path and Domain attributes are directly derived from client-influenced request data with no validation or fixed-value override, confirming the finding. Evidence: Lines 41-42 set Path from request.getRequestURI() and Domain from request.getRequestURL().getHost(), and the enclosing doGet method (lines 33-47) contains no sanitization, allowlist, or canonical-domain fallback before response.addCookie(userCookie) at line 43. Gap: none.

