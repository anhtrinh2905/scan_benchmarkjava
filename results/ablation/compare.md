# Ablation — kiến trúc discovery nào đáng tiền?

_Sinh lúc 2026-07-31T03:25:51.175693+00:00 · scope 36 test (BenchmarkTest00001 → BenchmarkTest00036) · ruleset Semgrep: p/java, p/owasp-top-ten, /Users/trinhthilananh/Desktop/Personal/vinsoc/week2/scan_benchmarkjava/rules/benchmarkjava_

| Arm | Youden(strict) | Youden(lenient) | Precision | Recall | FPR | Token | Phút | Youden/1M | Pareto |
|---|---:|---:|---:|---:|---:|---:|---:|---:|:--:|
| prompt_only | 65.6% | 65.6% | 96.7% | 90.6% | 25.0% | 194,208 | 2.8 | 337.9 | **✓** |
| harness | 65.6% | 65.6% | 96.7% | 90.6% | 25.0% | 1,029,939 | 6.0 | 63.7 |  |
| static | 90.6% | 87.5% | 100.0% | 90.6% | 0.0% | 761,359 | 3.2 | 119.0 | **✓** |
| B_union_C | 68.8% | 68.8% | 96.8% | 93.8% | 25.0% | 1,791,298 | 9.2 | 38.4 |  |

**Đề xuất: `prompt_only`** — ROI cao nhất: 337.9 điểm Youden trên mỗi 1M token (Youden strict 65.6% với 0.194M token). Arm điểm cao nhất là `static` (90.6%) nhưng phải trả 3.9× token để đổi lấy +25.0 điểm Youden.

## Chú thích từng arm

- `prompt_only` — A — LLM trần, không tool, không triage (sàn dưới)
- `harness` — B — harness đầy đủ (= baseline sweep)
- `static` — C — Semgrep tìm, LLM chỉ verify
- `B_union_C` — dẫn xuất — gộp offline SARIF của `harness` ∪ `static`

> **Youden/1M** = (recall − FPR) × 100 chia cho số token tính bằng triệu. Cột Pareto đánh dấu arm không bị arm nào khác vừa cao điểm hơn vừa rẻ hơn.

> `B_union_C` là arm **dẫn xuất**: nó gộp offline SARIF đã có của `harness` và `static`, không gọi thêm LLM lần nào. Token và phút của nó vì thế được ghi bằng **TỔNG** của hai arm nguồn — phải chạy cả hai mới có nó, nên cột Youden/1M mới trung thực.

> `static` tốn 0 token cho khâu Semgrep (chỉ tốn wall-clock, đã cộng vào cột Phút); toàn bộ token của nó là của khâu `triage`.

> Precision/recall/FPR lấy từ cột **strict** (`inconclusive` = vẫn tính là báo cáo), đối chiếu ground truth `expectedresults-1.2.csv`. Không LLM-judge. Đơn vị là mỗi FILE test, không phải mỗi finding.

> Arm `prompt_only` không chạy triage nên mọi finding mặc định `valid` → strict phải bằng lenient. Nếu hai cột lệch nhau là logic status mặc định sai.

